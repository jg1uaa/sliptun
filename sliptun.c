// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 SASANO Takayoshi <uaa@uaa.org.uk>

/*
 * slipTUN - a simple SLIP implementation with TUN interface
 *
 * reference: RFC 1055 (https://datatracker.ietf.org/doc/html/rfc1055)
 * - Nonstandard for transmission of IP datagrams over serial lines: SLIP
 */ 

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <pthread.h>

#if defined(__OpenBSD__) /* OpenBSD requires TUN packet information (PI) */
#define USE_TUN_PI
#include <sys/socket.h>
#define PROTO_UNDEF AF_UNSPEC
#define PROTO_INET AF_INET
#define PROTO_INET6 AF_INET6
#elif defined(__linux__) /* Linux supports TUN PI */
#define USE_TUN_PI
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#define PROTO_UNDEF 0
#define PROTO_INET ETH_P_IP
#define PROTO_INET6 ETH_P_IPV6
#else /* Others (FreeBSD/NetBSD/DragonflyBSD) has no PI */
#undef USE_TUN_PI
#endif

#ifdef USE_TUN_PI
#include <arpa/inet.h>
#endif

extern char *optarg;

static char *serdev = NULL;
static char *tundev = NULL;
static int serspeed = -1;
static bool rtscts = false;

static int fd_ser, fd_tun;
static bool die = false;

/*
 * OpenBSD's <net/if_tun.h> defines TUNMTU (3000) and TUNMRU (16384),
 * but there is no definition in Linux. 16Kbyte may be enough. 
 */
#define BUFSIZE 16384

/*
 * TUN packet information and data frame (see <linux/if_tun.h>)
 *
 * flags: Linux defines TUN_PKT_STRIP (0x0001), but OpenBSD uses this field
 *        as a part of proto. This field should be zero.
 * proto: this shoud be network byte order (big endian).
 *        Linux uses ethernet type defined by <linux/if_ether.h>.
 *        OpenBSD uses address/protocol family, <sys/socket.h>.
 */
struct tun_packet {
#ifdef USE_TUN_PI
	uint16_t flags;
	uint16_t proto;
#endif
	uint8_t data[BUFSIZE];
} __attribute__((packed));

static struct tun_packet tun_rx, tun_tx;

#define END_CHAR 0xc0		/* indicates end of packet */
#define ESC_CHAR 0xdb		/* indicates byte stuffing */
#define ESCAPED_END 0xdc	/* ESC ESC_END means END data byte */
#define ESCAPED_ESC 0xdd	/* ESC ESC_ESC means ESC data byte */

static inline int put_serial_char(uint8_t c)
{
	return write(fd_ser, &c, sizeof(c)) != sizeof(c);
}

static inline int get_serial_char(uint8_t *c)
{
	return read(fd_ser, c, sizeof(*c)) != sizeof(*c);
}

static void *do_serial_rx(__attribute__((unused)) void *arg)
{
	uint8_t c;
	size_t len;
	bool received;

	len = 0;
	received = false;
	while (!die) {
		if (get_serial_char(&c)) {
			printf("serial read error\n");
			goto fin0;
		}

		switch (c) {
		case END_CHAR:
#ifdef USE_TUN_PI
			if (received) {
				uint16_t proto;

				/* check IP version from header */
				switch (tun_tx.data[0] >> 4) {
				case 4:
					proto = PROTO_INET;
					break;
				case 6:
					proto = PROTO_INET6;
					break;
				default:
					proto = PROTO_UNDEF;
					received = false; /* discard */
					break;
				}

				tun_tx.flags = 0;
				tun_tx.proto = htons(proto);
			}
#endif
			if (received) {
				write(fd_tun, &tun_tx,
				      offsetof(struct tun_packet, data[len]));
			}

			len = 0;
			received = false;
			break;

		case ESC_CHAR:
			if (get_serial_char(&c)) {
				printf("serial read error\n");
				goto fin0;
			}

			if (c == ESCAPED_END) c = END_CHAR;
			else if (c == ESCAPED_ESC) c = ESC_CHAR;

			/* FALLTHROUGH */
		default:
			if (len < sizeof(tun_tx.data))
				tun_tx.data[len++] = c;
			received = true;
			break;
		}
	}

fin0:
	die = true;
	return NULL;
}

static void *do_serial_tx(__attribute__((unused)) void *arg)
{
	ssize_t i, size;

	while (!die) {
		if ((size = read(fd_tun, &tun_rx, sizeof(tun_rx))) < 0) {
			printf("tun read error\n");
			goto fin0;
		}

		/*
		 * RFC says send END character first to flush out
		 * receiver accumulated garbage (by noise?)
		 */
		put_serial_char(END_CHAR);

		/*
		 * send frame, two characters (END, ESC) needs to
		 * handled by special sequence
		 */
		size -= offsetof(struct tun_packet, data);
		for (i = 0; i < size; i++) {
			switch (tun_rx.data[i]) {
			case END_CHAR:
				put_serial_char(ESC_CHAR);
				put_serial_char(ESCAPED_END);
				break;
			case ESC_CHAR:
				put_serial_char(ESC_CHAR);
				put_serial_char(ESCAPED_ESC);
				break;
			default:
				put_serial_char(tun_rx.data[i]);
				break;
			}
		}

		/* tell the receiver that "end of frame" */
		put_serial_char(END_CHAR);
	}

fin0:
	die = true;
	return NULL;
}

static int get_speed(int speed)
{
#if defined(B38400) && (B38400 == 38400)
	return speed;
#else
	switch (speed) {
	case 0:		return B0;
	case 50:	return B50;
	case 75:	return B75;
	case 110:	return B110;
	case 134:	return B134;
	case 150:	return B150;
	case 200:	return B200;
	case 300:	return B300;
	case 600:	return B600;
	case 1200:	return B1200;
	case 1800:	return B1800;
	case 2400:	return B2400;
	case 4800:	return B4800;
	case 9600:	return B9600;
	case 19200:	return B19200;
	case 38400:	return B38400;
#if defined(B57600)
	case 57600:	return B57600;
#endif
#if defined(B115200)
	case 115200:	return B115200;
#endif
#if defined(B230400)
	case 230400:	return B230400;
#endif
#if defined(B460800)
	case 460800:	return B460800;
#endif
#if defined(B500000)
	case 500000:	return B500000;
#endif
#if defined(B576000)
	case 576000:	return B576000;
#endif
#if defined(B921600)
	case 921600:	return B921600;
#endif
#if defined(B1000000)
	case 1000000:	return B1000000;
#endif
#if defined(B1152000)
	case 1152000:	return B1152000;
#endif
#if defined(B1500000)
	case 1500000:	return B1500000;
#endif
#if defined(B2000000)
	case 2000000:	return B2000000;
#endif
#if defined(B2500000)
	case 2500000:	return B2500000;
#endif
#if defined(B3000000)
	case 3000000:	return B3000000;
#endif
#if defined(B3500000)
	case 3500000:	return B3500000;
#endif
#if defined(B4000000)
	case 4000000:	return B4000000;
#endif
	default:	return -1;
	}
#endif
}

static int open_tun(void)
#if defined(__linux__)
{
#define TUN_DEVICE "/dev/net/tun"

	int fd;
	struct ifreq ifr;

	if ((fd = open(TUN_DEVICE, O_RDWR)) < 0)
		goto fin0;

	memset(&ifr, 0, sizeof(ifr));
#ifdef USE_TUN_PI
	ifr.ifr_flags = IFF_TUN;
#else
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
#endif
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tundev);
	if (ioctl(fd, TUNSETIFF, &ifr) < 0)
		goto fin1;

	goto fin0;

fin1:
	close(fd);
	fd = -1;
fin0:
	return fd;
}
#else
{
	return open(tundev, O_RDWR | O_EXCL);
}
#endif

static int do_main(void)
{
	int ret = -1;
	struct termios t;
	pthread_t tid;

	if ((fd_ser = open(serdev, O_RDWR | O_NOCTTY | O_EXCL)) < 0) {
		printf("device open error (serial)\n");
		goto fin0;
	}

	if ((fd_tun = open_tun()) < 0) {
		printf("device open error (tun)\n");
		goto fin1;
	}

	memset(&t, 0, sizeof(t));
	cfsetospeed(&t, get_speed(serspeed));
	cfsetispeed(&t, get_speed(serspeed));

	t.c_cflag |= CREAD | CLOCAL | CS8;
	if (rtscts) t.c_cflag |= CRTSCTS;
	t.c_iflag = INPCK;
	t.c_oflag = 0;
	t.c_lflag = 0;
	t.c_cc[VTIME] = 0;
	t.c_cc[VMIN] = 1;

	tcflush(fd_ser, TCIOFLUSH);
	tcsetattr(fd_ser, TCSANOW, &t);

	if (pthread_create(&tid, NULL, &do_serial_tx, NULL)) {
		printf("pthread_create error\n");
		goto fin2;
	}

	do_serial_rx(NULL);

	pthread_cancel(tid);
	pthread_join(tid, NULL);
	ret = 0;

fin2:
	close(fd_tun);
fin1:
	close(fd_ser);
fin0:
	return ret;
}

int main(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "s:l:t:f")) != -1) {
		switch (ch) {
		case 's':
			serspeed = atoi(optarg);
			break;
		case 'l':
			serdev = optarg;
			break;
		case 't':
			tundev = optarg;
			break;
		case 'f':
			rtscts = true;
			break;
		}
	}

	if (serdev == NULL || tundev == NULL || serspeed < 0 ||
	    get_speed(serspeed) < 0) {
		printf("usage: %s: -s [serial speed] -l [serial device] "
		       "-t [tun device]\n", argv[0]);
		goto fin0;
	}

	do_main();

fin0:
	return 0;
}