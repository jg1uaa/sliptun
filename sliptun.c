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
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#if defined(__OpenBSD__)
#define USE_TUN_PI /* OpenBSD requires TUN packet information (PI) */
#define PROTO_INET AF_INET
#define PROTO_INET6 AF_INET6
#elif defined(__linux__)
/* Linux supports TUN PI, but not used */
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#else
/* Others (FreeBSD/NetBSD/DragonflyBSD) has no PI */
#endif

extern char *optarg;

static char *serdev = NULL;
static char *tundev = NULL;
static bool rtscts = false;

enum portmode {
	NONE, SERIAL, TCP_CLIENT, TCP_SERVER,
};
static enum portmode portmode = NONE;
static int portarg;

static int fd_ser, fd_tun;
static bool die = false;

#define TCP_MAX_SOCKET 2

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

#define END_CHAR 0xc0		/* indicates end of packet */
#define ESC_CHAR 0xdb		/* indicates byte stuffing */
#define ESCAPED_END 0xdc	/* ESC ESC_END means END data byte */
#define ESCAPED_ESC 0xdd	/* ESC ESC_ESC means ESC data byte */

static inline bool get_serial_char(int fd, uint8_t *c)
{
	return die || read(fd, c, sizeof(*c)) != sizeof(*c);
}

static ssize_t receive_slip_frame(int fd, uint8_t *buf, size_t bufsize)
{
	uint8_t c;
	size_t len;
	bool received;

	len = 0;
	received = false;
	while (1) {
		if (get_serial_char(fd, &c))
			goto error;

		switch (c) {
		case END_CHAR:
			if (received)
				goto success;

			len = 0;
			received = false;
			break;

		case ESC_CHAR:
			if (get_serial_char(fd, &c))
				goto error;

			if (c == ESCAPED_END) c = END_CHAR;
			else if (c == ESCAPED_ESC) c = ESC_CHAR;

			/* FALLTHROUGH */
		default:
			if (len < bufsize)
				buf[len++] = c;
			received = true;
			break;
		}
	}

error:
	return -1;
success:
	return len;
}

static void *do_slip_rx(__attribute__((unused)) void *arg)
{
	struct tun_packet tun_tx;
	ssize_t len;
	bool received;

	while (!die) {
		if ((len = receive_slip_frame(fd_ser, tun_tx.data,
					      sizeof(tun_tx.data))) < 0) {
			printf("slip read error\n");
			goto fin0;
		}

		received = true;
#ifdef USE_TUN_PI
		/* check IP version from header */
		switch (tun_tx.data[0] >> 4) {
		case 4:
			tun_tx.proto = htons(PROTO_INET);
			break;
		case 6:
			tun_tx.proto = htons(PROTO_INET6);
			break;
		default:
			received = false; /* discard */
			break;
		}

		tun_tx.flags = 0;
#endif
		if (received) {
			write(fd_tun, &tun_tx,
			      offsetof(struct tun_packet, data[len]));
		}
	}

fin0:
	die = true;
	return NULL;
}

static size_t build_slip_frame(uint8_t *out, uint8_t *in, size_t in_size)
{
#define put_buffer(c) {out[out_size++] = (c);}

	size_t i, out_size = 0;

	/*
	 * RFC says send END character first to flush out
	 * receiver accumulated garbage (by noise?)
	 */
	put_buffer(END_CHAR);

	/*
	 * send frame, two characters (END, ESC) needs to
	 * handled by special sequence
	 */
	for (i = 0; i < in_size; i++) {
		switch (in[i]) {
		case END_CHAR:
			put_buffer(ESC_CHAR);
			put_buffer(ESCAPED_END);
			break;
		case ESC_CHAR:
			put_buffer(ESC_CHAR);
			put_buffer(ESCAPED_ESC);
			break;
		default:
			put_buffer(in[i]);
			break;
		}
	}

	/* tell the receiver that "end of frame" */
	put_buffer(END_CHAR);

	return out_size;
}

static void *do_slip_tx(__attribute__((unused)) void *arg)
{
	struct tun_packet tun_rx;
	ssize_t size;

	/* END_CHAR + escaped character(2) * received size + END_CHAR */
	uint8_t buf[2 * sizeof(tun_rx.data) + 2];

	while (!die) {
		if ((size = read(fd_tun, &tun_rx, sizeof(tun_rx))) < 0) {
			printf("tun read error\n");
			goto fin0;
		}

		size -= offsetof(struct tun_packet, data);
		size = build_slip_frame(buf, tun_rx.data, size);
		write(fd_ser, buf, size);
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
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
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

static bool set_nonblock(int d, bool nonblock)
{
	int flags;

	return ((flags = fcntl(d, F_GETFL)) < 0 ||
		fcntl(d, F_SETFL, nonblock ?
		      (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK)) < 0);
}

static int open_serial(void)
{
	int fd;
	struct termios t;

	if ((fd = open(serdev,
		       O_RDWR | O_NOCTTY | O_EXCL | O_NONBLOCK)) < 0)
		goto fin0;

	memset(&t, 0, sizeof(t));
	cfsetospeed(&t, get_speed(portarg));
	cfsetispeed(&t, get_speed(portarg));

	t.c_cflag |= CREAD | CLOCAL | CS8;
	if (rtscts) t.c_cflag |= CRTSCTS;
	t.c_iflag = INPCK;
	t.c_oflag = 0;
	t.c_lflag = 0;
	t.c_cc[VTIME] = 0;
	t.c_cc[VMIN] = 1;

	tcflush(fd, TCIOFLUSH);
	tcsetattr(fd, TCSANOW, &t);

	if (set_nonblock(fd, false))
		goto fin1;

	goto fin0;

fin1:
	close(fd);
	fd = -1;
fin0:
	return fd;
}

static const char *inet_ntopXX(int af, const void *src, char *dst, socklen_t size)
{
	struct sockaddr_in *s4 = (struct sockaddr_in *)src;
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)src;

	switch (af) {
	case AF_INET:
		return inet_ntop(af, &s4->sin_addr.s_addr, dst, size);
	case AF_INET6:
		return inet_ntop(af, &s6->sin6_addr.s6_addr, dst, size);
	default:
		return strncpy(dst, "unknown", size);
	}
}

static struct addrinfo *acquire_address_info(void)
{
	struct addrinfo hints, *res;
	char tmp[16];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(tmp, sizeof(tmp), "%d", portarg);

	return getaddrinfo(serdev, tmp, &hints, &res) ? NULL : res;
}

static int wait_for_accept(int *list, int entries)
{
	int i, s = -1;
	struct pollfd *pfd;

	if (entries <= 0 ||
	    (pfd = calloc(sizeof(struct pollfd), entries)) == NULL)
		goto fin0;

	for (i = 0; i < entries; i++) {
		pfd[i].fd = list[i];
		pfd[i].events = POLLIN;
	}

	if (poll(pfd, entries, -1) <= 0)
		goto fin1;

	for (i = 0; i < entries; i++) {
		if (pfd[i].revents & POLLIN) {
			s = list[i];
			break;
		}
	}

fin1:
	free(pfd);
fin0:
	return s;
}

static int open_tcp_server(void)
{
	int i, s, enable = 1, fd = -1;
	int sock[TCP_MAX_SOCKET], numsock;
	struct addrinfo *res, *res0;
	struct sockaddr_storage ss;
	socklen_t ss_len;
	char addr_str[INET6_ADDRSTRLEN];

	if ((res0 = acquire_address_info()) == NULL)
		goto fin0;

	numsock = 0;
	for (res = res0; res && numsock < TCP_MAX_SOCKET;
	     res = res->ai_next) {
		if ((s = socket(res->ai_family, res->ai_socktype,
				res->ai_protocol)) < 0)
			continue;

		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			       &enable, sizeof(enable)) >= 0 &&
		    bind(s, res->ai_addr, res->ai_addrlen) >= 0 &&
		    listen(s, 1) >= 0 && !set_nonblock(s, true)) {
			sock[numsock++] = s;
			continue;
		}

		close(s);
	}

	while (1) {
		if ((s = wait_for_accept(sock, numsock)) < 0)
			break;

		ss_len = sizeof(ss);
		if ((fd = accept(s, (struct sockaddr *)&ss, &ss_len)) < 0)
			continue;

		/* nonblock is inherited from original socket (OpenBSD) */
		if (set_nonblock(fd, false)) {
			fd = s = -1;
			break;
		}

		inet_ntopXX(ss.ss_family, &ss, addr_str, sizeof(addr_str));
		printf("*** CONNECTED from %s\n", addr_str);
		break;
	}

	for (i = 0; i < numsock; i++)
		if (s != sock[i]) close(sock[i]);

	freeaddrinfo(res0);
fin0:
	return fd;
}

static int open_tcp_client(void)
{
	int s = -1;
	struct addrinfo *res, *res0;
	char addr_str[INET6_ADDRSTRLEN];

	if ((res0 = acquire_address_info()) == NULL)
		goto fin0;

	for (res = res0; res; res = res->ai_next) {
		if ((s = socket(res->ai_family, res->ai_socktype,
				 res->ai_protocol)) < 0)
			continue;

		if (connect(s, res->ai_addr, res->ai_addrlen) >= 0) {
			inet_ntopXX(res->ai_family, res->ai_addr,
				    addr_str, sizeof(addr_str));
			printf("*** CONNECTED to %s\n", addr_str);
			break;
		}

		close(s);
		s = -1;
	}

	freeaddrinfo(res0);
fin0:
	return s;
}

static int do_main(void)
{
	int ret = -1;
	pthread_t tid;

	if ((fd_tun = open_tun()) < 0) {
		printf("device open error (tun)\n");
		goto fin0;
	}

	switch (portmode) {
	case SERIAL:
		fd_ser = open_serial();
		break;
	case TCP_CLIENT:
		fd_ser = open_tcp_client();
		break;
	case TCP_SERVER:
		fd_ser = open_tcp_server();
		break;
	default:
		fd_ser = -1;
		break;
	}
	if (fd_ser < 0) {
		printf("device open error (serial)\n");
		goto fin1;
	}

	if (pthread_create(&tid, NULL, &do_slip_tx, NULL)) {
		printf("pthread_create error\n");
		goto fin2;
	}

	do_slip_rx(NULL);

	pthread_cancel(tid);
	pthread_join(tid, NULL);
	ret = 0;

fin2:
	close(fd_ser);
fin1:
	close(fd_tun);
fin0:
	return ret;
}

int main(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "s:p:P:l:t:f")) != -1) {
		switch (ch) {
		case 's':
			portmode = SERIAL;
			portarg = atoi(optarg);
			break;
		case 'p':
			portmode = TCP_CLIENT;
			portarg = atoi(optarg);
			break;
		case 'P':
			portmode = TCP_SERVER;
			portarg = atoi(optarg);
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

	if (serdev == NULL || tundev == NULL || portmode == NONE ||
	    (portmode == SERIAL && get_speed(portarg) < 0)) {
		printf("usage: %s: -s [serial speed] -l [serial device] "
		       "-t [tun device]\n", argv[0]);
		goto fin0;
	}

	do_main();

fin0:
	return 0;
}
