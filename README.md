# slipTUN

---
## Description

a simple SLIP implementation with TUN interface

the detail of SLIP: see [RFC 1055](https://datatracker.ietf.org/doc/html/rfc1055)

## Usage

```
# sliptun
usage: sliptun -s [serial speed] -l [serial device] -t [tun device]
#
```

### Example

#### set up SLIP peer on OpenBSD

```
# ifconfig tun0 create
# ifconfig tun0 inet 192.168.200.1 192.168.200.2
# ifconfig tun0 mtu 296 up
# sliptun -s 115200 -l /dev/tty00 -t /dev/tun0 &
```

#### set up SLIP peer on Linux with sliptun

```
# sliptun -s 115200 -l /dev/ttyS1 -t tun0 &
# ip addr add 192.168.200.2 peer 192.168.200.1 dev tun0
# ip link set tun0 mtu 296 up
```

#### set up SLIP peer on Linux with slattach (standard tool)

```
# /sbin/slattach -L -p slip -s 115200 /dev/ttyS1 &
# ip addr add 192.168.200.2 peer 192.168.200.1 dev sl0
# ip link set sl0 up 
```

## Limitation

No plan to support CSLIP.

## License

MIT License
