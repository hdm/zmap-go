//go:build linux

package raw

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const ethPAll = 0x0003

type linuxConn struct {
	f      *os.File
	intf   *net.Interface
	link   string
	closed bool
}

func htons(i uint16) uint16 { return (i<<8)&0xff00 | i>>8 }

func listenPacket(intf *net.Interface) (PacketConn, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("raw: socket(AF_PACKET): %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  intf.Index,
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("raw: bind: %w", err)
	}
	link := "ethernet"
	if sa, err := unix.Getsockname(fd); err == nil {
		if sll, ok := sa.(*unix.SockaddrLinklayer); ok {
			switch sll.Hatype {
			case 1:
				link = "ethernet"
			case 772:
				link = "loopback"
			case 65534:
				link = "raw"
			default:
				link = fmt.Sprintf("unknown-%d", sll.Hatype)
			}
		}
	}
	f := os.NewFile(uintptr(fd), "raw-"+intf.Name)
	return &linuxConn{f: f, intf: intf, link: link}, nil
}

func (c *linuxConn) WriteTo(b []byte) (int, error) {
	rc, err := c.f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var werr error
	cerr := rc.Write(func(fd uintptr) bool {
		werr = unix.Sendto(int(fd), b, 0, &unix.SockaddrLinklayer{
			Ifindex:  c.intf.Index,
			Halen:    uint8(len(c.intf.HardwareAddr)),
			Protocol: htons(ethPAll),
		})
		if werr == unix.EAGAIN {
			return false
		}
		if werr == nil {
			n = len(b)
		}
		return true
	})
	if werr != nil {
		return n, werr
	}
	if cerr != nil {
		return n, cerr
	}
	return n, nil
}

func (c *linuxConn) ReadFrom(b []byte) (int, error) {
	rc, err := c.f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var rerr error
	cerr := rc.Read(func(fd uintptr) bool {
		n, _, rerr = unix.Recvfrom(int(fd), b, 0)
		return rerr != unix.EAGAIN
	})
	if rerr != nil {
		return n, rerr
	}
	return n, cerr
}

func (c *linuxConn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.f.Close()
}

func (c *linuxConn) Interface() *net.Interface { return c.intf }
func (c *linuxConn) LinkType() string          { return c.link }

// linuxSender is a per-thread AF_PACKET transmit handle. It owns a raw fd
// (not wrapped in *os.File) so WriteTo is a direct unix.Sendto syscall with
// no internal mutex / pollDesc serialization. This is the key to scaling
// past ~100k pps on multi-core systems where many sender goroutines would
// otherwise contend on the receive socket's fdMutex.
type linuxSender struct {
	fd     int
	sa     unix.SockaddrLinklayer
	closed bool
}

func (c *linuxConn) NewSender() (Sender, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("raw: sender socket(AF_PACKET): %w", err)
	}
	// Bind so the kernel knows the egress interface; QDISC bypass below
	// short-circuits the qdisc layer for stateless probe traffic.
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  c.intf.Index,
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("raw: sender bind: %w", err)
	}
	// PACKET_QDISC_BYPASS (0x14): skip the qdisc layer, hand the frame
	// straight to the driver. Available since Linux 3.14. Best-effort —
	// failure (e.g. unprivileged or older kernel) is non-fatal.
	const packetQdiscBypass = 20
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, packetQdiscBypass, 1)
	// Larger SO_SNDBUF reduces the chance of EAGAIN under bursty load.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4*1024*1024)
	return &linuxSender{
		fd: fd,
		sa: unix.SockaddrLinklayer{
			Ifindex:  c.intf.Index,
			Halen:    uint8(len(c.intf.HardwareAddr)),
			Protocol: htons(ethPAll),
		},
	}, nil
}

func (s *linuxSender) WriteTo(b []byte) (int, error) {
	if err := unix.Sendto(s.fd, b, 0, &s.sa); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (s *linuxSender) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return unix.Close(s.fd)
}

// silence unused import warnings on builds where syscall is not referenced.
var _ = syscall.AF_INET
