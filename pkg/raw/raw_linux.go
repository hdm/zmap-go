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

// silence unused import warnings on builds where syscall is not referenced.
var _ = syscall.AF_INET
