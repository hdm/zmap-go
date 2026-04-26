// Package raw provides a minimal CGO-free raw L2 packet socket suitable for
// transmit and receive of arbitrary Ethernet frames.
//
// On Linux this is implemented with AF_PACKET / SOCK_RAW.
// On the BSDs (Darwin, FreeBSD, NetBSD, OpenBSD, DragonFly) it uses BPF via
// /dev/bpf*.
//
// The implementations are intentionally small and tailored for zmap's
// stateless probing pattern: send arbitrary frames quickly, read frames into
// a caller-provided buffer.
package raw

import (
	"errors"
	"net"
)

// ErrUnsupported is returned by ListenPacket on unsupported platforms.
var ErrUnsupported = errors.New("raw: unsupported platform")

// PacketConn is the cross-platform interface implemented by Linux and BSD
// raw sockets.
type PacketConn interface {
	// WriteTo writes a fully formed Ethernet frame to the wire.
	WriteTo(b []byte) (int, error)
	// ReadFrom reads the next frame into b. The slice returned aliases b.
	ReadFrom(b []byte) (n int, err error)
	// Close releases the socket.
	Close() error
	// Interface returns the underlying network interface.
	Interface() *net.Interface
	// LinkType reports "ethernet", "loopback", etc.
	LinkType() string
	// NewSender returns a write-only handle independent of the receive
	// path. On platforms that benefit (Linux AF_PACKET, BSD BPF) this is
	// a fresh kernel socket / fd, eliminating per-fd lock contention when
	// many sender goroutines run in parallel. On platforms without that
	// benefit it returns a sender that delegates to WriteTo. Each sender
	// goroutine should call NewSender once and Close it on exit.
	NewSender() (Sender, error)
}

// Sender is a write-only handle returned by PacketConn.NewSender. Independent
// senders avoid contention on the receive socket's fd lock, which is the
// dominant bottleneck on high-core-count systems sending at hundreds of kpps.
type Sender interface {
	WriteTo(b []byte) (int, error)
	Close() error
}

// ListenPacket opens a raw L2 socket on the named interface.
func ListenPacket(ifname string) (PacketConn, error) {
	intf, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	return listenPacket(intf)
}
