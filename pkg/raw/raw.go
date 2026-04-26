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
}

// ListenPacket opens a raw L2 socket on the named interface.
func ListenPacket(ifname string) (PacketConn, error) {
	intf, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	return listenPacket(intf)
}
