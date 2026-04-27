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
	"sync/atomic"
)

// ErrUnsupported is returned by ListenPacket on unsupported platforms.
var ErrUnsupported = errors.New("raw: unsupported platform")

// PreferTxRing, when true, hints platform implementations to use a
// PACKET_MMAP / TPACKET TX ring (or equivalent zero-copy ring) for the
// senders returned by PacketConn.NewSender. Currently consulted only on
// Linux; ignored everywhere else. Implementations fall back to their
// regular sender on any setup failure (capability, quota, kernel version).
var PreferTxRing atomic.Bool

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
	// WriteBatch transmits a batch of pre-built frames in a single
	// underlying syscall where the platform supports it (Linux:
	// sendmmsg(2)). It returns the number of frames the kernel accepted;
	// the remainder were dropped (the caller should treat them as send
	// failures). Implementations that don't have a native batch syscall
	// fall back to looping over WriteTo.
	WriteBatch(pkts [][]byte) (int, error)
	Close() error
}

// MaxBatch is the recommended upper bound on the number of frames passed
// to Sender.WriteBatch. The Linux UIO_MAXIOV cap is 1024; staying well
// below it keeps each syscall cheap and predictable.
const MaxBatch = 256

// ListenPacket opens a raw L2 socket on the named interface.
func ListenPacket(ifname string) (PacketConn, error) {
	intf, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	return listenPacket(intf)
}
