//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package raw

import "net"

func listenPacket(_ *net.Interface) (PacketConn, error) {
	return nil, ErrUnsupported
}
