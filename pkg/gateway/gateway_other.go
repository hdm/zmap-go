//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package gateway

import "net"

func defaultGateway(_ *net.Interface) (net.IP, error) {
	return nil, ErrNoDefault
}
