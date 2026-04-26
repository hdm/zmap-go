//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package gateway

import (
	"net"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func defaultGateway(intf *net.Interface) (net.IP, error) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}
		if intf != nil && rm.Index != intf.Index {
			continue
		}
		// Need at least Dst, Gateway, Netmask in Addrs.
		if len(rm.Addrs) < 3 {
			continue
		}
		dst, _ := rm.Addrs[0].(*route.Inet4Addr)
		gw, _ := rm.Addrs[1].(*route.Inet4Addr)
		if dst == nil || gw == nil {
			continue
		}
		// default route: Dst == 0.0.0.0
		if dst.IP != [4]byte{0, 0, 0, 0} {
			continue
		}
		return net.IPv4(gw.IP[0], gw.IP[1], gw.IP[2], gw.IP[3]).To4(), nil
	}
	return nil, ErrNoDefault
}
