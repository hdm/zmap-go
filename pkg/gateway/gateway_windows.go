//go:build windows

package gateway

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// defaultGateway returns the first IPv4 gateway address advertised by the
// Windows adapter matching intf (or the first adapter that has any gateway
// when intf is nil), via GetAdaptersAddresses(AF_INET).
func defaultGateway(intf *net.Interface) (net.IP, error) {
	const (
		flags = windows.GAA_FLAG_INCLUDE_GATEWAYS |
			windows.GAA_FLAG_SKIP_ANYCAST |
			windows.GAA_FLAG_SKIP_MULTICAST |
			windows.GAA_FLAG_SKIP_DNS_SERVER
	)
	var size uint32
	// First call to size the buffer.
	err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, nil, &size)
	if err != nil && err != windows.ERROR_BUFFER_OVERFLOW {
		return nil, fmt.Errorf("gateway: GetAdaptersAddresses size: %w", err)
	}
	if size == 0 {
		return nil, ErrNoDefault
	}
	buf := make([]byte, size)
	addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, addr, &size); err != nil {
		return nil, fmt.Errorf("gateway: GetAdaptersAddresses: %w", err)
	}
	for a := addr; a != nil; a = a.Next {
		if intf != nil && int(a.IfIndex) != intf.Index {
			continue
		}
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			ip := sockaddrToIP(g.Address.Sockaddr)
			if ip != nil && ip.To4() != nil {
				return ip.To4(), nil
			}
		}
	}
	return nil, ErrNoDefault
}

func sockaddrToIP(sa *syscall.RawSockaddrAny) net.IP {
	if sa == nil {
		return nil
	}
	switch sa.Addr.Family {
	case windows.AF_INET:
		p := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sa))
		return net.IPv4(p.Addr[0], p.Addr[1], p.Addr[2], p.Addr[3])
	}
	return nil
}
