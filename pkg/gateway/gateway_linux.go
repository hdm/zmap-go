//go:build linux

package gateway

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"strings"
)

func defaultGateway(intf *net.Interface) (net.IP, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Scan() // header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		// fields: Iface Destination Gateway Flags ...
		if fields[1] != "00000000" {
			continue
		}
		if intf != nil && fields[0] != intf.Name {
			continue
		}
		gw, err := hex.DecodeString(fields[2])
		if err != nil || len(gw) != 4 {
			continue
		}
		// /proc/net/route is little-endian.
		ip := net.IPv4(gw[3], gw[2], gw[1], gw[0])
		return ip.To4(), nil
	}
	return nil, ErrNoDefault
}
