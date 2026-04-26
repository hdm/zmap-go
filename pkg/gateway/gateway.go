// Package gateway resolves the default IPv4 gateway for a given interface
// and (optionally) its hardware address via ARP.
package gateway

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/hdm/zmap-go/pkg/raw"
)

// ErrNoDefault is returned when no default IPv4 route could be found.
var ErrNoDefault = errors.New("gateway: no default IPv4 route")

// DefaultGateway returns the default IPv4 next-hop for the given interface.
// If intf is nil, the system's primary default route is returned regardless
// of interface.
func DefaultGateway(intf *net.Interface) (net.IP, error) {
	return defaultGateway(intf)
}

// ResolveMAC returns the hardware address of nextHop reachable on intf.
// It opens its own raw socket for the request: callers should pass an
// already-open one via ResolveMACWithConn for efficiency during a scan.
func ResolveMAC(intf *net.Interface, srcIP net.IP, srcMAC net.HardwareAddr,
	nextHop net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	conn, err := raw.ListenPacket(intf.Name)
	if err != nil {
		return nil, fmt.Errorf("gateway: open raw socket: %w", err)
	}
	defer conn.Close()
	return ResolveMACWithConn(conn, srcIP, srcMAC, nextHop, timeout)
}

// ResolveMACWithConn performs ARP resolution over an existing raw conn.
func ResolveMACWithConn(conn raw.PacketConn, srcIP net.IP, srcMAC net.HardwareAddr,
	nextHop net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	if srcIP.To4() == nil || nextHop.To4() == nil {
		return nil, errors.New("gateway: IPv4 only")
	}
	if len(srcMAC) == 0 {
		return nil, errors.New("gateway: source MAC required for ARP")
	}
	req, err := buildARPRequest(srcMAC, srcIP, nextHop)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	// We may need to retransmit a couple of times because the RX queue we
	// just opened may drop early frames.
	for retries := 0; retries < 3 && time.Now().Before(deadline); retries++ {
		if _, err := conn.WriteTo(req); err != nil {
			return nil, fmt.Errorf("gateway: write arp: %w", err)
		}
		buf := make([]byte, 1500)
		stop := time.Now().Add(timeout / 3)
		for time.Now().Before(stop) {
			n, err := conn.ReadFrom(buf)
			if err != nil {
				break
			}
			mac, ok := parseARPReply(buf[:n], nextHop, srcIP)
			if ok {
				return mac, nil
			}
		}
	}
	return nil, fmt.Errorf("gateway: ARP for %s timed out", nextHop)
}

func buildARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) ([]byte, error) {
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       bcast,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true},
		eth, arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseARPReply(frame []byte, expectSrcIP, expectDstIP net.IP) (net.HardwareAddr, bool) {
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)
	arpL := pkt.Layer(layers.LayerTypeARP)
	if arpL == nil {
		return nil, false
	}
	arp := arpL.(*layers.ARP)
	if arp.Operation != layers.ARPReply {
		return nil, false
	}
	if !net.IP(arp.SourceProtAddress).Equal(expectSrcIP.To4()) {
		return nil, false
	}
	if !net.IP(arp.DstProtAddress).Equal(expectDstIP.To4()) {
		return nil, false
	}
	mac := make(net.HardwareAddr, len(arp.SourceHwAddress))
	copy(mac, arp.SourceHwAddress)
	return mac, true
}
