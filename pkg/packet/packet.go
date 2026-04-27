// Package packet builds zmap-style probe packets (Ethernet/IPv4/TCP/ICMPv4)
// using gopacket. CGO-free.
//
// This mirrors src/probe_modules/packet.c and the TCP option layouts in
// module_tcp_synscan.c. Only IPv4 is supported (matching upstream zmap).
package packet

import (
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// SerializeOptions used for all probe builds.
var SerializeOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

// TCPOptionStyle selects which TCP option set to attach to a SYN.
// Mirrors zmap's --probe-args=os values.
type TCPOptionStyle int

const (
	StyleSmallest TCPOptionStyle = iota
	StyleBSD
	StyleWindows
	StyleLinux
)

// ParseStyle parses a zmap probe-args style string.
func ParseStyle(s string) (TCPOptionStyle, error) {
	switch s {
	case "", "windows":
		return StyleWindows, nil
	case "smallest-probes", "smallest":
		return StyleSmallest, nil
	case "bsd":
		return StyleBSD, nil
	case "linux":
		return StyleLinux, nil
	}
	return 0, fmt.Errorf("packet: unknown TCP option style %q", s)
}

// HeaderLen returns the TCP header length (in bytes) for the given style.
func (s TCPOptionStyle) HeaderLen() int {
	switch s {
	case StyleSmallest:
		return 24
	case StyleBSD:
		return 44
	case StyleWindows:
		return 32
	case StyleLinux:
		return 40
	}
	return 20
}

// PacketLen returns the on-the-wire length (Ethernet + IPv4 + TCP) for SYN
// probes built with the given style.
func (s TCPOptionStyle) PacketLen() int {
	return 14 + 20 + s.HeaderLen()
}

// TCPSynOptions returns gopacket TCPOptions for the given style.
func (s TCPOptionStyle) TCPSynOptions() []layers.TCPOption {
	now := uint32(time.Now().Unix())
	tsBytes := []byte{byte(now >> 24), byte(now >> 16), byte(now >> 8), byte(now), 0, 0, 0, 0}

	mss := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xb4}, // 1460
	}
	nop := layers.TCPOption{OptionType: layers.TCPOptionKindNop, OptionLength: 1}
	sackPerm := layers.TCPOption{
		OptionType:   layers.TCPOptionKindSACKPermitted,
		OptionLength: 2,
	}
	ts := layers.TCPOption{
		OptionType:   layers.TCPOptionKindTimestamps,
		OptionLength: 10,
		OptionData:   tsBytes,
	}
	wscale := func(shift byte) layers.TCPOption {
		return layers.TCPOption{
			OptionType:   layers.TCPOptionKindWindowScale,
			OptionLength: 3,
			OptionData:   []byte{shift},
		}
	}
	eol := layers.TCPOption{OptionType: layers.TCPOptionKindEndList, OptionLength: 1}

	switch s {
	case StyleSmallest:
		// 4 bytes opts: just MSS  -> 24-byte TCP header
		return []layers.TCPOption{mss}
	case StyleWindows:
		// 12 bytes opts: MSS, NOP, WindowScale(8), SACKPermitted -> 32-byte
		return []layers.TCPOption{mss, nop, wscale(0x08), sackPerm}
	case StyleLinux:
		// 20 bytes opts: MSS, SACKPerm+TS (12), NOP, WS(7) -> 40-byte
		return []layers.TCPOption{mss, sackPerm, ts, nop, wscale(0x07)}
	case StyleBSD:
		// 24 bytes opts -> 44-byte TCP header
		return []layers.TCPOption{mss, nop, wscale(0x06), nop, nop, ts, sackPerm, eol}
	}
	return nil
}

// SynParams describes a single TCP SYN probe.
type SynParams struct {
	SrcMAC, DstMAC net.HardwareAddr
	SrcIP, DstIP   net.IP
	SrcPort        uint16
	DstPort        uint16
	Seq            uint32
	IPID           uint16
	TTL            uint8
	Style          TCPOptionStyle
	SendIPOnly     bool // skip Ethernet header (raw IP)
}

// BuildSYN serializes a SYN probe into a fresh buffer. Equivalent to
// BuildSYNInto(gopacket.NewSerializeBuffer(), p) and kept for backward
// compatibility; high-throughput callers should prefer BuildSYNInto with a
// pooled buffer to avoid per-packet allocation.
func BuildSYN(p SynParams) ([]byte, error) {
	return BuildSYNInto(gopacket.NewSerializeBuffer(), p)
}

// BuildSYNInto serializes a SYN probe into the provided SerializeBuffer.
// The buffer must be empty (Clear was just called or it is freshly created).
// The returned []byte aliases the buffer's storage and is invalidated by the
// next Clear() on buf.
func BuildSYNInto(buf gopacket.SerializeBuffer, p SynParams) ([]byte, error) {
	if p.SrcIP.To4() == nil || p.DstIP.To4() == nil {
		return nil, fmt.Errorf("packet: IPv4 only")
	}
	ttl := p.TTL
	if ttl == 0 {
		ttl = 255
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      ttl,
		Id:       p.IPID,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    p.SrcIP.To4(),
		DstIP:    p.DstIP.To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(p.SrcPort),
		DstPort: layers.TCPPort(p.DstPort),
		Seq:     p.Seq,
		SYN:     true,
		Window:  65535,
		Options: p.Style.TCPSynOptions(),
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	if p.SendIPOnly {
		if err := gopacket.SerializeLayers(buf, SerializeOptions, ip, tcp); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	eth := &layers.Ethernet{
		SrcMAC:       p.SrcMAC,
		DstMAC:       p.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	if err := gopacket.SerializeLayers(buf, SerializeOptions, eth, ip, tcp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// IcmpEchoParams describes a single ICMP echo probe.
type IcmpEchoParams struct {
	SrcMAC, DstMAC net.HardwareAddr
	SrcIP, DstIP   net.IP
	ID             uint16
	Seq            uint16
	IPID           uint16
	TTL            uint8
	Payload        []byte
	SendIPOnly     bool
}

// BuildICMPEcho serializes an ICMP echo request into a fresh buffer.
func BuildICMPEcho(p IcmpEchoParams) ([]byte, error) {
	return BuildICMPEchoInto(gopacket.NewSerializeBuffer(), p)
}

// BuildICMPEchoInto serializes an ICMP echo request into the provided buffer.
func BuildICMPEchoInto(buf gopacket.SerializeBuffer, p IcmpEchoParams) ([]byte, error) {
	if p.SrcIP.To4() == nil || p.DstIP.To4() == nil {
		return nil, fmt.Errorf("packet: IPv4 only")
	}
	ttl := p.TTL
	if ttl == 0 {
		ttl = 255
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      ttl,
		Id:       p.IPID,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    p.SrcIP.To4(),
		DstIP:    p.DstIP.To4(),
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       p.ID,
		Seq:      p.Seq,
	}
	payload := gopacket.Payload(p.Payload)
	if p.SendIPOnly {
		if err := gopacket.SerializeLayers(buf, SerializeOptions, ip, icmp, payload); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	eth := &layers.Ethernet{
		SrcMAC:       p.SrcMAC,
		DstMAC:       p.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	if err := gopacket.SerializeLayers(buf, SerializeOptions, eth, ip, icmp, payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
