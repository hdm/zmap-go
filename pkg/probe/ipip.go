package probe

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/hdm/zmap-go/pkg/packet"
	"github.com/hdm/zmap-go/pkg/validate"
)

// IPIP wraps a UDP probe in an outer IPv4(proto=4 IPIP) header. The reply
// path also expects an outer IPIP frame containing an inner IP+UDP.
//
// Mirrors src/probe_modules/module_ipip.c.
type IPIP struct {
	Payload      []byte
	SrcPortFirst uint16
	SrcPortLast  uint16
	TTL          uint8
	SendIPOnly   bool
}

// NewIPIP returns an IPIP UDP probe.
func NewIPIP(payload []byte, srcFirst, srcLast uint16, ttl uint8, ipOnly bool) *IPIP {
	if payload == nil {
		payload = []byte("GET / HTTP/1.1\r\nHost: www\r\n\r\n")
	}
	return &IPIP{Payload: payload, SrcPortFirst: srcFirst, SrcPortLast: srcLast, TTL: ttl, SendIPOnly: ipOnly}
}
func (m *IPIP) Name() string { return "ipip" }
func (m *IPIP) MaxPacketLen() int {
	return 14 + 20 + 20 + 8 + len(m.Payload)
}
func (m *IPIP) Fields() []FieldDef {
	return []FieldDef{{"data", FieldBinary, "UDP payload"}}
}
func (m *IPIP) numPorts() uint16 { return m.SrcPortLast - m.SrcPortFirst + 1 }

// BuildProbe builds outer-IPv4(proto=IPIP) carrying inner-IPv4(proto=UDP).
func (m *IPIP) BuildProbe(srcIP, dstIP net.IP, dstPort uint16,
	srcMAC, dstMAC net.HardwareAddr, ipID uint16, t [4]uint32) ([]byte, uint16, error) {
	return m.BuildProbeInto(gopacket.NewSerializeBuffer(), srcIP, dstIP, dstPort, srcMAC, dstMAC, ipID, t)
}

// BuildProbeInto serializes the encapsulated probe into buf.
func (m *IPIP) BuildProbeInto(buf gopacket.SerializeBuffer,
	srcIP, dstIP net.IP, dstPort uint16,
	srcMAC, dstMAC net.HardwareAddr, ipID uint16, t [4]uint32) ([]byte, uint16, error) {
	srcPort := SrcPortFor(m.numPorts(), m.SrcPortFirst, t)

	innerIP := &layers.IPv4{
		Version: 4, IHL: 5, TTL: m.TTL, Id: ipID,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP.To4(), DstIP: dstIP.To4(),
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(innerIP); err != nil {
		return nil, 0, err
	}

	outerIP := &layers.IPv4{
		Version: 4, IHL: 5, TTL: m.TTL, Id: ipID,
		Protocol: layers.IPProtocolIPv4, // IPIP / proto 4
		SrcIP:    srcIP.To4(), DstIP: dstIP.To4(),
	}

	pl := gopacket.Payload(m.Payload)
	if m.SendIPOnly {
		if err := gopacket.SerializeLayers(buf, packet.SerializeOptions, outerIP, innerIP, udp, pl); err != nil {
			return nil, 0, err
		}
		return buf.Bytes(), srcPort, nil
	}
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buf, packet.SerializeOptions, eth, outerIP, innerIP, udp, pl); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), srcPort, nil
}

// ValidatePacket accepts replies that are IPv4 to us, either:
// (a) plain UDP (some peers reply un-encapsulated), or
// (b) outer IPv4(proto=4) carrying inner IPv4+UDP.
func (m *IPIP) ValidatePacket(p gopacket.Packet, v *validate.Validator,
	srcIP net.IP, _, _ uint16) (*Result, bool) {
	ipL := p.Layer(layers.LayerTypeIPv4)
	if ipL == nil {
		return nil, false
	}
	ip := ipL.(*layers.IPv4)
	if !ip.DstIP.Equal(srcIP) {
		return nil, false
	}
	// Plain UDP reply (un-encapsulated)
	if udpL := p.Layer(layers.LayerTypeUDP); udpL != nil {
		udp := udpL.(*layers.UDP)
		remotePort := uint16(udp.SrcPort)
		ourPort := uint16(udp.DstPort)
		t := v.GenWords(ipBE(srcIP), ipBE(ip.SrcIP), uint32(remotePort), 0)
		if !VerifyDstPortMatches(ourPort, m.numPorts(), m.SrcPortFirst, t) {
			return nil, false
		}
		return &Result{
			SrcIP: ip.SrcIP, DstIP: ip.DstIP,
			SrcPort: remotePort, DstPort: ourPort,
			IPID: ip.Id, TTL: ip.TTL,
			Classification: "udp", Success: true,
			Extra: map[string]any{"data": append([]byte(nil), udp.Payload...)},
		}, true
	}
	// Encapsulated: ip.Protocol == IPv4(4), payload is another IP packet.
	if ip.Protocol == layers.IPProtocolIPv4 {
		innerIP := &layers.IPv4{}
		if err := innerIP.DecodeFromBytes(ip.Payload, gopacket.NilDecodeFeedback); err != nil {
			return nil, false
		}
		if innerIP.Protocol != layers.IPProtocolUDP {
			return nil, false
		}
		hdrLen := int(innerIP.IHL) * 4
		if hdrLen+8 > len(ip.Payload) {
			return nil, false
		}
		innerUDP := &layers.UDP{}
		if err := innerUDP.DecodeFromBytes(ip.Payload[hdrLen:], gopacket.NilDecodeFeedback); err != nil {
			return nil, false
		}
		remotePort := uint16(innerUDP.SrcPort)
		ourPort := uint16(innerUDP.DstPort)
		t := v.GenWords(ipBE(srcIP), ipBE(innerIP.SrcIP), uint32(remotePort), 0)
		if !VerifyDstPortMatches(ourPort, m.numPorts(), m.SrcPortFirst, t) {
			return nil, false
		}
		return &Result{
			SrcIP: innerIP.SrcIP, DstIP: innerIP.DstIP,
			SrcPort: remotePort, DstPort: ourPort,
			IPID: innerIP.Id, TTL: innerIP.TTL,
			Classification: "ipip-udp", Success: true,
			Extra: map[string]any{"data": append([]byte(nil), innerUDP.Payload...)},
		}, true
	}
	return nil, false
}
