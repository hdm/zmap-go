package probe

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/hdm/zmap-go/pkg/packet"
	"github.com/hdm/zmap-go/pkg/validate"
)

// UDP is a generic UDP probe module. Sends a fixed payload to dstPort and
// validates either a UDP reply on the same flow or an ICMP unreachable that
// quotes our outgoing UDP header.
type UDP struct {
	Payload      []byte
	SrcPortFirst uint16
	SrcPortLast  uint16
	TTL          uint8
	SendIPOnly   bool

	// PostValidate, if non-nil, is invoked on a successful UDP reply with
	// the parsed UDP layer. It may populate r.Extra with module-specific
	// fields and may downgrade by returning false to reject the reply.
	PostValidate func(r *Result, udp *layers.UDP) bool
}

func (m *UDP) Name() string { return "udp" }
func (m *UDP) MaxPacketLen() int {
	return 14 + 20 + 8 + len(m.Payload)
}

func (m *UDP) Fields() []FieldDef {
	return []FieldDef{
		{"udp_pkt_size", FieldInt, "UDP packet length"},
		{"data", FieldBinary, "UDP payload"},
		{"icmp_responder", FieldString, "if ICMP error: responding host"},
		{"icmp_type", FieldInt, "if ICMP error: type"},
		{"icmp_code", FieldInt, "if ICMP error: code"},
		{"icmp_unreach_str", FieldString, "if ICMP error: textual reason"},
	}
}

func (m *UDP) numPorts() uint16 { return m.SrcPortLast - m.SrcPortFirst + 1 }

func (m *UDP) BuildProbe(srcIP, dstIP net.IP, dstPort uint16,
	srcMAC, dstMAC net.HardwareAddr, ipID uint16, t [4]uint32) ([]byte, uint16, error) {
	return m.BuildProbeInto(gopacket.NewSerializeBuffer(), srcIP, dstIP, dstPort, srcMAC, dstMAC, ipID, t)
}

// BuildProbeInto serializes the UDP probe into the provided buffer.
func (m *UDP) BuildProbeInto(buf gopacket.SerializeBuffer,
	srcIP, dstIP net.IP, dstPort uint16,
	srcMAC, dstMAC net.HardwareAddr, ipID uint16, t [4]uint32) ([]byte, uint16, error) {
	srcPort := SrcPortFor(m.numPorts(), m.SrcPortFirst, t)
	pkt, err := packet.BuildUDPInto(buf, packet.UDPParams{
		SrcMAC: srcMAC, DstMAC: dstMAC,
		SrcIP: srcIP, DstIP: dstIP,
		SrcPort: srcPort, DstPort: dstPort,
		IPID:       ipID,
		TTL:        m.TTL,
		Payload:    m.Payload,
		SendIPOnly: m.SendIPOnly,
	})
	return pkt, srcPort, err
}

func (m *UDP) ValidatePacket(p gopacket.Packet, v *validate.Validator,
	srcIP net.IP, _, _ uint16) (*Result, bool) {
	ipL := p.Layer(layers.LayerTypeIPv4)
	if ipL == nil {
		return nil, false
	}
	ip := ipL.(*layers.IPv4)
	if !ip.DstIP.Equal(srcIP) {
		return nil, false
	}
	// Direct UDP reply.
	if udpL := p.Layer(layers.LayerTypeUDP); udpL != nil {
		udp := udpL.(*layers.UDP)
		remotePort := uint16(udp.SrcPort)
		ourPort := uint16(udp.DstPort)
		t := v.GenWords(ipBE(srcIP), ipBE(ip.SrcIP), uint32(remotePort), 0)
		if !VerifyDstPortMatches(ourPort, m.numPorts(), m.SrcPortFirst, t) {
			return nil, false
		}
		r := &Result{
			SrcIP: ip.SrcIP, DstIP: ip.DstIP,
			SrcPort: remotePort, DstPort: ourPort,
			IPID: ip.Id, TTL: ip.TTL,
			Classification: "udp", Success: true,
			Extra: map[string]any{
				"udp_pkt_size": uint64(udp.Length),
				"data":         append([]byte(nil), udp.Payload...),
			},
		}
		if m.PostValidate != nil {
			if !m.PostValidate(r, udp) {
				return nil, false
			}
		}
		return r, true
	}
	// ICMP unreachable carrying our IPv4+UDP header.
	if icmpL := p.Layer(layers.LayerTypeICMPv4); icmpL != nil {
		icmp := icmpL.(*layers.ICMPv4)
		itype := icmp.TypeCode.Type()
		icode := icmp.TypeCode.Code()
		if itype != layers.ICMPv4TypeDestinationUnreachable &&
			itype != layers.ICMPv4TypeTimeExceeded {
			return nil, false
		}
		payload := icmp.Payload
		if len(payload) < 28 {
			return nil, false
		}
		innerIP := &layers.IPv4{}
		if err := innerIP.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return nil, false
		}
		hdrLen := int(innerIP.IHL) * 4
		if hdrLen+8 > len(payload) {
			return nil, false
		}
		innerUDP := &layers.UDP{}
		if err := innerUDP.DecodeFromBytes(payload[hdrLen:], gopacket.NilDecodeFeedback); err != nil {
			return nil, false
		}
		t := v.GenWords(ipBE(srcIP), ipBE(innerIP.DstIP), uint32(innerUDP.DstPort), 0)
		if !VerifyDstPortMatches(uint16(innerUDP.SrcPort), m.numPorts(), m.SrcPortFirst, t) {
			return nil, false
		}
		return &Result{
			SrcIP: ip.SrcIP, DstIP: ip.DstIP,
			SrcPort: uint16(innerUDP.SrcPort), DstPort: uint16(innerUDP.DstPort),
			IPID: ip.Id, TTL: ip.TTL,
			Classification: classifyICMP(itype), Success: false,
			Extra: map[string]any{
				"icmp_responder":   ip.SrcIP.String(),
				"icmp_type":        uint64(itype),
				"icmp_code":        uint64(icode),
				"icmp_unreach_str": icmpUnreachString(itype, icode),
			},
		}, true
	}
	return nil, false
}

func icmpUnreachString(itype, icode uint8) string {
	if itype != layers.ICMPv4TypeDestinationUnreachable {
		return ""
	}
	switch icode {
	case 0:
		return "network-unreachable"
	case 1:
		return "host-unreachable"
	case 2:
		return "protocol-unreachable"
	case 3:
		return "port-unreachable"
	case 4:
		return "fragmentation-needed"
	case 5:
		return "source-route-failed"
	case 6:
		return "destination-network-unknown"
	case 7:
		return "destination-host-unknown"
	case 9:
		return "network-administratively-prohibited"
	case 10:
		return "host-administratively-prohibited"
	case 13:
		return "communication-administratively-prohibited"
	}
	return "unknown"
}
