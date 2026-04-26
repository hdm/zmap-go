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
}

func (m *UDP) Name() string { return "udp" }
func (m *UDP) MaxPacketLen() int {
	return 14 + 20 + 8 + len(m.Payload)
}

func (m *UDP) numPorts() uint16 { return m.SrcPortLast - m.SrcPortFirst + 1 }

func (m *UDP) BuildProbe(srcIP, dstIP net.IP, dstPort uint16,
	srcMAC, dstMAC net.HardwareAddr, ipID uint16, t [4]uint32) ([]byte, uint16, error) {
	srcPort := SrcPortFor(m.numPorts(), m.SrcPortFirst, t)
	pkt, err := packet.BuildUDP(packet.UDPParams{
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
	// Direct UDP reply: src=remote, dst=us. Re-derive tuple from remote port.
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
			Classification: "udp", Success: true,
		}, true
	}
	// ICMP unreachable carrying our IPv4+UDP header.
	if icmpL := p.Layer(layers.LayerTypeICMPv4); icmpL != nil {
		icmp := icmpL.(*layers.ICMPv4)
		if icmp.TypeCode.Type() != layers.ICMPv4TypeDestinationUnreachable {
			return nil, false
		}
		// gopacket parses the embedded IP via ICMPv4 payload; decode ourselves.
		payload := icmp.Payload
		if len(payload) < 28 {
			return nil, false
		}
		innerIP := &layers.IPv4{}
		if err := innerIP.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return nil, false
		}
		if int(innerIP.IHL)*4+8 > len(payload) {
			return nil, false
		}
		innerUDP := &layers.UDP{}
		if err := innerUDP.DecodeFromBytes(payload[innerIP.IHL*4:], gopacket.NilDecodeFeedback); err != nil {
			return nil, false
		}
		// dst port of our original probe is innerUDP.DstPort; src port (ours) innerUDP.SrcPort.
		t := v.GenWords(ipBE(srcIP), ipBE(innerIP.DstIP), uint32(innerUDP.DstPort), 0)
		if !VerifyDstPortMatches(uint16(innerUDP.SrcPort), m.numPorts(), m.SrcPortFirst, t) {
			return nil, false
		}
		return &Result{
			SrcIP: ip.SrcIP, DstIP: ip.DstIP,
			SrcPort: uint16(innerUDP.SrcPort), DstPort: uint16(innerUDP.DstPort),
			Classification: "icmp_unreach", Success: false,
		}, true
	}
	return nil, false
}
