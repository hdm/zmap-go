package probe

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/hdm/zmap-go/pkg/packet"
	"github.com/hdm/zmap-go/pkg/validate"
)

// IcmpEcho is the zmap "icmp_echo" probe module.
type IcmpEcho struct {
	Payload    []byte
	TTL        uint8
	SendIPOnly bool
}

func (m *IcmpEcho) Name() string { return "icmp_echo" }
func (m *IcmpEcho) MaxPacketLen() int {
	// Eth(14) + IPv4(20) + ICMP(8) + payload
	return 14 + 20 + 8 + len(m.Payload)
}

func (m *IcmpEcho) BuildProbe(srcIP, dstIP net.IP, _ uint16,
	srcMAC, dstMAC net.HardwareAddr, ipID uint16, t [4]uint32) ([]byte, uint16, error) {
	pkt, err := packet.BuildICMPEcho(packet.IcmpEchoParams{
		SrcMAC:     srcMAC,
		DstMAC:     dstMAC,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		ID:         uint16(t[1]),
		Seq:        uint16(t[2]),
		IPID:       ipID,
		TTL:        m.TTL,
		Payload:    m.Payload,
		SendIPOnly: m.SendIPOnly,
	})
	return pkt, 0, err
}

func (m *IcmpEcho) ValidatePacket(p gopacket.Packet, v *validate.Validator,
	srcIP net.IP, _, _ uint16) (*Result, bool) {
	ipL := p.Layer(layers.LayerTypeIPv4)
	if ipL == nil {
		return nil, false
	}
	ip := ipL.(*layers.IPv4)
	if !ip.DstIP.Equal(srcIP) {
		return nil, false
	}
	icmpL := p.Layer(layers.LayerTypeICMPv4)
	if icmpL == nil {
		return nil, false
	}
	icmp := icmpL.(*layers.ICMPv4)
	if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoReply {
		return nil, false
	}
	t := v.GenWords(ipBE(srcIP), ipBE(ip.SrcIP), 0, 0)
	if uint16(t[1]) != icmp.Id || uint16(t[2]) != icmp.Seq {
		return nil, false
	}
	_ = packet.SerializeOptions
	return &Result{
		SrcIP: ip.SrcIP, DstIP: ip.DstIP,
		Classification: "echoreply", Success: true,
	}, true
}
