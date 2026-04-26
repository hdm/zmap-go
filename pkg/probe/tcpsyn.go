package probe

import (
	"encoding/binary"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/hdm/zmap-go/pkg/packet"
	"github.com/hdm/zmap-go/pkg/validate"
)

// TCPSyn is the zmap "tcp_synscan" probe module.
type TCPSyn struct {
	Style        packet.TCPOptionStyle
	SrcPortFirst uint16
	SrcPortLast  uint16
	TTL          uint8
	SendIPOnly   bool
}

func (m *TCPSyn) Name() string      { return "tcp_synscan" }
func (m *TCPSyn) MaxPacketLen() int { return m.Style.PacketLen() }

func (m *TCPSyn) Fields() []FieldDef {
	return []FieldDef{
		{"seq", FieldInt, "TCP sequence number of response"},
		{"ack", FieldInt, "TCP acknowledgement number of response"},
		{"window", FieldInt, "TCP window of response"},
	}
}

func (m *TCPSyn) numPorts() uint16 {
	return m.SrcPortLast - m.SrcPortFirst + 1
}

func (m *TCPSyn) BuildProbe(srcIP, dstIP net.IP, dstPort uint16,
	srcMAC, dstMAC net.HardwareAddr, ipID uint16, t [4]uint32) ([]byte, uint16, error) {
	srcPort := SrcPortFor(m.numPorts(), m.SrcPortFirst, t)
	pkt, err := packet.BuildSYN(packet.SynParams{
		SrcMAC:     srcMAC,
		DstMAC:     dstMAC,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Seq:        t[0],
		IPID:       ipID,
		TTL:        m.TTL,
		Style:      m.Style,
		SendIPOnly: m.SendIPOnly,
	})
	return pkt, srcPort, err
}

// ValidatePacket inspects an inbound packet for a SYN+ACK or RST that matches
// one of our outstanding probes. It re-derives the validation tuple from the
// packet's source IP, our local IP, and the packet's source port (which was
// our probe's destination port).
func (m *TCPSyn) ValidatePacket(p gopacket.Packet, v *validate.Validator,
	srcIP net.IP, _, _ uint16) (*Result, bool) {
	ipL := p.Layer(layers.LayerTypeIPv4)
	if ipL == nil {
		return nil, false
	}
	ip := ipL.(*layers.IPv4)
	if !ip.DstIP.Equal(srcIP) {
		return nil, false
	}
	tcpL := p.Layer(layers.LayerTypeTCP)
	if tcpL == nil {
		return nil, false
	}
	tcp := tcpL.(*layers.TCP)
	// reply: src=remote, dst=us. dport is our former sport. sport is the
	// remote port we probed.
	remoteIP := ip.SrcIP
	remotePort := uint16(tcp.SrcPort)
	ourPort := uint16(tcp.DstPort)
	// Re-derive validation tuple using IPs in network byte order interpreted
	// as host-order uint32 (zmap stores them that way; here we stick to a
	// stable byte->uint32 in big-endian since that's how AES sees them).
	t := v.GenWords(ipBE(srcIP), ipBE(remoteIP), uint32(remotePort), 0)
	if !VerifyDstPortMatches(ourPort, m.numPorts(), m.SrcPortFirst, t) {
		return nil, false
	}
	// SYN+ACK: ack == seq+1
	extra := map[string]any{
		"seq":    uint64(tcp.Seq),
		"ack":    uint64(tcp.Ack),
		"window": uint64(tcp.Window),
	}
	if tcp.SYN && tcp.ACK {
		if tcp.Ack != t[0]+1 {
			return nil, false
		}
		return &Result{
			SrcIP: remoteIP, DstIP: ip.DstIP,
			SrcPort: remotePort, DstPort: ourPort,
			IPID: ip.Id, TTL: ip.TTL,
			Classification: "synack", Success: true,
			Extra: extra,
		}, true
	}
	if tcp.RST {
		if tcp.Ack != t[0] && tcp.Ack != t[0]+1 {
			return nil, false
		}
		return &Result{
			SrcIP: remoteIP, DstIP: ip.DstIP,
			SrcPort: remotePort, DstPort: ourPort,
			IPID: ip.Id, TTL: ip.TTL,
			Classification: "rst", Success: false,
			Extra: extra,
		}, true
	}
	return nil, false
}

func ipBE(ip net.IP) uint32 {
	b := ip.To4()
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
