package probe

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/hdm/zmap-go/pkg/packet"
	"github.com/hdm/zmap-go/pkg/validate"
)

// TCPSynAck implements zmap's tcp_synackscan: sends SYN+ACK and watches for
// RST replies. Some hosts/firewalls respond to SYN+ACK with RST even when
// the port is closed; this allows liveness detection without a 3WH.
type TCPSynAck struct {
	SrcPortFirst uint16
	SrcPortLast  uint16
	TTL          uint8
	SendIPOnly   bool
}

func (m *TCPSynAck) Name() string      { return "tcp_synackscan" }
func (m *TCPSynAck) MaxPacketLen() int { return 14 + 20 + 24 } // MSS-only

func (m *TCPSynAck) numPorts() uint16 { return m.SrcPortLast - m.SrcPortFirst + 1 }

func (m *TCPSynAck) BuildProbe(srcIP, dstIP net.IP, dstPort uint16,
	srcMAC, dstMAC net.HardwareAddr, ipID uint16, t [4]uint32) ([]byte, uint16, error) {
	srcPort := SrcPortFor(m.numPorts(), m.SrcPortFirst, t)
	pkt, err := packet.BuildSYNACK(packet.SynAckParams{
		SrcMAC: srcMAC, DstMAC: dstMAC,
		SrcIP: srcIP, DstIP: dstIP,
		SrcPort: srcPort, DstPort: dstPort,
		Seq: t[0], Ack: t[2],
		IPID: ipID, TTL: m.TTL,
		SendIPOnly: m.SendIPOnly,
	})
	return pkt, srcPort, err
}

func (m *TCPSynAck) ValidatePacket(p gopacket.Packet, v *validate.Validator,
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
	remotePort := uint16(tcp.SrcPort)
	ourPort := uint16(tcp.DstPort)
	t := v.GenWords(ipBE(srcIP), ipBE(ip.SrcIP), uint32(remotePort), 0)
	if !VerifyDstPortMatches(ourPort, m.numPorts(), m.SrcPortFirst, t) {
		return nil, false
	}
	if tcp.RST {
		// per zmap's synackscan validation: ack==seq+1 OR seq==ack OR seq==ack+1
		if tcp.Ack != t[0]+1 && tcp.Seq != t[2] && tcp.Seq != t[2]+1 {
			return nil, false
		}
		return &Result{
			SrcIP: ip.SrcIP, DstIP: ip.DstIP,
			SrcPort: remotePort, DstPort: ourPort,
			Classification: "rst", Success: true,
		}, true
	}
	if tcp.Ack != t[0]+1 {
		return nil, false
	}
	return &Result{
		SrcIP: ip.SrcIP, DstIP: ip.DstIP,
		SrcPort: remotePort, DstPort: ourPort,
		Classification: "tcp", Success: true,
	}, true
}
