package packet

import (
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// UDPParams describes a UDP probe.
type UDPParams struct {
	SrcMAC, DstMAC net.HardwareAddr
	SrcIP, DstIP   net.IP
	SrcPort        uint16
	DstPort        uint16
	IPID           uint16
	TTL            uint8
	Payload        []byte
	SendIPOnly     bool
}

// BuildUDP serializes a UDP probe with raw payload into a fresh buffer.
func BuildUDP(p UDPParams) ([]byte, error) {
	return BuildUDPInto(gopacket.NewSerializeBuffer(), p)
}

// BuildUDPInto serializes a UDP probe into the provided buffer.
func BuildUDPInto(buf gopacket.SerializeBuffer, p UDPParams) ([]byte, error) {
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
		Protocol: layers.IPProtocolUDP,
		SrcIP:    p.SrcIP.To4(),
		DstIP:    p.DstIP.To4(),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(p.SrcPort),
		DstPort: layers.UDPPort(p.DstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	payload := gopacket.Payload(p.Payload)
	if p.SendIPOnly {
		if err := gopacket.SerializeLayers(buf, SerializeOptions, ip, udp, payload); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	eth := &layers.Ethernet{SrcMAC: p.SrcMAC, DstMAC: p.DstMAC, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buf, SerializeOptions, eth, ip, udp, payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SynAckParams describes a TCP SYN+ACK probe (used by tcp_synackscan).
type SynAckParams struct {
	SrcMAC, DstMAC net.HardwareAddr
	SrcIP, DstIP   net.IP
	SrcPort        uint16
	DstPort        uint16
	Seq            uint32
	Ack            uint32
	IPID           uint16
	TTL            uint8
	SendIPOnly     bool
}

// BuildSYNACK serializes a SYN+ACK probe (one MSS option).
func BuildSYNACK(p SynAckParams) ([]byte, error) {
	return BuildSYNACKInto(gopacket.NewSerializeBuffer(), p)
}

// BuildSYNACKInto serializes a SYN+ACK probe into the provided buffer.
func BuildSYNACKInto(buf gopacket.SerializeBuffer, p SynAckParams) ([]byte, error) {
	if p.SrcIP.To4() == nil || p.DstIP.To4() == nil {
		return nil, fmt.Errorf("packet: IPv4 only")
	}
	ttl := p.TTL
	if ttl == 0 {
		ttl = 255
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: ttl, Id: p.IPID,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    p.SrcIP.To4(), DstIP: p.DstIP.To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(p.SrcPort),
		DstPort: layers.TCPPort(p.DstPort),
		Seq:     p.Seq, Ack: p.Ack,
		SYN: true, ACK: true, Window: 65535,
		Options: []layers.TCPOption{{
			OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4},
		}},
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
	eth := &layers.Ethernet{SrcMAC: p.SrcMAC, DstMAC: p.DstMAC, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buf, SerializeOptions, eth, ip, tcp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// NTPRequestPayload returns a 48-byte NTP v3 client request body.
//
// Field LI=0, VN=3 (or 4), Mode=3 (client) -> first byte = (0<<6)|(3<<3)|3 = 27
// upstream zmap uses 227 (LI=3 unknown, VN=4, Mode=3), we follow that.
func NTPRequestPayload() []byte {
	b := make([]byte, 48)
	b[0] = 227
	return b
}

// DNSQueryPayload builds a minimal DNS query body for class IN.
func DNSQueryPayload(name string, qtype uint16, txnID uint16) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("packet: empty dns name")
	}
	q := &layers.DNS{
		ID:      txnID,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      true,
		QDCount: 1,
		Questions: []layers.DNSQuestion{{
			Name:  []byte(name),
			Type:  layers.DNSType(qtype),
			Class: layers.DNSClassIN,
		}},
	}
	buf := gopacket.NewSerializeBuffer()
	if err := q.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
