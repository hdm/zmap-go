package probe

import (
	"encoding/binary"
	"net"
	"time"

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
	return 14 + 20 + 8 + len(m.Payload)
}

func (m *IcmpEcho) Fields() []FieldDef {
	return []FieldDef{
		{"icmp_type", FieldInt, "ICMP message type"},
		{"icmp_code", FieldInt, "ICMP message sub-type code"},
		{"icmp_id", FieldInt, "ICMP id number"},
		{"icmp_seq", FieldInt, "ICMP sequence number"},
		{"icmp_data", FieldBinary, "ICMP payload"},
	}
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
	itype := icmp.TypeCode.Type()
	icode := icmp.TypeCode.Code()

	// Echo reply: re-derive tuple directly.
	if itype == layers.ICMPv4TypeEchoReply {
		t := v.GenWords(ipBE(srcIP), ipBE(ip.SrcIP), 0, 0)
		if uint16(t[1]) != icmp.Id || uint16(t[2]) != icmp.Seq {
			return nil, false
		}
		return &Result{
			SrcIP: ip.SrcIP, DstIP: ip.DstIP,
			IPID: ip.Id, TTL: ip.TTL,
			Classification: "echoreply", Success: true,
			Extra: map[string]any{
				"icmp_type": uint64(itype),
				"icmp_code": uint64(icode),
				"icmp_id":   uint64(icmp.Id),
				"icmp_seq":  uint64(icmp.Seq),
				"icmp_data": append([]byte(nil), icmp.Payload...),
			},
		}, true
	}
	// Error responses (dest unreachable, time exceeded, etc.) carry our
	// original IP+ICMP header — re-derive tuple from them.
	if itype == layers.ICMPv4TypeDestinationUnreachable ||
		itype == layers.ICMPv4TypeTimeExceeded ||
		itype == layers.ICMPv4TypeSourceQuench ||
		itype == layers.ICMPv4TypeRedirect ||
		itype == layers.ICMPv4TypeParameterProblem {
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
		innerICMP := &layers.ICMPv4{}
		if err := innerICMP.DecodeFromBytes(payload[hdrLen:], gopacket.NilDecodeFeedback); err != nil {
			return nil, false
		}
		t := v.GenWords(ipBE(srcIP), ipBE(innerIP.DstIP), 0, 0)
		if uint16(t[1]) != innerICMP.Id || uint16(t[2]) != innerICMP.Seq {
			return nil, false
		}
		return &Result{
			SrcIP: ip.SrcIP, DstIP: ip.DstIP,
			IPID: ip.Id, TTL: ip.TTL,
			Classification: classifyICMP(itype), Success: false,
			Extra: map[string]any{
				"icmp_type": uint64(itype),
				"icmp_code": uint64(icode),
				"icmp_id":   uint64(innerICMP.Id),
				"icmp_seq":  uint64(innerICMP.Seq),
			},
		}, true
	}
	return nil, false
}

func classifyICMP(t uint8) string {
	switch t {
	case layers.ICMPv4TypeDestinationUnreachable:
		return "icmp_unreach"
	case layers.ICMPv4TypeTimeExceeded:
		return "icmp_ttl_exceeded"
	case layers.ICMPv4TypeSourceQuench:
		return "icmp_source_quench"
	case layers.ICMPv4TypeRedirect:
		return "icmp_redirect"
	case layers.ICMPv4TypeParameterProblem:
		return "icmp_param_problem"
	}
	return "icmp_other"
}

// IcmpEchoTime is ICMP echo carrying an 8-byte timestamp (microseconds since
// epoch, big-endian) that is echoed back, allowing per-probe RTT.
type IcmpEchoTime struct {
	IcmpEcho
}

// NewIcmpEchoTime returns the timestamped ICMP echo probe.
func NewIcmpEchoTime(ttl uint8, ipOnly bool) *IcmpEchoTime {
	// 16-byte payload: 8 bytes timestamp + 8 bytes pad. We stamp at build time.
	return &IcmpEchoTime{IcmpEcho: IcmpEcho{
		Payload: make([]byte, 16),
		TTL:     ttl, SendIPOnly: ipOnly,
	}}
}
func (m *IcmpEchoTime) Name() string { return "icmp_echo_time" }
func (m *IcmpEchoTime) Fields() []FieldDef {
	return append(m.IcmpEcho.Fields(),
		FieldDef{"sent_timestamp_us", FieldInt, "probe send time, µs since epoch"},
		FieldDef{"recv_timestamp_us", FieldInt, "response receive time, µs since epoch"},
		FieldDef{"latency_us", FieldInt, "round-trip latency, µs"},
	)
}

// BuildProbe stamps the current monotonic-µs into the first 8 payload bytes.
func (m *IcmpEchoTime) BuildProbe(srcIP, dstIP net.IP, dport uint16,
	srcMAC, dstMAC net.HardwareAddr, ipID uint16, t [4]uint32) ([]byte, uint16, error) {
	now := uint64(time.Now().UnixMicro())
	if len(m.Payload) >= 8 {
		binary.BigEndian.PutUint64(m.Payload[:8], now)
	}
	return m.IcmpEcho.BuildProbe(srcIP, dstIP, dport, srcMAC, dstMAC, ipID, t)
}

func (m *IcmpEchoTime) ValidatePacket(p gopacket.Packet, v *validate.Validator,
	srcIP net.IP, a, b uint16) (*Result, bool) {
	r, ok := m.IcmpEcho.ValidatePacket(p, v, srcIP, a, b)
	if !ok {
		return r, ok
	}
	now := uint64(time.Now().UnixMicro())
	r.Extra["recv_timestamp_us"] = now
	if data, ok2 := r.Extra["icmp_data"].([]byte); ok2 && len(data) >= 8 {
		sent := binary.BigEndian.Uint64(data[:8])
		r.Extra["sent_timestamp_us"] = sent
		if now > sent {
			r.Extra["latency_us"] = now - sent
		}
	}
	return r, ok
}
