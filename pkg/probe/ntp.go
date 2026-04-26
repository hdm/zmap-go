package probe

import (
	"encoding/binary"

	"github.com/gopacket/gopacket/layers"

	"github.com/hdm/zmap-go/pkg/packet"
)

// NTP is a UDP-based NTP v3/v4 client probe (mode=3, version=3) that parses
// 48-byte server replies and exposes the standard NTP header fields.
type NTP struct{ UDP }

// NewNTP returns an NTP probe.
func NewNTP(srcPortFirst, srcPortLast uint16, ttl uint8, ipOnly bool) *NTP {
	n := &NTP{UDP: UDP{
		Payload:      packet.NTPRequestPayload(),
		SrcPortFirst: srcPortFirst, SrcPortLast: srcPortLast,
		TTL: ttl, SendIPOnly: ipOnly,
	}}
	n.UDP.PostValidate = n.parseReply
	return n
}
func (m *NTP) Name() string { return "ntp" }

func (m *NTP) Fields() []FieldDef {
	return []FieldDef{
		{"ntp_li", FieldInt, "NTP leap indicator"},
		{"ntp_version", FieldInt, "NTP version"},
		{"ntp_mode", FieldInt, "NTP mode"},
		{"ntp_stratum", FieldInt, "NTP stratum"},
		{"ntp_poll", FieldInt, "NTP poll interval"},
		{"ntp_precision", FieldInt, "NTP precision (signed 8-bit)"},
		{"ntp_root_delay", FieldInt, "NTP root delay (NTP short format)"},
		{"ntp_root_dispersion", FieldInt, "NTP root dispersion"},
		{"ntp_ref_id", FieldInt, "NTP reference identifier"},
	}
}

func (m *NTP) parseReply(r *Result, udp *layers.UDP) bool {
	if len(udp.Payload) < 48 {
		r.Classification = "ntp_short"
		return true
	}
	p := udp.Payload
	flags := p[0]
	r.Extra["ntp_li"] = uint64(flags >> 6)
	r.Extra["ntp_version"] = uint64((flags >> 3) & 7)
	r.Extra["ntp_mode"] = uint64(flags & 7)
	r.Extra["ntp_stratum"] = uint64(p[1])
	r.Extra["ntp_poll"] = uint64(int8(p[2]))
	r.Extra["ntp_precision"] = uint64(int8(p[3]))
	r.Extra["ntp_root_delay"] = uint64(binary.BigEndian.Uint32(p[4:8]))
	r.Extra["ntp_root_dispersion"] = uint64(binary.BigEndian.Uint32(p[8:12]))
	r.Extra["ntp_ref_id"] = uint64(binary.BigEndian.Uint32(p[12:16]))
	r.Classification = "ntp"
	return true
}
