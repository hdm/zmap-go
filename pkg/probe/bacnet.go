package probe

import (
	"github.com/gopacket/gopacket/layers"
)

// BACnet sends a BACnet/IP ReadProperty(deviceObject) over UDP/47808.
// Mirrors src/probe_modules/module_bacnet.c.
//
// Wire format (17 bytes):
//
//	BVLC: 81 0a 00 11
//	NPDU: 01 04
//	APDU: 00 05 0c 0c 02 3f ff ff 19 4b
type BACnet struct{ UDP }

func bacnetPayload() []byte {
	return []byte{
		0x81, 0x0a, 0x00, 0x11, // BVLC: type=BACnet/IP, function=Unicast-NPDU, length=17
		0x01, 0x04, // NPDU: version=1, control=expecting-reply
		0x00, 0x05, 0x01, 0x0c, // APDU: type_flags, max-segments-apdu, invoke_id, server_choice=ReadProperty
		0x0c, 0x02, 0x3f, 0xff, 0xff, // ObjectIdentifier: device(8), instance=0x3FFFFF
		0x19, 0x4b, // PropertyIdentifier: vendor-id (75 = 0x4b)
	}
}

// NewBACnet returns a BACnet probe.
func NewBACnet(srcFirst, srcLast uint16, ttl uint8, ipOnly bool) *BACnet {
	b := &BACnet{UDP: UDP{
		Payload:      bacnetPayload(),
		SrcPortFirst: srcFirst, SrcPortLast: srcLast,
		TTL: ttl, SendIPOnly: ipOnly,
	}}
	b.UDP.PostValidate = b.parseReply
	return b
}
func (m *BACnet) Name() string { return "bacnet" }
func (m *BACnet) Fields() []FieldDef {
	return []FieldDef{
		{"bvlc_type", FieldInt, "BVLC type"},
		{"bvlc_function", FieldInt, "BVLC function"},
		{"bvlc_length", FieldInt, "BVLC length"},
		{"data", FieldBinary, "raw UDP payload"},
	}
}

func (m *BACnet) parseReply(r *Result, udp *layers.UDP) bool {
	r.Extra["data"] = append([]byte(nil), udp.Payload...)
	if len(udp.Payload) < 4 || udp.Payload[0] != 0x81 {
		r.Classification = "non-bacnet"
		r.Success = false
		return true
	}
	r.Extra["bvlc_type"] = uint64(udp.Payload[0])
	r.Extra["bvlc_function"] = uint64(udp.Payload[1])
	r.Extra["bvlc_length"] = uint64(uint16(udp.Payload[2])<<8 | uint16(udp.Payload[3]))
	r.Classification = "bacnet"
	return true
}
