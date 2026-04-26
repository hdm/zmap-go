// Package probe implements zmap's probe modules: tcp_synscan, tcp_synackscan,
// icmp_echo, icmp_echo_time, udp, dns, ntp, ntp_short, upnp, bacnet, ipip.
//
// A probe module knows how to:
//   - report the size and layout of probes it generates
//   - serialize a probe targeting (dstIP, dstPort) given a per-probe AES
//     validation tuple
//   - inspect an inbound packet, decide whether it is a response to one
//     of our probes, classify it (e.g. "synack", "rst", "echoreply"), and
//     extract module-specific fields into Result.Extra.
package probe

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/hdm/zmap-go/pkg/validate"
)

// FieldType is the declared type of a Result.Extra field, mirroring
// upstream's fielddef.type ("int", "string", "binary").
type FieldType string

const (
	FieldInt    FieldType = "int"
	FieldString FieldType = "string"
	FieldBinary FieldType = "binary"
	FieldBool   FieldType = "bool"
)

// FieldDef describes one Result.Extra field a module may populate.
type FieldDef struct {
	Name string
	Type FieldType
	Desc string
}

// CommonFields are the framework-supplied fields every module exposes.
func CommonFields() []FieldDef {
	return []FieldDef{
		{"saddr", FieldString, "source IP address of response"},
		{"daddr", FieldString, "destination IP address of response (us)"},
		{"sport", FieldInt, "source port of response"},
		{"dport", FieldInt, "destination port of response"},
		{"ipid", FieldInt, "IP identification number of response"},
		{"ttl", FieldInt, "TTL of response"},
		{"classification", FieldString, "packet classification"},
		{"success", FieldBool, "whether response is considered success"},
		{"repeat", FieldBool, "whether this is a duplicate response"},
	}
}

// Result is what a probe module emits from ValidatePacket on a successful match.
//
// Extra holds module-specific fields keyed by FieldDef.Name. Values may be
// int, uint, string, []byte, or bool.
type Result struct {
	SrcIP          net.IP
	DstIP          net.IP
	SrcPort        uint16
	DstPort        uint16
	IPID           uint16
	TTL            uint8
	Classification string
	Success        bool
	Repeat         bool
	Extra          map[string]any
}

// Module is the interface implemented by every probe module.
type Module interface {
	Name() string
	MaxPacketLen() int
	Fields() []FieldDef
	BuildProbe(srcIP, dstIP net.IP, dstPort uint16, srcMAC, dstMAC net.HardwareAddr,
		ipID uint16, t [4]uint32) ([]byte, uint16 /*srcport*/, error)
	ValidatePacket(pkt gopacket.Packet, v *validate.Validator, srcIP net.IP,
		srcPortFirst, srcPortLast uint16) (*Result, bool)
}

// CheckSrcPort verifies an observed source port lies in our scan's range.
func CheckSrcPort(p uint16, first, last uint16) bool {
	return p >= first && p <= last
}

// SrcPortFor returns the source port to use for a probe given the validation
// tuple and the configured port range. Mirrors get_src_port() in zmap.
func SrcPortFor(num, first uint16, t [4]uint32) uint16 {
	if num == 0 {
		return first
	}
	off := uint16(t[3] % uint32(num))
	return first + off
}

// VerifyDstPortMatches verifies that the observed dest port (which is our
// former source port) is consistent with the validation tuple range.
func VerifyDstPortMatches(observed uint16, num, first uint16, t [4]uint32) bool {
	if num == 0 {
		return observed == first
	}
	expected := SrcPortFor(num, first, t)
	return observed == expected
}

// ipIDFromTuple derives a 16-bit IP ID from a validation tuple.
func ipIDFromTuple(t [4]uint32) uint16 {
	return uint16(t[2] >> 16)
}

var _ = layers.LayerTypeEthernet
