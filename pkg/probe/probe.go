// Package probe implements zmap's probe modules in Go: TCP SYN scan and
// ICMP echo. CGO-free.
//
// A probe module knows how to:
//   - report the size and layout of probes it generates
//   - serialize a probe targeting (dstIP, dstPort) given a per-probe
//     validation tuple
//   - inspect an inbound packet and decide whether it is a response to one
//     of our probes, classifying it (e.g. "synack", "rst", "echoreply")
package probe

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/hdm/zmap-go/pkg/validate"
)

// Result is what a probe module emits from ValidatePacket on a successful match.
type Result struct {
	SrcIP          net.IP
	DstIP          net.IP
	SrcPort        uint16
	DstPort        uint16
	Classification string // "synack" | "rst" | "echoreply"
	Success        bool
}

// Module is the interface implemented by both TCP SYN and ICMP echo.
type Module interface {
	Name() string
	MaxPacketLen() int
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

// VerifySrcPort verifies that the observed dest port (which is our former
// source port) is consistent with the validation tuple range.
func VerifyDstPortMatches(observed uint16, num, first uint16, t [4]uint32) bool {
	if num == 0 {
		return observed == first
	}
	expected := SrcPortFor(num, first, t)
	return observed == expected
}

// ipIDFromTuple derives a 16-bit IP ID from a validation tuple (matching
// zmap's typical use of validation[2] high bytes).
func ipIDFromTuple(t [4]uint32) uint16 {
	return uint16(t[2] >> 16)
}

// helpers exported for cmd/zmap convenience
var _ = layers.LayerTypeEthernet
