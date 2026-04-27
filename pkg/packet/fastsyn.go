package packet

import (
	"encoding/binary"
	"fmt"

	"github.com/gopacket/gopacket/layers"
)

// staticTCPOptionBytes holds the precomputed wire-format TCP option blob for
// each supported TCPOptionStyle, indexed by style. It is built once at
// package init and reused for every SYN probe — the steady-state hot path
// would otherwise spend ~22% of its CPU rebuilding the same option list per
// packet (see profile of the 2 Mpps benchmark).
var staticTCPOptionBytes [4][]byte

func init() {
	for s := StyleSmallest; s <= StyleLinux; s++ {
		staticTCPOptionBytes[s] = encodeTCPOptions(s.TCPSynOptions())
	}
}

func encodeTCPOptions(opts []layers.TCPOption) []byte {
	out := make([]byte, 0, 24)
	for _, o := range opts {
		switch o.OptionType {
		case layers.TCPOptionKindEndList:
			out = append(out, 0)
		case layers.TCPOptionKindNop:
			out = append(out, 1)
		default:
			out = append(out, byte(o.OptionType))
			out = append(out, byte(len(o.OptionData)+2))
			out = append(out, o.OptionData...)
		}
	}
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

// BuildSYNFast writes a TCP SYN probe directly into out (which must have at
// least p.Style.PacketLen() bytes of capacity). It bypasses gopacket entirely
// — no per-packet allocations, no interface dispatch, just byte writes and
// two one's-complement checksum loops. Returns out re-sliced to the frame
// length.
func BuildSYNFast(out []byte, p SynParams) ([]byte, error) {
	src4 := p.SrcIP.To4()
	dst4 := p.DstIP.To4()
	if src4 == nil || dst4 == nil {
		return nil, fmt.Errorf("packet: IPv4 only")
	}
	style := p.Style
	if int(style) < 0 || int(style) >= len(staticTCPOptionBytes) {
		return nil, fmt.Errorf("packet: unknown TCP option style %d", style)
	}
	opts := staticTCPOptionBytes[style]
	tcpHdrLen := 20 + len(opts)
	frameLen := 20 + tcpHdrLen
	ethHdr := 0
	if !p.SendIPOnly {
		ethHdr = 14
		frameLen += ethHdr
	}
	// Pad short Ethernet frames to the minimum 60-byte payload that the
	// NIC will otherwise pad with (gopacket emits the same padding).
	paddedLen := frameLen
	if !p.SendIPOnly && paddedLen < 60 {
		paddedLen = 60
	}
	if cap(out) < paddedLen {
		return nil, fmt.Errorf("packet: output buffer too small (%d < %d)", cap(out), paddedLen)
	}
	out = out[:paddedLen]
	if paddedLen > frameLen {
		// Zero pad bytes — Go zeroes new slice extents but reused scratch may
		// hold stale bytes from a prior packet.
		for i := frameLen; i < paddedLen; i++ {
			out[i] = 0
		}
	}

	off := 0
	if !p.SendIPOnly {
		copy(out[0:6], p.DstMAC)
		copy(out[6:12], p.SrcMAC)
		binary.BigEndian.PutUint16(out[12:14], 0x0800) // IPv4
		off = 14
	}

	// IPv4 header.
	ip := out[off : off+20]
	ip[0] = 0x45 // version 4, IHL 5
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+tcpHdrLen))
	binary.BigEndian.PutUint16(ip[4:6], p.IPID)
	binary.BigEndian.PutUint16(ip[6:8], 0) // flags/frag offset zero (matches gopacket)
	ttl := p.TTL
	if ttl == 0 {
		ttl = 255
	}
	ip[8] = ttl
	ip[9] = 6 // TCP
	ip[10] = 0
	ip[11] = 0
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))

	// TCP header + options.
	tcp := out[off+20 : off+20+tcpHdrLen]
	binary.BigEndian.PutUint16(tcp[0:2], p.SrcPort)
	binary.BigEndian.PutUint16(tcp[2:4], p.DstPort)
	binary.BigEndian.PutUint32(tcp[4:8], p.Seq)
	binary.BigEndian.PutUint32(tcp[8:12], 0) // Ack
	tcp[12] = byte(tcpHdrLen/4) << 4         // data offset, reserved
	tcp[13] = 0x02                           // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	tcp[16] = 0
	tcp[17] = 0
	binary.BigEndian.PutUint16(tcp[18:20], 0)
	copy(tcp[20:], opts)

	// TCP checksum: pseudo-header (src, dst, 0, proto=6, tcp_len) + segment.
	var sum uint32
	sum += uint32(src4[0])<<8 | uint32(src4[1])
	sum += uint32(src4[2])<<8 | uint32(src4[3])
	sum += uint32(dst4[0])<<8 | uint32(dst4[1])
	sum += uint32(dst4[2])<<8 | uint32(dst4[3])
	sum += 6
	sum += uint32(tcpHdrLen)
	sum += sumWords(tcp)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16(sum))

	return out, nil
}

// ipv4Checksum returns the one's-complement IPv4 header checksum.
func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// sumWords folds b into a 32-bit big-endian word sum, padding a trailing
// byte with zero if needed. Caller folds carries.
func sumWords(b []byte) uint32 {
	var sum uint32
	n := len(b) &^ 1
	for i := 0; i < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}
