package packet

import (
	"bytes"
	"net"
	"testing"
)

// Verify that the hand-rolled BuildSYNFast produces byte-for-byte the same
// frame as the gopacket-based BuildSYN for every supported style.
func TestBuildSYNFastMatchesGopacket(t *testing.T) {
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	src := net.IPv4(10, 1, 2, 3)
	dst := net.IPv4(8, 8, 8, 8)
	for _, style := range []TCPOptionStyle{StyleSmallest, StyleWindows, StyleLinux, StyleBSD} {
		for _, ipOnly := range []bool{false, true} {
			p := SynParams{
				SrcMAC: srcMAC, DstMAC: dstMAC,
				SrcIP: src, DstIP: dst,
				SrcPort: 33333, DstPort: 80,
				Seq: 0xdeadbeef, IPID: 0xabcd,
				TTL: 64, Style: style, SendIPOnly: ipOnly,
			}
			want, err := BuildSYN(p)
			if err != nil {
				t.Fatalf("style=%v BuildSYN: %v", style, err)
			}
			got, err := BuildSYNFast(make([]byte, 0, 128), p)
			if err != nil {
				t.Fatalf("style=%v BuildSYNFast: %v", style, err)
			}
			if !bytes.Equal(want, got) {
				t.Fatalf("style=%v ipOnly=%v frames differ\nwant %x\ngot  %x", style, ipOnly, want, got)
			}
		}
	}
}
