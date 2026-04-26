package packet

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestBuildSYNRoundTrip(t *testing.T) {
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	pkt, err := BuildSYN(SynParams{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   net.IPv4(10, 0, 0, 1),
		DstIP:   net.IPv4(10, 0, 0, 2),
		SrcPort: 33333,
		DstPort: 80,
		Seq:     0xdeadbeef,
		IPID:    0x1234,
		TTL:     64,
		Style:   StyleWindows,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(pkt); got != StyleWindows.PacketLen() {
		t.Fatalf("len=%d want=%d", got, StyleWindows.PacketLen())
	}
	p := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
	tcpL := p.Layer(layers.LayerTypeTCP)
	if tcpL == nil {
		t.Fatal("no TCP layer")
	}
	tcp := tcpL.(*layers.TCP)
	if tcp.SrcPort != 33333 || tcp.DstPort != 80 || tcp.Seq != 0xdeadbeef || !tcp.SYN {
		t.Fatalf("unexpected TCP: %+v", tcp)
	}
}

func TestBuildSYNIPOnly(t *testing.T) {
	pkt, err := BuildSYN(SynParams{
		SrcIP:      net.IPv4(10, 0, 0, 1),
		DstIP:      net.IPv4(10, 0, 0, 2),
		SrcPort:    1234,
		DstPort:    443,
		Seq:        1,
		Style:      StyleSmallest,
		SendIPOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(pkt); got != StyleSmallest.PacketLen()-14 {
		t.Fatalf("ip-only len=%d want=%d", got, StyleSmallest.PacketLen()-14)
	}
	p := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)
	if p.Layer(layers.LayerTypeTCP) == nil {
		t.Fatal("no tcp")
	}
}

func TestBuildICMPEcho(t *testing.T) {
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	pkt, err := BuildICMPEcho(IcmpEchoParams{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   net.IPv4(10, 0, 0, 1),
		DstIP:   net.IPv4(10, 0, 0, 2),
		ID:      0x1111,
		Seq:     0x2222,
		Payload: []byte("ZMAPGOPING12345678"),
	})
	if err != nil {
		t.Fatal(err)
	}
	p := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
	icmpL := p.Layer(layers.LayerTypeICMPv4)
	if icmpL == nil {
		t.Fatal("no icmp")
	}
	ic := icmpL.(*layers.ICMPv4)
	if ic.Id != 0x1111 || ic.Seq != 0x2222 {
		t.Fatalf("unexpected icmp: %+v", ic)
	}
}

func TestParseStyle(t *testing.T) {
	for _, s := range []string{"", "windows", "linux", "bsd", "smallest-probes"} {
		if _, err := ParseStyle(s); err != nil {
			t.Errorf("ParseStyle(%q) err=%v", s, err)
		}
	}
	if _, err := ParseStyle("nope"); err == nil {
		t.Errorf("expected error for unknown style")
	}
}
