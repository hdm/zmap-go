package probe

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/hdm/zmap-go/pkg/packet"
	"github.com/hdm/zmap-go/pkg/validate"
)

func TestSrcPortFor(t *testing.T) {
	tup := [4]uint32{0, 0, 0, 7}
	if got := SrcPortFor(10, 33000, tup); got != 33007 {
		t.Fatalf("got %d", got)
	}
	if !VerifyDstPortMatches(33007, 10, 33000, tup) {
		t.Fatalf("expected match")
	}
}

func TestTCPSynRoundTrip(t *testing.T) {
	v, _ := validate.NewFromSeed(7)
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	mod := &TCPSyn{Style: packet.StyleWindows, SrcPortFirst: 33000, SrcPortLast: 33009, TTL: 64}
	tup := v.GenWords(ipBE(src), ipBE(dst), 80, 0)
	pkt, sport, err := mod.BuildProbe(src, dst, 80, srcMAC, dstMAC, 0xabcd, tup)
	if err != nil {
		t.Fatal(err)
	}
	// Synthesize a SYN+ACK reply: swap IPs/ports and set SYN+ACK with ack=seq+1.
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: dst, DstIP: src}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(80), DstPort: layers.TCPPort(sport),
		Seq: 0x99, Ack: tup[0] + 1, SYN: true, ACK: true, Window: 65535,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	eth := &layers.Ethernet{SrcMAC: dstMAC, DstMAC: srcMAC, EthernetType: layers.EthernetTypeIPv4}
	if err := gopacket.SerializeLayers(buf, packet.SerializeOptions, eth, ip, tcp); err != nil {
		t.Fatal(err)
	}
	reply := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	res, ok := mod.ValidatePacket(reply, v, src, 33000, 33009)
	if !ok {
		t.Fatalf("expected validate success; built pkt sport=%d ack=%x", sport, tup[0]+1)
	}
	if res.Classification != "synack" || !res.Success {
		t.Fatalf("unexpected result %+v", res)
	}
	_ = pkt
}

func TestTCPSynRejectsForeign(t *testing.T) {
	v, _ := validate.NewFromSeed(7)
	src := net.IPv4(10, 0, 0, 1)
	mod := &TCPSyn{Style: packet.StyleWindows, SrcPortFirst: 33000, SrcPortLast: 33009}
	// Random unrelated SYN+ACK
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IPv4(8, 8, 8, 8), DstIP: src}
	tcp := &layers.TCP{SrcPort: 80, DstPort: 33001, Seq: 1, Ack: 2, SYN: true, ACK: true}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, packet.SerializeOptions, ip, tcp)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	if _, ok := mod.ValidatePacket(pkt, v, src, 33000, 33009); ok {
		t.Fatal("should not validate")
	}
}

func TestICMPEchoRoundTrip(t *testing.T) {
	v, _ := validate.NewFromSeed(11)
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	mod := &IcmpEcho{Payload: []byte("hello, zmapgo"), TTL: 64}
	tup := v.GenWords(ipBE(src), ipBE(dst), 0, 0)
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	pktBytes, _, err := mod.BuildProbe(src, dst, 0, srcMAC, dstMAC, 0, tup)
	if err != nil {
		t.Fatal(err)
	}
	_ = pktBytes
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: dst, DstIP: src}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		Id:       uint16(tup[1]), Seq: uint16(tup[2]),
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, packet.SerializeOptions, ip, icmp)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	res, ok := mod.ValidatePacket(pkt, v, src, 0, 0)
	if !ok {
		t.Fatal("expected echoreply match")
	}
	if res.Classification != "echoreply" {
		t.Fatalf("got %q", res.Classification)
	}
}
