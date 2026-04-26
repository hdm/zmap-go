package probe

import (
	"net"
	"testing"

	"github.com/hdm/zmap-go/pkg/validate"
)

func TestBACnetBuild(t *testing.T) {
	v, _ := validate.NewFromSeed(7)
	m := NewBACnet(40000, 40000, 64, true)
	pkt, _, err := m.BuildProbe(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 47808, nil, nil, 1, v.GenWords(0, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	// outer IPv4(20) + UDP(8) + payload(>=16) = >= 44
	if len(pkt) < 44 {
		t.Fatalf("short: %d", len(pkt))
	}
	if got := m.Fields(); len(got) == 0 {
		t.Fatal("no fields")
	}
	body := bacnetPayload()
	if body[0] != 0x81 || body[3] != 0x11 || body[len(body)-1] != 0x4b {
		t.Fatalf("bad bacnet payload bytes: % x", body)
	}
}

func TestUPnPBuild(t *testing.T) {
	v, _ := validate.NewFromSeed(7)
	m := NewUPnP(40000, 40000, 64, true)
	pkt, _, err := m.BuildProbe(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 1900, nil, nil, 1, v.GenWords(0, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) <= 28 {
		t.Fatalf("short: %d", len(pkt))
	}
	if len(m.Fields()) == 0 {
		t.Fatal("no fields")
	}
}

func TestIPIPBuild(t *testing.T) {
	v, _ := validate.NewFromSeed(7)
	m := NewIPIP(nil, 40000, 40000, 64, true)
	pkt, _, err := m.BuildProbe(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 80, nil, nil, 1, v.GenWords(0, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	// outer IP 20 + inner IP 20 + UDP 8 + payload >= 29
	if len(pkt) < 77 {
		t.Fatalf("short: %d", len(pkt))
	}
}
