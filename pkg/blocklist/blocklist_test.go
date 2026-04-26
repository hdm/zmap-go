package blocklist

import (
	"net/netip"
	"testing"
)

func TestAllowlistAndBlocklist(t *testing.T) {
	list, err := New(Config{
		AllowlistEntries: []string{"192.0.2.0/30"},
		BlocklistEntries: []string{"192.0.2.1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !list.IsAllowed(netip.MustParseAddr("192.0.2.0")) {
		t.Fatal("192.0.2.0 should be allowed")
	}
	if list.IsAllowed(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("192.0.2.1 should be blocked")
	}
	if list.IsAllowed(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("198.51.100.1 should be blocked by default allowlist mode")
	}
	if got := list.CountAllowed(); got != 3 {
		t.Fatalf("allowed count = %d, want 3", got)
	}

	got, err := list.LookupIndex(1)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("192.0.2.2"); got != want {
		t.Fatalf("LookupIndex(1) = %s, want %s", got, want)
	}
}

func TestBlocklistOnlyDefaultsToAllowed(t *testing.T) {
	list, err := New(Config{BlocklistEntries: []string{"203.0.113.0/31"}})
	if err != nil {
		t.Fatal(err)
	}
	if list.IsAllowed(netip.MustParseAddr("203.0.113.0")) {
		t.Fatal("203.0.113.0 should be blocked")
	}
	if !list.IsAllowed(netip.MustParseAddr("203.0.113.2")) {
		t.Fatal("203.0.113.2 should be allowed")
	}
}

func TestIPv6EntriesAreIgnored(t *testing.T) {
	list, err := New(Config{BlocklistEntries: []string{"2001:db8::/64"}})
	if err != nil {
		t.Fatal(err)
	}
	if !list.IsAllowed(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("IPv6-only blocklist entry should not affect IPv4 scanning")
	}
}
