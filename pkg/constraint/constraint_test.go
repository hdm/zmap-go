package constraint

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestConstraintSetLookupCount(t *testing.T) {
	c := New(1)
	mustSet(t, c, ip("10.0.0.0"), 8, 0)
	mustSet(t, c, ip("10.11.12.0"), 24, 1)

	if got := c.Lookup(ip("10.0.0.1")); got != 0 {
		t.Fatalf("10.0.0.1 value = %d, want 0", got)
	}
	if got := c.Lookup(ip("10.11.12.5")); got != 1 {
		t.Fatalf("10.11.12.5 value = %d, want 1", got)
	}

	wantAllowed := (uint64(1) << 32) - (uint64(1) << 24) + 256
	if got := c.Count(1); got != wantAllowed {
		t.Fatalf("allowed count = %d, want %d", got, wantAllowed)
	}
	if got := c.Count(0); got != (uint64(1)<<24)-256 {
		t.Fatalf("blocked count = %d, want %d", got, (uint64(1)<<24)-256)
	}
}

func TestConstraintLookupIndex(t *testing.T) {
	c := New(0)
	mustSet(t, c, ip("192.0.2.0"), 30, 1)
	c.Paint(1)

	for i, want := range []string{"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		got, err := c.LookupIndex(uint64(i), 1)
		if err != nil {
			t.Fatalf("LookupIndex(%d): %v", i, err)
		}
		if got != ip(want) {
			t.Fatalf("LookupIndex(%d) = %s, want %s", i, addr(got), want)
		}
	}
	if _, err := c.LookupIndex(4, 1); err == nil {
		t.Fatal("LookupIndex(4) succeeded, want out-of-range error")
	}
}

func mustSet(t *testing.T, c *Constraint, prefix uint32, length int, value Value) {
	t.Helper()
	if err := c.Set(prefix, length, value); err != nil {
		t.Fatal(err)
	}
}

func ip(value string) uint32 {
	addr := netip.MustParseAddr(value).As4()
	return binary.BigEndian.Uint32(addr[:])
}

func addr(value uint32) netip.Addr {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], value)
	return netip.AddrFrom4(bytes)
}
