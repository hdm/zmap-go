package shard

import (
	"net/netip"
	"testing"

	"github.com/zmap/zmap/pkg/cyclic"
)

func TestShardIteratesValidTargets(t *testing.T) {
	group, err := cyclic.GetGroup(8)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		ShardIndex:     0,
		NumShards:      1,
		ThreadIndex:    0,
		NumThreads:     1,
		BitsForPort:    1,
		Cycle:          cyclic.Cycle{Group: group, Generator: 3, Order: group.Prime - 1, Offset: 0},
		MaxIPIndex:     4,
		MaxTargetIndex: 1 << 33,
		Ports:          []uint16{80, 443},
		LookupIndex:    syntheticLookup,
	})
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	current, err := s.CurrentTarget()
	if err != nil {
		t.Fatal(err)
	}
	for current.Status == OK {
		seen[current.IP.String()+":"+portString(current.Port)] = true
		current, err = s.NextTarget()
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 8 {
		t.Fatalf("visited %d targets, want 8", len(seen))
	}
	for _, key := range []string{
		"192.0.2.0:80", "192.0.2.0:443",
		"192.0.2.1:80", "192.0.2.1:443",
		"192.0.2.2:80", "192.0.2.2:443",
		"192.0.2.3:80", "192.0.2.3:443",
	} {
		if !seen[key] {
			t.Fatalf("missing target %s", key)
		}
	}
}

func TestShardDividesMaxTargets(t *testing.T) {
	group, err := cyclic.GetGroup(8)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		ShardIndex:      0,
		NumShards:       2,
		ThreadIndex:     1,
		NumThreads:      2,
		MaxTotalTargets: 10,
		BitsForPort:     0,
		Cycle:           cyclic.Cycle{Group: group, Generator: 3, Order: group.Prime - 1, Offset: 0},
		MaxIPIndex:      4,
		MaxTargetIndex:  1 << 32,
		Ports:           []uint16{80},
		LookupIndex:     syntheticLookup,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.State.MaxTargets != 3 {
		t.Fatalf("max targets = %d, want 3", s.State.MaxTargets)
	}
}

func syntheticLookup(index uint64) (netip.Addr, error) {
	return netip.AddrFrom4([4]byte{192, 0, 2, byte(index)}), nil
}

func portString(port uint16) string {
	switch port {
	case 80:
		return "80"
	case 443:
		return "443"
	default:
		return "unknown"
	}
}
