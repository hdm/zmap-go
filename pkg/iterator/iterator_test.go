package iterator

import (
	"net/netip"
	"testing"

	"github.com/hdm/zmap-go/pkg/cyclic"
)

type staticSource struct {
	values []uint64
	index  int
}

func (s *staticSource) Uint64() (uint64, error) {
	if s.index >= len(s.values) {
		return 0, nil
	}
	value := s.values[s.index]
	s.index++
	return value, nil
}

func TestIteratorBuildsThreadShards(t *testing.T) {
	it, err := New(Config{
		NumThreads:  2,
		ShardIndex:  0,
		NumShards:   1,
		NumAddrs:    4,
		Ports:       []uint16{80, 443},
		Source:      &staticSource{values: []uint64{0, 0}},
		LookupIndex: iteratorLookup,
	})
	if err != nil {
		t.Fatal(err)
	}
	if it.BitsForIP() != 2 {
		t.Fatalf("bits for IP = %d, want 2", it.BitsForIP())
	}
	if it.BitsForPort() != 1 {
		t.Fatalf("bits for port = %d, want 1", it.BitsForPort())
	}
	if it.Cycle.Order == 0 || it.Cycle.Generator == 0 {
		t.Fatal("iterator cycle was not initialized")
	}

	first, err := it.Shard(0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := it.Shard(1)
	if err != nil {
		t.Fatal(err)
	}
	if first.CurrentElement() == second.CurrentElement() {
		t.Fatal("thread shards started at the same element")
	}
	if _, err := it.Shard(2); err == nil {
		t.Fatal("Shard(2) succeeded for two-thread iterator")
	}
}

func TestIteratorRejectsEmptyPorts(t *testing.T) {
	_, err := New(Config{
		NumThreads:  1,
		ShardIndex:  0,
		NumShards:   1,
		NumAddrs:    1,
		LookupIndex: iteratorLookup,
		Source:      cyclic.SecureSource{},
	})
	if err == nil {
		t.Fatal("iterator accepted empty ports")
	}
}

func iteratorLookup(index uint64) (netip.Addr, error) {
	return netip.AddrFrom4([4]byte{198, 51, 100, byte(index)}), nil
}
