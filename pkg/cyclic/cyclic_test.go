package cyclic

import "testing"

type sequenceSource struct {
	values []uint64
	index  int
}

func (s *sequenceSource) Uint64() (uint64, error) {
	if s.index >= len(s.values) {
		return 0, nil
	}
	value := s.values[s.index]
	s.index++
	return value, nil
}

func TestGetGroup(t *testing.T) {
	group, err := GetGroup(257)
	if err != nil {
		t.Fatal(err)
	}
	if group.Prime != 65537 {
		t.Fatalf("group prime = %d, want 65537", group.Prime)
	}

	if _, err := GetGroup(1 << 60); err == nil {
		t.Fatal("GetGroup accepted an oversized minimum")
	}
}

func TestMakeCycle(t *testing.T) {
	group, err := GetGroup(16)
	if err != nil {
		t.Fatal(err)
	}
	cycle, err := MakeCycle(group, &sequenceSource{values: []uint64{0, 300}})
	if err != nil {
		t.Fatal(err)
	}
	if cycle.Generator == 0 {
		t.Fatal("generator was zero")
	}
	if cycle.Order != group.Prime-1 {
		t.Fatalf("cycle order = %d, want %d", cycle.Order, group.Prime-1)
	}
	if cycle.Offset != 300%group.Prime {
		t.Fatalf("cycle offset = %d, want %d", cycle.Offset, 300%group.Prime)
	}
}
