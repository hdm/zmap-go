package validate

import "testing"

func TestSeededDeterministic(t *testing.T) {
	a, err := NewFromSeed(42)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewFromSeed(42)
	if err != nil {
		t.Fatal(err)
	}
	t1 := a.Gen(0x01020304, 0x05060708, 80, 0)
	t2 := b.Gen(0x01020304, 0x05060708, 80, 0)
	if t1 != t2 {
		t.Fatalf("same seed should produce same tuple")
	}
	t3 := a.Gen(0x01020304, 0x05060708, 81, 0)
	if t1 == t3 {
		t.Fatalf("different dport should produce different tuple")
	}
}

func TestGenWordsMatchesGen(t *testing.T) {
	v, err := NewFromSeed(1)
	if err != nil {
		t.Fatal(err)
	}
	w := v.GenWords(1, 2, 3, 4)
	bytes := v.Gen(1, 2, 3, 4)
	for i := 0; i < 4; i++ {
		got := uint32(bytes[i*4]) | uint32(bytes[i*4+1])<<8 | uint32(bytes[i*4+2])<<16 | uint32(bytes[i*4+3])<<24
		if got != w[i] {
			t.Fatalf("word %d mismatch: %x vs %x", i, got, w[i])
		}
	}
}

func TestRandomKey(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatal(err)
	}
	_ = v.Gen(1, 2, 3, 4)
}
