package ports

import "testing"

func TestParsePorts(t *testing.T) {
	conf, err := Parse("53,80-82,443")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{53, 80, 81, 82, 443}
	if len(conf.Ports) != len(want) {
		t.Fatalf("port count = %d, want %d", len(conf.Ports), len(want))
	}
	for i := range want {
		if conf.Ports[i] != want[i] {
			t.Fatalf("port[%d] = %d, want %d", i, conf.Ports[i], want[i])
		}
		if !conf.Contains(want[i]) {
			t.Fatalf("Contains(%d) = false", want[i])
		}
	}
}

func TestParseRejectsInvalidRange(t *testing.T) {
	if _, err := Parse("10-9"); err == nil {
		t.Fatal("Parse accepted descending range")
	}
}
