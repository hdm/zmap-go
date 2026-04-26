package output

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/hdm/zmap-go/pkg/probe"
)

func sample() probe.Result {
	return probe.Result{
		SrcIP: net.IPv4(1, 2, 3, 4), DstIP: net.IPv4(10, 0, 0, 1),
		SrcPort: 80, DstPort: 33000,
		Classification: "synack", Success: true,
	}
}

func TestCSV(t *testing.T) {
	var b bytes.Buffer
	w, err := New("csv", &b, DefaultFields())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteResult(sample()); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	got := b.String()
	if !strings.Contains(got, "saddr,daddr,sport,dport,classification,success") {
		t.Fatalf("missing header: %q", got)
	}
	if !strings.Contains(got, "1.2.3.4,10.0.0.1,80,33000,synack,true") {
		t.Fatalf("missing row: %q", got)
	}
}

func TestJSON(t *testing.T) {
	var b bytes.Buffer
	w, err := New("json", &b, []string{"saddr", "classification"})
	if err != nil {
		t.Fatal(err)
	}
	w.WriteResult(sample())
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["saddr"] != "1.2.3.4" || m["classification"] != "synack" {
		t.Fatalf("got %+v", m)
	}
}

func TestDefaultSaddrOnly(t *testing.T) {
	var b bytes.Buffer
	w, err := New("default", &b, []string{"saddr"})
	if err != nil {
		t.Fatal(err)
	}
	w.WriteResult(sample())
	if got := strings.TrimSpace(b.String()); got != "1.2.3.4" {
		t.Fatalf("got %q", got)
	}
}

func TestUnknown(t *testing.T) {
	if _, err := New("xml", nil, nil); err == nil {
		t.Fatal("expected error")
	}
}
