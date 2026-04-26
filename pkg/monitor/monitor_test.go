package monitor

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestCountersSnapshot(t *testing.T) {
	var c Counters
	c.Sent.Add(10)
	c.Success.Add(3)
	c.Drops.Add(1)
	s := c.Snapshot()
	if s.Sent != 10 || s.Success != 3 || s.Drops != 1 {
		t.Fatalf("unexpected snapshot: %+v", s)
	}
}

func TestPrintSummary(t *testing.T) {
	var c Counters
	c.Sent.Add(100)
	c.Success.Add(25)
	c.Recv.Add(40)
	var buf bytes.Buffer
	PrintSummary(&buf, &c, 10*time.Second)
	out := buf.String()
	if !strings.Contains(out, "scan complete") || !strings.Contains(out, "probes sent: 100") || !strings.Contains(out, "hit rate: 25.00%") {
		t.Errorf("summary missing fields:\n%s", out)
	}
}

func TestRunCancels(t *testing.T) {
	var c Counters
	ctx, cancel := context.WithCancel(context.Background())
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() { Run(ctx, &buf, &c, 10*time.Millisecond, 0); close(done) }()
	c.Sent.Add(5)
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not exit")
	}
}
