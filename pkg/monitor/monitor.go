package monitor
// Package monitor implements zmap's progress monitor and final scan summary.
//
// Mirrors src/monitor.c, src/state.c, src/summary.c.
//
// Counters is goroutine-safe and is intended to be shared between the
// sender(s), the receiver, and a Run goroutine that prints a periodic
// progress line to stderr.
package monitor

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// Counters tracks scan-wide counts. All accessor methods are safe to call
// concurrently with sender/receiver goroutines.
type Counters struct {
	Sent     atomic.Uint64 // probes successfully written to the wire
	SendFail atomic.Uint64 // probes that failed to send
	Recv     atomic.Uint64 // raw frames read by the receiver
	Success  atomic.Uint64 // results classified as success
	Failure  atomic.Uint64 // results classified but not success
	Drops    atomic.Uint64 // OS-reported drops (best-effort)
	Filtered atomic.Uint64 // results suppressed by --output-filter
}

// Snapshot returns a coherent (best-effort) view of the counters.
type Snapshot struct {
	Sent, SendFail, Recv, Success, Failure, Drops, Filtered uint64
}

// Snapshot returns the current values.
func (c *Counters) Snapshot() Snapshot {
	return Snapshot{
		Sent:     c.Sent.Load(),
		SendFail: c.SendFail.Load(),
		Recv:     c.Recv.Load(),
		Success:  c.Success.Load(),
		Failure:  c.Failure.Load(),
		Drops:    c.Drops.Load(),
		Filtered: c.Filtered.Load(),
	}
}

// Run prints a progress line to w every interval until ctx is cancelled.
// totalTargets, if > 0, is used to compute the percentage and ETA.
func Run(ctx context.Context, w io.Writer, c *Counters, interval time.Duration, totalTargets uint64) {
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	start := time.Now()
	var prev Snapshot
	prevTime := start
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			cur := c.Snapshot()
			elapsed := now.Sub(start)
			window := now.Sub(prevTime)
			if window <= 0 {
				window = interval
			}
			sendPS := float64(cur.Sent-prev.Sent) / window.Seconds()
			avgSend := float64(cur.Sent) / elapsed.Seconds()
			recvPS := float64(cur.Recv-prev.Recv) / window.Seconds()
			avgRecv := float64(cur.Recv) / elapsed.Seconds()
			pct := ""
			eta := ""
			if totalTargets > 0 {
				p := 100 * float64(cur.Sent) / float64(totalTargets)
				if p > 100 {
					p = 100
				}
				pct = fmt.Sprintf(" %5.2f%%;", p)
				if avgSend > 0 && cur.Sent < totalTargets {
					remaining := time.Duration(float64(totalTargets-cur.Sent)/avgSend) * time.Second
					eta = "; ETA " + dur(remaining)
				}
			}
			hit := 0.0
			if cur.Sent > 0 {
				hit = 100 * float64(cur.Success) / float64(cur.Sent)
			}
			fmt.Fprintf(w,
				"%s%s send: %d %s p/s (%s p/s avg); recv: %d %s p/s (%s p/s avg); drops: %d; hits: %.2f%%%s\n",
				dur(elapsed), pct,
				cur.Sent, kfmt(sendPS), kfmt(avgSend),
				cur.Recv, kfmt(recvPS), kfmt(avgRecv),
				cur.Drops, hit, eta,
			)
			prev, prevTime = cur, now
		}
	}
}

// PrintSummary emits a multi-line scan summary to w.
func PrintSummary(w io.Writer, c *Counters, elapsed time.Duration) {
	s := c.Snapshot()
	fmt.Fprintf(w, "zmap: scan complete in %s\n", dur(elapsed))
	fmt.Fprintf(w, "zmap: probes sent: %d (failed: %d)\n", s.Sent, s.SendFail)
	fmt.Fprintf(w, "zmap: replies recv: %d  success: %d  failure: %d\n", s.Recv, s.Success, s.Failure)
	if s.Filtered > 0 {
		fmt.Fprintf(w, "zmap: filtered out: %d\n", s.Filtered)
	}
	if s.Sent > 0 {
		fmt.Fprintf(w, "zmap: hit rate: %.2f%%\n", 100*float64(s.Success)/float64(s.Sent))
	}
	if elapsed > 0 {
		fmt.Fprintf(w, "zmap: average send rate: %s p/s\n", kfmt(float64(s.Sent)/elapsed.Seconds()))
	}
}

func kfmt(v float64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fK", v/1e3)
	}
	return fmt.Sprintf("%.0f", v)
}

func dur(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d / time.Hour)
	m := int(d/time.Minute) % 60
	s := int(d/time.Second) % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}
