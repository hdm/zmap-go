package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunOutputsIPs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"--seed", "1", "--max-targets", "3", "192.0.2.0/30"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v\nstderr: %s", err, stderr.String())
	}
	lines := nonEmptyLines(stdout.String())
	if len(lines) != 3 {
		t.Fatalf("line count = %d, want 3; output: %q", len(lines), stdout.String())
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "192.0.2.") || strings.Contains(line, ",") {
			t.Fatalf("unexpected IP-only output line %q", line)
		}
	}
}

func TestRunOutputsPorts(t *testing.T) {
	var stdout bytes.Buffer
	err := run([]string{"--seed", "1", "-p", "80,443", "-n", "4", "198.51.100.0/30"}, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	lines := nonEmptyLines(stdout.String())
	if len(lines) != 4 {
		t.Fatalf("line count = %d, want 4; output: %q", len(lines), stdout.String())
	}
	for _, line := range lines {
		if !strings.Contains(line, ",") {
			t.Fatalf("expected ip,port output, got %q", line)
		}
	}
}

func TestRunRequiresSeedForSharding(t *testing.T) {
	var stdout bytes.Buffer
	err := run([]string{"--shards", "2", "--shard", "0", "192.0.2.0/30"}, &stdout, &bytes.Buffer{})
	if err == nil {
		t.Fatal("run accepted sharding without seed")
	}
}

func TestParseMaxTargets(t *testing.T) {
	got, err := parseMaxTargets("50%", 2)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(1) << 32; got != want {
		t.Fatalf("parseMaxTargets = %d, want %d", got, want)
	}
}

func nonEmptyLines(value string) []string {
	var lines []string
	for _, line := range strings.Split(value, "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
