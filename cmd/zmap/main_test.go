package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDryrunCSV(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"--dryrun",
		"-O", "csv",
		"--seed", "42",
		"--max-targets", "5",
		"-p", "80",
		"192.0.2.0/29",
	}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "saddr,daddr,sport,dport,classification,success") {
		t.Fatalf("missing header: %q", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 1 header + 5 rows, got %d: %q", len(lines), out)
	}
	for _, ln := range lines[1:] {
		if !strings.Contains(ln, ",80,") {
			t.Errorf("expected port 80 in %q", ln)
		}
	}
}

func TestDryrunJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"--dryrun", "-O", "json", "--seed", "1", "--max-targets", "3",
		"-p", "443", "192.0.2.0/30"}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	for _, ln := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("invalid json line %q: %v", ln, err)
		}
		if m["dport"] != "443" {
			t.Fatalf("expected dport=443: %+v", m)
		}
	}
}

func TestDryrunDefaultText(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"--dryrun", "-O", "default", "-f", "saddr",
		"-S", "10.0.0.1",
		"--seed", "1", "--max-targets", "2", "-p", "80", "192.0.2.0/30"}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(stdout.String(), "\n"); got != 2 {
		t.Fatalf("expected 2 newlines, got %d: %q", got, stdout.String())
	}
}

func TestDryrunICMP(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"--dryrun", "-M", "icmp_echo", "-O", "csv",
		"--seed", "1", "--max-targets", "3", "192.0.2.0/30"}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "saddr,daddr,sport,dport") {
		t.Fatalf("expected csv header")
	}
}

func TestDryrunUDPSupported(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"--dryrun", "-M", "udp", "-O", "csv", "-p", "53",
		"--seed", "1", "--max-targets", "2", "192.0.2.0/30"}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatalf("udp dryrun: %v stderr=%s", err, stderr.String())
	}
}

func TestDryrunDNSSupported(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"--dryrun", "-M", "dns", "-O", "csv",
		"--probe-args", "example.com", "--seed", "1", "--max-targets", "2",
		"192.0.2.0/30"}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatalf("dns dryrun: %v stderr=%s", err, stderr.String())
	}
}

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-V"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "zmap ") {
		t.Fatalf("unexpected: %q", stdout.String())
	}
}

func TestShardingRequiresSeed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"--dryrun", "--shards", "2", "--shard", "0", "-p", "80", "192.0.2.0/29"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUnknownModule(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"--dryrun", "-M", "bogus", "-p", "53", "192.0.2.0/30"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUnknownOutputModule(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"--dryrun", "-O", "xml", "-p", "53", "192.0.2.0/30"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseSrcPorts(t *testing.T) {
	a, b, err := parseSrcPorts("33000")
	if err != nil || a != 33000 || b != 33000 {
		t.Fatal(a, b, err)
	}
	a, b, err = parseSrcPorts("33000-34000")
	if err != nil || a != 33000 || b != 34000 {
		t.Fatal(a, b, err)
	}
	if _, _, err := parseSrcPorts("70000"); err == nil {
		t.Fatal("expected error")
	}
}
