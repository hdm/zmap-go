package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunFiltersByBlocklist(t *testing.T) {
	dir := t.TempDir()
	blocklistPath := filepath.Join(dir, "blocklist.conf")
	if err := os.WriteFile(blocklistPath, []byte("192.0.2.0/30\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdin := strings.NewReader("192.0.2.1\n192.0.2.5\n198.51.100.1\n198.51.100.1\n")
	var stdout, stderr bytes.Buffer
	err := run([]string{"-b", blocklistPath}, stdin, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}
	got := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	want := []string{"192.0.2.5", "198.51.100.1"}
	if !equalLines(got, want) {
		t.Fatalf("output = %#v, want %#v", got, want)
	}
}

func TestRunRejectsMissingLists(t *testing.T) {
	if err := run(nil, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("run accepted invocation without any list")
	}
}

func TestRunRespectsDisableDuplicates(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "allowlist.conf")
	if err := os.WriteFile(allowlistPath, []byte("192.0.2.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdin := strings.NewReader("192.0.2.1\n192.0.2.1\n192.0.2.1\n")
	var stdout bytes.Buffer
	err := run([]string{"-w", allowlistPath, "--no-duplicate-checking"}, stdin, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	want := []string{"192.0.2.1", "192.0.2.1", "192.0.2.1"}
	if !equalLines(got, want) {
		t.Fatalf("output = %#v, want %#v", got, want)
	}
}

func equalLines(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
