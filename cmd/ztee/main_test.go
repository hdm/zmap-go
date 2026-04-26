package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCSVExtractsIP(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "out.csv")
	stdin := strings.NewReader("saddr,success\n192.0.2.1,1\n192.0.2.2,0\n198.51.100.1,1\n")
	var stdout, stderr bytes.Buffer
	if err := run([]string{output}, stdin, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}
	gotStdout := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	wantStdout := []string{"192.0.2.1", "192.0.2.2", "198.51.100.1"}
	if !equalLines(gotStdout, wantStdout) {
		t.Fatalf("stdout = %#v, want %#v", gotStdout, wantStdout)
	}
	wantFile := "saddr,success\n192.0.2.1,1\n192.0.2.2,0\n198.51.100.1,1\n"
	gotFile, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotFile) != wantFile {
		t.Fatalf("output file = %q, want %q", string(gotFile), wantFile)
	}
}

func TestRunSuccessOnly(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "out.csv")
	stdin := strings.NewReader("saddr,success\n192.0.2.1,1\n192.0.2.2,0\n198.51.100.1,true\n")
	var stdout bytes.Buffer
	if err := run([]string{"--success-only", output}, stdin, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	want := []string{"192.0.2.1", "198.51.100.1"}
	if !equalLines(got, want) {
		t.Fatalf("stdout = %#v, want %#v", got, want)
	}
}

func TestRunRawPassthrough(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "out.txt")
	stdin := strings.NewReader("hello\nworld\n")
	var stdout bytes.Buffer
	if err := run([]string{"--raw", output}, stdin, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "hello\nworld\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "hello\nworld\n")
	}
	gotFile, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotFile) != "hello\nworld\n" {
		t.Fatalf("output file = %q", string(gotFile))
	}
}

func TestRunRequiresOutput(t *testing.T) {
	if err := run(nil, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("run accepted missing output file")
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
