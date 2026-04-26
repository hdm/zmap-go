// Package output implements zmap's output modules: csv, json, default text.
//
// Mirrors src/output_modules/{module_csv.c, module_json.c, output_modules.c}.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/hdm/zmap-go/pkg/probe"
)

// Writer is the output module interface.
type Writer interface {
	WriteResult(r probe.Result) error
	Flush() error
	Close() error
}

// New returns a writer for the named module ("csv", "json", "default"/"text").
func New(name string, w io.Writer, fields []string) (Writer, error) {
	if len(fields) == 0 {
		fields = DefaultFields()
	}
	switch strings.ToLower(name) {
	case "", "default", "text":
		return &textWriter{w: w, fields: fields}, nil
	case "csv":
		cw := csv.NewWriter(w)
		_ = cw.Write(fields)
		return &csvWriter{cw: cw, fields: fields}, nil
	case "json":
		return &jsonWriter{enc: json.NewEncoder(w), fields: fields}, nil
	}
	return nil, fmt.Errorf("output: unknown module %q", name)
}

// DefaultFields returns the default per-result fields.
func DefaultFields() []string {
	return []string{"saddr", "daddr", "sport", "dport", "classification", "success"}
}

func resultMap(r probe.Result) map[string]string {
	srcIP := ""
	if r.SrcIP != nil {
		srcIP = r.SrcIP.String()
	}
	dstIP := ""
	if r.DstIP != nil {
		dstIP = r.DstIP.String()
	}
	return map[string]string{
		"saddr":          srcIP,
		"daddr":          dstIP,
		"sport":          strconv.Itoa(int(r.SrcPort)),
		"dport":          strconv.Itoa(int(r.DstPort)),
		"classification": r.Classification,
		"success":        fmt.Sprintf("%t", r.Success),
	}
}

func project(r probe.Result, fields []string) []string {
	m := resultMap(r)
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = m[f]
	}
	return out
}

// ----- csv -----

type csvWriter struct {
	cw     *csv.Writer
	fields []string
	mu     sync.Mutex
}

func (w *csvWriter) WriteResult(r probe.Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.cw.Write(project(r, w.fields)); err != nil {
		return err
	}
	w.cw.Flush()
	return w.cw.Error()
}
func (w *csvWriter) Flush() error { w.cw.Flush(); return w.cw.Error() }
func (w *csvWriter) Close() error { w.cw.Flush(); return nil }

// ----- json -----

type jsonWriter struct {
	enc    *json.Encoder
	fields []string
	mu     sync.Mutex
}

func (w *jsonWriter) WriteResult(r probe.Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	m := resultMap(r)
	out := make(map[string]any, len(w.fields))
	for _, f := range w.fields {
		out[f] = m[f]
	}
	return w.enc.Encode(out)
}
func (w *jsonWriter) Flush() error { return nil }
func (w *jsonWriter) Close() error { return nil }

// ----- default text (one IP per line, mirroring upstream zmap default) -----

type textWriter struct {
	w      io.Writer
	fields []string
	mu     sync.Mutex
}

func (w *textWriter) WriteResult(r probe.Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Default text mode emits the responding IP only, matching upstream
	// zmap's default behavior. If "saddr" isn't in fields, fall back to a
	// key=value form.
	if len(w.fields) == 1 && w.fields[0] == "saddr" {
		if r.SrcIP != nil {
			_, err := fmt.Fprintln(w.w, r.SrcIP.String())
			return err
		}
		return nil
	}
	m := resultMap(r)
	parts := make([]string, 0, len(w.fields))
	for _, f := range w.fields {
		parts = append(parts, fmt.Sprintf("%s=%s", f, m[f]))
	}
	_, err := fmt.Fprintln(w.w, strings.Join(parts, " "))
	return err
}
func (w *textWriter) Flush() error { return nil }
func (w *textWriter) Close() error { return nil }
