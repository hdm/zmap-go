// Package output implements zmap's output modules: csv, json, default text.
//
// Mirrors src/output_modules/{module_csv.c, module_json.c, output_modules.c}.
package output

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/hdm/zmap-go/pkg/probe"
)

// Filter is an optional predicate that decides whether a result is emitted.
// Implementors live in pkg/filter.
type Filter interface {
	Match(fields map[string]any) bool
}

// Writer is the output module interface.
type Writer interface {
	WriteResult(r probe.Result) error
	Flush() error
	Close() error
}

// Config bundles options for New.
type Config struct {
	Module string
	Fields []string
	Filter Filter
}

// New returns a writer for the named module ("csv", "json", "default"/"text").
func New(name string, w io.Writer, fields []string) (Writer, error) {
	return NewWithConfig(w, Config{Module: name, Fields: fields})
}

// NewWithConfig returns a writer with optional filter and fields.
func NewWithConfig(w io.Writer, c Config) (Writer, error) {
	fields := c.Fields
	if len(fields) == 0 {
		fields = DefaultFields()
	}
	switch strings.ToLower(c.Module) {
	case "", "default", "text":
		return &textWriter{w: w, fields: fields, filter: c.Filter}, nil
	case "csv":
		cw := csv.NewWriter(w)
		_ = cw.Write(fields)
		cw.Flush()
		return &csvWriter{cw: cw, fields: fields, filter: c.Filter}, nil
	case "json":
		return &jsonWriter{enc: json.NewEncoder(w), fields: fields, filter: c.Filter}, nil
	}
	return nil, fmt.Errorf("output: unknown module %q", c.Module)
}

// DefaultFields returns the default per-result fields.
func DefaultFields() []string {
	return []string{"saddr", "daddr", "sport", "dport", "classification", "success"}
}

// resultMap merges Result's framework fields with module-specific Extra.
func resultMap(r probe.Result) map[string]any {
	m := map[string]any{
		"saddr":          ipString(r.SrcIP),
		"daddr":          ipString(r.DstIP),
		"sport":          uint64(r.SrcPort),
		"dport":          uint64(r.DstPort),
		"ipid":           uint64(r.IPID),
		"ttl":            uint64(r.TTL),
		"classification": r.Classification,
		"success":        r.Success,
		"repeat":         r.Repeat,
	}
	for k, v := range r.Extra {
		m[k] = v
	}
	return m
}

func ipString(b interface{ String() string }) string {
	if b == nil {
		return ""
	}
	if v, ok := b.(interface{ IsUnspecified() bool }); ok && v.IsUnspecified() {
		return ""
	}
	return b.String()
}

// formatScalar renders a value as a string for csv/text/json writers.
func formatScalar(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case []byte:
		return hex.EncodeToString(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint:
		return strconv.FormatUint(uint64(x), 10)
	case uint16, uint32:
		return fmt.Sprintf("%d", x)
	case uint64:
		return strconv.FormatUint(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	}
	return fmt.Sprintf("%v", v)
}

func project(r probe.Result, fields []string) []string {
	m := resultMap(r)
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = formatScalar(m[f])
	}
	return out
}

// ----- csv -----

type csvWriter struct {
	cw     *csv.Writer
	fields []string
	filter Filter
	mu     sync.Mutex
}

func (w *csvWriter) WriteResult(r probe.Result) error {
	if w.filter != nil && !w.filter.Match(resultMap(r)) {
		return nil
	}
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
	filter Filter
	mu     sync.Mutex
}

func (w *jsonWriter) WriteResult(r probe.Result) error {
	m := resultMap(r)
	if w.filter != nil && !w.filter.Match(m) {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]any, len(w.fields))
	for _, f := range w.fields {
		out[f] = formatScalar(m[f])
	}
	return w.enc.Encode(out)
}
func (w *jsonWriter) Flush() error { return nil }
func (w *jsonWriter) Close() error { return nil }

// ----- default text -----

type textWriter struct {
	w      io.Writer
	fields []string
	filter Filter
	mu     sync.Mutex
}

func (w *textWriter) WriteResult(r probe.Result) error {
	m := resultMap(r)
	if w.filter != nil && !w.filter.Match(m) {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.fields) == 1 && w.fields[0] == "saddr" {
		s := formatScalar(m["saddr"])
		if s == "" {
			return nil
		}
		_, err := fmt.Fprintln(w.w, s)
		return err
	}
	parts := make([]string, 0, len(w.fields))
	for _, f := range w.fields {
		parts = append(parts, fmt.Sprintf("%s=%s", f, formatScalar(m[f])))
	}
	_, err := fmt.Fprintln(w.w, strings.Join(parts, " "))
	return err
}
func (w *textWriter) Flush() error { return nil }
func (w *textWriter) Close() error { return nil }
