package filter

import "testing"

func TestFilter(t *testing.T) {
	cases := []struct {
		expr string
		row  map[string]any
		want bool
	}{
		{`success = 1`, map[string]any{"success": true}, true},
		{`success = 1`, map[string]any{"success": false}, false},
		{`success = 0`, map[string]any{"success": false}, true},
		{`classification = "synack"`, map[string]any{"classification": "synack"}, true},
		{`classification = "synack"`, map[string]any{"classification": "rst"}, false},
		{`success = 1 && classification = "synack"`,
			map[string]any{"success": true, "classification": "synack"}, true},
		{`success = 1 && classification = "synack"`,
			map[string]any{"success": true, "classification": "rst"}, false},
		{`dport > 1023 && dport < 49152`, map[string]any{"dport": uint64(80)}, false},
		{`dport > 1023 && dport < 49152`, map[string]any{"dport": uint64(8080)}, true},
		{`!success`, map[string]any{"success": false}, true},
		{`!success`, map[string]any{"success": true}, false},
		{`success || classification = "rst"`,
			map[string]any{"success": false, "classification": "rst"}, true},
		{`(success = 1 || repeat = 1) && dport != 0`,
			map[string]any{"success": true, "repeat": false, "dport": uint64(80)}, true},
		{`dns_rcode = 0 && dns_ancount > 0`,
			map[string]any{"dns_rcode": uint64(0), "dns_ancount": uint64(2)}, true},
		{`ipid >= 0x0100`, map[string]any{"ipid": uint64(0x200)}, true},
	}
	for _, c := range cases {
		e, err := Parse(c.expr)
		if err != nil {
			t.Fatalf("parse %q: %v", c.expr, err)
		}
		if got := e.Match(c.row); got != c.want {
			t.Errorf("%q on %v = %v, want %v", c.expr, c.row, got, c.want)
		}
	}
}

func TestFilterParseErrors(t *testing.T) {
	bad := []string{`success = `, `success && `, `(success = 1`, `unterminated "`, `@`}
	for _, b := range bad {
		if _, err := Parse(b); err == nil {
			t.Errorf("expected parse error for %q", b)
		}
	}
}
