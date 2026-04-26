// Package filter implements zmap's output-filter expression language.
//
// Grammar (mirrors src/expression.c + src/lexer.l + src/parser.y):
//
//	expr     := or
//	or       := and ( "||" and )*
//	and      := not ( "&&" not )*
//	not      := "!" not | cmp
//	cmp      := primary ( ( "=" | "!=" | "<" | "<=" | ">" | ">=" ) primary )?
//	primary  := IDENT | INT | STRING | "(" expr ")"
//
// Identifiers reference Result fields (framework or module-specific). String
// literals use double quotes. Integers may be decimal or 0x-prefixed hex.
//
// Examples:
//
//	success = 1
//	success = 1 && classification = "synack"
//	dns_rcode = 0 && dns_ancount > 0
package filter

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Expression is a compiled filter.
type Expression struct {
	root node
}

// Match returns true if r satisfies the expression.
func (e *Expression) Match(r map[string]any) bool {
	if e == nil || e.root == nil {
		return true
	}
	v, _ := e.root.eval(r)
	return truthy(v)
}

// Parse compiles a filter expression.
func Parse(src string) (*Expression, error) {
	toks, err := tokenize(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	root, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("filter: unexpected token %q at offset %d", p.toks[p.pos].lit, p.toks[p.pos].pos)
	}
	return &Expression{root: root}, nil
}

// ---- AST ----

type node interface {
	eval(r map[string]any) (any, bool)
}

type binOp struct{ op, lhs, rhs interface{} }

type identNode struct{ name string }

func (n identNode) eval(r map[string]any) (any, bool) { v, ok := r[n.name]; return v, ok }

type intNode struct{ v int64 }

func (n intNode) eval(map[string]any) (any, bool) { return n.v, true }

type strNode struct{ v string }

func (n strNode) eval(map[string]any) (any, bool) { return n.v, true }

type cmpNode struct {
	op       string
	lhs, rhs node
}

func (n cmpNode) eval(r map[string]any) (any, bool) {
	a, _ := n.lhs.eval(r)
	b, _ := n.rhs.eval(r)
	return compare(a, b, n.op), true
}

type notNode struct{ x node }

func (n notNode) eval(r map[string]any) (any, bool) {
	v, _ := n.x.eval(r)
	return !truthy(v), true
}

type andNode struct{ a, b node }

func (n andNode) eval(r map[string]any) (any, bool) {
	if v, _ := n.a.eval(r); !truthy(v) {
		return false, true
	}
	v, _ := n.b.eval(r)
	return truthy(v), true
}

type orNode struct{ a, b node }

func (n orNode) eval(r map[string]any) (any, bool) {
	if v, _ := n.a.eval(r); truthy(v) {
		return true, true
	}
	v, _ := n.b.eval(r)
	return truthy(v), true
}

// ---- evaluator helpers ----

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int64:
		return x != 0
	case int:
		return x != 0
	case uint64:
		return x != 0
	case string:
		return x != ""
	}
	return true
}

func toInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case uint:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint64:
		return int64(x), true
	case float64:
		return int64(x), true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case string:
		if n, err := strconv.ParseInt(x, 0, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

func compare(a, b any, op string) bool {
	if as, aok := a.(string); aok {
		bs := fmt.Sprintf("%v", b)
		if bb, ok := b.(string); ok {
			bs = bb
		}
		switch op {
		case "=":
			return as == bs
		case "!=":
			return as != bs
		case "<":
			return as < bs
		case "<=":
			return as <= bs
		case ">":
			return as > bs
		case ">=":
			return as >= bs
		}
	}
	an, aok := toInt(a)
	bn, bok := toInt(b)
	if !aok || !bok {
		// Mixed/unknown: fall back to stringified equality only.
		if op == "=" {
			return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
		}
		if op == "!=" {
			return fmt.Sprintf("%v", a) != fmt.Sprintf("%v", b)
		}
		return false
	}
	switch op {
	case "=":
		return an == bn
	case "!=":
		return an != bn
	case "<":
		return an < bn
	case "<=":
		return an <= bn
	case ">":
		return an > bn
	case ">=":
		return an >= bn
	}
	return false
}

// ---- lexer ----

type token struct {
	kind string // ident, int, str, op, lparen, rparen
	lit  string
	pos  int
}

func tokenize(src string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{"lparen", "(", i})
			i++
		case c == ')':
			toks = append(toks, token{"rparen", ")", i})
			i++
		case c == '"':
			j := i + 1
			var sb strings.Builder
			for j < len(src) && src[j] != '"' {
				if src[j] == '\\' && j+1 < len(src) {
					sb.WriteByte(src[j+1])
					j += 2
					continue
				}
				sb.WriteByte(src[j])
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("filter: unterminated string at %d", i)
			}
			toks = append(toks, token{"str", sb.String(), i})
			i = j + 1
		case c == '&' && i+1 < len(src) && src[i+1] == '&':
			toks = append(toks, token{"op", "&&", i})
			i += 2
		case c == '|' && i+1 < len(src) && src[i+1] == '|':
			toks = append(toks, token{"op", "||", i})
			i += 2
		case c == '!':
			if i+1 < len(src) && src[i+1] == '=' {
				toks = append(toks, token{"op", "!=", i})
				i += 2
			} else {
				toks = append(toks, token{"op", "!", i})
				i++
			}
		case c == '=':
			toks = append(toks, token{"op", "=", i})
			i++
		case c == '<':
			if i+1 < len(src) && src[i+1] == '=' {
				toks = append(toks, token{"op", "<=", i})
				i += 2
			} else {
				toks = append(toks, token{"op", "<", i})
				i++
			}
		case c == '>':
			if i+1 < len(src) && src[i+1] == '=' {
				toks = append(toks, token{"op", ">=", i})
				i += 2
			} else {
				toks = append(toks, token{"op", ">", i})
				i++
			}
		case isDigit(c):
			j := i
			if c == '0' && i+1 < len(src) && (src[i+1] == 'x' || src[i+1] == 'X') {
				j += 2
				for j < len(src) && isHex(src[j]) {
					j++
				}
			} else {
				for j < len(src) && isDigit(src[j]) {
					j++
				}
			}
			toks = append(toks, token{"int", src[i:j], i})
			i = j
		case isIdentStart(c):
			j := i + 1
			for j < len(src) && isIdent(src[j]) {
				j++
			}
			toks = append(toks, token{"ident", src[i:j], i})
			i = j
		default:
			return nil, fmt.Errorf("filter: unexpected character %q at %d", c, i)
		}
	}
	return toks, nil
}

func isDigit(c byte) bool       { return c >= '0' && c <= '9' }
func isHex(c byte) bool         { return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }
func isIdentStart(c byte) bool  { return c == '_' || unicode.IsLetter(rune(c)) }
func isIdent(c byte) bool       { return isIdentStart(c) || isDigit(c) }

// ---- parser ----

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() *token {
	if p.pos >= len(p.toks) {
		return nil
	}
	return &p.toks[p.pos]
}
func (p *parser) eat() token { t := p.toks[p.pos]; p.pos++; return t }

func (p *parser) parseExpr() (node, error) { return p.parseOr() }

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t == nil || t.kind != "op" || t.lit != "||" {
			return left, nil
		}
		p.eat()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{a: left, b: right}
	}
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t == nil || t.kind != "op" || t.lit != "&&" {
			return left, nil
		}
		p.eat()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = andNode{a: left, b: right}
	}
}

func (p *parser) parseNot() (node, error) {
	t := p.peek()
	if t != nil && t.kind == "op" && t.lit == "!" {
		p.eat()
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return notNode{x}, nil
	}
	return p.parseCmp()
}

func (p *parser) parseCmp() (node, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	if t != nil && t.kind == "op" {
		switch t.lit {
		case "=", "!=", "<", "<=", ">", ">=":
			op := p.eat().lit
			right, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			return cmpNode{op: op, lhs: left, rhs: right}, nil
		}
	}
	return left, nil
}

func (p *parser) parsePrimary() (node, error) {
	t := p.peek()
	if t == nil {
		return nil, fmt.Errorf("filter: unexpected end of input")
	}
	switch t.kind {
	case "lparen":
		p.eat()
		x, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if p.peek() == nil || p.peek().kind != "rparen" {
			return nil, fmt.Errorf("filter: missing ')'")
		}
		p.eat()
		return x, nil
	case "int":
		p.eat()
		n, err := strconv.ParseInt(t.lit, 0, 64)
		if err != nil {
			return nil, err
		}
		return intNode{v: n}, nil
	case "str":
		p.eat()
		return strNode{v: t.lit}, nil
	case "ident":
		p.eat()
		return identNode{name: t.lit}, nil
	}
	return nil, fmt.Errorf("filter: unexpected token %q", t.lit)
}
