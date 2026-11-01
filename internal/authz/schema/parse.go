package schema

import (
	"fmt"
	"regexp"
	"strings"
)

// Limits keep a single schema from exhausting memory or stack.
const (
	MaxSchemaBytes  = 256 << 10
	MaxDefinitions  = 256
	MaxNamesPerDef  = 256
	MaxExprDepth    = 32
	MaxAllowedTypes = 32
)

var identRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ValidIdent reports whether s is a valid type, relation or permission name.
func ValidIdent(s string) bool { return identRe.MatchString(s) }

// Error is a schema error with a source position when one is known.
type Error struct {
	Line, Col int
	Msg       string
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("schema:%d:%d: %s", e.Line, e.Col, e.Msg)
	}
	return "schema: " + e.Msg
}

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tLBrace
	tRBrace
	tLParen
	tRParen
	tColon
	tPipe
	tHash
	tEq
	tPlus
	tAmp
	tMinus
	tArrow
	tStar
)

var tokNames = map[tokKind]string{
	tEOF: "end of input", tIdent: "name", tLBrace: "'{'", tRBrace: "'}'", tLParen: "'('", tRParen: "')'",
	tColon: "':'", tPipe: "'|'", tHash: "'#'", tEq: "'='", tPlus: "'+'", tAmp: "'&'", tMinus: "'-'",
	tArrow: "'->'", tStar: "'*'",
}

type token struct {
	kind      tokKind
	text      string
	line, col int
}

func lex(src string) ([]token, error) {
	var toks []token
	line, col := 1, 1
	i := 0
	adv := func(n int) {
		for k := 0; k < n; k++ {
			if src[i] == '\n' {
				line++
				col = 1
			} else {
				col++
			}
			i++
		}
	}
	single := map[byte]tokKind{'{': tLBrace, '}': tRBrace, '(': tLParen, ')': tRParen, ':': tColon, '|': tPipe,
		'#': tHash, '=': tEq, '+': tPlus, '&': tAmp, '*': tStar}
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			adv(1)
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				adv(1)
			}
		case c == '-':
			if i+1 < len(src) && src[i+1] == '>' {
				toks = append(toks, token{tArrow, "->", line, col})
				adv(2)
			} else {
				toks = append(toks, token{tMinus, "-", line, col})
				adv(1)
			}
		case single[c] != 0:
			toks = append(toks, token{single[c], string(c), line, col})
			adv(1)
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_':
			start, l, cl := i, line, col
			for i < len(src) {
				d := src[i]
				if d >= 'a' && d <= 'z' || d >= 'A' && d <= 'Z' || d >= '0' && d <= '9' || d == '_' {
					adv(1)
					continue
				}
				break
			}
			toks = append(toks, token{tIdent, src[start:i], l, cl})
		default:
			return nil, &Error{line, col, fmt.Sprintf("unexpected character %q", c)}
		}
	}
	toks = append(toks, token{tEOF, "", line, col})
	return toks, nil
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != tEOF {
		p.pos++
	}
	return t
}

func (p *parser) expect(k tokKind) (token, error) {
	t := p.next()
	if t.kind != k {
		return t, p.errAt(t, fmt.Sprintf("expected %s, found %s", tokNames[k], describe(t)))
	}
	return t, nil
}

func (p *parser) errAt(t token, msg string) error { return &Error{t.line, t.col, msg} }

func describe(t token) string {
	if t.kind == tIdent {
		return fmt.Sprintf("%q", t.text)
	}
	return tokNames[t.kind]
}

func (p *parser) ident(what string) (token, error) {
	t, err := p.expect(tIdent)
	if err != nil {
		return t, err
	}
	if !ValidIdent(t.text) {
		return t, p.errAt(t, fmt.Sprintf("invalid %s name %q: use lowercase letters, digits and underscores, starting with a letter (max 64)", what, t.text))
	}
	return t, nil
}

// Parse parses and validates schema source.
func Parse(src string) (*Schema, error) {
	if len(src) > MaxSchemaBytes {
		return nil, &Error{Msg: fmt.Sprintf("schema is larger than %d bytes", MaxSchemaBytes)}
	}
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	s := &Schema{Defs: map[string]*Definition{}}
	for p.peek().kind != tEOF {
		kw := p.next()
		if kw.kind != tIdent || kw.text != "definition" {
			return nil, p.errAt(kw, fmt.Sprintf("expected \"definition\", found %s", describe(kw)))
		}
		name, err := p.ident("definition")
		if err != nil {
			return nil, err
		}
		if _, dup := s.Defs[name.text]; dup {
			return nil, p.errAt(name, fmt.Sprintf("definition %q is declared twice", name.text))
		}
		if len(s.Order) >= MaxDefinitions {
			return nil, p.errAt(name, fmt.Sprintf("too many definitions (max %d)", MaxDefinitions))
		}
		d, err := p.definition(name.text)
		if err != nil {
			return nil, err
		}
		s.Defs[d.Name] = d
		s.Order = append(s.Order, d.Name)
	}
	if err := validate(s); err != nil {
		return nil, err
	}
	return s, nil
}

func (p *parser) definition(name string) (*Definition, error) {
	d := &Definition{Name: name, Relations: map[string]*Relation{}, Permissions: map[string]*Permission{}}
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	for {
		t := p.next()
		if t.kind == tRBrace {
			return d, nil
		}
		if t.kind != tIdent || (t.text != "relation" && t.text != "permission") {
			return nil, p.errAt(t, fmt.Sprintf("expected \"relation\", \"permission\" or '}', found %s", describe(t)))
		}
		n, err := p.ident(t.text)
		if err != nil {
			return nil, err
		}
		if d.Has(n.text) {
			return nil, p.errAt(n, fmt.Sprintf("%q is declared twice in definition %q", n.text, name))
		}
		if len(d.Order) >= MaxNamesPerDef {
			return nil, p.errAt(n, fmt.Sprintf("too many relations and permissions in %q (max %d)", name, MaxNamesPerDef))
		}
		if t.text == "relation" {
			r, err := p.relation(n.text)
			if err != nil {
				return nil, err
			}
			d.Relations[r.Name] = r
		} else {
			if _, err := p.expect(tEq); err != nil {
				return nil, err
			}
			e, err := p.expr(0)
			if err != nil {
				return nil, err
			}
			d.Permissions[n.text] = &Permission{Name: n.text, Expr: e}
		}
		d.Order = append(d.Order, n.text)
	}
}

func (p *parser) relation(name string) (*Relation, error) {
	if _, err := p.expect(tColon); err != nil {
		return nil, err
	}
	r := &Relation{Name: name}
	seen := map[string]bool{}
	for {
		tn, err := p.ident("type")
		if err != nil {
			return nil, err
		}
		st := SubjectType{Type: tn.text}
		switch p.peek().kind {
		case tColon:
			p.next()
			if _, err := p.expect(tStar); err != nil {
				return nil, err
			}
			st.Wildcard = true
		case tHash:
			p.next()
			rn, err := p.ident("relation")
			if err != nil {
				return nil, err
			}
			st.Relation = rn.text
		}
		if seen[st.String()] {
			return nil, p.errAt(tn, fmt.Sprintf("subject type %q is listed twice", st.String()))
		}
		seen[st.String()] = true
		if len(r.Allowed) >= MaxAllowedTypes {
			return nil, p.errAt(tn, fmt.Sprintf("too many subject types (max %d)", MaxAllowedTypes))
		}
		r.Allowed = append(r.Allowed, st)
		if p.peek().kind != tPipe {
			return r, nil
		}
		p.next()
	}
}

// Binding power: exclusion < union < intersection.
func precedence(k tokKind) int {
	switch k {
	case tMinus:
		return 1
	case tPlus:
		return 2
	case tAmp:
		return 3
	}
	return 0
}

func (p *parser) expr(depth int) (Expr, error) {
	return p.binary(1, depth)
}

func (p *parser) binary(minPrec, depth int) (Expr, error) {
	if depth > MaxExprDepth {
		return nil, p.errAt(p.peek(), fmt.Sprintf("expression is nested too deeply (max %d)", MaxExprDepth))
	}
	left, err := p.primary(depth)
	if err != nil {
		return nil, err
	}
	for {
		op := p.peek()
		prec := precedence(op.kind)
		if prec == 0 || prec < minPrec {
			return left, nil
		}
		p.next()
		right, err := p.binary(prec+1, depth+1)
		if err != nil {
			return nil, err
		}
		switch op.kind {
		case tPlus:
			left = &Union{left, right}
		case tAmp:
			left = &Intersection{left, right}
		default:
			left = &Exclusion{left, right}
		}
	}
}

func (p *parser) primary(depth int) (Expr, error) {
	if p.peek().kind == tLParen {
		p.next()
		e, err := p.binary(1, depth+1)
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tRParen); err != nil {
			return nil, err
		}
		return e, nil
	}
	n, err := p.ident("relation")
	if err != nil {
		return nil, err
	}
	if p.peek().kind == tArrow {
		p.next()
		c, err := p.ident("permission")
		if err != nil {
			return nil, err
		}
		return &Arrow{Tupleset: n.text, Computed: c.text}, nil
	}
	return &Ref{Name: n.text}, nil
}

func validate(s *Schema) error {
	for _, dn := range s.Order {
		d := s.Defs[dn]
		for _, n := range d.Order {
			if r, ok := d.Relations[n]; ok {
				for _, a := range r.Allowed {
					target, ok := s.Defs[a.Type]
					if !ok {
						return &Error{Msg: fmt.Sprintf("%s#%s allows unknown type %q", dn, n, a.Type)}
					}
					if a.Relation != "" && !target.Has(a.Relation) {
						return &Error{Msg: fmt.Sprintf("%s#%s allows %s, but %q has no relation or permission %q", dn, n, a, a.Type, a.Relation)}
					}
				}
				continue
			}
			if err := validateExpr(s, d, n, d.Permissions[n].Expr); err != nil {
				return err
			}
		}
		if err := checkPermissionCycles(d); err != nil {
			return err
		}
	}
	return nil
}

func validateExpr(s *Schema, d *Definition, perm string, e Expr) error {
	switch e := e.(type) {
	case *Ref:
		if !d.Has(e.Name) {
			return &Error{Msg: fmt.Sprintf("%s#%s refers to %q, which is not declared in %q", d.Name, perm, e.Name, d.Name)}
		}
	case *Arrow:
		r, ok := d.Relations[e.Tupleset]
		if !ok {
			if d.IsPermission(e.Tupleset) {
				return &Error{Msg: fmt.Sprintf("%s#%s: the left side of %s must be a relation, not a permission", d.Name, perm, e)}
			}
			return &Error{Msg: fmt.Sprintf("%s#%s: %q in %s is not a relation of %q", d.Name, perm, e.Tupleset, e, d.Name)}
		}
		for _, a := range r.Allowed {
			if a.Relation != "" || a.Wildcard {
				return &Error{Msg: fmt.Sprintf("%s#%s: %s follows %s#%s, which allows %s; arrows need plain object types", d.Name, perm, e, d.Name, r.Name, a)}
			}
			target, ok := s.Defs[a.Type]
			if !ok {
				// The relation is checked again in declaration order, but a
				// permission declared before it reaches here first.
				return &Error{Msg: fmt.Sprintf("%s#%s allows unknown type %q", d.Name, r.Name, a.Type)}
			}
			if !target.Has(e.Computed) {
				return &Error{Msg: fmt.Sprintf("%s#%s: %s reaches type %q, which has no relation or permission %q", d.Name, perm, e, a.Type, e.Computed)}
			}
		}
	case *Union:
		return firstErr(validateExpr(s, d, perm, e.L), func() error { return validateExpr(s, d, perm, e.R) })
	case *Intersection:
		return firstErr(validateExpr(s, d, perm, e.L), func() error { return validateExpr(s, d, perm, e.R) })
	case *Exclusion:
		return firstErr(validateExpr(s, d, perm, e.L), func() error { return validateExpr(s, d, perm, e.R) })
	}
	return nil
}

func firstErr(err error, next func() error) error {
	if err != nil {
		return err
	}
	return next()
}

// checkPermissionCycles rejects permissions that depend on themselves without
// going through stored data (e.g. "permission a = b" and "permission b = a").
func checkPermissionCycles(d *Definition) error {
	const (
		unvisited = iota
		visiting
		done
	)
	state := map[string]int{}
	var visit func(name string, path []string) error
	visit = func(name string, path []string) error {
		switch state[name] {
		case visiting:
			return &Error{Msg: fmt.Sprintf("permissions in %q depend on themselves: %s", d.Name, strings.Join(append(path, name), " -> "))}
		case done:
			return nil
		}
		state[name] = visiting
		for _, dep := range localRefs(d.Permissions[name].Expr) {
			if d.IsPermission(dep) {
				if err := visit(dep, append(path, name)); err != nil {
					return err
				}
			}
		}
		state[name] = done
		return nil
	}
	for _, n := range d.Order {
		if d.IsPermission(n) {
			if err := visit(n, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func localRefs(e Expr) []string {
	switch e := e.(type) {
	case *Ref:
		return []string{e.Name}
	case *Union:
		return append(localRefs(e.L), localRefs(e.R)...)
	case *Intersection:
		return append(localRefs(e.L), localRefs(e.R)...)
	case *Exclusion:
		return append(localRefs(e.L), localRefs(e.R)...)
	}
	return nil
}
