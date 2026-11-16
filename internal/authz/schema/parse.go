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
	MaxCaveats      = 256
	MaxCaveatParams = 32
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
	tComma
	tLAngle
	tRAngle
	tErr // a lexical error; text holds the message
)

var tokNames = map[tokKind]string{
	tEOF: "end of input", tIdent: "name", tLBrace: "'{'", tRBrace: "'}'", tLParen: "'('", tRParen: "')'",
	tColon: "':'", tPipe: "'|'", tHash: "'#'", tEq: "'='", tPlus: "'+'", tAmp: "'&'", tMinus: "'-'",
	tArrow: "'->'", tStar: "'*'", tComma: "','", tLAngle: "'<'", tRAngle: "'>'",
}

type token struct {
	kind      tokKind
	text      string
	line, col int
}

var single = [256]tokKind{'{': tLBrace, '}': tRBrace, '(': tLParen, ')': tRParen, ':': tColon, '|': tPipe,
	'#': tHash, '=': tEq, '+': tPlus, '&': tAmp, '*': tStar, ',': tComma, '<': tLAngle, '>': tRAngle}

// lexer produces tokens on demand, so the parser can hand the body of a
// caveat, which is CEL and not schema syntax, to the CEL parser instead.
type lexer struct {
	src       string
	i         int
	line, col int
}

func (l *lexer) adv(n int) {
	for k := 0; k < n; k++ {
		if l.src[l.i] == '\n' {
			l.line++
			l.col = 1
		} else {
			l.col++
		}
		l.i++
	}
}

func isNameByte(d byte) bool {
	return d >= 'a' && d <= 'z' || d >= 'A' && d <= 'Z' || d >= '0' && d <= '9' || d == '_'
}

// next returns the next token, or a tErr token at the first character no
// token starts with.
func (l *lexer) next() token {
	for l.i < len(l.src) {
		c := l.src[l.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			l.adv(1)
		case c == '/' && l.i+1 < len(l.src) && l.src[l.i+1] == '/':
			for l.i < len(l.src) && l.src[l.i] != '\n' {
				l.adv(1)
			}
		case c == '-':
			t := token{tMinus, "-", l.line, l.col}
			if l.i+1 < len(l.src) && l.src[l.i+1] == '>' {
				t.kind, t.text = tArrow, "->"
			}
			l.adv(len(t.text))
			return t
		case single[c] != 0:
			t := token{single[c], string(c), l.line, l.col}
			l.adv(1)
			return t
		case isNameByte(c):
			start, line, col := l.i, l.line, l.col
			for l.i < len(l.src) && isNameByte(l.src[l.i]) {
				l.adv(1)
			}
			return token{tIdent, l.src[start:l.i], line, col}
		default:
			return token{tErr, fmt.Sprintf("unexpected character %q", c), l.line, l.col}
		}
	}
	return token{tEOF, "", l.line, l.col}
}

// celBody reads the source of a caveat expression, from just after its '{'
// up to the '}' that closes it, skipping braces inside CEL strings,
// comments and map literals. It consumes the closing brace and returns the
// body with the line and column where it starts.
func (l *lexer) celBody() (body string, line, col int, err error) {
	start, line, col := l.i, l.line, l.col
	depth := 0
	for l.i < len(l.src) {
		c := l.src[l.i]
		switch {
		case c == '{':
			depth++
		case c == '}':
			if depth == 0 {
				body = l.src[start:l.i]
				l.adv(1)
				return body, line, col, nil
			}
			depth--
		case c == '/' && l.i+1 < len(l.src) && l.src[l.i+1] == '/':
			for l.i < len(l.src) && l.src[l.i] != '\n' {
				l.adv(1)
			}
			continue
		case c == '"' || c == '\'':
			if err := l.celString(); err != nil {
				return "", 0, 0, err
			}
			continue
		}
		l.adv(1)
	}
	return "", 0, 0, &Error{line, col, "caveat expression has no closing '}'"}
}

// celString skips a CEL string literal starting at the quote at l.i: single
// or triple quoted, with backslash escapes unless an r or R before the
// quote makes it raw. It only has to find where the string ends; the CEL
// parser checks what is inside.
func (l *lexer) celString() error {
	line, col := l.line, l.col
	q := l.src[l.i]
	raw := l.i > 0 && (l.src[l.i-1] == 'r' || l.src[l.i-1] == 'R')
	triple := strings.HasPrefix(l.src[l.i:], strings.Repeat(string(q), 3))
	if triple {
		l.adv(3)
	} else {
		l.adv(1)
	}
	for l.i < len(l.src) {
		c := l.src[l.i]
		switch {
		case c == '\\' && !raw && l.i+1 < len(l.src):
			l.adv(2)
			continue
		case c == q && !triple:
			l.adv(1)
			return nil
		case c == q && strings.HasPrefix(l.src[l.i:], strings.Repeat(string(q), 3)):
			l.adv(3)
			return nil
		case c == '\n' && !triple:
			return &Error{l.line, l.col, "newline in string in caveat expression"}
		}
		l.adv(1)
	}
	return &Error{line, col, "string in caveat expression has no closing quote"}
}

type parser struct {
	lx    lexer
	tok   token
	ahead bool // tok holds the next token
}

func (p *parser) peek() token {
	if !p.ahead {
		p.tok, p.ahead = p.lx.next(), true
	}
	return p.tok
}

func (p *parser) next() token {
	t := p.peek()
	if t.kind != tEOF && t.kind != tErr {
		p.ahead = false
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

// errAt reports msg at t, or the lexical error t holds.
func (p *parser) errAt(t token, msg string) error {
	if t.kind == tErr {
		msg = t.text
	}
	return &Error{t.line, t.col, msg}
}

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
	p := &parser{lx: lexer{src: src, line: 1, col: 1}}
	s := &Schema{Defs: map[string]*Definition{}, Caveats: map[string]*Caveat{}}
	for p.peek().kind != tEOF {
		kw := p.next()
		if kw.kind != tIdent || kw.text != "definition" && kw.text != "caveat" {
			return nil, p.errAt(kw, fmt.Sprintf("expected \"definition\" or \"caveat\", found %s", describe(kw)))
		}
		name, err := p.ident(kw.text)
		if err != nil {
			return nil, err
		}
		if _, dup := s.Defs[name.text]; dup {
			return nil, p.errAt(name, fmt.Sprintf("definition %q is declared twice", name.text))
		}
		if _, dup := s.Caveats[name.text]; dup {
			return nil, p.errAt(name, fmt.Sprintf("caveat %q is declared twice", name.text))
		}
		if kw.text == "caveat" {
			if len(s.CaveatOrder) >= MaxCaveats {
				return nil, p.errAt(name, fmt.Sprintf("too many caveats (max %d)", MaxCaveats))
			}
			c, err := p.caveat(name)
			if err != nil {
				return nil, err
			}
			s.Caveats[c.Name] = c
			s.CaveatOrder = append(s.CaveatOrder, c.Name)
			continue
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
		if t := p.peek(); t.kind == tIdent && t.text == "with" {
			p.next()
			cn, err := p.ident("caveat")
			if err != nil {
				return nil, err
			}
			st.Caveat = cn.text
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
					if _, ok := s.Caveats[a.Caveat]; a.Caveat != "" && !ok {
						return &Error{Msg: fmt.Sprintf("%s#%s allows %s, but there is no caveat %q", dn, n, a, a.Caveat)}
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
