package schema

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/laiwf94/authz/internal/platform/cel"
)

// Caveat is a named condition a relationship can carry. The relationship
// grants only when the caveat's expression is true for the context stored
// with the relationship merged with the context given to the check:
//
//	caveat ip_allowed(allowed cidr, client_ip ipaddress) {
//	  allowed.containsIP(client_ip)
//	}
//
// The expression is in the CEL subset of internal/platform/cel, checked
// against the typed parameters when the schema is parsed, and must be a
// bool.
type Caveat struct {
	Name   string
	Params []CaveatParam // in source order
	// Expr is the expression's source, without the whitespace around it.
	Expr string
	// Checked is the type-checked expression, and Program it ready to
	// evaluate with cel.DefaultMaxCost.
	Checked *cel.Checked
	Program *cel.Program
}

// CaveatParam is one typed parameter of a caveat.
type CaveatParam struct {
	Name string
	Type *cel.Type
}

// Param returns the type of the named parameter.
func (c *Caveat) Param(name string) (*cel.Type, bool) {
	for _, p := range c.Params {
		if p.Name == name {
			return p.Type, true
		}
	}
	return nil, false
}

// ValidateContext checks a context to store with a relationship, or to send
// with a check: every key must be a parameter of the caveat and every value
// must be one Eval takes for its type, as encoding/json decodes it or as a
// native Go value. Parameters it leaves out are allowed; the check names
// them when the answer depends on them.
func (c *Caveat) ValidateContext(ctx map[string]any) error {
	keys := make([]string, 0, len(ctx))
	for k := range ctx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t, ok := c.Param(k)
		if !ok {
			return fmt.Errorf("caveat %s has no parameter %q", c.Name, k)
		}
		if err := t.Accepts(ctx[k]); err != nil {
			return fmt.Errorf("caveat %s parameter %s %v", c.Name, k, err)
		}
	}
	return nil
}

// signature renders the parameter list: "(allowed cidr, client_ip ipaddress)".
func (c *Caveat) signature() string {
	parts := make([]string, len(c.Params))
	for i, p := range c.Params {
		parts[i] = p.Name + " " + p.Type.String()
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// meaning renders the signature and the parsed expression, so caveats that
// differ only in spacing, comments or redundant parentheses compare equal.
func (c *Caveat) meaning() string {
	return c.signature() + " " + c.Checked.AST().String()
}

// caveat parses the rest of a caveat declaration after its name.
func (p *parser) caveat(name token) (*Caveat, error) {
	c := &Caveat{Name: name.text}
	if _, err := p.expect(tLParen); err != nil {
		return nil, err
	}
	var vars []cel.Var
	for {
		pn, err := p.ident("parameter")
		if err != nil {
			return nil, err
		}
		if _, dup := c.Param(pn.text); dup {
			return nil, p.errAt(pn, fmt.Sprintf("parameter %q is declared twice in caveat %q", pn.text, c.Name))
		}
		if len(c.Params) >= MaxCaveatParams {
			return nil, p.errAt(pn, fmt.Sprintf("too many parameters in caveat %q (max %d)", c.Name, MaxCaveatParams))
		}
		if _, err := cel.NewEnv([]cel.Var{{Name: pn.text, Type: cel.Bool}}); err != nil {
			return nil, p.errAt(pn, fmt.Sprintf("parameter name %q is reserved in caveat expressions", pn.text))
		}
		tt := p.peek()
		src, err := p.typeSource(0)
		if err != nil {
			return nil, err
		}
		typ, err := cel.ParseType(src)
		if err != nil {
			return nil, p.errAt(tt, fmt.Sprintf("parameter %s of caveat %q: %v", pn.text, c.Name, err))
		}
		c.Params = append(c.Params, CaveatParam{Name: pn.text, Type: typ})
		vars = append(vars, cel.Var{Name: pn.text, Type: typ})
		t := p.next()
		if t.kind == tRParen {
			break
		}
		if t.kind != tComma {
			return nil, p.errAt(t, fmt.Sprintf("expected ',' or ')', found %s", describe(t)))
		}
	}
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	// The '{' was the lookahead, so the lexer stands just after it.
	body, line, col, err := p.lx.celBody()
	if err != nil {
		return nil, err
	}
	env, err := cel.NewEnv(vars)
	if err != nil { // the names and types were checked above
		return nil, p.errAt(name, err.Error())
	}
	checked, err := env.CompileAs(body, cel.Bool)
	if err != nil {
		return nil, celError(c.Name, line, col, err)
	}
	c.Expr = strings.Trim(body, " \t\r\n")
	c.Checked, c.Program = checked, checked.Program(0)
	return c, nil
}

// celError places the first problem CEL found in a caveat body, which
// starts at line:col of the schema.
func celError(caveat string, line, col int, err error) error {
	var es cel.Errors
	if !errors.As(err, &es) || len(es) == 0 {
		return &Error{line, col, fmt.Sprintf("caveat %q: %v", caveat, err)}
	}
	e := es[0]
	msg := fmt.Sprintf("caveat %q: %s", caveat, e.Msg)
	if len(es) > 1 {
		msg += fmt.Sprintf(" (and %d more)", len(es)-1)
	}
	if e.Line > 1 {
		line, col = line+e.Line-1, e.Column
	} else {
		col += e.Column - 1
	}
	return &Error{line, col, msg}
}

// maxTypeNesting bounds a parameter type's nesting before cel.ParseType
// sees it, so a long run of '<' cannot recurse deeply here.
const maxTypeNesting = 16

// typeSource reads a parameter type such as "list<string>" or
// "map<string, int>" and returns it as cel.ParseType reads it.
func (p *parser) typeSource(depth int) (string, error) {
	t := p.next()
	if t.kind != tIdent {
		return "", p.errAt(t, fmt.Sprintf("expected a type, found %s", describe(t)))
	}
	if p.peek().kind != tLAngle {
		return t.text, nil
	}
	if depth >= maxTypeNesting {
		return "", p.errAt(p.peek(), fmt.Sprintf("type is nested too deeply (max %d)", maxTypeNesting))
	}
	p.next()
	var b strings.Builder
	b.WriteString(t.text)
	b.WriteString("<")
	for {
		arg, err := p.typeSource(depth + 1)
		if err != nil {
			return "", err
		}
		b.WriteString(arg)
		t := p.next()
		switch t.kind {
		case tRAngle:
			b.WriteString(">")
			return b.String(), nil
		case tComma:
			b.WriteString(", ")
		default:
			return "", p.errAt(t, fmt.Sprintf("expected ',' or '>', found %s", describe(t)))
		}
	}
}
