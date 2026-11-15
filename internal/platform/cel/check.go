package cel

import (
	"fmt"
	"slices"
	"strings"
)

// Var declares a variable an expression may use: a caveat parameter, or a
// fact a tool rule is evaluated against.
type Var struct {
	Name string
	Type *Type
}

// Env is the set of variables expressions are checked against, and the
// limits they are held to. An Env is safe for concurrent use.
type Env struct {
	vars map[string]*Type
	lim  Limits
}

// Option configures an Env.
type Option func(*Env)

// WithLimits replaces DefaultLimits.
func WithLimits(l Limits) Option { return func(e *Env) { e.lim = l } }

// NewEnv declares vars. Names must be identifiers that are not keywords or
// reserved words, each declared once.
func NewEnv(vars []Var, opts ...Option) (*Env, error) {
	e := &Env{vars: make(map[string]*Type, len(vars)), lim: DefaultLimits}
	for _, o := range opts {
		o(e)
	}
	if e.lim.MaxSourceBytes <= 0 || e.lim.MaxDepth <= 0 || e.lim.MaxNodes <= 0 {
		return nil, fmt.Errorf("cel: limits must be positive: %+v", e.lim)
	}
	for _, v := range vars {
		if !isIdentifier(v.Name) {
			return nil, fmt.Errorf("cel: variable name %q is not an identifier", v.Name)
		}
		if reserved[v.Name] || keywords[v.Name] {
			return nil, fmt.Errorf("cel: variable name %q is a reserved word", v.Name)
		}
		if v.Type == nil || hasParam(v.Type) {
			return nil, fmt.Errorf("cel: variable %q has no type", v.Name)
		}
		if _, dup := e.vars[v.Name]; dup {
			return nil, fmt.Errorf("cel: variable %q is declared twice", v.Name)
		}
		e.vars[v.Name] = v.Type
	}
	return e, nil
}

var keywords = map[string]bool{"true": true, "false": true, "null": true, "in": true}

func isIdentifier(s string) bool {
	if s == "" || isDigit(s[0]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentByte(s[i]) {
			return false
		}
	}
	return true
}

func hasParam(t *Type) bool {
	switch t.kind {
	case KindParam:
		return true
	case KindList:
		return hasParam(t.elem)
	case KindMap:
		return hasParam(t.key) || hasParam(t.elem)
	}
	return false
}

// Lookup returns the declared type of a variable.
func (e *Env) Lookup(name string) (*Type, bool) {
	t, ok := e.vars[name]
	return t, ok
}

// Parse parses src under the Env's limits.
func (e *Env) Parse(src string) (*AST, error) { return parse(src, e.lim) }

// Compile parses and checks src.
func (e *Env) Compile(src string) (*Checked, error) {
	a, err := e.Parse(src)
	if err != nil {
		return nil, err
	}
	return e.Check(a)
}

// CompileAs compiles src and requires its result to have type want. A dyn
// result is accepted, as its type is known only when it runs.
func (e *Env) CompileAs(src string, want *Type) (*Checked, error) {
	c, err := e.Compile(src)
	if err != nil {
		return nil, err
	}
	if !assignable(want, c.Type()) {
		return nil, locate(src, Errors{errorf(c.ast.Root.Pos, "expression is %s, want %s", c.Type(), want)})
	}
	return c, nil
}

// Checked is a type-checked expression: its AST with the type of every node,
// the overloads each call can resolve to, and its string-literal arguments
// already parsed.
type Checked struct {
	env       *Env
	ast       *AST
	types     []*Type
	overloads [][]string
	consts    map[int]any
	vars      []string
}

// AST returns the checked expression.
func (c *Checked) AST() *AST { return c.ast }

// Type returns the type of the whole expression.
func (c *Checked) Type() *Type { return c.types[c.ast.Root.ID] }

// TypeOf returns the type of a node of the AST.
func (c *Checked) TypeOf(n *Node) *Type { return c.types[n.ID] }

// Overloads returns the IDs of the overloads a call node can resolve to,
// in table order. It is one ID unless an argument is dyn.
func (c *Checked) Overloads(n *Node) []string { return c.overloads[n.ID] }

// Constant returns the value parsed from a string-literal argument the
// checker parsed in advance: a time.Time, time.Duration, *regexp.Regexp,
// *time.Location, netip.Addr or netip.Prefix.
func (c *Checked) Constant(n *Node) (any, bool) {
	v, ok := c.consts[n.ID]
	return v, ok
}

// Vars returns the names of the declared variables the expression refers
// to, sorted. A caveat whose context lacks some of them may be conditional.
func (c *Checked) Vars() []string { return c.vars }

// Check type-checks a parsed expression. The AST must come from this Env's
// Parse or from Parse; it is not changed and may be checked again.
func (e *Env) Check(a *AST) (*Checked, error) {
	k := &checker{
		env: e,
		c: &Checked{
			env:       e,
			ast:       a,
			types:     make([]*Type, a.nodes),
			overloads: make([][]string, a.nodes),
			consts:    map[int]any{},
		},
		used: map[string]bool{},
	}
	k.check(a.Root)
	if len(k.errs) > 0 {
		slices.SortStableFunc(k.errs, func(x, y *Error) int { return x.Pos - y.Pos })
		return nil, locate(a.Source, k.errs)
	}
	for name := range k.used {
		k.c.vars = append(k.c.vars, name)
	}
	slices.Sort(k.c.vars)
	return k.c, nil
}

type binding struct {
	name string
	t    *Type
}

type checker struct {
	env    *Env
	c      *Checked
	errs   Errors
	scopes []binding
	used   map[string]bool
}

func (k *checker) errorf(pos int, format string, args ...any) {
	if len(k.errs) < maxErrors {
		k.errs = append(k.errs, errorf(pos, format, args...))
	}
}

func (k *checker) check(n *Node) *Type {
	t := k.typeOf(n)
	k.c.types[n.ID] = t
	return t
}

func (k *checker) typeOf(n *Node) *Type {
	switch n.Kind {
	case NodeLiteral:
		switch n.Value.(type) {
		case nil:
			return Null
		case bool:
			return Bool
		case int64:
			return Int
		case uint64:
			return Uint
		case float64:
			return Double
		case string:
			return String
		}
		k.errorf(n.Pos, "literal of unsupported type %T", n.Value)
		return Dyn
	case NodeIdent:
		for i := len(k.scopes) - 1; i >= 0; i-- {
			if k.scopes[i].name == n.Name {
				return k.scopes[i].t
			}
		}
		if t, ok := k.env.vars[n.Name]; ok {
			k.used[n.Name] = true
			return t
		}
		k.errorf(n.Pos, "undeclared reference to '%s'", n.Name)
		return Dyn
	case NodeSelect:
		return k.selectField(n)
	case NodeList:
		var elem *Type
		for _, a := range n.Args {
			elem = join(elem, k.check(a))
		}
		if elem == nil {
			elem = Dyn
		}
		return ListOf(elem)
	case NodeMap:
		return k.mapLiteral(n)
	case NodeComprehension:
		return k.comprehension(n)
	case NodeCall:
		return k.call(n)
	}
	k.errorf(n.Pos, "unknown node kind %d", n.Kind)
	return Dyn
}

func (k *checker) selectField(n *Node) *Type {
	t := k.check(n.Target)
	result := func(v *Type) *Type {
		if n.TestOnly {
			return Bool
		}
		return v
	}
	switch {
	case t.kind == KindDyn:
		return result(Dyn)
	case t.kind == KindMap && (t.key.kind == KindString || t.key.kind == KindDyn):
		return result(t.elem)
	}
	k.errorf(n.Pos, "'%s' selects a field of %s, but only maps with string keys have fields", n.Name, t)
	return result(Dyn)
}

func (k *checker) mapLiteral(n *Node) *Type {
	var key, value *Type
	seen := map[any]int{}
	for i := 0; i < len(n.Args); i += 2 {
		kn := n.Args[i]
		kt := k.check(kn)
		if !validKey(kt) {
			k.errorf(kn.Pos, "map keys must be bool, int, uint or string, not %s", kt)
			kt = Dyn
		}
		if kn.Kind == NodeLiteral {
			if _, dup := seen[kn.Value]; dup {
				k.errorf(kn.Pos, "map key %s appears twice", kn)
			}
			seen[kn.Value] = i
		}
		key = join(key, kt)
		value = join(value, k.check(n.Args[i+1]))
	}
	if key == nil {
		key, value = Dyn, Dyn
	}
	return &Type{kind: KindMap, key: key, elem: value}
}

func (k *checker) comprehension(n *Node) *Type {
	name := n.Macro.String()
	rt := k.check(n.Target)
	var iter *Type
	switch rt.kind {
	case KindList:
		iter = rt.elem
	case KindMap:
		iter = rt.key
	case KindDyn:
		iter = Dyn
	default:
		k.errorf(n.Pos, "%s() needs a list or a map, not %s", name, rt)
		iter = Dyn
	}
	k.scopes = append(k.scopes, binding{n.Name, iter})
	defer func() { k.scopes = k.scopes[:len(k.scopes)-1] }()
	predicate := func(a *Node, what string) {
		if t := k.check(a); !assignable(Bool, t) {
			k.errorf(a.Pos, "the %s of %s() must be bool, not %s", what, name, t)
		}
	}
	switch n.Macro {
	case MacroAll, MacroExists, MacroExistsOne:
		predicate(n.Args[0], "predicate")
		return Bool
	case MacroFilter:
		predicate(n.Args[0], "predicate")
		if rt.kind == KindList {
			return rt
		}
		return ListOf(iter)
	}
	// MacroMap
	if len(n.Args) == 2 {
		predicate(n.Args[0], "filter")
	}
	return ListOf(k.check(n.Args[len(n.Args)-1]))
}

func (k *checker) call(n *Node) *Type {
	var operands []*Node
	if n.Target != nil {
		operands = append(operands, n.Target)
	}
	operands = append(operands, n.Args...)
	args := make([]*Type, len(operands))
	for i, a := range operands {
		args[i] = k.check(a)
	}
	ovs, known := functions[n.Name]
	if !known {
		k.errorf(n.Pos, "undeclared function '%s'", n.Name)
		return Dyn
	}
	var result *Type
	var matched []string
	isMember := n.Target != nil
	for _, o := range ovs {
		if o.member != isMember || len(o.params) != len(args) {
			continue
		}
		b := map[string]*Type{}
		ok := true
		for i, p := range o.params {
			if !unify(p, args[i], b) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		matched = append(matched, o.id)
		result = join(result, substitute(o.result, b))
		if c, ok := constantArgs[o.id]; ok {
			k.constant(operands[c.index], c)
		}
	}
	if matched == nil {
		if n.Name == OpConditional && len(args) == 3 {
			if !assignable(Bool, args[0]) {
				k.errorf(n.Pos, "the condition of '?:' must be bool, not %s", args[0])
			} else {
				k.errorf(n.Pos, "the branches of '?:' have different types, %s and %s", args[1], args[2])
			}
			return Dyn
		}
		k.errorf(n.Pos, "no matching overload for %s", describeCall(n, args))
		return Dyn
	}
	k.c.overloads[n.ID] = matched
	return result
}

// constant parses a string-literal argument in advance.
func (k *checker) constant(a *Node, c constantArg) {
	s, ok := a.Value.(string)
	if a.Kind != NodeLiteral || !ok {
		return
	}
	if _, done := k.c.consts[a.ID]; done {
		return
	}
	v, err := c.parse(s)
	if err != nil {
		k.errorf(a.Pos, "%v", err)
		return
	}
	k.c.consts[a.ID] = v
}

func describeCall(n *Node, args []*Type) string {
	names := make([]string, len(args))
	for i, t := range args {
		names[i] = t.String()
	}
	if sym, ok := binarySymbols[n.Name]; ok {
		return fmt.Sprintf("'%s' applied to (%s)", sym, strings.Join(names, ", "))
	}
	switch n.Name {
	case OpNeg:
		return fmt.Sprintf("'-' applied to (%s)", strings.Join(names, ", "))
	case OpNot:
		return fmt.Sprintf("'!' applied to (%s)", strings.Join(names, ", "))
	case OpIndex:
		return fmt.Sprintf("'[]' applied to (%s)", strings.Join(names, ", "))
	}
	if n.Target != nil {
		return fmt.Sprintf("%s.%s(%s)", names[0], n.Name, strings.Join(names[1:], ", "))
	}
	return fmt.Sprintf("%s(%s)", n.Name, strings.Join(names, ", "))
}

// unify matches the argument type a against the parameter type p, binding
// type parameters in b. Dyn matches anything; a parameter bound twice to
// different types is bound to dyn when either is dyn, and fails otherwise.
func unify(p, a *Type, b map[string]*Type) bool {
	switch p.kind {
	case KindParam:
		cur, ok := b[p.param]
		if !ok {
			b[p.param] = a
			return true
		}
		if !assignable(cur, a) {
			return false
		}
		b[p.param] = join(cur, a)
		return true
	case KindList:
		if a.kind == KindDyn {
			return true
		}
		return a.kind == KindList && unify(p.elem, a.elem, b)
	case KindMap:
		if a.kind == KindDyn {
			return true
		}
		return a.kind == KindMap && unify(p.key, a.key, b) && unify(p.elem, a.elem, b)
	}
	return assignable(p, a)
}

// substitute replaces the type parameters of t by their bindings, and those
// left unbound by dyn.
func substitute(t *Type, b map[string]*Type) *Type {
	switch t.kind {
	case KindParam:
		if v, ok := b[t.param]; ok {
			return v
		}
		return Dyn
	case KindList:
		return ListOf(substitute(t.elem, b))
	case KindMap:
		return &Type{kind: KindMap, key: substitute(t.key, b), elem: substitute(t.elem, b)}
	}
	return t
}
