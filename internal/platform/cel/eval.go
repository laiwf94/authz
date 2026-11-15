package cel

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// DefaultMaxCost is the cost limit of a Program made with a limit of 0. A
// caveat of the size schemas write costs a few dozen units; a membership
// test against a list costs one unit per element, and a comprehension the
// cost of its body for each element.
const DefaultMaxCost = 100_000

// ErrCostLimit is the error, wrapped, of an evaluation that went over its
// Program's cost limit. Unlike other runtime errors it is never absorbed by
// && or ||: the evaluation stops.
var ErrCostLimit = errors.New("cel: evaluation cost limit exceeded")

// Program is a checked expression ready to evaluate. It is safe for
// concurrent use; each Eval keeps its state to itself.
type Program struct {
	c       *Checked
	maxCost uint64
	missing []*unknown // per variable of Checked.Vars, the unknown that stands for it
	refs    []int      // per ident node: index into vars, or -(slot+1)
	slots   []int      // per comprehension node: its local slot
	lits    []any      // per literal node: its value, parsed if Constant
	nslots  int
}

// Program prepares c for evaluation with the given cost limit, in units
// of one per node evaluated plus the size of the strings, lists and maps an
// operation goes through; 0 means DefaultMaxCost.
func (c *Checked) Program(maxCost uint64) *Program {
	if maxCost == 0 {
		maxCost = DefaultMaxCost
	}
	n := c.ast.nodes
	p := &Program{c: c, maxCost: maxCost, refs: make([]int, n), slots: make([]int, n), lits: make([]any, n)}
	index := map[string]int{}
	for i, name := range c.vars {
		index[name] = i
		p.missing = append(p.missing, &unknown{names: []string{name}})
	}
	var scopes []string
	var walk func(*Node)
	walk = func(n *Node) {
		switch n.Kind {
		case NodeLiteral:
			p.lits[n.ID] = n.Value
			if v, ok := c.consts[n.ID]; ok {
				if t, isTime := v.(time.Time); isTime {
					v = t.UTC()
				}
				p.lits[n.ID] = v
			}
		case NodeIdent:
			for i := len(scopes) - 1; i >= 0; i-- {
				if scopes[i] == n.Name {
					p.refs[n.ID] = -(i + 1)
					return
				}
			}
			p.refs[n.ID] = index[n.Name]
		case NodeComprehension:
			walk(n.Target)
			p.slots[n.ID] = len(scopes)
			scopes = append(scopes, n.Name)
			p.nslots = max(p.nslots, len(scopes))
			for _, a := range n.Args {
				walk(a)
			}
			scopes = scopes[:len(scopes)-1]
			return
		}
		if n.Target != nil {
			walk(n.Target)
		}
		for _, a := range n.Args {
			walk(a)
		}
	}
	walk(c.ast.Root)
	return p
}

// Checked returns the expression the Program evaluates.
func (p *Program) Checked() *Checked { return p.c }

// Result is the outcome of an evaluation. When Missing is empty the
// expression has the value Value. Otherwise its value depends on the
// variables Missing names, which were absent: supplying them may give any
// value. An expression is unknown only when no value of the absent
// variables could be left out of account: false && x is false and
// true || x is true whatever x is.
type Result struct {
	Value   any
	Missing []string // sorted
	Cost    uint64
}

// Known reports whether the result has a value.
func (r Result) Known() bool { return len(r.Missing) == 0 }

// Eval evaluates the expression with the variables in vars. A declared
// variable that vars lacks is unknown: the result is unknown if it depends
// on it. A variable's value must have its declared type; Eval converts Go's
// other integer and float types, json.Number, and the strings and whole
// numbers encoding/json gives (see the package doc). Lists come back as
// []any and maps as map[any]any.
//
// A runtime error, such as a division by zero, an overflow, a missing map
// key or an index out of range, is returned as Errors with its position,
// unless && or || made it irrelevant (false && 1/0 == 1 is false). Going
// over the cost limit returns an error wrapping ErrCostLimit.
func (p *Program) Eval(vars map[string]any) (r Result, err error) {
	e := &evaluator{p: p, limit: p.maxCost}
	e.vals = make([]any, len(p.c.vars))
	for i, v := range p.c.vars {
		x, ok := vars[v]
		if !ok {
			e.vals[i] = p.missing[i]
			continue
		}
		t := p.c.env.vars[v]
		cv, err := convertInput(t, x, 0)
		if err != nil {
			return Result{}, fmt.Errorf("cel: variable %s %v", v, err)
		}
		e.vals[i] = cv
	}
	if p.nslots > 0 {
		e.locals = make([]any, p.nslots)
	}
	defer func() {
		if x := recover(); x != nil {
			if _, ok := x.(costExceeded); !ok {
				panic(x)
			}
			r, err = Result{Cost: e.cost}, fmt.Errorf("%w: more than %d units", ErrCostLimit, p.maxCost)
		}
	}()
	v := e.eval(p.c.ast.Root)
	switch v := v.(type) {
	case *unknown:
		return Result{Missing: slices.Clone(v.names), Cost: e.cost}, nil
	case *evalErr:
		return Result{Cost: e.cost}, locate(p.c.ast.Source, Errors{errorf(v.pos, "%s", v.msg)})
	}
	return Result{Value: exportValue(v), Cost: e.cost}, nil
}

// unknown is the value of an expression that depends on absent variables.
type unknown struct{ names []string }

// merge returns the union of two sets of missing names.
func (u *unknown) merge(o *unknown) *unknown {
	if u == nil {
		return o
	}
	if o == nil || slices.Equal(u.names, o.names) {
		return u
	}
	names := make([]string, 0, len(u.names)+len(o.names))
	i, j := 0, 0
	for i < len(u.names) || j < len(o.names) {
		switch {
		case j == len(o.names) || i < len(u.names) && u.names[i] < o.names[j]:
			names = append(names, u.names[i])
			i++
		case i == len(u.names) || o.names[j] < u.names[i]:
			names = append(names, o.names[j])
			j++
		default:
			names = append(names, u.names[i])
			i++
			j++
		}
	}
	return &unknown{names: names}
}

// evalErr is a runtime error; pos is -1 until the call that raised it
// places it.
type evalErr struct {
	pos int
	msg string
}

func fail(format string, args ...any) *evalErr {
	return &evalErr{pos: -1, msg: fmt.Sprintf(format, args...)}
}

type costExceeded struct{}

type evaluator struct {
	p           *Program
	vals        []any
	locals      []any
	cost, limit uint64
}

func (e *evaluator) charge(n uint64) {
	e.cost += n
	if e.cost > e.limit {
		panic(costExceeded{})
	}
}

// chargeBytes charges for going through n bytes of strings.
func (e *evaluator) chargeBytes(n int) { e.charge(uint64(n) / 16) }

func (e *evaluator) eval(n *Node) any {
	e.charge(1)
	switch n.Kind {
	case NodeLiteral:
		return e.p.lits[n.ID]
	case NodeIdent:
		if r := e.p.refs[n.ID]; r < 0 {
			return e.locals[-r-1]
		} else {
			return e.vals[r]
		}
	case NodeSelect:
		t := e.eval(n.Target)
		if isPending(t) {
			return t
		}
		m, ok := t.(*mapValue)
		if !ok {
			return place(fail("no field '%s' on a %s", n.Name, typeName(t)), n)
		}
		v, found := m.get(n.Name)
		if n.TestOnly {
			return found
		}
		if !found {
			return place(fail("no such key: '%s'", n.Name), n)
		}
		return v
	case NodeList:
		out := make([]any, len(n.Args))
		var pend any
		for i, a := range n.Args {
			out[i] = e.eval(a)
			pend = pending(pend, out[i])
		}
		if pend != nil {
			return pend
		}
		return out
	case NodeMap:
		return e.mapLiteral(n)
	case NodeComprehension:
		return e.comprehension(n)
	}
	return e.call(n)
}

// isPending reports whether v is an unknown or an error, which a strict
// operation passes on instead of operating on.
func isPending(v any) bool {
	switch v.(type) {
	case *unknown, *evalErr:
		return true
	}
	return false
}

// pending folds the operand v into acc, the outcome so far of a strict
// operation's operands: unknowns merge and win over errors, so that
// supplying the missing variables is always the way forward, and the first
// error is kept.
func pending(acc, v any) any {
	switch v := v.(type) {
	case *unknown:
		if u, ok := acc.(*unknown); ok {
			return u.merge(v)
		}
		return v
	case *evalErr:
		if acc == nil {
			return v
		}
	}
	return acc
}

func place(err *evalErr, n *Node) *evalErr {
	if err.pos < 0 {
		err.pos = n.Pos
	}
	return err
}

func (e *evaluator) mapLiteral(n *Node) any {
	m := newMap(len(n.Args) / 2)
	var pend any
	for i := 0; i < len(n.Args); i += 2 {
		k, v := e.eval(n.Args[i]), e.eval(n.Args[i+1])
		pend = pending(pending(pend, k), v)
		if pend != nil {
			continue
		}
		if !isKey(k) {
			pend = place(fail("a map key cannot be a %s", typeName(k)), n.Args[i])
			continue
		}
		if !m.put(k, v) {
			pend = place(fail("map key %v appears twice", k), n.Args[i])
		}
	}
	if pend != nil {
		return pend
	}
	return m
}

// logical evaluates && (isAnd) or ||. Either operand decides the result
// when it is false (for &&) or true (for ||), even if the other is unknown
// or an error, so the operands can be read in either order.
func (e *evaluator) logical(n *Node, isAnd bool) any {
	decisive := !isAnd
	l := e.eval(n.Args[0])
	if b, ok := l.(bool); ok && b == decisive {
		return b
	}
	r := e.eval(n.Args[1])
	if b, ok := r.(bool); ok && b == decisive {
		return b
	}
	_, lb := l.(bool)
	_, rb := r.(bool)
	if lb && rb {
		return !decisive
	}
	var pend any
	for _, v := range []any{l, r} {
		if _, ok := v.(bool); !ok && !isPending(v) {
			v = place(fail("no matching overload for '%s' applied to a %s", binarySymbols[n.Name], typeName(v)), n)
		}
		pend = pending(pend, v)
	}
	return pend
}

func (e *evaluator) conditional(n *Node) any {
	c := e.eval(n.Args[0])
	if isPending(c) {
		return c
	}
	b, ok := c.(bool)
	if !ok {
		return place(fail("the condition of '?:' is a %s, not a bool", typeName(c)), n)
	}
	if b {
		return e.eval(n.Args[1])
	}
	return e.eval(n.Args[2])
}

func (e *evaluator) comprehension(n *Node) any {
	r := e.eval(n.Target)
	if isPending(r) {
		return r
	}
	var items []any
	switch r := r.(type) {
	case []any:
		items = r
	case *mapValue:
		items = r.keys
	default:
		return place(fail("%s() needs a list or a map, not a %s", n.Macro, typeName(r)), n)
	}
	slot := e.p.slots[n.ID]
	predicate := func(a *Node) (bool, any) {
		v := e.eval(a)
		if isPending(v) {
			return false, v
		}
		b, ok := v.(bool)
		if !ok {
			return false, place(fail("the predicate of %s() is a %s, not a bool", n.Macro, typeName(v)), a)
		}
		return b, nil
	}
	switch n.Macro {
	case MacroAll, MacroExists:
		// all is a chain of &&, exists of ||: a decisive element wins over
		// unknown and failing ones.
		decisive := n.Macro == MacroExists
		var pend any
		for _, x := range items {
			e.locals[slot] = x
			b, p := predicate(n.Args[0])
			if p == nil && b == decisive {
				return decisive
			}
			pend = pending(pend, p)
		}
		if pend != nil {
			return pend
		}
		return !decisive
	case MacroExistsOne:
		count := 0
		var pend any
		for _, x := range items {
			e.locals[slot] = x
			b, p := predicate(n.Args[0])
			pend = pending(pend, p)
			if b {
				count++
			}
		}
		if pend != nil {
			return pend
		}
		return count == 1
	case MacroFilter:
		var out []any
		var pend any
		for _, x := range items {
			e.locals[slot] = x
			b, p := predicate(n.Args[0])
			pend = pending(pend, p)
			if b && pend == nil {
				out = append(out, x)
			}
		}
		if pend != nil {
			return pend
		}
		if out == nil {
			out = []any{}
		}
		return out
	}
	// MacroMap, with a filter first when it has two arguments.
	out := make([]any, 0, len(items))
	var pend any
	transform := n.Args[len(n.Args)-1]
	for _, x := range items {
		e.locals[slot] = x
		if len(n.Args) == 2 {
			b, p := predicate(n.Args[0])
			if p != nil {
				pend = pending(pend, p)
				continue
			}
			if !b {
				continue
			}
		}
		v := e.eval(transform)
		pend = pending(pend, v)
		out = append(out, v)
	}
	if pend != nil {
		return pend
	}
	return out
}

func (e *evaluator) call(n *Node) any {
	switch n.Name {
	case OpAnd:
		return e.logical(n, true)
	case OpOr:
		return e.logical(n, false)
	case OpConditional:
		return e.conditional(n)
	}
	var buf [2]any
	args := buf[:0]
	if n.Target != nil {
		args = append(args, e.eval(n.Target))
	}
	for _, a := range n.Args {
		args = append(args, e.eval(a))
	}
	var pend any
	for _, a := range args {
		pend = pending(pend, a)
	}
	if pend != nil {
		return pend
	}
	v := e.apply(n, args)
	if err, ok := v.(*evalErr); ok {
		return place(err, n)
	}
	return v
}

// noOverload is the error of a call whose operands, of dyn type when it
// was checked, have types no overload takes.
func noOverload(n *Node, args []any) *evalErr {
	names := make([]string, len(args))
	for i, a := range args {
		names[i] = typeName(a)
	}
	return fail("no matching overload for %s applied to (%s)", displayName(n), strings.Join(names, ", "))
}

func displayName(n *Node) string {
	if sym, ok := binarySymbols[n.Name]; ok {
		return "'" + sym + "'"
	}
	switch n.Name {
	case OpNeg:
		return "'-'"
	case OpNot:
		return "'!'"
	case OpIndex:
		return "'[]'"
	}
	return "'" + n.Name + "'"
}

const (
	errOverflow = "integer overflow"
	errRange    = "timestamp out of range"
)

func (e *evaluator) apply(n *Node, args []any) any {
	switch len(args) {
	case 1:
		if v, ok := e.unary(n.Name, args[0]); ok {
			return v
		}
	case 2:
		if v, ok := e.binary(n.Name, args[0], args[1]); ok {
			return v
		}
	}
	return noOverload(n, args)
}

func (e *evaluator) binary(name string, a, b any) (any, bool) {
	switch name {
	case OpAdd:
		return e.add(a, b)
	case OpSub:
		return sub(a, b)
	case OpMul:
		return mul(a, b)
	case OpDiv:
		return div(a, b)
	case OpMod:
		return mod(a, b)
	case OpEq:
		return e.equal(a, b), true
	case OpNe:
		return !e.equal(a, b), true
	case OpLess, OpLessEq, OpGreater, OpGreaterEq:
		c, comparable, ok := e.compare(a, b)
		if !ok {
			return nil, false
		}
		if !comparable {
			return false, true // NaN
		}
		switch name {
		case OpLess:
			return c < 0, true
		case OpLessEq:
			return c <= 0, true
		case OpGreater:
			return c > 0, true
		}
		return c >= 0, true
	case OpIn:
		switch c := b.(type) {
		case []any:
			for _, x := range c {
				e.charge(1)
				if e.equal(a, x) {
					return true, true
				}
			}
			return false, true
		case *mapValue:
			_, found := c.get(a)
			return found, true
		}
	case OpIndex:
		return index(a, b)
	case "contains", "startsWith", "endsWith":
		s, ok1 := a.(string)
		t, ok2 := b.(string)
		if !ok1 || !ok2 {
			return nil, false
		}
		e.chargeBytes(len(s))
		switch name {
		case "contains":
			return strings.Contains(s, t), true
		case "startsWith":
			return strings.HasPrefix(s, t), true
		}
		return strings.HasSuffix(s, t), true
	case "matches":
		return e.matches(a, b)
	case "in_cidr", "containsIP", "containsCIDR":
		return ipBinary(name, a, b)
	}
	if strings.HasPrefix(name, "get") && b != nil {
		return timePart(name, a, b)
	}
	return nil, false
}

func (e *evaluator) add(a, b any) (any, bool) {
	switch a := a.(type) {
	case int64:
		if b, ok := b.(int64); ok {
			r := a + b
			if (r > a) != (b > 0) {
				return fail(errOverflow), true
			}
			return r, true
		}
	case uint64:
		if b, ok := b.(uint64); ok {
			r := a + b
			if r < a {
				return fail(errOverflow), true
			}
			return r, true
		}
	case float64:
		if b, ok := b.(float64); ok {
			return a + b, true
		}
	case string:
		if b, ok := b.(string); ok {
			e.chargeBytes(len(a) + len(b))
			return a + b, true
		}
	case []any:
		if b, ok := b.([]any); ok {
			e.charge(uint64(len(a) + len(b)))
			out := make([]any, 0, len(a)+len(b))
			return append(append(out, a...), b...), true
		}
	case time.Time:
		if b, ok := b.(time.Duration); ok {
			return addTime(a, b), true
		}
	case time.Duration:
		switch b := b.(type) {
		case time.Duration:
			r := a + b
			if (r > a) != (b > 0) {
				return fail("duration overflow"), true
			}
			return r, true
		case time.Time:
			return addTime(b, a), true
		}
	}
	return nil, false
}

func addTime(t time.Time, d time.Duration) any {
	r := t.Add(d)
	if r.Before(minTimestamp) || r.After(maxTimestamp) {
		return fail(errRange)
	}
	return r
}

func sub(a, b any) (any, bool) {
	switch a := a.(type) {
	case int64:
		if b, ok := b.(int64); ok {
			r := a - b
			if (r < a) != (b > 0) {
				return fail(errOverflow), true
			}
			return r, true
		}
	case uint64:
		if b, ok := b.(uint64); ok {
			if b > a {
				return fail(errOverflow), true
			}
			return a - b, true
		}
	case float64:
		if b, ok := b.(float64); ok {
			return a - b, true
		}
	case time.Time:
		switch b := b.(type) {
		case time.Time:
			d := a.Sub(b)
			if (d == math.MaxInt64 || d == math.MinInt64) && !b.Add(d).Equal(a) {
				return fail("duration overflow"), true
			}
			return d, true
		case time.Duration:
			if b == math.MinInt64 {
				return fail("duration overflow"), true
			}
			return addTime(a, -b), true
		}
	case time.Duration:
		if b, ok := b.(time.Duration); ok {
			r := a - b
			if (r < a) != (b > 0) {
				return fail("duration overflow"), true
			}
			return r, true
		}
	}
	return nil, false
}

func mul(a, b any) (any, bool) {
	switch a := a.(type) {
	case int64:
		if b, ok := b.(int64); ok {
			r := a * b
			if a != 0 && (r/a != b || a == -1 && b == math.MinInt64) {
				return fail(errOverflow), true
			}
			return r, true
		}
	case uint64:
		if b, ok := b.(uint64); ok {
			r := a * b
			if a != 0 && r/a != b {
				return fail(errOverflow), true
			}
			return r, true
		}
	case float64:
		if b, ok := b.(float64); ok {
			return a * b, true
		}
	}
	return nil, false
}

func div(a, b any) (any, bool) {
	switch a := a.(type) {
	case int64:
		if b, ok := b.(int64); ok {
			switch {
			case b == 0:
				return fail("division by zero"), true
			case a == math.MinInt64 && b == -1:
				return fail(errOverflow), true
			}
			return a / b, true
		}
	case uint64:
		if b, ok := b.(uint64); ok {
			if b == 0 {
				return fail("division by zero"), true
			}
			return a / b, true
		}
	case float64:
		if b, ok := b.(float64); ok {
			return a / b, true
		}
	}
	return nil, false
}

func mod(a, b any) (any, bool) {
	switch a := a.(type) {
	case int64:
		if b, ok := b.(int64); ok {
			switch {
			case b == 0:
				return fail("modulus by zero"), true
			case a == math.MinInt64 && b == -1:
				return fail(errOverflow), true
			}
			return a % b, true
		}
	case uint64:
		if b, ok := b.(uint64); ok {
			if b == 0 {
				return fail("modulus by zero"), true
			}
			return a % b, true
		}
	}
	return nil, false
}

// compare orders a and b: c is their order, comparable is false when a
// NaN makes them unordered, and ok is false when no overload orders them.
func (e *evaluator) compare(a, b any) (c int, comparable, ok bool) {
	switch a := a.(type) {
	case int64, uint64, float64:
		switch b.(type) {
		case int64, uint64, float64:
			c, comparable := compareNumbers(a, b)
			return c, comparable, true
		}
	case bool:
		if b, ok := b.(bool); ok {
			return cmp3(!a && b, a && !b), true, true
		}
	case string:
		if b, ok := b.(string); ok {
			e.chargeBytes(min(len(a), len(b)))
			return strings.Compare(a, b), true, true
		}
	case time.Time:
		if b, ok := b.(time.Time); ok {
			return a.Compare(b), true, true
		}
	case time.Duration:
		if b, ok := b.(time.Duration); ok {
			return cmp3(a < b, a > b), true, true
		}
	}
	return 0, false, false
}

func index(a, b any) (any, bool) {
	switch c := a.(type) {
	case []any:
		var i int64
		switch b := b.(type) {
		case int64:
			i = b
		case uint64:
			if b > math.MaxInt64 {
				return fail("index %d out of range for a list of %d", b, len(c)), true
			}
			i = int64(b)
		default:
			return nil, false
		}
		if i < 0 || i >= int64(len(c)) {
			return fail("index %d out of range for a list of %d", i, len(c)), true
		}
		return c[i], true
	case *mapValue:
		switch b.(type) {
		case bool, int64, uint64, float64, string:
		default:
			return nil, false
		}
		v, found := c.get(b)
		if !found {
			if s, ok := b.(string); ok {
				return fail("no such key: '%s'", s), true
			}
			return fail("no such key: %v", b), true
		}
		return v, true
	}
	return nil, false
}
