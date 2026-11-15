package cel

import (
	"math"
	"strconv"
)

// Limits bound the work of parsing and checking one expression, so an
// expression from a schema or a policy file cannot exhaust the process.
type Limits struct {
	// MaxSourceBytes is the longest accepted source text.
	MaxSourceBytes int
	// MaxDepth is the deepest accepted tree: a leaf has depth 1. Chains of
	// && and || are built balanced, so a thousand conditions joined by ||
	// are about ten deep.
	MaxDepth int
	// MaxNodes is the most nodes one expression may have.
	MaxNodes int
}

// DefaultLimits are the limits of Parse and of an Env made without
// WithLimits. They are far above any caveat or tool rule written by hand.
var DefaultLimits = Limits{MaxSourceBytes: 16 << 10, MaxDepth: 100, MaxNodes: 4096}

// Parse parses src under DefaultLimits. It returns an Errors holding the
// first problem it finds.
func Parse(src string) (*AST, error) { return parse(src, DefaultLimits) }

func parse(src string, lim Limits) (ast *AST, err error) {
	if len(src) > lim.MaxSourceBytes {
		return nil, locate(src, Errors{errorf(0, "expression is %d bytes, more than the limit of %d", len(src), lim.MaxSourceBytes)})
	}
	p := &parser{lex: lexer{src: src}, lim: lim}
	defer func() {
		if r := recover(); r != nil {
			pe, ok := r.(parseError)
			if !ok {
				panic(r)
			}
			ast, err = nil, locate(src, Errors{pe.err})
		}
	}()
	root := p.expr()
	if p.tok().kind != tokEOF {
		p.failf(p.tok().pos, "unexpected %s", p.describe(p.tok()))
	}
	return &AST{Source: src, Root: root, nodes: p.nodes}, nil
}

// parseError carries the first problem out of the recursive descent.
type parseError struct{ err *Error }

// parser is a recursive-descent parser over a streaming lexer, with up to
// two tokens of lookahead in buf.
type parser struct {
	lex    lexer
	lim    Limits
	buf    []token
	nodes  int
	nested int // recursion depth of expr, which bounds the Go stack
}

func (p *parser) failf(pos int, format string, args ...any) {
	panic(parseError{errorf(pos, format, args...)})
}

// fill lexes ahead until the buffer holds token n, or ends at EOF.
func (p *parser) fill(n int) {
	for len(p.buf) <= n {
		if k := len(p.buf); k > 0 && p.buf[k-1].kind == tokEOF {
			return
		}
		t, err := p.lex.next()
		if err != nil {
			panic(parseError{err})
		}
		p.buf = append(p.buf, t)
	}
}

func (p *parser) tok() token {
	p.fill(0)
	return p.buf[0]
}

// peek returns the token n after the current one, or EOF.
func (p *parser) peek(n int) token {
	p.fill(n)
	if n < len(p.buf) {
		return p.buf[n]
	}
	return p.buf[len(p.buf)-1]
}

func (p *parser) advance() token {
	t := p.tok()
	if t.kind != tokEOF {
		p.buf = p.buf[1:]
	}
	return t
}

func (p *parser) accept(k tokenKind) bool {
	if p.tok().kind == k {
		p.advance()
		return true
	}
	return false
}

func (p *parser) expect(k tokenKind, context string) token {
	t := p.tok()
	if t.kind != k {
		p.failf(t.pos, "expected %s %s, found %s", tokenText[k], context, p.describe(t))
	}
	return p.advance()
}

func (p *parser) describe(t token) string {
	if t.kind == tokIdent {
		return "'" + t.text + "'"
	}
	return tokenText[t.kind]
}

// node makes a node, numbering it and enforcing the node and depth limits.
func (p *parser) node(n *Node) *Node {
	if p.nodes >= p.lim.MaxNodes {
		p.failf(n.Pos, "expression has more than %d nodes", p.lim.MaxNodes)
	}
	n.ID = p.nodes
	p.nodes++
	d := 0
	if n.Target != nil {
		d = n.Target.depth
	}
	for _, a := range n.Args {
		d = max(d, a.depth)
	}
	n.depth = d + 1
	if n.depth > p.lim.MaxDepth {
		p.failf(n.Pos, "expression is nested more than %d deep", p.lim.MaxDepth)
	}
	return n
}

func (p *parser) call(pos int, fn string, args ...*Node) *Node {
	return p.node(&Node{Kind: NodeCall, Pos: pos, Name: fn, Args: args})
}

// expr = or ["?" or ":" expr]
func (p *parser) expr() *Node {
	p.nested++
	defer func() { p.nested-- }()
	if p.nested > p.lim.MaxDepth {
		p.failf(p.tok().pos, "expression is nested more than %d deep", p.lim.MaxDepth)
	}
	cond := p.logical(tokOr, OpOr)
	if t := p.tok(); t.kind == tokQuestion {
		p.advance()
		yes := p.logical(tokOr, OpOr)
		p.expect(tokColon, "in a conditional")
		no := p.expr()
		return p.call(t.pos, OpConditional, cond, yes, no)
	}
	return cond
}

// logical parses a chain joined by || (or by && one level down) and builds
// it as a balanced tree, which keeps long chains shallow. Both operators are
// commutative in CEL, so the shape does not change the result.
func (p *parser) logical(k tokenKind, fn string) *Node {
	next := func() *Node {
		if k == tokOr {
			return p.logical(tokAnd, OpAnd)
		}
		return p.relation()
	}
	operands := []*Node{next()}
	var positions []int
	for p.tok().kind == k {
		positions = append(positions, p.advance().pos)
		operands = append(operands, next())
	}
	return p.balance(fn, operands, positions)
}

func (p *parser) balance(fn string, operands []*Node, positions []int) *Node {
	if len(operands) == 1 {
		return operands[0]
	}
	mid := len(operands) / 2
	left := p.balance(fn, operands[:mid], positions[:mid-1])
	right := p.balance(fn, operands[mid:], positions[mid:])
	return p.call(positions[mid-1], fn, left, right)
}

var relations = map[tokenKind]string{
	tokLess: OpLess, tokLessEq: OpLessEq, tokGreater: OpGreater,
	tokGreaterEq: OpGreaterEq, tokEq: OpEq, tokNotEq: OpNe, tokIn: OpIn,
}

// relation = addition {relop addition}
func (p *parser) relation() *Node {
	left := p.addition()
	for {
		fn, ok := relations[p.tok().kind]
		if !ok {
			return left
		}
		pos := p.advance().pos
		left = p.call(pos, fn, left, p.addition())
	}
}

// addition = multiplication {("+" | "-") multiplication}
func (p *parser) addition() *Node {
	left := p.multiplication()
	for {
		var fn string
		switch p.tok().kind {
		case tokPlus:
			fn = OpAdd
		case tokMinus:
			fn = OpSub
		default:
			return left
		}
		pos := p.advance().pos
		left = p.call(pos, fn, left, p.multiplication())
	}
}

// multiplication = unary {("*" | "/" | "%") unary}
func (p *parser) multiplication() *Node {
	left := p.unary()
	for {
		var fn string
		switch p.tok().kind {
		case tokStar:
			fn = OpMul
		case tokSlash:
			fn = OpDiv
		case tokPercent:
			fn = OpMod
		default:
			return left
		}
		pos := p.advance().pos
		left = p.call(pos, fn, left, p.unary())
	}
}

// unary = member | "!" {"!"} member | "-" {"-"} member
//
// A minus directly before a number literal with nothing after it is folded
// into the literal, so -9223372036854775808 is the smallest int rather than
// an overflow, and -5 is the literal -5 rather than a call.
func (p *parser) unary() *Node {
	t := p.tok()
	switch t.kind {
	case tokNot, tokMinus:
		var positions []int
		for p.tok().kind == t.kind {
			positions = append(positions, p.advance().pos)
		}
		var operand *Node
		if n := p.tok(); t.kind == tokMinus && (n.kind == tokInt || n.kind == tokDouble) && !isSuffix(p.peek(1).kind) {
			p.advance()
			operand = p.number(n, true)
			positions = positions[:len(positions)-1]
		} else {
			operand = p.member()
		}
		fn := OpNot
		if t.kind == tokMinus {
			fn = OpNeg
		}
		for i := len(positions) - 1; i >= 0; i-- {
			operand = p.call(positions[i], fn, operand)
		}
		return operand
	}
	return p.member()
}

func isSuffix(k tokenKind) bool { return k == tokDot || k == tokLBracket }

// member = primary {"." IDENT ["(" [args] ")"] | "[" expr "]"}
func (p *parser) member() *Node {
	n := p.primary()
	for {
		switch t := p.tok(); t.kind {
		case tokDot:
			p.advance()
			id := p.expect(tokIdent, "after '.'")
			p.checkReserved(id)
			if p.tok().kind == tokLParen {
				p.advance()
				args := p.args(tokRParen, "to end the arguments")
				n = p.method(id, n, args)
			} else {
				n = p.node(&Node{Kind: NodeSelect, Pos: id.pos, Target: n, Name: id.text})
			}
		case tokLBracket:
			p.advance()
			index := p.expr()
			p.expect(tokRBracket, "to end the index")
			n = p.call(t.pos, OpIndex, n, index)
		default:
			return n
		}
	}
}

// method builds target.name(args), expanding the comprehension macros.
func (p *parser) method(id token, target *Node, args []*Node) *Node {
	if m, ok := macroNames[id.text]; ok && (len(args) == 2 || m == MacroMap && len(args) == 3) {
		v := args[0]
		if v.Kind != NodeIdent {
			p.failf(v.Pos, "the first argument of %s() must be a variable name", id.text)
		}
		return p.node(&Node{Kind: NodeComprehension, Pos: id.pos, Macro: m, Name: v.Name, Target: target, Args: args[1:]})
	}
	return p.node(&Node{Kind: NodeCall, Pos: id.pos, Name: id.text, Target: target, Args: args})
}

// args reads a comma-separated list up to the closing token, allowing a
// trailing comma when it is a list or map literal.
func (p *parser) args(end tokenKind, context string) []*Node {
	var out []*Node
	for p.tok().kind != end {
		out = append(out, p.expr())
		if !p.accept(tokComma) {
			break
		}
		if end == tokRParen && p.tok().kind == end {
			p.failf(p.tok().pos, "unexpected ')' after ','")
		}
	}
	p.expect(end, context)
	return out
}

func (p *parser) checkReserved(t token) {
	if reserved[t.text] {
		p.failf(t.pos, "'%s' is a reserved word", t.text)
	}
}

func (p *parser) primary() *Node {
	t := p.advance()
	switch t.kind {
	case tokIdent:
		p.checkReserved(t)
		if p.tok().kind != tokLParen {
			return p.node(&Node{Kind: NodeIdent, Pos: t.pos, Name: t.text})
		}
		p.advance()
		args := p.args(tokRParen, "to end the arguments")
		if t.text == "has" {
			if len(args) != 1 || args[0].Kind != NodeSelect {
				p.failf(t.pos, "has() takes one field selection, such as has(m.key)")
			}
			sel := args[0]
			return p.node(&Node{Kind: NodeSelect, Pos: t.pos, Target: sel.Target, Name: sel.Name, TestOnly: true})
		}
		return p.node(&Node{Kind: NodeCall, Pos: t.pos, Name: t.text, Args: args})
	case tokLParen:
		n := p.expr()
		p.expect(tokRParen, "to close '('")
		return n
	case tokLBracket:
		elems := p.args(tokRBracket, "to end the list")
		return p.node(&Node{Kind: NodeList, Pos: t.pos, Args: elems})
	case tokLBrace:
		var entries []*Node
		for p.tok().kind != tokRBrace {
			k := p.expr()
			p.expect(tokColon, "after a map key")
			v := p.expr()
			entries = append(entries, k, v)
			if !p.accept(tokComma) {
				break
			}
		}
		p.expect(tokRBrace, "to end the map")
		return p.node(&Node{Kind: NodeMap, Pos: t.pos, Args: entries})
	case tokInt, tokUint, tokDouble:
		return p.number(t, false)
	case tokString:
		return p.node(&Node{Kind: NodeLiteral, Pos: t.pos, Value: t.text})
	case tokBytes:
		p.failf(t.pos, "bytes literals are not supported")
	case tokTrue, tokFalse:
		return p.node(&Node{Kind: NodeLiteral, Pos: t.pos, Value: t.kind == tokTrue})
	case tokNull:
		return p.node(&Node{Kind: NodeLiteral, Pos: t.pos, Value: nil})
	case tokDot:
		p.failf(t.pos, "names starting with '.' are not supported")
	}
	p.failf(t.pos, "unexpected %s", p.describe(t))
	return nil
}

// number converts a number token, negated when a minus was folded into it.
func (p *parser) number(t token, negative bool) *Node {
	lit := &Node{Kind: NodeLiteral, Pos: t.pos}
	switch t.kind {
	case tokDouble:
		f, err := strconv.ParseFloat(t.text, 64)
		if err != nil || math.IsInf(f, 0) {
			p.failf(t.pos, "number %s is out of range", t.text)
		}
		if negative {
			f = -f
		}
		lit.Value = f
	case tokUint:
		u, err := parseDigits(t.text)
		if err != nil {
			p.failf(t.pos, "unsigned integer %su is out of range", t.text)
		}
		lit.Value = u
	default:
		u, err := parseDigits(t.text)
		switch {
		case err != nil, !negative && u > math.MaxInt64, negative && u > 1<<63:
			sign := ""
			if negative {
				sign = "-"
			}
			p.failf(t.pos, "integer %s%s is out of range", sign, t.text)
		}
		if negative {
			lit.Value = -int64(u) // wraps to MinInt64 for 1<<63, as wanted
		} else {
			lit.Value = int64(u)
		}
	}
	return p.node(lit)
}

// parseDigits reads the digits of an int or uint token: hexadecimal after
// 0x, decimal otherwise (a leading zero does not mean octal in CEL).
func parseDigits(s string) (uint64, error) {
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}
