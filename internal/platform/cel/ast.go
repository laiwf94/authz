package cel

import (
	"math"
	"strconv"
	"strings"
)

// NodeKind says which fields of a Node are in use.
type NodeKind uint8

const (
	// NodeLiteral is a constant: Value is nil (null), bool, int64, uint64,
	// float64 or string.
	NodeLiteral NodeKind = iota
	// NodeIdent is a variable: Name.
	NodeIdent
	// NodeSelect is Target.Name, a field of a map; with TestOnly it is
	// has(Target.Name).
	NodeSelect
	// NodeCall is the function Name applied to Args, with Target as the
	// receiver of a method call (x.f(y)) and nil for a global call (f(y)).
	// Operators are calls too, named by the Op constants.
	NodeCall
	// NodeList is a list literal of Args.
	NodeList
	// NodeMap is a map literal; Args holds key, value, key, value, ...
	NodeMap
	// NodeComprehension is a macro over the list or map Target, binding
	// each element (or key) to the variable Name. Args holds the predicate
	// of all, exists, exists_one and filter, the transform of a two-argument
	// map, and the filter then the transform of a three-argument map.
	NodeComprehension
)

// Macro names the comprehension of a NodeComprehension.
type Macro uint8

const (
	MacroAll Macro = iota + 1
	MacroExists
	MacroExistsOne
	MacroMap
	MacroFilter
)

var macroNames = map[string]Macro{
	"all":        MacroAll,
	"exists":     MacroExists,
	"exists_one": MacroExistsOne,
	"map":        MacroMap,
	"filter":     MacroFilter,
}

func (m Macro) String() string {
	for name, v := range macroNames {
		if v == m {
			return name
		}
	}
	return "macro(" + strconv.Itoa(int(m)) + ")"
}

// The function names of the operators, as CEL spells them.
const (
	OpAdd         = "_+_"
	OpSub         = "_-_"
	OpMul         = "_*_"
	OpDiv         = "_/_"
	OpMod         = "_%_"
	OpNeg         = "-_"
	OpNot         = "!_"
	OpAnd         = "_&&_"
	OpOr          = "_||_"
	OpConditional = "_?_:_"
	OpEq          = "_==_"
	OpNe          = "_!=_"
	OpLess        = "_<_"
	OpLessEq      = "_<=_"
	OpGreater     = "_>_"
	OpGreaterEq   = "_>=_"
	OpIn          = "@in"
	OpIndex       = "_[_]"
)

var binarySymbols = map[string]string{
	OpAdd: "+", OpSub: "-", OpMul: "*", OpDiv: "/", OpMod: "%",
	OpAnd: "&&", OpOr: "||", OpEq: "==", OpNe: "!=", OpLess: "<",
	OpLessEq: "<=", OpGreater: ">", OpGreaterEq: ">=", OpIn: "in",
}

// Node is one node of a parsed expression. The IDs of the nodes of one AST
// are distinct and below its Nodes(), in the order the parser made them, so
// a checker or an evaluator can keep per-node facts in slices.
type Node struct {
	ID       int
	Kind     NodeKind
	Pos      int // byte offset in the source
	Value    any
	Name     string
	Target   *Node
	Args     []*Node
	TestOnly bool
	Macro    Macro

	depth int // nodes on the longest path from here to a leaf
}

// AST is a parsed expression.
type AST struct {
	Source string
	Root   *Node
	nodes  int
}

// Nodes returns the bound on the node IDs of the AST: every ID is below
// it. Macro expansion drops a few nodes, so there may be fewer nodes.
func (a *AST) Nodes() int { return a.nodes }

// String renders the AST as source that parses back to the same tree, with
// every operator in parentheses.
func (a *AST) String() string { return a.Root.String() }

// String renders the expression rooted at n; see AST.String.
func (n *Node) String() string {
	var b strings.Builder
	n.write(&b)
	return b.String()
}

func (n *Node) write(b *strings.Builder) {
	switch n.Kind {
	case NodeLiteral:
		writeLiteral(b, n.Value)
	case NodeIdent:
		b.WriteString(n.Name)
	case NodeSelect:
		if n.TestOnly {
			b.WriteString("has(")
		}
		n.Target.writeOperand(b)
		b.WriteByte('.')
		b.WriteString(n.Name)
		if n.TestOnly {
			b.WriteByte(')')
		}
	case NodeCall:
		n.writeCall(b)
	case NodeList:
		b.WriteByte('[')
		writeList(b, n.Args)
		b.WriteByte(']')
	case NodeMap:
		b.WriteByte('{')
		for i := 0; i < len(n.Args); i += 2 {
			if i > 0 {
				b.WriteString(", ")
			}
			n.Args[i].write(b)
			b.WriteString(": ")
			n.Args[i+1].write(b)
		}
		b.WriteByte('}')
	case NodeComprehension:
		n.Target.writeOperand(b)
		b.WriteByte('.')
		b.WriteString(n.Macro.String())
		b.WriteByte('(')
		b.WriteString(n.Name)
		for _, a := range n.Args {
			b.WriteString(", ")
			a.write(b)
		}
		b.WriteByte(')')
	}
}

func (n *Node) writeCall(b *strings.Builder) {
	if sym, ok := binarySymbols[n.Name]; ok && n.Target == nil && len(n.Args) == 2 {
		b.WriteByte('(')
		n.Args[0].write(b)
		b.WriteByte(' ')
		b.WriteString(sym)
		b.WriteByte(' ')
		n.Args[1].write(b)
		b.WriteByte(')')
		return
	}
	switch {
	case n.Name == OpNeg && n.Target == nil && len(n.Args) == 1:
		b.WriteString("-(")
		n.Args[0].write(b)
		b.WriteByte(')')
		return
	case n.Name == OpNot && n.Target == nil && len(n.Args) == 1:
		b.WriteString("!(")
		n.Args[0].write(b)
		b.WriteByte(')')
		return
	case n.Name == OpConditional && n.Target == nil && len(n.Args) == 3:
		b.WriteByte('(')
		n.Args[0].write(b)
		b.WriteString(" ? ")
		n.Args[1].write(b)
		b.WriteString(" : ")
		n.Args[2].write(b)
		b.WriteByte(')')
		return
	case n.Name == OpIndex && n.Target == nil && len(n.Args) == 2:
		n.Args[0].writeOperand(b)
		b.WriteByte('[')
		n.Args[1].write(b)
		b.WriteByte(']')
		return
	}
	if n.Target != nil {
		n.Target.writeOperand(b)
		b.WriteByte('.')
	}
	b.WriteString(n.Name)
	b.WriteByte('(')
	writeList(b, n.Args)
	b.WriteByte(')')
}

// writeOperand writes the operand of a member access or an index. A
// negative number there is parenthesized: -1.a would parse as -(1.a).
func (n *Node) writeOperand(b *strings.Builder) {
	neg := false
	switch v := n.Value.(type) {
	case int64:
		neg = v < 0
	case float64:
		neg = math.Signbit(v)
	}
	if n.Kind == NodeLiteral && neg {
		b.WriteByte('(')
		n.write(b)
		b.WriteByte(')')
		return
	}
	n.write(b)
}

func writeList(b *strings.Builder, ns []*Node) {
	for i, a := range ns {
		if i > 0 {
			b.WriteString(", ")
		}
		a.write(b)
	}
}

func writeLiteral(b *strings.Builder, v any) {
	switch v := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case int64:
		b.WriteString(strconv.FormatInt(v, 10))
	case uint64:
		b.WriteString(strconv.FormatUint(v, 10))
		b.WriteByte('u')
	case float64:
		s := strconv.FormatFloat(v, 'g', -1, 64)
		if math.IsInf(v, 0) || math.IsNaN(v) {
			// Not reachable from source, which refuses out-of-range
			// literals; written as a call so the text still parses.
			s = "double(\"" + s + "\")"
		} else if !strings.ContainsAny(s, ".eE") {
			s += ".0"
		}
		b.WriteString(s)
	case string:
		b.WriteString(strconv.Quote(v))
	}
}
