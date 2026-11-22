package policy

import (
	"context"
	"slices"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/engine"
)

// Kinds of rule, as Candidate.Kind reports them.
const (
	KindPublic = "public" // anyone, signed in or not
	KindDeny   = "deny"   // nobody
	KindAllow  = "allow"  // the users the rule lists
	KindCheck  = "check"  // a relationship rule: the engine decides
)

// Candidate is one rule whose pattern matches a request's path, as
// Candidates lists them for an explanation.
type Candidate struct {
	// Rule names it as the configuration does ("paths[3]", "public[0]",
	// or "allow" for the app-wide rule) and Pattern is its normalized
	// pattern ("" for the app-wide rule).
	Rule    string `json:"rule"`
	Pattern string `json:"pattern,omitempty"`
	Exact   bool   `json:"exact,omitempty"`
	// Methods are the methods the rule lists, GET standing for GET and
	// HEAD; empty is every method.
	Methods []string `json:"methods,omitempty"`
	Kind    string   `json:"kind"`
	StepUp  bool     `json:"step_up,omitempty"`
	// MethodMatches says the rule covers the request's method: a rule
	// whose pattern matches but whose methods do not is passed over.
	MethodMatches bool `json:"method_matches"`
	// Selected marks the one rule that decides the request.
	Selected bool `json:"selected"`
	// Params are the values its {parameters} would take.
	Params map[string]string `json:"params,omitempty"`
}

// Candidates matches a request as Match does and also returns every rule
// whose pattern matches its path, in the order the rules are tried: the
// most specific first, by the four order rules of App. The first with
// MethodMatches is the one Match selected; the app-wide rule comes last
// and is selected when no path rule is. A bad path matches no rule, and
// the list is then empty. It allocates, and is meant for explanations,
// not for deciding requests.
func (p *Policy) Candidates(method, rawPath string) (Match, []Candidate) {
	m := p.Match(method, rawPath)
	if m.Bad {
		return m, nil
	}
	var found []hit
	if p.root != nil {
		c := collector{p: p}
		c.walk(p.root, m.Path, 0, 0)
		found = c.found
		// Stable: at equal score the rule reached first, a literal
		// before a {parameter}, is tried first, as Match does.
		slices.SortStableFunc(found, func(a, b hit) int { return b.score - a.score })
	}
	bit := methodBit(method)
	out := make([]Candidate, 0, len(found)+1)
	for _, f := range found {
		r := &p.rules[f.rule]
		c := Candidate{Rule: r.name, Pattern: r.pattern, Exact: r.exact, Methods: methodNames(r.methods),
			Kind: r.kind(), StepUp: r.stepUp != nil, MethodMatches: r.methods == methodAny || r.methods&bit != 0,
			Selected: f.rule == m.Rule}
		if len(r.params) > 0 {
			c.Params = make(map[string]string, len(r.params))
			for i, n := range r.params {
				c.Params[n] = f.params[i]
			}
		}
		out = append(out, c)
	}
	out = append(out, Candidate{Rule: "allow", Kind: KindAllow, MethodMatches: true, Selected: m.Rule < 0})
	return m, out
}

func (r *rule) kind() string {
	switch {
	case r.public:
		return KindPublic
	case r.deny:
		return KindDeny
	case r.check != nil:
		return KindCheck
	}
	return KindAllow
}

// methodNames lists a rule's methods; GET implies HEAD, which a rule
// cannot list beside it, so HEAD is shown only when listed alone.
func methodNames(bits uint16) []string {
	if bits == methodAny {
		return nil
	}
	var out []string
	for _, n := range methodBits {
		b := methodBit(n)
		if bits&b == 0 || (n == "HEAD" && bits&methodBit("GET") != 0) {
			continue
		}
		out = append(out, n)
	}
	return out
}

type hit struct {
	rule   int
	score  int
	params [MaxParams]string
}

// collector walks the trie as walker does, keeping every rule on the way
// instead of the best.
type collector struct {
	p      *Policy
	params [MaxParams]string
	found  []hit
}

func (c *collector) walk(n *node, rest string, depth, np int) {
	end := rest == "" || rest == "/"
	if end {
		c.add(n.exact, 2*depth+1)
	}
	c.add(n.prefix, 2*depth)
	if end {
		return
	}
	rest = rest[1:]
	seg, after := rest, ""
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			seg, after = rest[:i], rest[i:]
			break
		}
	}
	if l := n.lit[seg]; l != nil {
		c.walk(l, after, depth+1, np)
	}
	if n.param != nil && seg != "" && np < MaxParams {
		c.params[np] = seg
		c.walk(n.param, after, depth+1, np+1)
	}
}

func (c *collector) add(list []int, score int) {
	for _, i := range list {
		c.found = append(c.found, hit{rule: i, score: score, params: c.params})
	}
}

var _ Explainer = (*engine.Local)(nil)

// Explainer is a Checker that can also explain a check: the answer with a
// trace of how the engine reached it, of at most maxNodes nodes.
// *engine.Local is one.
type Explainer interface {
	Checker
	Explain(ctx context.Context, req engine.CheckRequest, maxNodes int) (engine.CheckResult, *check.Trace, error)
}

// AuthorizeExplain is Authorize for an explanation: when eng is an
// Explainer, the relationship check is explained and its trace, of at
// most maxNodes nodes (check.DefaultTraceNodes when maxNodes <= 0), is in
// the Decision's CheckTrace. Otherwise the check is made as Authorize
// makes it and the trace is nil. The answer is the one Authorize gives.
func (p *Policy) AuthorizeExplain(ctx context.Context, m *Match, id *Identity, eng Checker, tok string, maxNodes int) Decision {
	return p.authorize(ctx, m, id, eng, tok, true, maxNodes)
}
