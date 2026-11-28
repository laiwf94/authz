// Package policy decides which agent may call which tool, with which
// arguments.
//
// A policy is an ordered list of rules. Evaluation is default deny, and an
// explicit deny beats any allow:
//
//  1. If any deny rule matches the call (subject, upstream, tool and, when the
//     rule has one, its argument schema), the call is denied by the first such
//     rule.
//  2. Otherwise the first allow rule whose subject, upstream and tool match
//     and whose argument schema accepts the arguments allows the call.
//  3. Otherwise the call is denied by "default-deny". If an allow rule matched
//     everything but the arguments (or its relationship check), its id and
//     the reason are reported, so the agent learns what to fix.
//
// A rule may also ask the authorization engine whether the user behind the
// agent holds a permission on a resource named by the arguments (check.go):
// in an allow rule that is one more condition, in a deny rule the condition
// under which it forbids the call.
//
// Every decision names the rule that produced it, for the audit log.
package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/agents/guard"
	"github.com/laiwf94/authz/internal/agents/jsonrpc"
	"github.com/laiwf94/authz/internal/agents/schema"
	"github.com/laiwf94/authz/internal/platform/cel"
)

// Limits on a policy document.
const (
	MaxBytes         = 1 << 20
	MaxRules         = 1000
	MaxSelectorItems = 256
)

// DefaultDenyID is the rule id reported when no rule allows a call.
const DefaultDenyID = "default-deny"

// Wildcard matches any agent, upstream or tool in a selector.
const Wildcard = "*"

var (
	ruleIDRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	agentIDRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$`)
	scopeRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}$`)
	upstreamRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	toolRe     = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

// ValidAgentID reports whether id is usable as an agent id.
func ValidAgentID(id string) bool { return agentIDRe.MatchString(id) }

// ValidScope reports whether s is usable as a scope.
func ValidScope(s string) bool { return scopeRe.MatchString(s) }

// ValidUpstream reports whether name is usable as an upstream name.
func ValidUpstream(name string) bool { return upstreamRe.MatchString(name) }

// ValidTool reports whether name is usable as a tool name.
func ValidTool(name string) bool { return toolRe.MatchString(name) }

// Effect is allow or deny.
type Effect string

// Effects.
const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

type fileRule struct {
	ID               string          `json:"id"`
	Description      string          `json:"description"`
	Effect           Effect          `json:"effect"`
	Agents           []string        `json:"agents"`
	Scopes           []string        `json:"scopes"`
	Upstreams        []string        `json:"upstreams"`
	Tools            []string        `json:"tools"`
	Arguments        json.RawMessage `json:"arguments"`
	RequiresApproval bool            `json:"requires_approval"`
	Output           *fileOutput     `json:"output"`
	Check            *fileCheck      `json:"check"`
	Windows          []fileWindow    `json:"windows"`
	When             *string         `json:"when"`
	Limits           *fileLimits     `json:"limits"`
}

type fileOutput struct {
	Redact         []string `json:"redact"`
	RedactPatterns []string `json:"redact_patterns"`
	Deny           []string `json:"deny"`
	DenyPatterns   []string `json:"deny_patterns"`
	MaxBytes       int      `json:"max_bytes"`
}

type file struct {
	Version int        `json:"version"`
	Rules   []fileRule `json:"rules"`
}

// Rule is a compiled rule.
type Rule struct {
	ID               string
	Effect           Effect
	agents           map[string]bool
	anyAgent         bool
	scopes           map[string]bool
	upstreams        map[string]bool
	anyUpstream      bool
	tools            []toolPattern
	args             *schema.Schema
	RequiresApproval bool
	Output           *guard.Guard
	check            *compiledCheck
	windows          []window
	when             *cel.Program
	limits           *Limits
}

// conditional reports whether the rule has windows or a when expression.
func (r *Rule) conditional() bool { return len(r.windows) > 0 || r.when != nil }

// Limits returns the rule's limits on the calls it allows, or nil.
func (r *Rule) Limits() *Limits { return r.limits }

// HasCheck reports whether the rule asks the authorization engine.
func (r *Rule) HasCheck() bool { return r.check != nil }

type toolPattern struct {
	name   string
	prefix bool // name is a prefix: "read_*" was written
}

// Policy is a compiled, immutable policy.
type Policy struct {
	Hash  string // hex SHA-256 of the source document
	Rules []*Rule
	// byUpstream holds, for each upstream named by some rule, the indexes of
	// the rules that can apply to it (naming it or "*"), in file order.
	byUpstream map[string][]int
	wildcard   []int // rules that apply to every upstream
	checks     bool  // some rule has a relationship check
}

// Subject is who is calling.
type Subject struct {
	AgentID string
	Owner   string // the user behind the agent, {owner} in checks
	Scopes  []string
	Session Session // facts for when expressions
}

// Decision is the outcome of an evaluation.
type Decision struct {
	Allowed          bool
	RuleID           string
	Reason           string
	RequiresApproval bool
	Output           *guard.Guard
	// ConstraintRuleID is set on a default deny when an allow rule matched
	// everything except its argument schema or its relationship check.
	ConstraintRuleID string
	// Unavailable is set on a denial that is an outage: a relationship
	// check the decision depends on could not be answered.
	Unavailable bool
	// Checks are the relationship checks the call reached, in the order
	// asked.
	Checks []CheckTrace
	// Limits are the allowing rule's limits, which the caller enforces;
	// nil when it has none.
	Limits *Limits
	// constraint is what ConstraintRuleID's rule failed.
	constraint constraintKind
}

type constraintKind uint8

const (
	byArguments constraintKind = iota
	byCheck
	byCondition
)

// Parse validates and compiles a policy document.
func Parse(src []byte) (*Policy, error) {
	if len(src) > MaxBytes {
		return nil, fmt.Errorf("policy is larger than %d bytes", MaxBytes)
	}
	if err := jsonrpc.CheckStructure(src); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	var f file
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if f.Version != 1 {
		return nil, errors.New("policy: version must be 1")
	}
	if len(f.Rules) > MaxRules {
		return nil, fmt.Errorf("policy: at most %d rules", MaxRules)
	}
	sum := sha256.Sum256(src)
	p := &Policy{Hash: hex.EncodeToString(sum[:]), byUpstream: map[string][]int{}}
	seen := map[string]bool{}
	for i, fr := range f.Rules {
		r, err := compileRule(fr)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %d (%q): %w", i, fr.ID, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("policy: rule id %q is used twice", r.ID)
		}
		seen[r.ID] = true
		p.checks = p.checks || r.check != nil
		p.Rules = append(p.Rules, r)
	}
	for i, r := range p.Rules {
		if r.anyUpstream {
			p.wildcard = append(p.wildcard, i)
		}
		for u := range r.upstreams {
			p.byUpstream[u] = append(p.byUpstream[u], i)
		}
	}
	for u, idx := range p.byUpstream {
		p.byUpstream[u] = mergeSorted(idx, p.wildcard)
	}
	return p, nil
}

func mergeSorted(a, b []int) []int {
	out := make([]int, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		if j == len(b) || i < len(a) && a[i] < b[j] {
			out = append(out, a[i])
			i++
		} else {
			out = append(out, b[j])
			j++
		}
	}
	return out
}

func compileRule(fr fileRule) (*Rule, error) {
	if !ruleIDRe.MatchString(fr.ID) || fr.ID == DefaultDenyID {
		return nil, errors.New(`id must be 1 to 64 letters, digits, "_", "." or "-", and not "default-deny"`)
	}
	if len(fr.Description) > 1024 {
		return nil, errors.New("description is longer than 1024 bytes")
	}
	r := &Rule{ID: fr.ID, Effect: fr.Effect, RequiresApproval: fr.RequiresApproval}
	if r.Effect != Allow && r.Effect != Deny {
		return nil, errors.New(`effect must be "allow" or "deny"`)
	}
	if len(fr.Agents) == 0 && len(fr.Scopes) == 0 {
		return nil, errors.New(`name the subject with agents or scopes (use "agents": ["*"] for every agent)`)
	}
	var err error
	if r.agents, r.anyAgent, err = selector(fr.Agents, ValidAgentID, "agents"); err != nil {
		return nil, err
	}
	if slices.Contains(fr.Scopes, Wildcard) {
		return nil, errors.New(`scopes cannot be "*"; use "agents": ["*"]`)
	}
	if r.scopes, _, err = selector(fr.Scopes, ValidScope, "scopes"); err != nil {
		return nil, err
	}
	if len(fr.Upstreams) == 0 {
		return nil, errors.New("upstreams must not be empty")
	}
	if r.upstreams, r.anyUpstream, err = selector(fr.Upstreams, ValidUpstream, "upstreams"); err != nil {
		return nil, err
	}
	if len(fr.Tools) == 0 || len(fr.Tools) > MaxSelectorItems {
		return nil, fmt.Errorf("tools must have 1 to %d entries", MaxSelectorItems)
	}
	for _, t := range fr.Tools {
		base, prefix := strings.CutSuffix(t, Wildcard)
		if base == "" && !prefix || base != "" && !ValidTool(base) || strings.Contains(base, Wildcard) {
			return nil, fmt.Errorf("tool %q must be a tool name, a prefix ending in \"*\", or \"*\"", t)
		}
		r.tools = append(r.tools, toolPattern{name: base, prefix: prefix})
	}
	if fr.Arguments != nil {
		if r.args, err = schema.Compile(fr.Arguments); err != nil {
			return nil, fmt.Errorf("arguments: %w", err)
		}
		// A deny rule fires when the arguments match its schema. The
		// allow-list keywords refuse unusual input, so in a deny rule they
		// would let exactly the unusual input (an IPv4-mapped address, a
		// user@host URL) slip past the deny. Express such limits as allow
		// rules instead.
		if r.Effect == Deny && r.args.UsesAllowLists() {
			return nil, errors.New("x-path-prefix and x-allowed-hosts are allow-lists and cannot be used in deny rules; put them in the allow rule")
		}
	}
	if r.Effect == Deny && (fr.RequiresApproval || fr.Output != nil) {
		return nil, errors.New("requires_approval and output apply only to allow rules")
	}
	if r.Effect == Deny && fr.Limits != nil {
		return nil, errors.New("limits apply only to allow rules")
	}
	if len(fr.Windows) > MaxWindows {
		return nil, fmt.Errorf("at most %d windows", MaxWindows)
	}
	for i, fw := range fr.Windows {
		w, err := compileWindow(i, fw)
		if err != nil {
			return nil, err
		}
		r.windows = append(r.windows, w)
	}
	if fr.When != nil {
		if r.when, err = compileWhen(*fr.When); err != nil {
			return nil, err
		}
	}
	if fr.Limits != nil {
		if r.limits, err = compileLimits(r.ID, fr.Limits); err != nil {
			return nil, err
		}
	}
	if fr.Check != nil {
		if r.check, err = compileCheck(fr.Check); err != nil {
			return nil, err
		}
	}
	if fr.Output != nil {
		o := fr.Output
		if r.Output, err = guard.NewRules(guard.Rules{Redact: o.Redact, RedactPatterns: o.RedactPatterns,
			Deny: o.Deny, DenyPatterns: o.DenyPatterns, MaxBytes: o.MaxBytes}); err != nil {
			return nil, fmt.Errorf("output: %w", err)
		}
	}
	return r, nil
}

func selector(items []string, valid func(string) bool, field string) (map[string]bool, bool, error) {
	if len(items) > MaxSelectorItems {
		return nil, false, fmt.Errorf("%s has more than %d entries", field, MaxSelectorItems)
	}
	set := make(map[string]bool, len(items))
	for _, it := range items {
		if it != Wildcard && !valid(it) {
			return nil, false, fmt.Errorf("%s entry %q is not valid", field, it)
		}
		set[it] = true
	}
	all := set[Wildcard]
	if all {
		delete(set, Wildcard)
		if len(set) > 0 {
			return nil, false, fmt.Errorf(`%s: "*" already matches everything; remove the other entries`, field)
		}
	}
	return set, all, nil
}

func (r *Rule) matchesSubject(s Subject) bool {
	if r.anyAgent || r.agents[s.AgentID] {
		return true
	}
	for _, sc := range s.Scopes {
		if r.scopes[sc] {
			return true
		}
	}
	return false
}

func (r *Rule) matchesTool(tool string) bool {
	for _, t := range r.tools {
		if t.prefix && strings.HasPrefix(tool, t.name) || !t.prefix && tool == t.name {
			return true
		}
	}
	return false
}

func (p *Policy) candidates(upstream string) []int {
	if idx, ok := p.byUpstream[upstream]; ok {
		return idx
	}
	return p.wildcard
}

// Evaluate decides a tools/call without an engine: a rule with a
// relationship check counts its check as unavailable. args is the decoded
// arguments object (or nil when the call has none, which is checked as an
// empty object).
func (p *Policy) Evaluate(s Subject, upstream, tool string, args any) Decision {
	return p.Decide(context.Background(), s, upstream, tool, args, nil)
}

// Decide decides a tools/call, asking the engine get returns for the
// relationship checks of the rules the call reaches. get is called at most
// once, and only when a check has to be asked; nil means there is no
// engine. Identical checks are asked once per call. Time windows and when
// expressions are evaluated at the current time.
func (p *Policy) Decide(ctx context.Context, s Subject, upstream, tool string, args any, get CheckEngine) Decision {
	return p.DecideAt(ctx, time.Now(), s, upstream, tool, args, get)
}

// DecideAt is Decide at the time now. The zero time is an unknown time:
// windows, and when expressions that read now, are then unknown.
func (p *Policy) DecideAt(ctx context.Context, now time.Time, s Subject, upstream, tool string, args any, get CheckEngine) Decision {
	return p.decideAt(ctx, now, s, upstream, tool, args, get, nil)
}

// decideAt is DecideAt with the trace collector tr, nil when the call is
// not explained.
func (p *Policy) decideAt(ctx context.Context, now time.Time, s Subject, upstream, tool string, args any, get CheckEngine, tr *tracer) Decision {
	if args == nil {
		args = map[string]any{}
	}
	k := checker{ctx: ctx, get: get, tr: tr}
	in := condInput{now: now, s: s, up: upstream, tool: tool, args: args}
	d := p.decide(&k, &in, s, upstream, tool, args)
	d.Checks = k.traces
	return d
}

func (p *Policy) decide(k *checker, in *condInput, s Subject, upstream, tool string, args any) Decision {
	// Every k.tr test guards what only an explanation needs, so that
	// deciding a call builds no reasons it does not return.
	cands := p.candidates(upstream)
	for _, i := range cands {
		r := p.Rules[i]
		if r.Effect != Deny {
			continue
		}
		if !r.matchesSubject(s) || !r.matchesTool(tool) {
			if k.tr != nil {
				k.tr.mismatch(i, r, s)
			}
			continue
		}
		if r.args != nil {
			if err := r.args.Validate(args); err != nil {
				if k.tr != nil {
					k.tr.note(i, ResultArgumentsNotMatched, err.Error())
				}
				continue
			}
		}
		if r.conditional() {
			// Fail closed: only a definite "false" lets the call past.
			out, why := r.conditions(in)
			if out == condFalse {
				if k.tr != nil {
					k.tr.note(i, ResultConditionsFalse, why)
				}
				continue
			}
			if out == condUnknown {
				if k.tr != nil {
					k.tr.note(i, ResultConditionsUnknown, why+"; a deny rule counts that as true")
				}
				return Decision{RuleID: r.ID, Reason: "rule " + r.ID + " forbids this call: " + why}
			}
		}
		if r.check == nil {
			if k.tr != nil {
				k.tr.note(i, ResultMatched, "")
			}
			return Decision{RuleID: r.ID, Reason: "rule " + r.ID + " forbids this call"}
		}
		// Fail closed: only a definite "denied" lets the call past.
		t := k.run(r, s, args)
		if k.tr != nil {
			res, why := ResultCheckPrefix+t.Outcome, checkWhy(t)
			if t.Outcome == CheckAllowed {
				res, why = ResultMatched, ""
			} else if t.Outcome != CheckDenied {
				why += "; a deny rule counts that as allowed"
			}
			k.tr.noteCheck(i, k, res, why)
		}
		switch t.Outcome {
		case CheckDenied:
			continue
		case CheckAllowed:
			return Decision{RuleID: r.ID, Reason: "rule " + r.ID + " forbids this call"}
		case CheckUnavailable:
			return Decision{RuleID: r.ID, Unavailable: true,
				Reason: "rule " + r.ID + ": the relationship check could not be made: " + t.Err.Error()}
		default:
			return Decision{RuleID: r.ID, Reason: "rule " + r.ID + " forbids this call: its relationship check is " + checkWhy(t)}
		}
	}
	var constraint *Rule
	var constraintWhy string
	var constraintKind constraintKind
	var unavailable *Rule
	var unavailableErr error
	for _, i := range cands {
		r := p.Rules[i]
		if r.Effect != Allow {
			continue
		}
		if !r.matchesSubject(s) || !r.matchesTool(tool) {
			if k.tr != nil {
				k.tr.mismatch(i, r, s)
			}
			continue
		}
		if r.args != nil {
			if err := r.args.Validate(args); err != nil {
				if constraint == nil {
					constraint, constraintWhy = r, "arguments rejected by rule "+r.ID+": "+err.Error()
				}
				if k.tr != nil {
					k.tr.note(i, ResultArgumentsNotMatched, err.Error())
				}
				continue
			}
		}
		if r.conditional() {
			if out, why := r.conditions(in); out != condTrue {
				if constraint == nil {
					constraint, constraintWhy, constraintKind = r, why, byCondition
				}
				if k.tr != nil {
					res := ResultConditionsFalse
					if out == condUnknown {
						res = ResultConditionsUnknown
					}
					k.tr.note(i, res, why)
				}
				continue
			}
		}
		if r.check != nil {
			if t := k.run(r, s, args); t.Outcome != CheckAllowed {
				if t.Outcome == CheckUnavailable {
					if unavailable == nil {
						unavailable, unavailableErr = r, t.Err
					}
				} else if constraint == nil {
					constraint, constraintWhy, constraintKind = r, "relationship check of rule "+r.ID+" is "+checkWhy(t), byCheck
				}
				if k.tr != nil {
					k.tr.noteCheck(i, k, ResultCheckPrefix+t.Outcome, checkWhy(t))
				}
				continue
			}
			if k.tr != nil {
				k.tr.noteCheck(i, k, ResultMatched, "")
			}
		} else if k.tr != nil {
			k.tr.note(i, ResultMatched, "")
		}
		return Decision{Allowed: true, RuleID: r.ID, Reason: "allowed by rule " + r.ID,
			RequiresApproval: r.RequiresApproval, Output: r.Output, Limits: r.limits}
	}
	if unavailable != nil {
		// The rule that could not ask might have allowed the call.
		return Decision{RuleID: DefaultDenyID, ConstraintRuleID: unavailable.ID, Unavailable: true,
			Reason: "rule " + unavailable.ID + ": the relationship check could not be made: " + unavailableErr.Error()}
	}
	if constraint != nil {
		return Decision{RuleID: DefaultDenyID, ConstraintRuleID: constraint.ID, Reason: constraintWhy, constraint: constraintKind}
	}
	return Decision{RuleID: DefaultDenyID, Reason: "no rule allows this call"}
}

// checkWhy is a check's failed outcome for a reason.
func checkWhy(t CheckTrace) string {
	q := t.Request
	what := q.ResourceType + ":" + q.ResourceID + "#" + q.Permission + "@" + q.Subject.String()
	switch t.Outcome {
	case CheckBadInput:
		return "missing its input: " + t.Err.Error()
	case CheckConditional:
		return "conditional on " + strings.Join(t.Result.Missing, ", ") + ": " + what
	}
	return t.Outcome + ": " + what
}

// Visible reports whether a tool should appear in the subject's tools/list:
// some allow rule could permit a call to it, and no deny rule without an
// argument schema or a relationship check forbids every call to it. It
// never asks the engine.
func (p *Policy) Visible(s Subject, upstream, tool string) bool {
	visible := false
	for _, i := range p.candidates(upstream) {
		r := p.Rules[i]
		if !r.matchesSubject(s) || !r.matchesTool(tool) {
			continue
		}
		if r.Effect == Deny && r.args == nil && r.check == nil && !r.conditional() {
			return false
		}
		if r.Effect == Allow {
			visible = true
		}
	}
	return visible
}
