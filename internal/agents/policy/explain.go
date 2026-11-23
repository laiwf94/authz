package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/agents/jsonrpc"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/engine"
)

// An explanation is a decision with every rule the call reached and why
// each did or did not apply. It is made by the same evaluation as
// DecideAt, with a trace collector switched on: Decide and DecideAt run
// with the collector off, which costs them one nil test per rule and
// nothing else (BenchmarkExplain, TestDecideUntracedAllocations).

// Rule results, as RuleTrace.Result reports them. A check result is
// "check_" and the check's outcome, such as "check_denied".
const (
	// ResultMatched: the rule applies to the call. An allow rule
	// allows it, a deny rule forbids it.
	ResultMatched = "matched"
	// ResultSubjectNotMatched: the rule names other agents and scopes.
	ResultSubjectNotMatched = "subject_not_matched"
	// ResultToolNotMatched: the rule names other tools.
	ResultToolNotMatched = "tool_not_matched"
	// ResultArgumentsNotMatched: the arguments fail the rule's schema.
	ResultArgumentsNotMatched = "arguments_not_matched"
	// ResultConditionsFalse: a window is closed or when is false.
	ResultConditionsFalse = "conditions_false"
	// ResultConditionsUnknown: the conditions cannot be decided (the
	// time is unknown, or when fails or needs a missing fact). A deny
	// rule counts that as true and forbids the call.
	ResultConditionsUnknown = "conditions_unknown"
	// ResultNotReached: an earlier rule decided the call.
	ResultNotReached = "not_reached"
	// ResultCheckPrefix starts the result of a rule whose relationship
	// check decided whether it applies; the check's outcome follows.
	ResultCheckPrefix = "check_"
)

// DefaultExplainTraceNodes bounds each relationship check's engine trace
// in an explanation unless the caller names another bound;
// MaxExplainTraceNodes is the largest a caller may name.
const (
	DefaultExplainTraceNodes = check.DefaultTraceNodes
	MaxExplainTraceNodes     = 10_000
)

// Explainer is a Checker that can explain a check: the answer with a
// trace of how the engine reached it. *engine.Local is one. When the
// engine an explanation asks is an Explainer, its checks carry the trace.
type Explainer interface {
	Checker
	Explain(ctx context.Context, req engine.CheckRequest, maxNodes int) (engine.CheckResult, *check.Trace, error)
}

var _ Explainer = (*engine.Local)(nil)

// Explanation is a decision and how it was reached.
type Explanation struct {
	// Policy is the hash of the policy that decided.
	Policy   string `json:"policy"`
	Upstream string `json:"upstream"`
	Tool     string `json:"tool"`
	// At is the time the call was decided at; absent when unknown.
	At *time.Time `json:"at,omitempty"`

	Decision string `json:"decision"` // "allow" or "deny"
	Rule     string `json:"rule"`
	Reason   string `json:"reason"`
	// ConstraintRule is the allow rule a default deny names, the first
	// that matched everything but its arguments, conditions or check.
	ConstraintRule string `json:"constraint_rule,omitempty"`
	// Unavailable: a relationship check the decision depends on could not
	// be answered, which the gateway reports as an outage.
	Unavailable bool `json:"unavailable,omitempty"`
	// Hidden: the call is denied by default and the tool is not in the
	// agent's tools/list, so the gateway answers "Unknown tool".
	Hidden bool `json:"hidden,omitempty"`
	// Visible says whether the tool is in the agent's tools/list.
	Visible          bool `json:"visible"`
	RequiresApproval bool `json:"requires_approval,omitempty"`
	// Limits are the allowing rule's limits, as written.
	Limits string `json:"limits,omitempty"`
	// ResultDenies are the allowing rule's result deny patterns, in the
	// order they are tried.
	ResultDenies []string `json:"result_denies,omitempty"`

	// Rules is every rule that can apply to the upstream, in the order
	// they are tried: the deny rules, then the allow rules, each in file
	// order. OtherUpstreams counts the rules that name only other
	// upstreams, which the call never reaches.
	Rules          []RuleTrace `json:"rules"`
	OtherUpstreams int         `json:"other_upstreams"`
}

// RuleTrace is one rule a call reached, and what it found.
type RuleTrace struct {
	Rule   string `json:"rule"`
	Effect Effect `json:"effect"`
	// Result is one of the Result* values, or "check_" and a check
	// outcome; Reason says more when there is more to say.
	Result string `json:"result"`
	Reason string `json:"reason,omitempty"`
	// Selected marks the rule the decision names; Constraint the allow
	// rule a default deny names.
	Selected   bool `json:"selected,omitempty"`
	Constraint bool `json:"constraint,omitempty"`
	// Check is the rule's relationship check, when the call reached it.
	Check *CheckExplanation `json:"check,omitempty"`
}

// CheckExplanation is one relationship check of an explanation.
type CheckExplanation struct {
	Resource   string   `json:"resource"`
	Permission string   `json:"permission"`
	Subject    string   `json:"subject"`
	Outcome    string   `json:"outcome"`
	Missing    []string `json:"missing,omitempty"`
	Revision   uint64   `json:"revision,omitempty"`
	Error      string   `json:"error,omitempty"`
	// Cached: an earlier identical check of this call answered it.
	Cached bool `json:"cached,omitempty"`
	// Trace is the engine's evaluation, when the engine can explain.
	Trace *CheckEngineTrace `json:"trace,omitempty"`
}

// CheckEngineTrace is an engine's trace of a check.
type CheckEngineTrace struct {
	Root      *check.TraceNode `json:"root"`
	Nodes     int              `json:"nodes"`
	Truncated bool             `json:"truncated,omitempty"`
}

// tracer collects what each rule found during one evaluation.
type tracer struct {
	nodes int        // engine trace bound
	rules []ruleNote // by rule index
}

type ruleNote struct {
	set    bool
	result string
	reason string
	check  int // index into the checker's traces, or -1
}

// note records what rule i found. Callers test k.tr first, so that the
// untraced path builds no reasons.
func (t *tracer) note(i int, result, reason string) {
	t.rules[i] = ruleNote{set: true, result: result, reason: reason, check: -1}
}

// noteCheck records that rule i's check, the checker's latest, decided
// what it found.
func (t *tracer) noteCheck(i int, k *checker, result, reason string) {
	t.rules[i] = ruleNote{set: true, result: result, reason: reason, check: len(k.traces) - 1}
}

// mismatch records why rule i does not match the subject or the tool.
func (t *tracer) mismatch(i int, r *Rule, s Subject) {
	if !r.matchesSubject(s) {
		t.note(i, ResultSubjectNotMatched, "")
		return
	}
	t.note(i, ResultToolNotMatched, "")
}

// Explain decides a call as DecideAt does, giving the same Decision, and
// explains it. When the engine get returns is an Explainer, each check is
// explained instead of checked, with a trace of at most traceNodes nodes
// (DefaultExplainTraceNodes when traceNodes <= 0). It allocates, and is
// meant for explanations, not for deciding calls.
func (p *Policy) Explain(ctx context.Context, now time.Time, s Subject, upstream, tool string, args any, get CheckEngine, traceNodes int) (Decision, *Explanation) {
	if traceNodes <= 0 {
		traceNodes = DefaultExplainTraceNodes
	}
	traceNodes = min(traceNodes, MaxExplainTraceNodes)
	tr := &tracer{nodes: traceNodes, rules: make([]ruleNote, len(p.Rules))}
	d := p.decideAt(ctx, now, s, upstream, tool, args, get, tr)
	visible := p.Visible(s, upstream, tool)
	ex := &Explanation{Policy: p.Hash, Upstream: upstream, Tool: tool, Decision: decisionWord(d.Allowed),
		Rule: d.RuleID, Reason: d.Reason, ConstraintRule: d.ConstraintRuleID, Unavailable: d.Unavailable,
		Visible: visible, RequiresApproval: d.RequiresApproval, ResultDenies: d.Output.DenyNames(),
		Hidden: !d.Allowed && d.RuleID == DefaultDenyID && d.ConstraintRuleID == "" && !visible,
		Rules:  []RuleTrace{}}
	if !now.IsZero() {
		at := now
		ex.At = &at
	}
	if d.Limits != nil {
		ex.Limits = d.Limits.String()
	}
	cands := p.candidates(upstream)
	ex.OtherUpstreams = len(p.Rules) - len(cands)
	for _, effect := range []Effect{Deny, Allow} {
		for _, i := range cands {
			r := p.Rules[i]
			if r.Effect != effect {
				continue
			}
			n := tr.rules[i]
			rt := RuleTrace{Rule: r.ID, Effect: r.Effect, Result: ResultNotReached,
				Selected: r.ID == d.RuleID, Constraint: r.ID == d.ConstraintRuleID}
			if n.set {
				rt.Result, rt.Reason = n.result, n.reason
				if n.check >= 0 {
					rt.Check = explainCheck(d.Checks[n.check])
				}
			}
			ex.Rules = append(ex.Rules, rt)
		}
	}
	return d, ex
}

func explainCheck(t CheckTrace) *CheckExplanation {
	q := t.Request
	c := &CheckExplanation{Resource: q.ResourceType + ":" + q.ResourceID, Permission: q.Permission,
		Subject: q.Subject.String(), Outcome: t.Outcome, Missing: t.Result.Missing,
		Revision: uint64(t.Result.At.Revision), Cached: t.Cached}
	if t.Err != nil {
		c.Error = t.Err.Error()
	}
	if t.trace != nil {
		c.Trace = &CheckEngineTrace{Root: t.trace.Root, Nodes: t.trace.Nodes, Truncated: t.trace.Truncated}
	}
	return c
}

// MaxCallBytes bounds a call file.
const MaxCallBytes = 1 << 20

// A call file describes one tools/call to explain, as a case of a case
// file does, without a name or expectations:
//
//	{"subject": {"agent": "alice-bot", "owner": "alice", "scopes": ["files:read"]},
//	 "call": {"tool": "fs.write_file", "arguments": {"project": "p1"}},
//	 "now": "2026-12-05T10:00:00+01:00",
//	 "checks": {"project:p1#edit@user:alice": "allowed"},
//	 "trace_nodes": 200}
//
// now is the time of the call; without it the time is unknown. checks
// answers relationship checks when no engine is asked ("authz mcp policy
// explain"); a check it does not list is denied. trace_nodes bounds each
// check's engine trace when the engine can explain.
type callFile struct {
	Subject    fileSubject       `json:"subject"`
	Call       *fileCall         `json:"call"`
	Now        string            `json:"now"`
	Checks     map[string]string `json:"checks"`
	TraceNodes int               `json:"trace_nodes"`
}

// Call is a parsed call file.
type Call struct {
	Subject   Subject
	Tool      ToolRef
	Arguments any       // nil when absent
	Now       time.Time // zero when absent
	// Checks is nil when the file gives none.
	Checks     map[string]string
	TraceNodes int
}

// ParseCall validates and decodes a call file. It is as strict as
// ParseCases: unknown fields and duplicate keys are errors.
func ParseCall(src []byte) (*Call, error) {
	if len(src) > MaxCallBytes {
		return nil, fmt.Errorf("call: larger than %d bytes", MaxCallBytes)
	}
	if err := jsonrpc.CheckStructure(src); err != nil {
		return nil, fmt.Errorf("call: %w", err)
	}
	var f callFile
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("call: %w", err)
	}
	var c Call
	var err error
	if c.Subject, err = compileSubject(f.Subject); err != nil {
		return nil, fmt.Errorf("call: %w", err)
	}
	if f.Call == nil {
		return nil, errors.New(`call: "call" with the tool and its arguments is required`)
	}
	if c.Tool, err = ParseToolRef(f.Call.Tool); err != nil {
		return nil, fmt.Errorf("call: %w", err)
	}
	if c.Arguments, err = decodeArguments(f.Call.Arguments); err != nil {
		return nil, fmt.Errorf("call: %w", err)
	}
	if c.Now, err = parseNow(f.Now); err != nil {
		return nil, fmt.Errorf("call: %w", err)
	}
	if err := validateChecks(f.Checks); err != nil {
		return nil, fmt.Errorf("call: %w", err)
	}
	c.Checks = f.Checks
	if f.TraceNodes < 0 || f.TraceNodes > MaxExplainTraceNodes {
		return nil, fmt.Errorf("call: trace_nodes must be from 0 to %d", MaxExplainTraceNodes)
	}
	c.TraceNodes = f.TraceNodes
	return &c, nil
}

// ExplainCall explains c without an engine: its relationship checks are
// answered from c.Checks, as a case file's are.
func (p *Policy) ExplainCall(c *Call) (Decision, *Explanation) {
	return p.Explain(context.Background(), c.Now, c.Subject, c.Tool.Upstream, c.Tool.Tool, c.Arguments,
		func(context.Context) (Checker, error) { return caseChecker(c.Checks), nil }, c.TraceNodes)
}

// WriteText writes an explanation for a reader: the decision, then each
// rule the call reached with what it found.
func (ex *Explanation) WriteText(w io.Writer) {
	fmt.Fprintf(w, "%s.%s: %s by %s\n", ex.Upstream, ex.Tool, ex.Decision, ex.Rule)
	fmt.Fprintf(w, "  reason: %s\n", ex.Reason)
	if ex.ConstraintRule != "" {
		fmt.Fprintf(w, "  constraint rule: %s\n", ex.ConstraintRule)
	}
	if ex.Unavailable {
		fmt.Fprintln(w, "  unavailable: a relationship check could not be made")
	}
	if ex.Hidden {
		fmt.Fprintln(w, "  hidden: the agent cannot see the tool and is told it is unknown")
	}
	if ex.RequiresApproval {
		fmt.Fprintln(w, "  requires approval")
	}
	if ex.Limits != "" {
		fmt.Fprintf(w, "  limits: %s\n", ex.Limits)
	}
	if len(ex.ResultDenies) > 0 {
		fmt.Fprintf(w, "  result deny patterns: %s\n", strings.Join(ex.ResultDenies, ", "))
	}
	if ex.At != nil {
		fmt.Fprintf(w, "  at: %s\n", ex.At.Format(time.RFC3339))
	} else {
		fmt.Fprintln(w, "  at: unknown time")
	}
	fmt.Fprintf(w, "  policy: %s\n", ex.Policy)
	fmt.Fprintf(w, "rules (%d for this upstream, %d for others):\n", len(ex.Rules), ex.OtherUpstreams)
	for _, r := range ex.Rules {
		mark := " "
		switch {
		case r.Selected:
			mark = "*"
		case r.Constraint:
			mark = "!"
		}
		fmt.Fprintf(w, "  %s %-5s %-24s %s", mark, r.Effect, r.Rule, r.Result)
		if r.Reason != "" {
			fmt.Fprintf(w, ": %s", r.Reason)
		}
		fmt.Fprintln(w)
		if c := r.Check; c != nil {
			fmt.Fprintf(w, "          check %s#%s@%s: %s", c.Resource, c.Permission, c.Subject, c.Outcome)
			if c.Cached {
				fmt.Fprint(w, " (cached)")
			}
			fmt.Fprintln(w)
		}
	}
}
