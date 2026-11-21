package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/laiwf94/authz/internal/agents/jsonrpc"
	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/store"
)

// Limits on a case file.
const (
	MaxCaseBytes     = 4 << 20
	MaxCases         = 10000
	MaxCaseListTools = 1024
)

// A case file is a list of expectations about a policy, checked by
// RunCases: what a call is decided, and what a tools/list shows.
//
//	{"version": 1, "cases": [
//	  {"name": "alice reads a report",
//	   "subject": {"agent": "alice-bot", "scopes": ["files:read"]},
//	   "call": {"tool": "fake.read_file", "arguments": {"path": "reports/q1.txt"}},
//	   "expect": {"decision": "allow", "rule": "read-workspace"}},
//	  {"name": "bob sees only echo",
//	   "subject": {"agent": "bob-bot"},
//	   "list": ["fake.echo", "fake.read_file"],
//	   "expect": {"visible": ["fake.echo"]}}
//	]}
//
// Tool names are written as agents see them, "upstream.tool". A call case
// must expect a decision; rule, constraint_rule, requires_approval,
// reason_contains and hidden are checked only when present. hidden is true
// when the gateway would answer "Unknown tool" rather than "denied by
// policy", because the agent cannot see the tool. A list case names the
// tools an upstream offers and expects exactly the ones the subject sees.
//
// Rules with a relationship check are decided against the case's checks
// instead of an engine: a map from "resource#permission@subject" to
// "allowed", "denied", "conditional" or "unavailable". A check the map
// does not list is denied. The subject's owner fills {owner}:
//
//	{"name": "alice edits her project",
//	 "subject": {"agent": "alice-bot", "owner": "alice"},
//	 "call": {"tool": "fs.write_file", "arguments": {"project": "p1"}},
//	 "checks": {"project:p1#edit@user:alice": "allowed"},
//	 "expect": {"decision": "allow", "rule": "edit-projects"}}
type caseFile struct {
	Version int        `json:"version"`
	Cases   []fileCase `json:"cases"`
}

type fileCase struct {
	Name    string            `json:"name"`
	Subject fileSubject       `json:"subject"`
	Call    *fileCall         `json:"call"`
	List    []string          `json:"list"`
	Checks  map[string]string `json:"checks"`
	Expect  fileExpect        `json:"expect"`
}

type fileSubject struct {
	Agent  string   `json:"agent"`
	Owner  string   `json:"owner"`
	Scopes []string `json:"scopes"`
}

type fileCall struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
}

type fileExpect struct {
	Decision         string   `json:"decision"`
	Rule             *string  `json:"rule"`
	ConstraintRule   *string  `json:"constraint_rule"`
	RequiresApproval *bool    `json:"requires_approval"`
	ReasonContains   *string  `json:"reason_contains"`
	Hidden           *bool    `json:"hidden"`
	Visible          []string `json:"visible"`
}

// ToolRef is a tool as agents name it: upstream "." tool.
type ToolRef struct {
	Upstream, Tool string
}

func (t ToolRef) String() string { return t.Upstream + "." + t.Tool }

// ParseToolRef splits "upstream.tool" the way the gateway does.
func ParseToolRef(name string) (ToolRef, error) {
	up, tool, ok := strings.Cut(name, ".")
	if !ok || !ValidUpstream(up) || !ValidTool(tool) {
		return ToolRef{}, fmt.Errorf("tool %q must be written as upstream.tool", name)
	}
	return ToolRef{up, tool}, nil
}

// Case is one parsed expectation.
type Case struct {
	Name    string
	Subject Subject

	// A call case has Call set; a list case has List set.
	Call      *ToolRef
	Arguments any // decoded with numbers as json.Number; nil when absent
	List      []ToolRef
	// Checks answers the relationship checks of a call case, keyed by
	// "resource#permission@subject"; unlisted checks are denied.
	Checks map[string]string

	Want Expect
}

// Expect is what a case expects. Nil pointers are not checked.
type Expect struct {
	Allowed          bool // call cases
	Rule             *string
	ConstraintRule   *string
	RequiresApproval *bool
	ReasonContains   *string
	Hidden           *bool
	Visible          []string // list cases, sorted
}

// Cases is a parsed case file.
type Cases struct {
	Cases []Case
}

// ParseCases validates and decodes a case file. It is strict: unknown
// fields, duplicate keys, duplicate case names, malformed names and
// expectations that do not apply to the kind of case are all errors, so a
// typo cannot turn a case into one that passes without checking anything.
func ParseCases(src []byte) (*Cases, error) {
	if len(src) > MaxCaseBytes {
		return nil, fmt.Errorf("cases: file is larger than %d bytes", MaxCaseBytes)
	}
	if err := jsonrpc.CheckStructure(src); err != nil {
		return nil, fmt.Errorf("cases: %w", err)
	}
	var f caseFile
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("cases: %w", err)
	}
	if f.Version != 1 {
		return nil, errors.New("cases: version must be 1")
	}
	if len(f.Cases) == 0 {
		return nil, errors.New("cases: no cases")
	}
	if len(f.Cases) > MaxCases {
		return nil, fmt.Errorf("cases: at most %d cases", MaxCases)
	}
	out := &Cases{Cases: make([]Case, 0, len(f.Cases))}
	seen := map[string]bool{}
	for i, fc := range f.Cases {
		c, err := compileCase(fc)
		if err != nil {
			return nil, fmt.Errorf("cases: case %d (%q): %w", i, fc.Name, err)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("cases: case name %q is used twice", c.Name)
		}
		seen[c.Name] = true
		out.Cases = append(out.Cases, c)
	}
	return out, nil
}

func compileCase(fc fileCase) (Case, error) {
	c := Case{Name: fc.Name}
	if fc.Name == "" || len(fc.Name) > 200 || strings.ContainsFunc(fc.Name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return c, errors.New("name must be 1 to 200 bytes with no control characters")
	}
	s := fc.Subject
	if !ValidAgentID(s.Agent) {
		return c, fmt.Errorf("subject agent %q is not a valid agent id", s.Agent)
	}
	if len(s.Scopes) > MaxSelectorItems {
		return c, fmt.Errorf("subject has more than %d scopes", MaxSelectorItems)
	}
	for _, sc := range s.Scopes {
		if !ValidScope(sc) {
			return c, fmt.Errorf("subject scope %q is not valid", sc)
		}
	}
	if len(s.Owner) > 128 || strings.ContainsFunc(s.Owner, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return c, errors.New("subject owner must be at most 128 bytes with no control characters")
	}
	c.Subject = Subject{AgentID: s.Agent, Owner: s.Owner, Scopes: s.Scopes}
	if fc.Checks != nil && fc.Call == nil {
		return c, errors.New(`"checks" applies only to call cases`)
	}
	if len(fc.Checks) > MaxSelectorItems {
		return c, fmt.Errorf("checks has more than %d entries", MaxSelectorItems)
	}
	for k, v := range fc.Checks {
		if _, err := parseCheckText(k); err != nil {
			return c, fmt.Errorf("checks: %w", err)
		}
		switch v {
		case CheckAllowed, CheckDenied, CheckConditional, CheckUnavailable:
		default:
			return c, fmt.Errorf("checks: %q must be \"allowed\", \"denied\", \"conditional\" or \"unavailable\"", k)
		}
	}
	c.Checks = fc.Checks
	e := fc.Expect
	switch {
	case fc.Call != nil && fc.List != nil:
		return c, errors.New(`a case has either "call" or "list", not both`)
	case fc.Call != nil:
		ref, err := ParseToolRef(fc.Call.Tool)
		if err != nil {
			return c, err
		}
		c.Call = &ref
		if fc.Call.Arguments != nil {
			v, err := jsonrpc.DecodeValue(fc.Call.Arguments)
			if err != nil {
				return c, fmt.Errorf("arguments: %w", err)
			}
			if _, ok := v.(map[string]any); !ok {
				return c, errors.New("arguments must be an object")
			}
			c.Arguments = v
		}
		switch e.Decision {
		case string(Allow):
			c.Want.Allowed = true
		case string(Deny):
		default:
			return c, errors.New(`expect.decision must be "allow" or "deny"`)
		}
		if e.Visible != nil {
			return c, errors.New("expect.visible applies only to list cases")
		}
		for _, id := range []*string{e.Rule, e.ConstraintRule} {
			if id != nil && *id != DefaultDenyID && !ruleIDRe.MatchString(*id) {
				return c, fmt.Errorf("expected rule id %q is not a valid rule id", *id)
			}
		}
		if c.Want.Allowed {
			switch {
			case e.ConstraintRule != nil:
				return c, errors.New("expect.constraint_rule applies only to denials")
			case e.Hidden != nil:
				return c, errors.New("expect.hidden applies only to denials")
			case e.Rule != nil && *e.Rule == DefaultDenyID:
				return c, errors.New(`an allowed call cannot expect rule "default-deny"`)
			}
		} else if e.RequiresApproval != nil {
			return c, errors.New("expect.requires_approval applies only to allowed calls")
		}
		c.Want.Rule, c.Want.ConstraintRule, c.Want.RequiresApproval = e.Rule, e.ConstraintRule, e.RequiresApproval
		c.Want.ReasonContains, c.Want.Hidden = e.ReasonContains, e.Hidden
	case fc.List != nil:
		if len(fc.List) == 0 || len(fc.List) > MaxCaseListTools {
			return c, fmt.Errorf("list must name 1 to %d tools", MaxCaseListTools)
		}
		offered := map[string]bool{}
		for _, name := range fc.List {
			ref, err := ParseToolRef(name)
			if err != nil {
				return c, fmt.Errorf("list: %w", err)
			}
			if offered[name] {
				return c, fmt.Errorf("list names %q twice", name)
			}
			offered[name] = true
			c.List = append(c.List, ref)
		}
		if e.Decision != "" || e.Rule != nil || e.ConstraintRule != nil || e.RequiresApproval != nil ||
			e.ReasonContains != nil || e.Hidden != nil {
			return c, errors.New("a list case expects only visible")
		}
		if e.Visible == nil {
			return c, errors.New(`a list case must expect "visible" (use [] for none)`)
		}
		vis := map[string]bool{}
		for _, name := range e.Visible {
			if !offered[name] {
				return c, fmt.Errorf("expect.visible names %q, which the list does not offer", name)
			}
			if vis[name] {
				return c, fmt.Errorf("expect.visible names %q twice", name)
			}
			vis[name] = true
		}
		c.Want.Visible = slices.Sorted(func(yield func(string) bool) {
			for n := range vis {
				if !yield(n) {
					return
				}
			}
		})
	default:
		return c, errors.New(`a case needs "call" or "list"`)
	}
	return c, nil
}

// Mismatch is one difference between what a case expects and what the
// policy decided.
type Mismatch struct {
	Field     string
	Want, Got string
}

// CaseResult is the outcome of one case.
type CaseResult struct {
	Name       string
	Mismatches []Mismatch // empty when the case passed
	// Got is a description of the actual decision, for the report.
	Got string
}

// Passed reports whether the case passed.
func (r CaseResult) Passed() bool { return len(r.Mismatches) == 0 }

// CaseReport is the outcome of a run.
type CaseReport struct {
	Results        []CaseResult
	Passed, Failed int
}

// RunCases checks every case against p. A case that names a rule the
// policy does not define fails, so renaming a rule cannot leave cases that
// quietly expect something that no longer exists.
func RunCases(p *Policy, cs *Cases) CaseReport {
	ids := make(map[string]bool, len(p.Rules)+1)
	ids[DefaultDenyID] = true
	for _, r := range p.Rules {
		ids[r.ID] = true
	}
	rep := CaseReport{Results: make([]CaseResult, 0, len(cs.Cases))}
	for i := range cs.Cases {
		res := runCase(p, ids, &cs.Cases[i])
		if res.Passed() {
			rep.Passed++
		} else {
			rep.Failed++
		}
		rep.Results = append(rep.Results, res)
	}
	return rep
}

func runCase(p *Policy, ids map[string]bool, c *Case) CaseResult {
	res := CaseResult{Name: c.Name}
	bad := func(field, want, got string) {
		res.Mismatches = append(res.Mismatches, Mismatch{field, want, got})
	}
	for _, id := range []*string{c.Want.Rule, c.Want.ConstraintRule} {
		if id != nil && !ids[*id] {
			bad("rule", *id+" (defined in the policy)", "no rule with that id")
		}
	}
	if c.List != nil {
		var got []string
		for _, t := range c.List {
			if p.Visible(c.Subject, t.Upstream, t.Tool) {
				got = append(got, t.String())
			}
		}
		slices.Sort(got)
		res.Got = "visible [" + strings.Join(got, ", ") + "]"
		if !slices.Equal(got, c.Want.Visible) {
			for _, n := range c.Want.Visible {
				if !slices.Contains(got, n) {
					bad("visible", n+" listed", "hidden")
				}
			}
			for _, n := range got {
				if !slices.Contains(c.Want.Visible, n) {
					bad("visible", n+" hidden", "listed")
				}
			}
		}
		return res
	}
	d := p.Decide(context.Background(), c.Subject, c.Call.Upstream, c.Call.Tool, c.Arguments,
		func(context.Context) (Checker, error) { return caseChecker(c.Checks), nil })
	hidden := !d.Allowed && d.RuleID == DefaultDenyID && d.ConstraintRuleID == "" &&
		!p.Visible(c.Subject, c.Call.Upstream, c.Call.Tool)
	res.Got = describe(d, hidden)
	if d.Allowed != c.Want.Allowed {
		bad("decision", decisionWord(c.Want.Allowed), decisionWord(d.Allowed))
	}
	if w := c.Want.Rule; w != nil && *w != d.RuleID {
		bad("rule", *w, d.RuleID)
	}
	if w := c.Want.ConstraintRule; w != nil && *w != d.ConstraintRuleID {
		bad("constraint_rule", *w, orNone(d.ConstraintRuleID))
	}
	if w := c.Want.RequiresApproval; w != nil && *w != d.RequiresApproval {
		bad("requires_approval", fmt.Sprint(*w), fmt.Sprint(d.RequiresApproval))
	}
	if w := c.Want.ReasonContains; w != nil && !strings.Contains(d.Reason, *w) {
		bad("reason", "contains "+strconvQuote(*w), strconvQuote(d.Reason))
	}
	if w := c.Want.Hidden; w != nil && *w != hidden {
		bad("hidden", fmt.Sprint(*w), fmt.Sprint(hidden))
	}
	return res
}

func decisionWord(allowed bool) string {
	if allowed {
		return string(Allow)
	}
	return string(Deny)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func describe(d Decision, hidden bool) string {
	var b strings.Builder
	b.WriteString(decisionWord(d.Allowed))
	b.WriteString(" by ")
	b.WriteString(d.RuleID)
	switch {
	case d.ConstraintRuleID == "":
	case d.Unavailable:
		b.WriteString(" (check of " + d.ConstraintRuleID + " unavailable)")
	case d.byCheck:
		b.WriteString(" (check of " + d.ConstraintRuleID + " failed)")
	default:
		b.WriteString(" (arguments rejected by " + d.ConstraintRuleID + ")")
	}
	if d.RequiresApproval {
		b.WriteString(", requires approval")
	}
	if hidden {
		b.WriteString(", tool hidden from the agent")
	}
	b.WriteString(": ")
	b.WriteString(d.Reason)
	return b.String()
}

// WriteText writes a readable report: every failing case with each
// mismatch as want and got, then a one-line summary. verbose also lists
// passing cases.
func (rep CaseReport) WriteText(w io.Writer, verbose bool) {
	for _, r := range rep.Results {
		if r.Passed() {
			if verbose {
				fmt.Fprintf(w, "ok   %s\n", r.Name)
			}
			continue
		}
		fmt.Fprintf(w, "FAIL %s\n", r.Name)
		width := 0
		for _, m := range r.Mismatches {
			width = max(width, len(m.Field))
		}
		for _, m := range r.Mismatches {
			fmt.Fprintf(w, "     %-*s want %s\n", width+1, m.Field+":", m.Want)
			fmt.Fprintf(w, "     %-*s  got %s\n", width+1, "", m.Got)
		}
		fmt.Fprintf(w, "     decided: %s\n", r.Got)
	}
	status := "PASS"
	if rep.Failed > 0 {
		status = "FAIL"
	}
	fmt.Fprintf(w, "%s %d cases: %d passed, %d failed\n", status, len(rep.Results), rep.Passed, rep.Failed)
}

// caseChecker answers checks from a case's map.
type caseChecker map[string]string

func (m caseChecker) Check(_ context.Context, req engine.CheckRequest) (engine.CheckResult, error) {
	key := req.ResourceType + ":" + req.ResourceID + "#" + req.Permission + "@" + req.Subject.String()
	switch m[key] {
	case CheckAllowed:
		return engine.CheckResult{Allowed: true, Permissionship: check.Allowed}, nil
	case CheckConditional:
		return engine.CheckResult{Permissionship: check.Conditional, Missing: []string{"case"}}, nil
	case CheckUnavailable:
		return engine.CheckResult{}, errors.New("the case makes the engine unavailable")
	}
	return engine.CheckResult{Permissionship: check.Denied}, nil
}

// parseCheckText validates "type:id#permission@subject".
func parseCheckText(s string) (engine.CheckRequest, error) {
	var req engine.CheckRequest
	res, sub, ok := strings.Cut(s, "@")
	if !ok {
		return req, fmt.Errorf("%q must be type:id#permission@subject", s)
	}
	obj, perm, ok := strings.Cut(res, "#")
	if !ok {
		return req, fmt.Errorf("%q must be type:id#permission@subject", s)
	}
	typ, id, ok := strings.Cut(obj, ":")
	if !ok || !validName(typ) || !store.ValidID(id) || !validName(perm) {
		return req, fmt.Errorf("%q must be type:id#permission@subject", s)
	}
	subj, err := store.ParseSubject(sub, false)
	if err != nil {
		return req, fmt.Errorf("%q: %w", s, err)
	}
	req.ResourceType, req.ResourceID, req.Permission, req.Subject = typ, id, perm, subj
	return req, nil
}
