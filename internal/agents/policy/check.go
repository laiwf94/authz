package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/store"
)

// A rule may carry a relationship check: the in-process authorization
// engine (internal/authz/engine) is asked whether a subject has a
// permission on a resource, and the rule applies only when it does.
//
//	{"id": "edit-own-projects", "effect": "allow", "agents": ["*"],
//	 "upstreams": ["files"], "tools": ["write_file"],
//	 "check": {"resource": "project:{args.project}", "permission": "edit"}}
//
// Resource and subject are "type:id" (the subject may add "#relation", a
// userset), and their IDs are templates of literal text and {variables}:
//
//   - {owner}: the user behind the calling agent (its owner);
//   - {agent}: the calling agent's id;
//   - {args.<name>} or {args.<name>.<name>...}: an argument of the call, a
//     string or an integer, found by walking objects from the arguments.
//
// The subject defaults to "user:{owner}". A filled-in ID must be a valid
// object ID; a call whose values make an invalid one, or that lacks a value
// the check needs, is not asked about.
//
// In an allow rule, the check is one more thing the call must satisfy,
// like the argument schema: when the engine does not answer "allowed" the
// rule does not allow the call and evaluation moves on to the next allow
// rule, and a default deny names the first such rule as its
// ConstraintRuleID. In a deny rule, the check is the condition under which
// the rule forbids the call, and the rule fails closed: a call it cannot
// ask about (a missing or invalid value), a conditional answer and an
// engine that cannot answer all deny the call as if the check held.
//
// An engine that cannot answer (none in this process, or an error) makes a
// deny rule's call Unavailable, and makes the decision Unavailable when no
// later allow rule allows the call either: the gateway answers that as an
// outage (503) rather than a denial. Each distinct check is asked at most
// once per call (Decide's cache), at the engine's default consistency,
// minimize_latency.
type fileCheck struct {
	Resource   string `json:"resource"`
	Permission string `json:"permission"`
	Subject    string `json:"subject"`
}

// DefaultCheckSubject is a check's subject when the rule names none.
const DefaultCheckSubject = "user:{owner}"

// MaxArgPathDepth bounds the names in an {args...} variable.
const MaxArgPathDepth = 8

// Check outcomes, as CheckTrace.Outcome and in audit records.
const (
	CheckAllowed     = "allowed"
	CheckDenied      = "denied"
	CheckConditional = "conditional" // depends on caveat parameters no one supplied
	CheckBadInput    = "bad_input"   // a value is missing or not an object ID
	CheckUnavailable = "unavailable" // the engine could not answer
)

// Checker answers permission checks; engine.Engine is one.
type Checker interface {
	Check(ctx context.Context, req engine.CheckRequest) (engine.CheckResult, error)
}

// CheckTrace records one relationship check a call reached.
type CheckTrace struct {
	RuleID  string
	Request engine.CheckRequest // what was asked, or would have been
	Outcome string              // one of the Check* outcomes
	Result  engine.CheckResult  // when the engine answered
	Err     error               // bad input, or the engine's error
	Cached  bool                // answered by an earlier identical check of this call
}

// String is the check as "resource#permission@subject: outcome".
func (t CheckTrace) String() string {
	q := t.Request
	return q.ResourceType + ":" + q.ResourceID + "#" + q.Permission + "@" + q.Subject.String() + ": " + t.Outcome
}

type varSource uint8

const (
	varLit varSource = iota
	varOwner
	varAgent
	varArg
)

type varPart struct {
	src  varSource
	lit  string   // varLit
	path []string // varArg
}

type idTemplate []varPart

type compiledCheck struct {
	resType    string
	resID      idTemplate
	permission string
	subType    string
	subID      idTemplate
	subRel     string
}

func compileCheck(c *fileCheck) (*compiledCheck, error) {
	cc := &compiledCheck{permission: c.Permission}
	var err error
	if c.Resource == "" {
		return nil, errors.New("check.resource is required, as type:id")
	}
	if cc.resType, cc.resID, _, err = compileObject("check.resource", c.Resource, false); err != nil {
		return nil, err
	}
	if !validName(c.Permission) {
		return nil, fmt.Errorf("check.permission %q must be a relation or permission name: a lower-case letter, then lower-case letters, digits or '_', at most 64", c.Permission)
	}
	sub := c.Subject
	if sub == "" {
		sub = DefaultCheckSubject
	}
	if cc.subType, cc.subID, cc.subRel, err = compileObject("check.subject", sub, true); err != nil {
		return nil, err
	}
	return cc, nil
}

func compileObject(field, s string, rel bool) (string, idTemplate, string, error) {
	typ, rest, ok := strings.Cut(s, ":")
	if !ok {
		return "", nil, "", fmt.Errorf("%s %q must be type:id", field, s)
	}
	if !validName(typ) {
		return "", nil, "", fmt.Errorf("%s %q: type %q must be a lower-case letter, then lower-case letters, digits or '_', at most 64", field, s, typ)
	}
	id, relation := rest, ""
	if i := strings.LastIndexByte(rest, '#'); i >= 0 {
		if !rel {
			return "", nil, "", fmt.Errorf("%s %q: a resource is one object, without #relation", field, s)
		}
		id, relation = rest[:i], rest[i+1:]
		if !validName(relation) {
			return "", nil, "", fmt.Errorf("%s %q: relation %q must be a lower-case letter, then lower-case letters, digits or '_', at most 64", field, s, relation)
		}
	}
	t, err := compileTemplate(id)
	if err != nil {
		return "", nil, "", fmt.Errorf("%s %q: %v", field, s, err)
	}
	return typ, t, relation, nil
}

func compileTemplate(s string) (idTemplate, error) {
	if s == "" {
		return nil, errors.New("the id is empty")
	}
	var t idTemplate
	for s != "" {
		open := strings.IndexByte(s, '{')
		if cl := strings.IndexByte(s, '}'); cl >= 0 && (open < 0 || cl < open) {
			return nil, errors.New("'}' without '{'")
		}
		if open < 0 {
			t = append(t, varPart{lit: s})
			break
		}
		if open > 0 {
			t = append(t, varPart{lit: s[:open]})
		}
		end := strings.IndexByte(s[open:], '}')
		if end < 0 {
			return nil, errors.New("'{' without '}'")
		}
		p, err := variable(s[open+1 : open+end])
		if err != nil {
			return nil, err
		}
		t = append(t, p)
		s = s[open+end+1:]
	}
	for _, p := range t {
		if p.src == varLit && !idChars(p.lit) {
			return nil, fmt.Errorf("%q is not made of object ID characters (letters, digits and _-=.+/|)", p.lit)
		}
	}
	return t, nil
}

func variable(v string) (varPart, error) {
	switch v {
	case "owner":
		return varPart{src: varOwner}, nil
	case "agent":
		return varPart{src: varAgent}, nil
	}
	if rest, ok := strings.CutPrefix(v, "args."); ok {
		path := strings.Split(rest, ".")
		if len(path) > MaxArgPathDepth {
			return varPart{}, fmt.Errorf("{%s}: at most %d names after args", v, MaxArgPathDepth)
		}
		for _, n := range path {
			if n == "" {
				return varPart{}, fmt.Errorf("{%s}: an argument name is empty", v)
			}
		}
		return varPart{src: varArg, path: path}, nil
	}
	return varPart{}, fmt.Errorf("unknown variable {%s}: use {owner}, {agent} or {args.<name>}", v)
}

// validName is the engine's rule for type, relation and permission names.
func validName(s string) bool {
	if s == "" || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// idChars reports whether s is made of the characters of an object ID.
func idChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_-=.+/|", c) >= 0) {
			return false
		}
	}
	return true
}

// argValue walks the arguments to a string or integer value.
func argValue(args any, path []string) (string, bool) {
	v := args
	for _, n := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return "", false
		}
		if v, ok = m[n]; !ok {
			return "", false
		}
	}
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return strconv.FormatInt(i, 10), true
		}
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			return strconv.FormatInt(int64(x), 10), true
		}
	}
	return "", false
}

func (p varPart) value(s Subject, args any) (string, error) {
	switch p.src {
	case varOwner:
		if s.Owner == "" {
			return "", errors.New("the agent has no owner")
		}
		return s.Owner, nil
	case varAgent:
		return s.AgentID, nil
	case varArg:
		v, ok := argValue(args, p.path)
		if !ok || v == "" {
			return "", fmt.Errorf("argument %s is missing or not a string or integer", strings.Join(p.path, "."))
		}
		return v, nil
	}
	return p.lit, nil
}

func (t idTemplate) fill(s Subject, args any) (string, error) {
	if len(t) == 1 {
		return t[0].value(s, args)
	}
	var b strings.Builder
	for _, p := range t {
		v, err := p.value(s, args)
		if err != nil {
			return "", err
		}
		b.WriteString(v)
	}
	return b.String(), nil
}

// build fills the check in for a call.
func (c *compiledCheck) build(s Subject, args any) (engine.CheckRequest, error) {
	req := engine.CheckRequest{ResourceType: c.resType, Permission: c.permission,
		Subject: store.Subject{Type: c.subType, Relation: c.subRel}}
	resID, resErr := c.resID.fill(s, args)
	subID, subErr := c.subID.fill(s, args)
	req.ResourceID, req.Subject.ID = resID, subID
	switch {
	case resErr != nil:
		return req, fmt.Errorf("resource: %w", resErr)
	case !store.ValidID(resID):
		return req, fmt.Errorf("resource id %q is not a valid object id", resID)
	case subErr != nil:
		return req, fmt.Errorf("subject: %w", subErr)
	case !store.ValidID(subID):
		// "*" is refused too: it is the wildcard, not a subject.
		return req, fmt.Errorf("subject id %q is not a valid object id", subID)
	}
	return req, nil
}

// checker asks one call's checks, each distinct request once.
type checker struct {
	ctx    context.Context
	get    CheckEngine
	eng    Checker
	engErr error // why there is no engine, when eng is nil
	seen   map[checkKey]CheckTrace
	traces []CheckTrace
}

type checkKey struct {
	resType, resID, perm, subType, subID, subRel string
}

func (k *checker) run(r *Rule, s Subject, args any) CheckTrace {
	req, err := r.check.build(s, args)
	if err != nil {
		t := CheckTrace{RuleID: r.ID, Request: req, Outcome: CheckBadInput, Err: err}
		k.traces = append(k.traces, t)
		return t
	}
	key := checkKey{req.ResourceType, req.ResourceID, req.Permission, req.Subject.Type, req.Subject.ID, req.Subject.Relation}
	if t, ok := k.seen[key]; ok {
		t.RuleID, t.Cached = r.ID, true
		k.traces = append(k.traces, t)
		return t
	}
	t := CheckTrace{RuleID: r.ID, Request: req}
	k.ensure()
	switch {
	case k.eng == nil:
		t.Outcome, t.Err = CheckUnavailable, k.engErr
		if t.Err == nil {
			t.Err = errors.New("no authorization engine in this process")
		}
	default:
		res, err := k.eng.Check(k.ctx, req)
		switch {
		case err != nil:
			t.Outcome, t.Err = CheckUnavailable, err
		case res.Allowed:
			t.Outcome, t.Result = CheckAllowed, res
		case len(res.Missing) > 0:
			t.Outcome, t.Result = CheckConditional, res
		default:
			t.Outcome, t.Result = CheckDenied, res
		}
	}
	if k.seen == nil {
		k.seen = map[checkKey]CheckTrace{}
	}
	k.seen[key] = t
	k.traces = append(k.traces, t)
	return t
}

// HasChecks reports whether any rule asks the engine.
func (p *Policy) HasChecks() bool { return p.checks }

// CheckEngine is how Decide gets an engine: called at most once per call,
// and only when the call reaches a rule with a check.
type CheckEngine func(ctx context.Context) (Checker, error)

func (k *checker) ensure() {
	if k.eng != nil || k.engErr != nil {
		return
	}
	get := k.get
	if get == nil {
		k.engErr = errors.New("no authorization engine in this process: run authz run with its serve part")
		return
	}
	k.eng, k.engErr = get(k.ctx)
	if k.eng == nil && k.engErr == nil {
		k.engErr = errors.New("no authorization engine in this process")
	}
}
