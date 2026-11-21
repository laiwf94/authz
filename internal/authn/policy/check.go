package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
)

// CheckRule makes a path rule ask the authorization engine: the request
// is allowed when Subject has Permission on Resource. Resource and Subject
// are "type:id" (Subject may add "#relation", a userset), and their IDs
// are templates: literal text and {variables}, filled in per request from
//
//   - {path.<name>}: the value of the rule's {name} path parameter;
//   - {claims.sub} and {claims.idp}: the signed-in user's subject and
//     identity provider, the sub and idp claims of the gateway's upstream
//     token.
//
// A filled-in ID must be a valid object ID (at most 128 of the letters,
// digits and _-=.+/|); a request whose values make an invalid one is
// denied without asking. Subject defaults to "user:{claims.sub}". A check rule may also list who
// (AnyUser, Emails, EmailDomains, Groups); then the user must be one of
// them as well, and the engine is asked only for those who are.
type CheckRule struct {
	Resource   string
	Permission string
	Subject    string
}

// DefaultCheckSubject is a CheckRule's Subject when it names none.
const DefaultCheckSubject = "user:{claims.sub}"

// Reason codes of relationship rules.
const (
	// CheckRequired is Evaluate's answer for a relationship rule whose
	// prerequisites hold: only Authorize, which asks the engine, decides.
	CheckRequired = "check_required"
	// DeniedCheck: the engine answered that the subject lacks the
	// permission.
	DeniedCheck = "check_denied"
	// DeniedCheckConditional: the answer depends on caveat parameters no
	// one supplied, which is not an allow.
	DeniedCheckConditional = "check_conditional"
	// DeniedCheckInput: a path value or claim the check needs is missing
	// or is not a valid object ID, so there is nothing to ask.
	DeniedCheckInput = "check_bad_input"
	// CheckUnavailable: the engine could not answer (it is not running in
	// this process, or it failed). The request is refused, but as an
	// outage rather than a denial.
	CheckUnavailable = "check_unavailable"
)

// MaxTokenBytes bounds a consistency token Authorize sends; a longer one
// is ignored as if there were none.
const MaxTokenBytes = 512

// Checker answers permission checks; engine.Engine is one.
type Checker interface {
	Check(ctx context.Context, req engine.CheckRequest) (engine.CheckResult, error)
}

// Decision is Authorize's answer.
type Decision struct {
	Allowed bool
	Reason  string
	// Check is set when a relationship rule was reached: what was asked
	// and what the engine said.
	Check *CheckTrace
	// StepUp is the rule's requirement when the sign-in did not satisfy
	// it (Reason StepUpMaxAge or StepUpACR, or StepUpLoop).
	StepUp *StepUp
}

// CheckTrace records one relationship check.
type CheckTrace struct {
	// Request is the check sent (or that would have been sent, when the
	// engine was unavailable). Its Consistency is that of the last
	// attempt.
	Request engine.CheckRequest
	// Result is the engine's answer; At is the snapshot it read, whose
	// token the caller keeps in the session for the next check.
	Result engine.CheckResult
	// Err is the engine's error when it could not answer, or why the
	// request could not be built (DeniedCheckInput).
	Err error
	// Retried says the session's token was refused (another key, or a
	// newer revision than the store has) and the check was asked again
	// fully consistent.
	Retried bool
}

type tmplSource uint8

const (
	srcLit tmplSource = iota
	srcParam
	srcSub
	srcIdP
)

type tmplPart struct {
	src   tmplSource
	lit   string // srcLit
	param int    // srcParam: index into the rule's params
}

// template is an object ID with {variables}.
type template []tmplPart

type compiledCheck struct {
	resType    string
	resID      template
	permission string
	subType    string
	subID      template
	subRel     string
}

// compileCheck checks a CheckRule against the parameters of its pattern.
func compileCheck(c *CheckRule, params []string) (*compiledCheck, error) {
	cc := &compiledCheck{permission: c.Permission}
	var err error
	if c.Resource == "" {
		return nil, errors.New("check.resource is required, as type:id")
	}
	if cc.resType, cc.resID, _, err = compileObject("check.resource", c.Resource, params, false); err != nil {
		return nil, err
	}
	if !validName(c.Permission) {
		return nil, fmt.Errorf("check.permission %q must be a relation or permission name: a lower-case letter, then lower-case letters, digits or '_', at most 64", c.Permission)
	}
	sub := c.Subject
	if sub == "" {
		sub = DefaultCheckSubject
	}
	if cc.subType, cc.subID, cc.subRel, err = compileObject("check.subject", sub, params, true); err != nil {
		return nil, err
	}
	return cc, nil
}

// compileObject splits "type:id" (with "#relation" when rel is allowed)
// and compiles the ID template.
func compileObject(field, s string, params []string, rel bool) (string, template, string, error) {
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
	t, err := compileTemplate(id, params)
	if err != nil {
		return "", nil, "", fmt.Errorf("%s %q: %v", field, s, err)
	}
	return typ, t, relation, nil
}

func compileTemplate(s string, params []string) (template, error) {
	if s == "" {
		return nil, errors.New("the id is empty")
	}
	var t template
	for s != "" {
		open := strings.IndexByte(s, '{')
		if cl := strings.IndexByte(s, '}'); cl >= 0 && (open < 0 || cl < open) {
			return nil, errors.New("'}' without '{'")
		}
		if open < 0 {
			t = append(t, tmplPart{lit: s})
			break
		}
		if open > 0 {
			t = append(t, tmplPart{lit: s[:open]})
		}
		end := strings.IndexByte(s[open:], '}')
		if end < 0 {
			return nil, errors.New("'{' without '}'")
		}
		v := s[open+1 : open+end]
		s = s[open+end+1:]
		p, err := variable(v, params)
		if err != nil {
			return nil, err
		}
		t = append(t, p)
	}
	for _, p := range t {
		if p.src == srcLit && !idChars(p.lit) {
			return nil, fmt.Errorf("%q is not made of object ID characters (letters, digits and _-=.+/|)", p.lit)
		}
	}
	return t, nil
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

func variable(v string, params []string) (tmplPart, error) {
	switch v {
	case "claims.sub":
		return tmplPart{src: srcSub}, nil
	case "claims.idp":
		return tmplPart{src: srcIdP}, nil
	}
	if name, ok := strings.CutPrefix(v, "path."); ok {
		for i, p := range params {
			if p == name {
				return tmplPart{src: srcParam, param: i}, nil
			}
		}
		return tmplPart{}, fmt.Errorf("{%s}: the rule's path has no {%s} parameter", v, name)
	}
	return tmplPart{}, fmt.Errorf("unknown variable {%s}: use {path.<parameter>}, {claims.sub} or {claims.idp}", v)
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

// fill builds an ID from the template; ok is false when a value is empty.
func (t template) fill(m *Match, id *Identity) (string, bool) {
	if len(t) == 1 {
		v := t[0].value(m, id)
		return v, v != ""
	}
	var b strings.Builder
	for _, p := range t {
		v := p.value(m, id)
		if v == "" && p.src != srcLit {
			return "", false
		}
		b.WriteString(v)
	}
	return b.String(), true
}

func (p tmplPart) value(m *Match, id *Identity) string {
	switch p.src {
	case srcParam:
		if p.param < m.NParams {
			return m.Params[p.param]
		}
		return ""
	case srcSub:
		return id.Subject
	case srcIdP:
		return id.Provider
	}
	return p.lit
}

// build turns a matched request and identity into a check request.
func (c *compiledCheck) build(m *Match, id *Identity) (engine.CheckRequest, error) {
	req := engine.CheckRequest{ResourceType: c.resType, Permission: c.permission,
		Subject: store.Subject{Type: c.subType, Relation: c.subRel}}
	var resOK, subOK bool
	req.ResourceID, resOK = c.resID.fill(m, id)
	req.Subject.ID, subOK = c.subID.fill(m, id)
	switch {
	case !resOK:
		return req, errors.New("the resource id has an empty value")
	case !store.ValidID(req.ResourceID):
		return req, fmt.Errorf("resource id %q is not a valid object id", req.ResourceID)
	case !subOK:
		return req, errors.New("the subject id has an empty value")
	case !store.ValidID(req.Subject.ID):
		// A claim or path value of "*" is refused too: it is not a
		// subject but the wildcard.
		return req, fmt.Errorf("subject id %q is not a valid object id", req.Subject.ID)
	}
	return req, nil
}

// HasChecks says whether any path rule asks the engine.
func (p *Policy) HasChecks() bool {
	for i := range p.rules {
		if p.rules[i].check != nil {
			return true
		}
	}
	return false
}

// CheckFor returns the check a relationship rule would send for a matched
// request and identity, with ok false when the matched rule is not one.
func (p *Policy) CheckFor(m *Match, id *Identity) (req engine.CheckRequest, ok bool, err error) {
	if m.Rule < 0 || p.rules[m.Rule].check == nil {
		return req, false, nil
	}
	req, err = p.rules[m.Rule].check.build(m, id)
	return req, true, err
}

// Authorize decides a matched request completely: Evaluate, then for a
// relationship rule a check of eng. tok is the consistency token the
// session keeps from its previous check ("" for none): the check reads a
// snapshot at least as fresh, so a session never sees an older state than
// it already saw. A token the engine refuses is dropped and the check
// asked fully consistent instead. eng may be nil when there is no engine;
// a relationship rule then answers CheckUnavailable.
func (p *Policy) Authorize(ctx context.Context, m *Match, id *Identity, eng Checker, tok string) Decision {
	ok, reason := p.Evaluate(m, id)
	if reason != CheckRequired {
		return Decision{Allowed: ok, Reason: reason}
	}
	req, _, err := p.CheckFor(m, id)
	tr := &CheckTrace{Request: req}
	d := Decision{Check: tr}
	if err != nil {
		tr.Err = err
		d.Reason = DeniedCheckInput
		return d
	}
	if eng == nil {
		tr.Err = errors.New("no authorization engine in this process")
		d.Reason = CheckUnavailable
		return d
	}
	if tok != "" && len(tok) <= MaxTokenBytes {
		tr.Request.Consistency = engine.Consistency{Mode: engine.AtLeastAsFresh, Token: tok}
	}
	res, err := eng.Check(ctx, tr.Request)
	if err != nil && tr.Request.Consistency.Token != "" &&
		(errors.Is(err, token.ErrInvalid) || errors.Is(err, engine.ErrInvalidArgument)) {
		tr.Retried = true
		tr.Request.Consistency = engine.Consistency{Mode: engine.FullyConsistent}
		res, err = eng.Check(ctx, tr.Request)
	}
	if err != nil {
		tr.Err = err
		d.Reason = CheckUnavailable
		return d
	}
	tr.Result = res
	switch {
	case res.Allowed:
		d.Allowed, d.Reason = true, Allowed
	case len(res.Missing) > 0:
		d.Reason = DeniedCheckConditional
	default:
		d.Reason = DeniedCheck
	}
	return d
}
