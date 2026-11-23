package server

import (
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/laiwf94/authz/internal/authn/policy"
	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/engine"
)

// Limits of POST /admin/explain.
const (
	// MaxExplainTraceNodes bounds the check trace one explanation returns;
	// DefaultExplainTraceNodes is used when the request names none.
	MaxExplainTraceNodes     = 10_000
	DefaultExplainTraceNodes = check.DefaultTraceNodes
	maxExplainURL            = 4096
	maxExplainGroups         = 256
)

// explainRequest is a synthetic forward-auth request: the original URL and
// method, and who asks: a live session, an identity, or nobody.
type explainRequest struct {
	// App names the app; without it the URL's host chooses, as for
	// forward-auth.
	App    string `json:"app"`
	URL    string `json:"url"`
	Method string `json:"method"`
	// Session is a live session's ID: its identity, sign-in and
	// consistency token are used.
	Session string `json:"session"`
	// Identity is a signed-in user that need not exist, and Auth how they
	// signed in, for step-up rules.
	Identity *policy.Identity `json:"identity"`
	Auth     *struct {
		Time *time.Time `json:"time"`
		ACR  string     `json:"acr"`
	} `json:"auth"`
	TraceNodes int `json:"trace_nodes"`
}

// explainResponse says what forward-auth would answer and why.
type explainResponse struct {
	App string `json:"app,omitempty"`
	// Method and Path are what the rules were matched against.
	Method string `json:"method"`
	Path   string `json:"path,omitempty"`
	// Status is forward-auth's status code: 200, 401, 403 or 503.
	// Decision is the wicket_auth_decisions_total label it counts under,
	// and Reason the reason code it logs and audits.
	Status   int    `json:"status"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	// Rule names the rule that decided; Rules is every rule whose
	// pattern matches the path, in the order they are tried (see
	// policy.Candidates), ending with the app-wide rule.
	Rule     string             `json:"rule,omitempty"`
	Rules    []policy.Candidate `json:"rules"`
	Session  string             `json:"session,omitempty"`
	Identity *policy.Identity   `json:"identity,omitempty"`
	// LoginURL is where the user is sent to sign in, for a 401.
	LoginURL string         `json:"login_url,omitempty"`
	StepUp   *explainStepUp `json:"step_up,omitempty"`
	Check    *explainCheck  `json:"check,omitempty"`
}

// explainStepUp is the deciding rule's step-up requirement and whether the
// sign-in meets it.
type explainStepUp struct {
	MaxAge    int64      `json:"max_age,omitempty"` // seconds
	ACRValues []string   `json:"acr_values,omitempty"`
	AuthTime  *time.Time `json:"auth_time,omitempty"`
	ACR       string     `json:"acr,omitempty"`
	Satisfied bool       `json:"satisfied"`
}

// explainCheck is the relationship check a rule made, with the engine's
// trace when it can explain.
type explainCheck struct {
	Resource    string   `json:"resource"`
	Permission  string   `json:"permission"`
	Subject     string   `json:"subject"`
	Consistency string   `json:"consistency"`
	Retried     bool     `json:"retried,omitempty"`
	Result      string   `json:"result,omitempty"` // allowed, denied or conditional
	Missing     []string `json:"missing,omitempty"`
	Revision    uint64   `json:"revision,omitempty"`
	Error       string   `json:"error,omitempty"`
	Trace       *struct {
		Root      *check.TraceNode `json:"root"`
		Nodes     int              `json:"nodes"`
		Truncated bool             `json:"truncated,omitempty"`
	} `json:"trace,omitempty"`
}

// handleExplain: POST /admin/explain. It decides a synthetic request as
// forward-auth would, for a live session, an identity or nobody, and
// returns the decision with the rule chain that led to it: every rule
// whose pattern matches, the one selected, the step-up requirement and,
// when a relationship rule decided, the check with the engine's explain
// trace. Nothing changes: no session is touched, nothing is audited and
// no metric is counted.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	var req explainRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}
	orig, q, msg := s.explainInput(&req)
	if msg != "" {
		writeError(w, r, http.StatusBadRequest, "invalid_argument", msg)
		return
	}
	if req.Session != "" && q.id == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "no such live session")
		return
	}
	nodes := req.TraceNodes
	if nodes == 0 {
		nodes = DefaultExplainTraceNodes
	}
	writeJSON(w, http.StatusOK, s.explain(r, orig, req.App, req.Method, q, nodes))
}

// explainInput checks an explain request and builds who it asks for.
// A session that is not live gives a requester with no identity.
func (s *Server) explainInput(req *explainRequest) (*url.URL, requester, string) {
	var q requester
	if req.URL == "" || len(req.URL) > maxExplainURL {
		return nil, q, "url is required, at most 4096 bytes"
	}
	orig, err := url.Parse(req.URL)
	if err != nil || orig.Host == "" || (orig.Scheme != "https" && orig.Scheme != "http") {
		return nil, q, "url must be an absolute http or https URL"
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	if len(req.Method) > 16 {
		return nil, q, "method must be an upper-case HTTP method"
	}
	for i := 0; i < len(req.Method); i++ {
		if c := req.Method[i]; c < 'A' || c > 'Z' {
			return nil, q, "method must be an upper-case HTTP method"
		}
	}
	if len(req.App) > 128 {
		return nil, q, "app is too long"
	}
	if req.TraceNodes < 0 || req.TraceNodes > MaxExplainTraceNodes {
		return nil, q, "trace_nodes must be between 0 and 10000"
	}
	switch {
	case req.Session != "" && req.Identity != nil:
		return nil, q, "give a session or an identity, not both"
	case req.Auth != nil && req.Identity == nil:
		return nil, q, "auth describes an identity's sign-in; a session has its own"
	case req.Session != "":
		if !sessionIDRe.MatchString(req.Session) {
			return nil, q, "session must be 32 hex characters"
		}
		if sess, ok := s.sessions.Get(req.Session); ok {
			q = sessionRequester(sess)
		}
	case req.Identity != nil:
		id := req.Identity
		if id.Subject == "" || id.Provider == "" {
			return nil, q, "identity needs a provider and a sub"
		}
		if len(id.Subject) > 512 || len(id.Provider) > 64 || len(id.Email) > 512 || len(id.Name) > 512 ||
			len(id.Groups) > maxExplainGroups || slices.ContainsFunc(id.Groups, func(g string) bool { return len(g) > 512 }) {
			return nil, q, "identity is too large"
		}
		if err := policy.CheckClaims(id.Claims); err != nil {
			return nil, q, "identity.claims: " + err.Error()
		}
		q.id = id
		if a := req.Auth; a != nil {
			if a.ACR != "" && !policy.ValidACR(a.ACR) {
				return nil, q, "auth.acr is not a valid authentication context class"
			}
			if a.Time != nil {
				q.auth.Time = *a.Time
			}
			q.auth.ACR = a.ACR
		}
	}
	return orig, q, ""
}

// explain decides a request the way forwardAuth does and says why. Keep
// the two in step: TestExplainAgreesWithForwardAuth compares them.
func (s *Server) explain(r *http.Request, orig *url.URL, appID, method string, q requester, nodes int) *explainResponse {
	rt := s.rt.Load()
	out := &explainResponse{Method: method, Session: q.session, Identity: q.id, Rules: []policy.Candidate{}}
	a := rt.appFor(appID, orig.Host)
	if a == nil {
		out.Status, out.Decision, out.Reason = http.StatusForbidden, "forbidden", "unknown_app"
		return out
	}
	out.App = a.id
	m, cands := a.policy.CandidatesFor(method, orig.EscapedPath(), q.id)
	out.Path = m.Path
	if cands != nil {
		out.Rules = cands
	}
	if m.Bad {
		out.Status, out.Decision, out.Reason = http.StatusForbidden, "forbidden", policy.DeniedBadPath
		return out
	}
	out.Rule = a.policy.RuleName(m.Rule)
	rd, _ := rt.redirects.Validate(orig.String())
	su := a.policy.StepUp(&m)
	if su != nil {
		out.StepUp = &explainStepUp{MaxAge: max(su.MaxAgeSeconds(), 0), ACRValues: su.ACRValues}
		if q.id != nil {
			out.StepUp.Satisfied, _ = su.Satisfied(q.auth, s.now())
			if !q.auth.Time.IsZero() {
				t := q.auth.Time
				out.StepUp.AuthTime = &t
			}
			out.StepUp.ACR = q.auth.ACR
		}
	}
	switch {
	case m.Public:
		out.Status, out.Decision, out.Reason = http.StatusOK, "public", policy.AllowedPublic
		return out
	case q.id == nil:
		stepRule := ""
		if su != nil {
			stepRule = out.Rule
		}
		out.Status, out.Decision, out.Reason = http.StatusUnauthorized, "unauthenticated", policy.DeniedNoSubject
		out.LoginURL = stepUpLoginURL(rt, a.id, rd, "", stepRule)
		return out
	}
	d := s.decide(r.Context(), a, &m, q, nodes)
	out.Reason = d.Reason
	switch {
	case d.Allowed:
		out.Status, out.Decision = http.StatusOK, "allowed"
	case policy.IsStepUp(d.Reason):
		out.Status, out.Decision = http.StatusUnauthorized, "step_up"
		out.LoginURL = stepUpLoginURL(rt, a.id, rd, q.id.Provider, out.Rule)
	case d.Reason == policy.CheckUnavailable:
		out.Status, out.Decision = http.StatusServiceUnavailable, "unavailable"
	default:
		out.Status, out.Decision = http.StatusForbidden, "forbidden"
	}
	if c := d.Check; c != nil {
		out.Check = explainCheckOf(c)
	}
	return out
}

func explainCheckOf(c *policy.CheckTrace) *explainCheck {
	q := c.Request
	ec := &explainCheck{Resource: q.ResourceType + ":" + q.ResourceID, Permission: q.Permission, Subject: q.Subject.String(),
		Consistency: string(q.Consistency.Mode), Retried: c.Retried}
	if ec.Consistency == "" {
		ec.Consistency = string(engine.MinimizeLatency)
	}
	if c.Err != nil {
		ec.Error = c.Err.Error()
		return ec
	}
	switch {
	case c.Result.Allowed:
		ec.Result = "allowed"
	case len(c.Result.Missing) > 0:
		ec.Result, ec.Missing = "conditional", c.Result.Missing
	default:
		ec.Result = "denied"
	}
	ec.Revision = uint64(c.Result.At.Revision)
	if t := c.Trace; t != nil {
		ec.Trace = &struct {
			Root      *check.TraceNode `json:"root"`
			Nodes     int              `json:"nodes"`
			Truncated bool             `json:"truncated,omitempty"`
		}{t.Root, t.Nodes, t.Truncated}
	}
	return ec
}
