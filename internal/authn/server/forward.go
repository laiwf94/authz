package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/authn/policy"
	"github.com/laiwf94/authz/internal/authn/session"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/logging"
)

// Identity headers sent to the proxy on success. The proxy copies them to
// the upstream request; it must also strip any copies the client sent.
const (
	HeaderUser     = "X-Auth-User"
	HeaderEmail    = "X-Auth-Email"
	HeaderGroups   = "X-Auth-Groups"
	HeaderProvider = "X-Auth-Provider"
	HeaderToken    = "X-Auth-Token"
	HeaderRedirect = "X-Auth-Redirect"
)

// handleAuth is the forward-auth endpoint for nginx auth_request and
// Traefik ForwardAuth. The original request is described by
// X-Original-URL, or X-Forwarded-Proto/-Host/-Uri; X-Forwarded-Method gives
// its method. The app comes from ?app= or from the original host.
//
// Responses: 200 with identity headers; 401 when not signed in (with
// X-Auth-Redirect naming the login URL, or a 302 to it when ?redirect=1 and
// the request is a browser navigation); 403 when signed in but not allowed.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	orig := originalURL(r)
	s.forwardAuth(w, r, orig, r.URL.Query().Get("app"), r.URL.Query().Get("redirect") == "1")
}

// handleEnvoyAuth is the endpoint for Envoy's HTTP ext_authz service with
// path_prefix "/auth/envoy": Envoy appends the original path and keeps the
// original Host header. Denied responses are passed to the client, so
// browsers get a redirect directly.
func (s *Server) handleEnvoyAuth(w http.ResponseWriter, r *http.Request) {
	u := &url.URL{Scheme: "https", Host: r.Host, Path: strings.TrimPrefix(r.URL.Path, "/auth/envoy"), RawQuery: r.URL.RawQuery}
	if u.Path == "" {
		u.Path = "/"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p == "http" {
		u.Scheme = "http"
	}
	s.forwardAuth(w, r, u, "", true)
}

// originalURL reconstructs the URL the client asked the proxy for.
func originalURL(r *http.Request) *url.URL {
	if v := r.Header.Get("X-Original-URL"); v != "" {
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			return u
		}
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto != "http" {
		proto = "https"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		return nil
	}
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" || uri[0] != '/' {
		uri = "/"
	}
	u, err := url.Parse(proto + "://" + host + uri)
	if err != nil {
		return nil
	}
	return u
}

// originalMethod is the method of the original request: X-Forwarded-Method
// (Traefik), X-Original-Method (nginx, when the location sets it), or the
// method of the auth request itself (Envoy, and nginx by default).
func originalMethod(r *http.Request) string {
	if m := r.Header.Get("X-Forwarded-Method"); m != "" {
		return m
	}
	if m := r.Header.Get("X-Original-Method"); m != "" {
		return m
	}
	return r.Method
}

// isNavigation guesses whether the original request came from a browser
// page load (which can follow a redirect to a login page) rather than an
// API call or a script.
func isNavigation(r *http.Request) bool {
	method := originalMethod(r)
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	if r.Header.Get("X-Requested-With") != "" {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func (s *Server) forwardAuth(w http.ResponseWriter, r *http.Request, orig *url.URL, appID string, redirect bool) {
	rt := s.rt.Load()
	host := ""
	if orig != nil {
		host = orig.Host
	}
	a := rt.appFor(appID, host)
	if a == nil {
		// Misconfiguration or a probe: deny by default.
		s.decision("forbidden")
		h := printableASCII(host, 128)
		s.audit(r.Context(), audit.Envelope{Subject: "host:" + h, Action: "access", Decision: audit.Deny},
			audit.AccessDenied{Reason: "unknown_app", Host: h},
			slog.String("reason", "unknown_app"), slog.String("host", h))
		writeError(w, r, http.StatusForbidden, "permission_denied", "no application is configured for this host")
		return
	}
	path := ""
	if orig != nil {
		path = orig.EscapedPath()
	}
	m := a.policy.Match(originalMethod(r), path)
	if m.Bad {
		s.decision("forbidden")
		s.audit(r.Context(), audit.Envelope{Subject: "app:" + a.id, Action: "access", Decision: audit.Deny},
			audit.AccessDenied{Reason: policy.DeniedBadPath, App: a.id},
			slog.String("reason", policy.DeniedBadPath), slog.String("app", a.id),
			slog.String("path", printableASCII(path, 256)))
		writeError(w, r, http.StatusForbidden, "permission_denied", "the request path is ambiguous")
		return
	}
	sess, err := s.currentSession(r, rt)
	if m.Public {
		// Anyone may open a public path. A signed-in user's identity is
		// still passed on, so a public page can greet them.
		s.decision("public")
		if err != nil || !slices.Contains(a.providers, sess.Identity.Provider) {
			w.WriteHeader(http.StatusOK)
			return
		}
	} else if err != nil {
		s.decision("unauthenticated")
		rd := ""
		if orig != nil {
			rd, _ = rt.redirects.Validate(orig.String())
		}
		// A step-up path asks for its requirement at the first sign-in
		// too, so one login is enough.
		stepRule := ""
		if a.policy.StepUp(&m) != nil {
			stepRule = a.policy.RuleName(m.Rule)
		}
		login := stepUpLoginURL(rt, a.id, rd, "", stepRule)
		w.Header().Set(HeaderRedirect, login)
		if redirect && isNavigation(r) {
			http.Redirect(w, r, login, http.StatusFound)
			return
		}
		w.Header().Set("WWW-Authenticate", `Cookie realm="wicket"`)
		writeError(w, r, http.StatusUnauthorized, "unauthenticated", "sign in at the URL in the X-Auth-Redirect header")
		return
	} else if d := s.authorize(r.Context(), a, &m, sess); !d.Allowed {
		reason := d.Reason
		attrs := []slog.Attr{slog.String("reason", reason), slog.String("app", a.id),
			slog.String("provider", sess.Identity.Provider), slog.String("sub", sess.Identity.Subject),
			slog.String("session", sess.ID)}
		if m.Rule >= 0 {
			attrs = append(attrs, slog.String("rule", a.policy.RuleName(m.Rule)))
		}
		if c := d.Check; c != nil {
			attrs = append(attrs, slog.String("check", checkText(c)))
			if c.Err != nil {
				attrs = append(attrs, slog.String("error", c.Err.Error()))
			}
		}
		if policy.IsStepUp(reason) {
			s.stepUp(w, r, rt, a, &m, sess, orig, redirect, d.StepUp, reason, attrs)
			return
		}
		if reason == policy.CheckUnavailable {
			// An outage, not a denial: the engine could not answer.
			s.decision("unavailable")
			s.log.LogAttrs(r.Context(), slog.LevelError, "relationship check failed", append(attrs,
				slog.String("request_id", requestIDFrom(r.Context())))...)
			writeError(w, r, http.StatusServiceUnavailable, "unavailable", "the access check could not be made; try again")
			return
		}
		s.decision("forbidden")
		s.audit(r.Context(), audit.Envelope{Actor: sess.Identity.Subject, Subject: "app:" + a.id, Action: "access", Decision: audit.Deny},
			audit.AccessDenied{Reason: reason, App: a.id, Provider: sess.Identity.Provider, Session: sess.ID},
			attrs...)
		if isNavigation(r) {
			renderPage(w, http.StatusForbidden, "forbidden", map[string]any{"Title": "No access", "User": displayUser(sess),
				"LogoutURL": rt.cfg.PublicURL + "/logout", "CSRF": s.keys.Seal(purposeLogout, []byte(sess.ID)),
				"RequestID": requestIDFrom(r.Context())})
			return
		}
		msg := "this account may not use this application"
		if reason == policy.StepUpLoop {
			msg = "the identity provider did not give the sign-in this page needs"
		}
		writeError(w, r, http.StatusForbidden, "permission_denied", msg)
		return
	}
	tok, err := s.upstreamToken(rt, sess, a.id)
	if err != nil {
		s.log.ErrorContext(r.Context(), "signing upstream token", "request_id", requestIDFrom(r.Context()), "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if !m.Public {
		s.decision("allowed")
	}
	h := w.Header()
	h.Set(HeaderUser, headerValue(sess.Identity.Subject))
	h.Set(HeaderEmail, headerValue(sess.Identity.Email))
	groups := make([]string, len(sess.Identity.Groups))
	for i, g := range sess.Identity.Groups {
		groups[i] = headerValue(g)
	}
	h.Set(HeaderGroups, strings.Join(groups, ","))
	h.Set(HeaderProvider, sess.Identity.Provider)
	h.Set(HeaderToken, tok)
	// A proxy that traces sent a traceparent; answer with one for it to copy
	// upstream with the identity headers, carrying the same trace ID with
	// the gateway's own parent ID. Without one the response is unchanged,
	// as wicket wrote it.
	if _, ok := logging.ParseTraceparent(r.Header.Get(logging.HeaderTraceparent)); ok {
		logging.Propagate(r.Context(), h)
	}
	w.WriteHeader(http.StatusOK)
}

// authorize decides a signed-in request: the path rule, then the rule's
// step-up requirement, and for a relationship rule a check of the
// in-process engine at least as fresh as the session's previous one. The
// snapshot the check read is kept in the session for the next. A user the
// rule refuses is refused before any step-up, and a user who must step up
// is sent to do so before the engine is asked.
func (s *Server) authorize(ctx context.Context, a *app, m *policy.Match, sess *session.Session) policy.Decision {
	ok, reason := a.policy.Evaluate(m, &sess.Identity)
	if !ok && reason != policy.CheckRequired {
		return policy.Decision{Allowed: false, Reason: reason}
	}
	if su := a.policy.StepUp(m); su != nil {
		if fresh, why := su.Satisfied(sess.Auth(), s.now()); !fresh {
			if sess.StepUp() == a.policy.RuleName(m.Rule) && su.IsStepUpLoop(sess.Auth(), sess.CreatedAt, s.now()) {
				why = policy.StepUpLoop
			}
			return policy.Decision{Reason: why, StepUp: su}
		}
	}
	if reason != policy.CheckRequired {
		return policy.Decision{Allowed: ok, Reason: reason}
	}
	var eng policy.Checker
	var engErr error
	if s.opts.Engine == nil {
		engErr = errors.New("no authorization engine: run the gateway under authz run with its serve part")
	} else if e, err := s.opts.Engine(ctx); err != nil {
		engErr = err
	} else {
		eng = e
	}
	d := a.policy.Authorize(ctx, m, &sess.Identity, eng, sess.ConsistencyToken())
	if c := d.Check; c != nil {
		if engErr != nil && d.Reason == policy.CheckUnavailable {
			c.Err = engErr
		}
		if c.Err == nil {
			s.sessions.SetConsistency(sess.ID, uint64(c.Result.At.Revision), c.Result.At.Token)
		}
		s.m.Counter("wicket_relationship_checks_total", `result="`+d.Reason+`"`, "Relationship checks made by path rules, by result.").Inc()
	}
	return d
}

// stepUp answers a signed-in request whose sign-in is too old or too weak
// for its rule: the user is sent to sign in again with the same provider,
// asking for the rule's max_age and acr_values, and returned to the
// original URL (its path and query; a request body cannot be replayed, so
// a non-GET request gets the challenge and the client decides). A browser
// navigation with ?redirect=1 is redirected; anything else gets 401 with
// an insufficient_user_authentication challenge (RFC 9470) and the login
// URL in X-Auth-Redirect.
func (s *Server) stepUp(w http.ResponseWriter, r *http.Request, rt *runtime, a *app, m *policy.Match, sess *session.Session,
	orig *url.URL, redirect bool, su *policy.StepUp, reason string, attrs []slog.Attr) {
	s.decision("step_up")
	s.m.Counter("wicket_step_ups_total", `reason="`+reason+`"`, "Requests sent to sign in again for a path rule's step-up, by reason.").Inc()
	attrs = append(attrs, slog.String("request_id", requestIDFrom(r.Context())))
	if au := sess.Auth(); !au.Time.IsZero() {
		attrs = append(attrs, slog.Time("auth_time", au.Time))
	}
	if acr := sess.Auth().ACR; acr != "" {
		attrs = append(attrs, slog.String("acr", acr))
	}
	s.log.LogAttrs(r.Context(), slog.LevelInfo, "step-up required", attrs...)
	rd := ""
	if orig != nil {
		rd, _ = rt.redirects.Validate(orig.String())
	}
	login := stepUpLoginURL(rt, a.id, rd, sess.Identity.Provider, a.policy.RuleName(m.Rule))
	w.Header().Set(HeaderRedirect, login)
	if redirect && isNavigation(r) {
		http.Redirect(w, r, login, http.StatusFound)
		return
	}
	w.Header().Set("WWW-Authenticate", `Cookie realm="wicket", error="insufficient_user_authentication", `+
		`error_description="a more recent or stronger sign-in is required", `+su.Challenge())
	writeError(w, r, http.StatusUnauthorized, "step_up_required", "sign in again at the URL in the X-Auth-Redirect header")
}

// checkText is a check for logs: resource#permission@subject.
func checkText(c *policy.CheckTrace) string {
	q := c.Request
	return q.ResourceType + ":" + q.ResourceID + "#" + q.Permission + "@" + q.Subject.String()
}

func (s *Server) decision(d string) {
	s.m.Counter("wicket_auth_decisions_total", `decision="`+d+`"`, "Forward-auth decisions.").Inc()
}

func displayUser(sess *session.Session) string {
	if sess.Identity.Email != "" {
		return sess.Identity.Email
	}
	return sess.Identity.Subject
}

// headerValue percent-encodes everything outside printable ASCII, and '%'
// and ',' (the group separator), so a value can never break a header or the
// group list. Upstreams decode with any URL-unescape function.
func headerValue(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f || c == '%' || c == ',' {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// upstreamClaims is the JWT given to upstreams, so they can verify the
// identity instead of trusting headers.
type upstreamClaims struct {
	Issuer    string   `json:"iss"`
	Audience  string   `json:"aud"`
	Subject   string   `json:"sub"`
	Email     string   `json:"email,omitempty"`
	Name      string   `json:"name,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	Provider  string   `json:"idp"`
	SessionID string   `json:"sid"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	Expiry    int64    `json:"exp"`
}

// upstreamToken returns a short-lived ES256 token for this session and app,
// reusing one until half its lifetime has passed.
func (s *Server) upstreamToken(rt *runtime, sess *session.Session, appID string) (string, error) {
	key := sess.ID + "\x00" + appID
	now := s.now()
	sg := s.upstreamKeys().signer
	s.tokenMu.Lock()
	if t, ok := s.tokens[key]; ok && now.Before(t.refresh) && t.signer == sg {
		s.tokenMu.Unlock()
		return t.value, nil
	}
	s.tokenMu.Unlock()
	ttl := time.Duration(rt.cfg.UpstreamTokenTTL)
	exp := now.Add(ttl)
	if sess.ExpiresAt.Before(exp) {
		exp = sess.ExpiresAt
	}
	id := sess.Identity
	tok, err := sg.Sign(upstreamClaims{Issuer: rt.cfg.PublicURL, Audience: appID, Subject: id.Subject,
		Email: id.Email, Name: id.Name, Groups: id.Groups, Provider: id.Provider, SessionID: sess.ID,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: exp.Unix()})
	if err != nil {
		return "", err
	}
	s.tokenMu.Lock()
	if len(s.tokens) >= maxTokenCache {
		clear(s.tokens)
	}
	s.tokens[key] = cachedToken{value: tok, refresh: now.Add(exp.Sub(now) / 2), signer: sg}
	s.tokenMu.Unlock()
	return tok, nil
}
