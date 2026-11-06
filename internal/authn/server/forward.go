package server

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/authn/session"
	"github.com/laiwf94/authz/internal/platform/audit"
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

// isNavigation guesses whether the original request came from a browser
// page load (which can follow a redirect to a login page) rather than an
// API call or a script.
func isNavigation(r *http.Request) bool {
	method := r.Header.Get("X-Forwarded-Method")
	if method == "" {
		method = r.Method
	}
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
	sess, err := s.currentSession(r, rt)
	if err != nil {
		s.decision("unauthenticated")
		rd := ""
		if orig != nil {
			rd, _ = rt.redirects.Validate(orig.String())
		}
		login := loginURL(rt, a.id, rd, "")
		w.Header().Set(HeaderRedirect, login)
		if redirect && isNavigation(r) {
			http.Redirect(w, r, login, http.StatusFound)
			return
		}
		w.Header().Set("WWW-Authenticate", `Cookie realm="wicket"`)
		writeError(w, r, http.StatusUnauthorized, "unauthenticated", "sign in at the URL in the X-Auth-Redirect header")
		return
	}
	if ok, reason := a.policy.Evaluate(sess.Identity); !ok {
		s.decision("forbidden")
		s.audit(r.Context(), audit.Envelope{Actor: sess.Identity.Subject, Subject: "app:" + a.id, Action: "access", Decision: audit.Deny},
			audit.AccessDenied{Reason: reason, App: a.id, Provider: sess.Identity.Provider, Session: sess.ID},
			slog.String("reason", reason), slog.String("app", a.id),
			slog.String("provider", sess.Identity.Provider), slog.String("sub", sess.Identity.Subject),
			slog.String("session", sess.ID))
		if isNavigation(r) {
			renderPage(w, http.StatusForbidden, "forbidden", map[string]any{"Title": "No access", "User": displayUser(sess),
				"LogoutURL": rt.cfg.PublicURL + "/logout", "CSRF": s.keys.Seal(purposeLogout, []byte(sess.ID)),
				"RequestID": requestIDFrom(r.Context())})
			return
		}
		writeError(w, r, http.StatusForbidden, "permission_denied", "this account may not use this application")
		return
	}
	tok, err := s.upstreamToken(rt, sess, a.id)
	if err != nil {
		s.log.Error("signing upstream token", "request_id", requestIDFrom(r.Context()), "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.decision("allowed")
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
	w.WriteHeader(http.StatusOK)
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
	s.tokenMu.Lock()
	if t, ok := s.tokens[key]; ok && now.Before(t.refresh) {
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
	tok, err := s.signers[0].Sign(upstreamClaims{Issuer: rt.cfg.PublicURL, Audience: appID, Subject: id.Subject,
		Email: id.Email, Name: id.Name, Groups: id.Groups, Provider: id.Provider, SessionID: sess.ID,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: exp.Unix()})
	if err != nil {
		return "", err
	}
	s.tokenMu.Lock()
	if len(s.tokens) >= maxTokenCache {
		clear(s.tokens)
	}
	s.tokens[key] = cachedToken{value: tok, refresh: now.Add(exp.Sub(now) / 2)}
	s.tokenMu.Unlock()
	return tok, nil
}
