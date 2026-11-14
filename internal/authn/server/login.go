package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/authn/config"
	"github.com/laiwf94/authz/internal/authn/oidc"
	"github.com/laiwf94/authz/internal/authn/policy"
	"github.com/laiwf94/authz/internal/authn/saml"
	"github.com/laiwf94/authz/internal/authn/session"
	"github.com/laiwf94/authz/internal/platform/audit"
)

// callbackTimeout bounds all back-channel calls of one callback (discovery,
// token, JWKS, userinfo); the public server's write timeout is longer.
const callbackTimeout = 25 * time.Second

// maxLoginCookies bounds pending logins per browser, so a page that makes a
// browser start many logins can't fill its cookie jar and push the session
// cookie out.
const maxLoginCookies = 5

// Seal purposes: a value sealed for one use can't be opened as another.
const (
	purposeSession = "session"
	purposeLogin   = "login"
	purposeLogout  = "logout"
)

// loginState is what the browser carries, sealed, between starting a login
// and the identity provider's answer. It binds the answer to this browser:
// state (or RelayState), nonce, PKCE verifier and SAML request ID only ever
// exist here and at the provider.
type loginState struct {
	Kind      string `json:"k"`
	Provider  string `json:"p"`
	App       string `json:"a"`
	Return    string `json:"r"`
	State     string `json:"s"`
	Nonce     string `json:"n,omitempty"`
	Verifier  string `json:"v,omitempty"`
	RequestID string `json:"i,omitempty"`
	Expires   int64  `json:"e"`
}

const loginCookiePrefix = "__Host-wicket-login-"

// loginCookieName derives a per-login cookie name from the state, so several
// logins in different tabs don't overwrite each other.
func loginCookieName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return loginCookiePrefix + hex.EncodeToString(sum[:8])
}

func sessionCookieName(rt *runtime) string {
	if rt.cfg.CookieDomain == "" {
		return "__Host-wicket"
	}
	return "__Secure-wicket"
}

func (s *Server) setLoginCookie(w http.ResponseWriter, r *http.Request, st *loginState, sameSite http.SameSite) {
	var pending []string
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, loginCookiePrefix) {
			pending = append(pending, c.Name)
		}
	}
	if len(pending) >= maxLoginCookies {
		for _, name := range pending {
			clearCookie(w, name, "", http.SameSiteLaxMode)
		}
	}
	b, _ := json.Marshal(st)
	http.SetCookie(w, &http.Cookie{Name: loginCookieName(st.State), Value: s.keys.Seal(purposeLogin, b), Path: "/",
		MaxAge: int(loginTTL.Seconds()), Secure: true, HttpOnly: true, SameSite: sameSite})
}

func clearCookie(w http.ResponseWriter, name, domain string, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Domain: domain, MaxAge: -1, Secure: true,
		HttpOnly: true, SameSite: sameSite})
}

// takeLoginState opens the login cookie for state, checks that it matches,
// and marks the state used so it can complete only one login.
func (s *Server) takeLoginState(w http.ResponseWriter, r *http.Request, kind, providerID, state string, sameSite http.SameSite) (*loginState, string) {
	if state == "" || len(state) > 128 {
		return nil, "state_missing"
	}
	name := loginCookieName(state)
	c, err := r.Cookie(name)
	if err != nil {
		return nil, "state_cookie_missing"
	}
	clearCookie(w, name, "", sameSite)
	b, err := s.keys.Open(purposeLogin, c.Value)
	if err != nil {
		return nil, "state_cookie_invalid"
	}
	var st loginState
	if json.Unmarshal(b, &st) != nil {
		return nil, "state_cookie_invalid"
	}
	if subtle.ConstantTimeCompare([]byte(st.State), []byte(state)) != 1 {
		return nil, "state_mismatch"
	}
	if st.Kind != kind || st.Provider != providerID {
		return nil, "state_wrong_provider"
	}
	exp := time.Unix(st.Expires, 0)
	if !s.now().Before(exp) {
		return nil, "login_expired"
	}
	if !s.used.Claim("state\x00"+state, exp) {
		return nil, "state_replayed"
	}
	return &st, ""
}

// handleLogin starts a login: GET /login?app=ID&rd=URL[&provider=ID].
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	rt := s.rt.Load()
	q := r.URL.Query()
	a := rt.apps[q.Get("app")]
	if a == nil {
		s.errorPage(w, r, http.StatusBadRequest, "Unknown application", "This sign-in link does not name an application this gateway protects.", "")
		return
	}
	rd := a.defaultURL
	if v := q.Get("rd"); v != "" {
		var err error
		if rd, err = rt.redirects.Validate(v); err != nil {
			s.audit(r.Context(), audit.Envelope{Subject: "app:" + a.id, Action: "login", Decision: audit.Deny},
				audit.LoginRejected{Reason: "return_url_not_allowed", App: a.id},
				slog.String("reason", "return_url_not_allowed"), slog.String("app", a.id))
			s.errorPage(w, r, http.StatusBadRequest, "Return address not allowed", "The page asked to send you to an address this gateway does not protect.", "")
			return
		}
	}
	pid := q.Get("provider")
	if pid == "" && len(a.providers) == 1 {
		pid = a.providers[0]
	}
	if pid == "" {
		links := make([]providerLink, 0, len(a.providers))
		for _, id := range a.providers {
			links = append(links, providerLink{Name: rt.providers[id].display, URL: loginURL(rt, a.id, rd, id)})
		}
		renderPage(w, http.StatusOK, "choose", map[string]any{"Title": "Sign in", "Providers": links})
		return
	}
	if !contains(a.providers, pid) {
		s.errorPage(w, r, http.StatusBadRequest, "Sign-in option not available", "This application does not accept that identity provider.", loginURL(rt, a.id, rd, ""))
		return
	}
	p := rt.providers[pid]
	st := &loginState{Provider: p.id, App: a.id, Return: rd, State: oidc.RandomToken(), Expires: s.now().Add(loginTTL).Unix()}
	var target string
	var err error
	sameSite := http.SameSiteLaxMode
	switch p.kind {
	case config.ProviderOIDC:
		st.Kind, st.Nonce, st.Verifier = config.ProviderOIDC, oidc.RandomToken(), oidc.RandomToken()
		target, err = p.oidc.AuthURL(r.Context(), st.State, st.Nonce, st.Verifier)
	case config.ProviderSAML:
		// The IdP answers with a cross-site POST, which carries only
		// SameSite=None cookies. The cookie is still Secure, HttpOnly,
		// sealed and single-use.
		st.Kind, st.RequestID, sameSite = config.ProviderSAML, saml.NewRequestID(), http.SameSiteNoneMode
		target, err = p.saml.AuthnRequestURL(st.RequestID, st.State)
	}
	if err != nil {
		s.loginFailed(w, r, rt, p.id, a.id, reasonOf(err), err)
		return
	}
	s.setLoginCookie(w, r, st, sameSite)
	http.Redirect(w, r, target, http.StatusFound)
}

func loginURL(rt *runtime, appID, rd, providerID string) string {
	q := url.Values{"app": {appID}}
	if rd != "" {
		q.Set("rd", rd)
	}
	if providerID != "" {
		q.Set("provider", providerID)
	}
	return rt.cfg.PublicURL + "/login?" + q.Encode()
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func reasonOf(err error) string {
	var oe *oidc.Error
	var se *saml.Error
	switch {
	case errors.As(err, &oe):
		return oe.Reason
	case errors.As(err, &se):
		return se.Reason
	case errors.Is(err, session.ErrFull):
		return "session_store_full"
	case errors.Is(err, session.ErrUnavailable):
		return "session_store_unavailable"
	case errors.Is(err, session.ErrExpired):
		return "idp_session_ended"
	}
	return "internal_error"
}

// loginFailed audits a failed login and shows a page with a fresh start.
// The detailed error goes to the log, never to the browser.
func (s *Server) loginFailed(w http.ResponseWriter, r *http.Request, rt *runtime, providerID, appID, reason string, err error) {
	ip := clientIP(r, s.opts.TrustedProxies)
	attrs := []slog.Attr{slog.String("reason", reason), slog.String("provider", providerID), slog.String("app", appID),
		slog.String("client_ip", ip)}
	p := audit.LoginFailed{Reason: reason, Provider: providerID, App: appID, ClientIP: ip}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
		p.Error = err.Error()
	}
	env := audit.Envelope{Action: "login", Decision: audit.Deny}
	if appID != "" {
		env.Subject = "app:" + appID
	}
	s.audit(r.Context(), env, p, attrs...)
	s.m.Counter("wicket_logins_total", `result="failure",reason="`+reason+`"`, "Completed logins by result.").Inc()
	retry := ""
	if a := rt.apps[appID]; a != nil {
		retry = loginURL(rt, a.id, a.defaultURL, "")
	}
	status := http.StatusBadRequest
	switch reason {
	case oidc.ReasonDiscovery, oidc.ReasonJWKS, oidc.ReasonTokenExchange, oidc.ReasonUserinfo:
		status = http.StatusBadGateway
	case "session_store_full", "session_store_unavailable":
		status = http.StatusServiceUnavailable
	case "internal_error":
		status = http.StatusInternalServerError
	}
	s.errorPage(w, r, status, "Sign-in failed", "We couldn't complete your sign-in. Please try again; if it keeps happening, give the reference below to your administrator.", retry)
}

// handleCallback finishes an OpenID Connect login:
// GET /callback/{provider}?code=...&state=...
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	rt := s.rt.Load()
	pid := r.PathValue("provider")
	q := r.URL.Query()
	st, reason := s.takeLoginState(w, r, config.ProviderOIDC, pid, q.Get("state"), http.SameSiteLaxMode)
	if st == nil {
		s.loginFailed(w, r, rt, pid, "", reason, nil)
		return
	}
	if e := q.Get("error"); e != "" {
		s.loginFailed(w, r, rt, pid, st.App, "idp_error", errors.New("provider returned error "+printableASCII(e, 64)))
		return
	}
	p := rt.providers[pid]
	if p == nil || p.oidc == nil {
		s.loginFailed(w, r, rt, pid, st.App, "provider_removed", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callbackTimeout)
	defer cancel()
	res, err := p.oidc.Exchange(ctx, q.Get("code"), st.Verifier, st.Nonce)
	if err != nil {
		s.loginFailed(w, r, rt, pid, st.App, reasonOf(err), err)
		return
	}
	s.finishLogin(w, r, rt, st, res.Identity, time.Time{}, res.RefreshToken, http.StatusFound)
}

// handleACS finishes a SAML login: POST /saml/{provider}/acs.
func (s *Server) handleACS(w http.ResponseWriter, r *http.Request) {
	rt := s.rt.Load()
	pid := r.PathValue("provider")
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
		s.loginFailed(w, r, rt, pid, "", "malformed_response", errors.New("ACS needs a form POST"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBody)
	if err := r.ParseForm(); err != nil {
		s.loginFailed(w, r, rt, pid, "", "malformed_response", err)
		return
	}
	st, reason := s.takeLoginState(w, r, config.ProviderSAML, pid, r.PostForm.Get("RelayState"), http.SameSiteNoneMode)
	if st == nil {
		s.loginFailed(w, r, rt, pid, "", reason, nil)
		return
	}
	p := rt.providers[pid]
	if p == nil || p.saml == nil {
		s.loginFailed(w, r, rt, pid, st.App, "provider_removed", nil)
		return
	}
	res, err := p.saml.ParseResponse(r.PostForm.Get("SAMLResponse"), st.RequestID)
	if err != nil {
		s.loginFailed(w, r, rt, pid, st.App, reasonOf(err), err)
		return
	}
	// 303 turns the IdP's POST into a GET of the return URL.
	s.finishLogin(w, r, rt, st, res.Identity, res.SessionNotOnOrAfter, "", http.StatusSeeOther)
}

// finishLogin replaces any existing session with a new one (a fresh id at
// every login prevents session fixation) and returns the user to the app.
// A refresh token is kept, sealed, only for a provider that revalidates.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, rt *runtime, st *loginState, id policy.Identity, notAfter time.Time, refresh string, status int) {
	if old, _ := s.currentSession(r, rt); old != nil {
		if _, err := s.sessions.Revoke(old.ID); err != nil {
			s.log.ErrorContext(r.Context(), "revoking the previous session", "request_id", requestIDFrom(r.Context()), "error", err.Error())
		}
	}
	sealed := ""
	if p := rt.providers[id.Provider]; p != nil && p.reval.enabled() {
		if refresh != "" {
			sealed = s.sealRefresh(id.Provider, id.Subject, refresh)
		} else {
			s.log.WarnContext(r.Context(), "the provider issued no usable refresh token; the session can't be revalidated and follows on_failure",
				"request_id", requestIDFrom(r.Context()), "provider", id.Provider)
		}
	}
	secret, sess, err := s.sessions.CreateWithRefresh(id, notAfter, sealed)
	if err != nil {
		s.loginFailed(w, r, rt, st.Provider, st.App, reasonOf(err), err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName(rt), Value: s.keys.Seal(purposeSession, []byte(secret)),
		Path: "/", Domain: rt.cfg.CookieDomain, Expires: sess.ExpiresAt, Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode})
	ip := clientIP(r, s.opts.TrustedProxies)
	s.audit(r.Context(), audit.Envelope{Actor: id.Subject, Subject: "app:" + st.App, Action: "login", Decision: audit.Allow},
		audit.LoginSucceeded{Provider: id.Provider, App: st.App, Session: sess.ID, Email: id.Email, ClientIP: ip},
		slog.String("provider", id.Provider), slog.String("app", st.App),
		slog.String("sub", id.Subject), slog.String("email", id.Email), slog.String("session", sess.ID),
		slog.String("client_ip", ip))
	s.m.Counter("wicket_logins_total", `result="success",reason="ok"`, "Completed logins by result.").Inc()
	http.Redirect(w, r, st.Return, status)
}

// currentSession returns the session named by the request's cookie, or nil.
func (s *Server) currentSession(r *http.Request, rt *runtime) (*session.Session, error) {
	c, err := r.Cookie(sessionCookieName(rt))
	if err != nil {
		return nil, err
	}
	secret, err := s.keys.Open(purposeSession, c.Value)
	if err != nil {
		return nil, err
	}
	return s.sessions.Lookup(string(secret))
}

func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	p := s.rt.Load().providers[r.PathValue("provider")]
	if p == nil || p.saml == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "no such SAML provider")
		return
	}
	md, err := p.saml.Metadata()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(md)
}

// printableASCII keeps visible ASCII only, at most n bytes, for values
// echoed into logs.
func printableASCII(s string, n int) string {
	b := make([]byte, 0, min(len(s), n))
	for i := 0; i < len(s) && len(b) < n; i++ {
		if s[i] >= 0x20 && s[i] < 0x7f {
			b = append(b, s[i])
		}
	}
	return string(b)
}
