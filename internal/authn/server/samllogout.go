package server

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"mime"
	"net/http"

	"github.com/laiwf94/authz/internal/authn/oidc"
	"github.com/laiwf94/authz/internal/authn/saml"
	"github.com/laiwf94/authz/internal/authn/session"
	"github.com/laiwf94/authz/internal/platform/audit"
)

// SAML 2.0 Single Logout (Profiles section 4.4), both directions, at
// /saml/{provider}/slo on the HTTP-Redirect (GET) and HTTP-POST (POST)
// bindings.
//
//   - IdP-initiated: a signed LogoutRequest names a NameID and, usually,
//     the identity provider's SessionIndexes. The sessions it names end at
//     once (the SessionIndex of each login is kept with its session and
//     indexed like an OpenID Connect sid), each audited as
//     authn.session_ended with reason saml_logout, and the browser carries a
//     signed LogoutResponse back.
//   - SP-initiated: POST /logout ends the session here first, then sends
//     the browser to the identity provider with a signed LogoutRequest for
//     its SessionIndex. The LogoutResponse comes back here, is matched to the
//     request through a sealed, single-use cookie (as a login's state is),
//     and the browser goes on to the return URL.
//
// Single logout runs only for a SAML provider with an SP key whose IdP
// metadata lists a SingleLogoutService; elsewhere sign-out stays local.

// kindSAMLLogout is the loginState kind of a pending SP-initiated logout.
const kindSAMLLogout = "saml_logout"

// reasonSAMLLogout is the audited reason a SAML LogoutRequest ends a
// session.
const reasonSAMLLogout = "saml_logout"

// handleSAMLLogout serves GET and POST /saml/{provider}/slo.
func (s *Server) handleSAMLLogout(w http.ResponseWriter, r *http.Request) {
	rt := s.rt.Load()
	pid := r.PathValue("provider")
	p := rt.providers[pid]
	if p == nil || p.saml == nil || !p.saml.LogoutEnabled() {
		s.samlLogoutRejected(w, r, pid, reasonLogoutProvider, errors.New("no SAML provider with single logout"))
		return
	}
	if r.Method == http.MethodPost {
		if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
			s.samlLogoutRejected(w, r, pid, saml.ReasonMalformed, errors.New("the HTTP-POST binding needs a form POST"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxFormBody)
		if err := r.ParseForm(); err != nil {
			s.samlLogoutRejected(w, r, pid, saml.ReasonMalformed, err)
			return
		}
	}
	in, err := p.saml.ReadLogout(r.Method, r.URL.RawQuery, r.PostForm)
	if err != nil {
		s.samlLogoutRejected(w, r, pid, reasonOf(err), err)
		return
	}
	if in.Request != nil {
		s.samlIdPLogout(w, r, rt, p, in)
		return
	}
	s.samlLogoutAnswered(w, r, p, in)
}

// samlIdPLogout ends the sessions an IdP-initiated LogoutRequest names and
// answers it.
func (s *Server) samlIdPLogout(w http.ResponseWriter, r *http.Request, rt *runtime, p *provider, in *saml.Inbound) {
	req := in.Request
	cur, _ := s.currentSession(r, rt)
	var ended []session.Ended
	var perr error
	if len(req.SessionIndexes) == 0 {
		// Without a SessionIndex the request means every session of the
		// principal (Core section 3.7.3.2).
		ended, perr = s.sessions.EndProviderSessions(p.id, req.NameID, "")
	}
	for _, idx := range req.SessionIndexes {
		e, err := s.sessions.EndProviderSessions(p.id, req.NameID, idx)
		ended, perr = append(ended, e...), errors.Join(perr, err)
	}
	if perr != nil {
		// The sessions stopped working at once; only their record may not
		// survive a restart.
		s.log.ErrorContext(r.Context(), "persisting a SAML single logout", "request_id", requestIDFrom(r.Context()),
			"provider", p.id, "error", perr.Error())
	}
	for _, e := range ended {
		if cur != nil && e.ID == cur.ID {
			clearCookie(w, sessionCookieName(rt), rt.cfg.CookieDomain, http.SameSiteLaxMode)
		}
		s.audit(r.Context(), audit.Envelope{Actor: e.Subject, Subject: "session:" + e.ID, Action: "session.end"},
			audit.SessionEnded{Provider: p.id, Session: e.ID, Reason: reasonSAMLLogout},
			slog.String("provider", p.id), slog.String("sub", e.Subject), slog.String("session", e.ID),
			slog.String("reason", reasonSAMLLogout))
		s.m.Counter("wicket_sessions_ended_total", `reason="`+reasonSAMLLogout+`"`, "Sessions ended because the identity provider no longer vouched for them.").Inc()
	}
	// Success whether or not a session matched: the identity provider asked
	// for none of this principal's sessions here to remain, and none do.
	msg, err := p.saml.NewLogoutResponse(req.ID, saml.StatusSuccess, in.RelayState, in.Binding)
	if err != nil {
		s.log.ErrorContext(r.Context(), "building a SAML LogoutResponse", "request_id", requestIDFrom(r.Context()),
			"provider", p.id, "error", err.Error())
		s.samlLogouts(p.id, "idp", "error")
		s.errorPage(w, r, http.StatusInternalServerError, "Sign-out incomplete", "You are signed out here, but we couldn't tell your identity provider.", "")
		return
	}
	s.samlLogouts(p.id, "idp", "accepted")
	s.sendSAML(w, r, msg)
}

// samlLogoutAnswered finishes an SP-initiated logout with the identity
// provider's LogoutResponse.
func (s *Server) samlLogoutAnswered(w http.ResponseWriter, r *http.Request, p *provider, in *saml.Inbound) {
	st, reason := s.takeLoginState(w, r, kindSAMLLogout, p.id, in.RelayState, http.SameSiteNoneMode)
	if st == nil {
		s.samlLogoutRejected(w, r, p.id, reason, errors.New("no pending logout for this RelayState"))
		return
	}
	if in.Response.InResponseTo != st.RequestID {
		s.samlLogoutRejected(w, r, p.id, saml.ReasonInResponseTo, errors.New("the LogoutResponse answers another request"))
		return
	}
	result := "accepted"
	if !in.Response.Success() {
		// The session here ended before the browser left; the identity
		// provider kept its own or another participant's. Operators see it;
		// the user is still signed out of everything this gateway guards.
		result = "partial"
		s.log.WarnContext(r.Context(), "the identity provider did not end every session", "request_id", requestIDFrom(r.Context()),
			"provider", p.id, "status", in.Response.Status, "sub_status", in.Response.SubStatus)
	}
	s.samlLogouts(p.id, "sp", result)
	http.Redirect(w, r, st.Return, http.StatusSeeOther)
}

// startSAMLLogout sends the browser to the identity provider with a
// LogoutRequest for the session that just ended here. It reports false
// (having written nothing) when the provider has no single logout or the
// request can't be built; the caller then finishes locally.
func (s *Server) startSAMLLogout(w http.ResponseWriter, r *http.Request, p *provider, sess *session.Session, done string) bool {
	if p.saml == nil || !p.saml.LogoutEnabled() {
		return false
	}
	st := &loginState{Kind: kindSAMLLogout, Provider: p.id, Return: done, State: oidc.RandomToken(),
		RequestID: saml.NewRequestID(), Expires: s.now().Add(loginTTL).Unix()}
	msg, err := p.saml.NewLogoutRequest(st.RequestID, sess.Identity.Subject, sess.SID(), st.State)
	if err != nil {
		s.log.ErrorContext(r.Context(), "building a SAML LogoutRequest", "request_id", requestIDFrom(r.Context()),
			"provider", p.id, "error", err.Error())
		s.samlLogouts(p.id, "sp", "error")
		return false
	}
	// The answer may come as a cross-site POST, which carries only
	// SameSite=None cookies; the cookie is still sealed and single-use.
	s.setLoginCookie(w, r, st, http.SameSiteNoneMode)
	s.samlLogouts(p.id, "sp", "sent")
	s.sendSAML(w, r, msg)
	return true
}

// sendSAML hands a message to the browser: a redirect for HTTP-Redirect, a
// self-submitting form for HTTP-POST.
func (s *Server) sendSAML(w http.ResponseWriter, r *http.Request, msg *saml.Message) {
	if msg.Binding == saml.BindingRedirect {
		http.Redirect(w, r, msg.URL, http.StatusSeeOther)
		return
	}
	fields := make([]samlField, 0, len(msg.Form))
	for _, k := range []string{"SAMLRequest", "SAMLResponse", "RelayState"} {
		if v := msg.Form.Get(k); v != "" {
			fields = append(fields, samlField{Name: k, Value: v})
		}
	}
	// The page's policy allows its one script by hash, and nothing else.
	w.Header().Set("Content-Security-Policy", samlPostPolicy)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = samlPostPage.Execute(w, map[string]any{"Action": msg.URL, "Fields": fields})
}

type samlField struct{ Name, Value string }

// samlPostScript submits the HTTP-POST binding's form on load; without
// scripts the button does.
const samlPostScript = `document.forms[0].submit()`

var samlPostPolicy = func() string {
	css := sha256.Sum256([]byte(pageCSS))
	js := sha256.Sum256([]byte(samlPostScript))
	return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(css[:]) +
		"'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(js[:]) +
		"'; form-action https:; frame-ancestors 'none'; base-uri 'none'"
}()

var samlPostPage = template.Must(template.New("samlpost").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Signing out</title><style>` + pageCSS + `</style></head><body><main>
<h1>Signing out</h1><p>Continuing to your identity provider.</p>
<form method="post" action="{{.Action}}">{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}<button class="primary" type="submit">Continue</button></form>
</main><script>` + samlPostScript + `</script></body></html>`))

// samlLogoutRejected audits and counts a refused logout message and shows
// an error page.
func (s *Server) samlLogoutRejected(w http.ResponseWriter, r *http.Request, pid, reason string, cause error) {
	pid = printableASCII(pid, 64)
	s.audit(r.Context(), audit.Envelope{Subject: "provider:" + pid, Action: "logout", Decision: audit.Deny},
		audit.LogoutRejected{Reason: reason, Provider: pid},
		slog.String("provider", pid), slog.String("reason", reason), slog.String("error", cause.Error()))
	s.samlLogouts(pid, "", "rejected")
	s.errorPage(w, r, http.StatusBadRequest, "Sign-out failed", "This sign-out message could not be accepted. If you meant to sign out, use the sign-out page.", "")
}

// samlLogouts counts single logout messages by provider, who started the
// logout (idp, sp, or empty for a message refused before that was known)
// and result.
func (s *Server) samlLogouts(pid, initiator, result string) {
	if p := s.rt.Load().providers[pid]; p == nil || p.saml == nil {
		pid = "unknown" // the label set stays bounded
	}
	s.m.Counter("wicket_saml_logouts_total", `provider="`+pid+`",initiator="`+initiator+`",result="`+result+`"`,
		"SAML single logout messages by provider, initiator (idp or sp) and result.").Inc()
}
