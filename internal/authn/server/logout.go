package server

import (
	"crypto/subtle"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/laiwf94/authz/internal/authn/config"
	"github.com/laiwf94/authz/internal/platform/audit"
)

// handleLogoutPage shows a confirmation with a POST form. Logging out only
// happens on POST with a token bound to the session, so a link or image on
// another site can't sign anyone out.
func (s *Server) handleLogoutPage(w http.ResponseWriter, r *http.Request) {
	rt := s.rt.Load()
	sess, err := s.currentSession(r, rt)
	if err != nil {
		renderPage(w, http.StatusOK, "loggedout", map[string]any{"Title": "Signed out"})
		return
	}
	rd, _ := rt.redirects.Validate(r.URL.Query().Get("rd"))
	renderPage(w, http.StatusOK, "logout", map[string]any{"Title": "Sign out", "User": displayUser(sess),
		"LogoutURL": rt.cfg.PublicURL + "/logout", "CSRF": s.keys.Seal(purposeLogout, []byte(sess.ID)), "Return": rd})
}

// handleLogout ends the session: POST /logout with form fields csrf and,
// optionally, rd. For OpenID Connect providers that publish an
// end_session_endpoint, the browser continues there (RP-initiated logout);
// SAML sessions end locally.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	rt := s.rt.Load()
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
		writeError(w, r, http.StatusUnsupportedMediaType, "invalid_argument", "logout needs a form POST")
		return
	}
	// Defense in depth next to the token: a browser that sends Origin must
	// be on our own origin.
	if o := r.Header.Get("Origin"); o != "" && !strings.EqualFold(o, rt.public.Scheme+"://"+rt.public.Host) {
		writeError(w, r, http.StatusForbidden, "permission_denied", "cross-origin logout refused")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxJSONBody)
	if err := r.ParseForm(); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_argument", "bad form")
		return
	}
	done := rt.cfg.PublicURL + "/logged-out"
	if rd, err := rt.redirects.Validate(r.PostForm.Get("rd")); err == nil {
		done = rd
	}
	sess, err := s.currentSession(r, rt)
	if err != nil {
		// Nothing to end; clearing a stale cookie is harmless.
		clearCookie(w, sessionCookieName(rt), rt.cfg.CookieDomain, http.SameSiteLaxMode)
		http.Redirect(w, r, done, http.StatusSeeOther)
		return
	}
	// The cookie is cleared only after the token checks out, so a forged
	// POST can't even sign the browser out.
	tok, err := s.keys.Open(purposeLogout, r.PostForm.Get("csrf"))
	if err != nil || subtle.ConstantTimeCompare(tok, []byte(sess.ID)) != 1 {
		s.audit(r.Context(), audit.Envelope{Subject: "session:" + sess.ID, Action: "logout", Decision: audit.Deny},
			audit.LogoutRejected{Reason: "csrf_token_invalid", Session: sess.ID},
			slog.String("reason", "csrf_token_invalid"), slog.String("session", sess.ID))
		writeError(w, r, http.StatusForbidden, "permission_denied", "invalid logout token; use the sign-out page")
		return
	}
	clearCookie(w, sessionCookieName(rt), rt.cfg.CookieDomain, http.SameSiteLaxMode)
	if _, err := s.sessions.Revoke(sess.ID); err != nil {
		s.log.Error("persisting logout", "request_id", requestIDFrom(r.Context()), "error", err.Error())
	}
	s.audit(r.Context(), audit.Envelope{Actor: sess.Identity.Subject, Subject: "session:" + sess.ID, Action: "logout"},
		audit.Logout{Provider: sess.Identity.Provider, Session: sess.ID},
		slog.String("provider", sess.Identity.Provider), slog.String("sub", sess.Identity.Subject),
		slog.String("session", sess.ID))
	if p := rt.providers[sess.Identity.Provider]; p != nil && p.kind == config.ProviderOIDC {
		if u := p.oidc.EndSessionURL(r.Context(), p.postLogout); u != "" {
			done = u
		}
	}
	http.Redirect(w, r, done, http.StatusSeeOther)
}

func (s *Server) handleLoggedOut(w http.ResponseWriter, r *http.Request) {
	renderPage(w, http.StatusOK, "loggedout", map[string]any{"Title": "Signed out"})
}
