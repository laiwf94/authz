package server

import (
	"crypto/subtle"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"strings"

	"github.com/laiwf94/authz/internal/platform/audit"
)

// purposeSessions seals the sessions page's CSRF token. It is bound to the
// session viewing the page, like the logout token, but sealed for another
// purpose so neither token works in the other form.
const purposeSessions = "sessions"

// sessionRow is one line of the sessions page.
type sessionRow struct {
	ID, Device, IP           string
	SignedIn, LastUsed, Ends string
	Current                  bool
}

const pageTime = "2 Jan 2006 15:04 UTC"

// handleSessionsPage lists the signed-in user's sessions at the provider
// they signed in with: device, address, sign-in time and last use, each
// with a POST form to end it, and one to end every other session.
func (s *Server) handleSessionsPage(w http.ResponseWriter, r *http.Request) {
	rt := s.rt.Load()
	sess, err := s.currentSession(r, rt)
	if err != nil {
		s.errorPage(w, r, http.StatusUnauthorized, "You are not signed in",
			"Sign in to an application first, then come back to see your sessions.", "")
		return
	}
	list := s.sessions.UserSessions(sess.Identity.Provider, sess.Identity.Subject)
	rows := make([]sessionRow, 0, len(list))
	for i := range list {
		l := &list[i]
		ip := l.IP()
		if ip == "" {
			ip = "unknown"
		}
		dev := l.Device()
		if dev == "" {
			dev = "Unknown device"
		}
		rows = append(rows, sessionRow{ID: l.ID, Device: dev, IP: ip,
			SignedIn: l.CreatedAt.UTC().Format(pageTime), LastUsed: l.LastSeen.UTC().Format(pageTime),
			Ends: l.ExpiresAt.UTC().Format(pageTime), Current: l.ID == sess.ID})
	}
	w.Header().Set("Content-Security-Policy", sessionsPolicy)
	renderPage(w, http.StatusOK, "sessions", map[string]any{"Title": "Your sessions", "User": displayUser(sess),
		"Sessions": rows, "Others": len(rows) > 1, "EndURL": rt.cfg.PublicURL + "/sessions/end",
		"CSRF": s.keys.Seal(purposeSessions, []byte(sess.ID))})
}

// handleEndSession is POST /sessions/end with form fields csrf and either
// id (one session of the user's) or all=others. Ending the session making
// the request signs this browser out here; use /logout to also sign out at
// the identity provider.
func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	rt := s.rt.Load()
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
		writeError(w, r, http.StatusUnsupportedMediaType, "invalid_argument", "ending a session needs a form POST")
		return
	}
	if o := r.Header.Get("Origin"); o != "" && !strings.EqualFold(o, rt.public.Scheme+"://"+rt.public.Host) {
		writeError(w, r, http.StatusForbidden, "permission_denied", "cross-origin request refused")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxJSONBody)
	if err := r.ParseForm(); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_argument", "bad form")
		return
	}
	sess, err := s.currentSession(r, rt)
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "unauthenticated", "not signed in")
		return
	}
	tok, err := s.keys.Open(purposeSessions, r.PostForm.Get("csrf"))
	if err != nil || subtle.ConstantTimeCompare(tok, []byte(sess.ID)) != 1 {
		s.audit(r.Context(), audit.Envelope{Actor: sess.Identity.Subject, Subject: "session:" + sess.ID,
			Action: "session.revoke", Decision: audit.Deny},
			audit.LogoutRejected{Reason: "csrf_token_invalid", Session: sess.ID},
			slog.String("reason", "csrf_token_invalid"), slog.String("session", sess.ID))
		writeError(w, r, http.StatusForbidden, "permission_denied", "invalid token; reload the sessions page")
		return
	}
	var targets []string
	switch id, all := r.PostForm.Get("id"), r.PostForm.Get("all"); {
	case all == "others" && id == "":
		for _, l := range s.sessions.UserSessions(sess.Identity.Provider, sess.Identity.Subject) {
			if l.ID != sess.ID {
				targets = append(targets, l.ID)
			}
		}
	case all == "" && sessionIDRe.MatchString(id):
		targets = []string{id}
	default:
		writeError(w, r, http.StatusBadRequest, "invalid_argument", "name one session id, or all=others")
		return
	}
	ended, self := 0, false
	var saveErr error
	for _, id := range targets {
		ok, err := s.sessions.RevokeUser(sess.Identity.Provider, sess.Identity.Subject, id)
		if err != nil {
			saveErr = err
		}
		if !ok {
			continue
		}
		ended++
		self = self || id == sess.ID
		s.audit(r.Context(), audit.Envelope{Actor: sess.Identity.Subject, Subject: "session:" + id, Action: "session.revoke"},
			audit.SessionRevoked{Session: id, Provider: sess.Identity.Provider, Count: 1, By: "user"},
			slog.String("session", id), slog.String("provider", sess.Identity.Provider),
			slog.String("sub", sess.Identity.Subject), slog.String("by", "user"))
	}
	if saveErr != nil {
		s.log.ErrorContext(r.Context(), "persisting revocation", "request_id", requestIDFrom(r.Context()), "error", saveErr.Error())
	}
	if len(targets) == 1 && ended == 0 {
		writeError(w, r, http.StatusNotFound, "not_found", "no such session of yours")
		return
	}
	if self {
		clearCookie(w, sessionCookieName(rt), rt.cfg.CookieDomain, http.SameSiteLaxMode)
		http.Redirect(w, r, rt.cfg.PublicURL+"/logged-out", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, rt.cfg.PublicURL+"/sessions", http.StatusSeeOther)
}

// deviceOf is what a new session records about the browser signing in.
func (s *Server) deviceOf(r *http.Request) (device, ip string) {
	return deviceLabel(r.UserAgent()), canonicalIP(clientIP(r, s.opts.TrustedProxies))
}

// canonicalIP keeps an address the session store accepts, or "".
func canonicalIP(ip string) string {
	if a, err := netip.ParseAddr(ip); err == nil && a.Zone() == "" {
		return a.Unmap().String()
	}
	return ""
}
