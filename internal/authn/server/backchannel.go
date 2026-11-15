package server

import (
	"context"
	"errors"
	"log/slog"
	"mime"
	"net/http"

	"github.com/laiwf94/authz/internal/platform/audit"
)

// OpenID Connect Back-Channel Logout 1.0, relying party side.
//
// The provider POSTs a signed logout token to
// /backchannel-logout/{provider} when a user's session there ends (they
// signed out, an administrator ended it, the user was disabled). The token
// names the provider's session (sid), the user (sub) or both; every
// session it names ends at once, and each is audited as
// authn.session_ended with reason backchannel_logout.

// reasonBackchannelLogout is the audited reason a back-channel logout ends
// a session.
const reasonBackchannelLogout = "backchannel_logout"

// Reasons a back-channel logout request is refused that are not about the
// token itself.
const (
	reasonLogoutReplayed  = "logout_token_replayed"
	reasonLogoutRequest   = "logout_request_invalid"
	reasonLogoutProvider  = "logout_provider_unknown"
	reasonLogoutReplayCap = "logout_token_replay_cache_full"
)

// handleBackchannelLogout: POST /backchannel-logout/{provider} with an
// application/x-www-form-urlencoded body holding logout_token (section 2.5).
// It answers 200 when the token is valid, whether or not any session
// matched (the provider can't know which sessions this relying party still
// holds), and 400 with a JSON error otherwise (section 2.8). Responses are
// never cached (the route sets Cache-Control: no-store).
func (s *Server) handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	rt := s.rt.Load()
	pid := r.PathValue("provider")
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
		s.logoutTokenRejected(w, r, pid, reasonLogoutRequest, errors.New("the logout token must be a form POST"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxJSONBody)
	if err := r.ParseForm(); err != nil {
		s.logoutTokenRejected(w, r, pid, reasonLogoutRequest, err)
		return
	}
	// A token in the query string could be logged on the way; only the body
	// counts, and only one token.
	if len(r.PostForm["logout_token"]) != 1 || r.URL.Query().Has("logout_token") {
		s.logoutTokenRejected(w, r, pid, reasonLogoutRequest, errors.New("exactly one logout_token form field is required"))
		return
	}
	p := rt.providers[pid]
	if p == nil || p.oidc == nil {
		s.logoutTokenRejected(w, r, pid, reasonLogoutProvider, errors.New("no such OpenID Connect provider"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callbackTimeout)
	defer cancel()
	lt, err := p.oidc.VerifyLogoutToken(ctx, r.PostForm.Get("logout_token"))
	if err != nil {
		s.logoutTokenRejected(w, r, pid, reasonOf(err), err)
		return
	}
	// Each token is used once (section 2.6, step 7 recommends it): a
	// captured token naming only a user must not end the sessions they
	// start afterwards. The cache keeps the jti for as long as the token
	// would pass, and refuses new ones rather than forget when full.
	if !s.jtis.Claim(pid+"\x00"+lt.JTI, lt.Until) {
		reason := reasonLogoutReplayed
		if s.jtis.Len() >= s.jtis.Cap() {
			reason = reasonLogoutReplayCap
		}
		s.logoutTokenRejected(w, r, pid, reason, errors.New("the logout token was already used"))
		return
	}
	ended, err := s.sessions.EndProviderSessions(pid, lt.Subject, lt.SessionID)
	if err != nil {
		// As with an administrator's revocation, the sessions stopped
		// working at once; only their record may not survive a restart. A
		// retry of this token would be refused as a replay, so the provider
		// is told the logout happened, and operators get the error.
		s.log.ErrorContext(r.Context(), "persisting a back-channel logout", "request_id", requestIDFrom(r.Context()),
			"provider", pid, "error", err.Error())
	}
	for _, e := range ended {
		s.audit(r.Context(), audit.Envelope{Actor: e.Subject, Subject: "session:" + e.ID, Action: "session.end"},
			audit.SessionEnded{Provider: pid, Session: e.ID, Reason: reasonBackchannelLogout},
			slog.String("provider", pid), slog.String("sub", e.Subject), slog.String("session", e.ID),
			slog.String("reason", reasonBackchannelLogout))
		s.m.Counter("wicket_sessions_ended_total", `reason="`+reasonBackchannelLogout+`"`, "Sessions ended because the identity provider no longer vouched for them.").Inc()
	}
	s.backchannelLogouts(pid, "accepted")
	w.WriteHeader(http.StatusOK)
}

// logoutTokenRejected audits and counts a refused back-channel logout and
// answers 400 as section 2.8 asks: {"error":"invalid_request", ...}.
func (s *Server) logoutTokenRejected(w http.ResponseWriter, r *http.Request, pid, reason string, cause error) {
	pid = printableASCII(pid, 64)
	s.audit(r.Context(), audit.Envelope{Subject: "provider:" + pid, Action: "logout", Decision: audit.Deny},
		audit.LogoutRejected{Reason: reason, Provider: pid},
		slog.String("provider", pid), slog.String("reason", reason), slog.String("error", cause.Error()))
	s.backchannelLogouts(pid, "rejected")
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": reason})
}

func (s *Server) backchannelLogouts(pid, result string) {
	if _, known := s.rt.Load().providers[pid]; !known {
		pid = "unknown" // the label set stays bounded
	}
	s.m.Counter("wicket_backchannel_logouts_total", `provider="`+pid+`",result="`+result+`"`,
		"Back-channel logout requests by provider and result: accepted or rejected.").Inc()
}
