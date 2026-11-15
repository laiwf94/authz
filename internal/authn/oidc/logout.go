package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/platform/jose"
)

// Back-channel logout (OpenID Connect Back-Channel Logout 1.0).

// BackchannelLogoutEvent is the member of a logout token's events claim
// that makes it one (section 2.4).
const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// Reasons a logout token is refused, as audited and counted.
const (
	ReasonLogoutToken = "logout_token_invalid"
	// ReasonLogoutEvents is a token without the back-channel logout event.
	ReasonLogoutEvents = "logout_token_no_event"
	// ReasonLogoutNonce is a token carrying a nonce, which section 2.6
	// forbids so an ID token can't pass as a logout token.
	ReasonLogoutNonce = "logout_token_nonce"
	// ReasonLogoutTarget is a token naming neither sub nor sid.
	ReasonLogoutTarget = "logout_token_no_target"
	// ReasonLogoutJTI is a token without a usable jti.
	ReasonLogoutJTI = "logout_token_no_jti"
	// ReasonLogoutClaims is any other bad claim (iss, aud, exp, iat, ...).
	ReasonLogoutClaims = "logout_token_claims_invalid"
)

// logoutTokenMaxAge bounds how long after iat a logout token is accepted.
// The replay cache keeps each jti this long, so a replay is refused for as
// long as the token itself would be accepted.
const logoutTokenMaxAge = 10 * time.Minute

// LogoutToken is a validated logout token.
type LogoutToken struct {
	Subject   string // "" when the token names only a session
	SessionID string // "" when the token names only a subject
	JTI       string
	// Until is when the token stops being accepted: the earlier of exp
	// and iat plus the maximum age, plus the clock skew. A replay cache
	// must remember the jti until then.
	Until time.Time
}

// VerifyLogoutToken checks a logout token as section 2.6 lists: a JWS
// signed with the provider's keys under an allowed algorithm (never
// "none"), typed as a logout token or plain JWT, from this provider's
// issuer, for this client, current, with a jti, an events claim holding
// the back-channel logout event as an object, a sub or a sid (or both),
// and no nonce. It does not check for replays: the caller keeps the jti.
func (p *Provider) VerifyLogoutToken(ctx context.Context, raw string) (*LogoutToken, error) {
	if raw == "" || len(raw) > maxLogoutTokenBytes {
		return nil, fail(ReasonLogoutToken, "missing or oversized logout_token")
	}
	tok, err := jose.Parse(raw)
	if err != nil {
		return nil, fail(ReasonLogoutToken, "%v", err)
	}
	// Section 2.4 recommends explicit typing (logout+jwt); "JWT" and none
	// are what most providers send. Any other type (an access token, an ID
	// token typed as such, a security event token) is refused.
	switch t := strings.ToLower(tok.Header.Typ); t {
	case "", "jwt", "logout+jwt", "application/logout+jwt":
	default:
		return nil, fail(ReasonLogoutToken, "unexpected typ %q", printable(tok.Header.Typ, 32))
	}
	if !contains(p.cfg.Algorithms, tok.Header.Alg) {
		return nil, fail(ReasonLogoutToken, "algorithm %q not allowed", printable(tok.Header.Alg, 16))
	}
	key, err := p.keys.key(ctx, tok.Header.Kid, tok.Header.Alg)
	if err != nil {
		return nil, err
	}
	if err := tok.Verify(key, p.cfg.Algorithms); err != nil {
		return nil, fail(ReasonLogoutToken, "%v", err)
	}
	claims, err := jose.ParseClaims(tok.Payload)
	if err != nil {
		return nil, fail(ReasonLogoutClaims, "%v", err)
	}
	now := p.cfg.Now()
	err = claims.Validate(jose.Expect{Issuer: p.cfg.Issuer, Audience: p.cfg.ClientID, Now: now,
		Skew: p.cfg.Skew, MaxAge: logoutTokenMaxAge, TrustedAudiences: p.cfg.TrustedAudiences})
	if err != nil {
		var ce *jose.ClaimError
		if errors.As(err, &ce) {
			return nil, &Error{Reason: "logout_token_" + ce.Reason, Err: err}
		}
		return nil, fail(ReasonLogoutClaims, "%v", err)
	}
	if _, has := claims.Raw["nonce"]; has {
		return nil, fail(ReasonLogoutNonce, "a logout token must not contain a nonce")
	}
	if err := logoutEvent(claims.Raw["events"]); err != nil {
		return nil, err
	}
	jti, ok := stringClaim(claims, "jti")
	if !ok || jti == "" || len(jti) > maxClaimLength || !isPrintableASCII(jti) {
		return nil, fail(ReasonLogoutJTI, "jti must be 1-%d printable ASCII characters", maxClaimLength)
	}
	out := &LogoutToken{JTI: jti}
	if _, has := claims.Raw["sub"]; has {
		if claims.Subject == "" || len(claims.Subject) > maxSubjectLength || !isPrintableASCII(claims.Subject) {
			return nil, fail(ReasonLogoutClaims, "sub must be 1-%d printable ASCII characters", maxSubjectLength)
		}
		out.Subject = claims.Subject
	}
	if out.SessionID, err = sessionID(claims); err != nil {
		return nil, &Error{Reason: ReasonLogoutClaims, Err: err}
	}
	if out.Subject == "" && out.SessionID == "" {
		return nil, fail(ReasonLogoutTarget, "a logout token must name a sub, a sid or both")
	}
	out.Until = claims.IssuedAt.Time().Add(logoutTokenMaxAge)
	if exp := claims.Expiry.Time(); exp.Before(out.Until) {
		out.Until = exp
	}
	out.Until = out.Until.Add(p.cfg.Skew)
	return out, nil
}

// maxLogoutTokenBytes bounds a logout token: far above any real one (they
// carry a handful of short claims) and well inside the form body limit.
const maxLogoutTokenBytes = 16 << 10

// logoutEvent checks that events is an object whose back-channel logout
// member is itself a JSON object (section 2.4).
func logoutEvent(raw json.RawMessage) error {
	if raw == nil {
		return fail(ReasonLogoutEvents, "no events claim")
	}
	var events map[string]json.RawMessage
	if err := json.Unmarshal(raw, &events); err != nil || events == nil {
		return fail(ReasonLogoutEvents, "events must be a JSON object")
	}
	ev, ok := events[BackchannelLogoutEvent]
	if !ok {
		return fail(ReasonLogoutEvents, "events has no %s member", BackchannelLogoutEvent)
	}
	if t := bytes.TrimSpace(ev); len(t) == 0 || t[0] != '{' {
		return fail(ReasonLogoutEvents, "the back-channel logout event must be a JSON object")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(ev, &obj); err != nil {
		return fail(ReasonLogoutEvents, "the back-channel logout event must be a JSON object")
	}
	return nil
}

// stringClaim returns a claim that must be a string when present.
func stringClaim(c *jose.Claims, name string) (string, bool) {
	raw, has := c.Raw[name]
	if !has {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// sessionID reads the sid claim: absent is "", present must be a string of
// 1-255 printable ASCII characters, so a logout that names it can match.
func sessionID(c *jose.Claims) (string, error) {
	if _, has := c.Raw["sid"]; !has {
		return "", nil
	}
	sid, ok := stringClaim(c, "sid")
	if !ok || sid == "" || len(sid) > maxSubjectLength || !isPrintableASCII(sid) {
		return "", fail(ReasonClaims, "sid must be 1-%d printable ASCII characters without spaces", maxSubjectLength)
	}
	return sid, nil
}
