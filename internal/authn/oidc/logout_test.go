package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func (op *testOP) logoutClaims() map[string]any {
	now := op.clk.now().Unix()
	return map[string]any{"iss": op.srv.URL, "aud": "client", "sub": "alice", "sid": "sid-1", "iat": now, "exp": now + 120,
		"jti": "jti-1", "events": map[string]any{BackchannelLogoutEvent: map[string]any{}}}
}

func TestVerifyLogoutToken(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, nil)
	mod := func(f func(c map[string]any)) map[string]any { c := op.logoutClaims(); f(c); return c }
	now := op.clk.now().Unix()
	typ := func(v string) map[string]any { return map[string]any{"typ": v} }
	cases := []struct {
		name     string
		tok      string
		reason   string
		sub, sid string
	}{
		{"sub and sid", token(t, "RS256", opKey, testKid, typ("logout+jwt"), op.logoutClaims()), "", "alice", "sid-1"},
		{"media type form of typ", token(t, "RS256", opKey, testKid, typ("application/logout+JWT"), op.logoutClaims()), "", "alice", "sid-1"},
		{"typ JWT", token(t, "RS256", opKey, testKid, typ("JWT"), op.logoutClaims()), "", "alice", "sid-1"},
		{"no typ", token(t, "RS256", opKey, testKid, nil, op.logoutClaims()), "", "alice", "sid-1"},
		{"sid only", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { delete(c, "sub") })), "", "", "sid-1"},
		{"sub only", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { delete(c, "sid") })), "", "alice", ""},
		{"event with members", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) {
			c["events"] = map[string]any{BackchannelLogoutEvent: map[string]any{"reason": "x"}, "urn:other": true}
		})), "", "alice", "sid-1"},

		{"alg none", token(t, "none", nil, testKid, nil, op.logoutClaims()), ReasonLogoutToken, "", ""},
		{"signed by another key", token(t, "RS256", otherKey, testKid, nil, op.logoutClaims()), ReasonLogoutToken, "", ""},
		{"unknown kid", token(t, "RS256", otherKey, "k-other", nil, op.logoutClaims()), ReasonUnknownKey, "", ""},
		{"access token type", token(t, "RS256", opKey, testKid, typ("at+jwt"), op.logoutClaims()), ReasonLogoutToken, "", ""},
		{"security event token type", token(t, "RS256", opKey, testKid, typ("secevent+jwt"), op.logoutClaims()), ReasonLogoutToken, "", ""},
		{"wrong audience", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["aud"] = "other-client" })), "logout_token_wrong_audience", "", ""},
		{"wrong issuer", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["iss"] = "https://evil.example" })), "logout_token_wrong_issuer", "", ""},
		{"expired", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["exp"] = now - 600 })), "logout_token_expired", "", ""},
		{"no exp", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { delete(c, "exp") })), "logout_token_missing_claim", "", ""},
		{"no iat", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { delete(c, "iat") })), "logout_token_missing_claim", "", ""},
		{"issued long ago", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["iat"] = now - 3600; c["exp"] = now + 60 })), "logout_token_bad_issued_at", "", ""},
		{"issued in the future", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["iat"] = now + 600 })), "logout_token_bad_issued_at", "", ""},
		{"nonce", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["nonce"] = "n-1" })), ReasonLogoutNonce, "", ""},
		{"an ID token", token(t, "RS256", opKey, testKid, nil, op.claims()), ReasonLogoutNonce, "", ""},
		{"no events", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { delete(c, "events") })), ReasonLogoutEvents, "", ""},
		{"events not an object", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["events"] = []string{BackchannelLogoutEvent} })), ReasonLogoutEvents, "", ""},
		{"events null", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["events"] = nil })), ReasonLogoutEvents, "", ""},
		{"other event only", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) {
			c["events"] = map[string]any{"http://schemas.openid.net/event/front-channel-logout": map[string]any{}}
		})), ReasonLogoutEvents, "", ""},
		{"event member not an object", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["events"] = map[string]any{BackchannelLogoutEvent: true} })), ReasonLogoutEvents, "", ""},
		{"event member an array", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["events"] = map[string]any{BackchannelLogoutEvent: []int{}} })), ReasonLogoutEvents, "", ""},
		{"neither sub nor sid", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { delete(c, "sub"); delete(c, "sid") })), ReasonLogoutTarget, "", ""},
		{"empty sub", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["sub"] = "" })), ReasonLogoutClaims, "", ""},
		{"sub with control chars", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["sub"] = "a\nb" })), ReasonLogoutClaims, "", ""},
		{"sid not a string", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["sid"] = 7 })), ReasonLogoutClaims, "", ""},
		{"sid too long", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["sid"] = strings.Repeat("s", 256) })), ReasonLogoutClaims, "", ""},
		{"sid with a space", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["sid"] = "a b" })), ReasonLogoutClaims, "", ""},
		{"no jti", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { delete(c, "jti") })), ReasonLogoutJTI, "", ""},
		{"jti not a string", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["jti"] = 1 })), ReasonLogoutJTI, "", ""},
		{"jti too long", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["jti"] = strings.Repeat("j", 513) })), ReasonLogoutJTI, "", ""},
		{"malformed", "not.a.jwt", ReasonLogoutToken, "", ""},
		{"empty", "", ReasonLogoutToken, "", ""},
		{"oversized", strings.Repeat("a", maxLogoutTokenBytes+1), ReasonLogoutToken, "", ""},
		{"bad claims JSON", token(t, "RS256", opKey, testKid, nil, mod(func(c map[string]any) { c["iat"] = "now" })), ReasonLogoutClaims, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lt, err := p.VerifyLogoutToken(context.Background(), c.tok)
			if c.reason != "" {
				if got := reasonOf(err); got != c.reason {
					t.Fatalf("got %v (reason %q), want reason %s", err, got, c.reason)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if lt.Subject != c.sub || lt.SessionID != c.sid || lt.JTI != "jti-1" {
				t.Fatalf("got %+v", lt)
			}
		})
	}
}

func TestLogoutTokenUntil(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, func(c *Config) { c.Skew = time.Minute })
	now := op.clk.now()
	ctx := context.Background()
	// A short-lived token is remembered until its exp, plus the skew.
	lt, err := p.VerifyLogoutToken(ctx, token(t, "RS256", opKey, testKid, nil, op.logoutClaims()))
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(120*time.Second + time.Minute); !lt.Until.Equal(want) {
		t.Fatalf("until %v, want %v", lt.Until, want)
	}
	// A long-lived one only until it would stop being accepted anyway.
	c := op.logoutClaims()
	c["exp"] = now.Add(24 * time.Hour).Unix()
	lt, err = p.VerifyLogoutToken(ctx, token(t, "RS256", opKey, testKid, nil, c))
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(logoutTokenMaxAge + time.Minute); !lt.Until.Equal(want) {
		t.Fatalf("until %v, want %v", lt.Until, want)
	}
	// And the cap holds: past it the token is refused.
	op.clk.add(logoutTokenMaxAge + 2*time.Minute)
	if _, err := p.VerifyLogoutToken(ctx, token(t, "RS256", opKey, testKid, nil, c)); reasonOf(err) != "logout_token_bad_issued_at" {
		t.Fatalf("stale token: %v", err)
	}
}

func TestExchangeReturnsSessionID(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, nil)
	for _, c := range []struct {
		name   string
		sid    any
		want   string
		reason string
	}{
		{"sid", "sid-42", "sid-42", ""},
		{"no sid", nil, "", ""},
		{"sid not a string", 42, "", ReasonClaims},
		{"empty sid", "", "", ReasonClaims},
		{"sid with control chars", "a\x00b", "", ReasonClaims},
	} {
		op.set(func(op *testOP) {
			op.tokenHandler = func(url.Values, *http.Request) (int, any) {
				claims := op.claims()
				if c.sid != nil {
					claims["sid"] = c.sid
				}
				return 200, map[string]any{"access_token": "at-1", "token_type": "Bearer", "id_token": token(t, "RS256", opKey, testKid, nil, claims)}
			}
		})
		res, err := p.Exchange(context.Background(), "code", "v", "n-1")
		if c.reason != "" {
			if reasonOf(err) != c.reason {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err != nil || res.SessionID != c.want {
			t.Errorf("%s: %v %+v", c.name, err, res)
		}
	}
}

func BenchmarkVerifyLogoutToken(b *testing.B) {
	op := newOP(b)
	p := op.provider(b, nil)
	tok := token(b, "RS256", opKey, testKid, nil, op.logoutClaims())
	ctx := context.Background()
	for b.Loop() {
		if _, err := p.VerifyLogoutToken(ctx, tok); err != nil {
			b.Fatal(err)
		}
	}
}
