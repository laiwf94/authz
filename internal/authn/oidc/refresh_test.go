package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func reasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func TestExchangeReturnsRefreshToken(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, nil)
	op.set(func(op *testOP) {
		op.tokenHandler = func(url.Values, *http.Request) (int, any) {
			return 200, map[string]any{"access_token": "at-1", "token_type": "Bearer", "refresh_token": "rt-1",
				"id_token": token(t, "RS256", opKey, testKid, nil, op.claims())}
		}
	})
	res, err := p.Exchange(context.Background(), "code", "v", "n-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.RefreshToken != "rt-1" {
		t.Fatalf("refresh token %q", res.RefreshToken)
	}
	for name, rt := range map[string]string{"oversized": strings.Repeat("r", MaxRefreshTokenBytes+1), "control": "rt\n1"} {
		op.set(func(op *testOP) {
			op.tokenHandler = func(url.Values, *http.Request) (int, any) {
				return 200, map[string]any{"access_token": "at-1", "token_type": "Bearer", "refresh_token": rt,
					"id_token": token(t, "RS256", opKey, testKid, nil, op.claims())}
			}
		})
		// The login stands; the token is not kept.
		if res, err := p.Exchange(context.Background(), "code", "v", "n-1"); err != nil || res.RefreshToken != "" {
			t.Errorf("%s refresh token: %v", name, err)
		}
	}
}

func TestRefresh(t *testing.T) {
	op := newOP(t)
	ctx := context.Background()
	for _, auth := range []string{ClientSecretBasic, ClientSecretPost, ClientAuthNone} {
		p := op.provider(t, func(c *Config) {
			c.ClientAuth = auth
			if auth == ClientAuthNone {
				c.ClientSecret = ""
			}
		})
		// Rotation: the provider hands back a new refresh token.
		op.set(func(op *testOP) {
			op.tokenHandler = func(f url.Values, r *http.Request) (int, any) {
				if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != "rt-1" {
					return 400, map[string]string{"error": "invalid_request"}
				}
				return 200, map[string]any{"access_token": "at-2", "token_type": "Bearer", "refresh_token": "rt-2"}
			}
		})
		got, err := p.Refresh(ctx, "rt-1", "alice")
		if err != nil {
			t.Fatalf("%s: %v", auth, err)
		}
		if !got.Rotated || got.RefreshToken != "rt-2" {
			t.Fatalf("%s: %+v", auth, got)
		}
		op.mu.Lock()
		form, hdr := op.lastForm, op.lastAuth
		op.mu.Unlock()
		switch auth {
		case ClientSecretBasic:
			if !strings.HasPrefix(hdr, "Basic ") || form.Get("client_secret") != "" {
				t.Errorf("basic: %q %v", hdr, form)
			}
		case ClientSecretPost:
			if hdr != "" || form.Get("client_id") != "client" || form.Get("client_secret") != "s3cret" {
				t.Errorf("post: %q %v", hdr, form)
			}
		case ClientAuthNone:
			if hdr != "" || form.Get("client_id") != "client" || form.Has("client_secret") {
				t.Errorf("none: %q %v", hdr, form)
			}
		}
		if form.Has("redirect_uri") || form.Has("code") || form.Has("scope") {
			t.Errorf("%s: refresh request carries login parameters: %v", auth, form)
		}
	}

	// No rotation: the same token again, or none at all.
	p := op.provider(t, nil)
	for _, back := range []string{"", "rt-1"} {
		op.set(func(op *testOP) {
			op.tokenHandler = func(url.Values, *http.Request) (int, any) {
				body := map[string]any{"access_token": "at-2", "token_type": "Bearer"}
				if back != "" {
					body["refresh_token"] = back
				}
				return 200, body
			}
		})
		got, err := p.Refresh(ctx, "rt-1", "alice")
		if err != nil || got.Rotated || got.RefreshToken != "rt-1" {
			t.Fatalf("no rotation (%q back): %+v %v", back, got, err)
		}
	}
}

func TestRefreshIDToken(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, nil)
	ctx := context.Background()
	respond := func(claims map[string]any, mutate func(map[string]any)) {
		op.set(func(op *testOP) {
			op.tokenHandler = func(url.Values, *http.Request) (int, any) {
				c := claims
				if c == nil {
					c = op.claims()
				}
				if mutate != nil {
					mutate(c)
				}
				return 200, map[string]any{"access_token": "at-2", "token_type": "Bearer",
					"id_token": token(t, "RS256", opKey, testKid, nil, c)}
			}
		})
	}
	// Core 12.2: a refreshed ID token answers no login request, so it may
	// lack the nonce, or carry the first one.
	respond(nil, func(c map[string]any) { delete(c, "nonce") })
	if _, err := p.Refresh(ctx, "rt-1", "alice"); err != nil {
		t.Fatalf("no nonce: %v", err)
	}
	respond(nil, nil)
	if _, err := p.Refresh(ctx, "rt-1", "alice"); err != nil {
		t.Fatalf("original nonce: %v", err)
	}
	// Another subject is the provider saying this is not the same user.
	respond(nil, func(c map[string]any) { c["sub"] = "mallory" })
	if _, err := p.Refresh(ctx, "rt-1", "alice"); reasonOf(err) != ReasonRefreshRefused {
		t.Fatalf("other subject: %v", err)
	}
	// A token that fails its checks is no answer either way.
	for name, mutate := range map[string]func(map[string]any){
		"wrong issuer":   func(c map[string]any) { c["iss"] = "https://evil.example" },
		"wrong audience": func(c map[string]any) { c["aud"] = "other-client" },
		"expired":        func(c map[string]any) { c["exp"] = op.clk.now().Unix() - 3600 },
		"bad at_hash":    func(c map[string]any) { c["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA" },
	} {
		respond(nil, mutate)
		if _, err := p.Refresh(ctx, "rt-1", "alice"); reasonOf(err) != ReasonRefreshFailed {
			t.Errorf("%s: %v", name, err)
		}
	}
	op.set(func(op *testOP) {
		op.tokenHandler = func(url.Values, *http.Request) (int, any) {
			return 200, map[string]any{"access_token": "at-2", "token_type": "Bearer", "id_token": "x.y.z"}
		}
	})
	if _, err := p.Refresh(ctx, "rt-1", "alice"); reasonOf(err) != ReasonRefreshFailed {
		t.Errorf("garbage id_token: %v", err)
	}
}

func TestRefreshOutcomes(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, nil)
	ctx := context.Background()
	cases := []struct {
		name   string
		status int
		body   any
		want   string
	}{
		{"invalid_grant", 400, map[string]string{"error": "invalid_grant", "error_description": "Session not active"}, ReasonRefreshRefused},
		{"invalid_grant on 401", 401, map[string]string{"error": "invalid_grant"}, ReasonRefreshRefused},
		// Errors about the client or the request say nothing about the user.
		{"invalid_client", 401, map[string]string{"error": "invalid_client"}, ReasonRefreshFailed},
		{"unauthorized_client", 400, map[string]string{"error": "unauthorized_client"}, ReasonRefreshFailed},
		{"unsupported_grant_type", 400, map[string]string{"error": "unsupported_grant_type"}, ReasonRefreshFailed},
		{"invalid_grant on 500", 500, map[string]string{"error": "invalid_grant"}, ReasonRefreshFailed},
		{"server error", 503, map[string]string{}, ReasonRefreshFailed},
		{"not json", 400, "x", ReasonRefreshFailed},
		{"no access token", 200, map[string]string{"token_type": "Bearer"}, ReasonRefreshFailed},
		{"mac token", 200, map[string]string{"access_token": "a", "token_type": "mac"}, ReasonRefreshFailed},
		{"oversized new token", 200, map[string]string{"access_token": "a", "token_type": "Bearer",
			"refresh_token": strings.Repeat("r", MaxRefreshTokenBytes+1)}, ReasonRefreshFailed},
	}
	for _, c := range cases {
		op.set(func(op *testOP) {
			op.tokenHandler = func(url.Values, *http.Request) (int, any) { return c.status, c.body }
		})
		if _, err := p.Refresh(ctx, "rt-1", "alice"); reasonOf(err) != c.want {
			t.Errorf("%s: %v, want %s", c.name, err, c.want)
		}
	}
	for name, tok := range map[string]string{"empty": "", "oversized": strings.Repeat("r", MaxRefreshTokenBytes+1)} {
		if _, err := p.Refresh(ctx, tok, "alice"); reasonOf(err) != ReasonRefreshFailed {
			t.Errorf("%s token: %v", name, err)
		}
	}

	// The provider unreachable: no answer.
	op.srv.Close()
	down := op.provider(t, nil)
	if _, err := down.Refresh(ctx, "rt-1", "alice"); reasonOf(err) != ReasonRefreshFailed {
		t.Fatalf("provider down: %v", err)
	}
	// Errors never carry the refresh token.
	if _, err := p.Refresh(ctx, "rt-secret-value-0123", "alice"); err == nil || strings.Contains(err.Error(), "rt-secret-value-0123") {
		t.Fatalf("error %v", err)
	}
}
