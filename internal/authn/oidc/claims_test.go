package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestClaimValues(t *testing.T) {
	for raw, want := range map[string][]string{
		`"acme"`:                          {"acme"},
		` "a b" `:                         {"a b"},
		`42`:                              {"42"},
		`-1.5e3`:                          {"-1.5e3"},
		`true`:                            {"true"},
		`false`:                           {"false"},
		`["it", 7, false, null, {}, [1]]`: {"it", "7", "false"},
		`null`:                            nil,
		`{"a": "b"}`:                      nil,
		`[]`:                              nil,
		``:                                nil,
		`[`:                               nil,
		`"été"`:                           {"été"},
	} {
		if got := claimValues(json.RawMessage(raw)); !reflect.DeepEqual(got, want) {
			t.Errorf("claimValues(%s) = %q, want %q", raw, got, want)
		}
	}
	for _, raw := range []string{`"unterminated`, `tru`, `-`, `x`} {
		if _, ok := scalarClaim(json.RawMessage(raw)); ok {
			t.Errorf("scalarClaim(%s) accepted", raw)
		}
	}
}

func TestExchangeKeepsNamedClaims(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, func(c *Config) {
		c.UseUserinfo = true
		c.Claims = []string{"department", "tenant", "level", "admin", "roles", "from_userinfo", "absent", "object"}
	})
	op.set(func(op *testOP) {
		op.userinfo = map[string]any{"sub": "alice", "from_userinfo": "yes", "tenant": "userinfo-does-not-win"}
		op.tokenHandler = func(url.Values, *http.Request) (int, any) {
			c := op.claims()
			c["at_hash"] = AccessTokenHash("RS256", "at-123")
			c["department"] = "eng"
			c["tenant"] = "acme"
			c["level"] = 3
			c["admin"] = true
			c["roles"] = []any{"reader", "writer", "reader", ""}
			c["object"] = map[string]any{"k": "v"}
			c["unnamed"] = "not kept"
			return 200, map[string]any{"access_token": "at-123", "token_type": "Bearer", "id_token": token(t, "RS256", opKey, testKid, nil, c)}
		}
	})
	res, err := p.Exchange(context.Background(), "c", "v", "n-1")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"department": {"eng"}, "tenant": {"acme"}, "level": {"3"}, "admin": {"true"},
		"roles": {"reader", "writer"}, "from_userinfo": {"yes"}}
	if !reflect.DeepEqual(res.Identity.Claims, want) {
		t.Errorf("claims %v, want %v", res.Identity.Claims, want)
	}

	// A provider that names no claims keeps none.
	bare := op.provider(t, nil)
	if res, err := bare.Exchange(context.Background(), "c", "v", "n-1"); err != nil || res.Identity.Claims != nil {
		t.Errorf("no names: %v, %v", res.Identity.Claims, err)
	}

	// A named claim the session could not keep fails the login.
	op.set(func(op *testOP) {
		op.tokenHandler = func(url.Values, *http.Request) (int, any) {
			c := op.claims()
			c["department"] = strings.Repeat("x", 1025)
			return 200, map[string]any{"access_token": "at-9", "token_type": "Bearer", "id_token": token(t, "RS256", opKey, testKid, nil, c)}
		}
	})
	if _, err := bare.Exchange(context.Background(), "c", "v", "n-1"); err != nil {
		t.Errorf("an oversized claim nobody names fails the login: %v", err)
	}
	strict := op.provider(t, func(c *Config) { c.Claims = []string{"department"} })
	if _, err := strict.Exchange(context.Background(), "c", "v", "n-1"); err == nil || !strings.Contains(err.Error(), ReasonClaims) {
		t.Errorf("oversized named claim: %v", err)
	}
}
