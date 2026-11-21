package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// TestAuthURLStepUp: a step-up login asks for max_age and acr_values, and
// an ordinary one for neither.
func TestAuthURLStepUp(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, nil)
	ctx := context.Background()
	for _, c := range []struct {
		o              AuthOptions
		maxAge, values string
	}{
		{AuthOptions{MaxAge: -1}, "", ""},
		{AuthOptions{MaxAge: 900}, "900", ""},
		{AuthOptions{MaxAge: 0}, "0", ""},
		{AuthOptions{MaxAge: -1, ACRValues: []string{"urn:mfa", "urn:hwk"}}, "", "urn:mfa urn:hwk"},
		{AuthOptions{MaxAge: 60, ACRValues: []string{"urn:mfa"}}, "60", "urn:mfa"},
	} {
		u, err := p.AuthURLWith(ctx, "st", "n", "v", c.o)
		if err != nil {
			t.Fatal(err)
		}
		pu, _ := url.Parse(u)
		q := pu.Query()
		if _, has := q["max_age"]; has != (c.maxAge != "") || q.Get("max_age") != c.maxAge {
			t.Errorf("%+v: max_age %q in %s", c.o, q.Get("max_age"), u)
		}
		if _, has := q["acr_values"]; has != (c.values != "") || q.Get("acr_values") != c.values {
			t.Errorf("%+v: acr_values %q in %s", c.o, q.Get("acr_values"), u)
		}
	}
	plain, _ := p.AuthURL(ctx, "st", "n", "v")
	if pu, _ := url.Parse(plain); pu.Query().Has("max_age") || pu.Query().Has("acr_values") {
		t.Fatalf("AuthURL asks for a step-up: %s", plain)
	}
}

// TestExchangeAuthContext: auth_time and acr come back with the login,
// and a malformed one fails it rather than being dropped.
func TestExchangeAuthContext(t *testing.T) {
	op := newOP(t)
	p := op.provider(t, nil)
	at := op.clk.now().Add(-2 * time.Minute).Unix()
	for _, c := range []struct {
		name    string
		set     map[string]any
		time    int64
		acr     string
		failure bool
	}{
		{"neither", nil, 0, "", false},
		{"both", map[string]any{"auth_time": at, "acr": "urn:mfa"}, at, "urn:mfa", false},
		{"fractional auth_time", map[string]any{"auth_time": float64(at) + 0.75}, at, "", false},
		{"auth_time a string", map[string]any{"auth_time": "1700000000"}, 0, "", true},
		{"auth_time zero", map[string]any{"auth_time": 0}, 0, "", true},
		{"auth_time negative", map[string]any{"auth_time": -5}, 0, "", true},
		{"acr a number", map[string]any{"acr": 2}, 0, "", true},
		{"acr empty", map[string]any{"acr": ""}, 0, "", true},
		{"acr with a space", map[string]any{"acr": "two words"}, 0, "", true},
	} {
		op.set(func(op *testOP) {
			op.tokenHandler = func(url.Values, *http.Request) (int, any) {
				cl := op.claims()
				for k, v := range c.set {
					cl[k] = v
				}
				return 200, map[string]any{"id_token": token(t, "RS256", opKey, testKid, nil, cl)}
			}
		})
		res, err := p.Exchange(context.Background(), "code", "v", "n-1")
		if c.failure {
			var oe *Error
			if !errors.As(err, &oe) || oe.Reason != ReasonClaims {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := res.AuthTime; (c.time == 0) != got.IsZero() || (c.time != 0 && got.Unix() != c.time) || res.ACR != c.acr {
			t.Errorf("%s: auth_time %v acr %q", c.name, got, res.ACR)
		}
	}
}
