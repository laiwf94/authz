package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authn/fakeidp"
	"github.com/laiwf94/authz/internal/authn/policy"
)

// claimUsers are the demo users with claims of their own: alice's come in
// her ID token and, for tenant, from userinfo alone; carol signs in over
// SAML, where hers are attributes.
func claimUsers() []fakeidp.User {
	users := append([]fakeidp.User(nil), fakeidp.DemoUsers...)
	users[0].Claims = map[string][]string{"department": {"eng", "sec"}, "clearance": {"level-3"}, "unused": {"kept-by-nobody"}}
	users[0].UserinfoClaims = map[string][]string{"tenant": {"acme"}}
	users[1].Claims = map[string][]string{"department": {"sales"}, "clearance": {"level-1"}}
	users[2].Claims = map[string][]string{"department": {"it"}, "clearance": {"level-12"}}
	return users
}

// claimRules gives the whoami app rules over claims: the admin area for
// the it and sec departments, the tenant area for acme, and the vault for
// clearance level-0 to level-9 who are also in eng.
func claimRules(cfg map[string]any) {
	app := cfg["apps"].([]any)[0].(map[string]any)
	app["allow"] = map[string]any{"any_user": true}
	app["paths"] = []any{
		map[string]any{"path": "/admin", "allow": map[string]any{"claims": []any{
			map[string]any{"claim": "department", "in": []string{"it", "sec"}}}}},
		map[string]any{"path": "/tenant", "allow": map[string]any{"claims": []any{
			map[string]any{"claim": "tenant", "equals": "acme"}}}},
		map[string]any{"path": "/vault", "allow": map[string]any{"groups": []string{"eng"}, "claims": []any{
			map[string]any{"claim": "clearance", "matches": "level-?"}}}},
	}
}

func TestForwardAuthClaimConditions(t *testing.T) {
	h := newHarness(t, harnessOpts{cfgMutate: claimRules, adminToken: strings.Repeat("t", 32)})
	h.idp.SetUsers(claimUsers())
	alice, bob, carol := h.browser(), h.browser(), h.browser()
	alice.loginOIDC("alice", "alice-pass", "")
	bob.loginOIDC("bob", "bob-pass", "")
	if resp := carol.loginSAML("carol", "carol-pass"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("carol SAML login: %d", resp.StatusCode)
	}
	for _, c := range []struct {
		who  string
		b    *browser
		path string
		want int
	}{
		{"alice", alice, "/admin/users", 200}, // department sec, from the ID token
		{"alice", alice, "/tenant", 200},      // tenant acme, from userinfo
		{"alice", alice, "/vault", 200},       // eng, and level-3 matches level-?
		{"alice", alice, "/home", 200},
		{"bob", bob, "/admin/users", 403}, // sales
		{"bob", bob, "/tenant", 403},      // no tenant claim at all
		{"bob", bob, "/vault", 403},       // level-1 but not in eng
		{"bob", bob, "/home", 200},
		{"carol", carol, "/admin/users", 200}, // department it, a SAML attribute
		{"carol", carol, "/vault", 403},       // eng, but level-12 is two characters past level-
		{"carol", carol, "/tenant", 403},
	} {
		if resp := c.b.auth(c.path, nil); resp.StatusCode != c.want {
			t.Errorf("%s %s: %d, want %d", c.who, c.path, resp.StatusCode, c.want)
		}
	}
	h.expectAudit("access_denied", policy.DeniedClaims)

	// Sessions keep the claims the app's conditions name and no others.
	want := map[string]map[string][]string{
		"alice":                 {"department": {"eng", "sec"}, "clearance": {"level-3"}, "tenant": {"acme"}},
		"bob":                   {"department": {"sales"}, "clearance": {"level-1"}},
		"carol@partner.example": {"department": {"it"}, "clearance": {"level-12"}},
	}
	sessions := h.sessions.List("", 0)
	if len(sessions) != 3 {
		t.Fatalf("%d sessions", len(sessions))
	}
	var aliceID, bobID string
	for _, s := range sessions {
		if got := s.Identity.Claims; !reflect.DeepEqual(got, want[s.Identity.Subject]) {
			t.Errorf("%s keeps %v, want %v", s.Identity.Subject, got, want[s.Identity.Subject])
		}
		switch s.Identity.Subject {
		case "alice":
			aliceID = s.ID
		case "bob":
			bobID = s.ID
		}
	}

	// Explain by session shows each condition and the one that failed.
	out := h.explainFor("GET", "/admin/users", fmt.Sprintf(`,"session":%q`, bobID))
	if out.Status != 403 || out.Reason != policy.DeniedClaims || out.Rule != "paths[0]" {
		t.Fatalf("explain bob: %+v", out)
	}
	c0 := out.Rules[0].Claims
	if len(c0) != 1 || c0[0].Claim != "department" || !reflect.DeepEqual(c0[0].In, []string{"it", "sec"}) || c0[0].Holds == nil || *c0[0].Holds {
		t.Errorf("explain bob claims %+v", c0)
	}
	if out.Identity == nil || !reflect.DeepEqual(out.Identity.Claims, want["bob"]) {
		t.Errorf("explain bob identity %+v", out.Identity)
	}
	out = h.explainFor("GET", "/vault", fmt.Sprintf(`,"session":%q`, aliceID))
	if out.Status != 200 || len(out.Rules[0].Claims) != 1 || !*out.Rules[0].Claims[0].Holds {
		t.Errorf("explain alice /vault: %+v", out)
	}

	// A synthetic identity carries its own claims.
	synth := func(claims string) explainResponse {
		return h.explainFor("GET", "/vault", `,"identity":{"provider":"corp","sub":"dave","groups":["eng"],"claims":`+claims+`}`)
	}
	if out := synth(`{"clearance":["level-7"]}`); out.Status != 200 || out.Reason != policy.Allowed {
		t.Errorf("dave level-7: %+v", out)
	}
	if out := synth(`{"clearance":["top"]}`); out.Status != 403 || out.Reason != policy.DeniedClaims || *out.Rules[0].Claims[0].Holds {
		t.Errorf("dave top: %+v", out)
	}
	// Signed out: the conditions are listed without an answer.
	out = h.explainFor("GET", "/vault", "")
	if out.Status != 401 || len(out.Rules[0].Claims) != 1 || out.Rules[0].Claims[0].Holds != nil {
		t.Errorf("signed out: %+v", out)
	}
	for _, bad := range []string{`{"sub":["x"]}`, `{"a":[""]}`, `{"a":["x","x"]}`, `{"a b":["x"]}`, `{"a":"x"}`} {
		body := `{"url":"https://` + h.host + `/vault","identity":{"provider":"corp","sub":"dave","claims":` + bad + `}}`
		if code, _, raw := h.explainCall(body); code != http.StatusBadRequest {
			t.Errorf("claims %s: %d %s", bad, code, raw)
		}
	}

	// A reload that names a claim no session kept denies until the user
	// signs in again, and the new login keeps it.
	cfgWith := func(cfg map[string]any) {
		claimRules(cfg)
		app := cfg["apps"].([]any)[0].(map[string]any)
		app["paths"] = append(app["paths"].([]any), map[string]any{"path": "/unused", "allow": map[string]any{"claims": []any{
			map[string]any{"claim": "unused", "equals": "kept-by-nobody"}}}})
	}
	reconfigure(t, h, cfgWith)
	if resp := alice.auth("/unused", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alice /unused before a new login: %d", resp.StatusCode)
	}
	alice.loginOIDC("alice", "alice-pass", "")
	if resp := alice.auth("/unused", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("alice /unused after a new login: %d", resp.StatusCode)
	}
}

// reconfigure rewrites the harness's configuration with mutate applied to
// a fresh copy of it and reloads.
func reconfigure(t *testing.T, h *harness, mutate func(cfg map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(h.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	mutate(cfg)
	h.writeConfig(cfg)
	if err := h.srv.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
}
