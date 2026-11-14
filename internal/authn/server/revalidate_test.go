package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/policy"
)

// revalidating returns harness options that turn revalidation on for the
// corp OpenID provider.
func revalidating(rv map[string]any, sessionFile bool) harnessOpts {
	return harnessOpts{sessionFile: sessionFile, cfgMutate: func(cfg map[string]any) {
		cfg["providers"].([]any)[0].(map[string]any)["revalidate"] = rv
	}}
}

func TestRevalidationConfirmsThenEnds(t *testing.T) {
	h := newHarness(t, revalidating(map[string]any{"interval": "1m"}, true))
	b := h.browser()
	b.loginOIDC("alice", "alice-pass", "")
	if b.auth("/", nil).StatusCode != 200 {
		t.Fatal("not signed in")
	}
	first := h.idp.RefreshTokens("alice")
	if len(first) != 1 {
		t.Fatalf("%d refresh tokens at the provider", len(first))
	}
	ctx := context.Background()

	// Not due yet.
	if res := h.srv.Revalidate(ctx); res != (RevalidateResult{}) {
		t.Fatalf("early pass: %+v", res)
	}
	// Due: the provider confirms and rotates the token.
	h.clk.Advance(61 * time.Second)
	if res := h.srv.Revalidate(ctx); res != (RevalidateResult{Checked: 1, Confirmed: 1}) {
		t.Fatalf("pass: %+v\n%s", res, h.logs.String())
	}
	second := h.idp.RefreshTokens("alice")
	if len(second) != 1 || second[0] == first[0] {
		t.Fatal("the provider did not rotate the refresh token")
	}
	if b.auth("/", nil).StatusCode != 200 {
		t.Fatal("confirmed session ended")
	}
	// Confirmed sessions are not due again until the interval passes.
	if res := h.srv.Revalidate(ctx); res.Checked != 0 {
		t.Fatalf("re-checked at once: %+v", res)
	}

	// Sealed at rest: no refresh token, old or new, is in the session log
	// or the logs in the clear.
	raw, err := os.ReadFile(filepath.Join(h.dir, "sessions.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range append(first, second...) {
		if strings.Contains(string(raw), tok) || strings.Contains(h.logs.String(), tok) {
			t.Fatal("a refresh token is stored or logged in the clear")
		}
	}
	if !strings.Contains(string(raw), `"refresh":"`) {
		t.Fatalf("no sealed refresh token in the session log:\n%s", raw)
	}
	// The admin API never shows it.
	_, list := h.adminDo("GET", "/admin/sessions", "", "")
	if s := strings.ToLower(jsonString(t, list)); strings.Contains(s, "refresh") {
		t.Fatalf("admin API shows the refresh token: %s", s)
	}

	// The user is disabled at the provider: the next revalidation ends the
	// session.
	h.idp.EndSessions("alice")
	h.clk.Advance(61 * time.Second)
	if res := h.srv.Revalidate(ctx); res != (RevalidateResult{Checked: 1, Ended: 1}) {
		t.Fatalf("pass after the provider ended it: %+v", res)
	}
	if b.auth("/", nil).StatusCode != 401 {
		t.Fatal("refused session still signs in")
	}
	h.expectAudit("session_ended", "refresh_refused")
	m := h.metrics()
	for _, want := range []string{`wicket_revalidations_total{provider="corp",result="confirmed"} 1`,
		`wicket_revalidations_total{provider="corp",result="refused"} 1`,
		`wicket_sessions_ended_total{reason="refresh_refused"} 1`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestRevalidationFailureEnds(t *testing.T) {
	h := newHarness(t, revalidating(map[string]any{"interval": "1m", "on_failure": "end"}, false))
	b := h.browser()
	b.loginOIDC("alice", "alice-pass", "")
	h.idp.SetTokenEndpointDown(true)
	h.clk.Advance(61 * time.Second)
	if res := h.srv.Revalidate(context.Background()); res != (RevalidateResult{Checked: 1, Ended: 1}) {
		t.Fatalf("pass: %+v", res)
	}
	if b.auth("/", nil).StatusCode != 401 {
		t.Fatal("session outlived a failed revalidation under on_failure end")
	}
	h.expectAudit("session_ended", "refresh_failed")
}

func TestRevalidationGrace(t *testing.T) {
	h := newHarness(t, revalidating(map[string]any{"interval": "1m", "on_failure": "grace", "grace": "5m"}, false))
	ctx := context.Background()
	b := h.browser()
	b.loginOIDC("alice", "alice-pass", "")
	h.idp.SetTokenEndpointDown(true)

	// Inside the grace the session lives on, and is retried every pass.
	h.clk.Advance(61 * time.Second)
	if res := h.srv.Revalidate(ctx); res != (RevalidateResult{Checked: 1, Kept: 1}) {
		t.Fatalf("first failure: %+v", res)
	}
	h.clk.Advance(3 * time.Minute)
	if res := h.srv.Revalidate(ctx); res != (RevalidateResult{Checked: 1, Kept: 1}) {
		t.Fatalf("second failure: %+v", res)
	}
	if b.auth("/", nil).StatusCode != 200 {
		t.Fatal("session ended inside its grace")
	}
	// The provider comes back: confirmed, and the grace starts over.
	h.idp.SetTokenEndpointDown(false)
	if res := h.srv.Revalidate(ctx); res != (RevalidateResult{Checked: 1, Confirmed: 1}) {
		t.Fatalf("recovery: %+v", res)
	}
	h.idp.SetTokenEndpointDown(true)
	h.clk.Advance(61 * time.Second)
	if res := h.srv.Revalidate(ctx); res.Kept != 1 {
		t.Fatalf("after recovery: %+v", res)
	}
	// Past interval plus grace since the last confirmation: ended.
	h.clk.Advance(5 * time.Minute)
	if res := h.srv.Revalidate(ctx); res != (RevalidateResult{Checked: 1, Ended: 1}) {
		t.Fatalf("past the grace: %+v", res)
	}
	if b.auth("/", nil).StatusCode != 401 {
		t.Fatal("session outlived its grace")
	}
	h.expectAudit("session_ended", "refresh_failed")
	if !strings.Contains(h.metrics(), `wicket_revalidations_total{provider="corp",result="kept"} 3`) {
		t.Errorf("metrics:\n%s", h.metrics())
	}

	// A refusal ends a session even inside the grace.
	h.idp.SetTokenEndpointDown(false)
	b2 := h.browser()
	b2.loginOIDC("alice", "alice-pass", "")
	h.idp.EndSessions("alice")
	h.clk.Advance(61 * time.Second)
	if res := h.srv.Revalidate(ctx); res != (RevalidateResult{Checked: 1, Ended: 1}) {
		t.Fatalf("refusal inside the grace: %+v", res)
	}
}

func TestRevalidationWithoutAUsableToken(t *testing.T) {
	h := newHarness(t, revalidating(map[string]any{"interval": "1m"}, false))
	ctx := context.Background()
	alice := policy.Identity{Provider: "corp", Subject: "alice", Groups: []string{"eng"}}
	// No refresh token at all, one sealed for another user, and garbage.
	_, none, _ := h.sessions.CreateWithRefresh(alice, time.Time{}, "")
	_, moved, _ := h.sessions.CreateWithRefresh(alice, time.Time{}, h.srv.sealRefresh("corp", "bob", "rt-bob"))
	_, junk, _ := h.sessions.CreateWithRefresh(alice, time.Time{}, "not-a-sealed-value")
	// SAML sessions and providers without revalidation are left alone.
	_, saml, _ := h.sessions.Create(policy.Identity{Provider: "partner", Subject: "carol"}, time.Time{})
	h.clk.Advance(61 * time.Second)
	if res := h.srv.Revalidate(ctx); res != (RevalidateResult{Checked: 3, Ended: 3}) {
		t.Fatalf("pass: %+v", res)
	}
	for _, id := range []string{none.ID, moved.ID, junk.ID} {
		if ok, _ := h.sessions.Revoke(id); ok {
			t.Errorf("session %s survived", id)
		}
	}
	if ok, _ := h.sessions.Revoke(saml.ID); !ok {
		t.Error("a SAML session was ended")
	}
	h.expectAudit("session_ended", "no_refresh_token")
	h.expectAudit("session_ended", "refresh_token_unreadable")

	// Binding: a token opens only for the provider and subject it was
	// sealed for.
	sealed := h.srv.sealRefresh("corp", "alice", "rt-1")
	if tok, err := h.srv.openRefresh("corp", "alice", sealed); err != nil || tok != "rt-1" {
		t.Fatalf("open: %q %v", tok, err)
	}
	for _, who := range [][2]string{{"corp", "bob"}, {"other", "alice"}} {
		if _, err := h.srv.openRefresh(who[0], who[1], sealed); err == nil {
			t.Errorf("opened for %v", who)
		}
	}
	if _, err := h.srv.openRefresh("corp", "alice", h.srv.keys.Seal(purposeRefresh, []byte("short"))); err == nil {
		t.Error("opened a value without a binding")
	}
}

func TestRevalidationManySessionsAndCancel(t *testing.T) {
	h := newHarness(t, revalidating(map[string]any{"interval": "1m"}, false))
	const n = 12
	browsers := make([]*browser, n)
	for i := range browsers {
		browsers[i] = h.browser()
		browsers[i].loginOIDC("alice", "alice-pass", "")
	}
	h.clk.Advance(61 * time.Second)

	// A cancelled pass asks nothing and ends nothing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if res := h.srv.Revalidate(ctx); res.Confirmed != 0 || res.Ended != 0 {
		t.Fatalf("cancelled pass: %+v", res)
	}
	// Passes don't overlap.
	h.srv.revalMu.Lock()
	if res := h.srv.Revalidate(context.Background()); res != (RevalidateResult{}) {
		t.Fatalf("overlapping pass: %+v", res)
	}
	h.srv.revalMu.Unlock()

	if res := h.srv.Revalidate(context.Background()); res != (RevalidateResult{Checked: n, Confirmed: n}) {
		t.Fatalf("pass: %+v", res)
	}
	if got := len(h.idp.RefreshTokens("alice")); got != n {
		t.Fatalf("%d live tokens at the provider, want %d", got, n)
	}
	for i, b := range browsers {
		if b.auth("/", nil).StatusCode != 200 {
			t.Fatalf("browser %d signed out", i)
		}
	}
}

func TestRunRevalidation(t *testing.T) {
	h := newHarness(t, revalidating(map[string]any{"interval": "1m"}, false))
	b := h.browser()
	b.loginOIDC("alice", "alice-pass", "")
	h.idp.EndSessions("alice")
	h.clk.Advance(61 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.srv.RunRevalidation(ctx, 5*time.Millisecond); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for b.auth("/", nil).StatusCode != 401 {
		if time.Now().After(deadline) {
			t.Fatal("RunRevalidation never ended the refused session")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

func jsonString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
