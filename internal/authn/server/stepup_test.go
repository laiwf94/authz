package server

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/laiwf94/authz/internal/authn/fakeidp"
	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/enginetest"
)

// stepUpRules gives the whoami app a wiki whose admin area needs the
// admins group and a sign-in from the last ten minutes, a billing area
// that needs a second factor, and documents whose edits ask the engine
// and need a sign-in from the last five minutes.
func stepUpRules(cfg map[string]any) {
	app := cfg["apps"].([]any)[0].(map[string]any)
	app["allow"] = map[string]any{"any_user": true}
	app["public"] = []string{"/wiki"}
	app["paths"] = []any{
		map[string]any{"path": "/admin", "allow": map[string]any{"groups": []string{"admins"}},
			"step_up": map[string]any{"max_age": "10m"}},
		map[string]any{"path": "/billing", "allow": map[string]any{"any_user": true},
			"step_up": map[string]any{"acr_values": []string{fakeidp.ACRMFA}}},
		map[string]any{"path": "/docs/{id}", "methods": []string{"PUT"},
			"check":   map[string]any{"resource": "doc:{path.id}", "permission": "edit"},
			"step_up": map[string]any{"max_age": "5m"}},
	}
}

// authAt calls a forward-auth URL (with ?redirect=1, say) as nginx does.
func (b *browser) authAt(endpoint, path string, extra http.Header) (*http.Response, string) {
	b.h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, b.h.public+endpoint, nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", b.h.host)
	req.Header.Set("X-Forwarded-Uri", path)
	req.Header.Set("Accept", "text/html")
	for k, v := range extra {
		req.Header[k] = v
	}
	u, _ := url.Parse(b.h.public)
	for _, c := range b.jar.Cookies(u) {
		req.AddCookie(c)
	}
	resp, err := b.h.noRedirect().Do(req)
	if err != nil {
		b.h.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

// wantStepUp expects a step-up answer for path and returns its login URL.
func (b *browser) wantStepUp(path, rule, provider, challenge string) string {
	b.h.t.Helper()
	resp, body := b.authAt("/auth", path, nil)
	login := resp.Header.Get(HeaderRedirect)
	lu, _ := url.Parse(login)
	q := lu.Query()
	wa := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, `"step_up_required"`) ||
		!strings.Contains(wa, `error="insufficient_user_authentication"`) || !strings.Contains(wa, challenge) ||
		q.Get("step_up") != rule || q.Get("provider") != provider || q.Get("rd") != "https://"+b.h.host+path {
		b.h.t.Fatalf("%s: %d %s\nWWW-Authenticate: %s\nX-Auth-Redirect: %s\nlogs:\n%s", path, resp.StatusCode, body, wa, login, b.h.logs.String())
	}
	return login
}

// stepUpOIDC follows a login URL through the IdP's form, giving the
// one-time code when the form asks for it, and returns the callback's
// answer and the authorization request the IdP was sent.
func (b *browser) stepUpOIDC(login, user, pass, otp string) (*http.Response, string, url.Values) {
	b.h.t.Helper()
	resp, _ := b.get(login)
	if resp.StatusCode != http.StatusFound {
		b.h.t.Fatalf("login: %d", resp.StatusCode)
	}
	authURL, _ := url.Parse(resp.Header.Get("Location"))
	resp, body := b.get(authURL.String())
	if resp.StatusCode != http.StatusOK {
		b.h.t.Fatalf("authorize form: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(body, `name="otp"`) != (otp != "") {
		b.h.t.Fatalf("the form asks for a code: %v, want %v", otp == "", otp != "")
	}
	action, fields := formFields(body)
	fields.Set("username", user)
	fields.Set("password", pass)
	if otp != "" {
		fields.Set("otp", otp)
	}
	resp, body = b.post(action, fields)
	if resp.StatusCode != http.StatusFound {
		return resp, body, authURL.Query()
	}
	resp, body = b.get(resp.Header.Get("Location"))
	return resp, body, authURL.Query()
}

func sessionCookie(b *browser) string {
	u, _ := url.Parse(b.h.public)
	for _, c := range b.jar.Cookies(u) {
		if c.Name == "__Host-wicket" {
			return c.Value
		}
	}
	return ""
}

// TestStepUpMaxAge: a sign-in older than the rule's max_age is sent back
// to the provider with max_age, and returned to the request it made, query
// and all; the new session replaces the old.
func TestStepUpMaxAge(t *testing.T) {
	h := newHarness(t, harnessOpts{cfgMutate: stepUpRules})
	alice := h.browser()
	alice.loginOIDC("alice", "alice-pass", "")
	if resp := alice.auth("/admin/users", nil); resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderUser) != "alice" {
		t.Fatalf("fresh sign-in: %d", resp.StatusCode)
	}
	h.clk.Advance(10*time.Minute + time.Second)
	// Paths without a step-up are unaffected.
	if resp := alice.auth("/reports", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("/reports: %d", resp.StatusCode)
	}
	login := alice.wantStepUp("/admin/users?tab=keys", "paths[0]", "corp", `max_age="600"`)

	// A browser navigation with ?redirect=1 is redirected; a POST to the
	// same path gets the challenge, since its body cannot be replayed.
	if resp, _ := alice.authAt("/auth?redirect=1", "/admin/users?tab=keys", nil); resp.StatusCode != http.StatusFound ||
		resp.Header.Get("Location") != login {
		t.Fatalf("navigation: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := alice.authAt("/auth?redirect=1", "/admin/users", http.Header{"X-Forwarded-Method": {"POST"}}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST: %d", resp.StatusCode)
	}

	old := sessionCookie(alice)
	resp, body, asked := alice.stepUpOIDC(login, "alice", "alice-pass", "")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://"+h.host+"/admin/users?tab=keys" {
		t.Fatalf("callback: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	if asked.Get("max_age") != "600" || asked.Has("acr_values") {
		t.Fatalf("authorization request %v", asked)
	}
	if resp := alice.auth("/admin/users", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("after the step-up: %d", resp.StatusCode)
	}
	if sessionCookie(alice) == old {
		t.Fatal("the step-up kept the session")
	}
	stale := h.browser()
	u, _ := url.Parse(h.public)
	stale.jar.SetCookies(u, []*http.Cookie{{Name: "__Host-wicket", Value: old, Path: "/"}})
	if resp := stale.auth("/reports", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the old session still works: %d", resp.StatusCode)
	}

	// A user the rule refuses is refused, not asked to sign in again.
	bob := h.browser()
	bob.loginOIDC("bob", "bob-pass", "")
	h.clk.Advance(11 * time.Minute)
	if resp := bob.auth("/admin/users", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bob: %d", resp.StatusCode)
	}

	// Someone not signed in at all is asked for the step-up with the first
	// sign-in, so one login is enough.
	anon := h.browser()
	resp, _ = anon.authAt("/auth", "/admin", nil)
	if lu, _ := url.Parse(resp.Header.Get(HeaderRedirect)); resp.StatusCode != http.StatusUnauthorized || lu.Query().Get("step_up") != "paths[0]" {
		t.Fatalf("anonymous: %d %s", resp.StatusCode, resp.Header.Get(HeaderRedirect))
	}
	h.wantMetrics(`wicket_step_ups_total{reason="step_up_max_age"} 3`, `wicket_auth_decisions_total{decision="step_up"} 3`)
	if !strings.Contains(h.logs.String(), `"msg":"step-up required"`) || !strings.Contains(h.logs.String(), `"rule":"paths[0]"`) {
		t.Fatalf("the step-up is not logged:\n%s", h.logs.String())
	}
}

// TestStepUpACR: a rule that needs a class the sign-in lacks sends the
// user back with acr_values; the provider asks for the second factor.
func TestStepUpACR(t *testing.T) {
	h := newHarness(t, harnessOpts{cfgMutate: stepUpRules})
	alice := h.browser()
	alice.loginOIDC("alice", "alice-pass", "")
	login := alice.wantStepUp("/billing/invoices", "paths[1]", "corp", `acr_values="`+fakeidp.ACRMFA+`"`)
	resp, _, asked := alice.stepUpOIDC(login, "alice", "alice-pass", "246810")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://"+h.host+"/billing/invoices" {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	if asked.Get("acr_values") != fakeidp.ACRMFA || asked.Has("max_age") {
		t.Fatalf("authorization request %v", asked)
	}
	if resp := alice.auth("/billing/invoices", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("after the step-up: %d", resp.StatusCode)
	}
	// The class lasts as long as the session: an hour on, billing still
	// opens, while the admin area wants a recent sign-in again.
	h.clk.Advance(time.Hour)
	if resp := alice.auth("/billing", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("an hour on: %d", resp.StatusCode)
	}
	alice.wantStepUp("/admin", "paths[0]", "corp", `max_age="600"`)
	h.wantMetrics(`wicket_step_ups_total{reason="step_up_acr"} 1`)
}

// TestStepUpProviderIgnoresRequest: a provider that answers a step-up
// with an older or weaker sign-in than it was asked for does not get a
// session made, and the user is shown a page instead of being sent round
// again; their session stays as it was.
func TestStepUpProviderIgnoresRequest(t *testing.T) {
	h := newHarness(t, harnessOpts{cfgMutate: stepUpRules})
	alice := h.browser()
	alice.loginOIDC("alice", "alice-pass", "")
	before := sessionCookie(alice)

	h.idp.SetIgnore(false, true)
	login := alice.wantStepUp("/billing", "paths[1]", "corp", "acr_values=")
	resp, body, _ := alice.stepUpOIDC(login, "alice", "alice-pass", "")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "Sign-in failed") {
		t.Fatalf("weak answer: %d %s", resp.StatusCode, body)
	}
	h.expectAudit("login_failed", "step_up_not_satisfied")
	if sessionCookie(alice) != before {
		t.Fatal("the refused step-up changed the session")
	}
	if resp := alice.auth("/reports", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("the session no longer works: %d", resp.StatusCode)
	}

	h.idp.SetIgnore(true, false)
	h.clk.Advance(11 * time.Minute)
	login = alice.wantStepUp("/admin", "paths[0]", "corp", `max_age="600"`)
	resp, _, _ = alice.stepUpOIDC(login, "alice", "alice-pass", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("stale answer: %d", resp.StatusCode)
	}
	if n := h.auditCount("login_failed", "step_up_not_satisfied"); n != 2 {
		t.Fatalf("%d refused step-ups audited", n)
	}
	if !strings.Contains(h.logs.String(), "step_up_max_age: the provider's answer does not meet max_age") {
		t.Fatalf("the refusal does not say why:\n%s", h.logs.String())
	}
}

// TestStepUpLoop: a session made by a step-up that at once fails the rule
// it was made for (here because a reload made the rule stricter under
// the login) is refused rather than sent round again, until the loop
// window has passed.
func TestStepUpLoop(t *testing.T) {
	var cfg map[string]any
	h := newHarness(t, harnessOpts{cfgMutate: func(c map[string]any) { stepUpRules(c); cfg = c }})
	alice := h.browser()
	alice.loginOIDC("alice", "alice-pass", "")
	h.clk.Advance(11 * time.Minute)
	login := alice.wantStepUp("/admin", "paths[0]", "corp", `max_age="600"`)
	if resp, _, _ := alice.stepUpOIDC(login, "alice", "alice-pass", ""); resp.StatusCode != http.StatusFound {
		t.Fatalf("step-up: %d", resp.StatusCode)
	}
	rule := cfg["apps"].([]any)[0].(map[string]any)["paths"].([]any)[0].(map[string]any)
	rule["step_up"] = map[string]any{"max_age": "10m", "acr_values": []string{fakeidp.ACRMFA}}
	h.writeConfig(cfg)
	if err := h.srv.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, body := alice.authAt("/auth?redirect=1", "/admin", nil)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(HeaderRedirect) != "" {
		t.Fatalf("loop: %d %s", resp.StatusCode, body)
	}
	h.expectAudit("access_denied", "step_up_loop")
	resp, body = alice.authAt("/auth", "/admin", http.Header{"Accept": {"application/json"}})
	if !strings.Contains(body, "the identity provider did not give the sign-in this page needs") {
		t.Fatalf("API loop answer: %d %s", resp.StatusCode, body)
	}
	h.clk.Advance(time.Minute)
	alice.wantStepUp("/admin", "paths[0]", "corp", `acr_values="`+fakeidp.ACRMFA+`"`)

	// A login link naming a rule the app no longer has is refused.
	resp, body = alice.get(h.public + "/login?app=whoami&provider=corp&step_up=paths[9]")
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Sign-in link out of date") {
		t.Fatalf("unknown rule: %d %s", resp.StatusCode, body)
	}
}

// TestStepUpBeforeCheck: a relationship rule with a step-up sends a stale
// sign-in to sign in again before asking the engine.
func TestStepUpBeforeCheck(t *testing.T) {
	h := newHarness(t, harnessOpts{cfgMutate: stepUpRules})
	f, err := enginetest.NewFake(docsSchema, "doc:plan#editor@user:alice")
	if err != nil {
		t.Fatal(err)
	}
	eng := &checkEngine{Engine: f}
	h.srv.opts.Engine = func(context.Context) (engine.Engine, error) { return eng, nil }
	alice := h.browser()
	alice.loginOIDC("alice", "alice-pass", "")
	put := http.Header{"X-Forwarded-Method": {"PUT"}}
	if resp := alice.auth("/docs/plan", put); resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh: %d", resp.StatusCode)
	}
	h.clk.Advance(6 * time.Minute)
	resp, _ := alice.authAt("/auth", "/docs/plan", put)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `max_age="300"`) {
		t.Fatalf("stale: %d", resp.StatusCode)
	}
	eng.mu.Lock()
	n := len(eng.seen)
	eng.mu.Unlock()
	if n != 1 {
		t.Fatalf("the engine was asked %d times", n)
	}
}

// TestStepUpSAML: a SAML user steps up with ForceAuthn for age and a
// RequestedAuthnContext for a class, and the AuthnInstant and class ref
// of the answer decide.
func TestStepUpSAML(t *testing.T) {
	h := newHarness(t, harnessOpts{cfgMutate: stepUpRules})
	alice := h.browser()
	if resp := alice.loginSAML("alice", "alice-pass"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("SAML login: %d", resp.StatusCode)
	}
	if resp := alice.auth("/admin", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh SAML sign-in: %d", resp.StatusCode)
	}
	login := alice.wantStepUp("/billing", "paths[1]", "partner", "acr_values=")
	resp, _ := alice.get(login)
	sso := resp.Header.Get("Location")
	req := samlRequest(t, sso)
	if req.SelectAttr("ForceAuthn") != nil || req.FindElement(".//AuthnContextClassRef").Text() != fakeidp.ACRMFA {
		t.Fatalf("class step-up request: ForceAuthn %v", req.SelectAttr("ForceAuthn"))
	}
	resp, body := alice.get(sso)
	action, fields := formFields(body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `name="otp"`) {
		t.Fatalf("SSO form: %d", resp.StatusCode)
	}
	fields.Set("username", "alice")
	fields.Set("password", "alice-pass")
	fields.Set("otp", "246810")
	_, body = alice.post(action, fields)
	acs, form := formFields(body)
	resp, _ = alice.post(acs, form)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "https://"+h.host+"/billing" {
		t.Fatalf("ACS: %d %s\n%s", resp.StatusCode, resp.Header.Get("Location"), h.logs.String())
	}
	if resp := alice.auth("/billing", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("after the SAML step-up: %d", resp.StatusCode)
	}
	h.clk.Advance(11 * time.Minute)
	login = alice.wantStepUp("/admin", "paths[0]", "partner", `max_age="600"`)
	resp, _ = alice.get(login)
	if req := samlRequest(t, resp.Header.Get("Location")); req.SelectAttrValue("ForceAuthn", "") != "true" || req.FindElement(".//RequestedAuthnContext") != nil {
		t.Fatal("age step-up request does not force authentication")
	}
}

func samlRequest(t *testing.T, sso string) *etree.Element {
	t.Helper()
	u, err := url.Parse(sso)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	b, _ := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(b); err != nil {
		t.Fatalf("%v: %s", err, sso)
	}
	return doc.Root()
}
