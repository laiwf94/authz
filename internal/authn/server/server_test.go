package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/config"
	"github.com/laiwf94/authz/internal/authn/policy"
	"github.com/laiwf94/authz/internal/authn/session"
	"github.com/laiwf94/authz/internal/platform/jose"
	"github.com/laiwf94/authz/internal/platform/seal"
)

func TestForwardAuthModes(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	c := h.noRedirect()
	call := func(path string, hdr map[string]string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, h.public+path, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	// nginx with X-Original-URL.
	resp := call("/auth", map[string]string{"X-Original-URL": h.public + "/a?b=1"})
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get(HeaderRedirect), url.QueryEscape(h.public+"/a?b=1")) {
		t.Fatalf("X-Original-URL: %d %s", resp.StatusCode, resp.Header.Get(HeaderRedirect))
	}
	// Traefik: redirect mode sends browsers straight to the login page...
	resp = call("/auth?redirect=1", map[string]string{"X-Forwarded-Host": h.host, "X-Forwarded-Uri": "/x", "Accept": "text/html", "X-Forwarded-Method": "GET"})
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), h.public+"/login?") {
		t.Fatalf("traefik browser: %d", resp.StatusCode)
	}
	// ...but API calls, scripts and POSTs get 401 JSON.
	for _, hdr := range []map[string]string{
		{"X-Forwarded-Host": h.host, "Accept": "application/json"},
		{"X-Forwarded-Host": h.host, "Accept": "text/html", "X-Requested-With": "XMLHttpRequest"},
		{"X-Forwarded-Host": h.host, "Accept": "text/html", "X-Forwarded-Method": "POST"},
	} {
		if resp := call("/auth?redirect=1", hdr); resp.StatusCode != 401 || resp.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("API call %v: %d", hdr, resp.StatusCode)
		}
	}
	// Envoy ext_authz: original path appended, Host kept, redirect for browsers.
	req, _ := http.NewRequest(http.MethodGet, h.public+"/auth/envoy/docs/page?q=1", nil)
	req.Header.Set("Accept", "text/html")
	resp, _ = c.Do(req)
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc.Query().Get("rd") != h.public+"/docs/page?q=1" {
		t.Fatalf("envoy: %d %s", resp.StatusCode, loc)
	}
	// Unknown host: default deny.
	if resp := call("/auth", map[string]string{"X-Forwarded-Host": "unknown.example.com"}); resp.StatusCode != 403 {
		t.Fatalf("unknown app: %d", resp.StatusCode)
	}
	if resp := call("/auth", nil); resp.StatusCode != 403 {
		t.Fatalf("no host: %d", resp.StatusCode)
	}
	// An app chosen explicitly; an original URL outside the allow-list
	// is not used as the return address.
	resp = call("/auth?app=open", map[string]string{"X-Forwarded-Host": "evil.com", "X-Forwarded-Uri": "/x"})
	if resp.StatusCode != 401 || strings.Contains(resp.Header.Get(HeaderRedirect), "evil.com") {
		t.Fatalf("explicit app: %d %s", resp.StatusCode, resp.Header.Get(HeaderRedirect))
	}

	// Signed in: works through every mode, and HEAD too.
	b.loginOIDC("alice", "alice-pass", "")
	cookies := b.jar.Cookies(&url.URL{Scheme: "https", Host: h.host})
	req, _ = http.NewRequest(http.MethodGet, h.public+"/auth/envoy/", nil)
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	if resp, _ := c.Do(req); resp.StatusCode != 200 || resp.Header.Get(HeaderUser) != "alice" {
		t.Fatalf("envoy signed in: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodHead, h.public+"/auth", nil)
	req.Header.Set("X-Forwarded-Host", h.host)
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	if resp, _ := c.Do(req); resp.StatusCode != 200 {
		t.Fatalf("HEAD: %d", resp.StatusCode)
	}
	// The other app accepts any user of its provider; host:443 maps to it.
	if resp := b.auth("/", http.Header{"X-Forwarded-Host": {"open.example.com:443"}}); resp.StatusCode != 200 {
		t.Fatalf("open app: %d", resp.StatusCode)
	}
}

func TestSessionCookieAttacks(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.loginOIDC("alice", "alice-pass", "")
	u := &url.URL{Scheme: "https", Host: h.host}
	var sess *http.Cookie
	for _, c := range b.jar.Cookies(u) {
		if c.Name == "__Host-wicket" {
			sess = c
		}
	}
	if sess == nil {
		t.Fatal("no session cookie")
	}
	try := func(value string) int {
		req, _ := http.NewRequest(http.MethodGet, h.public+"/auth", nil)
		req.Header.Set("X-Forwarded-Host", h.host)
		req.AddCookie(&http.Cookie{Name: "__Host-wicket", Value: value})
		resp, err := h.noRedirect().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if try(sess.Value) != 200 {
		t.Fatal("genuine cookie refused")
	}
	tampered := []byte(sess.Value)
	tampered[len(tampered)/2] ^= 1
	logoutTok := h.srv.keys.Seal(purposeLogout, []byte("x"))
	foreign, _ := seal.New([][]byte{seal.RandomKey()})
	for name, v := range map[string]string{
		"tampered":                    string(tampered),
		"garbage":                     "not-a-cookie",
		"other purpose":               logoutTok,
		"sealed with an unknown key":  foreign.Seal(purposeSession, []byte("anything")),
		"valid seal, unknown session": h.srv.keys.Seal(purposeSession, []byte("guessed-secret")),
	} {
		if code := try(v); code != 401 {
			t.Errorf("%s: %d", name, code)
		}
	}
	// Expiry: idle, then absolute.
	h.clk.Advance(9 * time.Hour)
	if try(sess.Value) != 401 {
		t.Fatal("idle-expired session accepted")
	}
}

func TestKeyRotation(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.loginOIDC("alice", "alice-pass", "")
	newKey := seal.RandomKey()
	// During rotation the new key goes first and the old one still opens.
	both, _ := seal.New([][]byte{newKey, h.cookieKey})
	h.srv.keys = both
	if resp := b.auth("/", nil); resp.StatusCode != 200 {
		t.Fatalf("cookie from the previous key during rotation: %d", resp.StatusCode)
	}
	// Then the old key is removed; cookies sealed with it stop working.
	only, _ := seal.New([][]byte{newKey})
	h.srv.keys = only
	if resp := b.auth("/", nil); resp.StatusCode != 401 {
		t.Fatalf("cookie from a rotated-out key: %d", resp.StatusCode)
	}
}

func TestLoginValidation(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	cases := []struct {
		path   string
		status int
		want   string
	}{
		{"/login?app=ghost", 400, "Unknown application"},
		{"/login?app=whoami&rd=https://evil.com/", 400, "Return address not allowed"},
		{"/login?app=whoami&rd=//evil.com", 400, "Return address not allowed"},
		{"/login?app=whoami&rd=https://whoami@evil.com", 400, "Return address not allowed"},
		{"/login?app=whoami&provider=ghost", 400, "Sign-in option not available"},
		{"/login?app=whoami", 200, "Choose how you want to sign in"},
	}
	for _, c := range cases {
		resp, body := b.get(h.public + c.path)
		if resp.StatusCode != c.status || !strings.Contains(body, c.want) {
			t.Errorf("%s: %d %s", c.path, resp.StatusCode, body)
		}
	}
	_, body := b.get(h.public + "/login?app=whoami&rd=" + url.QueryEscape("https://app.example.com/x"))
	if !strings.Contains(body, "Corp SSO") || !strings.Contains(body, "Partner SAML") || !strings.Contains(body, "provider=partner") {
		t.Fatalf("chooser: %s", body)
	}
	// A single-provider app skips the chooser.
	resp, _ := b.get(h.public + "/login?app=open")
	if resp.StatusCode != 302 {
		t.Fatalf("single provider: %d", resp.StatusCode)
	}
	h.expectAudit("login_rejected", "return_url_not_allowed")
}

func TestCallbackAttacks(t *testing.T) {
	h := newHarness(t, harnessOpts{})

	// Start a login and capture the provider's redirect back without
	// following it.
	start := func(b *browser) (callback string) {
		resp, body := b.get(h.public + "/login?app=whoami&provider=corp")
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("login: %d %s\n%s", resp.StatusCode, body, h.logs.String())
		}
		resp, body = b.get(resp.Header.Get("Location"))
		action, fields := formFields(body)
		fields.Set("username", "alice")
		fields.Set("password", "alice-pass")
		resp, _ = b.post(action, fields)
		return resp.Header.Get("Location")
	}
	expectFail := func(b *browser, u, reason string) {
		t.Helper()
		resp, body := b.get(u)
		if resp.StatusCode < 400 || !strings.Contains(body, "Sign-in failed") {
			t.Fatalf("%s: %d", reason, resp.StatusCode)
		}
		h.expectAudit("login_failed", reason)
	}

	// Login CSRF: the callback arrives in a browser that never started it.
	victim := h.browser()
	expectFail(victim, start(h.browser()), "state_cookie_missing")

	// Swapped code: the attacker's code injected into the victim's own
	// flow. The state matches the victim's, but PKCE binds the code to the
	// attacker's verifier, so the provider refuses it.
	attackerCB, _ := url.Parse(start(h.browser()))
	victim = h.browser()
	victimCB, _ := url.Parse(start(victim))
	q := victimCB.Query()
	q.Set("code", attackerCB.Query().Get("code"))
	victimCB.RawQuery = q.Encode()
	expectFail(victim, victimCB.String(), "token_exchange_failed")

	// Replay: the same callback twice.
	b := h.browser()
	cb := start(b)
	saved := b.jar.Cookies(&url.URL{Scheme: "https", Host: h.host})
	if resp, _ := b.get(cb); resp.StatusCode != 302 {
		t.Fatal("first callback should succeed")
	}
	b2 := h.browser()
	b2.jar.SetCookies(&url.URL{Scheme: "https", Host: h.host}, saved)
	expectFail(b2, cb, "state_replayed")

	// State tampering: cookie for one state, URL with another.
	b = h.browser()
	cb = start(b)
	cbu, _ := url.Parse(cb)
	q = cbu.Query()
	q.Set("state", q.Get("state")+"x")
	cbu.RawQuery = q.Encode()
	expectFail(b, cbu.String(), "state_cookie_missing")

	// The login took too long.
	b = h.browser()
	cb = start(b)
	h.clk.Advance(11 * time.Minute)
	expectFail(b, cb, "login_expired")
	h.clk.Advance(-11 * time.Minute)

	// The provider reports an error.
	b = h.browser()
	cbu, _ = url.Parse(start(b))
	q = cbu.Query()
	q.Del("code")
	q.Set("error", "access_denied")
	cbu.RawQuery = q.Encode()
	expectFail(b, cbu.String(), "idp_error")

	// A callback for the SAML provider's id with OIDC state.
	b = h.browser()
	cbu, _ = url.Parse(start(b))
	cbu.Path = "/callback/partner"
	expectFail(b, cbu.String(), "state_wrong_provider")

	// No state at all.
	expectFail(h.browser(), h.public+"/callback/corp?code=x", "state_missing")
}

func TestSAMLACSAttacks(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	acs, form := b.samlResponseFor("carol", "carol-pass")
	saved := b.jar.Cookies(&url.URL{Scheme: "https", Host: h.host})
	if resp, _ := b.post(acs, form); resp.StatusCode != 303 {
		t.Fatal("first post should succeed")
	}
	// Replaying the captured POST, even with the login cookie, fails.
	b2 := h.browser()
	b2.jar.SetCookies(&url.URL{Scheme: "https", Host: h.host}, saved)
	if resp, _ := b2.post(acs, form); resp.StatusCode != 400 {
		t.Fatalf("replayed ACS post: %d", resp.StatusCode)
	}
	h.expectAudit("login_failed", "state_replayed")

	// The response posted into a browser that never asked (login CSRF).
	acs, form = h.browser().samlResponseFor("carol", "carol-pass")
	if resp, _ := h.browser().post(acs, form); resp.StatusCode != 400 {
		t.Fatal("unsolicited post accepted")
	}
	h.expectAudit("login_failed", "state_cookie_missing")

	// A response whose signature is broken.
	b = h.browser()
	acs, form = b.samlResponseFor("carol", "carol-pass")
	form.Set("SAMLResponse", "PHNhbWxwOlJlc3BvbnNlLz4=")
	if resp, _ := b.post(acs, form); resp.StatusCode != 400 {
		t.Fatal("bad response accepted")
	}
	h.expectAudit("login_failed", "malformed_response")

	// Not a form post.
	req, _ := http.NewRequest(http.MethodPost, acs, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if resp := b.do(req); resp.StatusCode != 400 {
		t.Fatal("JSON to ACS accepted")
	}
	req, _ = http.NewRequest(http.MethodPost, acs, strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp := b.do(req); resp.StatusCode != 400 {
		t.Fatal("bad form accepted")
	}
	// SP metadata.
	resp, body := b.get(h.public + "/saml/partner/metadata")
	if resp.StatusCode != 200 || !strings.Contains(body, h.public+"/saml/partner/acs") {
		t.Fatalf("metadata: %d", resp.StatusCode)
	}
	if resp, _ := b.get(h.public + "/saml/corp/metadata"); resp.StatusCode != 404 {
		t.Fatal("metadata for an OIDC provider")
	}
}

func TestPendingLoginCookiesBounded(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	count := func() int {
		n := 0
		for _, c := range b.jar.Cookies(&url.URL{Scheme: "https", Host: h.host}) {
			if strings.HasPrefix(c.Name, loginCookiePrefix) {
				n++
			}
		}
		return n
	}
	for i := 1; i <= maxLoginCookies; i++ {
		b.get(h.public + "/login?app=whoami&provider=corp")
		if count() != i {
			t.Fatalf("after %d logins: %d cookies", i, count())
		}
	}
	b.get(h.public + "/login?app=whoami&provider=corp")
	if count() != 1 {
		t.Fatalf("pending login cookies not bounded: %d", count())
	}
}

func TestSessionFixationAndReplace(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.loginOIDC("alice", "alice-pass", "")
	first := h.sessions.List("alice", 0)
	b.loginOIDC("alice", "alice-pass", "")
	second := h.sessions.List("alice", 0)
	if len(first) != 1 || len(second) != 1 || first[0].ID == second[0].ID {
		t.Fatalf("a new login must replace the session: %v %v", first, second)
	}
}

func TestLogoutEdges(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	// No session: GET shows "signed out", POST just clears.
	if _, body := b.get(h.public + "/logout"); !strings.Contains(body, "You are signed out") {
		t.Fatal("logout page without session")
	}
	if resp, _ := b.post(h.public+"/logout", url.Values{}); resp.StatusCode != 303 {
		t.Fatal("logout without session")
	}
	b.loginSAML("carol", "carol-pass")
	_, page := b.get(h.public + "/logout?rd=" + url.QueryEscape("https://app.example.com/bye"))
	action, form := formFields(page)

	// Cross-origin POST refused even with the token.
	req, _ := http.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.com")
	if resp := b.do(req); resp.StatusCode != 403 {
		t.Fatalf("cross-origin logout: %d", resp.StatusCode)
	}
	// Wrong or missing token refused.
	if resp, _ := b.post(action, url.Values{"csrf": {"forged"}}); resp.StatusCode != 403 {
		t.Fatal("forged token")
	}
	h.expectAudit("logout_rejected", "csrf_token_invalid")
	// Wrong content type.
	req, _ = http.NewRequest(http.MethodPost, action, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if resp := b.do(req); resp.StatusCode != 415 {
		t.Fatal("JSON logout")
	}
	// Regression: refused logouts must leave the browser signed in.
	if resp := b.auth("/", nil); resp.StatusCode != 200 {
		t.Fatalf("a refused logout signed the browser out: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", h.public)
	resp := b.do(req)
	// SAML logout is local; the browser goes to the validated return URL.
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "https://app.example.com/bye" {
		t.Fatalf("SAML logout: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, body := b.get(h.public + "/logged-out"); !strings.Contains(body, "signed out") {
		t.Fatal("logged-out page")
	}
}

func TestAdminAPI(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.loginOIDC("alice", "alice-pass", "")
	b2 := h.browser()
	b2.loginSAML("carol", "carol-pass")

	if resp, out := h.adminDo("GET", "/admin/sessions", "", ""); resp.StatusCode != 200 || len(out["sessions"].([]any)) != 2 {
		t.Fatalf("list: %v", out)
	}
	if _, out := h.adminDo("GET", "/admin/sessions?subject=nobody", "", ""); len(out["sessions"].([]any)) != 0 {
		t.Fatal("filtered list")
	}
	for _, q := range []string{"?limit=0", "?limit=x", "?subject=" + strings.Repeat("s", 600)} {
		if resp, _ := h.adminDo("GET", "/admin/sessions"+q, "", ""); resp.StatusCode != 400 {
			t.Errorf("%s: %d", q, resp.StatusCode)
		}
	}
	if resp, _ := h.adminDo("DELETE", "/admin/sessions/zz", "", ""); resp.StatusCode != 400 {
		t.Fatal("bad id")
	}
	if resp, _ := h.adminDo("DELETE", "/admin/sessions/"+strings.Repeat("a", 32), "", ""); resp.StatusCode != 404 {
		t.Fatal("unknown id")
	}
	for _, body := range []string{"", `{"subject":""}`, `{"subject":"a","x":1}`, `{"subject":"a"} {}`, `nope`} {
		if resp, _ := h.adminDo("POST", "/admin/sessions/revoke", "", body); resp.StatusCode != 400 {
			t.Errorf("revoke body %q: %d", body, resp.StatusCode)
		}
	}
	resp, out := h.adminDo("POST", "/admin/sessions/revoke", "", `{"subject":"carol@partner.example","provider":"partner"}`)
	if resp.StatusCode != 200 || out["revoked"].(float64) != 1 {
		t.Fatalf("revoke subject: %v", out)
	}
	if b2.auth("/", nil).StatusCode != 401 || b.auth("/", nil).StatusCode != 200 {
		t.Fatal("revoking carol must not touch alice")
	}

	// Metrics and health.
	req, _ := http.NewRequest("GET", h.admin.URL+"/metrics", nil)
	mresp, _ := http.DefaultClient.Do(req)
	mbody, _ := io.ReadAll(mresp.Body)
	mresp.Body.Close()
	for _, want := range []string{`wicket_logins_total{result="success"`, `wicket_auth_decisions_total{decision="allowed"}`, "wicket_sessions 1", "wicket_http_request_duration_seconds_bucket"} {
		if !strings.Contains(string(mbody), want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	if resp, _ := h.adminDo("GET", "/healthz", "", ""); resp.StatusCode != 200 {
		t.Fatal("admin health")
	}
	if resp, _ := h.adminDo("GET", "/nope", "", ""); resp.StatusCode != 404 {
		t.Fatal("admin 404")
	}
}

func TestReload(t *testing.T) {
	var cfg map[string]any
	h := newHarness(t, harnessOpts{cfgMutate: func(c map[string]any) { cfg = c }})
	b := h.browser()
	b.loginOIDC("bob", "bob-pass", "")
	if b.auth("/", nil).StatusCode != 403 {
		t.Fatal("bob starts without access")
	}
	// Grant bob's group and reload: the existing session now passes.
	cfg["apps"].([]any)[0].(map[string]any)["allow"] = map[string]any{"groups": []string{"eng", "sales"}}
	h.writeConfig(cfg)
	resp, out := h.adminDo("POST", "/admin/reload", "", "")
	if resp.StatusCode != 200 || out["apps"].(float64) != 2 {
		t.Fatalf("reload: %d %v", resp.StatusCode, out)
	}
	if b.auth("/", nil).StatusCode != 200 {
		t.Fatal("reload did not apply")
	}
	// A broken file is refused and the running configuration stays.
	os.WriteFile(h.cfgPath, []byte(`{"public_url":"http://x"}`), 0o600)
	if resp, _ := h.adminDo("POST", "/admin/reload", "", ""); resp.StatusCode != 400 {
		t.Fatal("bad config accepted")
	}
	if b.auth("/", nil).StatusCode != 200 {
		t.Fatal("bad reload changed the running configuration")
	}
	h.expectAudit("config_load_failed", "")

	// Removing the provider in the middle of a login fails that login
	// cleanly.
	b3 := h.browser()
	resp2, _ := b3.get(h.public + "/login?app=whoami&provider=corp")
	resp2, body := b3.get(resp2.Header.Get("Location"))
	action, fields := formFields(body)
	fields.Set("username", "alice")
	fields.Set("password", "alice-pass")
	resp2, _ = b3.post(action, fields)
	cb := resp2.Header.Get("Location")
	cfg["providers"] = cfg["providers"].([]any)[1:]
	cfg["apps"] = []any{map[string]any{"id": "whoami", "hosts": []string{h.host}, "providers": []string{"partner"}, "allow": map[string]any{"any_user": true}}}
	h.writeConfig(cfg)
	if err := h.srv.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resp, _ := b3.get(cb); resp.StatusCode != 400 {
		t.Fatalf("callback for a removed provider: %d", resp.StatusCode)
	}
	h.expectAudit("login_failed", "provider_removed")
	// bob's OIDC session is no longer accepted: corp isn't an app provider.
	if b.auth("/", nil).StatusCode != 403 {
		t.Fatal("session from a removed provider still accepted")
	}
}

func TestRateLimitAndHeaders(t *testing.T) {
	h := newHarness(t, harnessOpts{loginRate: 3})
	b := h.browser()
	var last *http.Response
	for i := 0; i < 4; i++ {
		last, _ = b.get(h.public + "/login?app=ghost")
	}
	if last.StatusCode != 429 || last.Header.Get("Retry-After") == "" {
		t.Fatalf("rate limit: %d", last.StatusCode)
	}
	resp, _ := b.get(h.public + "/healthz")
	for _, hd := range []string{"Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security", "Referrer-Policy", "X-Request-Id"} {
		if resp.Header.Get(hd) == "" {
			t.Errorf("missing %s", hd)
		}
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("CSP")
	}
	req, _ := http.NewRequest("GET", h.public+"/healthz", nil)
	req.Header.Set("X-Request-Id", "trace-123")
	if resp := b.do(req); resp.Header.Get("X-Request-Id") != "trace-123" {
		t.Error("request id not propagated")
	}
	req.Header.Set("X-Request-Id", "bad id with spaces")
	if resp := b.do(req); resp.Header.Get("X-Request-Id") == "bad id with spaces" {
		t.Error("unsafe request id echoed")
	}
	if resp, _ := b.get(h.public + "/nope"); resp.StatusCode != 404 {
		t.Error("404")
	}
	if _, body := b.get(h.public + "/.well-known/jwks.json"); !strings.Contains(body, `"kid":"`+h.signer.KeyID()+`"`) {
		t.Error("jwks")
	}
}

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		remote, xff, want string
	}{
		{"1.2.3.4:5", "9.9.9.9", "1.2.3.4"},            // untrusted peer: header ignored
		{"10.0.0.1:5", "9.9.9.9", "9.9.9.9"},           // trusted proxy
		{"10.0.0.1:5", "6.6.6.6, 9.9.9.9", "9.9.9.9"},  // rightmost untrusted wins
		{"10.0.0.1:5", "9.9.9.9, 10.0.0.2", "9.9.9.9"}, // skip trusted hops
		{"10.0.0.1:5", "garbage", "10.0.0.1"},          // unparsable header
		{"[::ffff:1.2.3.4]:5", "", "1.2.3.4"},          // mapped address
		{"not-an-addr", "", "not-an-addr"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r, trusted); got != c.want {
			t.Errorf("%s %q: got %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	l := newRateLimiter(60, c.Now)
	for i := 0; i < 60; i++ {
		if _, ok := l.allow("a"); !ok {
			t.Fatalf("burst refused at %d", i)
		}
	}
	wait, ok := l.allow("a")
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("over the limit: %v %v", ok, wait)
	}
	if _, ok := l.allow("b"); !ok {
		t.Fatal("limits are per client")
	}
	// Regression: a clock stepping backwards once drained buckets.
	c.Advance(-time.Hour)
	if _, ok := l.allow("b"); !ok {
		t.Fatal("clock step backwards drained the bucket")
	}
	c.Advance(time.Hour)
	c.Advance(time.Second)
	if _, ok := l.allow("a"); !ok {
		t.Fatal("refill")
	}
	c.Advance(2 * time.Minute)
	l.sweep()
	if l.lim.Len() != 0 {
		t.Fatal("sweep keeps full buckets")
	}
}

// fillBuckets fills the limiter to maxBuckets. Bucket i was last used i
// microseconds ago and holds the given number of tokens.
func fillBuckets(l *rateLimiter, now time.Time, tokens float64) {
	for i := 0; i < maxBuckets; i++ {
		l.lim.Set(strconv.Itoa(i), l.limit, tokens, now.Add(-time.Duration(i)*time.Microsecond))
	}
}

func TestRateLimiterEvictsIdleBuckets(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	l := newRateLimiter(60, c.Now)
	fillBuckets(l, c.Now(), l.burst)
	if l.lim.Len() != maxBuckets {
		t.Fatalf("filled %d buckets, want %d", l.lim.Len(), maxBuckets)
	}
	if _, ok := l.allow("new"); !ok {
		t.Fatal("new client refused")
	}
	if l.lim.Len() != 1 {
		t.Fatalf("idle buckets kept: %d", l.lim.Len())
	}
}

func TestRateLimiterEvictsOldestHalfWhenAllActive(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	l := newRateLimiter(60, c.Now)
	fillBuckets(l, c.Now(), 0)
	if _, ok := l.allow("new"); !ok {
		t.Fatal("new client refused")
	}
	if n := l.lim.Len(); n >= maxBuckets || n < maxBuckets/2 {
		t.Fatalf("after eviction: %d buckets", n)
	}
	if _, ok := l.lim.Tokens("0", l.limit); !ok {
		t.Error("most recent client forgotten")
	}
	if _, ok := l.lim.Tokens(strconv.Itoa(maxBuckets-1), l.limit); ok {
		t.Error("oldest client kept")
	}
	if b, ok := l.lim.Tokens("new", l.limit); !ok || b != l.burst-1 {
		t.Errorf("new client bucket: %+v", b)
	}
}

func TestUpstreamTokenCache(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.loginOIDC("alice", "alice-pass", "")
	t1 := b.auth("/", nil).Header.Get(HeaderToken)
	if t2 := b.auth("/", nil).Header.Get(HeaderToken); t1 != t2 {
		t.Fatal("token should be reused within half its lifetime")
	}
	h.clk.Advance(61 * time.Second)
	if t3 := b.auth("/", nil).Header.Get(HeaderToken); t3 == t1 {
		t.Fatal("token not refreshed")
	}
	h.srv.Sweep()
}

func TestHeaderValue(t *testing.T) {
	for in, want := range map[string]string{"plain": "plain", "a,b": "a%2Cb", "50%": "50%25", "é": "%C3%A9", "a\nb": "a%0Ab"} {
		if got := headerValue(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	if displayUser(&session.Session{Identity: policy.Identity{Subject: "s"}}) != "s" {
		t.Error("displayUser")
	}
	if printableASCII("a\x00béc", 2) != "ab" {
		t.Error("printableASCII")
	}
	if originalURL(httptest.NewRequest("GET", "/", nil)) != nil {
		t.Error("no forwarded host")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Original-URL", "not a url %%")
	r.Header.Set("X-Forwarded-Host", "h.example.com")
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("X-Forwarded-Uri", "relative")
	if u := originalURL(r); u == nil || u.String() != "http://h.example.com/" {
		t.Errorf("fallback: %v", u)
	}
	r.Header.Set("X-Forwarded-Host", "bad host")
	r.Header.Del("X-Original-URL")
	if originalURL(r) != nil {
		t.Error("bad host")
	}
}

func TestNewValidation(t *testing.T) {
	keys, _ := seal.New([][]byte{seal.RandomKey()})
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sg, _ := jose.NewSigner(ek)
	st, _ := session.Open(session.Options{})
	if _, err := New(Options{}); err == nil {
		t.Error("empty options")
	}
	if _, err := New(Options{Load: func() (*config.Config, error) { return nil, errors.New("x") }, Sessions: st, Keys: keys,
		Signers: []*jose.Signer{sg}, AdminToken: "short"}); err == nil {
		t.Error("short admin token")
	}
	if _, err := New(Options{Load: func() (*config.Config, error) { return nil, errors.New("boom") }, Sessions: st, Keys: keys,
		Signers: []*jose.Signer{sg}, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}); err == nil {
		t.Error("failing load")
	}
}

func TestRuntimeBuildErrors(t *testing.T) {
	dir := t.TempDir()
	base := func() *config.Config {
		b, _ := json.Marshal(map[string]any{
			"public_url": "https://gw.example.com",
			"providers":  []any{map[string]any{"id": "p", "type": "saml", "idp_metadata_file": dir + "/missing.xml"}},
			"apps":       []any{map[string]any{"id": "a", "hosts": []string{"a.example.com"}, "providers": []string{"p"}}},
		})
		c, err := config.Parse(b, func(string) string { return "" })
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ctx := context.Background()
	if _, err := buildRuntime(ctx, base(), buildOptions{now: time.Now}); err == nil {
		t.Error("missing metadata file")
	}
	os.WriteFile(dir+"/bad.xml", []byte("<x/>"), 0o600)
	c := base()
	c.Providers[0].IdPMetadataFile = dir + "/bad.xml"
	if _, err := buildRuntime(ctx, c, buildOptions{now: time.Now}); err == nil {
		t.Error("bad metadata")
	}
	c = base()
	c.Providers[0].CAFile = dir + "/missing.pem"
	if _, err := buildRuntime(ctx, c, buildOptions{now: time.Now}); err == nil {
		t.Error("missing CA file")
	}
	os.WriteFile(dir+"/empty.pem", []byte("nothing"), 0o600)
	c.Providers[0].CAFile = dir + "/empty.pem"
	if _, err := buildRuntime(ctx, c, buildOptions{now: time.Now}); err == nil {
		t.Error("CA file without certificates")
	}
}
