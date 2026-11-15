package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/fakeidp"
)

// newSID returns the provider session a login just started.
func newSID(t *testing.T, before, after []string) string {
	t.Helper()
	seen := map[string]bool{}
	for _, s := range before {
		seen[s] = true
	}
	for _, s := range after {
		if !seen[s] {
			return s
		}
	}
	t.Fatal("the login started no provider session")
	return ""
}

// backchannelHarness is a harness whose fake provider sends back-channel
// logouts for the corp client to the gateway.
func backchannelHarness(t *testing.T, o harnessOpts) *harness {
	h := newHarness(t, o)
	if !h.idp.SetBackchannelLogoutURI("wicket", h.public+"/backchannel-logout/corp") {
		t.Fatal("no wicket client at the provider")
	}
	h.idp.SetBackchannelClient(h.pub.Client())
	return h
}

// postLogout sends a back-channel logout request as the provider would.
func (h *harness) postLogout(path, contentType, body string) (int, map[string]any, http.Header) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.public+path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	resp, err := h.pub.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			h.t.Fatalf("not JSON: %q", raw)
		}
	}
	return resp.StatusCode, out, resp.Header
}

func form(tok string) string { return url.Values{"logout_token": {tok}}.Encode() }

const formType = "application/x-www-form-urlencoded"

func TestBackchannelLogoutBySID(t *testing.T) {
	h := backchannelHarness(t, harnessOpts{sessionFile: true})
	laptop, phone, bob := h.browser(), h.browser(), h.browser()
	laptop.loginOIDC("alice", "alice-pass", "")
	s1 := h.idp.Sessions("alice")
	phone.loginOIDC("alice", "alice-pass", "")
	phoneSID := newSID(t, s1, h.idp.Sessions("alice"))
	bob.loginOIDC("bob", "bob-pass", "")
	for _, b := range []*browser{laptop, phone} {
		if b.auth("/", nil).StatusCode != 200 {
			t.Fatal("not signed in")
		}
	}

	// The phone's provider session ends: only the phone is signed out.
	tok, err := h.idp.LogoutToken("wicket", "", phoneSID)
	if err != nil {
		t.Fatal(err)
	}
	code, body, hdr := h.postLogout("/backchannel-logout/corp", formType, form(tok))
	if code != 200 || body != nil {
		t.Fatalf("logout: %d %v", code, body)
	}
	if cc := hdr.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control %q", cc)
	}
	if c := phone.auth("/", nil).StatusCode; c == 200 {
		t.Fatal("the phone is still signed in")
	}
	if laptop.auth("/", nil).StatusCode != 200 {
		t.Fatal("the laptop was signed out too")
	}
	h.expectAudit("session_ended", "backchannel_logout")

	// The same token again is a replay, refused even though it would end
	// nothing.
	code, body, _ = h.postLogout("/backchannel-logout/corp", formType, form(tok))
	if code != 400 || body["error"] != "invalid_request" || body["error_description"] != "logout_token_replayed" {
		t.Fatalf("replay: %d %v", code, body)
	}

	// The user signs out at the provider: the provider tells this relying
	// party about both its sessions (the phone's again: the fake never ended
	// it, the test only minted a token), and the laptop's ends too; bob's
	// does not.
	n, err := h.idp.Logout(context.Background(), "alice")
	if err != nil || n != 2 {
		t.Fatalf("provider logout: %d %v", n, err)
	}
	if laptop.auth("/", nil).StatusCode == 200 {
		t.Fatal("the laptop is still signed in")
	}
	// Bob is signed in but not in the app's group: 403, not 401.
	if c := bob.auth("/", nil).StatusCode; c != 403 {
		t.Fatalf("bob: %d", c)
	}
	m := h.metrics()
	for _, want := range []string{`wicket_sessions_ended_total{reason="backchannel_logout"} 2`,
		`wicket_backchannel_logouts_total{provider="corp",result="accepted"} 3`,
		`wicket_backchannel_logouts_total{provider="corp",result="rejected"} 1`} {
		if !strings.Contains(m, want) {
			t.Errorf("no %s in\n%s", want, m)
		}
	}
	if l := h.sessions.List("", 0); len(l) != 1 || l[0].Identity.Subject != "bob" {
		t.Fatalf("sessions left: %+v", l)
	}
	// The sid is kept for the match but never shown.
	_, list := h.adminDo("GET", "/admin/sessions", "", "")
	if s := jsonString(t, list); strings.Contains(s, "sid") || strings.Contains(s, h.idp.Sessions("bob")[0]) {
		t.Fatalf("admin API shows the provider session: %s", s)
	}
}

func TestBackchannelLogoutBySubject(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	a, b := h.browser(), h.browser()
	a.loginOIDC("alice", "alice-pass", "")
	b.loginOIDC("alice", "alice-pass", "")
	tok, _ := h.idp.LogoutToken("wicket", "alice", "")
	if code, body, _ := h.postLogout("/backchannel-logout/corp", formType, form(tok)); code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	for _, br := range []*browser{a, b} {
		if br.auth("/", nil).StatusCode == 200 {
			t.Fatal("still signed in")
		}
	}
	// A valid token that matches nobody still answers 200: the provider
	// can't know which sessions this relying party holds.
	tok, _ = h.idp.LogoutToken("wicket", "nobody", "")
	if code, _, _ := h.postLogout("/backchannel-logout/corp", formType, form(tok)); code != 200 {
		t.Fatalf("no match: %d", code)
	}
	// sub and sid must both match: alice's sid with bob's subject ends
	// nothing.
	c := h.browser()
	c.loginOIDC("alice", "alice-pass", "")
	sid := h.idp.Sessions("alice")
	tok, _ = h.idp.LogoutToken("wicket", "bob", sid[len(sid)-1])
	h.postLogout("/backchannel-logout/corp", formType, form(tok))
	tok, _ = h.idp.LogoutToken("wicket", "bob", "")
	h.postLogout("/backchannel-logout/corp", formType, form(tok))
	if c.auth("/", nil).StatusCode != 200 {
		t.Fatal("a token for another subject ended alice's session")
	}
}

func TestBackchannelLogoutRejects(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	br := h.browser()
	br.loginOIDC("alice", "alice-pass", "")
	sid := h.idp.Sessions("alice")[0]
	good, _ := h.idp.LogoutToken("wicket", "alice", sid)
	other, err := fakeidp.New(fakeidp.Config{Issuer: h.idp.Issuer(), Now: h.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := other.LogoutToken("wicket", "alice", sid) // same issuer, another key
	wrongAud, _ := h.idp.LogoutToken("another-client", "alice", sid)
	idToken, _ := h.idp.SignJWT(map[string]any{"iss": h.idp.Issuer(), "aud": "wicket", "sub": "alice", "sid": sid,
		"iat": h.clk.Now().Unix(), "exp": h.clk.Now().Add(time.Minute).Unix(), "nonce": "n"})
	cases := []struct {
		name, path, ctype, body, reason string
	}{
		{"JSON body", "/backchannel-logout/corp", "application/json", `{"logout_token":"` + good + `"}`, reasonLogoutRequest},
		{"no token", "/backchannel-logout/corp", formType, "", reasonLogoutRequest},
		{"two tokens", "/backchannel-logout/corp", formType, url.Values{"logout_token": {good, good}}.Encode(), reasonLogoutRequest},
		{"token in the query", "/backchannel-logout/corp?logout_token=" + good, formType, form(good), reasonLogoutRequest},
		{"unknown provider", "/backchannel-logout/nope", formType, form(good), reasonLogoutProvider},
		{"SAML provider", "/backchannel-logout/partner", formType, form(good), reasonLogoutProvider},
		{"forged signature", "/backchannel-logout/corp", formType, form(forged), "logout_token_invalid"},
		{"another client's token", "/backchannel-logout/corp", formType, form(wrongAud), "logout_token_wrong_audience"},
		{"an ID token", "/backchannel-logout/corp", formType, form(idToken), "logout_token_nonce"},
		{"garbage", "/backchannel-logout/corp", formType, form("x.y.z"), "logout_token_invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, body, _ := h.postLogout(c.path, c.ctype, c.body)
			if code != 400 || body["error"] != "invalid_request" || body["error_description"] != c.reason {
				t.Fatalf("%d %v", code, body)
			}
			h.expectAudit("logout_rejected", c.reason)
		})
	}
	if br.auth("/", nil).StatusCode != 200 {
		t.Fatal("a rejected token ended the session")
	}
	// A GET is not a logout.
	resp, err := h.pub.Client().Get(h.public + "/backchannel-logout/corp?logout_token=" + good)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 200 || br.auth("/", nil).StatusCode != 200 {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
	// Unknown provider ids don't grow the metric label set.
	if m := h.metrics(); strings.Contains(m, `provider="nope"`) || !strings.Contains(m, `wicket_backchannel_logouts_total{provider="unknown",result="rejected"} 1`) {
		t.Fatalf("metrics:\n%s", m)
	}
	// The good token still works after all that.
	if code, _, _ := h.postLogout("/backchannel-logout/corp", formType, form(good)); code != 200 || br.auth("/", nil).StatusCode == 200 {
		t.Fatal("the good token did not end the session")
	}
}
