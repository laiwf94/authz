package server

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authn/fakeidp"
)

const carol = "carol@partner.example"

// sloHarness is a harness whose fake IdP does SAML single logout on these
// bindings (both when none are given) with the gateway's partner provider.
func sloHarness(t *testing.T, bindings ...string) *harness {
	t.Helper()
	h := newHarness(t, harnessOpts{})
	h.idp.EnableSingleLogout(bindings...)
	if !h.idp.SetSAMLLogout(h.public+"/saml/partner/metadata", h.public+"/saml/partner/slo", h.spCert) {
		t.Fatal("no partner service provider at the IdP")
	}
	writeFile(t, h.dir, "idp.xml", h.idp.Metadata())
	if err := h.srv.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

// signOut confirms the sign-out page.
func (b *browser) signOut() (*http.Response, string) {
	b.h.t.Helper()
	_, page := b.get(b.h.public + "/logout")
	action, fields := formFields(page)
	if fields.Get("csrf") == "" {
		b.h.t.Fatalf("no sign-out form: %s", page)
	}
	return b.post(action, fields)
}

// follow carries a SAML message on, as a browser does: it follows a
// redirect or submits a self-posting form.
func (b *browser) follow(resp *http.Response, body string) (*http.Response, string) {
	b.h.t.Helper()
	switch resp.StatusCode {
	case http.StatusFound, http.StatusSeeOther:
		return b.get(resp.Header.Get("Location"))
	case http.StatusOK:
		action, fields := formFields(body)
		if action == "" || (fields.Get("SAMLRequest") == "" && fields.Get("SAMLResponse") == "") {
			b.h.t.Fatalf("no SAML form in %s", body)
		}
		return b.post(action, fields)
	}
	b.h.t.Fatalf("nothing to follow: %d %s\nlogs:\n%s", resp.StatusCode, body, b.h.logs.String())
	return nil, ""
}

func (h *harness) wantMetrics(want ...string) {
	h.t.Helper()
	m := h.metrics()
	for _, w := range want {
		if !strings.Contains(m, w) {
			h.t.Errorf("no %s in\n%s", w, m)
		}
	}
}

func TestSAMLSingleLogoutSPInitiated(t *testing.T) {
	for _, tc := range []struct {
		name    string
		binding string
	}{{"redirect", fakeidp.Redirect}, {"POST", fakeidp.POST}} {
		t.Run(tc.name, func(t *testing.T) {
			h := sloHarness(t, tc.binding)
			b := h.browser()
			if resp := b.loginSAML("carol", "carol-pass"); resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("login: %d\n%s", resp.StatusCode, h.logs.String())
			}
			idx := h.idp.SAMLSessions(carol)
			if len(idx) != 1 || b.auth("/", nil).StatusCode != 200 {
				t.Fatalf("not signed in: %v", idx)
			}

			resp, body := b.signOut()
			idpSLO := h.idp.Issuer() + "/saml/slo"
			switch tc.binding {
			case fakeidp.Redirect:
				if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), idpSLO+"?SAMLRequest=") {
					t.Fatalf("sign-out: %d %s", resp.StatusCode, resp.Header.Get("Location"))
				}
			case fakeidp.POST:
				action, fields := formFields(body)
				csp := resp.Header.Get("Content-Security-Policy")
				if resp.StatusCode != 200 || action != idpSLO || fields.Get("SAMLRequest") == "" || fields.Get("RelayState") == "" ||
					!strings.Contains(csp, "script-src 'sha256-") || strings.Contains(csp, "unsafe-inline") {
					t.Fatalf("sign-out page: %d %q %v %s", resp.StatusCode, csp, fields, body)
				}
			}
			// The session ended here before the browser left.
			if c := b.auth("/", nil).StatusCode; c != 401 {
				t.Fatalf("still signed in while at the IdP: %d", c)
			}
			h.expectAudit("logout", "")

			resp, body = b.follow(resp, body) // to the IdP, which answers
			got := h.idp.LogoutRequests()
			if len(got) != 1 || got[0].NameID != carol || len(got[0].SessionIndex) != 1 || got[0].SessionIndex[0] != idx[0] ||
				got[0].EndedSessions != 1 {
				t.Fatalf("the IdP saw %+v", got)
			}
			if len(h.idp.SAMLSessions(carol)) != 0 {
				t.Fatal("the IdP session survived")
			}
			answer, answerBody := resp, body
			resp, _ = b.follow(resp, body) // back to the gateway
			if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != h.public+"/logged-out" {
				t.Fatalf("after the LogoutResponse: %d %s\n%s", resp.StatusCode, resp.Header.Get("Location"), h.logs.String())
			}
			h.wantMetrics(`wicket_saml_logouts_total{provider="partner",initiator="sp",result="sent"} 1`,
				`wicket_saml_logouts_total{provider="partner",initiator="sp",result="accepted"} 1`)

			// The same answer again is refused.
			resp, _ = b.follow(answer, answerBody)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("replayed LogoutResponse: %d", resp.StatusCode)
			}
			h.expectAudit("logout_rejected", "logout_replayed")
		})
	}
}

func TestSAMLSingleLogoutKeepsReturnURL(t *testing.T) {
	h := sloHarness(t, fakeidp.Redirect)
	b := h.browser()
	b.loginSAML("carol", "carol-pass")
	_, page := b.get(h.public + "/logout?rd=" + url.QueryEscape("https://app.example.com/bye"))
	action, fields := formFields(page)
	resp, body := b.post(action, fields)
	resp, body = b.follow(resp, body)
	resp, _ = b.follow(resp, body)
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "https://app.example.com/bye" {
		t.Fatalf("%d %s", resp.StatusCode, loc)
	}
}

func TestSAMLSingleLogoutIdPInitiated(t *testing.T) {
	h := sloHarness(t)
	laptop, phone, other := h.browser(), h.browser(), h.browser()
	laptop.loginSAML("carol", "carol-pass")
	phone.loginSAML("carol", "carol-pass")
	other.loginSAML("alice", "alice-pass")
	idx := h.idp.SAMLSessions(carol)
	if len(idx) != 2 {
		t.Fatalf("sessions %v", idx)
	}
	sp := h.public + "/saml/partner/metadata"

	// The phone's IdP session ends (redirect binding, by SessionIndex):
	// only the phone is signed out here.
	target, _, id, err := h.idp.SAMLLogoutRequest(fakeidp.SAMLLogoutOptions{SP: sp, NameID: carol,
		SessionIndex: []string{idx[1]}, RelayState: "idp-state", EndSessions: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, body := phone.get(target)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), h.idp.Issuer()+"/saml/slo?SAMLResponse=") ||
		!strings.Contains(resp.Header.Get("Location"), "RelayState=idp-state") {
		t.Fatalf("answer: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	if !strings.Contains(strings.Join(resp.Header.Values("Set-Cookie"), "\n"), "__Host-wicket=;") {
		t.Errorf("the phone's cookie was not cleared: %v", resp.Header.Values("Set-Cookie"))
	}
	if c := phone.auth("/", nil).StatusCode; c != 401 {
		t.Fatalf("phone: %d", c)
	}
	if laptop.auth("/", nil).StatusCode != 200 {
		t.Fatal("the laptop was signed out too")
	}
	if resp, body = phone.follow(resp, body); resp.StatusCode != 200 {
		t.Fatalf("IdP: %d %s", resp.StatusCode, body)
	}
	if st, ok := h.idp.SAMLLogoutResult(id); !ok || st != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		t.Fatalf("result %q %v", st, ok)
	}
	h.expectAudit("session_ended", "saml_logout")

	// Then the user signs out at the IdP (POST binding, NameID alone):
	// every session of carol ends, alice's does not. The browser carrying
	// it is a third one; no cookie of its own is needed.
	target, form, id, err := h.idp.SAMLLogoutRequest(fakeidp.SAMLLogoutOptions{SP: sp, NameID: carol, Binding: fakeidp.POST})
	if err != nil {
		t.Fatal(err)
	}
	carrier := h.browser()
	resp, body = carrier.post(target, form)
	if resp.StatusCode != 200 || !strings.Contains(body, `action="`+h.idp.Issuer()+`/saml/slo"`) {
		t.Fatalf("answer: %d %s", resp.StatusCode, body)
	}
	if resp, body = carrier.follow(resp, body); resp.StatusCode != 200 {
		t.Fatalf("IdP: %d %s", resp.StatusCode, body)
	}
	if st, _ := h.idp.SAMLLogoutResult(id); st != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		t.Fatalf("result %q", st)
	}
	if c := laptop.auth("/", nil).StatusCode; c != 401 {
		t.Fatalf("laptop: %d", c)
	}
	if other.auth("/", nil).StatusCode != 200 {
		t.Fatal("alice was signed out")
	}
	// A request naming nobody signed in here still succeeds.
	target, _, id, _ = h.idp.SAMLLogoutRequest(fakeidp.SAMLLogoutOptions{SP: sp, NameID: "nobody@partner.example"})
	resp, body = carrier.get(target)
	carrier.follow(resp, body)
	if st, _ := h.idp.SAMLLogoutResult(id); st != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		t.Fatalf("no match: %q", st)
	}
	h.wantMetrics(`wicket_sessions_ended_total{reason="saml_logout"} 2`,
		`wicket_saml_logouts_total{provider="partner",initiator="idp",result="accepted"} 3`)
	if l := h.sessions.List("", 0); len(l) != 1 || l[0].Identity.Subject != "alice@example.org" {
		t.Fatalf("sessions left: %+v", l)
	}
}

func TestSAMLSingleLogoutRejects(t *testing.T) {
	h := sloHarness(t)
	b := h.browser()
	b.loginSAML("carol", "carol-pass")
	sp := h.public + "/saml/partner/metadata"
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	request := func(o fakeidp.SAMLLogoutOptions) string {
		t.Helper()
		o.SP, o.NameID = sp, carol
		target, _, _, err := h.idp.SAMLLogoutRequest(o)
		if err != nil {
			t.Fatal(err)
		}
		return target
	}
	replayed := request(fakeidp.SAMLLogoutOptions{SessionIndex: []string{"_not-a-session"}})
	if resp, _ := b.get(replayed); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first use: %d", resp.StatusCode)
	}

	// A LogoutResponse for a request the gateway never sent, though it
	// names a pending logout's RelayState.
	pending := h.browser()
	pending.loginSAML("carol", "carol-pass")
	resp, _ := pending.signOut()
	relay, _ := url.Parse(resp.Header.Get("Location"))
	forged, _, err := h.idp.SAMLLogoutResponse(sp, "_another-request", "", fakeidp.Redirect, relay.Query().Get("RelayState"))
	if err != nil {
		t.Fatal(err)
	}
	// A real answer, carried by a browser without the logout cookie.
	carrier := h.browser()
	carrier.loginSAML("carol", "carol-pass")
	resp, body := carrier.signOut()
	answer, _ := carrier.follow(resp, body)
	stolen := answer.Header.Get("Location")

	for _, tc := range []struct {
		name, method, url, reason string
		br                        *browser
	}{
		{"unsigned", http.MethodGet, request(fakeidp.SAMLLogoutOptions{Unsigned: true}), "signature_missing", b},
		{"signed by another key", http.MethodGet, request(fakeidp.SAMLLogoutOptions{SignWithOther: otherKey}), "signature_invalid", b},
		{"replayed", http.MethodGet, replayed, "logout_replayed", b},
		{"answer to another request", http.MethodGet, forged, "wrong_in_response_to", pending},
		{"answer without its cookie", http.MethodGet, stolen, "state_cookie_missing", h.browser()},
		{"OpenID Connect provider", http.MethodGet, h.public + "/saml/corp/slo?SAMLRequest=x", reasonLogoutProvider, b},
		{"unknown provider", http.MethodGet, h.public + "/saml/nope/slo", reasonLogoutProvider, b},
		{"POST as JSON", http.MethodPost, h.public + "/saml/partner/slo", "malformed_response", b},
	} {
		var resp *http.Response
		if tc.method == http.MethodGet {
			resp, _ = tc.br.get(tc.url)
		} else {
			req, _ := http.NewRequest(http.MethodPost, tc.url, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			resp = tc.br.do(req)
			resp.Body.Close()
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", tc.name, resp.StatusCode)
			continue
		}
		h.expectAudit("logout_rejected", tc.reason)
	}
	if b.auth("/", nil).StatusCode != 200 {
		t.Fatal("a refused logout ended the session")
	}
	h.wantMetrics(`wicket_saml_logouts_total{provider="unknown",initiator="",result="rejected"} 2`)
}

// An IdP that could not end every session answers with another status:
// the user is still signed out here and sent on, and operators see it.
func TestSAMLSingleLogoutPartial(t *testing.T) {
	h := sloHarness(t, fakeidp.Redirect)
	b := h.browser()
	b.loginSAML("carol", "carol-pass")
	resp, _ := b.signOut()
	u, _ := url.Parse(resp.Header.Get("Location"))
	raw, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	xml, _ := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	id := regexp.MustCompile(` ID="([^"]+)"`).FindStringSubmatch(string(xml))
	if id == nil {
		t.Fatalf("no ID in %s", xml)
	}
	target, _, err := h.idp.SAMLLogoutResponse(h.public+"/saml/partner/metadata", id[1],
		"urn:oasis:names:tc:SAML:2.0:status:Responder", fakeidp.Redirect, u.Query().Get("RelayState"))
	if err != nil {
		t.Fatal(err)
	}
	resp, _ = b.get(target)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != h.public+"/logged-out" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	h.wantMetrics(`wicket_saml_logouts_total{provider="partner",initiator="sp",result="partial"} 1`)
	if !strings.Contains(h.logs.String(), "did not end every session") {
		t.Fatal("not logged")
	}
}

// Without single logout at the IdP, sign-out stays local and the metadata
// lists no SingleLogoutService.
func TestSAMLLogoutWithoutSingleLogout(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.loginSAML("carol", "carol-pass")
	resp, _ := b.signOut()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != h.public+"/logged-out" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, md := b.get(h.public + "/saml/partner/metadata"); strings.Contains(md, "SingleLogoutService") {
		t.Fatal("single logout advertised")
	}
	if resp, _ := b.get(h.public + "/saml/partner/slo?SAMLRequest=x"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("slo: %d", resp.StatusCode)
	}
	h.expectAudit("logout_rejected", reasonLogoutProvider)
}
