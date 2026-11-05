package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/jose"
)

func TestEndToEndOIDC(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()

	// Not signed in: 401 with a login URL that returns to the page.
	resp := b.auth("/private?x=1", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous: got %d", resp.StatusCode)
	}
	login := resp.Header.Get(HeaderRedirect)
	lu, _ := url.Parse(login)
	if lu.Query().Get("app") != "whoami" || lu.Query().Get("rd") != h.public+"/private?x=1" {
		t.Fatalf("login URL %q", login)
	}

	target := b.loginOIDC("alice", "alice-pass", h.public+"/private?x=1")
	if target != h.public+"/private?x=1" {
		t.Fatalf("returned to %q", target)
	}
	resp = b.auth("/private", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("after login: %d\n%s", resp.StatusCode, h.logs.String())
	}
	if resp.Header.Get(HeaderUser) != "alice" || resp.Header.Get(HeaderEmail) != "alice@example.org" ||
		resp.Header.Get(HeaderGroups) != "eng,admins" || resp.Header.Get(HeaderProvider) != "corp" {
		t.Fatalf("identity headers: %v", resp.Header)
	}

	// The upstream token verifies against the published key set.
	_, body := b.get(h.public + "/.well-known/jwks.json")
	ks, err := jose.ParseKeySet([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jose.Parse(resp.Header.Get(HeaderToken))
	if err != nil {
		t.Fatal(err)
	}
	if err := tok.Verify(ks.Keys[0], []string{"ES256"}); err != nil {
		t.Fatal(err)
	}
	claims, _ := jose.ParseClaims(tok.Payload)
	if err := claims.Validate(jose.Expect{Issuer: h.public, Audience: "whoami", Now: h.clk.Now(), Skew: time.Second}); err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "alice" || claims.String("idp") != "corp" {
		t.Fatalf("claims %+v", claims.Raw)
	}
	h.expectAudit("login_succeeded", "")
}

func TestEndToEndSAML(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    harnessOpts
	}{
		{"signed", harnessOpts{}},
		{"encrypted", harnessOpts{encrypt: true}},
		{"signed requests", harnessOpts{signRequests: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.o)
			b := h.browser()
			resp := b.loginSAML("carol", "carol-pass")
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("acs: %d\n%s", resp.StatusCode, h.logs.String())
			}
			resp = b.auth("/", nil)
			if resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderUser) != "carol@partner.example" ||
				resp.Header.Get(HeaderProvider) != "partner" {
				t.Fatalf("after SAML login: %d %v", resp.StatusCode, resp.Header)
			}
		})
	}
}

func TestForbiddenAndLogout(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browser()
	b.loginOIDC("bob", "bob-pass", "")
	resp := b.auth("/", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bob is not in eng: got %d", resp.StatusCode)
	}
	h.expectAudit("access_denied", "no_rule_matched")

	// The browser 403 page carries a working sign-out form.
	req, _ := http.NewRequest(http.MethodGet, h.public+"/auth", nil)
	req.Header.Set("X-Forwarded-Host", h.host)
	req.Header.Set("X-Forwarded-Uri", "/")
	resp = b.do(req)
	_, body := readBody(resp)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "bob@example.org") {
		t.Fatalf("forbidden page: %d %s", resp.StatusCode, body)
	}

	// Logout: the confirmation page has the token; POST ends the session
	// and continues to the provider's end-session endpoint.
	_, page := b.get(h.public + "/logout")
	action, form := formFields(page)
	if action != h.public+"/logout" || form.Get("csrf") == "" {
		t.Fatalf("logout page: %s", page)
	}
	resp, _ = b.post(action, form)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), h.idpSrv.URL+"/logout?") {
		t.Fatalf("logout: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := b.auth("/", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", resp.StatusCode)
	}
	h.expectAudit("logout", "")
}

func TestAdminRevocation(t *testing.T) {
	h := newHarness(t, harnessOpts{adminToken: "admin-token-0123456789"})
	b := h.browser()
	b.loginOIDC("alice", "alice-pass", "")
	if resp := b.auth("/", nil); resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := h.adminDo("GET", "/admin/sessions", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin without token: %d", resp.StatusCode)
	}
	resp, out := h.adminDo("GET", "/admin/sessions?subject=alice", "admin-token-0123456789", "")
	list, _ := out["sessions"].([]any)
	if resp.StatusCode != http.StatusOK || len(list) != 1 {
		t.Fatalf("list: %d %v", resp.StatusCode, out)
	}
	id := list[0].(map[string]any)["id"].(string)
	if resp, _ := h.adminDo("DELETE", "/admin/sessions/"+id, "admin-token-0123456789", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if resp := b.auth("/", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked session still works: %d", resp.StatusCode)
	}
	h.expectAudit("session_revoked", "")
}

func readBody(resp *http.Response) (*http.Response, string) {
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	resp.Body.Close()
	return resp, sb.String()
}

var _ = context.Background
