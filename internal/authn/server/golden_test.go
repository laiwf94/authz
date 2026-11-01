package server

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"flag"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authn/golden"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/golden from the current responses")

// The golden transcripts pin every byte the gateway sends on the end-to-end
// paths (OIDC, SAML, the nginx, Traefik and Envoy forward-auth modes, the
// forbidden page and the admin API) so a move or refactor that changes a
// status, a header, a cookie attribute or a page is caught. They were
// recorded from the wicket code as it was before it became `authz gateway`.
// Run with -update only for an intended change, and review the diff.

// goldenRecorder drives the gateway through a browser-like cookie jar and
// records only the gateway's exchanges; identity-provider hops are made but
// not recorded, since the provider is a test double.
type goldenRecorder struct {
	t   *testing.T
	h   *harness
	tr  *golden.Transcript
	jar *cookiejar.Jar
	seq int
}

func newGoldenRecorder(t *testing.T, h *harness) *goldenRecorder {
	n := golden.NewNormalizer()
	n.Literal(h.public, "public")
	n.Literal(h.host, "host")
	n.Literal(h.idpSrv.URL, "idp")
	n.Literal(h.admin.URL, "admin")
	n.Clock(h.clk.Now())
	for _, v := range []struct{ kind, re string }{
		// OAuth and SAML protocol randomness, in URLs (raw or HTML-escaped).
		{"state", `[?&;]state=([^&"\s]+)`},
		{"nonce", `[?&;]nonce=([^&"\s]+)`},
		{"pkce", `[?&;]code_challenge=([^&"\s]+)`},
		{"code", `[?&;]code=([^&"\s]+)`},
		{"samlrequest", `[?&;]SAMLRequest=([^&"\s]+)`},
		{"relaystate", `[?&;]RelayState=([^&"\s]+)`},
		{"relaystate", `(?:^|&)RelayState=([^&"\s]+)`},
		{"samlresponse", `(?:^|&)SAMLResponse=([^&"\s]+)`},
		{"signature", `[?&;]Signature=([^&"\s]+)`},
		{"samlid", ` ID="([^"]+)"`},
		// One pending-login cookie per state, named by its hash.
		{"login", regexp.QuoteMeta(loginCookiePrefix) + `([0-9a-f]{16})`},
		// Sealed form tokens.
		{"csrf", `name="csrf" value="([^"]+)"`},
		// Per-run keys and certificates.
		{"key", `"(?:kid|x|y)":"([^"]+)"`},
		{"cert", `<(?:ds:)?X509Certificate>([^<]+)<`},
		// Session IDs wherever they appear.
		{"session", `\b([0-9a-f]{32})\b`},
		// The client address in the admin session list carries a port.
		{"port", `127\.0\.0\.1:(\d+)`},
	} {
		n.Volatile(v.kind, regexp.MustCompile(v.re))
	}
	tr := golden.New(n)
	tr.RequestHeaders = []string{"Accept", "Authorization", "Content-Type", "X-Forwarded-Host", "X-Forwarded-Method",
		"X-Forwarded-Proto", "X-Forwarded-Uri", "X-Original-Url", "X-Requested-With"}
	jar, _ := cookiejar.New(nil)
	return &goldenRecorder{t: t, h: h, tr: tr, jar: jar}
}

// do sends a request to the gateway with the jar's cookies for the gateway
// host, records it, stores any cookies it sets, and returns the body.
func (g *goldenRecorder) do(method, target string, hdr map[string]string, form url.Values) (*http.Response, string) {
	g.t.Helper()
	var body []byte
	if form != nil {
		body = []byte(form.Encode())
	}
	req, err := http.NewRequest(method, target, strings.NewReader(string(body)))
	if err != nil {
		g.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	g.seq++
	req.Header.Set(requestIDHeader, "golden-"+strconv.Itoa(g.seq))
	pub, _ := url.Parse(g.h.public)
	for _, c := range g.jar.Cookies(pub) {
		req.AddCookie(c)
	}
	transport := g.h.pub.Client().Transport
	if strings.HasPrefix(target, g.h.admin.URL) {
		transport = http.DefaultTransport
	}
	c := &http.Client{Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	g.jar.SetCookies(pub, resp.Cookies())
	out, err := g.tr.Exchange(req, body, resp)
	if err != nil {
		g.t.Fatal(err)
	}
	return resp, string(out)
}

// idp makes an unrecorded request to the identity provider.
func (g *goldenRecorder) idp(method, target string, form url.Values) (*http.Response, string) {
	g.t.Helper()
	var rd io.Reader
	if form != nil {
		rd = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, target, rd)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	c := &http.Client{Transport: g.h.idpSrv.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// signIn fills in the provider's sign-in form and returns its response.
func (g *goldenRecorder) signIn(page, user, pass string) (*http.Response, string) {
	g.t.Helper()
	resp, body := g.idp(http.MethodGet, page, nil)
	if resp.StatusCode != http.StatusOK {
		g.t.Fatalf("provider sign-in page: %d %s", resp.StatusCode, body)
	}
	action, fields := formFields(body)
	fields.Set("username", user)
	fields.Set("password", pass)
	return g.idp(http.MethodPost, action, fields)
}

// loginOIDC records the gateway's side of an OpenID Connect login.
func (g *goldenRecorder) loginOIDC(user, pass, rd string) {
	g.t.Helper()
	q := url.Values{"app": {"whoami"}, "provider": {"corp"}}
	if rd != "" {
		q.Set("rd", rd)
	}
	resp, _ := g.do(http.MethodGet, g.h.public+"/login?"+q.Encode(), map[string]string{"Accept": "text/html"}, nil)
	resp, body := g.signIn(resp.Header.Get("Location"), user, pass)
	if resp.StatusCode != http.StatusFound {
		g.t.Fatalf("provider sign-in: %d %s", resp.StatusCode, body)
	}
	if resp, _ = g.do(http.MethodGet, resp.Header.Get("Location"), map[string]string{"Accept": "text/html"}, nil); resp.StatusCode != http.StatusFound {
		g.t.Fatalf("callback: %d\n%s", resp.StatusCode, g.h.logs.String())
	}
}

var issueInstantRe = regexp.MustCompile(`IssueInstant="[^"]*"`)

// authnRequest records the AuthnRequest carried by a redirect-binding URL,
// inflated, so its content is pinned and not only its presence.
func (g *goldenRecorder) authnRequest(location string) {
	g.t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		g.t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		g.t.Fatal(err)
	}
	xml, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		g.t.Fatal(err)
	}
	// The request builder stamps IssueInstant from the wall clock rather
	// than the injected one, so it is the one time masked outright.
	xml = issueInstantRe.ReplaceAll(xml, []byte(`IssueInstant="<wall-clock>"`))
	g.tr.Note("AuthnRequest: " + string(xml))
}

func (g *goldenRecorder) check(name string) {
	g.t.Helper()
	if err := golden.Check(filepath.Join("testdata", "golden", name), g.tr.Bytes(), *updateGolden); err != nil {
		g.t.Fatal(err)
	}
}

// nginx describes the original request the way nginx auth_request does.
func (g *goldenRecorder) nginx(uri string) map[string]string {
	return map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": g.h.host, "X-Forwarded-Uri": uri}
}

func TestGoldenOIDC(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	g := newGoldenRecorder(t, h)
	tr := g.tr

	tr.Step("anonymous forward-auth from nginx")
	g.do(http.MethodGet, h.public+"/auth", g.nginx("/private?x=1"), nil)
	tr.Step("provider chooser")
	g.do(http.MethodGet, h.public+"/login?app=whoami&rd="+url.QueryEscape(h.public+"/private?x=1"), map[string]string{"Accept": "text/html"}, nil)
	tr.Step("OpenID Connect login and callback")
	g.loginOIDC("alice", "alice-pass", h.public+"/private?x=1")
	tr.Step("signed-in forward-auth with identity headers and upstream token")
	g.do(http.MethodGet, h.public+"/auth", g.nginx("/private"), nil)
	tr.Step("published keys")
	g.do(http.MethodGet, h.public+"/.well-known/jwks.json", nil, nil)
	tr.Step("logout confirmation page")
	_, page := g.do(http.MethodGet, h.public+"/logout", map[string]string{"Accept": "text/html"}, nil)
	action, form := formFields(page)
	tr.Step("logout")
	g.do(http.MethodPost, action, map[string]string{"Accept": "text/html"}, form)
	tr.Step("forward-auth after logout")
	g.do(http.MethodGet, h.public+"/auth", g.nginx("/private"), nil)
	tr.Step("logged-out page and health")
	g.do(http.MethodGet, h.public+"/logged-out", map[string]string{"Accept": "text/html"}, nil)
	g.do(http.MethodGet, h.public+"/healthz", nil, nil)
	tr.Step("unknown path")
	g.do(http.MethodGet, h.public+"/nope", map[string]string{"Accept": "application/json"}, nil)
	g.check("oidc.txt")
}

func TestGoldenSAML(t *testing.T) {
	for _, tc := range []struct {
		file string
		o    harnessOpts
	}{
		{"saml.txt", harnessOpts{}},
		{"saml-signed-requests.txt", harnessOpts{signRequests: true}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			h := newHarness(t, tc.o)
			g := newGoldenRecorder(t, h)
			tr := g.tr
			tr.Step("service provider metadata")
			g.do(http.MethodGet, h.public+"/saml/partner/metadata", nil, nil)
			tr.Step("SAML login redirect")
			resp, _ := g.do(http.MethodGet, h.public+"/login?app=whoami&provider=partner", map[string]string{"Accept": "text/html"}, nil)
			g.authnRequest(resp.Header.Get("Location"))
			resp, body := g.signIn(resp.Header.Get("Location"), "carol", "carol-pass")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("provider sign-in: %d %s", resp.StatusCode, body)
			}
			acs, form := formFields(body)
			tr.Step("assertion consumer service")
			g.do(http.MethodPost, acs, map[string]string{"Accept": "text/html"}, form)
			tr.Step("replayed assertion")
			g.do(http.MethodPost, acs, map[string]string{"Accept": "text/html"}, form)
			tr.Step("signed-in forward-auth")
			g.do(http.MethodGet, h.public+"/auth", g.nginx("/"), nil)
			g.check(tc.file)
		})
	}
}

func TestGoldenProxyModes(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	g := newGoldenRecorder(t, h)
	tr := g.tr
	anon := func(target string, hdr map[string]string) {
		t.Helper()
		// Proxy calls without the browser's cookies.
		saved := g.jar
		g.jar, _ = cookiejar.New(nil)
		g.do(http.MethodGet, target, hdr, nil)
		g.jar = saved
	}

	tr.Step("nginx with X-Original-URL")
	anon(h.public+"/auth", map[string]string{"X-Original-URL": h.public + "/a?b=1"})
	tr.Step("Traefik redirect mode: browser navigation")
	anon(h.public+"/auth?redirect=1", map[string]string{"X-Forwarded-Host": h.host, "X-Forwarded-Uri": "/x",
		"Accept": "text/html", "X-Forwarded-Method": "GET"})
	tr.Step("Traefik redirect mode: API call, script and POST")
	anon(h.public+"/auth?redirect=1", map[string]string{"X-Forwarded-Host": h.host, "Accept": "application/json"})
	anon(h.public+"/auth?redirect=1", map[string]string{"X-Forwarded-Host": h.host, "Accept": "text/html", "X-Requested-With": "XMLHttpRequest"})
	anon(h.public+"/auth?redirect=1", map[string]string{"X-Forwarded-Host": h.host, "Accept": "text/html", "X-Forwarded-Method": "POST"})
	tr.Step("Envoy ext_authz: browser")
	anon(h.public+"/auth/envoy/docs/page?q=1", map[string]string{"Accept": "text/html"})
	tr.Step("Envoy ext_authz: API call")
	anon(h.public+"/auth/envoy/api", map[string]string{"Accept": "application/json"})
	tr.Step("unknown host and no host")
	anon(h.public+"/auth", map[string]string{"X-Forwarded-Host": "unknown.example.com"})
	anon(h.public+"/auth", nil)
	tr.Step("explicit app with a return address outside the allow-list")
	anon(h.public+"/auth?app=open", map[string]string{"X-Forwarded-Host": "evil.com", "X-Forwarded-Uri": "/x"})

	g.loginOIDC("alice", "alice-pass", "")
	tr.Step("signed in: Envoy")
	g.do(http.MethodGet, h.public+"/auth/envoy/", nil, nil)
	tr.Step("signed in: HEAD")
	g.do(http.MethodHead, h.public+"/auth", map[string]string{"X-Forwarded-Host": h.host}, nil)
	tr.Step("signed in: the other app by host:443")
	g.do(http.MethodGet, h.public+"/auth", map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "open.example.com:443", "X-Forwarded-Uri": "/"}, nil)
	tr.Step("forged session cookie")
	saved := g.jar
	g.jar, _ = cookiejar.New(nil)
	pub, _ := url.Parse(h.public)
	g.jar.SetCookies(pub, []*http.Cookie{{Name: "__Host-wicket", Value: "forged-value-0123456789"}})
	g.do(http.MethodGet, h.public+"/auth", g.nginx("/"), nil)
	g.jar = saved
	g.check("proxy-modes.txt")
}

func TestGoldenForbiddenAndAdmin(t *testing.T) {
	const token = "admin-token-0123456789"
	h := newHarness(t, harnessOpts{adminToken: token})
	g := newGoldenRecorder(t, h)
	tr := g.tr
	g.loginOIDC("bob", "bob-pass", "")
	tr.Step("forbidden: API call")
	g.do(http.MethodGet, h.public+"/auth", g.nginx("/"), nil)
	tr.Step("forbidden: browser page with sign-out form")
	g.do(http.MethodGet, h.public+"/auth", map[string]string{"X-Forwarded-Host": h.host, "X-Forwarded-Uri": "/", "Accept": "text/html"}, nil)

	tr.Step("admin without a token")
	g.do(http.MethodGet, h.admin.URL+"/admin/sessions", nil, nil)
	tr.Step("admin session list")
	g.do(http.MethodGet, h.admin.URL+"/admin/sessions?subject=bob", map[string]string{"Authorization": "Bearer " + token}, nil)
	tr.Step("admin bad requests")
	g.do(http.MethodGet, h.admin.URL+"/admin/sessions?limit=0", map[string]string{"Authorization": "Bearer " + token}, nil)
	g.do(http.MethodDelete, h.admin.URL+"/admin/sessions/not-an-id", map[string]string{"Authorization": "Bearer " + token}, nil)
	g.do(http.MethodDelete, h.admin.URL+"/admin/sessions/"+strings.Repeat("0", 32), map[string]string{"Authorization": "Bearer " + token}, nil)
	tr.Step("admin revokes the session")
	sessions := h.sessions.List("bob", 1)
	if len(sessions) != 1 {
		t.Fatalf("sessions for bob: %d", len(sessions))
	}
	g.do(http.MethodDelete, h.admin.URL+"/admin/sessions/"+sessions[0].ID, map[string]string{"Authorization": "Bearer " + token}, nil)
	tr.Step("forward-auth after revocation")
	g.do(http.MethodGet, h.public+"/auth", g.nginx("/"), nil)
	tr.Step("admin reload and health")
	g.do(http.MethodPost, h.admin.URL+"/admin/reload", map[string]string{"Authorization": "Bearer " + token}, nil)
	g.do(http.MethodGet, h.admin.URL+"/healthz", nil, nil)
	g.check("forbidden-admin.txt")
}
