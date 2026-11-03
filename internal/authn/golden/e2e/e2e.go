// Package e2e is the gateway's end-to-end golden suite: the OpenID Connect
// and SAML logins, the nginx, Traefik and Envoy forward-auth modes, the
// forbidden page and the admin API, each recorded as a golden transcript.
//
// The scenarios are separate from what runs the gateway, so the same
// transcripts in testdata/golden can be replayed against any build of it:
// this package's tests replay them against server.New in process, and
// cmd/authz/internal/gateway replays them through `authz gateway`'s own
// startup path, from WICKET_* variables and a wicket config file. The
// transcripts were recorded from the wicket code before it became
// `authz gateway`; a difference in any status, header, cookie attribute or
// page fails the replay with a line diff.
//
// An Env holds what every run shares: a fake identity provider (OpenID
// Connect and SAML) on a frozen clock, its CA and metadata files, and a
// wicket config file pointing at it. A Target says where the gateway under
// test listens.
package e2e

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/fakeidp"
	"github.com/laiwf94/authz/internal/authn/golden"
)

const (
	// ClientSecret is the OpenID Connect client secret; the config reads it
	// from CORP_SECRET.
	ClientSecret = "test-client-secret-value"
	// AdminToken is the admin API token for the forbidden-and-admin scenario.
	AdminToken = "admin-token-0123456789"

	loginCookiePrefix = "__Host-wicket-login-"
	sessionCookie     = "__Host-wicket"
	requestIDHeader   = "X-Request-Id"
)

// Clock is a frozen clock shared by the provider and the gateway, so the
// times in tokens, cookies and the admin API are fixed offsets from it.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// Now returns the clock's time.
func (c *Clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

// Options selects the configuration variant a scenario needs.
type Options struct {
	// SignRequests makes the gateway sign SAML AuthnRequests and the
	// provider require it.
	SignRequests bool
}

// Env is the fake identity provider and the files a gateway is started
// from.
type Env struct {
	Dir        string // temporary directory holding every file below
	ConfigPath string // the wicket config file
	Public     string // the gateway's public URL, https://Host
	Host       string // host:port the gateway listens on, also the app host
	IdP        string // the provider's issuer URL
	Clock      *Clock

	idpClient *http.Client
}

// NewEnv starts the fake provider and writes the config for a gateway that
// will listen on host (host:port). The provider is stopped when the test
// ends.
func NewEnv(t testing.TB, host string, o Options) *Env {
	t.Helper()
	e := &Env{Dir: t.TempDir(), Host: host, Public: "https://" + host, Clock: &Clock{t: time.Now()}}
	srv := httptest.NewUnstartedServer(nil)
	e.IdP = "https://" + srv.Listener.Addr().String()

	spKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spCert, err := fakeidp.SelfSignedCert(spKey, "sp", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(spKey)
	e.write(t, "sp-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	e.write(t, "sp.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: spCert.Raw}))

	sp := fakeidp.ServiceProvider{EntityID: e.Public + "/saml/partner/metadata", ACSURL: e.Public + "/saml/partner/acs",
		SignAssertion: true, SignResponse: true}
	if o.SignRequests {
		sp.RequestCert = spCert
	}
	idp, err := fakeidp.New(fakeidp.Config{Issuer: e.IdP, Now: e.Clock.Now,
		Clients: []fakeidp.Client{{ID: "wicket", Secret: ClientSecret, RedirectURIs: []string{e.Public + "/callback/corp"},
			PostLogoutRedirectURIs: []string{e.Public + "/logged-out"}}},
		ServiceProviders: []fakeidp.ServiceProvider{sp}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = idp
	srv.StartTLS()
	t.Cleanup(srv.Close)
	e.idpClient = srv.Client()
	e.write(t, "idp.xml", idp.Metadata())
	e.write(t, "idp-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))

	cfg := map[string]any{
		"public_url":     e.Public,
		"redirect_hosts": []string{"app.example.com"},
		"providers": []any{
			map[string]any{"id": "corp", "type": "oidc", "display_name": "Corp SSO", "issuer": e.IdP,
				"client_id": "wicket", "client_secret_env": "CORP_SECRET", "userinfo": true,
				"post_logout_redirect_url": e.Public + "/logged-out", "ca_file": e.path("idp-ca.pem")},
			map[string]any{"id": "partner", "type": "saml", "display_name": "Partner SAML",
				"idp_metadata_file": e.path("idp.xml"), "sp_key_file": e.path("sp-key.pem"),
				"sp_cert_file": e.path("sp.pem"), "email_attribute": "email", "name_attribute": "displayName",
				"groups_attribute": "groups", "sign_requests": o.SignRequests},
		},
		"apps": []any{
			map[string]any{"id": "whoami", "hosts": []string{host}, "providers": []string{"corp", "partner"},
				"allow": map[string]any{"groups": []string{"eng"}}},
			map[string]any{"id": "open", "hosts": []string{"open.example.com"}, "providers": []string{"corp"},
				"allow": map[string]any{"any_user": true}},
		},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	e.write(t, "wicket.json", b)
	e.ConfigPath = e.path("wicket.json")
	return e
}

// Getenv returns the variables the config file refers to.
func (e *Env) Getenv(k string) string {
	if k == "CORP_SECRET" {
		return ClientSecret
	}
	return ""
}

func (e *Env) path(name string) string { return filepath.Join(e.Dir, name) }

func (e *Env) write(t testing.TB, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(e.path(name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Target is a running gateway.
type Target struct {
	// Admin is the admin listener's base URL, e.g. http://127.0.0.1:4181.
	Admin string
	// Transport carries requests for Env.Public to the gateway. It may
	// rewrite the scheme when the gateway serves plain HTTP behind a
	// TLS-terminating proxy, as it does in production; the transcript
	// records the request as the browser made it.
	Transport http.RoundTripper
}

// PlainHTTP returns a transport that sends https:// requests for host to
// http://host, the way a TLS-terminating proxy in front of the gateway
// would.
func PlainHTTP(host string) http.RoundTripper {
	return plainHTTP{host: host, rt: &http.Transport{DisableKeepAlives: true}}
}

type plainHTTP struct {
	host string
	rt   http.RoundTripper
}

func (p plainHTTP) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" && req.URL.Host == p.host {
		r := req.Clone(req.Context())
		r.URL.Scheme = "http"
		return p.rt.RoundTrip(r)
	}
	return p.rt.RoundTrip(req)
}

// Recorder drives the gateway through a browser-like cookie jar and records
// only the gateway's exchanges; identity-provider hops are made but not
// recorded, since the provider is a test double.
type Recorder struct {
	t   testing.TB
	e   *Env
	tg  Target
	tr  *golden.Transcript
	jar *cookiejar.Jar
	seq int
}

// NewRecorder starts an empty transcript of tg.
func NewRecorder(t testing.TB, e *Env, tg Target) *Recorder {
	n := golden.NewNormalizer()
	n.Literal(e.Public, "public")
	n.Literal(e.Host, "host")
	n.Literal(e.IdP, "idp")
	n.Literal(tg.Admin, "admin")
	n.Clock(e.Clock.Now())
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
	return &Recorder{t: t, e: e, tg: tg, tr: tr, jar: jar}
}

// Bytes returns the transcript so far.
func (g *Recorder) Bytes() []byte { return g.tr.Bytes() }

// Do sends a request to the gateway with the jar's cookies for the gateway
// host, records it, stores any cookies it sets, and returns the raw body.
func (g *Recorder) Do(method, target string, hdr map[string]string, form url.Values) (*http.Response, string) {
	g.t.Helper()
	var body []byte
	if form != nil {
		body = []byte(form.Encode())
	}
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
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
	pub, _ := url.Parse(g.e.Public)
	for _, c := range g.jar.Cookies(pub) {
		req.AddCookie(c)
	}
	transport := g.tg.Transport
	if strings.HasPrefix(target, g.tg.Admin) {
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
func (g *Recorder) idp(method, target string, form url.Values) (*http.Response, string) {
	g.t.Helper()
	var rd io.Reader
	if form != nil {
		rd = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, target, rd)
	if err != nil {
		g.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	c := &http.Client{Transport: g.e.idpClient.Transport,
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
func (g *Recorder) signIn(page, user, pass string) (*http.Response, string) {
	g.t.Helper()
	resp, body := g.idp(http.MethodGet, page, nil)
	if resp.StatusCode != http.StatusOK {
		g.t.Fatalf("provider sign-in page: %d %s", resp.StatusCode, body)
	}
	action, fields := FormFields(body)
	fields.Set("username", user)
	fields.Set("password", pass)
	return g.idp(http.MethodPost, action, fields)
}

// loginOIDC records the gateway's side of an OpenID Connect login.
func (g *Recorder) loginOIDC(user, pass, rd string) {
	g.t.Helper()
	q := url.Values{"app": {"whoami"}, "provider": {"corp"}}
	if rd != "" {
		q.Set("rd", rd)
	}
	resp, _ := g.Do(http.MethodGet, g.e.Public+"/login?"+q.Encode(), map[string]string{"Accept": "text/html"}, nil)
	resp, body := g.signIn(resp.Header.Get("Location"), user, pass)
	if resp.StatusCode != http.StatusFound {
		g.t.Fatalf("provider sign-in: %d %s", resp.StatusCode, body)
	}
	if resp, body = g.Do(http.MethodGet, resp.Header.Get("Location"), map[string]string{"Accept": "text/html"}, nil); resp.StatusCode != http.StatusFound {
		g.t.Fatalf("callback: %d %s", resp.StatusCode, body)
	}
}

var issueInstantRe = regexp.MustCompile(`IssueInstant="[^"]*"`)

// authnRequest records the AuthnRequest carried by a redirect-binding URL,
// inflated, so its content is pinned and not only its presence.
func (g *Recorder) authnRequest(location string) {
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

// nginx describes the original request the way nginx auth_request does.
func (g *Recorder) nginx(uri string) map[string]string {
	return map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": g.e.Host, "X-Forwarded-Uri": uri}
}

var (
	hiddenRe = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)
	actionRe = regexp.MustCompile(`<form method="post" action="([^"]+)">`)
)

// FormFields returns the action and hidden fields of the first POST form in
// an HTML page.
func FormFields(body string) (action string, fields url.Values) {
	fields = url.Values{}
	for _, m := range hiddenRe.FindAllStringSubmatch(body, -1) {
		fields.Set(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	if m := actionRe.FindStringSubmatch(body); m != nil {
		action = html.UnescapeString(m[1])
	}
	return action, fields
}

// Scenario is one golden transcript: the file it is compared with, the
// configuration it needs, whether the gateway runs with AdminToken, and the
// steps.
type Scenario struct {
	File       string
	Options    Options
	AdminToken bool
	Run        func(g *Recorder)
}

// Scenarios are every golden transcript, in file order.
var Scenarios = []Scenario{
	{File: "forbidden-admin.txt", AdminToken: true, Run: forbiddenAndAdmin},
	{File: "oidc.txt", Run: oidcLogin},
	{File: "proxy-modes.txt", Run: proxyModes},
	{File: "saml-signed-requests.txt", Options: Options{SignRequests: true}, Run: samlLogin},
	{File: "saml.txt", Run: samlLogin},
}

// Check compares got with the golden file at path, or rewrites the file
// when update is set.
func Check(t testing.TB, path string, got []byte, update bool) {
	t.Helper()
	if err := golden.Check(path, got, update); err != nil {
		t.Fatal(err)
	}
}

func oidcLogin(g *Recorder) {
	e, tr := g.e, g.tr
	tr.Step("anonymous forward-auth from nginx")
	g.Do(http.MethodGet, e.Public+"/auth", g.nginx("/private?x=1"), nil)
	tr.Step("provider chooser")
	g.Do(http.MethodGet, e.Public+"/login?app=whoami&rd="+url.QueryEscape(e.Public+"/private?x=1"), map[string]string{"Accept": "text/html"}, nil)
	tr.Step("OpenID Connect login and callback")
	g.loginOIDC("alice", "alice-pass", e.Public+"/private?x=1")
	tr.Step("signed-in forward-auth with identity headers and upstream token")
	g.Do(http.MethodGet, e.Public+"/auth", g.nginx("/private"), nil)
	tr.Step("published keys")
	g.Do(http.MethodGet, e.Public+"/.well-known/jwks.json", nil, nil)
	tr.Step("logout confirmation page")
	_, page := g.Do(http.MethodGet, e.Public+"/logout", map[string]string{"Accept": "text/html"}, nil)
	action, form := FormFields(page)
	tr.Step("logout")
	g.Do(http.MethodPost, action, map[string]string{"Accept": "text/html"}, form)
	tr.Step("forward-auth after logout")
	g.Do(http.MethodGet, e.Public+"/auth", g.nginx("/private"), nil)
	tr.Step("logged-out page and health")
	g.Do(http.MethodGet, e.Public+"/logged-out", map[string]string{"Accept": "text/html"}, nil)
	g.Do(http.MethodGet, e.Public+"/healthz", nil, nil)
	tr.Step("unknown path")
	g.Do(http.MethodGet, e.Public+"/nope", map[string]string{"Accept": "application/json"}, nil)
}

func samlLogin(g *Recorder) {
	e, tr := g.e, g.tr
	tr.Step("service provider metadata")
	g.Do(http.MethodGet, e.Public+"/saml/partner/metadata", nil, nil)
	tr.Step("SAML login redirect")
	resp, _ := g.Do(http.MethodGet, e.Public+"/login?app=whoami&provider=partner", map[string]string{"Accept": "text/html"}, nil)
	g.authnRequest(resp.Header.Get("Location"))
	resp, body := g.signIn(resp.Header.Get("Location"), "carol", "carol-pass")
	if resp.StatusCode != http.StatusOK {
		g.t.Fatalf("provider sign-in: %d %s", resp.StatusCode, body)
	}
	acs, form := FormFields(body)
	tr.Step("assertion consumer service")
	g.Do(http.MethodPost, acs, map[string]string{"Accept": "text/html"}, form)
	tr.Step("replayed assertion")
	g.Do(http.MethodPost, acs, map[string]string{"Accept": "text/html"}, form)
	tr.Step("signed-in forward-auth")
	g.Do(http.MethodGet, e.Public+"/auth", g.nginx("/"), nil)
}

func proxyModes(g *Recorder) {
	e, tr := g.e, g.tr
	anon := func(target string, hdr map[string]string) {
		// Proxy calls without the browser's cookies.
		saved := g.jar
		g.jar, _ = cookiejar.New(nil)
		g.Do(http.MethodGet, target, hdr, nil)
		g.jar = saved
	}

	tr.Step("nginx with X-Original-URL")
	anon(e.Public+"/auth", map[string]string{"X-Original-URL": e.Public + "/a?b=1"})
	tr.Step("Traefik redirect mode: browser navigation")
	anon(e.Public+"/auth?redirect=1", map[string]string{"X-Forwarded-Host": e.Host, "X-Forwarded-Uri": "/x",
		"Accept": "text/html", "X-Forwarded-Method": "GET"})
	tr.Step("Traefik redirect mode: API call, script and POST")
	anon(e.Public+"/auth?redirect=1", map[string]string{"X-Forwarded-Host": e.Host, "Accept": "application/json"})
	anon(e.Public+"/auth?redirect=1", map[string]string{"X-Forwarded-Host": e.Host, "Accept": "text/html", "X-Requested-With": "XMLHttpRequest"})
	anon(e.Public+"/auth?redirect=1", map[string]string{"X-Forwarded-Host": e.Host, "Accept": "text/html", "X-Forwarded-Method": "POST"})
	tr.Step("Envoy ext_authz: browser")
	anon(e.Public+"/auth/envoy/docs/page?q=1", map[string]string{"Accept": "text/html"})
	tr.Step("Envoy ext_authz: API call")
	anon(e.Public+"/auth/envoy/api", map[string]string{"Accept": "application/json"})
	tr.Step("unknown host and no host")
	anon(e.Public+"/auth", map[string]string{"X-Forwarded-Host": "unknown.example.com"})
	anon(e.Public+"/auth", nil)
	tr.Step("explicit app with a return address outside the allow-list")
	anon(e.Public+"/auth?app=open", map[string]string{"X-Forwarded-Host": "evil.com", "X-Forwarded-Uri": "/x"})

	g.loginOIDC("alice", "alice-pass", "")
	tr.Step("signed in: Envoy")
	g.Do(http.MethodGet, e.Public+"/auth/envoy/", nil, nil)
	tr.Step("signed in: HEAD")
	g.Do(http.MethodHead, e.Public+"/auth", map[string]string{"X-Forwarded-Host": e.Host}, nil)
	tr.Step("signed in: the other app by host:443")
	g.Do(http.MethodGet, e.Public+"/auth", map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "open.example.com:443", "X-Forwarded-Uri": "/"}, nil)
	tr.Step("forged session cookie")
	saved := g.jar
	g.jar, _ = cookiejar.New(nil)
	pub, _ := url.Parse(e.Public)
	g.jar.SetCookies(pub, []*http.Cookie{{Name: sessionCookie, Value: "forged-value-0123456789"}})
	g.Do(http.MethodGet, e.Public+"/auth", g.nginx("/"), nil)
	g.jar = saved
}

func forbiddenAndAdmin(g *Recorder) {
	e, tr, admin := g.e, g.tr, g.tg.Admin
	bearer := map[string]string{"Authorization": "Bearer " + AdminToken}
	g.loginOIDC("bob", "bob-pass", "")
	tr.Step("forbidden: API call")
	g.Do(http.MethodGet, e.Public+"/auth", g.nginx("/"), nil)
	tr.Step("forbidden: browser page with sign-out form")
	g.Do(http.MethodGet, e.Public+"/auth", map[string]string{"X-Forwarded-Host": e.Host, "X-Forwarded-Uri": "/", "Accept": "text/html"}, nil)

	tr.Step("admin without a token")
	g.Do(http.MethodGet, admin+"/admin/sessions", nil, nil)
	tr.Step("admin session list")
	_, list := g.Do(http.MethodGet, admin+"/admin/sessions?subject=bob", bearer, nil)
	tr.Step("admin bad requests")
	g.Do(http.MethodGet, admin+"/admin/sessions?limit=0", bearer, nil)
	g.Do(http.MethodDelete, admin+"/admin/sessions/not-an-id", bearer, nil)
	g.Do(http.MethodDelete, admin+"/admin/sessions/"+strings.Repeat("0", 32), bearer, nil)
	tr.Step("admin revokes the session")
	var sessions struct {
		Sessions []struct {
			ID string `json:"id"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(list), &sessions); err != nil || len(sessions.Sessions) != 1 {
		g.t.Fatalf("sessions for bob: %v %s", err, list)
	}
	g.Do(http.MethodDelete, admin+"/admin/sessions/"+sessions.Sessions[0].ID, bearer, nil)
	tr.Step("forward-auth after revocation")
	g.Do(http.MethodGet, e.Public+"/auth", g.nginx("/"), nil)
	tr.Step("admin reload and health")
	g.Do(http.MethodPost, admin+"/admin/reload", bearer, nil)
	g.Do(http.MethodGet, admin+"/healthz", nil, nil)
}
