package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/config"
	"github.com/laiwf94/authz/internal/authn/fakeidp"
	"github.com/laiwf94/authz/internal/authn/metrics"
	"github.com/laiwf94/authz/internal/authn/oidc"
	"github.com/laiwf94/authz/internal/authn/session"
	"github.com/laiwf94/authz/internal/platform/jose"
	"github.com/laiwf94/authz/internal/platform/seal"
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// syncBuffer collects log output from concurrent handlers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// harness runs wicket and fakeidp over real TLS listeners.
type harness struct {
	t         testing.TB
	idp       *fakeidp.IdP
	idpSrv    *httptest.Server
	srv       *Server
	pub       *httptest.Server
	admin     *httptest.Server
	public    string // wicket public URL
	host      string // host:port of wicket, also the app host
	clk       *clock
	logs      *syncBuffer
	sessions  *session.Store
	cfgPath   string
	dir       string
	spCert    *x509.Certificate
	signer    *jose.Signer
	cookieKey []byte
}

type harnessOpts struct {
	allow        string // JSON for the app's allow block
	sessionFile  bool
	encrypt      bool
	signRequests bool
	adminToken   string
	loginRate    int
	cfgMutate    func(cfg map[string]any)
}

const clientSecret = "test-client-secret-value"

func newHarness(t testing.TB, o harnessOpts) *harness {
	t.Helper()
	h := &harness{t: t, clk: &clock{t: time.Now()}, logs: &syncBuffer{}, dir: t.TempDir()}
	// Listeners first, so every URL is known before anything is built.
	h.idpSrv = httptest.NewUnstartedServer(nil)
	h.pub = httptest.NewUnstartedServer(nil)
	h.admin = httptest.NewUnstartedServer(nil)
	issuer := "https://" + h.idpSrv.Listener.Addr().String()
	h.host = h.pub.Listener.Addr().String()
	h.public = "https://" + h.host

	spKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	h.spCert, _ = fakeidp.SelfSignedCert(spKey, "sp", time.Now())
	keyDER, _ := x509.MarshalPKCS8PrivateKey(spKey)
	writeFile(t, h.dir, "sp-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	writeFile(t, h.dir, "sp.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.spCert.Raw}))

	sp := fakeidp.ServiceProvider{EntityID: h.public + "/saml/partner/metadata", ACSURL: h.public + "/saml/partner/acs",
		SignAssertion: true, SignResponse: true}
	if o.encrypt {
		sp.EncryptCert = h.spCert
	}
	if o.signRequests {
		sp.RequestCert = h.spCert
	}
	h.idp, err = fakeidp.New(fakeidp.Config{Issuer: issuer, Now: h.clk.Now,
		Clients: []fakeidp.Client{{ID: "wicket", Secret: clientSecret, RedirectURIs: []string{h.public + "/callback/corp"},
			PostLogoutRedirectURIs: []string{h.public + "/logged-out"}}},
		ServiceProviders: []fakeidp.ServiceProvider{sp}})
	if err != nil {
		t.Fatal(err)
	}
	h.idpSrv.Config.Handler = h.idp
	h.idpSrv.StartTLS()
	t.Cleanup(h.idpSrv.Close)
	writeFile(t, h.dir, "idp.xml", h.idp.Metadata())

	allow := o.allow
	if allow == "" {
		allow = `{"groups":["eng"]}`
	}
	var allowObj any
	if err := json.Unmarshal([]byte(allow), &allowObj); err != nil {
		t.Fatal(err)
	}
	saml := map[string]any{"id": "partner", "type": "saml", "display_name": "Partner SAML",
		"idp_metadata_file": filepath.Join(h.dir, "idp.xml"), "sp_key_file": filepath.Join(h.dir, "sp-key.pem"),
		"sp_cert_file": filepath.Join(h.dir, "sp.pem"), "email_attribute": "email", "name_attribute": "displayName",
		"groups_attribute": "groups", "sign_requests": o.signRequests}
	cfg := map[string]any{
		"public_url":     h.public,
		"redirect_hosts": []string{"app.example.com"},
		"providers": []any{
			map[string]any{"id": "corp", "type": "oidc", "display_name": "Corp SSO", "issuer": issuer,
				"client_id": "wicket", "client_secret_env": "CORP_SECRET", "userinfo": true,
				"post_logout_redirect_url": h.public + "/logged-out"},
			saml,
		},
		"apps": []any{
			map[string]any{"id": "whoami", "hosts": []string{h.host}, "providers": []string{"corp", "partner"}, "allow": allowObj},
			map[string]any{"id": "open", "hosts": []string{"open.example.com"}, "providers": []string{"corp"},
				"allow": map[string]any{"any_user": true}},
		},
	}
	if o.cfgMutate != nil {
		o.cfgMutate(cfg)
	}
	h.writeConfig(cfg)

	getenv := func(k string) string {
		if k == "CORP_SECRET" {
			return clientSecret
		}
		return ""
	}
	if o.loginRate == 0 {
		o.loginRate = 10_000 // the limiter has its own test
	}
	sopts := session.Options{Now: h.clk.Now}
	if o.sessionFile {
		sopts.Path = filepath.Join(h.dir, "sessions.log")
	}
	h.sessions, err = session.Open(sopts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.sessions.Close() })
	h.cookieKey = seal.RandomKey()
	keys, _ := seal.New([][]byte{h.cookieKey})
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h.signer, _ = jose.NewSigner(ek)
	idpTransport := h.idpSrv.Client().Transport.(*http.Transport)
	h.srv, err = New(Options{
		Load:     func() (*config.Config, error) { return config.Load(h.cfgPath, getenv) },
		Sessions: h.sessions, Keys: keys, Signers: []*jose.Signer{h.signer},
		Logger:  slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Metrics: metrics.New(), AdminToken: o.adminToken, LoginRate: o.loginRate,
		HTTPClient: func(*config.Provider) (*http.Client, error) { return oidc.NewHTTPClient(idpTransport.Clone()), nil },
		Now:        h.clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.pub.Config.Handler = h.srv.Handler()
	h.pub.StartTLS()
	t.Cleanup(h.pub.Close)
	h.admin.Config.Handler = h.srv.AdminHandler()
	h.admin.Start()
	t.Cleanup(h.admin.Close)
	return h
}

func writeFile(t testing.TB, dir, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) writeConfig(cfg map[string]any) {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	h.cfgPath = filepath.Join(h.dir, "wicket.json")
	writeFile(h.t, h.dir, "wicket.json", b)
}

// browser is a client with a cookie jar that does not follow redirects, so
// each step can be checked.
type browser struct {
	h   *harness
	c   *http.Client
	jar *cookiejar.Jar
}

func (h *harness) browser() *browser {
	jar, _ := cookiejar.New(nil)
	// A fresh client per browser (Server.Client returns a shared one); the
	// transport trusts the httptest certificate every server uses.
	c := &http.Client{Transport: h.pub.Client().Transport, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &browser{h: h, c: c, jar: jar}
}

func (b *browser) do(req *http.Request) *http.Response {
	b.h.t.Helper()
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html")
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.h.t.Fatal(err)
	}
	return resp
}

func (b *browser) get(u string) (*http.Response, string) {
	b.h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	resp := b.do(req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func (b *browser) post(u string, form url.Values) (*http.Response, string) {
	b.h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := b.do(req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

var hiddenRe = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)
var actionRe = regexp.MustCompile(`<form method="post" action="([^"]+)">`)

func formFields(body string) (action string, fields url.Values) {
	fields = url.Values{}
	for _, m := range hiddenRe.FindAllStringSubmatch(body, -1) {
		fields.Set(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	if m := actionRe.FindStringSubmatch(body); m != nil {
		action = html.UnescapeString(m[1])
	}
	return action, fields
}

// auth calls the forward-auth endpoint the way nginx does, with the
// browser's cookies for the app.
func (b *browser) auth(path string, extra http.Header) *http.Response {
	b.h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, b.h.public+"/auth", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", b.h.host)
	req.Header.Set("X-Forwarded-Uri", path)
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
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// loginOIDC runs the whole OpenID Connect login and returns the final
// redirect target.
func (b *browser) loginOIDC(user, pass, rd string) string {
	b.h.t.Helper()
	q := url.Values{"app": {"whoami"}, "provider": {"corp"}}
	if rd != "" {
		q.Set("rd", rd)
	}
	resp, _ := b.get(b.h.public + "/login?" + q.Encode())
	if resp.StatusCode != http.StatusFound {
		b.h.t.Fatalf("login: status %d", resp.StatusCode)
	}
	authURL := resp.Header.Get("Location")
	resp, body := b.get(authURL)
	if resp.StatusCode != http.StatusOK {
		b.h.t.Fatalf("authorize form: %d %s", resp.StatusCode, body)
	}
	action, fields := formFields(body)
	fields.Set("username", user)
	fields.Set("password", pass)
	resp, body = b.post(action, fields)
	if resp.StatusCode != http.StatusFound {
		b.h.t.Fatalf("authorize submit: %d %s", resp.StatusCode, body)
	}
	resp, body = b.get(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound {
		b.h.t.Fatalf("callback: %d %s\nlogs:\n%s", resp.StatusCode, body, b.h.logs.String())
	}
	return resp.Header.Get("Location")
}

// samlResponseFor starts a SAML login and signs in at the IdP, returning
// the ACS URL and form the IdP would auto-post, without posting it.
func (b *browser) samlResponseFor(user, pass string) (string, url.Values) {
	b.h.t.Helper()
	resp, _ := b.get(b.h.public + "/login?app=whoami&provider=partner")
	if resp.StatusCode != http.StatusFound {
		b.h.t.Fatalf("login: status %d", resp.StatusCode)
	}
	resp, body := b.get(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusOK {
		b.h.t.Fatalf("sso form: %d %s", resp.StatusCode, body)
	}
	action, fields := formFields(body)
	fields.Set("username", user)
	fields.Set("password", pass)
	resp, body = b.post(action, fields)
	if resp.StatusCode != http.StatusOK {
		b.h.t.Fatalf("sso submit: %d %s", resp.StatusCode, body)
	}
	return formFields(body)
}

func (b *browser) loginSAML(user, pass string) *http.Response {
	b.h.t.Helper()
	acs, form := b.samlResponseFor(user, pass)
	resp, _ := b.post(acs, form)
	return resp
}

// noRedirect is a cookie-less client that shows redirects instead of
// following them, like a reverse proxy calling /auth.
func (h *harness) noRedirect() *http.Client {
	return &http.Client{Transport: h.pub.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (h *harness) adminDo(method, path, token string, body string) (*http.Response, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.admin.URL+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func (h *harness) expectAudit(event, reason string) {
	h.t.Helper()
	want := fmt.Sprintf(`"event":"%s"`, event)
	for _, line := range strings.Split(h.logs.String(), "\n") {
		if strings.Contains(line, want) && (reason == "" || strings.Contains(line, `"reason":"`+reason+`"`)) {
			return
		}
	}
	h.t.Fatalf("no audit event %s (reason %q) in logs:\n%s", event, reason, h.logs.String())
}

var _ = context.Background
