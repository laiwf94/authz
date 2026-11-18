//go:build interop

package interop

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/cmd/authz/internal/gateway"
)

// logoutWithin is how long a logout at Keycloak may take to end the
// matching gateway session (#79).
const logoutWithin = 2 * time.Second

const (
	clientID     = "gateway"
	clientSecret = "interop-client-secret-0123456789abcdef"
	alicePass    = "alice-interop-pass-0123"
	bobPass      = "bob-interop-pass-0123"
)

// world is one Keycloak realm and one gateway configured against it.
type world struct {
	t      *testing.T
	kc     string // Keycloak base URL
	realm  string
	tr     *http.Transport
	public string // the gateway's public URL
	host   string // its host:port, also the app's host
	dir    string
	logs   *syncBuf
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func mustEnv(t *testing.T, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Fatalf("%s is not set; run scripts/interop-keycloak.sh", k)
	}
	return v
}

// newWorld creates the realm (replacing one left over from an earlier run)
// and starts a gateway for it on a free loopback port.
func newWorld(t *testing.T, realm string) *world {
	t.Helper()
	w := &world{t: t, kc: strings.TrimSuffix(mustEnv(t, "KEYCLOAK_URL"), "/"), realm: realm, dir: t.TempDir(), logs: &syncBuf{}}
	caFile := mustEnv(t, "INTEROP_CA")
	pemCA, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemCA) {
		t.Fatalf("no certificate in %s", caFile)
	}
	w.tr = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	t.Cleanup(w.tr.CloseIdleConnections)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w.host = l.Addr().String()
	l.Close()
	w.public = "https://" + w.host

	spCert := w.spKeys()
	w.createRealm(spCert)
	t.Cleanup(func() { w.admin(http.MethodDelete, "", nil) })

	code, descriptor := w.get(w.kc + "/realms/" + realm + "/protocol/saml/descriptor")
	if code != http.StatusOK {
		t.Fatalf("SAML descriptor: %d %s", code, descriptor)
	}
	w.write("idp.xml", []byte(descriptor))
	w.startGateway(caFile)
	return w
}

// spKeys writes the gateway's SAML key and certificate and returns the
// certificate for Keycloak's client.
func (w *world) spKeys() *x509.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		w.t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "authz interop SP"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		w.t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	w.write("sp-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	w.write("sp.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return cert
}

func (w *world) write(name string, b []byte) string {
	w.t.Helper()
	p := filepath.Join(w.dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func user(name, first, pass string) map[string]any {
	return map[string]any{"username": name, "enabled": true, "email": name + "@example.com", "emailVerified": true,
		"firstName": first, "lastName": "Interop",
		"credentials": []any{map[string]any{"type": "password", "value": pass, "temporary": false}}}
}

// createRealm makes the realm with alice and bob, an OpenID Connect client
// that is told about logouts on the back channel, and a SAML client that
// verifies the gateway's signatures and sends it LogoutRequests on the
// back channel (POST binding).
func (w *world) createRealm(spCert *x509.Certificate) {
	w.t.Helper()
	if code, body := w.admin(http.MethodDelete, "", nil); code != http.StatusNoContent && code != http.StatusNotFound {
		w.t.Fatalf("deleting realm %s: %d %s", w.realm, code, body)
	}
	oidcClient := map[string]any{
		"clientId": clientID, "protocol": "openid-connect", "enabled": true, "publicClient": false,
		"clientAuthenticatorType": "client-secret", "secret": clientSecret,
		"standardFlowEnabled": true, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false,
		"redirectUris": []string{w.public + "/callback/corp"}, "frontchannelLogout": false,
		"attributes": map[string]string{
			"backchannel.logout.url":              w.public + "/backchannel-logout/corp",
			"backchannel.logout.session.required": "true",
			"post.logout.redirect.uris":           w.public + "/logged-out",
		},
	}
	slo := w.public + "/saml/partner/slo"
	samlClient := map[string]any{
		"clientId": w.public + "/saml/partner/metadata", "protocol": "saml", "enabled": true,
		"redirectUris": []string{w.public + "/*"}, "frontchannelLogout": false,
		"attributes": map[string]string{
			"saml_assertion_consumer_url_post":        w.public + "/saml/partner/acs",
			"saml_single_logout_service_url_post":     slo,
			"saml_single_logout_service_url_redirect": slo,
			"saml.server.signature":                   "true",
			"saml.assertion.signature":                "true",
			"saml.client.signature":                   "true",
			"saml.signing.certificate":                base64.StdEncoding.EncodeToString(spCert.Raw),
			"saml.signature.algorithm":                "RSA_SHA256",
			"saml_signature_canonicalization_method":  "http://www.w3.org/2001/10/xml-exc-c14n#",
			"saml.authnstatement":                     "true",
			"saml_name_id_format":                     "username",
		},
		"protocolMappers": []any{map[string]any{
			"name": "email", "protocol": "saml", "protocolMapper": "saml-user-property-mapper",
			"config": map[string]string{"user.attribute": "email", "attribute.name": "email", "attribute.nameformat": "Basic"},
		}},
	}
	rep := map[string]any{"realm": w.realm, "enabled": true, "sslRequired": "external",
		"users":   []any{user("alice", "Alice", alicePass), user("bob", "Bob", bobPass)},
		"clients": []any{oidcClient, samlClient}}
	if code, body := w.adminAt(http.MethodPost, w.kc+"/admin/realms", rep); code != http.StatusCreated {
		w.t.Fatalf("creating realm %s: %d %s", w.realm, code, body)
	}
}

// startGateway runs "authz gateway" in this process, as the binary does,
// until the test ends.
func (w *world) startGateway(caFile string) {
	w.t.Helper()
	cfg := map[string]any{
		"public_url": w.public,
		"providers": []any{
			map[string]any{"id": "corp", "type": "oidc", "display_name": "Keycloak (OpenID Connect)",
				"issuer": w.kc + "/realms/" + w.realm, "client_id": clientID, "client_secret_env": "INTEROP_CLIENT_SECRET",
				"ca_file": caFile, "post_logout_redirect_url": w.public + "/logged-out"},
			map[string]any{"id": "partner", "type": "saml", "display_name": "Keycloak (SAML)",
				"idp_metadata_file": filepath.Join(w.dir, "idp.xml"), "sp_key_file": filepath.Join(w.dir, "sp-key.pem"),
				"sp_cert_file": filepath.Join(w.dir, "sp.pem"), "sign_requests": true, "email_attribute": "email"},
		},
		"apps": []any{map[string]any{"id": "whoami", "hosts": []string{w.host}, "providers": []string{"corp", "partner"},
			"allow": map[string]any{"any_user": true}}},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	key := make([]byte, 32)
	rand.Read(key)
	env := map[string]string{
		"WICKET_CONFIG":         w.write("gateway.json", b),
		"WICKET_COOKIE_KEYS":    hex.EncodeToString(key),
		"WICKET_ADDR":           w.host,
		"WICKET_ADMIN_ADDR":     "127.0.0.1:0",
		"WICKET_TLS_CERT":       mustEnv(w.t, "INTEROP_TLS_CERT"),
		"WICKET_TLS_KEY":        mustEnv(w.t, "INTEROP_TLS_KEY"),
		"WICKET_LOGIN_RATE":     "1000",
		"WICKET_LOG_LEVEL":      "debug",
		"INTEROP_CLIENT_SECRET": clientSecret,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- gateway.Run(ctx, nil, func(k string) string { return env[k] }, nil, w.logs, w.logs) }()
	w.t.Cleanup(func() {
		cancel()
		select {
		case code := <-done:
			if code != 0 {
				w.t.Errorf("gateway exited %d\n%s", code, w.logs.String())
			}
		case <-time.After(30 * time.Second):
			w.t.Error("the gateway did not stop in 30s")
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case code := <-done:
			w.t.Fatalf("gateway exited %d\n%s", code, w.logs.String())
		default:
		}
		if code, _ := w.get(w.public + "/healthz"); code == http.StatusOK {
			return
		}
		if time.Now().After(deadline) {
			w.t.Fatalf("the gateway did not answer /healthz in 15s\n%s", w.logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (w *world) get(u string) (int, string) {
	resp, err := (&http.Client{Transport: w.tr, Timeout: 10 * time.Second}).Get(u)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// adminToken signs in to the master realm's admin-cli for one call, so a
// long run never meets an expired token.
func (w *world) adminToken() string {
	w.t.Helper()
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {mustEnv(w.t, "KEYCLOAK_ADMIN_USER")}, "password": {mustEnv(w.t, "KEYCLOAK_ADMIN_PASSWORD")}}
	resp, err := (&http.Client{Transport: w.tr, Timeout: 10 * time.Second}).PostForm(w.kc+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		w.t.Fatalf("admin sign-in: %d %v", resp.StatusCode, err)
	}
	return out.AccessToken
}

// admin calls the realm's admin API at path (relative to
// /admin/realms/<realm>).
func (w *world) admin(method, path string, body any) (int, []byte) {
	return w.adminAt(method, w.kc+"/admin/realms/"+w.realm+path, body)
}

func (w *world) adminAt(method, u string, body any) (int, []byte) {
	w.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, u, rd)
	req.Header.Set("Authorization", "Bearer "+w.adminToken())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Transport: w.tr, Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (w *world) userID(name string) string {
	w.t.Helper()
	code, body := w.admin(http.MethodGet, "/users?exact=true&username="+url.QueryEscape(name), nil)
	var users []struct {
		ID string `json:"id"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &users) != nil || len(users) != 1 {
		w.t.Fatalf("user %s: %d %s", name, code, body)
	}
	return users[0].ID
}

// sessions lists the user's Keycloak sessions.
func (w *world) sessions(name string) []string {
	w.t.Helper()
	code, body := w.admin(http.MethodGet, "/users/"+w.userID(name)+"/sessions", nil)
	var ss []struct {
		ID string `json:"id"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &ss) != nil {
		w.t.Fatalf("sessions of %s: %d %s", name, code, body)
	}
	ids := make([]string, len(ss))
	for i, s := range ss {
		ids[i] = s.ID
	}
	return ids
}

// newSession returns the one session in after that is not in before.
func (w *world) newSession(before, after []string) string {
	w.t.Helper()
	seen := map[string]bool{}
	for _, s := range before {
		seen[s] = true
	}
	var fresh []string
	for _, s := range after {
		if !seen[s] {
			fresh = append(fresh, s)
		}
	}
	if len(fresh) != 1 {
		w.t.Fatalf("want one new Keycloak session, have %v (before %v)", fresh, before)
	}
	return fresh[0]
}

// endSession ends one Keycloak session as an administrator does, which
// tells each of its clients on the back channel.
func (w *world) endSession(id string) {
	w.t.Helper()
	if code, body := w.admin(http.MethodDelete, "/sessions/"+id, nil); code != http.StatusNoContent {
		w.t.Fatalf("ending Keycloak session %s: %d %s", id, code, body)
	}
}

// count counts the gateway's log records of event with reason.
func (w *world) count(event, reason string) int {
	n := 0
	for _, line := range strings.Split(w.logs.String(), "\n") {
		if strings.Contains(line, `"event":"`+event+`"`) && (reason == "" || strings.Contains(line, `"reason":"`+reason+`"`)) {
			n++
		}
	}
	return n
}

func (w *world) wantCount(event, reason string, n int) {
	w.t.Helper()
	if got := w.count(event, reason); got != n {
		w.t.Fatalf("%d %s records with reason %q, want %d\n%s", got, event, reason, n, w.logs.String())
	}
}

// browser keeps cookies for Keycloak (localhost) and the gateway
// (127.0.0.1) and follows each redirect itself.
type browser struct {
	w    *world
	name string
	c    *http.Client
	jar  *cookiejar.Jar
}

func (w *world) browser(name string) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{w: w, name: name, jar: jar, c: &http.Client{Transport: w.tr, Jar: jar, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) do(method, u string, form url.Values) (*http.Response, string) {
	b.w.t.Helper()
	var rd io.Reader
	if form != nil {
		rd = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		b.w.t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.w.t.Fatalf("%s %s: %v", method, u, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

var (
	formRe  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	inputRe = regexp.MustCompile(`(?is)<(?:input|button)\b([^>]*)>`)
	attrRe  = regexp.MustCompile(`(?is)([a-z][a-z0-9_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

func attrs(s string) map[string]string {
	m := map[string]string{}
	for _, a := range attrRe.FindAllStringSubmatch(s, -1) {
		m[strings.ToLower(a[1])] = html.UnescapeString(a[2] + a[3])
	}
	return m
}

type form struct {
	action, method string
	fields         url.Values
}

// findForm returns the first form on the page with a field called name,
// with what a browser would send: every named field, and the first named
// submit button.
func findForm(page, name string) (form, bool) {
	for _, m := range formRe.FindAllStringSubmatch(page, -1) {
		fa := attrs(m[1])
		f := form{action: fa["action"], method: strings.ToUpper(fa["method"]), fields: url.Values{}}
		submitted, found := false, false
		for _, in := range inputRe.FindAllStringSubmatch(m[2], -1) {
			a := attrs(in[1])
			n := a["name"]
			if n == "" {
				continue
			}
			switch strings.ToLower(a["type"]) {
			case "submit", "button", "image":
				if !submitted {
					f.fields.Set(n, a["value"])
					submitted = true
				}
				continue
			}
			f.fields.Set(n, a["value"])
			if n == name {
				found = true
			}
		}
		if found {
			return f, true
		}
	}
	return form{}, false
}

func (b *browser) submit(from *http.Response, f form) (*http.Response, string) {
	b.w.t.Helper()
	u, err := from.Request.URL.Parse(f.action)
	if err != nil {
		b.w.t.Fatalf("form action %q: %v", f.action, err)
	}
	if f.method == "GET" {
		u.RawQuery = f.fields.Encode()
		return b.do(http.MethodGet, u.String(), nil)
	}
	return b.do(http.MethodPost, u.String(), f.fields)
}

// next takes the step a browser would take from this response: follow a
// redirect, fill in Keycloak's login form, or submit a self-posting SAML or
// logout confirmation form.
func (b *browser) next(resp *http.Response, page, user, pass string) (*http.Response, string) {
	b.w.t.Helper()
	switch resp.StatusCode {
	case http.StatusFound, http.StatusSeeOther, http.StatusMovedPermanently, http.StatusTemporaryRedirect:
		loc, err := resp.Location()
		if err != nil {
			b.w.t.Fatalf("redirect from %s: %v", resp.Request.URL, err)
		}
		return b.do(http.MethodGet, loc.String(), nil)
	case http.StatusOK:
		if f, ok := findForm(page, "password"); ok && user != "" {
			f.fields.Set("username", user)
			f.fields.Set("password", pass)
			return b.submit(resp, f)
		}
		for _, n := range []string{"SAMLResponse", "SAMLRequest", "session_code"} {
			if f, ok := findForm(page, n); ok {
				return b.submit(resp, f)
			}
		}
	}
	b.w.t.Fatalf("%s: nothing to do after %s %s: %d\n%s\ngateway log:\n%s", b.name, resp.Request.Method,
		resp.Request.URL, resp.StatusCode, page, b.w.logs.String())
	return nil, ""
}

func (b *browser) onGateway(resp *http.Response, path string) bool {
	return resp.Request.URL.Host == b.w.host && resp.Request.URL.Path == path
}

// signIn starts at the gateway's login for provider, signs in at Keycloak
// and stops once the gateway has answered its callback.
func (b *browser) signIn(provider, user, pass string) {
	b.w.t.Helper()
	cb := map[string]string{"corp": "/callback/corp", "partner": "/saml/partner/acs"}[provider]
	resp, page := b.do(http.MethodGet, b.w.public+"/login?app=whoami&provider="+provider, nil)
	for range 12 {
		if b.onGateway(resp, cb) {
			if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
				b.w.t.Fatalf("%s: %s answered %d\n%s\n%s", b.name, cb, resp.StatusCode, page, b.w.logs.String())
			}
			if !b.signedIn() {
				b.w.t.Fatalf("%s: not signed in after %s", b.name, cb)
			}
			return
		}
		resp, page = b.next(resp, page, user, pass)
	}
	b.w.t.Fatalf("%s: sign-in at %s did not reach %s", b.name, provider, cb)
}

// signedIn asks the forward-auth endpoint, as a reverse proxy does,
// whether the browser's gateway cookie still names a live session.
func (b *browser) signedIn() bool {
	b.w.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, b.w.public+"/auth", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", b.w.host)
	req.Header.Set("X-Forwarded-Uri", "/")
	u, _ := url.Parse(b.w.public)
	for _, c := range b.jar.Cookies(u) {
		req.AddCookie(c)
	}
	resp, err := (&http.Client{Transport: b.w.tr, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		b.w.t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true
	case http.StatusUnauthorized:
		return false
	}
	b.w.t.Fatalf("%s: /auth answered %d", b.name, resp.StatusCode)
	return false
}

func (b *browser) wantSignedIn() {
	b.w.t.Helper()
	if !b.signedIn() {
		b.w.t.Fatalf("%s was signed out\n%s", b.name, b.w.logs.String())
	}
}

// waitSignedOut requires the gateway session to end within logoutWithin
// of start, when the logout began at Keycloak.
func (b *browser) waitSignedOut(start time.Time) {
	b.w.t.Helper()
	for b.signedIn() {
		if time.Since(start) > logoutWithin {
			b.w.t.Fatalf("%s is still signed in %v after the logout at Keycloak\n%s", b.name, logoutWithin, b.w.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	b.w.t.Logf("%s signed out %v after the logout at Keycloak", b.name, time.Since(start).Round(time.Millisecond))
}

// logoutAtKeycloak signs the user out at Keycloak's own end-session page,
// confirming it as the user would.
func (b *browser) logoutAtKeycloak() {
	b.w.t.Helper()
	resp, page := b.do(http.MethodGet, b.w.kc+"/realms/"+b.w.realm+"/protocol/openid-connect/logout?client_id="+clientID, nil)
	f, ok := findForm(page, "session_code")
	if resp.StatusCode != http.StatusOK || !ok {
		b.w.t.Fatalf("%s: no logout confirmation at Keycloak: %d\n%s", b.name, resp.StatusCode, page)
	}
	if resp, page = b.submit(resp, f); resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		b.w.t.Fatalf("%s: Keycloak logout: %d\n%s", b.name, resp.StatusCode, page)
	}
}

// TestKeycloakBackchannelLogout: OpenID Connect Back-Channel Logout 1.0
// from Keycloak. Each way a session ends at Keycloak (an administrator
// ending one session, the user signing out at Keycloak, an administrator
// signing a user out everywhere) ends the matching gateway sessions within
// two seconds, by sid, and no others.
func TestKeycloakBackchannelLogout(t *testing.T) {
	w := newWorld(t, "authz-interop-oidc")
	laptop, phone, bob := w.browser("alice's laptop"), w.browser("alice's phone"), w.browser("bob")
	before := w.sessions("alice")
	laptop.signIn("corp", "alice", alicePass)
	mid := w.sessions("alice")
	laptopKC := w.newSession(before, mid)
	phone.signIn("corp", "alice", alicePass)
	w.newSession(mid, w.sessions("alice"))
	bob.signIn("corp", "bob", bobPass)

	// An administrator ends the laptop's Keycloak session: Keycloak posts a
	// logout token naming its sid, and only the laptop is signed out.
	start := time.Now()
	w.endSession(laptopKC)
	laptop.waitSignedOut(start)
	phone.wantSignedIn()
	bob.wantSignedIn()
	w.wantCount("session_ended", "backchannel_logout", 1)

	// Alice signs out at Keycloak on her phone.
	start = time.Now()
	phone.logoutAtKeycloak()
	phone.waitSignedOut(start)
	bob.wantSignedIn()
	if s := w.sessions("alice"); len(s) != 0 {
		t.Fatalf("alice still has Keycloak sessions %v", s)
	}
	w.wantCount("session_ended", "backchannel_logout", 2)

	// An administrator signs bob out everywhere.
	start = time.Now()
	if code, body := w.admin(http.MethodPost, "/users/"+w.userID("bob")+"/logout", nil); code != http.StatusNoContent {
		t.Fatalf("signing bob out: %d %s", code, body)
	}
	bob.waitSignedOut(start)
	w.wantCount("session_ended", "backchannel_logout", 3)
	w.wantCount("logout_rejected", "", 0)

	// Signing in again works: nothing was left half done.
	laptop.signIn("corp", "alice", alicePass)
}

// TestKeycloakSAMLSingleLogout: SAML single logout with Keycloak in both
// directions. IdP-initiated: Keycloak sends a signed LogoutRequest with the
// session's SessionIndex on the back channel, and only that browser's
// gateway session ends, within two seconds. SP-initiated: the gateway's
// signed LogoutRequest ends the Keycloak session and Keycloak's signed
// LogoutResponse brings the browser back to the gateway.
func TestKeycloakSAMLSingleLogout(t *testing.T) {
	w := newWorld(t, "authz-interop-saml")
	laptop, phone, bob := w.browser("alice's laptop"), w.browser("alice's phone"), w.browser("bob")
	before := w.sessions("alice")
	laptop.signIn("partner", "alice", alicePass)
	mid := w.sessions("alice")
	laptopKC := w.newSession(before, mid)
	phone.signIn("partner", "alice", alicePass)
	w.newSession(mid, w.sessions("alice"))
	bob.signIn("partner", "bob", bobPass)

	// IdP-initiated by an administrator: the laptop's SessionIndex only.
	start := time.Now()
	w.endSession(laptopKC)
	laptop.waitSignedOut(start)
	phone.wantSignedIn()
	bob.wantSignedIn()
	w.wantCount("session_ended", "saml_logout", 1)

	// IdP-initiated by the user, signing out at Keycloak on the phone.
	start = time.Now()
	phone.logoutAtKeycloak()
	phone.waitSignedOut(start)
	bob.wantSignedIn()
	w.wantCount("session_ended", "saml_logout", 2)

	// SP-initiated: bob signs out at the gateway.
	resp, page := bob.do(http.MethodGet, w.public+"/logout", nil)
	f, ok := findForm(page, "csrf")
	if !ok {
		t.Fatalf("no sign-out form: %d %s", resp.StatusCode, page)
	}
	resp, page = bob.submit(resp, f)
	for i := 0; !bob.onGateway(resp, "/saml/partner/slo"); i++ {
		if i == 10 {
			t.Fatalf("the LogoutResponse never came back to the gateway\n%s", w.logs.String())
		}
		resp, page = bob.next(resp, page, "", "")
	}
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound || loc != w.public+"/logged-out" {
		t.Fatalf("after the LogoutResponse: %d %q\n%s\n%s", resp.StatusCode, loc, page, w.logs.String())
	}
	if bob.signedIn() {
		t.Fatal("bob is still signed in at the gateway")
	}
	if s := w.sessions("bob"); len(s) != 0 {
		t.Fatalf("bob still has Keycloak sessions %v", s)
	}
	if strings.Contains(w.logs.String(), "did not end every session") {
		t.Fatalf("Keycloak answered with a partial logout\n%s", w.logs.String())
	}
	w.wantCount("logout_rejected", "", 0)
	if n := strings.Count(w.logs.String(), `"event":"logout"`); n < 1 {
		t.Fatalf("no logout record for bob\n%s", w.logs.String())
	}

	// Signing in again works.
	bob.signIn("partner", "bob", bobPass)
}
