// Package fakeidp is a small identity provider for tests and the demo. It
// speaks OpenID Connect (discovery, authorize with PKCE, token, JWKS,
// userinfo, end-session) and SAML 2.0 (metadata, HTTP-Redirect SSO, signed
// and optionally encrypted HTTP-POST responses) for a fixed list of users.
//
// It is strict where a real provider is strict (exact redirect URIs,
// single-use codes, PKCE, registered ACS URLs) so tests can't pass only
// because the fake is lenient. It is not meant for production use.
package fakeidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// User is a demo account.
type User struct {
	Username string
	Password string
	Email    string
	Name     string
	Groups   []string
}

// DemoUsers are the accounts used by the demo and tests.
var DemoUsers = []User{
	{Username: "alice", Password: "alice-pass", Email: "alice@example.org", Name: "Alice", Groups: []string{"eng", "admins"}},
	{Username: "bob", Password: "bob-pass", Email: "bob@example.org", Name: "Bob", Groups: []string{"sales"}},
	{Username: "carol", Password: "carol-pass", Email: "carol@partner.example", Name: "Carol", Groups: []string{"eng"}},
}

// Client is a registered OpenID Connect client.
type Client struct {
	ID                     string
	Secret                 string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
}

// ServiceProvider is a registered SAML service provider.
type ServiceProvider struct {
	EntityID      string
	ACSURL        string
	SignResponse  bool
	SignAssertion bool
	// EncryptCert, when set, makes the IdP encrypt assertions to this
	// certificate with AES-256-GCM and RSA-OAEP.
	EncryptCert *x509.Certificate
	// RequestCert, when set, requires AuthnRequests signed with this
	// certificate's key.
	RequestCert *x509.Certificate
}

// Config configures the identity provider.
type Config struct {
	// Issuer is the external base URL, e.g. https://localhost:9443.
	Issuer           string
	Users            []User
	Clients          []Client
	ServiceProviders []ServiceProvider
	Now              func() time.Time
}

// IdP is the identity provider. It is safe for concurrent use.
type IdP struct {
	cfg    Config
	rsaKey *rsa.PrivateKey
	cert   *x509.Certificate
	mux    *http.ServeMux

	mu        sync.Mutex
	codes     map[string]*grant
	tokens    map[string]*grant
	refreshes map[string]*grant // live refresh tokens
	down      bool              // the token endpoint answers 503
}

// New generates fresh signing keys and builds the IdP.
func New(cfg Config) (*IdP, error) {
	u, err := url.Parse(cfg.Issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("fakeidp: issuer must be an absolute URL")
	}
	cfg.Issuer = strings.TrimSuffix(cfg.Issuer, "/")
	if cfg.Users == nil {
		cfg.Users = DemoUsers
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	cert, err := SelfSignedCert(rk, "fakeidp signing", cfg.Now())
	if err != nil {
		return nil, err
	}
	i := &IdP{cfg: cfg, rsaKey: rk, cert: cert, codes: map[string]*grant{}, tokens: map[string]*grant{},
		refreshes: map[string]*grant{}}
	i.mux = http.NewServeMux()
	i.mux.HandleFunc("GET /.well-known/openid-configuration", i.discovery)
	i.mux.HandleFunc("GET /jwks", i.jwks)
	i.mux.HandleFunc("GET /authorize", i.authorizeForm)
	i.mux.HandleFunc("POST /authorize", i.authorizeSubmit)
	i.mux.HandleFunc("POST /token", i.token)
	i.mux.HandleFunc("GET /userinfo", i.userinfo)
	i.mux.HandleFunc("GET /logout", i.endSession)
	i.mux.HandleFunc("GET /saml/metadata", i.samlMetadata)
	i.mux.HandleFunc("GET /saml/sso", i.samlForm)
	i.mux.HandleFunc("POST /saml/sso", i.samlSubmit)
	i.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	return i, nil
}

// ServeHTTP implements http.Handler.
func (i *IdP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action *; script-src 'unsafe-inline'")
	i.mux.ServeHTTP(w, r)
}

// Certificate returns the SAML signing certificate.
func (i *IdP) Certificate() *x509.Certificate { return i.cert }

// SigningKey returns the RSA key that signs ID tokens and SAML messages.
func (i *IdP) SigningKey() *rsa.PrivateKey { return i.rsaKey }

func (i *IdP) user(username, password string) (*User, bool) {
	for k := range i.cfg.Users {
		u := &i.cfg.Users[k]
		if subtle.ConstantTimeCompare([]byte(u.Username), []byte(username)) == 1 &&
			subtle.ConstantTimeCompare([]byte(u.Password), []byte(password)) == 1 {
			return u, true
		}
	}
	return nil, false
}

// SelfSignedCert issues a one-year self-signed certificate for key.
func SelfSignedCert(key *rsa.PrivateKey, cn string, now time.Time) (*x509.Certificate, error) {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>fakeidp sign in</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1d2330;display:grid;place-items:center;min-height:100vh;margin:0;padding:16px;box-sizing:border-box}
form{background:#fff;padding:28px;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.12);width:100%;max-width:340px}
h1{font-size:20px;margin:0 0 4px}p{color:#5b6475;margin:0 0 20px;font-size:14px}
label{display:block;font-size:14px;margin:12px 0 4px}input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #c5cad3;border-radius:6px;font:inherit}
button{margin-top:20px;width:100%;padding:11px;border:0;border-radius:6px;background:#2f5bd3;color:#fff;font:inherit;cursor:pointer}
.err{color:#b42318}
</style></head><body>
<form method="post" action="{{.Action}}">
<h1>Sign in</h1><p>Test identity provider ({{.Protocol}}). Demo users: alice, bob, carol.</p>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
{{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<label for="u">Username</label><input id="u" name="username" autocomplete="username" required>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form></body></html>`))

type loginView struct {
	Action   string
	Protocol string
	Error    string
	Hidden   map[string]string
}

func renderLogin(w http.ResponseWriter, status int, v loginView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = loginPage.Execute(w, v)
}

func httpError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(msg + "\n"))
}
