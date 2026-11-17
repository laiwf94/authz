package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/egress"
	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/platform/jose"
)

const issuersBase = `{"agents":[],"upstreams":[{"name":"fake","url":"http://127.0.0.1:1/mcp"}],"issuers":%s}`

func goodIssuer() map[string]any {
	return map[string]any{"issuer": "https://idp.example.com", "audience": "https://mcp.example.com",
		"jwks_uri": "https://idp.example.com/jwks.json", "algorithms": []string{"ES256"},
		"claims": map[string]any{"subject": "azp", "scopes": "scp"}, "max_ttl_seconds": 900,
		"private_networks": []string{"10.0.0.0/8", "192.168.1.7"}, "ca_file": ""}
}

func parseIssuers(t *testing.T, list ...map[string]any) (*Config, error) {
	t.Helper()
	b, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	return ParseConfig(fmt.Appendf(nil, issuersBase, b), nil)
}

func TestParseConfigIssuers(t *testing.T) {
	c, err := parseIssuers(t, goodIssuer())
	if err != nil {
		t.Fatal(err)
	}
	want := IssuerConfig{Issuer: "https://idp.example.com", Audience: "https://mcp.example.com",
		JWKSURI: "https://idp.example.com/jwks.json", Algorithms: []string{"ES256"},
		Claims: ClaimsConfig{Subject: "azp", Scopes: "scp"}, MaxTTLSeconds: 900,
		PrivateNetworks: []string{"10.0.0.0/8", "192.168.1.7"}}
	if len(c.Issuers) != 1 || fmt.Sprint(c.Issuers[0]) != fmt.Sprint(want) {
		t.Fatalf("issuers %+v", c.Issuers)
	}
	// The least an issuer needs.
	if _, err := parseIssuers(t, map[string]any{"issuer": "i", "audience": "a", "jwks_uri": "https://i/k"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseConfig(fmt.Appendf(nil, issuersBase, "null"), nil); err != nil {
		t.Fatal(err)
	}

	with := func(kv ...any) map[string]any {
		m := goodIssuer()
		for i := 0; i < len(kv); i += 2 {
			if kv[i+1] == nil {
				delete(m, kv[i].(string))
			} else {
				m[kv[i].(string)] = kv[i+1]
			}
		}
		return m
	}
	many := make([]map[string]any, identity.MaxIssuers+1)
	for i := range many {
		many[i] = with("issuer", fmt.Sprintf("https://idp%d.example.com", i))
	}
	nets := make([]string, MaxPrivateNetworks+1)
	for i := range nets {
		nets[i] = fmt.Sprintf("10.0.%d.0/24", i)
	}
	for _, tc := range []struct {
		name string
		list []map[string]any
		want string
	}{
		{"no issuer", []map[string]any{with("issuer", nil)}, "issuers[0]: issuer is required"},
		{"no audience", []map[string]any{with("audience", "")}, "issuers[0]: audience is required"},
		{"long issuer", []map[string]any{with("issuer", strings.Repeat("i", identity.MaxIssuerBytes+1))}, "at most 1024 bytes"},
		{"no jwks_uri", []map[string]any{with("jwks_uri", nil)}, "issuers[0]: jwks_uri is required"},
		{"http jwks_uri", []map[string]any{with("jwks_uri", "http://idp.example.com/jwks")}, "must be an absolute https URL"},
		{"relative jwks_uri", []map[string]any{with("jwks_uri", "/jwks")}, "must be an absolute https URL"},
		{"jwks_uri user", []map[string]any{with("jwks_uri", "https://u:p@idp.example.com/jwks")}, "without user info"},
		{"jwks_uri fragment", []map[string]any{with("jwks_uri", "https://idp.example.com/jwks#x")}, "or fragment"},
		{"HS256", []map[string]any{with("algorithms", []string{"HS256"})}, `algorithm "HS256" is not one of`},
		{"PS256", []map[string]any{with("algorithms", []string{"PS256"})}, `algorithm "PS256" is not one of`},
		{"alg twice", []map[string]any{with("algorithms", []string{"RS256", "RS256"})}, "RS256 is listed twice"},
		{"subject iss", []map[string]any{with("claims", map[string]any{"subject": "iss"})}, `claim "iss" is checked on its own`},
		{"owner exp", []map[string]any{with("claims", map[string]any{"owner": "exp"})}, `claim "exp" is checked on its own`},
		{"same claims", []map[string]any{with("claims", map[string]any{"subject": "x", "scopes": "x"})}, "must differ"},
		{"control claim", []map[string]any{with("claims", map[string]any{"subject": "a\nb"})}, "control character"},
		{"unknown claim member", []map[string]any{with("claims", map[string]any{"role": "x"})}, `unknown field "role"`},
		{"negative ttl", []map[string]any{with("max_ttl_seconds", -1)}, "max_ttl_seconds must be from 0 to 86400"},
		{"long ttl", []map[string]any{with("max_ttl_seconds", 86401)}, "max_ttl_seconds must be from 0 to 86400"},
		{"bad network", []map[string]any{with("private_networks", []string{"10.0.0.0/8", "intranet"})}, `private_networks: "intranet" is neither an address nor a CIDR range`},
		{"many networks", []map[string]any{with("private_networks", nets)}, "more than 16 entries"},
		{"unknown member", []map[string]any{with("jwks_url", "https://x/y")}, `unknown field "jwks_url"`},
		{"twice", []map[string]any{goodIssuer(), with("audience", "other")}, `issuers[1]: issuer "https://idp.example.com" is configured twice`},
		{"too many", many, "at most 32 issuers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseIssuers(t, tc.list...)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), "config: ") {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestWithIssuers(t *testing.T) {
	c, err := parseIssuers(t, goodIssuer())
	if err != nil {
		t.Fatal(err)
	}
	if same, err := c.WithIssuers(nil); err != nil || same != c {
		t.Fatalf("no more issuers: %v %v", same, err)
	}
	more := IssuerConfig{Issuer: "https://other.example.com", Audience: "a", JWKSURI: "https://other.example.com/jwks"}
	all, err := c.WithIssuers([]IssuerConfig{more})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Issuers) != 2 || all.Issuers[1].Issuer != more.Issuer || len(c.Issuers) != 1 {
		t.Fatalf("combined %v, original %v", all.Issuers, c.Issuers)
	}
	// Appending to the result never writes into the original's array.
	again, err := c.WithIssuers([]IssuerConfig{{Issuer: "https://third.example.com", Audience: "a", JWKSURI: "https://t/k"}})
	if err != nil || all.Issuers[1].Issuer != more.Issuer || again.Issuers[1].Issuer != "https://third.example.com" {
		t.Fatalf("shared backing array: %v %v", all.Issuers, again.Issuers)
	}
	dup := c.Issuers[0]
	dup.Audience = "elsewhere"
	if _, err := c.WithIssuers([]IssuerConfig{dup}); err == nil || !strings.Contains(err.Error(), "issuers[1]: issuer \"https://idp.example.com\" is configured twice") {
		t.Fatalf("duplicate across lists: %v", err)
	}
}

// signer signs ES256 tokens for an issuer.
type signer struct {
	*jose.Signer
}

func newSigner(t testing.TB) signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jose.NewSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return signer{s}
}

func (s signer) token(t testing.TB, claims map[string]any) string {
	t.Helper()
	tok, err := s.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (s signer) jwk() string {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	pt, err := s.Public().Bytes() // 0x04 || x || y
	if err != nil {
		panic(err)
	}
	x, y := pt[1:33], pt[33:]
	return fmt.Sprintf(`{"kty":"EC","crv":"P-256","kid":%q,"use":"sig","x":%q,"y":%q}`, s.KeyID(), b64(x), b64(y))
}

func (s signer) keySet(t testing.TB) *identity.KeySet {
	t.Helper()
	ks, err := identity.NewKeySet(jose.Key{ID: s.KeyID(), Public: s.Public()})
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestNewIssuerAuthenticator(t *testing.T) {
	c, err := parseIssuers(t, goodIssuer(), map[string]any{"issuer": "https://other.example.com", "audience": "https://mcp.example.com",
		"jwks_uri": "https://other.example.com/jwks"})
	if err != nil {
		t.Fatal(err)
	}
	idp, other := newSigner(t), newSigner(t)
	var asked []string
	auth, err := c.NewIssuerAuthenticator(nil, func(ic IssuerConfig) (identity.KeySource, error) {
		asked = append(asked, ic.Issuer)
		if ic.Issuer == "https://idp.example.com" {
			return idp.keySet(t), nil
		}
		return other.keySet(t), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(asked, " ") != "https://idp.example.com https://other.example.com" {
		t.Fatalf("keys asked for %v", asked)
	}
	now := time.Now().Unix()
	claims := map[string]any{"iss": "https://idp.example.com", "aud": []string{"https://mcp.example.com"},
		"azp": "ci-bot", "scp": []string{"files:read"}, "iat": now, "exp": now + 600}
	id, err := auth.Authenticate(idp.token(t, claims))
	if err != nil {
		t.Fatal(err)
	}
	if id.AgentID != "ci-bot" || strings.Join(id.Scopes, " ") != "files:read" || id.Issuer != "https://idp.example.com" ||
		id.Method != "signed" || id.KeyID != idp.KeyID() {
		t.Fatalf("identity %+v", id)
	}
	// The mapping, audience, lifetime and keys are the issuer's own.
	for name, tok := range map[string]string{
		"other issuer's key":   other.token(t, claims),
		"wrong audience":       idp.token(t, with(claims, "aud", "https://elsewhere.example.com")),
		"lifetime over 900s":   idp.token(t, with(claims, "exp", now+901)),
		"sub instead of azp":   idp.token(t, with(with(claims, "azp", nil), "sub", "ci-bot")),
		"unconfigured issuer":  idp.token(t, with(claims, "iss", "https://third.example.com")),
		"other's default subs": other.token(t, with(with(claims, "iss", "https://other.example.com"), "azp", nil)),
	} {
		if _, err := auth.Authenticate(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The other issuer takes sub and the scope string.
	oc := with(with(with(claims, "iss", "https://other.example.com"), "azp", nil), "sub", "ops-bot")
	if id, err := auth.Authenticate(other.token(t, with(oc, "scope", "files:read files:write"))); err != nil ||
		id.AgentID != "ops-bot" || len(id.Scopes) != 2 {
		t.Fatalf("other issuer: %+v %v", id, err)
	}

	boom := errors.New("boom")
	if _, err := c.NewIssuerAuthenticator(nil, func(IssuerConfig) (identity.KeySource, error) { return nil, boom }); !errors.Is(err, boom) ||
		!strings.Contains(err.Error(), `config: issuers[0] ("https://idp.example.com")`) {
		t.Fatalf("key source error: %v", err)
	}
}

func with(c map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for kk, vv := range c {
		out[kk] = vv
	}
	if v == nil {
		delete(out, k)
	} else {
		out[k] = v
	}
	return out
}

// jwksServer is an issuer's key set endpoint on 127.0.0.1 over TLS.
type jwksServer struct {
	*httptest.Server
	doc     atomic.Value // string
	fetches atomic.Int64
	caFile  string
}

func newJWKSServer(t *testing.T, doc string) *jwksServer {
	t.Helper()
	s := &jwksServer{}
	s.doc.Store(doc)
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, s.doc.Load().(string))
	}))
	t.Cleanup(s.Close)
	s.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(s.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIssuerJWKS(t *testing.T) {
	idp := newSigner(t)
	srv := newJWKSServer(t, `{"keys":[`+idp.jwk()+`]}`)
	ic := IssuerConfig{Issuer: "https://idp.example.com", Audience: "https://mcp.example.com",
		JWKSURI: srv.URL + "/jwks", CAFile: srv.caFile, PrivateNetworks: []string{"127.0.0.1"}}
	if err := ic.Check(); err != nil {
		t.Fatal(err)
	}
	ks, err := LazyIssuerKeys(ic)
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := ks.Lookup(idp.KeyID(), "ES256"); !ok || k.ID != idp.KeyID() {
		t.Fatalf("lookup %v %v", k, ok)
	}
	if srv.fetches.Load() != 1 {
		t.Fatalf("%d fetches", srv.fetches.Load())
	}

	// The loopback address is refused unless private_networks names it.
	noNet := ic
	noNet.PrivateNetworks = nil
	ca, _, err := noNet.ReadCA()
	if err != nil {
		t.Fatal(err)
	}
	j, err := noNet.NewJWKS(ca, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Refresh(context.Background()); !errors.Is(err, egress.ErrBlocked) {
		t.Fatalf("loopback without private_networks: %v", err)
	}
	// Without the CA file the server's certificate is not trusted.
	noCA := ic
	noCA.CAFile = ""
	if j, err = noCA.NewJWKS(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := j.Refresh(context.Background()); err == nil || errors.Is(err, egress.ErrBlocked) {
		t.Fatalf("untrusted certificate: %v", err)
	}
}

func TestIssuerReadCA(t *testing.T) {
	if pool, b, err := (IssuerConfig{}).ReadCA(); pool != nil || b != nil || err != nil {
		t.Fatal("no ca_file")
	}
	dir := t.TempDir()
	srv := newJWKSServer(t, `{"keys":[]}`)
	big := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(big, make([]byte, MaxCAFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		filepath.Join(dir, "missing.pem"): "no such file",
		big:                               "larger than 1048576 bytes",
		notPEM:                            "holds no PEM certificate",
	} {
		if _, _, err := (IssuerConfig{CAFile: path}).ReadCA(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", path, err, want)
		}
		if _, err := LazyIssuerKeys(IssuerConfig{JWKSURI: "https://x/k", CAFile: path}); err == nil {
			t.Errorf("%s: LazyIssuerKeys accepted it", path)
		}
	}
	pool, b, err := (IssuerConfig{CAFile: srv.caFile}).ReadCA()
	if err != nil || pool == nil || len(b) == 0 {
		t.Fatalf("good CA: %v", err)
	}
	// A bad CA file stops the authenticator, as it stops the server.
	c, err := parseIssuers(t, map[string]any{"issuer": "i", "audience": "a", "jwks_uri": "https://i/k", "ca_file": notPEM})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.NewRingAuthenticator(nil); err == nil || !strings.Contains(err.Error(), "holds no PEM certificate") {
		t.Fatalf("ring authenticator: %v", err)
	}
	if _, err := c.NewAuthenticator(nil, ""); err == nil || !strings.Contains(err.Error(), "holds no PEM certificate") {
		t.Fatalf("authenticator: %v", err)
	}
}

func TestIssuerJWKSKey(t *testing.T) {
	a := IssuerConfig{JWKSURI: "https://idp/k", PrivateNetworks: []string{"10.0.0.0/8", "192.168.0.1"}}
	b := a
	b.PrivateNetworks = []string{"192.168.0.1", "10.0.0.0/8"}
	b.Issuer, b.Audience, b.Algorithms = "other", "other", []string{"RS256"}
	if a.JWKSKey(nil) != b.JWKSKey(nil) {
		t.Fatal("the order of networks or the token settings changed the key")
	}
	c := a
	c.JWKSURI = "https://idp/k2"
	d := a
	d.PrivateNetworks = d.PrivateNetworks[:1]
	for name, k := range map[string]string{"url": c.JWKSKey(nil), "networks": d.JWKSKey(nil), "ca": a.JWKSKey([]byte("ca"))} {
		if k == a.JWKSKey(nil) {
			t.Errorf("a different %s kept the key", name)
		}
	}
	if k1, k2 := a.JWKSKey([]byte("ca")), a.JWKSKey([]byte("ca")); k1 != k2 {
		t.Fatal("key not stable")
	}
}
