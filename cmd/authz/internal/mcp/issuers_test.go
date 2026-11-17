package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/gateway"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/jose"
)

// testIssuer is an identity provider on 127.0.0.1: an ES256 key whose
// set it serves over TLS at /jwks and /jwks2, counting fetches by path.
type testIssuer struct {
	*httptest.Server
	signer *jose.Signer
	caFile string

	mu      sync.Mutex
	fetches map[string]int
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jose.NewSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	is := &testIssuer{signer: s, fetches: map[string]int{}}
	pt, err := k.PublicKey.Bytes() // 0x04 || x || y
	if err != nil {
		t.Fatal(err)
	}
	x, y := pt[1:33], pt[33:]
	b64 := base64.RawURLEncoding.EncodeToString
	doc := fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","kid":%q,"x":%q,"y":%q}]}`, s.KeyID(), b64(x), b64(y))
	is.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.mu.Lock()
		is.fetches[r.URL.Path]++
		is.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, doc)
	}))
	t.Cleanup(is.Close)
	is.caFile = filepath.Join(t.TempDir(), "idp-ca.pem")
	if err := os.WriteFile(is.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: is.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return is
}

func (is *testIssuer) count(path string) int {
	is.mu.Lock()
	defer is.mu.Unlock()
	return is.fetches[path]
}

// config is the issuer's entry for an issuers section, with its keys at
// path.
func (is *testIssuer) config(path string) gateway.IssuerConfig {
	return gateway.IssuerConfig{Issuer: "https://idp.test", Audience: "https://mcp.test", JWKSURI: is.URL + path,
		Algorithms: []string{"ES256"}, Claims: gateway.ClaimsConfig{Subject: "azp", Scopes: "scp"},
		MaxTTLSeconds: 600, PrivateNetworks: []string{"127.0.0.1/32"}, CAFile: is.caFile}
}

func (is *testIssuer) token(t *testing.T, sub string) string {
	t.Helper()
	now := time.Now().Unix()
	tok, err := is.signer.Sign(map[string]any{"iss": "https://idp.test", "aud": "https://mcp.test", "azp": sub,
		"scp": "files:read", "iat": now, "exp": now + 300})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func toMap(t testing.TB, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestJWKSPool(t *testing.T) {
	is := newTestIssuer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := newJWKSPool(ctx, slog.New(slog.DiscardHandler))
	base := &gateway.Config{Issuers: []gateway.IssuerConfig{is.config("/jwks")}}
	// A second issuer on the same key set shares its client.
	second := is.config("/jwks")
	second.Issuer = "https://idp2.test"
	base.Issuers = append(base.Issuers, second)

	pd, err := p.authenticator(base, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pd.next) != 1 || len(p.clients) != 0 {
		t.Fatalf("pending %d clients, pool %d before commit", len(pd.next), len(p.clients))
	}
	if p.same(base, nil) {
		t.Fatal("same before commit")
	}
	p.commit(pd)
	within(t, "first fetch", func() bool { return is.count("/jwks") == 1 })
	if _, err := pd.auth.Authenticate(is.token(t, "ci-bot")); err != nil {
		t.Fatal(err)
	}
	if !p.same(base, nil) || strings.Join(p.urls(), " ") != is.URL+"/jwks" {
		t.Fatalf("same %v, urls %v", p.same(base, nil), p.urls())
	}

	// A rebuild with the same jwks_uri keeps the running client and its
	// keys: no fetch.
	changed := *base
	changed.Issuers = append([]gateway.IssuerConfig(nil), base.Issuers...)
	changed.Issuers[0].MaxTTLSeconds = 900
	pd2, err := p.authenticator(&changed, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var kept *pooledJWKS
	for _, e := range pd2.next {
		kept = e
	}
	for _, e := range p.clients {
		if e != kept {
			t.Fatal("rebuild made a new client for an unchanged jwks_uri")
		}
	}
	p.commit(pd2)
	if _, err := pd2.auth.Authenticate(is.token(t, "ci-bot")); err != nil {
		t.Fatal(err)
	}
	if n := is.count("/jwks"); n != 1 {
		t.Fatalf("%d fetches after a rebuild", n)
	}

	// A new jwks_uri gets a new client, and the old one stops. A build
	// that fails leaves the pool as it was.
	moved := is.config("/jwks2")
	bad := moved
	bad.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := p.authenticator(&gateway.Config{Issuers: []gateway.IssuerConfig{bad}}, nil, nil); err == nil {
		t.Fatal("missing CA file accepted")
	}
	if len(p.clients) != 1 {
		t.Fatal("a failed build changed the pool")
	}
	pd3, err := p.authenticator(&gateway.Config{Issuers: []gateway.IssuerConfig{moved}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.commit(pd3)
	within(t, "fetch from the new jwks_uri", func() bool { return is.count("/jwks2") == 1 })
	if kept.stop == nil {
		t.Fatal("old client never started")
	}
	if strings.Join(p.urls(), " ") != is.URL+"/jwks2" {
		t.Fatalf("urls %v", p.urls())
	}
	// The CA certificates the check read are used in place of the file.
	if p.same(&gateway.Config{Issuers: []gateway.IssuerConfig{moved}}, map[string][]byte{is.caFile: []byte("other")}) {
		t.Fatal("different CA certificates count as the same client")
	}
	if _, err := p.authenticator(&gateway.Config{Issuers: []gateway.IssuerConfig{moved}}, nil, map[string][]byte{is.caFile: []byte("x")}); err == nil {
		t.Fatal("bad CA bytes from the check accepted")
	}

	// No issuers: every client stops; close waits for the loops.
	pd4, err := p.authenticator(&gateway.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.commit(pd4)
	if len(p.urls()) != 0 || !p.same(&gateway.Config{}, nil) {
		t.Fatal("clients left")
	}
	done := make(chan struct{})
	go func() { p.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not return")
	}
}

// The close of a pool whose clients still run stops them all.
func TestJWKSPoolClose(t *testing.T) {
	is := newTestIssuer(t)
	p := newJWKSPool(context.Background(), slog.New(slog.DiscardHandler))
	pd, err := p.authenticator(&gateway.Config{Issuers: []gateway.IssuerConfig{is.config("/jwks"), func() gateway.IssuerConfig {
		c := is.config("/jwks2")
		c.Issuer = "https://other.test"
		return c
	}()}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.commit(pd)
	within(t, "both fetched", func() bool { return is.count("/jwks") == 1 && is.count("/jwks2") == 1 })
	done := make(chan struct{})
	go func() { p.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not stop the refresh loops")
	}
}

func TestSectionIssuers(t *testing.T) {
	is := newTestIssuer(t)
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not.pem")
	os.WriteFile(notPEM, []byte("hello"), 0o600)
	good := is.config("/jwks")

	r := mcpSchema(t, upstreamEnv).Check(goodSection(t, map[string]any{"issuers": toMap(t, []gateway.IssuerConfig{good})}), goodEnviron)
	if len(r.Problems) != 0 {
		t.Fatal(r.Problems)
	}
	s := pcfg.Get[Settings](r.Config, SectionName)
	if len(s.Issuers) != 1 || len(s.agents.Issuers) != 1 || s.agents.Issuers[0].JWKSURI != good.JWKSURI ||
		len(s.cas[is.caFile]) == 0 || s.auth == nil {
		t.Fatalf("settings %+v", s)
	}
	// The CA file is one of the sources the watcher follows.
	found := false
	for _, src := range r.Config.Sources() {
		found = found || src.Path == is.caFile
	}
	if !found {
		t.Fatal("ca_file is not a watched source")
	}

	// Issuers in the agents config, with the section's after them.
	src, _ := os.ReadFile(exampleConfig)
	var cfg map[string]any
	json.Unmarshal(src, &cfg)
	inConfig := good
	inConfig.Issuer = "https://config.test"
	cfg["issuers"] = toMap(t, []gateway.IssuerConfig{inConfig})
	b, _ := json.Marshal(cfg)
	withIssuers := filepath.Join(dir, "with-issuers.json")
	os.WriteFile(withIssuers, b, 0o600)
	r = mcpSchema(t, upstreamEnv).Check(goodSection(t, map[string]any{"config": withIssuers,
		"issuers": toMap(t, []gateway.IssuerConfig{good})}), goodEnviron)
	if len(r.Problems) != 0 {
		t.Fatal(r.Problems)
	}
	s = pcfg.Get[Settings](r.Config, SectionName)
	if len(s.agents.Issuers) != 2 || s.agents.Issuers[0].Issuer != "https://config.test" || s.agents.Issuers[1].Issuer != "https://idp.test" {
		t.Fatalf("combined issuers %+v", s.agents.Issuers)
	}

	badCA := inConfig
	badCA.CAFile = notPEM
	cfg["issuers"] = toMap(t, []gateway.IssuerConfig{badCA})
	b, _ = json.Marshal(cfg)
	badCAConfig := filepath.Join(dir, "bad-ca.json")
	os.WriteFile(badCAConfig, b, 0o600)

	dup := good
	dup.Issuer = "https://config.test"
	noURI := good
	noURI.JWKSURI = ""
	sectionCA := good
	sectionCA.CAFile = filepath.Join(dir, "missing.pem")
	for name, c := range map[string]struct {
		extra map[string]any
		path  string
		msg   string
	}{
		"bad issuer": {map[string]any{"issuers": toMap(t, []gateway.IssuerConfig{good, noURI})}, "$.mcp.issuers[1]", "jwks_uri is required"},
		"twice":      {map[string]any{"issuers": toMap(t, []gateway.IssuerConfig{good, good})}, "$.mcp.issuers", `issuers[1]: issuer "https://idp.test" is configured twice`},
		"in both": {map[string]any{"config": withIssuers, "issuers": toMap(t, []gateway.IssuerConfig{good, dup})}, "$.mcp.issuers",
			`with those of ` + withIssuers + `: issuers[2]: issuer "https://config.test" is configured twice`},
		"section CA":       {map[string]any{"issuers": toMap(t, []gateway.IssuerConfig{sectionCA})}, "$.mcp.issuers[0]", "ca_file " + sectionCA.CAFile + ": "},
		"agents config CA": {map[string]any{"config": badCAConfig}, "$.mcp.config", "ca_file " + notPEM + ": holds no PEM certificate"},
		"unknown member":   {map[string]any{"issuers": []any{map[string]any{"issuer": "x", "audience": "y", "jwks_uri": "https://x/k", "jwks": "y"}}}, "$.mcp.issuers[0].jwks", ""},
	} {
		r := mcpSchema(t, upstreamEnv).Check(goodSection(t, c.extra), goodEnviron)
		if r.Problems.Count(pcfg.SeverityError) != 1 || r.Problems[0].Path != c.path || !strings.Contains(r.Problems[0].Message, c.msg) {
			t.Errorf("%s: %v, want %s: %s", name, r.Problems, c.path, c.msg)
		}
	}
}

// An agent presents a token from an issuer in the mcp section; the
// server's JWKS client fetched the issuer's keys at start, keeps them
// across reloads that leave the jwks_uri alone, moves to a new jwks_uri
// when it changes, and stops with the server.
func TestServeFileIssuers(t *testing.T) {
	is := newTestIssuer(t)
	f := newFileSetup(t)
	f.section["issuers"] = toMap(t, []gateway.IssuerConfig{is.config("/jwks")})
	f.writeDoc(t, nil)
	r := f.start(t)
	within(t, "keys fetched at start", func() bool { return is.count("/jwks") == 1 })
	logs := r.logs.String()
	if !strings.Contains(logs, `"msg":"jwks client started","jwks_uri":"`+is.URL+`/jwks","issuers":["https://idp.test"]`) ||
		!strings.Contains(logs, `"issuers":1}`) || !strings.Contains(logs, `"sources":7`) {
		t.Fatalf("start-up log: %s", logs)
	}
	tok := is.token(t, "ci-bot")
	if res := readFile(t, r, tok); !ok(res) {
		t.Fatalf("issuer token: %v", res)
	}
	if res := readFile(t, r, agentKey); !ok(res) {
		t.Fatalf("static key: %v", res)
	}

	// The agents config changes: the client and its keys stay.
	f.write(t, f.agents, f.agentsDoc(t, true, 0))
	within(t, "agents reloaded", func() bool { return ok(readFile(t, r, carolKey)) })
	within(t, "reload logged", func() bool {
		return strings.Contains(r.logs.String(), `"msg":"configuration reloaded","applied":["config"]`)
	})
	if !ok(readFile(t, r, tok)) || is.count("/jwks") != 1 {
		t.Fatalf("after an agents change: %d fetches", is.count("/jwks"))
	}

	// The issuer's lifetime changes: a new authenticator on the same client.
	c := is.config("/jwks")
	c.MaxTTLSeconds = 60
	f.writeDoc(t, map[string]any{"issuers": toMap(t, []gateway.IssuerConfig{c})})
	within(t, "lifetime applied", func() bool { return readFile(t, r, tok)["error"] != nil })
	if strings.Count(r.logs.String(), `"msg":"jwks client started"`) != 1 || is.count("/jwks") != 1 {
		t.Fatalf("a lifetime change restarted the client: %d fetches", is.count("/jwks"))
	}
	if !strings.Contains(r.logs.String(), `"applied":["issuers"]`) {
		t.Fatalf("reload log: %s", r.logs.String())
	}

	// A broken issuer is refused and the running one kept.
	broken := is.config("/jwks")
	broken.JWKSURI = "http://" + strings.TrimPrefix(is.URL, "https://") + "/jwks"
	f.writeDoc(t, map[string]any{"issuers": toMap(t, []gateway.IssuerConfig{broken})})
	within(t, "broken issuer refused", func() bool {
		return strings.Contains(r.logs.String(), `"error":"$.mcp.issuers[0]: jwks_uri `)
	})

	// A new jwks_uri: a new client fetches, the old one stops.
	f.writeDoc(t, map[string]any{"issuers": toMap(t, []gateway.IssuerConfig{is.config("/jwks2")})})
	within(t, "new jwks_uri fetched", func() bool { return is.count("/jwks2") == 1 })
	within(t, "old client stopped", func() bool {
		return strings.Contains(r.logs.String(), `"msg":"jwks client stopped","jwks_uri":"`+is.URL+`/jwks"`)
	})
	if res := readFile(t, r, is.token(t, "ci-bot")); !ok(res) {
		t.Fatalf("token after the move: %v", res)
	}

	// Without the issuer its tokens stop; the static key still works.
	f.writeDoc(t, map[string]any{"issuers": nil})
	within(t, "issuer removed", func() bool { return readFile(t, r, tok)["error"] != nil })
	if !ok(readFile(t, r, agentKey)) {
		t.Fatal("static key after the issuer went")
	}
	r.stop(t)
}

// Issuers in the agents config under the TOOLGATE_ variables: the server
// runs their clients as it does from a file.
func TestRunIssuers(t *testing.T) {
	is := newTestIssuer(t)
	s := newSetup(t)
	var cfg map[string]any
	src, err := os.ReadFile(s.env["TOOLGATE_CONFIG"])
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(src, &cfg)
	cfg["issuers"] = toMap(t, []gateway.IssuerConfig{is.config("/jwks")})
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(s.env["TOOLGATE_CONFIG"], b, 0o600); err != nil {
		t.Fatal(err)
	}
	r := s.start(t)
	within(t, "keys fetched at start", func() bool { return is.count("/jwks") == 1 })
	if res := readFile(t, r, is.token(t, "ci-bot")); !ok(res) {
		t.Fatalf("issuer token: %v", res)
	}
	r.stop(t)

	// A CA file that does not parse stops the server before it listens.
	ic := is.config("/jwks")
	ic.CAFile = s.env["TOOLGATE_CONFIG"]
	cfg["issuers"] = toMap(t, []gateway.IssuerConfig{ic})
	b, _ = json.Marshal(cfg)
	os.WriteFile(s.env["TOOLGATE_CONFIG"], b, 0o600)
	var out syncBuffer
	if code := cli(context.Background(), nil, s.getenv, nil, &out, &out, nil); code == 0 ||
		!strings.Contains(out.String(), "holds no PEM certificate") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}
