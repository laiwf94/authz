package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/config"
	"github.com/laiwf94/authz/internal/authn/policy"
	"github.com/laiwf94/authz/internal/authn/session"
	"github.com/laiwf94/authz/internal/platform/jose"
	"github.com/laiwf94/authz/internal/platform/keys"
	"github.com/laiwf94/authz/internal/platform/seal"
)

const ringConfig = `{"public_url": "https://auth.example.com",
  "providers": [{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "S"}],
  "apps": [{"id": "app", "hosts": ["app.example.com"], "providers": ["corp"], "allow": {"any_user": true}}]}`

func ringServer(t *testing.T, opts Options) (*Server, *clock) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)}
	cfg, err := config.Parse([]byte(ringConfig), func(string) string { return "secret" })
	if err != nil {
		t.Fatal(err)
	}
	st, err := session.Open(session.Options{Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	kr, _ := seal.New([][]byte{seal.RandomKey()})
	opts.Load = func() (*config.Config, error) { return cfg, nil }
	opts.Sessions, opts.Keys, opts.Now = st, kr, clk.Now
	opts.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s, clk
}

func jwksKids(t *testing.T, s *Server) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	ks, err := jose.ParseKeySet(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("%v: %s", err, rec.Body)
	}
	var out []string
	for _, k := range ks.Keys {
		out = append(out, k.ID)
	}
	return out
}

// Upstream tokens signed from an ES256 ring: the JWKS publishes current,
// next and retired keys, follows rotations and prunes, and a cached token
// from a key that no longer signs is not handed out again.
func TestUpstreamRing(t *testing.T) {
	p := keys.Policy{RotateEvery: time.Hour, Overlap: 2 * time.Hour}
	ring, err := keys.NewRing(keys.ES256, p, time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s, clk := ringServer(t, Options{Upstream: ring})
	first, next := ring.Current().ID(), ring.Next().ID()
	if got := jwksKids(t, s); len(got) != 2 || got[0] != first || got[1] != next {
		t.Fatalf("JWKS %v, want current %s then next %s", got, first, next)
	}
	secret, sess, err := s.sessions.Create(policy.Identity{Provider: "corp", Subject: "alice"}, time.Time{})
	if err != nil || secret == "" {
		t.Fatal(err)
	}
	rt := s.rt.Load()
	tok, err := s.upstreamToken(rt, sess, "app")
	if err != nil {
		t.Fatal(err)
	}
	pt, _ := jose.Parse(tok)
	if pt.Header.Kid != first {
		t.Fatalf("signed by %s, want %s", pt.Header.Kid, first)
	}
	if again, _ := s.upstreamToken(rt, sess, "app"); again != tok {
		t.Fatal("the token was not reused before a rotation")
	}

	// A rotation the server has not been told about yet: the next token is
	// signed by the new key, and the JWKS published with it holds that key.
	clk.Advance(time.Hour)
	if err := ring.Rotate(clk.Now()); err != nil {
		t.Fatal(err)
	}
	tok2, err := s.upstreamToken(rt, sess, "app")
	if err != nil {
		t.Fatal(err)
	}
	if tok2 == tok {
		t.Fatal("a token from the retired key was reused after a rotation")
	}
	if pt, _ := jose.Parse(tok2); pt.Header.Kid != next {
		t.Fatalf("signed by %s after the rotation, want the published next key %s", pt.Header.Kid, next)
	}
	got := jwksKids(t, s)
	if len(got) != 3 || got[0] != next || got[1] != ring.Next().ID() || got[2] != first {
		t.Fatalf("JWKS after rotation %v", got)
	}
	// Once the overlap ends and the ring is pruned, RefreshKeys drops the
	// retired key from the published set.
	clk.Advance(2 * time.Hour)
	ring.Prune(clk.Now())
	if err := s.RefreshKeys(); err != nil {
		t.Fatal(err)
	}
	if got := jwksKids(t, s); len(got) != 2 || strings.Contains(strings.Join(got, ","), first) {
		t.Fatalf("JWKS after the overlap %v still has %s", got, first)
	}
}

func TestUpstreamOptions(t *testing.T) {
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sg, _ := jose.NewSigner(ek)
	es, _ := keys.NewRing(keys.ES256, keys.Policy{}, time.Now())
	hs, _ := keys.NewRing(keys.HS256, keys.Policy{}, time.Now())
	st, _ := session.Open(session.Options{})
	defer st.Close()
	kr, _ := seal.New([][]byte{seal.RandomKey()})
	load := func() (*config.Config, error) {
		return config.Parse([]byte(ringConfig), func(string) string { return "s" })
	}
	for name, o := range map[string]Options{
		"both":    {Signers: []*jose.Signer{sg}, Upstream: es},
		"hs256":   {Upstream: hs},
		"neither": {},
	} {
		o.Load, o.Sessions, o.Keys = load, st, kr
		if _, err := New(o); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Without a ring, RefreshKeys has nothing to do and the signers stay.
	s, _ := ringServer(t, Options{Signers: []*jose.Signer{sg}})
	if err := s.RefreshKeys(); err != nil || s.upstreamKeys().signer != sg {
		t.Fatalf("RefreshKeys with signers: %v", err)
	}
	if got := jwksKids(t, s); len(got) != 1 || got[0] != sg.KeyID() {
		t.Fatalf("JWKS %v", got)
	}
}
