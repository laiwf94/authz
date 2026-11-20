package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/clock"
)

// The benchmarks below are the figures in toolgate/README.md: each
// verification algorithm through Authenticate, the JWKS client's lookups,
// and its refresh path from the network through parsing.
//
//	go test -run='^$' -bench='Verify|JWKS' -benchmem ./internal/agents/identity/

var (
	rsaBySizeMu sync.Mutex
	rsaBySize   = map[int]*rsa.PrivateKey{}
)

// rsaKey returns an RSA key of the given size, generated once.
func rsaKey(b *testing.B, bits int) *rsa.PrivateKey {
	b.Helper()
	if bits == 2048 {
		return testKeys(b).rsa
	}
	rsaBySizeMu.Lock()
	defer rsaBySizeMu.Unlock()
	if k, ok := rsaBySize[bits]; ok {
		return k
	}
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		b.Fatal(err)
	}
	rsaBySize[bits] = k
	return k
}

type benchAlg struct {
	name, alg string
	priv      crypto.Signer // nil for HS256
}

func benchAlgs(b *testing.B) []benchAlg {
	k := testKeys(b)
	return []benchAlg{
		{"HS256", "HS256", nil},
		{"EdDSA", EdDSA, k.ed},
		{"ES256", ES256, k.ec},
		{"RS256-2048", RS256, k.rsa},
		{"RS256-3072", RS256, rsaKey(b, 3072)},
		{"RS256-4096", RS256, rsaKey(b, 4096)},
	}
}

// benchToken returns an authenticator holding the one key ba names and a
// token it accepts, so every case does the same claim checks.
func benchToken(b *testing.B, ba benchAlg) (*Authenticator, string) {
	b.Helper()
	cfg := Config{
		Keys:      map[string][]byte{"k1": keyA},
		ActiveKey: "k1",
		Issuer:    "toolgate",
		Audience:  "toolgate-gw",
		MaxTTL:    time.Hour,
		Now:       func() time.Time { return t0 },
	}
	c := claims(t0, 600)
	tok := sign(b, keyA, `{"alg":"HS256","typ":"JWT","kid":"k1"}`, c)
	if ba.priv != nil {
		ks, err := NewKeySet(pub("k", ba.priv))
		if err != nil {
			b.Fatal(err)
		}
		cfg.PublicKeys = ks
		tok = signAsym(b, ba.priv, ba.alg, hdr(ba.alg, "k"), c)
	}
	a, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := a.Authenticate(tok); err != nil {
		b.Fatalf("%s: %v", ba.name, err)
	}
	return a, tok
}

// BenchmarkVerify authenticates one token per algorithm on one goroutine.
func BenchmarkVerify(b *testing.B) {
	for _, ba := range benchAlgs(b) {
		b.Run(ba.name, func(b *testing.B) {
			a, tok := benchToken(b, ba)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := a.Authenticate(tok); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkVerifyParallel is BenchmarkVerify on every CPU: the
// authenticator holds no lock on the verification path.
func BenchmarkVerifyParallel(b *testing.B) {
	for _, ba := range benchAlgs(b) {
		b.Run(ba.name, func(b *testing.B) {
			a, tok := benchToken(b, ba)
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := a.Authenticate(tok); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}

// jwksBenchDoc is a key set of n keys: Ed25519, P-256 and RSA 2048 in
// turn, under kids k0, k1, ...
func jwksBenchDoc(b *testing.B, n int) string {
	k := testKeys(b)
	keys := make([]string, n)
	for i := range keys {
		var pk crypto.PublicKey
		switch i % 3 {
		case 0:
			pk = k.ed.Public()
		case 1:
			pk = k.ec.Public()
		default:
			pk = k.rsa.Public()
		}
		keys[i] = jwkOf(b, "k"+strconv.Itoa(i), pk, `"use":"sig"`)
	}
	return jwksDoc(keys...)
}

// BenchmarkVerifyJWKS authenticates through a JWKS client that holds the
// key: a known kid is read from the current set and never waits.
func BenchmarkVerifyJWKS(b *testing.B) {
	k := testKeys(b)
	is := newIssuer(b, jwksBenchDoc(b, 3))
	clk := clock.NewFake(t0)
	j := newJWKS(b, is, clk, nil)
	if err := j.Refresh(context.Background()); err != nil {
		b.Fatal(err)
	}
	a := jwksAuth(b, j, clk)
	c := claims(t0, 600)
	for _, tc := range []struct {
		alg, kid string
		priv     crypto.Signer
	}{{EdDSA, "k0", k.ed}, {ES256, "k1", k.ec}, {RS256, "k2", k.rsa}} {
		b.Run(tc.alg, func(b *testing.B) {
			tok := signAsym(b, tc.priv, tc.alg, hdr(tc.alg, tc.kid), c)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := a.Authenticate(tok); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
	if s := j.Stats(); s.Fetches != 1 {
		b.Fatalf("verification fetched: %+v", s)
	}
}

// BenchmarkJWKSUnknownKid is a token naming a kid the issuer doesn't
// publish, after the minute's one unknown-kid fetch has been spent: it is
// refused without a request.
func BenchmarkJWKSUnknownKid(b *testing.B) {
	k := testKeys(b)
	is := newIssuer(b, jwksBenchDoc(b, 3))
	clk := clock.NewFake(t0)
	j := newJWKS(b, is, clk, nil)
	a := jwksAuth(b, j, clk)
	tok := signAsym(b, k.ed2, EdDSA, hdr(EdDSA, "made-up"), claims(t0, 600))
	if _, err := a.Authenticate(tok); err == nil {
		b.Fatal("unknown kid accepted")
	}
	before := is.hits.Load()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := a.Authenticate(tok); err == nil {
			b.Fatal("unknown kid accepted")
		}
	}
	if is.hits.Load() != before {
		b.Fatalf("%d requests inside the minute", is.hits.Load()-before)
	}
}

// BenchmarkJWKSRefresh is one scheduled refresh against an issuer on
// loopback TLS, over a kept-alive connection: a 304 for an unchanged set,
// and a 200 whose set is parsed and replaced, for 3 and for 100 keys (the
// most a set may hold).
func BenchmarkJWKSRefresh(b *testing.B) {
	ctx := context.Background()
	for _, n := range []int{3, 100} {
		doc := jwksBenchDoc(b, n)
		b.Run("200/keys="+strconv.Itoa(n), func(b *testing.B) {
			is := newIssuer(b, doc)
			j := newJWKS(b, is, clock.NewFake(t0), nil)
			b.SetBytes(int64(len(doc)))
			b.ReportAllocs()
			for b.Loop() {
				if err := j.Refresh(ctx); err != nil {
					b.Fatal(err)
				}
			}
			if s := j.Stats(); s.NotModified != 0 || s.Failures != 0 || len(s.Keys) != n {
				b.Fatalf("stats %+v", s)
			}
		})
	}
	b.Run("304", func(b *testing.B) {
		is := newIssuer(b, jwksBenchDoc(b, 100))
		is.set(func(is *issuer) { is.etag = `"v1"` })
		j := newJWKS(b, is, clock.NewFake(t0), nil)
		if err := j.Refresh(ctx); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			if err := j.Refresh(ctx); err != nil {
				b.Fatal(err)
			}
		}
		if s := j.Stats(); s.NotModified != s.Fetches-1 || s.Failures != 0 {
			b.Fatalf("stats %+v", s)
		}
	})
}

// BenchmarkParseJWKS is the parsing part of a 200 refresh.
func BenchmarkParseJWKS(b *testing.B) {
	for _, n := range []int{3, 100} {
		doc := []byte(jwksBenchDoc(b, n))
		b.Run("keys="+strconv.Itoa(n), func(b *testing.B) {
			b.SetBytes(int64(len(doc)))
			b.ReportAllocs()
			for b.Loop() {
				if _, kids, err := ParseJWKS(doc); err != nil || len(kids) != n {
					b.Fatal(len(kids), err)
				}
			}
		})
	}
}

// BenchmarkJWKSRotation is the first token under a key the client has not
// seen: the issuer has rotated, the token's unknown kid fetches the new
// set (one per UnknownKidInterval, so the client's clock moves on a
// minute each time), and the token verifies under it. The issuer swaps
// between two sets of three keys, each without the other's kids.
func BenchmarkJWKSRotation(b *testing.B) {
	k := testKeys(b)
	docs := [2]string{
		jwksDoc(jwkOf(b, "a-ed", k.ed.Public(), ""), jwkOf(b, "a-ec", k.ec.Public(), ""), jwkOf(b, "a-rsa", k.rsa.Public(), "")),
		jwksDoc(jwkOf(b, "b-ed", k.ed.Public(), ""), jwkOf(b, "b-ec", k.ec.Public(), ""), jwkOf(b, "b-rsa", k.rsa.Public(), "")),
	}
	c := claims(t0, 600)
	toks := [2]string{
		signAsym(b, k.ed, EdDSA, hdr(EdDSA, "a-ed"), c),
		signAsym(b, k.ed, EdDSA, hdr(EdDSA, "b-ed"), c),
	}
	is := newIssuer(b, docs[0])
	clk := clock.NewFake(t0)
	j := newJWKS(b, is, clk, nil)
	// The authenticator's clock stays at t0 so the token stays valid; the
	// client's moves on to allow the next unknown-kid fetch.
	a, err := New(Config{PublicKeys: j, Issuer: "toolgate", Audience: "toolgate-gw", Now: func() time.Time { return t0 }})
	if err != nil {
		b.Fatal(err)
	}
	if err := j.Refresh(context.Background()); err != nil {
		b.Fatal(err)
	}
	i := 0
	b.ReportAllocs()
	for b.Loop() {
		i ^= 1
		is.set(func(is *issuer) { is.doc = docs[i] })
		clk.Advance(UnknownKidInterval)
		if id, err := a.Authenticate(toks[i]); err != nil || id.KeyID != []string{"a-ed", "b-ed"}[i] {
			b.Fatal(id, err)
		}
	}
	if s := j.Stats(); s.UnknownKid != s.Fetches-1 || s.Failures != 0 {
		b.Fatalf("stats %+v", s)
	}
}
