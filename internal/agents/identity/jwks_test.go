package identity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/egress"
	"github.com/laiwf94/authz/internal/platform/clock"
)

// jwkOf renders a public key as a JWK object.
func jwkOf(t testing.TB, kid string, pk crypto.PublicKey, extra string) string {
	t.Helper()
	var body string
	switch k := pk.(type) {
	case ed25519.PublicKey:
		body = `"kty":"OKP","crv":"Ed25519","x":"` + b64.EncodeToString(k) + `"`
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		pt, err := k.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		x, y := pt[1:1+size], pt[1+size:]
		body = `"kty":"EC","crv":"` + k.Curve.Params().Name + `","x":"` + b64.EncodeToString(x) + `","y":"` + b64.EncodeToString(y) + `"`
	case *rsa.PublicKey:
		body = `"kty":"RSA","n":"` + b64.EncodeToString(k.N.Bytes()) + `","e":"AQAB"`
	default:
		t.Fatalf("jwkOf: %T", pk)
	}
	if kid != "" {
		body += `,"kid":"` + kid + `"`
	}
	if extra != "" {
		body += "," + extra
	}
	return "{" + body + "}"
}

func jwksDoc(keys ...string) string { return `{"keys":[` + strings.Join(keys, ",") + `]}` }

// issuer is a test JWKS endpoint on loopback TLS. Its document, ETag,
// Cache-Control and status can change between requests.
type issuer struct {
	srv *httptest.Server

	mu           sync.Mutex
	doc          string
	etag         string
	cacheControl string
	status       int
	hold         chan struct{} // when set, requests wait for it to close
	hits         atomic.Int64
	conditional  atomic.Int64 // requests carrying If-None-Match
}

func newIssuer(t testing.TB, doc string) *issuer {
	t.Helper()
	is := &issuer{doc: doc}
	is.srv = httptest.NewTLSServer(http.HandlerFunc(is.serve))
	t.Cleanup(is.srv.Close)
	return is
}

func (is *issuer) serve(w http.ResponseWriter, r *http.Request) {
	is.hits.Add(1)
	is.mu.Lock()
	doc, etag, cc, status, hold := is.doc, is.etag, is.cacheControl, is.status, is.hold
	is.mu.Unlock()
	if hold != nil {
		<-hold
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		is.conditional.Add(1)
		if inm == etag {
			w.Header().Set("ETag", etag)
			if cc != "" {
				w.Header().Set("Cache-Control", cc)
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	if cc != "" {
		w.Header().Set("Cache-Control", cc)
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	_, _ = w.Write([]byte(doc))
}

func (is *issuer) set(f func(is *issuer)) {
	is.mu.Lock()
	defer is.mu.Unlock()
	f(is)
}

func (is *issuer) roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(is.srv.Certificate())
	return p
}

var loopback = egress.New(netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"))

func newJWKS(t testing.TB, is *issuer, clk clock.Clock, mod func(*JWKSConfig)) *JWKS {
	t.Helper()
	cfg := JWKSConfig{URL: is.srv.URL + "/jwks", Guard: loopback, RootCAs: is.roots(), Clock: clk}
	if mod != nil {
		mod(&cfg)
	}
	j, err := NewJWKS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func jwksAuth(t testing.TB, j *JWKS, clk clock.Clock) *Authenticator {
	t.Helper()
	a, err := New(Config{PublicKeys: j, Issuer: "toolgate", Audience: "toolgate-gw", Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestJWKSVerifiesEachAlgorithm(t *testing.T) {
	k := testKeys(t)
	is := newIssuer(t, jwksDoc(
		jwkOf(t, "ed1", k.ed.Public(), `"use":"sig"`),
		jwkOf(t, "ec1", k.ec.Public(), `"alg":"ES256"`),
		jwkOf(t, "rsa1", k.rsa.Public(), `"alg":"RS256","key_ops":["verify"]`),
		// Skipped: an encryption key, a P-384 key, an RS384-only key, an
		// HMAC secret and a key of an unknown type.
		jwkOf(t, "enc", k.ec2.Public(), `"use":"enc"`),
		jwkOf(t, "p384", k.p384.Public(), ""),
		jwkOf(t, "rs384", k.rsa2.Public(), `"alg":"RS384"`),
		`{"kty":"oct","kid":"s","k":"`+b64.EncodeToString(keyA)+`"}`,
		`{"kty":"AKP","kid":"pq","alg":"ML-DSA-44","pub":"AAAA"}`,
	))
	clk := clock.NewFake(t0)
	j := newJWKS(t, is, clk, nil)
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := j.Stats().Keys; !slices.Equal(got, []string{"ed1", "ec1", "rsa1"}) {
		t.Fatalf("kept keys %v", got)
	}
	a := jwksAuth(t, j, clk)
	c := claims(t0, 600)
	for _, tc := range []struct {
		alg, kid string
		priv     crypto.Signer
	}{{EdDSA, "ed1", k.ed}, {ES256, "ec1", k.ec}, {RS256, "rsa1", k.rsa}} {
		id, err := a.Authenticate(signAsym(t, tc.priv, tc.alg, hdr(tc.alg, tc.kid), c))
		if err != nil || id.KeyID != tc.kid {
			t.Errorf("%s: %+v %v", tc.alg, id, err)
		}
	}
	for _, tc := range []struct {
		name, alg, kid string
		priv           crypto.Signer
	}{
		{"skipped encryption key", ES256, "enc", k.ec2},
		{"skipped P-384 key", ES256, "p384", k.p384},
		{"skipped RS384 key", RS256, "rs384", k.rsa2},
		{"key of another type", ES256, "ed1", k.ec},
		{"jku pointing elsewhere", ES256, "nope", k.ec2},
	} {
		h := hdr(tc.alg, tc.kid)
		if tc.name == "jku pointing elsewhere" {
			h = `{"alg":"ES256","kid":"nope","jku":"` + is.srv.URL + `/other"}`
		}
		if _, err := a.Authenticate(signAsym(t, tc.priv, tc.alg, h, c)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s accepted", tc.name)
		}
	}
	// Only the pinned URL was ever fetched: the initial fetch and one
	// unknown-kid fetch for the first refused kid, then the minute limit.
	if n := is.hits.Load(); n != 2 {
		t.Errorf("issuer hits %d, want 2", n)
	}
}

// TestJWKSRotation follows an issuer that rotates its key: a token signed
// with the new kid fetches the set at once, made-up kids fetch at most once
// a minute, and the old key stops verifying when the issuer drops it.
func TestJWKSRotation(t *testing.T) {
	k := testKeys(t)
	is := newIssuer(t, jwksDoc(jwkOf(t, "ec1", k.ec.Public(), "")))
	clk := clock.NewFake(t0)
	j := newJWKS(t, is, clk, nil)
	a := jwksAuth(t, j, clk)
	tok1 := signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), claims(t0, 3000))
	// The first lookup fetches lazily.
	if _, err := a.Authenticate(tok1); err != nil {
		t.Fatal(err)
	}
	if is.hits.Load() != 1 {
		t.Fatalf("hits %d", is.hits.Load())
	}
	// Known kids never fetch.
	for range 50 {
		if _, err := a.Authenticate(tok1); err != nil {
			t.Fatal(err)
		}
	}
	if is.hits.Load() != 1 {
		t.Fatalf("known kid fetched: hits %d", is.hits.Load())
	}
	clk.Advance(UnknownKidInterval)
	// The issuer publishes ec2 beside ec1 and starts signing with it.
	is.set(func(is *issuer) {
		is.doc = jwksDoc(jwkOf(t, "ec1", k.ec.Public(), ""), jwkOf(t, "ec2", k.ec2.Public(), ""))
	})
	tok2 := signAsym(t, k.ec2, ES256, hdr(ES256, "ec2"), claims(t0, 3000))
	if _, err := a.Authenticate(tok2); err != nil {
		t.Fatalf("new kid after rotation: %v", err)
	}
	// Made-up kids within the minute cost nothing.
	for i := range 100 {
		forged := signAsym(t, k.ec2, ES256, hdr(ES256, "x"+strconv.Itoa(i)), claims(t0, 3000))
		if _, err := a.Authenticate(forged); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("forged kid accepted")
		}
	}
	if n := is.hits.Load(); n != 2 {
		t.Fatalf("hits %d after made-up kids, want 2", n)
	}
	// The issuer drops ec1. The next fetch, here the next unknown kid
	// after the minute, removes it.
	is.set(func(is *issuer) { is.doc = jwksDoc(jwkOf(t, "ec2", k.ec2.Public(), "")) })
	clk.Advance(UnknownKidInterval)
	if _, err := a.Authenticate(signAsym(t, k.ec2, ES256, hdr(ES256, "x"), claims(t0, 3000))); err == nil {
		t.Fatal("made-up kid accepted")
	}
	if n := is.hits.Load(); n != 3 {
		t.Fatalf("hits %d, want 3", n)
	}
	if _, err := a.Authenticate(tok1); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("dropped key still verifies")
	}
	if _, err := a.Authenticate(tok2); err != nil {
		t.Fatal(err)
	}
	if s := j.Stats(); s.UnknownKid != 3 || s.Fetches != 3 || !slices.Equal(s.Keys, []string{"ec2"}) {
		t.Fatalf("stats %+v", s)
	}
}

// TestJWKSUnknownKidConcurrent sends many tokens with the new kid at once
// while the fetch they cause is slow: one fetch, and every lookup waits
// for it and succeeds; tokens with known kids don't wait.
func TestJWKSUnknownKidConcurrent(t *testing.T) {
	k := testKeys(t)
	is := newIssuer(t, jwksDoc(jwkOf(t, "ec1", k.ec.Public(), "")))
	clk := clock.NewFake(t0)
	j := newJWKS(t, is, clk, nil)
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := jwksAuth(t, j, clk)
	hold := make(chan struct{})
	is.set(func(is *issuer) {
		is.doc = jwksDoc(jwkOf(t, "ec1", k.ec.Public(), ""), jwkOf(t, "ec2", k.ec2.Public(), ""))
		is.hold = hold
	})
	tok1 := signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), claims(t0, 600))
	tok2 := signAsym(t, k.ec2, ES256, hdr(ES256, "ec2"), claims(t0, 600))
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 16 {
		wg.Go(func() {
			if _, err := a.Authenticate(tok2); err != nil {
				errs <- err
			}
		})
	}
	// Wait until the fetch is at the issuer, then check that a known kid
	// still verifies while it is held.
	deadline := time.Now().Add(10 * time.Second)
	for is.hits.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("unknown-kid fetch never reached the issuer")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := a.Authenticate(tok1); err != nil {
		t.Fatalf("known kid during a fetch: %v", err)
	}
	close(hold)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := is.hits.Load(); n != 2 {
		t.Fatalf("hits %d, want 2", n)
	}
}

// TestJWKSRun checks the schedule: max-age, clamped, decides the next
// refresh, ETags make refreshes conditional, and failures back off.
func TestJWKSRun(t *testing.T) {
	k := testKeys(t)
	is := newIssuer(t, jwksDoc(jwkOf(t, "ed1", k.ed.Public(), "")))
	is.set(func(is *issuer) { is.etag, is.cacheControl = `"v1"`, "public, max-age=600" })
	clk := clock.NewFake(t0)
	j := newJWKS(t, is, clk, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { j.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitHits := func(n int64) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for is.hits.Load() < n {
			if time.Now().After(deadline) {
				t.Fatalf("hits %d, want %d", is.hits.Load(), n)
			}
			time.Sleep(time.Millisecond)
		}
	}
	// step waits for Run to be waiting on its timer, then moves the clock.
	step := func(d time.Duration) {
		t.Helper()
		bctx, bcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer bcancel()
		if err := clk.BlockUntil(bctx, 1); err != nil {
			t.Fatal(err)
		}
		clk.Advance(d)
	}
	// settle waits for Run to be back on its timer, its fetch done.
	settle := func() {
		t.Helper()
		bctx, bcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer bcancel()
		if err := clk.BlockUntil(bctx, 1); err != nil {
			t.Fatal(err)
		}
	}
	// Run fetches at once when it has no set.
	step(0)
	waitHits(1)
	// max-age=600: the next fetch is 10 minutes later, not before.
	step(9 * time.Minute)
	time.Sleep(20 * time.Millisecond)
	if is.hits.Load() != 1 {
		t.Fatalf("refreshed before max-age: hits %d", is.hits.Load())
	}
	step(time.Minute)
	waitHits(2)
	settle()
	if is.conditional.Load() != 1 {
		t.Fatalf("refresh was not conditional")
	}
	if s := j.Stats(); s.NotModified != 1 || !s.LastSuccess.Equal(t0.Add(10*time.Minute)) {
		t.Fatalf("stats after 304: %+v", s)
	}
	// A tiny max-age is raised to MinJWKSInterval.
	is.set(func(is *issuer) { is.etag, is.cacheControl = `"v2"`, "max-age=1" })
	step(10 * time.Minute)
	waitHits(3)
	step(MinJWKSInterval - time.Second)
	time.Sleep(20 * time.Millisecond)
	if is.hits.Load() != 3 {
		t.Fatalf("max-age=1 not clamped: hits %d", is.hits.Load())
	}
	step(time.Second)
	waitHits(4)
	// Failures retry after 30s, then 60s, keeping the keys.
	is.set(func(is *issuer) { is.status, is.etag = http.StatusServiceUnavailable, "" })
	step(MinJWKSInterval)
	waitHits(5)
	step(30 * time.Second)
	waitHits(6)
	step(59 * time.Second)
	time.Sleep(20 * time.Millisecond)
	if is.hits.Load() != 6 {
		t.Fatalf("backoff did not double: hits %d", is.hits.Load())
	}
	step(time.Second)
	waitHits(7)
	settle()
	if _, ok := j.Lookup("ed1", EdDSA); !ok {
		t.Fatal("keys lost on failed refresh")
	}
	// Recovery resets the backoff and the schedule.
	is.set(func(is *issuer) { is.status, is.cacheControl = 0, "" })
	step(2 * time.Minute)
	waitHits(8)
	step(DefaultJWKSInterval - time.Second)
	time.Sleep(20 * time.Millisecond)
	if is.hits.Load() != 8 {
		t.Fatalf("default interval not used: hits %d", is.hits.Load())
	}
	settle()
	if s := j.Stats(); s.Failures != 3 {
		t.Fatalf("failures %d", s.Failures)
	}
}

// TestJWKSRunWithSet starts Run on a client that already has keys: the
// first refresh waits for the rest of the interval.
func TestJWKSRunWithSet(t *testing.T) {
	k := testKeys(t)
	is := newIssuer(t, jwksDoc(jwkOf(t, "ed1", k.ed.Public(), "")))
	clk := clock.NewFake(t0)
	j := newJWKS(t, is, clk, func(c *JWKSConfig) { c.Interval = 20 * time.Minute })
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clk.Advance(5 * time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { j.Run(ctx); close(done) }()
	bctx, bcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer bcancel()
	if err := clk.BlockUntil(bctx, 1); err != nil {
		t.Fatal(err)
	}
	clk.Advance(15*time.Minute - time.Second)
	time.Sleep(20 * time.Millisecond)
	if is.hits.Load() != 1 {
		t.Fatalf("hits %d", is.hits.Load())
	}
	clk.Advance(time.Second)
	deadline := time.Now().Add(10 * time.Second)
	for is.hits.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("no refresh at the interval")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}

// TestJWKSMaxStale: keys verify while refreshes fail, up to MaxStale after
// the last success, and then no longer.
func TestJWKSMaxStale(t *testing.T) {
	k := testKeys(t)
	is := newIssuer(t, jwksDoc(jwkOf(t, "ed1", k.ed.Public(), "")))
	clk := clock.NewFake(t0)
	j := newJWKS(t, is, clk, func(c *JWKSConfig) { c.MaxStale = 2 * time.Hour })
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	is.set(func(is *issuer) { is.status = http.StatusInternalServerError })
	clk.Advance(2 * time.Hour)
	if _, ok := j.Lookup("ed1", EdDSA); !ok {
		t.Fatal("key gone before MaxStale")
	}
	clk.Advance(time.Second)
	if _, ok := j.Lookup("ed1", EdDSA); ok {
		t.Fatal("key kept past MaxStale")
	}
	// The stale lookup tried one fetch; when the issuer is back, the
	// next one a minute later restores the keys.
	is.set(func(is *issuer) { is.status = 0 })
	if _, ok := j.Lookup("ed1", EdDSA); ok {
		t.Fatal("fetch inside the minute limit")
	}
	clk.Advance(UnknownKidInterval)
	if _, ok := j.Lookup("ed1", EdDSA); !ok {
		t.Fatal("keys not restored")
	}
}

// TestJWKSBadResponses: none of these replace the current set.
func TestJWKSBadResponses(t *testing.T) {
	k := testKeys(t)
	good := jwksDoc(jwkOf(t, "ed1", k.ed.Public(), ""))
	big := jwksDoc(jwkOf(t, "ed1", k.ed.Public(), `"pad":"`+strings.Repeat("a", MaxJWKSBytes)+`"`))
	for _, tc := range []struct {
		name   string
		doc    string
		status int
		want   string
	}{
		{"server error", good, http.StatusInternalServerError, "status 500"},
		{"not found", good, http.StatusNotFound, "status 404"},
		{"not modified without a set", good, http.StatusNotModified, "status 304"},
		{"not JSON", "<html>", 0, "invalid key"},
		{"no keys member", `{}`, 0, "no \"keys\""},
		{"empty set", `{"keys":[]}`, 0, "no key in the set"},
		{"only unusable keys", jwksDoc(jwkOf(t, "p", k.p384.Public(), "")), 0, "no key in the set"},
		{"private key", jwksDoc(jwkOf(t, "ed1", k.ed.Public(), `"d":"AAAA"`)), 0, "private key"},
		{"duplicate kid", jwksDoc(jwkOf(t, "a", k.ed.Public(), ""), jwkOf(t, "a", k.ec.Public(), "")), 0, "duplicate kid"},
		{"malformed EC point", jwksDoc(`{"kty":"EC","crv":"P-256","kid":"e","x":"AAAA","y":"AAAA"}`), 0, "invalid key"},
		{"short RSA key", jwksDoc(`{"kty":"RSA","kid":"r","n":"` + b64.EncodeToString(bytes.Repeat([]byte{0xff}, 128)) + `","e":"AQAB"}`), 0, "RSA modulus"},
		{"alg not fitting the key", jwksDoc(jwkOf(t, "e", k.ec.Public(), `"alg":"RS256"`)), 0, "invalid key"},
		{"over 64 KiB", big, 0, "larger than"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := newIssuer(t, tc.doc)
			is.set(func(is *issuer) { is.status = tc.status })
			clk := clock.NewFake(t0)
			j := newJWKS(t, is, clk, nil)
			err := j.Refresh(context.Background())
			if !errors.Is(err, ErrJWKS) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if _, ok := j.Lookup("ed1", EdDSA); ok && tc.status == 0 {
				t.Fatal("key from a refused document")
			}
		})
	}
	// After a good fetch, a bad one leaves the keys.
	is := newIssuer(t, good)
	clk := clock.NewFake(t0)
	j := newJWKS(t, is, clk, nil)
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	is.set(func(is *issuer) { is.doc = `{"keys":[]}` })
	if err := j.Refresh(context.Background()); err == nil {
		t.Fatal("empty set accepted")
	}
	if _, ok := j.Lookup("ed1", EdDSA); !ok {
		t.Fatal("bad refresh dropped the keys")
	}
	if s := j.Stats(); s.Failures != 1 || s.Fetches != 2 {
		t.Fatalf("stats %+v", s)
	}
}

// TestJWKSBodyCap sends a body over the cap without a Content-Length,
// so only the read limit can stop it.
func TestJWKSBodyCap(t *testing.T) {
	var sent atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := bytes.Repeat([]byte(" "), 4096)
		_, _ = w.Write([]byte(`{"keys":[`))
		for range 1024 { // 4 MiB of whitespace
			if _, err := w.Write(chunk); err != nil {
				return
			}
			sent.Add(int64(len(chunk)))
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	j, err := NewJWKS(JWKSConfig{URL: srv.URL, Guard: loopback, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
	// Content-Length over the cap is refused before reading.
	srv2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(MaxJWKSBytes+1))
		_, _ = w.Write(bytes.Repeat([]byte(" "), MaxJWKSBytes+1))
	}))
	defer srv2.Close()
	roots.AddCert(srv2.Certificate())
	j2, err := NewJWKS(JWKSConfig{URL: srv2.URL, Guard: loopback, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	if err := j2.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%d bytes is larger", MaxJWKSBytes+1)) {
		t.Fatalf("got %v", err)
	}
}

// TestJWKSNoRedirects: a redirect, even to a valid key set on the same
// host, is not followed.
func TestJWKSNoRedirects(t *testing.T) {
	k := testKeys(t)
	doc := jwksDoc(jwkOf(t, "ed1", k.ed.Public(), ""))
	var followed atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			followed.Store(true)
			_, _ = w.Write([]byte(doc))
			return
		}
		http.Redirect(w, r, "/moved", http.StatusFound)
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	j, err := NewJWKS(JWKSConfig{URL: srv.URL + "/jwks", Guard: loopback, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "redirects are not followed") {
		t.Fatalf("got %v", err)
	}
	if followed.Load() {
		t.Fatal("redirect followed")
	}
}

// TestJWKSEgressGuard: with the default guard a loopback issuer is refused
// at connect time, before any request is sent, and an untrusted
// certificate fails too.
func TestJWKSEgressGuard(t *testing.T) {
	k := testKeys(t)
	is := newIssuer(t, jwksDoc(jwkOf(t, "ed1", k.ed.Public(), "")))
	j, err := NewJWKS(JWKSConfig{URL: is.srv.URL, RootCAs: is.roots()})
	if err != nil {
		t.Fatal(err)
	}
	err = j.Refresh(context.Background())
	var be *egress.BlockedError
	if !errors.As(err, &be) || !errors.Is(err, egress.ErrBlocked) || be.Addr != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("got %v", err)
	}
	// A name resolving to loopback is refused the same way.
	j, err = NewJWKS(JWKSConfig{URL: strings.Replace(is.srv.URL, "127.0.0.1", "localhost", 1), RootCAs: is.roots()})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Refresh(context.Background()); !errors.Is(err, egress.ErrBlocked) {
		t.Fatalf("localhost: got %v", err)
	}
	if is.hits.Load() != 0 {
		t.Fatal("a refused connection reached the issuer")
	}
	// Allowed, but with the system roots: the test certificate fails.
	j = newJWKS(t, is, nil, func(c *JWKSConfig) { c.RootCAs = nil })
	if err := j.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted certificate: got %v", err)
	}
}

func TestJWKSTimeout(t *testing.T) {
	k := testKeys(t)
	is := newIssuer(t, jwksDoc(jwkOf(t, "ed1", k.ed.Public(), "")))
	hold := make(chan struct{})
	defer close(hold)
	is.set(func(is *issuer) { is.hold = hold })
	j := newJWKS(t, is, nil, func(c *JWKSConfig) { c.Timeout = 50 * time.Millisecond })
	start := time.Now()
	if _, ok := j.Lookup("ed1", EdDSA); ok {
		t.Fatal("key from a fetch that timed out")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("lookup took %v", d)
	}
	if s := j.Stats(); s.Failures != 1 || s.UnknownKid != 1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestJWKSConfigErrors(t *testing.T) {
	for _, tc := range []struct {
		cfg  JWKSConfig
		want string
	}{
		{JWKSConfig{URL: "http://issuer.example/jwks"}, "https"},
		{JWKSConfig{URL: "https:///jwks"}, "https"},
		{JWKSConfig{URL: "https://u:p@issuer.example/jwks"}, "user info"},
		{JWKSConfig{URL: "https://issuer.example/jwks#k"}, "fragment"},
		{JWKSConfig{URL: "https:issuer.example"}, "absolute"},
		{JWKSConfig{URL: "%zz"}, "https"},
		{JWKSConfig{URL: "https://issuer.example/jwks", Interval: -1}, "negative"},
		{JWKSConfig{URL: "https://issuer.example/jwks", Timeout: -1}, "negative"},
		{JWKSConfig{URL: "https://issuer.example/jwks", Interval: 2 * time.Hour, MaxStale: time.Hour}, "shorter"},
	} {
		if _, err := NewJWKS(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: got %v, want %q", tc.cfg, err, tc.want)
		}
	}
	j, err := NewJWKS(JWKSConfig{URL: "https://issuer.example/jwks", Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if j.cfg.Interval != MinJWKSInterval || j.cfg.MaxStale != DefaultJWKSMaxStale || j.cfg.Timeout != DefaultJWKSTimeout {
		t.Fatalf("defaults %+v", j.cfg)
	}
	if s := j.Stats(); s.Keys != nil || !s.LastSuccess.IsZero() {
		t.Fatalf("stats before a fetch %+v", s)
	}
}

func TestParseJWKS(t *testing.T) {
	k := testKeys(t)
	// A lone key without a kid is kept; beside others it can't be named
	// and is dropped.
	set, kids, err := ParseJWKS([]byte(jwksDoc(jwkOf(t, "", k.ed.Public(), ""))))
	if err != nil || !slices.Equal(kids, []string{""}) {
		t.Fatalf("%v %v", kids, err)
	}
	if _, ok := set.Lookup("", EdDSA); !ok {
		t.Fatal("lone kid-less key not found")
	}
	_, kids, err = ParseJWKS([]byte(jwksDoc(jwkOf(t, "", k.ed.Public(), ""), jwkOf(t, "ec1", k.ec.Public(), ""))))
	if err != nil || !slices.Equal(kids, []string{"ec1"}) {
		t.Fatalf("%v %v", kids, err)
	}
	// Kids over MaxPublicKeyID are skipped.
	_, kids, err = ParseJWKS([]byte(jwksDoc(jwkOf(t, strings.Repeat("k", MaxPublicKeyID+1), k.ed.Public(), ""), jwkOf(t, "ec1", k.ec.Public(), ""))))
	if err != nil || !slices.Equal(kids, []string{"ec1"}) {
		t.Fatalf("%v %v", kids, err)
	}
	// Two kid-less keys: none can be named.
	if _, _, err := ParseJWKS([]byte(jwksDoc(jwkOf(t, "", k.ed.Public(), ""), jwkOf(t, "", k.ec.Public(), "")))); err == nil {
		t.Fatal("two kid-less keys accepted")
	}
	if _, _, err := ParseJWKS(make([]byte, MaxJWKSBytes+1)); err == nil {
		t.Fatal("oversized document accepted")
	}
}

func TestCacheMaxAge(t *testing.T) {
	for h, want := range map[string]time.Duration{
		"":                                    -1,
		"public":                              -1,
		"max-age=300":                         300 * time.Second,
		"public, MAX-AGE=60, must-revalidate": 60 * time.Second,
		`max-age="120"`:                       120 * time.Second,
		"max-age=-5":                          -1,
		"max-age=abc":                         -1,
		"max-age=99999999999999999999":        -1,
		"max-age=99999999999999999":           MaxJWKSInterval,
		"max-age=9999999":                     MaxJWKSInterval,
		"no-store":                            0,
		"max-age=600, no-cache":               0,
	} {
		if got := cacheMaxAge(h); got != want {
			t.Errorf("%q: got %v, want %v", h, got, want)
		}
	}
}

// TestJWKSLogsKeyChanges: a fetch that changes the kids is logged, one
// that doesn't is not.
func TestJWKSLogsKeyChanges(t *testing.T) {
	k := testKeys(t)
	is := newIssuer(t, jwksDoc(jwkOf(t, "ed1", k.ed.Public(), "")))
	var buf bytes.Buffer
	var mu sync.Mutex
	h := slog.NewTextHandler(lockedWriter{&mu, &buf}, nil)
	j := newJWKS(t, is, clock.NewFake(t0), func(c *JWKSConfig) { c.Logger = slog.New(h) })
	for range 2 {
		if err := j.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	is.set(func(is *issuer) { is.doc = jwksDoc(jwkOf(t, "ec1", k.ec.Public(), "")) })
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if n := strings.Count(buf.String(), "jwks keys loaded"); n != 2 {
		t.Fatalf("%d key change lines:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "kids=[ec1]") {
		t.Fatalf("log:\n%s", buf.String())
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
