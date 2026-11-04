package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/jose"
)

var t0 = time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)

// rsaKey is generated once: RSA generation dominates the suite otherwise.
var rsaKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, RSABits)
	if err != nil {
		panic(err)
	}
	return k
})

// rsaPool holds a few distinct RSA keys for tests that need more than one.
var rsaPool = sync.OnceValue(func() []*rsa.PrivateKey {
	out := []*rsa.PrivateKey{rsaKey()}
	for i := 0; i < 3; i++ {
		k, err := rsa.GenerateKey(rand.Reader, RSABits)
		if err != nil {
			panic(err)
		}
		out = append(out, k)
	}
	return out
})

func mustGen(t testing.TB, alg Alg) *Key {
	t.Helper()
	if alg == RS256 {
		k, err := FromSigner(rsaKey(), t0)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	k, err := Generate(alg, t0)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAlgs(t *testing.T) {
	for _, a := range Algs {
		if !a.Valid() {
			t.Errorf("%s not valid", a)
		}
	}
	if Alg("HS512").Valid() || Alg("none").Valid() {
		t.Error("unknown algorithms valid")
	}
	if !HS256.Symmetric() || !A256GCM.Symmetric() || ES256.Symmetric() || EdDSA.Symmetric() || RS256.Symmetric() {
		t.Error("Symmetric wrong")
	}
	if _, err := Generate("none", t0); !errors.Is(err, ErrAlg) {
		t.Errorf("Generate(none) = %v", err)
	}
}

func TestSignVerifyEveryAlg(t *testing.T) {
	for _, alg := range []Alg{EdDSA, ES256, RS256, HS256} {
		t.Run(string(alg), func(t *testing.T) {
			k := mustGen(t, alg)
			if k.Alg() != alg || !k.Created().Equal(t0) || !kidRe.MatchString(k.ID()) {
				t.Fatalf("key %s %s %s", k.Alg(), k.Created(), k.ID())
			}
			msg := []byte("header.payload")
			sig, err := k.Sign(msg)
			if err != nil {
				t.Fatal(err)
			}
			if !k.Verify(msg, sig) {
				t.Fatal("own signature does not verify")
			}
			if k.Verify([]byte("header.payloaD"), sig) {
				t.Error("signature verifies another message")
			}
			bad := append([]byte(nil), sig...)
			bad[len(bad)-1] ^= 1
			if k.Verify(msg, bad) {
				t.Error("tampered signature verifies")
			}
			if k.Verify(msg, sig[:len(sig)-1]) {
				t.Error("truncated signature verifies")
			}
			other := mustGen(t, alg)
			if alg == RS256 {
				other, _ = FromSigner(rsaPool()[1], t0)
			}
			if other.ID() == k.ID() || other.Verify(msg, sig) {
				t.Error("another key verifies the signature")
			}
			if _, err := k.AEAD(); !errors.Is(err, ErrNoSeal) {
				t.Errorf("AEAD on %s = %v", alg, err)
			}
		})
	}
}

func TestAsymmetricAccessors(t *testing.T) {
	for _, alg := range []Alg{EdDSA, ES256, RS256} {
		k := mustGen(t, alg)
		if k.Public() == nil || k.Signer() == nil || k.Secret() != nil || k.JWK() == nil {
			t.Errorf("%s accessors", alg)
		}
		pub, ok := k.Signer().Public().(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !pub.Equal(k.Public()) {
			t.Errorf("%s Public does not match Signer", alg)
		}
		var m map[string]string
		if err := json.Unmarshal(k.JWK(), &m); err != nil {
			t.Fatal(err)
		}
		if m["kid"] != k.ID() || m["alg"] != string(alg) || m["use"] != "sig" || m["d"] != "" {
			t.Errorf("%s JWK %v", alg, m)
		}
		j := k.JWK()
		j[0] = 'x'
		if k.JWK()[0] != '{' {
			t.Error("JWK returns the key's own buffer")
		}
	}
}

func TestSymmetricAccessors(t *testing.T) {
	h := mustGen(t, HS256)
	s := mustGen(t, A256GCM)
	for _, k := range []*Key{h, s} {
		if k.Public() != nil || k.Signer() != nil || k.JWK() != nil || len(k.Secret()) != 32 {
			t.Errorf("%s accessors", k.Alg())
		}
		sec := k.Secret()
		sec[0] ^= 0xff
		if bytes.Equal(sec, k.Secret()) {
			t.Error("Secret returns the key's own buffer")
		}
	}
	if _, err := s.Sign([]byte("x")); !errors.Is(err, ErrNoSign) {
		t.Errorf("A256GCM Sign = %v", err)
	}
	if s.Verify([]byte("x"), make([]byte, 32)) {
		t.Error("A256GCM verifies")
	}
	aead, err := s.AEAD()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	ct := aead.Seal(nil, nonce, []byte("session"), nil)
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil || string(pt) != "session" {
		t.Fatalf("open %q %v", pt, err)
	}
}

// The thumbprint kid matches the one wicket's upstream signer always put in
// token headers, so upstreams keep their cached keys across the move.
func TestES256KidMatchesWicketSigner(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k, err := FromSigner(priv, t0)
	if err != nil {
		t.Fatal(err)
	}
	sg, _ := jose.NewSigner(priv)
	if k.ID() != sg.KeyID() || k.ID() != jose.Thumbprint(&priv.PublicKey) {
		t.Fatalf("kid %s, wicket signer %s", k.ID(), sg.KeyID())
	}
}

// RFC 7638 section 3.1 gives the thumbprint of an RSA key.
func TestRFC7638Example(t *testing.T) {
	n, _ := base64.RawURLEncoding.DecodeString("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
	priv := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}}
	k := &Key{alg: RS256, rsa: priv}
	_, canon := k.publicMembers()
	sum := sha256Sum(canon)
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %s", got)
	}
}

// Tokens signed by ring keys verify with the JWKS the set renders, through
// the JOSE verifier wicket's relying party uses.
func TestJWKSVerifiesThroughJOSE(t *testing.T) {
	set := NewSet()
	for _, alg := range []Alg{EdDSA, ES256, RS256, HS256} {
		cur := mustGen(t, alg)
		if err := set.Add(strings.ToLower(string(alg)), mustConfigured(t, cur)); err != nil {
			t.Fatal(err)
		}
	}
	ks, err := jose.ParseKeySet(set.JWKS(t0))
	if err != nil {
		t.Fatal(err)
	}
	if len(ks.Keys) != 3 {
		t.Fatalf("JWKS has %d keys, want the 3 asymmetric ones", len(ks.Keys))
	}
	for _, alg := range []Alg{EdDSA, ES256, RS256} {
		k := set.Ring(strings.ToLower(string(alg))).Current()
		hb, _ := json.Marshal(jose.Header{Alg: string(alg), Kid: k.ID(), Typ: "JWT"})
		input := b64(hb) + "." + b64([]byte(`{"sub":"alice"}`))
		sig, err := k.Sign([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		tok, err := jose.Parse(input + "." + b64(sig))
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, jk := range ks.Keys {
			if jk.ID == k.ID() {
				found = true
				if err := tok.Verify(jk, jose.SupportedAlgorithms); err != nil {
					t.Errorf("%s: %v", alg, err)
				}
			}
		}
		if !found {
			t.Errorf("%s key %s not in JWKS", alg, k.ID())
		}
	}
}

func mustConfigured(t testing.TB, ks ...*Key) *Ring {
	t.Helper()
	r, err := Configured(Policy{}, t0, ks...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type fakeSigner struct{}

func (fakeSigner) Public() crypto.PublicKey                                  { return nil }
func (fakeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }

func TestFromSignerRefuses(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	broken := *rsaKey()
	broken.Primes = []*big.Int{big.NewInt(3), big.NewInt(5)}
	for name, s := range map[string]crypto.Signer{
		"P-384":       p384,
		"RSA-1024":    small,
		"RSA-broken":  &broken,
		"short-ed":    ed25519.PrivateKey(make([]byte, 10)),
		"unsupported": fakeSigner{},
	} {
		if _, err := FromSigner(s, t0); !errors.Is(err, ErrKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestFromSecret(t *testing.T) {
	sec := bytes.Repeat([]byte{7}, 32)
	a, err := FromSecret(HS256, "", sec, t0)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := FromSecret(HS256, "", sec, t0.Add(time.Hour))
	c, _ := FromSecret(A256GCM, "", sec, t0)
	if a.ID() != b.ID() {
		t.Error("derived kid is not stable")
	}
	if a.ID() == c.ID() {
		t.Error("the same secret has the same kid for two algorithms")
	}
	if len(a.ID()) != 16 {
		t.Errorf("derived kid %q", a.ID())
	}
	named, err := FromSecret(HS256, "k2026", sec, t0)
	if err != nil || named.ID() != "k2026" {
		t.Fatalf("named %v %v", named, err)
	}
	sec[0] = 9
	if named.Secret()[0] != 7 {
		t.Error("FromSecret keeps the caller's slice")
	}
	long, err := FromSecret(HS256, "", make([]byte, 64), t0)
	if err != nil || len(long.Secret()) != 64 {
		t.Errorf("64-byte HS256 secret: %v", err)
	}
	for name, tc := range map[string]struct {
		alg Alg
		kid string
		n   int
		err error
	}{
		"short hmac":  {HS256, "", 31, ErrKey},
		"long hmac":   {HS256, "", MaxSecretBytes + 1, ErrKey},
		"short seal":  {A256GCM, "", 16, ErrKey},
		"asymmetric":  {ES256, "", 32, ErrAlg},
		"bad kid":     {HS256, "a b", 32, ErrKey},
		"long kid":    {HS256, strings.Repeat("a", 65), 32, ErrKey},
		"unknown alg": {"HS384", "", 48, ErrAlg},
	} {
		if _, err := FromSecret(tc.alg, tc.kid, make([]byte, tc.n), t0); !errors.Is(err, tc.err) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCreatedIsUTC(t *testing.T) {
	loc := time.FixedZone("x", 3600)
	k, _ := Generate(ES256, t0.In(loc))
	if k.Created().Location() != time.UTC || !k.Created().Equal(t0) {
		t.Errorf("created %v", k.Created())
	}
}

func sha256Sum(s string) [32]byte { return sha256.Sum256([]byte(s)) }
