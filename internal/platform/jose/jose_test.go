package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	mrand "math/rand/v2"
	"strings"
	"testing"
	"time"
)

var (
	rsaKey, _        = rsa.GenerateKey(rand.Reader, 2048)
	p256Key, _       = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384Key, _       = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521Key, _       = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	edPub, edPriv, _ = ed25519.GenerateKey(rand.Reader)
	unusedKey, _     = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
)

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// sign produces a compact JWS with any algorithm, including ones Verify
// must refuse, so attacks can be built.
func sign(t testing.TB, alg string, key any, header map[string]any, claims any) string {
	t.Helper()
	if header == nil {
		header = map[string]any{}
	}
	header["alg"] = alg
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	input := enc(hb) + "." + enc(pb)
	var sig []byte
	var err error
	digest := func(h crypto.Hash) []byte { d := h.New(); d.Write([]byte(input)); return d.Sum(nil) }
	switch {
	case alg == "none":
	case strings.HasPrefix(alg, "HS"):
		m := hmac.New(sha256.New, key.([]byte))
		m.Write([]byte(input))
		sig = m.Sum(nil)
	case strings.HasPrefix(alg, "RS"):
		h := hashFor(alg)
		sig, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), h, digest(h))
	case strings.HasPrefix(alg, "PS"):
		h := hashFor(alg)
		sig, err = rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), h, digest(h), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case strings.HasPrefix(alg, "ES"):
		k := key.(*ecdsa.PrivateKey)
		r, s, e := ecdsa.Sign(rand.Reader, k, digest(hashFor(alg)))
		err = e
		size := (k.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*size)
		r.FillBytes(sig[:size])
		s.FillBytes(sig[size:])
	case alg == "EdDSA":
		sig = ed25519.Sign(key.(ed25519.PrivateKey), []byte(input))
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + enc(sig)
}

func rsaJWK(pub *rsa.PublicKey, kid, alg string) map[string]string {
	return map[string]string{"kty": "RSA", "kid": kid, "alg": alg, "n": enc(pub.N.Bytes()), "e": enc(big.NewInt(int64(pub.E)).Bytes())}
}

func ecJWK(pub *ecdsa.PublicKey, crv, kid string) map[string]string {
	b, _ := pub.Bytes()
	size := (len(b) - 1) / 2
	return map[string]string{"kty": "EC", "crv": crv, "kid": kid, "x": enc(b[1 : 1+size]), "y": enc(b[1+size:])}
}

func keySet(t testing.TB, keys ...map[string]string) *KeySet {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"keys": keys})
	ks, err := ParseKeySet(b)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestVerifyEveryAlgorithm(t *testing.T) {
	ks := keySet(t,
		rsaJWK(&rsaKey.PublicKey, "rsa", ""),
		ecJWK(&p256Key.PublicKey, "P-256", "p256"),
		ecJWK(&p384Key.PublicKey, "P-384", "p384"),
		ecJWK(&p521Key.PublicKey, "P-521", "p521"),
		map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": "ed", "x": enc(edPub)},
	)
	byID := map[string]Key{}
	for _, k := range ks.Keys {
		byID[k.ID] = k
	}
	cases := []struct {
		alg string
		key any
		kid string
	}{
		{"RS256", rsaKey, "rsa"}, {"RS384", rsaKey, "rsa"}, {"RS512", rsaKey, "rsa"},
		{"PS256", rsaKey, "rsa"}, {"PS384", rsaKey, "rsa"}, {"PS512", rsaKey, "rsa"},
		{"ES256", p256Key, "p256"}, {"ES384", p384Key, "p384"}, {"ES512", p521Key, "p521"},
		{"EdDSA", edPriv, "ed"},
	}
	for _, c := range cases {
		t.Run(c.alg, func(t *testing.T) {
			tok, err := Parse(sign(t, c.alg, c.key, map[string]any{"kid": c.kid}, map[string]any{"sub": "x"}))
			if err != nil {
				t.Fatal(err)
			}
			if err := tok.Verify(byID[c.kid], SupportedAlgorithms); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if err := tok.Verify(byID[c.kid], []string{"RS256"}); c.alg != "RS256" && !errors.Is(err, ErrAlgorithm) {
				t.Fatalf("algorithm outside allow-list: %v", err)
			}
		})
	}
}

// TestAttacks lists known JWT attacks and the rejection each must get.
func TestAttacks(t *testing.T) {
	rsaPub := Key{ID: "rsa", Public: &rsaKey.PublicKey}
	// The classic key-confusion attack: HMAC "signed" with the PEM bytes
	// of the server's RSA public key.
	pemLike, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	all := SupportedAlgorithms
	cases := []struct {
		name    string
		token   string
		key     Key
		allowed []string
		want    error
	}{
		{"alg none", sign(t, "none", nil, nil, map[string]any{"sub": "x"}), rsaPub, all, ErrAlgorithm},
		{"alg none even if listed", sign(t, "none", nil, nil, map[string]any{"sub": "x"}), rsaPub, []string{"none"}, ErrAlgorithm},
		{"HS256 with RSA public key as secret", sign(t, "HS256", pemLike, nil, map[string]any{"sub": "x"}), rsaPub, []string{"HS256", "RS256"}, ErrAlgorithm},
		{"RS256 token, EC key", sign(t, "RS256", rsaKey, nil, map[string]any{}), Key{Public: &p256Key.PublicKey}, all, ErrKeyMismatch},
		{"ES256 token, RSA key", sign(t, "ES256", p256Key, nil, map[string]any{}), rsaPub, all, ErrKeyMismatch},
		{"ES384 token, P-256 key", sign(t, "ES384", p384Key, nil, map[string]any{}), Key{Public: &p256Key.PublicKey}, all, ErrKeyMismatch},
		{"key pinned to another alg", sign(t, "PS256", rsaKey, nil, map[string]any{}), Key{Alg: "RS256", Public: &rsaKey.PublicKey}, all, ErrKeyMismatch},
		{"encryption key", sign(t, "RS256", rsaKey, nil, map[string]any{}), Key{Use: "enc", Public: &rsaKey.PublicKey}, all, ErrKeyMismatch},
		{"signed by another key", sign(t, "ES256", mustEC(), nil, map[string]any{}), Key{Public: &p256Key.PublicKey}, all, ErrSignature},
		{"EdDSA wrong key", sign(t, "EdDSA", edPriv, nil, map[string]any{}), Key{Public: mustEd()}, all, ErrSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok, err := Parse(c.token)
			if err != nil {
				t.Fatal(err)
			}
			if err := tok.Verify(c.key, c.allowed); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func mustEC() *ecdsa.PrivateKey { k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return k }
func mustEd() ed25519.PublicKey { p, _, _ := ed25519.GenerateKey(rand.Reader); return p }

func TestTamperedSignatures(t *testing.T) {
	tok := sign(t, "ES256", p256Key, nil, map[string]any{"sub": "alice"})
	parts := strings.Split(tok, ".")
	evil, _ := json.Marshal(map[string]any{"sub": "admin"})
	swapped := parts[0] + "." + enc(evil) + "." + parts[2]
	short := parts[0] + "." + parts[1] + "." + enc([]byte("short"))
	for _, s := range []string{swapped, short} {
		p, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Verify(Key{Public: &p256Key.PublicKey}, SupportedAlgorithms); !errors.Is(err, ErrSignature) {
			t.Fatalf("tampered token: %v", err)
		}
	}
	rs := sign(t, "RS256", rsaKey, nil, map[string]any{})
	p, _ := Parse(rs[:strings.LastIndexByte(rs, '.')+1] + enc(make([]byte, 256)))
	if err := p.Verify(Key{Public: &rsaKey.PublicKey}, SupportedAlgorithms); !errors.Is(err, ErrSignature) {
		t.Fatal(err)
	}
	ps := sign(t, "PS256", rsaKey, nil, map[string]any{})
	p, _ = Parse(ps[:strings.LastIndexByte(ps, '.')+1] + enc(make([]byte, 256)))
	if err := p.Verify(Key{Public: &rsaKey.PublicKey}, SupportedAlgorithms); !errors.Is(err, ErrSignature) {
		t.Fatal(err)
	}
}

func TestParseMalformed(t *testing.T) {
	good := sign(t, "ES256", p256Key, nil, map[string]any{})
	parts := strings.Split(good, ".")
	hdr := func(v string) string { return enc([]byte(v)) + "." + parts[1] + "." + parts[2] }
	cases := map[string]string{
		"two parts":       parts[0] + "." + parts[1],
		"four parts":      good + ".x",
		"padding":         parts[0] + "=." + parts[1] + "." + parts[2],
		"bad payload b64": parts[0] + ".!!." + parts[2],
		"bad sig b64":     parts[0] + "." + parts[1] + ".!!",
		"header not json": hdr("nope"),
		"header no alg":   hdr(`{"kid":"x"}`),
		"header trailing": hdr(`{"alg":"ES256"} {}`),
		"header array":    hdr(`["alg"]`),
		"critical":        hdr(`{"alg":"ES256","crit":["exp"]}`),
		"too long":        strings.Repeat("a", MaxTokenBytes+1),
		"empty":           "",
		"header alg type": hdr(`{"alg":1}`),
	}
	for name, s := range cases {
		if _, err := Parse(s); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := Parse(hdr(`{"alg":"ES256","crit":["b64"]}`)); !errors.Is(err, ErrCritical) {
		t.Errorf("crit: %v", err)
	}
}

func TestParseKeySet(t *testing.T) {
	ks := keySet(t,
		rsaJWK(&rsaKey.PublicKey, "a", "RS256"),
		map[string]string{"kty": "RSA", "use": "enc", "kid": "enc", "n": "AQAB", "e": "AQAB"},
		map[string]string{"kty": "oct", "kid": "sym", "k": "c2VjcmV0"},
		map[string]string{"kty": "EC", "crv": "secp256k1", "kid": "k1"},
		map[string]string{"kty": "OKP", "crv": "X25519", "kid": "x"},
	)
	if len(ks.Keys) != 1 || ks.Keys[0].ID != "a" || !ks.Keys[0].Fits("RS256") || ks.Keys[0].Fits("PS256") {
		t.Fatalf("got %+v", ks.Keys)
	}
	opsVerify, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "key_ops": []string{"encrypt"}, "n": "AQAB", "e": "AQAB"}}})
	if ks, err := ParseKeySet(opsVerify); err != nil || len(ks.Keys) != 0 {
		t.Fatalf("key_ops without verify: %v %v", ks, err)
	}

	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	offCurve := ecJWK(&p256Key.PublicKey, "P-256", "c")
	offCurve["y"] = offCurve["x"]
	bad := map[string]any{
		"not json":       "nope",
		"no keys":        map[string]any{},
		"private key":    map[string]any{"keys": []any{map[string]string{"kty": "EC", "crv": "P-256", "d": "AA"}}},
		"short rsa":      map[string]any{"keys": []any{rsaJWK(&small.PublicKey, "s", "")}},
		"even exponent":  map[string]any{"keys": []any{map[string]string{"kty": "RSA", "n": rsaJWK(&rsaKey.PublicKey, "", "")["n"], "e": enc([]byte{2})}}},
		"leading zero n": map[string]any{"keys": []any{map[string]string{"kty": "RSA", "n": enc(append([]byte{0}, rsaKey.N.Bytes()...)), "e": "AQAB"}}},
		"empty n":        map[string]any{"keys": []any{map[string]string{"kty": "RSA", "n": "", "e": "AQAB"}}},
		"bad e":          map[string]any{"keys": []any{map[string]string{"kty": "RSA", "n": rsaJWK(&rsaKey.PublicKey, "", "")["n"], "e": "!!"}}},
		"off curve":      map[string]any{"keys": []any{offCurve}},
		"short x":        map[string]any{"keys": []any{map[string]string{"kty": "EC", "crv": "P-256", "x": "AQAB", "y": "AQAB"}}},
		"bad y":          map[string]any{"keys": []any{map[string]string{"kty": "EC", "crv": "P-256", "x": ecJWK(&p256Key.PublicKey, "P-256", "")["x"], "y": "!"}}},
		"short ed25519":  map[string]any{"keys": []any{map[string]string{"kty": "OKP", "crv": "Ed25519", "x": "AQAB"}}},
		"duplicate kid":  map[string]any{"keys": []any{rsaJWK(&rsaKey.PublicKey, "d", ""), rsaJWK(&rsaKey.PublicKey, "d", "")}},
		"alg mismatch":   map[string]any{"keys": []any{rsaJWK(&rsaKey.PublicKey, "m", "ES256")}},
		"key not object": map[string]any{"keys": []any{"x"}},
	}
	for name, v := range bad {
		b, _ := json.Marshal(v)
		if name == "not json" {
			b = []byte("nope")
		}
		if _, err := ParseKeySet(b); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	many := make([]any, MaxJWKSKeys+1)
	for i := range many {
		many[i] = map[string]string{"kty": "oct"}
	}
	b, _ := json.Marshal(map[string]any{"keys": many})
	if _, err := ParseKeySet(b); err == nil {
		t.Error("too many keys accepted")
	}
	if _, err := ParseKeySet(make([]byte, MaxJWKSBytes+1)); err == nil {
		t.Error("oversized set accepted")
	}
}

func TestSignerAndThumbprint(t *testing.T) {
	if _, err := NewSigner(p384Key); err == nil {
		t.Fatal("P-384 signer accepted")
	}
	if _, err := NewSigner(nil); err == nil {
		t.Fatal("nil signer accepted")
	}
	s, err := NewSigner(p256Key)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 7638 thumbprints are 32 bytes, base64url without padding.
	if len(s.KeyID()) != 43 || s.KeyID() != Thumbprint(&p256Key.PublicKey) {
		t.Fatalf("kid %q", s.KeyID())
	}
	tok, err := s.Sign(map[string]any{"sub": "alice"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(tok)
	if err != nil || p.Header.Kid != s.KeyID() || p.Header.Typ != "JWT" {
		t.Fatalf("%v %+v", err, p)
	}
	jwk := PublicJWK(s.Public(), s.KeyID())
	b, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	ks, err := ParseKeySet(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(ks.Keys[0], []string{"ES256"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(func() {}); err == nil {
		t.Fatal("unmarshalable claims signed")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("PublicJWK accepted a P-384 key")
		}
	}()
	PublicJWK(&p384Key.PublicKey, "")
}

func TestClaimsValidate(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	base := func() map[string]any {
		return map[string]any{"iss": "https://idp", "aud": "client", "sub": "u", "exp": now.Unix() + 60, "iat": now.Unix()}
	}
	with := func(k string, v any) map[string]any { m := base(); m[k] = v; return m }
	without := func(k string) map[string]any { m := base(); delete(m, k); return m }
	expect := Expect{Issuer: "https://idp", Audience: "client", Now: now, Skew: 30 * time.Second, MaxAge: 10 * time.Minute}
	cases := []struct {
		name   string
		claims map[string]any
		reason string
	}{
		{"valid", base(), ""},
		{"wrong issuer", with("iss", "https://evil"), ReasonIssuer},
		{"wrong audience", with("aud", "other"), ReasonAudience},
		{"audience list", with("aud", []string{"client"}), ""},
		{"untrusted extra audience", with("aud", []string{"client", "other"}), ReasonAudience},
		{"expired", with("exp", now.Unix()-31), ReasonExpired},
		{"expired within skew", with("exp", now.Unix()-29), ""},
		{"no exp", without("exp"), ReasonMissing},
		{"no iat", without("iat"), ReasonMissing},
		{"iat in future", with("iat", now.Unix()+31), ReasonIssuedAt},
		{"iat too old", with("iat", now.Unix()-700), ReasonIssuedAt},
		{"nbf in future", with("nbf", now.Unix()+31), ReasonNotYet},
		{"nbf within skew", with("nbf", now.Unix()+29), ""},
		{"azp other client", with("azp", "other"), ReasonAZP},
		{"azp matches", with("azp", "client"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, _ := json.Marshal(c.claims)
			cl, err := ParseClaims(b)
			if err != nil {
				t.Fatal(err)
			}
			err = cl.Validate(expect)
			var ce *ClaimError
			if c.reason == "" && err != nil {
				t.Fatalf("unexpected %v", err)
			}
			if c.reason != "" && (!errors.As(err, &ce) || ce.Reason != c.reason) {
				t.Fatalf("got %v, want reason %s", err, c.reason)
			}
		})
	}
	// Several audiences: azp required, and each extra must be trusted.
	m := base()
	m["aud"] = []string{"client", "api"}
	b, _ := json.Marshal(m)
	cl, _ := ParseClaims(b)
	e := expect
	e.TrustedAudiences = []string{"api"}
	var ce *ClaimError
	if err := cl.Validate(e); !errors.As(err, &ce) || ce.Reason != ReasonAZP {
		t.Fatalf("multi-aud without azp: %v", err)
	}
	m["azp"] = "client"
	b, _ = json.Marshal(m)
	cl, _ = ParseClaims(b)
	if err := cl.Validate(e); err != nil {
		t.Fatal(err)
	}
}

func TestClaimHelpers(t *testing.T) {
	cl, err := ParseClaims([]byte(`{"aud":["a","b"],"s":"x","b":true,"n":3,"g":["x","y"],"g1":"z","gn":null,"gbad":[1]}`))
	if err != nil {
		t.Fatal(err)
	}
	if cl.String("s") != "x" || cl.String("n") != "" || cl.String("missing") != "" {
		t.Fatal("String")
	}
	if v, ok := cl.Bool("b"); !v || !ok {
		t.Fatal("Bool")
	}
	if _, ok := cl.Bool("s"); ok {
		t.Fatal("Bool on string")
	}
	if _, ok := cl.Bool("missing"); ok {
		t.Fatal("Bool on missing")
	}
	if g, err := cl.Strings("g"); err != nil || len(g) != 2 {
		t.Fatal("Strings array")
	}
	if g, err := cl.Strings("g1"); err != nil || len(g) != 1 {
		t.Fatal("Strings single")
	}
	if g, err := cl.Strings("gn"); err != nil || g != nil {
		t.Fatal("Strings null")
	}
	if _, err := cl.Strings("gbad"); err == nil {
		t.Fatal("Strings bad")
	}
	if b, _ := json.Marshal(Audience{"a"}); string(b) != `"a"` {
		t.Fatalf("single audience: %s", b)
	}
	if b, _ := json.Marshal(Audience{"a", "b"}); string(b) != `["a","b"]` {
		t.Fatalf("audience list: %s", b)
	}
	for _, bad := range []string{`{"exp":"123"}`, `{"exp":-1}`, `{"exp":1e300}`, `{"aud":5}`, `{"iss":1}`, `[]`, `{} x`} {
		if _, err := ParseClaims([]byte(bad)); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
	if cl, err := ParseClaims([]byte(`{"exp":1.9}`)); err != nil || int64(*cl.Expiry) != 1 {
		t.Fatal("fractional exp")
	}
	ce := &ClaimError{Reason: "r", Msg: "m"}
	if ce.Error() != "jose: m" {
		t.Fatal(ce.Error())
	}
}

// TestPropertySignedTokens: for random claims, a signed token verifies and
// returns exactly the payload; flipping any single character of the
// compact form makes parsing or verification fail.
func TestPropertySignedTokens(t *testing.T) {
	r := mrand.New(mrand.NewPCG(1, 2))
	s, _ := NewSigner(p256Key)
	key := Key{Public: &p256Key.PublicKey}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := 0; i < 200; i++ {
		claims := map[string]any{"sub": randString(r, 1+r.IntN(40)), "n": r.Int64(), "groups": []string{randString(r, 5)}}
		tok, err := s.Sign(claims)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Parse(tok)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Verify(key, []string{"ES256"}); err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(claims)
		if string(p.Payload) != string(want) {
			t.Fatalf("payload changed: %s vs %s", p.Payload, want)
		}
		pos := r.IntN(len(tok))
		if tok[pos] == '.' {
			continue
		}
		c := alphabet[r.IntN(len(alphabet))]
		if c == tok[pos] {
			continue
		}
		mut := tok[:pos] + string(c) + tok[pos+1:]
		if mp, err := Parse(mut); err == nil {
			if err := mp.Verify(key, []string{"ES256"}); err == nil {
				// Only the unused low bits of the last base64 character
				// can change without changing the decoded bytes; Strict
				// decoding rejects those, so any success is a bug.
				t.Fatalf("mutated token verified: %s", mut)
			}
		}
	}
}

func randString(r *mrand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(0x20 + r.IntN(0x5e))
	}
	return string(b)
}

func FuzzParse(f *testing.F) {
	f.Add(sign(f, "ES256", p256Key, nil, map[string]any{"sub": "x"}))
	f.Add("e30.e30.")
	f.Add("..")
	f.Fuzz(func(t *testing.T, s string) {
		tok, err := Parse(s)
		if err != nil {
			return
		}
		if tok.Header.Alg == "" || len(tok.Header.Crit) > 0 {
			t.Fatalf("accepted header %+v", tok.Header)
		}
		// Nothing may verify under a key that never signed anything.
		if tok.Verify(Key{Public: &unusedKey.PublicKey}, SupportedAlgorithms) == nil {
			t.Fatalf("random token verified: %q", s)
		}
		_, _ = ParseClaims(tok.Payload)
	})
}

func FuzzParseKeySet(f *testing.F) {
	b, _ := json.Marshal(map[string]any{"keys": []any{rsaJWK(&rsaKey.PublicKey, "a", "RS256"), ecJWK(&p256Key.PublicKey, "P-256", "b")}})
	f.Add(b)
	f.Add([]byte(`{"keys":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		ks, err := ParseKeySet(b)
		if err != nil {
			return
		}
		for _, k := range ks.Keys {
			if k.Public == nil {
				t.Fatal("key without public part")
			}
			if k.Alg != "" && !k.Fits(k.Alg) {
				t.Fatalf("key pinned to an algorithm it can't verify: %+v", k)
			}
		}
	})
}

func BenchmarkVerifyRS256(b *testing.B) {
	tok, _ := Parse(sign(b, "RS256", rsaKey, nil, map[string]any{"sub": "x"}))
	key := Key{Public: &rsaKey.PublicKey}
	for b.Loop() {
		if err := tok.Verify(key, []string{"RS256"}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignES256(b *testing.B) {
	s, _ := NewSigner(p256Key)
	claims := map[string]any{"sub": "alice", "groups": []string{"eng"}}
	for b.Loop() {
		if _, err := s.Sign(claims); err != nil {
			b.Fatal(err)
		}
	}
}
