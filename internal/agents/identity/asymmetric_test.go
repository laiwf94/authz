package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/jose"
)

// asymKeys are generated once: RSA key generation is slow under -race.
type asymKeys struct {
	ed, ed2 ed25519.PrivateKey
	ec, ec2 *ecdsa.PrivateKey
	p384    *ecdsa.PrivateKey
	rsa     *rsa.PrivateKey
	rsa2    *rsa.PrivateKey
}

var (
	asymOnce sync.Once
	asym     asymKeys
)

func testKeys(t testing.TB) *asymKeys {
	t.Helper()
	asymOnce.Do(func() {
		must := func(err error) {
			if err != nil {
				panic(err)
			}
		}
		var err error
		_, asym.ed, err = ed25519.GenerateKey(rand.Reader)
		must(err)
		_, asym.ed2, err = ed25519.GenerateKey(rand.Reader)
		must(err)
		asym.ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		asym.ec2, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		asym.p384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		must(err)
		asym.rsa, err = rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		asym.rsa2, err = rsa.GenerateKey(rand.Reader, 2048)
		must(err)
	})
	return &asym
}

// signAsym signs header.claims with priv as alg says, the way an issuer
// would; alg is taken as given, so the tests can lie in the header.
func signAsym(t testing.TB, priv crypto.Signer, alg, header, claims string) string {
	t.Helper()
	input := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(claims))
	return input + "." + b64.EncodeToString(rawSign(t, priv, alg, []byte(input)))
}

func rawSign(t testing.TB, priv crypto.Signer, alg string, input []byte) []byte {
	t.Helper()
	var sig []byte
	var err error
	switch k := priv.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, input)
	case *ecdsa.PrivateKey:
		var d []byte
		if k.Curve == elliptic.P384() {
			s := sha512.Sum384(input)
			d = s[:]
		} else {
			s := sha256.Sum256(input)
			d = s[:]
		}
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, k, d)
		size := (k.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*size)
		r.FillBytes(sig[:size])
		s.FillBytes(sig[size:])
	case *rsa.PrivateKey:
		d := sha256.Sum256(input)
		if strings.HasPrefix(alg, "PS") {
			sig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func hdr(alg, kid string) string {
	if kid == "" {
		return `{"alg":"` + alg + `","typ":"JWT"}`
	}
	return `{"alg":"` + alg + `","typ":"JWT","kid":"` + kid + `"}`
}

func pub(id string, k crypto.Signer) jose.Key { return jose.Key{ID: id, Public: k.Public()} }

// newAsymAuth accepts the shared secrets of newAuth and one public key of
// each type: "ed1", "ec1" and "rsa1".
func newAsymAuth(t testing.TB, now *time.Time, algs ...string) *Authenticator {
	t.Helper()
	k := testKeys(t)
	ks, err := NewKeySet(pub("ed1", k.ed), pub("ec1", k.ec), pub("rsa1", k.rsa))
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{
		Agents:     []Agent{{ID: "alice-bot", Owner: "alice", TokenSHA256: HashToken(aliceKey)}},
		Keys:       map[string][]byte{"k1": keyA},
		ActiveKey:  "k1",
		PublicKeys: ks,
		Algorithms: algs,
		Issuer:     "toolgate",
		Audience:   "toolgate-gw",
		MaxTTL:     time.Hour,
		Now:        func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAsymmetricRoundTrip(t *testing.T) {
	now := t0
	a := newAsymAuth(t, &now)
	k := testKeys(t)
	for _, tc := range []struct {
		alg, kid string
		priv     crypto.Signer
	}{{EdDSA, "ed1", k.ed}, {ES256, "ec1", k.ec}, {RS256, "rsa1", k.rsa}} {
		tok := signAsym(t, tc.priv, tc.alg, hdr(tc.alg, tc.kid), claims(t0, 600))
		id, err := a.Authenticate(tok)
		if err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
		if id.AgentID != "ci-agent" || id.Method != "signed" || id.KeyID != tc.kid || !id.ExpiresAt.Equal(t0.Add(10*time.Minute)) {
			t.Fatalf("%s: got %+v", tc.alg, id)
		}
		// RFC 9068 typ, and header members a strict HS256 check would refuse:
		// keys never come from the token, so jku and jwk are ignored.
		for _, h := range []string{
			`{"alg":"` + tc.alg + `","typ":"at+jwt","kid":"` + tc.kid + `"}`,
			`{"alg":"` + tc.alg + `","kid":"` + tc.kid + `"}`,
			`{"alg":"` + tc.alg + `","kid":"` + tc.kid + `","x5t":"abc","jku":"https://evil.example/jwks"}`,
		} {
			if _, err := a.Authenticate(signAsym(t, tc.priv, tc.alg, h, claims(t0, 600))); err != nil {
				t.Errorf("%s %s: %v", tc.alg, h, err)
			}
		}
		// The claim checks of HS256 tokens apply unchanged.
		now = t0.Add(10*time.Minute + DefaultLeeway)
		if _, err := a.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: expired token accepted", tc.alg)
		}
		now = t0
		wrongAud := strings.Replace(claims(t0, 600), "toolgate-gw", "other", 1)
		if _, err := a.Authenticate(signAsym(t, tc.priv, tc.alg, hdr(tc.alg, tc.kid), wrongAud)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: wrong audience accepted", tc.alg)
		}
	}
	// HS256 tokens and static keys keep working beside the public keys.
	if _, err := a.Authenticate(sign(t, keyA, `{"alg":"HS256","typ":"JWT","kid":"k1"}`, claims(t0, 600))); err != nil {
		t.Fatalf("HS256 beside public keys: %v", err)
	}
	if id, err := a.Authenticate(aliceKey); err != nil || id.Method != "static" {
		t.Fatalf("static beside public keys: %+v %v", id, err)
	}
}

// TestAsymmetricConfusion signs tokens that name one algorithm and key and
// are signed with another: none may verify.
func TestAsymmetricConfusion(t *testing.T) {
	now := t0
	a := newAsymAuth(t, &now)
	k := testKeys(t)
	c := claims(t0, 600)
	rsaDER, err := x509.MarshalPKIXPublicKey(k.rsa.Public())
	if err != nil {
		t.Fatal(err)
	}
	ecDER, _ := x509.MarshalPKIXPublicKey(k.ec.Public())
	edRaw := []byte(k.ed.Public().(ed25519.PublicKey)) // 32 bytes: long enough for an HMAC secret
	cases := map[string]string{
		// A public key used as an HMAC secret, under the public key's kid
		// and under the shared secret's.
		"HS256 with Ed25519 public key":       sign(t, edRaw, hdr("HS256", "ed1"), c),
		"HS256 with Ed25519 public key, k1":   sign(t, edRaw, hdr("HS256", "k1"), c),
		"HS256 with RSA public key DER":       sign(t, rsaDER, hdr("HS256", "rsa1"), c),
		"HS256 with RSA public key DER, k1":   sign(t, rsaDER, hdr("HS256", "k1"), c),
		"HS256 with EC public key DER":        sign(t, ecDER, hdr("HS256", "ec1"), c),
		"HS256 with RSA modulus":              sign(t, k.rsa.N.Bytes(), hdr("HS256", "rsa1"), c),
		"shared secret's kid on an RS256 tok": signAsym(t, k.rsa, RS256, hdr(RS256, "k1"), c),
		// An algorithm whose key type is not the named key's.
		"RS256 naming the EC key":       signAsym(t, k.rsa, RS256, hdr(RS256, "ec1"), c),
		"RS256 naming the Ed25519 key":  signAsym(t, k.rsa, RS256, hdr(RS256, "ed1"), c),
		"ES256 naming the RSA key":      signAsym(t, k.ec, ES256, hdr(ES256, "rsa1"), c),
		"ES256 naming the Ed25519 key":  signAsym(t, k.ec, ES256, hdr(ES256, "ed1"), c),
		"EdDSA naming the RSA key":      signAsym(t, k.ed, EdDSA, hdr(EdDSA, "rsa1"), c),
		"EdDSA naming the EC key":       signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ec1"), c),
		"Ed25519 signature under ES256": signAsym(t, k.ed, ES256, hdr(ES256, "ec1"), c),
		// Algorithms the key could verify but agent tokens don't accept.
		"PS256 with the RSA key":   signAsym(t, k.rsa, "PS256", hdr("PS256", "rsa1"), c),
		"RS384":                    signAsym(t, k.rsa, RS256, hdr("RS384", "rsa1"), c),
		"ES384 with a P-384 key":   signAsym(t, k.p384, "ES384", hdr("ES384", "ec1"), c),
		"alg none":                 hdr2tok(`{"alg":"none","kid":"ed1"}`, c, ""),
		"alg none, signature kept": hdr2tok(`{"alg":"none","kid":"ed1"}`, c, "AAAA"),
		"alg lower case":           signAsym(t, k.ec, ES256, hdr("es256", "ec1"), c),
		"alg Ed25519":              signAsym(t, k.ed, EdDSA, hdr("Ed25519", "ed1"), c),
		// The wrong curve: a P-384 signature under the P-256 key's kid.
		"P-384 signature as ES256": signAsym(t, k.p384, ES256, hdr(ES256, "ec1"), c),
		// The right type, an unconfigured key of it.
		"other Ed25519 key": signAsym(t, k.ed2, EdDSA, hdr(EdDSA, "ed1"), c),
		"other P-256 key":   signAsym(t, k.ec2, ES256, hdr(ES256, "ec1"), c),
		"other RSA key":     signAsym(t, k.rsa2, RS256, hdr(RS256, "rsa1"), c),
		// Keys from the token are never used.
		"embedded jwk":       signAsym(t, k.ec2, ES256, `{"alg":"ES256","kid":"ec1","jwk":`+jwkJSON(t, &k.ec2.PublicKey)+`}`, c),
		"unknown kid":        signAsym(t, k.ec, ES256, hdr(ES256, "ec9"), c),
		"no kid, three keys": signAsym(t, k.ec, ES256, hdr(ES256, ""), c),
		"critical header":    signAsym(t, k.ec, ES256, `{"alg":"ES256","kid":"ec1","crit":["exp"],"exp":1}`, c),
		"typ":                signAsym(t, k.ec, ES256, `{"alg":"ES256","kid":"ec1","typ":"JWS"}`, c),
	}
	for name, tok := range cases {
		if id, err := a.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: accepted as %+v (%v)", name, id, err)
		}
	}

	// A key source that hands out a key of the wrong curve or type is
	// still caught by the algorithm binding in jose.
	for name, tc := range map[string]struct {
		key    jose.Key
		signer crypto.Signer
	}{
		"P-384 key for ES256":   {jose.Key{ID: "ec1", Public: k.p384.Public()}, k.p384},
		"RSA key for ES256":     {jose.Key{ID: "ec1", Public: k.rsa.Public()}, k.ec},
		"key bound to RS256":    {jose.Key{ID: "ec1", Alg: RS256, Public: k.ec.Public()}, k.ec},
		"encryption key":        {jose.Key{ID: "ec1", Use: "enc", Public: k.ec.Public()}, k.ec},
		"Ed25519 key for ES256": {jose.Key{ID: "ec1", Public: k.ed.Public()}, k.ec},
	} {
		b, err := New(Config{PublicKeys: fixedSource{tc.key}, Issuer: "toolgate", Audience: "toolgate-gw",
			Now: func() time.Time { return t0 }})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.Authenticate(signAsym(t, tc.signer, ES256, hdr(ES256, "ec1"), c)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}

	// Algorithms narrows what verifies: with only ES256, an Ed25519 token
	// with a valid signature is refused.
	only := newAsymAuth(t, &now, ES256)
	if _, err := only.Authenticate(signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), c)); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("EdDSA accepted with Algorithms [ES256]: %v", err)
	}
	if _, err := only.Authenticate(signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), c)); err != nil {
		t.Errorf("ES256 refused with Algorithms [ES256]: %v", err)
	}

	// Without public keys, no asymmetric token verifies at all.
	hs := newAuth(t, &now)
	if _, err := hs.Authenticate(signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), c)); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("ES256 accepted without public keys: %v", err)
	}
	// And without shared secrets no HS256 token does, whatever its secret.
	pk, err := New(Config{PublicKeys: fixedSource{pub("ed1", k.ed)}, Issuer: "toolgate", Audience: "toolgate-gw",
		Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{edRaw, keyA} {
		if _, err := pk.Authenticate(sign(t, secret, hdr("HS256", "ed1"), c)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("HS256 accepted with public keys only: %v", err)
		}
	}
	if _, err := pk.Mint("ci-agent", "", nil, time.Minute); err == nil {
		t.Error("Mint signed without a shared secret")
	}
}

// fixedSource returns its key for every kid, unchecked, to test what
// Verify does with a key a source should not have handed out.
type fixedSource struct{ k jose.Key }

func (s fixedSource) Lookup(string, string) (jose.Key, bool) { return s.k, true }

func hdr2tok(header, claims, sig string) string {
	return b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(claims)) + "." + sig
}

func jwkJSON(t testing.TB, k *ecdsa.PublicKey) string {
	t.Helper()
	j := jose.PublicJWK(k, "ec1")
	return `{"kty":"EC","crv":"P-256","x":"` + j["x"] + `","y":"` + j["y"] + `"}`
}

// TestAsymmetricMalformedSignatures keeps header and claims and breaks the
// signature in the ways a forger or a broken issuer would.
func TestAsymmetricMalformedSignatures(t *testing.T) {
	now := t0
	a := newAsymAuth(t, &now)
	k := testKeys(t)
	c := claims(t0, 600)
	n256 := elliptic.P256().Params().N
	for _, tc := range []struct {
		alg, kid string
		priv     crypto.Signer
	}{{EdDSA, "ed1", k.ed}, {ES256, "ec1", k.ec}, {RS256, "rsa1", k.rsa}} {
		good := signAsym(t, tc.priv, tc.alg, hdr(tc.alg, tc.kid), c)
		if _, err := a.Authenticate(good); err != nil {
			t.Fatalf("%s control: %v", tc.alg, err)
		}
		parts := strings.Split(good, ".")
		sig, _ := b64.DecodeString(parts[2])
		input := parts[0] + "." + parts[1]
		with := func(s []byte) string { return input + "." + b64.EncodeToString(s) }
		flip := func(i int) []byte { s := append([]byte(nil), sig...); s[i] ^= 1; return s }
		bad := map[string]string{
			"empty":                        input + ".",
			"one byte short":               with(sig[:len(sig)-1]),
			"one byte long":                with(append(append([]byte(nil), sig...), 0)),
			"leading zero":                 with(append([]byte{0}, sig...)),
			"doubled":                      with(append(append([]byte(nil), sig...), sig...)),
			"first bit flipped":            with(flip(0)),
			"last bit flipped":             with(flip(len(sig) - 1)),
			"middle flipped":               with(flip(len(sig) / 2)),
			"all zeros":                    with(make([]byte, len(sig))),
			"all ones":                     with([]byte(strings.Repeat("\xff", len(sig)))),
			"padded":                       good + "=",
			"standard base64":              input + "." + strings.NewReplacer("-", "+", "_", "/").Replace(parts[2]) + "+/",
			"line break":                   input + "." + parts[2][:10] + "\n" + parts[2][10:],
			"other claims":                 parts[0] + "." + b64.EncodeToString([]byte(strings.Replace(c, "ci-agent", "root-agent", 1))) + "." + parts[2],
			"other header":                 b64.EncodeToString([]byte(`{"alg":"`+tc.alg+`","kid":"`+tc.kid+`"}`)) + "." + parts[1] + "." + parts[2],
			"four parts":                   good + "." + parts[2],
			"signature of the header only": with(rawSign(t, tc.priv, tc.alg, []byte(parts[0]))),
		}
		if tc.alg == ES256 {
			r, s := sig[:32], sig[32:]
			der, _ := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)})
			nb := n256.FillBytes(make([]byte, 32))
			// s' = n - s verifies the same digest: Go accepts it, and so does
			// the gateway, since the claims are the issuer's either way. The
			// out-of-range and zero values below must not.
			bad["ASN.1 DER"] = with(der)
			bad["r = 0"] = with(append(make([]byte, 32), s...))
			bad["s = 0"] = with(append(append([]byte(nil), r...), make([]byte, 32)...))
			bad["r = n"] = with(append(append([]byte(nil), nb...), s...))
			bad["s = n"] = with(append(append([]byte(nil), r...), nb...))
			bad["r + n"] = with(append(addN(t, r, n256), s...))
			bad["r and s swapped"] = with(append(append([]byte(nil), s...), r...))
			bad["P-384 width"] = with(append(append(make([]byte, 16), r...), append(make([]byte, 16), s...)...))
		}
		if tc.alg == RS256 {
			nb := k.rsa.N.Bytes()
			bad["the modulus"] = with(nb)
			bad["PSS signature"] = with(rawSign(t, k.rsa, "PS256", []byte(input)))
			// A signature value of 1: 1^e mod n = 1, never a valid encoding.
			one := make([]byte, len(nb))
			one[len(one)-1] = 1
			bad["one"] = with(one)
		}
		if tc.alg == EdDSA {
			// Ed25519 refuses S >= L (RFC 8032 section 5.1.7), which keeps
			// its signatures from being malleable.
			l := new(big.Int).SetBit(new(big.Int), 252, 1)
			l.Add(l, new(big.Int).SetBytes([]byte{0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed}))
			s := new(big.Int).SetBytes(reverse(sig[32:]))
			s.Add(s, l)
			sb := reverse(s.FillBytes(make([]byte, 32)))
			bad["S + L"] = with(append(append([]byte(nil), sig[:32]...), sb...))
		}
		for name, tok := range bad {
			if _, err := a.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("%s %s: accepted (%v)", tc.alg, name, err)
			}
		}
	}
}

func addN(t testing.TB, b []byte, n *big.Int) []byte {
	t.Helper()
	v := new(big.Int).Add(new(big.Int).SetBytes(b), n)
	return v.FillBytes(make([]byte, (v.BitLen()+7)/8))
}

func reverse(b []byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return r
}

func TestAsymmetricKeyID(t *testing.T) {
	k := testKeys(t)
	c := claims(t0, 600)
	// A set of one key without a kid verifies tokens with or without one.
	one, err := NewKeySet(pub("", k.ec))
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{PublicKeys: one, Issuer: "toolgate", Audience: "toolgate-gw", Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	if id, err := a.Authenticate(signAsym(t, k.ec, ES256, hdr(ES256, ""), c)); err != nil || id.KeyID != "" {
		t.Fatalf("no kid: %+v %v", id, err)
	}
	if _, err := a.Authenticate(signAsym(t, k.ec, ES256, hdr(ES256, "anything"), c)); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("a kid matched a key that has none: %v", err)
	}
	// A set of one key with a kid verifies tokens naming it, or no kid.
	named, _ := NewKeySet(pub("ec1", k.ec))
	if key, ok := named.Lookup("", ES256); !ok || key.ID != "ec1" {
		t.Errorf("no kid, one named key: %+v %v", key, ok)
	}
	if _, ok := named.Lookup("ec2", ES256); ok {
		t.Error("unknown kid found")
	}
	if _, ok := named.Lookup("ec1", EdDSA); ok {
		t.Error("an EC key was handed out for EdDSA")
	}
	bound, _ := NewKeySet(jose.Key{ID: "r", Alg: RS256, Public: k.rsa.Public()})
	if _, ok := bound.Lookup("r", "PS256"); ok {
		t.Error("a key bound to RS256 was handed out for PS256")
	}
}

func TestAsymmetricConfigErrors(t *testing.T) {
	k := testKeys(t)
	ks, _ := NewKeySet(pub("ec1", k.ec))
	for name, cfg := range map[string]Config{
		"HS256 in algorithms":   {PublicKeys: ks, Algorithms: []string{"HS256"}, Issuer: "i", Audience: "a"},
		"PS256 in algorithms":   {PublicKeys: ks, Algorithms: []string{"PS256"}, Issuer: "i", Audience: "a"},
		"none in algorithms":    {PublicKeys: ks, Algorithms: []string{"none"}, Issuer: "i", Audience: "a"},
		"duplicate algorithm":   {PublicKeys: ks, Algorithms: []string{ES256, ES256}, Issuer: "i", Audience: "a"},
		"algorithms, no keys":   {Algorithms: []string{ES256}, Keys: map[string][]byte{"k1": keyA}, ActiveKey: "k1", Issuer: "i", Audience: "a"},
		"public keys, no iss":   {PublicKeys: ks, Audience: "a"},
		"public keys, no aud":   {PublicKeys: ks, Issuer: "i"},
		"lower case algorithm":  {PublicKeys: ks, Algorithms: []string{"eddsa"}, Issuer: "i", Audience: "a"},
		"empty-string algorith": {PublicKeys: ks, Algorithms: []string{""}, Issuer: "i", Audience: "a"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	small := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 1023, 1), E: 65537}
	huge := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), jose.MaxRSABits, 1), E: 65537}
	many := make([]jose.Key, MaxPublicKeys+1)
	for i := range many {
		many[i] = jose.Key{ID: fmt.Sprintf("k%d", i), Public: k.ec.Public()}
	}
	for name, keys := range map[string][]jose.Key{
		"no keys":            nil,
		"too many":           many,
		"duplicate kid":      {pub("a", k.ec), pub("a", k.ed)},
		"missing kid of two": {pub("", k.ec), pub("b", k.ed)},
		"P-384":              {pub("a", k.p384)},
		"RSA 1024":           {{ID: "a", Public: small}},
		"RSA too large":      {{ID: "a", Public: huge}},
		"nil RSA":            {{ID: "a", Public: (*rsa.PublicKey)(nil)}},
		"nil EC":             {{ID: "a", Public: (*ecdsa.PublicKey)(nil)}},
		"short Ed25519":      {{ID: "a", Public: ed25519.PublicKey(make([]byte, 31))}},
		"private key":        {{ID: "a", Public: k.ec}},
		"symmetric":          {{ID: "a", Public: keyA}},
		"no key":             {{ID: "a"}},
		"alg mismatch":       {{ID: "a", Alg: RS256, Public: k.ec.Public()}},
		"alg PS256":          {{ID: "a", Alg: "PS256", Public: k.rsa.Public()}},
		"alg HS256":          {{ID: "a", Alg: "HS256", Public: k.ec.Public()}},
		"use enc":            {{ID: "a", Use: "enc", Public: k.ec.Public()}},
		"kid too long":       {{ID: strings.Repeat("k", MaxPublicKeyID+1), Public: k.ec.Public()}},
		"one bad of several": {pub("a", k.ec), pub("b", k.p384)},
	} {
		if _, err := NewKeySet(keys...); err == nil {
			t.Errorf("NewKeySet %s: accepted", name)
		}
	}
	if _, err := NewKeySet(jose.Key{ID: strings.Repeat("k", MaxPublicKeyID), Alg: EdDSA, Use: "sig", Public: k.ed.Public()}); err != nil {
		t.Errorf("longest kid, alg and use: %v", err)
	}
}

// TestAsymmetricJWKS verifies with keys parsed from a JWK Set by the
// platform JOSE library, as the JWKS client will hand them over.
func TestAsymmetricJWKS(t *testing.T) {
	k := testKeys(t)
	j := jose.PublicJWK(&k.ec.PublicKey, "ec1")
	ed := k.ed.Public().(ed25519.PublicKey)
	doc := `{"keys":[` +
		`{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":"ec1","x":"` + j["x"] + `","y":"` + j["y"] + `"},` +
		`{"kty":"OKP","crv":"Ed25519","kid":"ed1","x":"` + b64.EncodeToString(ed) + `"},` +
		`{"kty":"RSA","kid":"rsa1","alg":"RS256","n":"` + b64.EncodeToString(k.rsa.N.Bytes()) + `","e":"AQAB"}]}`
	set, err := jose.ParseKeySet([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	ks, err := NewKeySet(set.Keys...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{PublicKeys: ks, Issuer: "toolgate", Audience: "toolgate-gw", Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	c := claims(t0, 600)
	for _, tok := range []string{
		signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), c),
		signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), c),
		signAsym(t, k.rsa, RS256, hdr(RS256, "rsa1"), c),
	} {
		if _, err := a.Authenticate(tok); err != nil {
			t.Error(err)
		}
	}
	// The shared HS256 secret path is not reachable through a JWKS: an
	// "oct" key is skipped by the parser and never becomes a secret.
	oct, err := jose.ParseKeySet([]byte(`{"keys":[{"kty":"oct","kid":"s","k":"` + b64.EncodeToString(keyA) + `"}]}`))
	if err != nil || len(oct.Keys) != 0 {
		t.Fatalf("oct key: %+v %v", oct, err)
	}
}
