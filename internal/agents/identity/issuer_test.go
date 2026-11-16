package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/policy"
	"github.com/laiwf94/authz/internal/platform/clock"
	"github.com/laiwf94/authz/internal/platform/jose"
)

const (
	idpIss   = "https://idp.example"
	idpAud   = "https://gw.example/mcp"
	otherIss = "https://other.example"
	otherAud = "gw"
)

// issuerKeys: the idp holds "ed1" (EdDSA) and "shared" (an ES256 key it
// may not use, since it accepts EdDSA only); the other issuer holds
// "ec1" and its own "shared", a different key under the same kid.
type issuerKeys struct {
	idp, other *KeySet
}

func newIssuerKeys(t testing.TB) issuerKeys {
	t.Helper()
	k := testKeys(t)
	idp, err := NewKeySet(pub("ed1", k.ed), pub("shared", k.ec2))
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewKeySet(pub("ec1", k.ec), pub("shared", k.ed2))
	if err != nil {
		t.Fatal(err)
	}
	return issuerKeys{idp, other}
}

// newIssuerAuth accepts HS256 tokens of "toolgate", the fixed key set of
// newAsymAuth as Config.PublicKeys, and two issuers: the idp, which puts
// the agent in client_id, its owner in a namespaced claim and its scopes
// in an scp array, signs with EdDSA only and allows two hours; and the
// other issuer, with the default claims and Config's one hour.
func newIssuerAuth(t testing.TB, now *time.Time) *Authenticator {
	t.Helper()
	k := testKeys(t)
	ik := newIssuerKeys(t)
	fixed, err := NewKeySet(pub("rsa1", k.rsa))
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{
		Keys:       map[string][]byte{"k1": keyA},
		ActiveKey:  "k1",
		PublicKeys: fixed,
		Issuer:     "toolgate",
		Audience:   "toolgate-gw",
		MaxTTL:     time.Hour,
		Issuers: []Issuer{
			{Issuer: idpIss, Audience: idpAud, Keys: ik.idp, Algorithms: []string{EdDSA},
				Claims: ClaimMap{Subject: "client_id", Owner: "https://idp.example/owner", Scopes: "scp"},
				MaxTTL: 2 * time.Hour},
			{Issuer: otherIss, Audience: otherAud, Keys: ik.other},
		},
		Now: func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// idpClaims is a claims set of the idp, as a map so cases can change it.
func idpClaims() map[string]any {
	n := t0.Unix()
	return map[string]any{
		"iss": idpIss, "aud": []string{"https://api.example", idpAud}, "sub": "user|8f2c",
		"client_id": "ci-agent", "https://idp.example/owner": "carol", "scp": []string{"deploy", "read"},
		"iat": n, "nbf": n, "exp": n + 600, "jti": "x1", "azp": "ci-agent", "act": map[string]any{"sub": "y"},
	}
}

func otherClaims() map[string]any {
	n := t0.Unix()
	return map[string]any{"iss": otherIss, "aud": otherAud, "sub": "build-agent", "owner": "dave",
		"scope": "read  write", "iat": n, "exp": n + 300}
}

func encode(t testing.TB, c map[string]any) string {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func with(c map[string]any, kv ...any) map[string]any {
	c = maps.Clone(c)
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(c, kv[i].(string))
		} else {
			c[kv[i].(string)] = kv[i+1]
		}
	}
	return c
}

func TestIssuersClaimMapping(t *testing.T) {
	now := t0
	a := newIssuerAuth(t, &now)
	k := testKeys(t)

	id, err := a.Authenticate(signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), encode(t, idpClaims())))
	if err != nil {
		t.Fatal(err)
	}
	want := Identity{AgentID: "ci-agent", Owner: "carol", Scopes: []string{"deploy", "read"}, Method: "signed",
		Issuer: idpIss, KeyID: "ed1", ExpiresAt: t0.Add(10 * time.Minute)}
	if !identityEqual(id, want) {
		t.Fatalf("idp: got %+v, want %+v", id, want)
	}

	id, err = a.Authenticate(signAsym(t, k.ec, ES256, `{"alg":"ES256","typ":"at+jwt","kid":"ec1"}`, encode(t, otherClaims())))
	if err != nil {
		t.Fatal(err)
	}
	want = Identity{AgentID: "build-agent", Owner: "dave", Scopes: []string{"read", "write"}, Method: "signed",
		Issuer: otherIss, KeyID: "ec1", ExpiresAt: t0.Add(5 * time.Minute)}
	if !identityEqual(id, want) {
		t.Fatalf("other: got %+v, want %+v", id, want)
	}

	// Config.PublicKeys is an issuer too: the HS256 issuer's name and
	// claims, its own keys.
	id, err = a.Authenticate(signAsym(t, k.rsa, RS256, hdr(RS256, "rsa1"), claims(t0, 600)))
	if err != nil || id.Issuer != "toolgate" || id.KeyID != "rsa1" {
		t.Fatalf("public keys issuer: %+v %v", id, err)
	}
	id, err = a.Authenticate(sign(t, keyA, `{"alg":"HS256","typ":"JWT","kid":"k1"}`, claims(t0, 600)))
	if err != nil || id.Issuer != "toolgate" || id.KeyID != "k1" {
		t.Fatalf("HS256: %+v %v", id, err)
	}

	// Optional claims: no owner, no scopes, null for either, no nbf, an
	// aud string, fractional dates rounded inwards.
	for name, c := range map[string]map[string]any{
		"no owner or scopes": with(idpClaims(), "https://idp.example/owner", nil, "scp", nil),
		"null owner, scopes": with(idpClaims(), "https://idp.example/owner", json.RawMessage("null"), "scp", json.RawMessage("null")),
		"no nbf":             with(idpClaims(), "nbf", nil),
		"aud string":         with(idpClaims(), "aud", idpAud),
		"scp string":         with(idpClaims(), "scp", "deploy read"),
		"empty scp":          with(idpClaims(), "scp", []string{}),
		"fractional":         with(idpClaims(), "iat", json.RawMessage(fmt.Sprint(t0.Unix()-1)+".25"), "exp", json.RawMessage(fmt.Sprint(t0.Unix()+600)+".9")),
		"exponent date":      with(idpClaims(), "exp", json.RawMessage("1.0006e6")),
		"owner of 128 bytes": with(idpClaims(), "https://idp.example/owner", strings.Repeat("o", MaxOwnerBytes)),
		"16 audiences":       with(idpClaims(), "aud", append(slices.Repeat([]string{"x"}, MaxAudiences-1), idpAud)),
		"64 scopes":          with(idpClaims(), "scp", slices.Repeat([]string{"s"}, MaxScopes)),
	} {
		id, err := a.Authenticate(signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), encode(t, c)))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if name == "fractional" && !id.ExpiresAt.Equal(t0.Add(10*time.Minute)) {
			t.Errorf("fractional exp: %v", id.ExpiresAt)
		}
		if name == "exponent date" && !id.ExpiresAt.Equal(t0.Add(10*time.Minute)) {
			t.Errorf("exponent exp: %v", id.ExpiresAt)
		}
	}
}

func identityEqual(a, b Identity) bool {
	return a.AgentID == b.AgentID && a.Owner == b.Owner && slices.Equal(a.Scopes, b.Scopes) &&
		a.Method == b.Method && a.Issuer == b.Issuer && a.KeyID == b.KeyID && a.ExpiresAt.Equal(b.ExpiresAt)
}

// TestIssuersIsolation: a token's iss picks one issuer, and only that
// issuer's keys, algorithms, audience and lifetime apply.
func TestIssuersIsolation(t *testing.T) {
	now := t0
	a := newIssuerAuth(t, &now)
	k := testKeys(t)
	idp, other := encode(t, idpClaims()), encode(t, otherClaims())
	for name, tok := range map[string]string{
		// The other issuer's key, under its kid, for the idp's iss.
		"other's key for idp": signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), idp),
		// The idp's key, under its kid, for the other's iss.
		"idp's key for other": signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), other),
		// One kid at both issuers: each issuer's own "shared" key only.
		"shared kid, other's key, idp iss": signAsym(t, k.ed2, EdDSA, hdr(EdDSA, "shared"), idp),
		"shared kid, idp's key, other iss": signAsym(t, k.ec2, ES256, hdr(ES256, "shared"), other),
		// The idp holds an ES256 key but accepts EdDSA only.
		"algorithm the idp refuses": signAsym(t, k.ec2, ES256, hdr(ES256, "shared"), idp),
		// The fixed key set belongs to "toolgate", not the idp.
		"toolgate's key for idp": signAsym(t, k.rsa, RS256, hdr(RS256, "rsa1"), idp),
		// HS256 belongs to the shared secrets, whatever iss says.
		"HS256 with idp iss": sign(t, keyA, `{"alg":"HS256","typ":"JWT","kid":"k1"}`, idp),
		// The idp's audience at the other issuer, and the reverse.
		"idp aud at other": signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), encode(t, with(otherClaims(), "aud", idpAud))),
		"other aud at idp": signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), encode(t, with(idpClaims(), "aud", otherAud))),
		// 90 minutes: within the idp's two hours, past the other's hour.
		"90m at other": signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), encode(t, with(otherClaims(), "exp", t0.Unix()+5400))),
		// The other issuer's claim mapping is the default one: client_id
		// means nothing there, and sub means nothing at the idp.
		"client_id at other": signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), encode(t, with(otherClaims(), "sub", nil, "client_id", "build-agent"))),
		"sub at idp":         signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), encode(t, with(idpClaims(), "client_id", nil, "sub", "ci-agent"))),
	} {
		if id, err := a.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: accepted %+v", name, id)
		}
	}
	if _, err := a.Authenticate(signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), encode(t, with(idpClaims(), "exp", t0.Unix()+5400)))); err != nil {
		t.Errorf("90m at the idp: %v", err)
	}
	if _, err := a.Authenticate(signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), encode(t, with(idpClaims(), "exp", t0.Unix()+7201)))); !errors.Is(err, ErrUnauthenticated) {
		t.Error("over two hours at the idp: accepted")
	}
}

// TestIssuersClaimErrors signs every claims set validly with the idp's
// key: only the claims can refuse it.
func TestIssuersClaimErrors(t *testing.T) {
	now := t0
	a := newIssuerAuth(t, &now)
	k := testKeys(t)
	n := t0.Unix()
	lw := int64(DefaultLeeway / time.Second)
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }
	cases := map[string]string{
		"not an object":       `["iss"]`,
		"null":                `null`,
		"string":              `"x"`,
		"trailing data":       encode(t, idpClaims()) + `{}`,
		"duplicate member":    strings.Replace(encode(t, idpClaims()), `"client_id":"ci-agent"`, `"client_id":"x","client_id":"ci-agent"`, 1),
		"nested duplicate":    strings.Replace(encode(t, idpClaims()), `"act":{"sub":"y"}`, `"act":{"sub":"y","sub":"z"}`, 1),
		"deeply nested":       strings.Replace(encode(t, idpClaims()), `"act":{"sub":"y"}`, `"act":`+strings.Repeat("[", 200)+strings.Repeat("]", 200), 1),
		"truncated":           strings.TrimSuffix(encode(t, idpClaims()), "}"),
		"empty":               ``,
		"not JSON":            `iss=x`,
		"duplicate iss":       strings.Replace(encode(t, idpClaims()), `"iss":"`+idpIss+`"`, `"iss":"`+otherIss+`","iss":"`+idpIss+`"`, 1),
		"no iss":              encode(t, with(idpClaims(), "iss", nil)),
		"iss number":          encode(t, with(idpClaims(), "iss", 1)),
		"iss array":           encode(t, with(idpClaims(), "iss", []string{idpIss})),
		"unknown iss":         encode(t, with(idpClaims(), "iss", "https://evil.example")),
		"iss trailing slash":  encode(t, with(idpClaims(), "iss", idpIss+"/")),
		"no aud":              encode(t, with(idpClaims(), "aud", nil)),
		"wrong aud":           encode(t, with(idpClaims(), "aud", "https://api.example")),
		"aud array without":   encode(t, with(idpClaims(), "aud", []string{"a", "b"})),
		"aud empty array":     encode(t, with(idpClaims(), "aud", []string{})),
		"aud too many":        encode(t, with(idpClaims(), "aud", append(slices.Repeat([]string{"x"}, MaxAudiences), idpAud))),
		"aud number":          encode(t, with(idpClaims(), "aud", 7)),
		"aud null":            encode(t, with(idpClaims(), "aud", raw("null"))),
		"aud array of nums":   encode(t, with(idpClaims(), "aud", []int{1})),
		"aud object":          encode(t, with(idpClaims(), "aud", map[string]string{"a": idpAud})),
		"no subject":          encode(t, with(idpClaims(), "client_id", nil)),
		"subject number":      encode(t, with(idpClaims(), "client_id", 5)),
		"subject null":        encode(t, with(idpClaims(), "client_id", raw("null"))),
		"subject invalid":     encode(t, with(idpClaims(), "client_id", "user|8f2c")),
		"subject empty":       encode(t, with(idpClaims(), "client_id", "")),
		"owner number":        encode(t, with(idpClaims(), "https://idp.example/owner", 1)),
		"owner array":         encode(t, with(idpClaims(), "https://idp.example/owner", []string{"carol"})),
		"owner too long":      encode(t, with(idpClaims(), "https://idp.example/owner", strings.Repeat("o", MaxOwnerBytes+1))),
		"scopes number":       encode(t, with(idpClaims(), "scp", 3)),
		"scopes object":       encode(t, with(idpClaims(), "scp", map[string]string{})),
		"scope number in arr": encode(t, with(idpClaims(), "scp", []any{"read", 1})),
		"scope null in arr":   encode(t, with(idpClaims(), "scp", []any{"read", nil})),
		"scope with space":    encode(t, with(idpClaims(), "scp", []string{"read write"})),
		"scope invalid":       encode(t, with(idpClaims(), "scp", "read\x00")),
		"too many scopes":     encode(t, with(idpClaims(), "scp", slices.Repeat([]string{"s"}, MaxScopes+1))),
		"too many in string":  encode(t, with(idpClaims(), "scp", strings.Repeat("s ", MaxScopes+1))),
		"no exp":              encode(t, with(idpClaims(), "exp", nil)),
		"no iat":              encode(t, with(idpClaims(), "iat", nil)),
		"exp string":          encode(t, with(idpClaims(), "exp", fmt.Sprint(n+600))),
		"exp null":            encode(t, with(idpClaims(), "exp", raw("null"))),
		"exp bool":            encode(t, with(idpClaims(), "exp", true)),
		"exp zero":            encode(t, with(idpClaims(), "exp", 0)),
		"exp negative":        encode(t, with(idpClaims(), "exp", -1)),
		"exp huge":            encode(t, with(idpClaims(), "exp", raw("1e300"))),
		"exp past int64":      encode(t, with(idpClaims(), "exp", raw("9223372036854775808"))),
		"iat huge":            encode(t, with(idpClaims(), "iat", raw("1e12"))),
		"nbf string":          encode(t, with(idpClaims(), "nbf", "0")),
		"nbf null":            encode(t, with(idpClaims(), "nbf", raw("null"))),
		"expired":             encode(t, with(idpClaims(), "iat", n-600-lw, "nbf", n-600-lw, "exp", n-lw)),
		"expired, fraction":   encode(t, with(idpClaims(), "iat", n-600, "nbf", n-600, "exp", raw(fmt.Sprint(n-lw)+".99"))),
		"not yet valid":       encode(t, with(idpClaims(), "nbf", n+lw+1)),
		"nbf fraction ahead":  encode(t, with(idpClaims(), "nbf", raw(fmt.Sprint(n+lw)+".01"))),
		"issued in future":    encode(t, with(idpClaims(), "iat", n+lw+1, "nbf", nil, "exp", n+lw+60)),
		"exp before iat":      encode(t, with(idpClaims(), "exp", n-1, "iat", n)),
		"exp equals iat":      encode(t, with(idpClaims(), "exp", n+10, "iat", n+10, "nbf", nil)),
		"lifetime too long":   encode(t, with(idpClaims(), "exp", n+7201)),
	}
	for name, c := range cases {
		if id, err := a.Authenticate(signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), c)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: accepted %+v", name, id)
		}
	}
	// The boundaries the refusals above sit on are accepted.
	for name, c := range map[string]map[string]any{
		"exp in leeway":   with(idpClaims(), "iat", n-600, "nbf", n-600, "exp", n-lw+1),
		"nbf in leeway":   with(idpClaims(), "nbf", n+lw),
		"iat in leeway":   with(idpClaims(), "iat", n+lw, "nbf", nil, "exp", n+lw+60),
		"exactly 2 hours": with(idpClaims(), "exp", n+7200),
	} {
		if _, err := a.Authenticate(signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), encode(t, c))); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestIssuersOnly: issuers need no shared secrets, fixed keys or
// Config.Issuer; a token for an issuer no one configured, and asymmetric
// tokens with no issuers at all, are refused.
func TestIssuersOnly(t *testing.T) {
	k := testKeys(t)
	ik := newIssuerKeys(t)
	a, err := New(Config{Issuers: []Issuer{{Issuer: otherIss, Audience: otherAud, Keys: ik.other}},
		Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), encode(t, otherClaims()))); err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{
		"idp token":     signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), encode(t, idpClaims())),
		"HS256 token":   sign(t, keyA, `{"alg":"HS256","typ":"JWT","kid":"k1"}`, claims(t0, 600)),
		"own-iss token": signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), claims(t0, 600)),
		"wrong typ":     signAsym(t, k.ec, ES256, `{"alg":"ES256","typ":"JOSE","kid":"ec1"}`, encode(t, otherClaims())),
		"no such kid":   signAsym(t, k.ec, ES256, hdr(ES256, "ec9"), encode(t, otherClaims())),
		"no kid of two": signAsym(t, k.ec, ES256, `{"alg":"ES256"}`, encode(t, otherClaims())),
		"bit flipped":   flipLast(signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), encode(t, otherClaims()))),
	} {
		if id, err := a.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: accepted %+v", name, id)
		}
	}
	none, err := New(Config{Agents: []Agent{{ID: "alice-bot", TokenSHA256: HashToken(aliceKey)}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := none.Authenticate(signAsym(t, k.ec, ES256, hdr(ES256, "ec1"), encode(t, otherClaims()))); !errors.Is(err, ErrUnauthenticated) {
		t.Error("asymmetric token accepted with no issuers")
	}
}

func flipLast(tok string) string {
	b := []byte(tok)
	i := len(b) - 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

func TestIssuersConfigErrors(t *testing.T) {
	ik := newIssuerKeys(t)
	good := Issuer{Issuer: idpIss, Audience: idpAud, Keys: ik.idp}
	mod := func(f func(*Issuer)) []Issuer { is := good; f(&is); return []Issuer{is} }
	many := make([]Issuer, MaxIssuers+1)
	for i := range many {
		many[i] = good
		many[i].Issuer = fmt.Sprintf("https://i%d.example", i)
	}
	for name, list := range map[string][]Issuer{
		"no issuer":            mod(func(is *Issuer) { is.Issuer = "" }),
		"no audience":          mod(func(is *Issuer) { is.Audience = "" }),
		"issuer too long":      mod(func(is *Issuer) { is.Issuer = strings.Repeat("i", MaxIssuerBytes+1) }),
		"audience too long":    mod(func(is *Issuer) { is.Audience = strings.Repeat("a", MaxIssuerBytes+1) }),
		"issuer not UTF-8":     mod(func(is *Issuer) { is.Issuer = "\xff" }),
		"no keys":              mod(func(is *Issuer) { is.Keys = nil }),
		"HS256":                mod(func(is *Issuer) { is.Algorithms = []string{"HS256"} }),
		"none":                 mod(func(is *Issuer) { is.Algorithms = []string{"none"} }),
		"duplicate algorithm":  mod(func(is *Issuer) { is.Algorithms = []string{EdDSA, EdDSA} }),
		"map subject to exp":   mod(func(is *Issuer) { is.Claims.Subject = "exp" }),
		"map owner to iss":     mod(func(is *Issuer) { is.Claims.Owner = "iss" }),
		"map scopes to aud":    mod(func(is *Issuer) { is.Claims.Scopes = "aud" }),
		"map subject to jti":   mod(func(is *Issuer) { is.Claims.Subject = "jti" }),
		"subject is owner":     mod(func(is *Issuer) { is.Claims.Subject = "owner" }),
		"owner is scopes":      mod(func(is *Issuer) { is.Claims.Owner = "scope" }),
		"subject is scopes":    mod(func(is *Issuer) { is.Claims.Scopes = "sub" }),
		"claim name too long":  mod(func(is *Issuer) { is.Claims.Owner = strings.Repeat("c", MaxClaimName+1) }),
		"claim name control":   mod(func(is *Issuer) { is.Claims.Owner = "own\ner" }),
		"claim name DEL":       mod(func(is *Issuer) { is.Claims.Owner = "own\x7f" }),
		"claim name not UTF-8": mod(func(is *Issuer) { is.Claims.Owner = "\xc3" }),
		"negative TTL":         mod(func(is *Issuer) { is.MaxTTL = -time.Second }),
		"TTL under a second":   mod(func(is *Issuer) { is.MaxTTL = time.Millisecond }),
		"TTL over a day":       mod(func(is *Issuer) { is.MaxTTL = MaxIssuerTTL + time.Second }),
		"duplicate issuer":     {good, good},
		"too many":             many,
	} {
		if _, err := New(Config{Issuers: list}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Config.PublicKeys is an issuer: configuring its name again is an error.
	k := testKeys(t)
	fixed, _ := NewKeySet(pub("rsa1", k.rsa))
	if _, err := New(Config{PublicKeys: fixed, Issuer: idpIss, Audience: "a", Issuers: []Issuer{good}}); err == nil {
		t.Error("PublicKeys issuer configured twice: accepted")
	}
	// The limits themselves are accepted, and the HS256 issuer may share a
	// name with an issuer of asymmetric tokens: the algorithm keeps them
	// apart.
	edge := good
	edge.Issuer = strings.Repeat("i", MaxIssuerBytes)
	edge.Claims = ClaimMap{Subject: strings.Repeat("c", MaxClaimName), Owner: "https://idp.example/owner", Scopes: "scp"}
	edge.MaxTTL = MaxIssuerTTL
	if _, err := New(Config{Issuers: append(many[:MaxIssuers-1], edge)}); err != nil {
		t.Errorf("limits: %v", err)
	}
	if _, err := New(Config{Keys: map[string][]byte{"k1": keyA}, ActiveKey: "k1", Issuer: idpIss, Audience: "a", Issuers: []Issuer{good}}); err != nil {
		t.Errorf("HS256 issuer named like an asymmetric one: %v", err)
	}
	// New copies the list: changing it afterwards changes nothing.
	list := []Issuer{good}
	a, err := New(Config{Issuers: list, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	list[0].Audience = "changed"
	if _, err := a.Authenticate(signAsym(t, k.ed, EdDSA, hdr(EdDSA, "ed1"), encode(t, with(idpClaims(), "sub", "ci-agent")))); err != nil {
		t.Errorf("after changing the caller's list: %v", err)
	}
}

func BenchmarkAuthenticateIssuer(b *testing.B) {
	now := t0
	a := newIssuerAuth(b, &now)
	k := testKeys(b)
	tok := signAsym(b, k.ed, EdDSA, hdr(EdDSA, "ed1"), encode(b, idpClaims()))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := a.Authenticate(tok); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzParseJWKS feeds JWK Set documents to the parser the JWKS client
// uses: whatever it accepts must be a usable set the key checks pass.
func FuzzParseJWKS(f *testing.F) {
	k := testKeys(f)
	j := jose.PublicJWK(&k.ec.PublicKey, "ec1")
	ed := k.ed.Public().(ed25519.PublicKey)
	ec := `{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":"ec1","x":"` + j["x"] + `","y":"` + j["y"] + `"}`
	okp := `{"kty":"OKP","crv":"Ed25519","kid":"ed1","x":"` + b64.EncodeToString(ed) + `"}`
	rsaKey := `{"kty":"RSA","kid":"rsa1","alg":"RS256","n":"` + b64.EncodeToString(k.rsa.N.Bytes()) + `","e":"AQAB"}`
	for _, doc := range []string{
		`{"keys":[` + ec + `,` + okp + `,` + rsaKey + `]}`,
		`{"keys":[` + ec + `]}`,
		`{"keys":[` + strings.Replace(okp, `"kid":"ed1",`, ``, 1) + `]}`,
		`{"keys":[` + ec + `,` + ec + `]}`,
		`{"keys":[{"kty":"oct","kid":"s","k":"AAAA"},` + okp + `]}`,
		`{"keys":[` + strings.Replace(ec, `"use":"sig"`, `"use":"enc"`, 1) + `]}`,
		`{"keys":[` + strings.Replace(ec, `"P-256"`, `"P-384"`, 1) + `]}`,
		`{"keys":[]}`, `{}`, `[]`, `null`, ``,
	} {
		f.Add([]byte(doc))
	}
	algs := append([]string{"HS256", "PS256", "none", ""}, AsymmetricAlgorithms...)
	f.Fuzz(func(t *testing.T, doc []byte) {
		set, kids, err := ParseJWKS(doc)
		if err != nil {
			if set != nil || kids != nil {
				t.Fatal("an error with a key set")
			}
			return
		}
		if len(kids) == 0 || len(kids) > MaxPublicKeys {
			t.Fatalf("%d keys accepted", len(kids))
		}
		seen := map[string]bool{}
		for _, kid := range kids {
			if seen[kid] {
				t.Fatalf("kid %q twice", kid)
			}
			seen[kid] = true
			if kid == "" && len(kids) > 1 {
				t.Fatal("a kid-less key in a set of several")
			}
			found := false
			for _, alg := range algs {
				key, ok := set.Lookup(kid, alg)
				if !ok {
					continue
				}
				found = true
				if !slices.Contains(AsymmetricAlgorithms, alg) || !key.Fits(alg) || key.ID != kid {
					t.Fatalf("kid %q handed out for %q: %+v", kid, alg, key)
				}
				if err := checkPublicKey(key); err != nil {
					t.Fatalf("kid %q: %v", kid, err)
				}
			}
			if !found {
				t.Fatalf("kid %q verifies nothing", kid)
			}
		}
	})
}

// fuzzIssuerAuth is newIssuerAuth with the claims checks as the fuzz
// targets see them: the idp and the other issuer.
func fuzzIssuerAuth(f *testing.F) (*Authenticator, *asymKeys) {
	now := t0
	return newIssuerAuth(f, &now), testKeys(f)
}

// FuzzAuthenticateIssuers feeds whole tokens to an authenticator with
// two issuers. Anything accepted must carry a signature that verifies,
// by the standard library alone, with the key its issuer holds under its
// kid, and claims that hold that issuer's audience.
func FuzzAuthenticateIssuers(f *testing.F) {
	a, k := fuzzIssuerAuth(f)
	f.Add(signAsym(f, k.ed, EdDSA, hdr(EdDSA, "ed1"), encode(f, idpClaims())))
	f.Add(signAsym(f, k.ec, ES256, hdr(ES256, "ec1"), encode(f, otherClaims())))
	f.Add(signAsym(f, k.ec2, ES256, hdr(ES256, "shared"), encode(f, idpClaims())))
	f.Add(signAsym(f, k.ed2, EdDSA, hdr(EdDSA, "shared"), encode(f, otherClaims())))
	f.Add(signAsym(f, k.ed, EdDSA, `{"alg":"EdDSA"}`, `{"iss":"https://idp.example"}`))
	f.Add(hdr2tok(hdr(EdDSA, "ed1"), encode(f, idpClaims()), ""))
	f.Add("eyJhbGciOiJFZERTQSJ9.e30.")
	keyOf := map[string]map[string]any{
		idpIss:   {"ed1": k.ed.Public(), "shared": k.ec2.Public()},
		otherIss: {"ec1": k.ec.Public(), "shared": k.ed2.Public()},
	}
	audOf := map[string]string{idpIss: idpAud, otherIss: otherAud}
	f.Fuzz(func(t *testing.T, token string) {
		id, err := a.Authenticate(token)
		if err != nil {
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if id.Method == "static" || id.Issuer == "toolgate" {
			return // the HS256 and fixed-key paths have fuzz targets of their own
		}
		parts := strings.Split(token, ".")
		input := []byte(parts[0] + "." + parts[1])
		sig, err := b64.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("accepted a signature that is not base64url: %q", token)
		}
		switch pk := keyOf[id.Issuer][id.KeyID].(type) {
		case ed25519.PublicKey:
			if !ed25519.Verify(pk, input, sig) {
				t.Fatalf("accepted a token without a valid Ed25519 signature: %q", token)
			}
		case *ecdsa.PublicKey:
			d := sha256.Sum256(input)
			if len(sig) != 64 || !ecdsa.Verify(pk, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				t.Fatalf("accepted a token without a valid ES256 signature: %q", token)
			}
		default:
			t.Fatalf("accepted with key %q of issuer %q: %q", id.KeyID, id.Issuer, token)
		}
		checkAccepted(t, id, parts[1], audOf[id.Issuer])
	})
}

// FuzzIssuerClaims signs fuzzed headers and claims sets with the idp's
// key, so the claims checks see input a forger can't produce but a
// broken or hostile issuer can. Whatever is accepted is checked against
// an independent reading of the claims.
func FuzzIssuerClaims(f *testing.F) {
	a, k := fuzzIssuerAuth(f)
	f.Add(hdr(EdDSA, "ed1"), encode(f, idpClaims()))
	f.Add(hdr(EdDSA, "ed1"), encode(f, with(idpClaims(), "aud", idpAud, "scp", "a b", "nbf", nil)))
	f.Add(hdr(EdDSA, "ed1"), encode(f, with(idpClaims(), "exp", json.RawMessage("1000600.5"))))
	f.Add(hdr(EdDSA, "ed1"), strings.Replace(encode(f, idpClaims()), `"client_id":"ci-agent"`, `"client_id":"x","client_id":"ci-agent"`, 1))
	f.Add(`{"alg":"EdDSA","typ":"at+jwt","kid":"ed1","crit":["x"]}`, encode(f, idpClaims()))
	f.Add(hdr(EdDSA, "ed1"), encode(f, with(otherClaims(), "iss", idpIss, "aud", idpAud)))
	f.Add(hdr(EdDSA, ""), `{}`)
	f.Fuzz(func(t *testing.T, header, claimsSet string) {
		tok := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(claimsSet))
		tok += "." + b64.EncodeToString(ed25519.Sign(k.ed, []byte(tok)))
		id, err := a.Authenticate(tok)
		if err != nil {
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if id.Issuer != idpIss || id.KeyID != "ed1" {
			t.Fatalf("the idp's key verified a token as %q/%q", id.Issuer, id.KeyID)
		}
		checkAccepted(t, id, b64.EncodeToString([]byte(claimsSet)), idpAud)
		var c map[string]any
		dec := json.NewDecoder(strings.NewReader(claimsSet))
		dec.UseNumber()
		if err := dec.Decode(&c); err != nil {
			t.Fatalf("accepted claims that do not decode: %v", err)
		}
		if c["client_id"] != id.AgentID {
			t.Fatalf("agent %q is not client_id %v", id.AgentID, c["client_id"])
		}
		if o, _ := c["https://idp.example/owner"].(string); o != id.Owner {
			t.Fatalf("owner %q is not %v", id.Owner, c["https://idp.example/owner"])
		}
	})
}

// checkAccepted checks an accepted identity against the claims part of
// its token, decoded independently.
func checkAccepted(t *testing.T, id Identity, claimsPart, aud string) {
	t.Helper()
	payload, err := b64.DecodeString(claimsPart)
	if err != nil {
		t.Fatalf("accepted claims that are not base64url")
	}
	var c map[string]any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("accepted claims that do not decode: %v", err)
	}
	if c["iss"] != id.Issuer {
		t.Fatalf("issuer %q is not iss %v", id.Issuer, c["iss"])
	}
	switch v := c["aud"].(type) {
	case string:
		if v != aud {
			t.Fatalf("accepted aud %q", v)
		}
	case []any:
		if !slices.Contains(v, any(aud)) || len(v) > MaxAudiences {
			t.Fatalf("accepted aud %v", v)
		}
	default:
		t.Fatalf("accepted aud %v", c["aud"])
	}
	if !policy.ValidAgentID(id.AgentID) || len(id.Owner) > MaxOwnerBytes || len(id.Scopes) > MaxScopes {
		t.Fatalf("accepted identity %+v", id)
	}
	for _, s := range id.Scopes {
		if !policy.ValidScope(s) {
			t.Fatalf("accepted scope %q", s)
		}
	}
	exp, err := c["exp"].(json.Number).Float64()
	if err != nil || int64(exp) != id.ExpiresAt.Unix() {
		t.Fatalf("exp %v gave %v", c["exp"], id.ExpiresAt)
	}
	if t0.Unix() >= id.ExpiresAt.Unix()+int64(DefaultLeeway/time.Second) {
		t.Fatalf("accepted an expired token: %v", id.ExpiresAt)
	}
}

// TestLookupServesAgentAlgorithmsOnly: a key without an alg fits more
// algorithms than agent tokens may use (an RSA key fits PS256 and RS384
// too). KeySource promises only keys that may verify the algorithm, so
// neither source hands one out for another algorithm, and the JWKS client
// does not fetch for one. FuzzParseJWKS found the fixed set doing it.
func TestLookupServesAgentAlgorithmsOnly(t *testing.T) {
	k := testKeys(t)
	ks, err := NewKeySet(pub("rsa1", k.rsa), pub("ec1", k.ec), pub("ed1", k.ed))
	if err != nil {
		t.Fatal(err)
	}
	only, err := NewKeySet(pub("", k.rsa))
	if err != nil {
		t.Fatal(err)
	}
	other := []string{"PS256", "PS384", "PS512", "RS384", "RS512", "ES384", "ES512", "Ed25519", "HS256", "none", "", "rs256"}
	for _, alg := range other {
		for _, kid := range []string{"rsa1", "ec1", "ed1"} {
			if key, ok := ks.Lookup(kid, alg); ok {
				t.Errorf("%s handed out for %q: %+v", kid, alg, key)
			}
		}
		if key, ok := only.Lookup("", alg); ok {
			t.Errorf("the only key handed out for %q: %+v", alg, key)
		}
	}
	for kid, alg := range map[string]string{"rsa1": RS256, "ec1": ES256, "ed1": EdDSA} {
		if _, ok := ks.Lookup(kid, alg); !ok {
			t.Errorf("%s not handed out for %s", kid, alg)
		}
	}

	is := newIssuer(t, jwksDoc(jwkOf(t, "rsa1", k.rsa.Public(), "")))
	clk := clock.NewFake(t0)
	j := newJWKS(t, is, clk, nil)
	if err := j.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, alg := range other {
		if key, ok := j.Lookup("rsa1", alg); ok {
			t.Errorf("JWKS: rsa1 handed out for %q: %+v", alg, key)
		}
		if _, ok := j.Lookup("rsa9", alg); ok {
			t.Errorf("JWKS: unknown kid found for %q", alg)
		}
	}
	if s := j.Stats(); s.Fetches != 1 || s.UnknownKid != 0 {
		t.Errorf("lookups for other algorithms fetched: %+v", s)
	}
	if _, ok := j.Lookup("rsa1", RS256); !ok {
		t.Error("JWKS: rsa1 not handed out for RS256")
	}
}
