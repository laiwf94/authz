package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

var hmacKey = bytes.Repeat([]byte{7}, 32)

// hsToken signs header and payload by hand, independently of SignHMAC.
func hsToken(secret []byte, header, payload string) string {
	enc := base64.RawURLEncoding
	in := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString([]byte(payload))
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(in))
	return in + "." + enc.EncodeToString(m.Sum(nil))
}

func TestSignHMACRoundTrip(t *testing.T) {
	claims := map[string]any{"sub": "ci-agent", "exp": 1_000_600}
	tok, err := SignHMAC("k1", hmacKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	if h := p.Header; h.Alg != HS256 || h.Kid != "k1" || h.Typ != "JWT" || h.Crit != nil {
		t.Fatalf("header = %+v", p.Header)
	}
	if err := p.StrictHeader(); err != nil {
		t.Fatalf("StrictHeader on our own token: %v", err)
	}
	if err := p.VerifyHMAC(hmacKey); err != nil {
		t.Fatalf("VerifyHMAC: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(p.Payload, &got); err != nil || got["sub"] != "ci-agent" {
		t.Fatalf("payload = %s (%v)", p.Payload, err)
	}
	// Byte for byte what an independent HS256 implementation produces.
	parts := strings.Split(tok, ".")
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if want := hsToken(hmacKey, string(hb), string(p.Payload)); tok != want {
		t.Fatalf("token = %s, want %s", tok, want)
	}
}

func TestVerifyHMACRejects(t *testing.T) {
	good := `{"alg":"HS256","kid":"k1"}`
	other := bytes.Repeat([]byte{8}, 32)
	valid := hsToken(hmacKey, good, `{}`)
	parts := strings.Split(valid, ".")

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)

	cases := []struct {
		name   string
		token  string
		secret []byte
		want   error
	}{
		{"wrong secret", valid, other, ErrSignature},
		{"short secret", valid, hmacKey[:31], ErrKeyMismatch},
		{"nil secret", valid, nil, ErrKeyMismatch},
		{"tampered payload", parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"admin":true}`)) + "." + parts[2], hmacKey, ErrSignature},
		{"truncated signature", valid[:len(valid)-3], hmacKey, ErrSignature},
		{"empty signature", parts[0] + "." + parts[1] + ".", hmacKey, ErrSignature},
		{"HS384", hsToken(hmacKey, `{"alg":"HS384"}`, `{}`), hmacKey, ErrAlgorithm},
		{"HS512", hsToken(hmacKey, `{"alg":"HS512"}`, `{}`), hmacKey, ErrAlgorithm},
		{"none", hsToken(hmacKey, `{"alg":"none"}`, `{}`), hmacKey, ErrAlgorithm},
		{"lowercase alg", hsToken(hmacKey, `{"alg":"hs256"}`, `{}`), hmacKey, ErrAlgorithm},
		{"ES256 token", hsToken(hmacKey, `{"alg":"ES256"}`, `{}`), hmacKey, ErrAlgorithm},
		// The public key is no secret: a token MACed with it still fails
		// when the verifier holds its real secret.
		{"public key as secret", hsToken(der, good, `{}`), hmacKey, ErrSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Parse(c.token)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if err := p.VerifyHMAC(c.secret); !errors.Is(err, c.want) {
				t.Fatalf("VerifyHMAC = %v, want %v", err, c.want)
			}
		})
	}
}

// Verify, the asymmetric path, must still refuse HS256 even when a caller
// lists it, so an HMAC token can never pass as a signed one.
func TestVerifyStillRefusesHS256(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	p, err := Parse(hsToken(der, `{"alg":"HS256"}`, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(Key{Public: &ec.PublicKey}, []string{"HS256", "ES256"}); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("Verify = %v, want ErrAlgorithm", err)
	}
	if IsSupported(HS256) {
		t.Fatal("HS256 must not be in SupportedAlgorithms")
	}
}

func TestStrictHeader(t *testing.T) {
	for header, ok := range map[string]bool{
		`{"alg":"HS256"}`:                               true,
		`{"alg":"HS256","kid":"k1","typ":"JWT"}`:        true,
		`{"alg":"HS256","kid":"k1","jku":"https://x"}`:  false,
		`{"alg":"HS256","jwk":{"kty":"oct","k":"AA"}}`:  false,
		`{"alg":"HS256","x5u":"https://x"}`:             false,
		`{"alg":"HS256","kid":"k1","b64":false}`:        false,
		`{"alg":"HS256","kid":1}`:                       false,
		`{"alg":"HS256","Kid":"k1","kid":"k2","zip":1}`: false,
	} {
		p, err := Parse(hsToken(hmacKey, header, `{}`))
		if err != nil {
			if !ok {
				continue // refused even earlier, by Parse
			}
			t.Fatalf("%s: Parse: %v", header, err)
		}
		err = p.StrictHeader()
		if ok && err != nil {
			t.Errorf("%s: refused: %v", header, err)
		}
		if !ok && !errors.Is(err, ErrHeader) {
			t.Errorf("%s: StrictHeader = %v, want ErrHeader", header, err)
		}
	}
}

func TestSignHMACErrors(t *testing.T) {
	if _, err := SignHMAC("k1", hmacKey[:16], map[string]any{}); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("short secret: %v", err)
	}
	if _, err := SignHMAC("k1", hmacKey, map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("unencodable claims were signed")
	}
}

func FuzzVerifyHMAC(f *testing.F) {
	tok, _ := SignHMAC("k1", hmacKey, map[string]any{"sub": "a"})
	f.Add(tok)
	f.Add(hsToken(hmacKey, `{"alg":"HS256","jku":"x"}`, `{}`))
	f.Add("eyJhbGciOiJIUzI1NiJ9.e30.")
	f.Fuzz(func(t *testing.T, s string) {
		p, err := Parse(s)
		if err != nil {
			return
		}
		_ = p.StrictHeader()
		if p.VerifyHMAC(hmacKey) != nil {
			return
		}
		// Anything accepted carries a valid MAC over its first two parts
		// and says HS256.
		parts := strings.Split(s, ".")
		if p.Header.Alg != HS256 || hsMAC(parts[0]+"."+parts[1]) != parts[2] {
			t.Fatalf("accepted %q without a valid HS256 MAC", s)
		}
	})
}

func hsMAC(in string) string {
	m := hmac.New(sha256.New, hmacKey)
	m.Write([]byte(in))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func BenchmarkVerifyHMAC(b *testing.B) {
	tok, _ := SignHMAC("k1", hmacKey, map[string]any{"sub": "ci-agent", "exp": 1_000_600})
	for b.Loop() {
		p, err := Parse(tok)
		if err != nil {
			b.Fatal(err)
		}
		if err := p.VerifyHMAC(hmacKey); err != nil {
			b.Fatal(err)
		}
	}
}
