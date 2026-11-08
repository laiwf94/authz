package jose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // register SHA-256 for crypto.Hash
	_ "crypto/sha512" // register SHA-384 and SHA-512
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// MaxTokenBytes bounds the compact serialization accepted by Parse.
const MaxTokenBytes = 64 << 10

// Errors returned by Parse and Verify.
var (
	ErrMalformed   = errors.New("jose: malformed token")
	ErrAlgorithm   = errors.New("jose: algorithm not allowed")
	ErrSignature   = errors.New("jose: signature verification failed")
	ErrKeyMismatch = errors.New("jose: key does not fit the algorithm")
	ErrCritical    = errors.New("jose: unsupported critical header")
)

// SupportedAlgorithms are the asymmetric JWS algorithms Verify implements.
// Symmetric algorithms (HS256...) and "none" are deliberately absent: a
// relying party that verifies with a public key must never accept them
// (RFC 8725 section 3.1 and 3.2).
var SupportedAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// IsSupported reports whether alg is in SupportedAlgorithms.
func IsSupported(alg string) bool { return contains(SupportedAlgorithms, alg) }

// Header is the protected JOSE header.
type Header struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid,omitempty"`
	Typ  string   `json:"typ,omitempty"`
	Crit []string `json:"crit,omitempty"`
}

// Token is a parsed but not yet verified JWS in compact serialization.
type Token struct {
	Header       Header
	Payload      []byte
	extraHeader  bool // the header has members Header does not model
	signingInput []byte
	signature    []byte
}

// Parse splits and decodes a compact JWS. It checks structure only: the
// payload must not be trusted until Verify succeeds.
func Parse(s string) (*Token, error) {
	if len(s) > MaxTokenBytes {
		return nil, fmt.Errorf("%w: longer than %d bytes", ErrMalformed, MaxTokenBytes)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: want 3 parts, got %d", ErrMalformed, len(parts))
	}
	hb, err := b64(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	payload, err := b64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	sig, err := b64(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}
	t := &Token{Payload: payload, signature: sig, signingInput: []byte(s[:len(parts[0])+1+len(parts[1])])}
	if err := strictUnmarshal(hb, &t.Header, true); err != nil {
		// Decode again, leniently: members this package doesn't model are
		// ignored here and refused by StrictHeader. Almost every header
		// decodes on the first, exact pass.
		t.Header = Header{}
		if err := strictUnmarshal(hb, &t.Header, false); err != nil {
			return nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
		}
		t.extraHeader = true
	}
	if t.Header.Alg == "" {
		return nil, fmt.Errorf("%w: header has no alg", ErrMalformed)
	}
	// RFC 7515 section 4.1.11: a recipient that does not understand a
	// critical extension must reject the token. This package understands none.
	if len(t.Header.Crit) > 0 {
		return nil, ErrCritical
	}
	return t, nil
}

// b64 decodes one canonical unpadded base64url string. Strict refuses
// non-zero padding bits but, like every Go base64 decoder, skips CR and LF,
// which would let two different strings decode to one signature (#237).
func b64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("line break in base64url")
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// strictUnmarshal decodes one JSON object. Unless exact is set, header
// members it doesn't model (jku, jwk, x5u, x5c...) are ignored on purpose:
// keys always come from the configured key set, never from the token
// (RFC 8725 section 3.10).
func strictUnmarshal(b []byte, v any, exact bool) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if exact {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// Verify checks the signature with key, accepting only algorithms in allowed.
func (t *Token) Verify(key Key, allowed []string) error {
	alg := t.Header.Alg
	if !contains(allowed, alg) || !IsSupported(alg) {
		return fmt.Errorf("%w: %q", ErrAlgorithm, alg)
	}
	if key.Alg != "" && key.Alg != alg {
		return fmt.Errorf("%w: key is for %s, token uses %s", ErrKeyMismatch, key.Alg, alg)
	}
	if key.Use != "" && key.Use != "sig" {
		return fmt.Errorf("%w: key use is %q", ErrKeyMismatch, key.Use)
	}
	if err := checkKeyAlg(key.Public, alg); err != nil {
		return err
	}
	return verify(key.Public, alg, t.signingInput, t.signature)
}

func hashFor(alg string) crypto.Hash {
	switch alg[2:] {
	case "384":
		return crypto.SHA384
	case "512":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// checkKeyAlg enforces that a key verifies only its own algorithm family,
// which rules out "HS256 signed with the RSA public key" confusion.
func checkKeyAlg(pub crypto.PublicKey, alg string) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
			if k.N.BitLen() < MinRSABits {
				return fmt.Errorf("%w: RSA key shorter than %d bits", ErrKeyMismatch, MinRSABits)
			}
			return nil
		}
	case *ecdsa.PublicKey:
		want := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()}[alg]
		if want != nil && k.Curve == want {
			return nil
		}
	case ed25519.PublicKey:
		if alg == "EdDSA" {
			return nil
		}
	}
	return fmt.Errorf("%w: %T cannot verify %s", ErrKeyMismatch, pub, alg)
}

func verify(pub crypto.PublicKey, alg string, input, sig []byte) error {
	if alg == "EdDSA" {
		if !ed25519.Verify(pub.(ed25519.PublicKey), input, sig) {
			return ErrSignature
		}
		return nil
	}
	h := hashFor(alg).New()
	h.Write(input)
	digest := h.Sum(nil)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		var err error
		if alg[0] == 'P' {
			err = rsa.VerifyPSS(k, hashFor(alg), digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			err = rsa.VerifyPKCS1v15(k, hashFor(alg), digest, sig)
		}
		if err != nil {
			return ErrSignature
		}
		return nil
	case *ecdsa.PublicKey:
		// JWS uses the fixed-width R || S encoding (RFC 7518 section 3.4),
		// not ASN.1.
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return ErrSignature
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, digest, r, s) {
			return ErrSignature
		}
		return nil
	}
	return ErrKeyMismatch
}

// Signer issues ES256 tokens with one P-256 key.
type Signer struct {
	key *ecdsa.PrivateKey
	kid string
}

// NewSigner wraps a P-256 private key. The kid is the key's RFC 7638
// thumbprint, so it is stable across restarts without configuration.
func NewSigner(key *ecdsa.PrivateKey) (*Signer, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errors.New("jose: signer needs a P-256 private key")
	}
	return &Signer{key: key, kid: Thumbprint(&key.PublicKey)}, nil
}

// KeyID returns the kid placed in every token header.
func (s *Signer) KeyID() string { return s.kid }

// Public returns the verification key.
func (s *Signer) Public() *ecdsa.PublicKey { return &s.key.PublicKey }

// Sign serializes claims and returns a compact ES256 JWS with typ "JWT".
func (s *Signer) Sign(claims any) (string, error) {
	hb, _ := json.Marshal(Header{Alg: "ES256", Kid: s.kid, Typ: "JWT"})
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	digest := crypto.SHA256.New()
	digest.Write([]byte(input))
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, digest.Sum(nil))
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Fits reports whether the key may verify alg.
func (k Key) Fits(alg string) bool {
	return (k.Alg == "" || k.Alg == alg) && checkKeyAlg(k.Public, alg) == nil
}
