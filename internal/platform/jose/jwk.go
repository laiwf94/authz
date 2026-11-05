// Package jose implements the parts of JSON Web Signature (RFC 7515), JSON
// Web Key (RFC 7517) and JSON Web Token (RFC 7519) that an OpenID Connect
// relying party and a token issuer need, following the JWT best current
// practices of RFC 8725: an explicit algorithm allow-list, keys bound to one
// algorithm family, no "none", no keys taken from the token itself.
//
// It is the platform's one JOSE library: the sign-on gateway verifies ID
// tokens and signs upstream JWTs with it, and the agent gateway signs and
// verifies its HS256 agent tokens through VerifyHMAC and SignHMAC, which
// are kept apart from the asymmetric Verify.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// Limits on untrusted key material.
const (
	MaxJWKSBytes  = 1 << 20
	MaxJWKSKeys   = 100
	MinRSABits    = 2048
	MaxRSABits    = 8192
	maxRSAExpBits = 32
)

// ErrInvalidKey reports a JWK that is malformed or not acceptable.
var ErrInvalidKey = errors.New("jose: invalid key")

// Key is a public verification key.
type Key struct {
	ID     string
	Alg    string // optional; when set, the only algorithm this key may verify
	Use    string // optional; when set, must be "sig"
	Public crypto.PublicKey
}

// KeySet is a parsed JWK Set.
type KeySet struct {
	Keys []Key
}

type rawJWK struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	Alg string   `json:"alg"`
	Ops []string `json:"key_ops"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	Crv string   `json:"crv"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	D   string   `json:"d"`
}

// ParseKeySet parses a JWK Set document. Keys this package can't use (for
// encryption, unknown key types or curves) are skipped, as RFC 7517 section
// 5 asks; a key of a known type that is malformed fails the whole set.
func ParseKeySet(b []byte) (*KeySet, error) {
	if len(b) > MaxJWKSBytes {
		return nil, fmt.Errorf("%w: key set larger than %d bytes", ErrInvalidKey, MaxJWKSBytes)
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if doc.Keys == nil {
		return nil, fmt.Errorf("%w: no \"keys\" member", ErrInvalidKey)
	}
	if len(doc.Keys) > MaxJWKSKeys {
		return nil, fmt.Errorf("%w: more than %d keys", ErrInvalidKey, MaxJWKSKeys)
	}
	ks := &KeySet{}
	seen := map[string]bool{}
	for _, raw := range doc.Keys {
		k, ok, err := parseJWK(raw)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if k.ID != "" {
			if seen[k.ID] {
				return nil, fmt.Errorf("%w: duplicate kid %q", ErrInvalidKey, k.ID)
			}
			seen[k.ID] = true
		}
		ks.Keys = append(ks.Keys, k)
	}
	return ks, nil
}

// parseJWK returns ok=false for keys that are well formed but not usable for
// signature verification here.
func parseJWK(b []byte) (Key, bool, error) {
	var j rawJWK
	if err := json.Unmarshal(b, &j); err != nil {
		return Key{}, false, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if j.D != "" {
		return Key{}, false, fmt.Errorf("%w: key set contains a private key", ErrInvalidKey)
	}
	if j.Use != "" && j.Use != "sig" {
		return Key{}, false, nil
	}
	if len(j.Ops) > 0 && !contains(j.Ops, "verify") {
		return Key{}, false, nil
	}
	k := Key{ID: j.Kid, Alg: j.Alg, Use: j.Use}
	switch j.Kty {
	case "RSA":
		n, err := decodeBigInt(j.N)
		if err != nil {
			return Key{}, false, fmt.Errorf("%w: RSA n: %v", ErrInvalidKey, err)
		}
		e, err := decodeBigInt(j.E)
		if err != nil {
			return Key{}, false, fmt.Errorf("%w: RSA e: %v", ErrInvalidKey, err)
		}
		if n.BitLen() < MinRSABits || n.BitLen() > MaxRSABits {
			return Key{}, false, fmt.Errorf("%w: RSA modulus of %d bits (allowed %d-%d)", ErrInvalidKey, n.BitLen(), MinRSABits, MaxRSABits)
		}
		if e.BitLen() > maxRSAExpBits || e.Int64() < 3 || e.Bit(0) == 0 {
			return Key{}, false, fmt.Errorf("%w: RSA exponent out of range", ErrInvalidKey)
		}
		k.Public = &rsa.PublicKey{N: n, E: int(e.Int64())}
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return Key{}, false, nil
		}
		size := (curve.Params().BitSize + 7) / 8
		x, err := decodeFixed(j.X, size)
		if err != nil {
			return Key{}, false, fmt.Errorf("%w: EC x: %v", ErrInvalidKey, err)
		}
		y, err := decodeFixed(j.Y, size)
		if err != nil {
			return Key{}, false, fmt.Errorf("%w: EC y: %v", ErrInvalidKey, err)
		}
		// The uncompressed point encoding lets crypto/ecdh-backed parsing
		// reject points that are not on the curve.
		pt := append([]byte{4}, append(x, y...)...)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, pt)
		if err != nil {
			return Key{}, false, fmt.Errorf("%w: EC point: %v", ErrInvalidKey, err)
		}
		k.Public = pub
	case "OKP":
		if j.Crv != "Ed25519" {
			return Key{}, false, nil
		}
		x, err := decodeFixed(j.X, ed25519.PublicKeySize)
		if err != nil {
			return Key{}, false, fmt.Errorf("%w: OKP x: %v", ErrInvalidKey, err)
		}
		k.Public = ed25519.PublicKey(x)
	default:
		return Key{}, false, nil
	}
	if k.Alg != "" {
		if err := checkKeyAlg(k.Public, k.Alg); err != nil {
			return Key{}, false, fmt.Errorf("%w: kid %q: %v", ErrInvalidKey, k.ID, err)
		}
	}
	return k, true, nil
}

func decodeBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("empty")
	}
	if b[0] == 0 {
		return nil, errors.New("leading zero byte")
	}
	return new(big.Int).SetBytes(b), nil
}

func decodeFixed(s string, size int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, fmt.Errorf("want %d bytes, got %d", size, len(b))
	}
	return b, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// PublicJWK renders an ECDSA P-256 public key as a JWK with the given kid.
func PublicJWK(pub *ecdsa.PublicKey, kid string) map[string]string {
	b, err := pub.Bytes()
	if err != nil || pub.Curve != elliptic.P256() {
		panic("jose: PublicJWK needs a valid P-256 key")
	}
	return map[string]string{
		"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": kid,
		"x": base64.RawURLEncoding.EncodeToString(b[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(b[33:65]),
	}
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of a P-256 public key,
// base64url encoded. It is used as a stable kid.
func Thumbprint(pub *ecdsa.PublicKey) string {
	j := PublicJWK(pub, "")
	// RFC 7638 section 3.2: required members only, in lexicographic order,
	// no whitespace.
	canon := `{"crv":"P-256","kty":"EC","x":"` + j["x"] + `","y":"` + j["y"] + `"}`
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
