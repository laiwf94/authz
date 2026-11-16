package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"

	"github.com/laiwf94/authz/internal/platform/jose"
)

// The asymmetric JWS algorithms agent tokens may be signed with. Each is
// bound to one key type: EdDSA to an Ed25519 key, ES256 to a P-256 key and
// RS256 to an RSA key of at least jose.MinRSABits. HS256 tokens never reach
// these keys and these algorithms never reach the HMAC keys, so a public
// key can't be used as a shared secret (RFC 8725 section 2.1).
const (
	EdDSA = "EdDSA"
	ES256 = "ES256"
	RS256 = "RS256"
)

// AsymmetricAlgorithms are the algorithms Config.Algorithms may name, and
// its default.
var AsymmetricAlgorithms = []string{EdDSA, ES256, RS256}

// Limits on public verification keys.
const (
	MaxPublicKeys  = 100
	MaxPublicKeyID = 256
)

// KeySource gives the public keys that verify asymmetrically signed agent
// tokens. Lookup returns the key a token's kid names, if that key may
// verify alg; for a token without a kid it returns the source's only key,
// and nothing when there is more than one. A source is read on every
// verification and must be safe for concurrent use; keys come only from
// it, never from the token (jku, jwk, x5u and x5c are ignored).
type KeySource interface {
	Lookup(kid, alg string) (jose.Key, bool)
}

// KeySet is a fixed KeySource: keys from configuration, or a test issuer's.
type KeySet struct {
	byID map[string]jose.Key
	only *jose.Key // the one key, when there is exactly one
}

// NewKeySet validates keys: each is an Ed25519, P-256 or RSA public key
// (at least jose.MinRSABits), its alg, when set, is one of
// AsymmetricAlgorithms and fits the key, its use, when set, is "sig", and
// kids are unique. At most one key may have no kid, and only when it is
// the only key.
func NewKeySet(keys ...jose.Key) (*KeySet, error) {
	if len(keys) == 0 {
		return nil, errors.New("identity: a key set needs at least one key")
	}
	if len(keys) > MaxPublicKeys {
		return nil, fmt.Errorf("identity: a key set holds at most %d keys", MaxPublicKeys)
	}
	ks := &KeySet{byID: make(map[string]jose.Key, len(keys))}
	for i, k := range keys {
		if err := checkPublicKey(k); err != nil {
			return nil, fmt.Errorf("identity: key %d (kid %q): %w", i, k.ID, err)
		}
		if k.ID == "" {
			if len(keys) > 1 {
				return nil, errors.New("identity: every key of a set with more than one key needs a kid")
			}
			continue
		}
		if _, dup := ks.byID[k.ID]; dup {
			return nil, fmt.Errorf("identity: kid %q is in the key set twice", k.ID)
		}
		ks.byID[k.ID] = k
	}
	if len(keys) == 1 {
		ks.only = &keys[0]
	}
	return ks, nil
}

func checkPublicKey(k jose.Key) error {
	if len(k.ID) > MaxPublicKeyID {
		return fmt.Errorf("kid is longer than %d bytes", MaxPublicKeyID)
	}
	if k.Use != "" && k.Use != "sig" {
		return fmt.Errorf("use is %q, not \"sig\"", k.Use)
	}
	switch p := k.Public.(type) {
	case ed25519.PublicKey:
		if len(p) != ed25519.PublicKeySize {
			return errors.New("Ed25519 key of the wrong size")
		}
	case *ecdsa.PublicKey:
		if p == nil || p.Curve != elliptic.P256() {
			return errors.New("EC keys must be on P-256")
		}
	case *rsa.PublicKey:
		if p == nil || p.N == nil || p.N.BitLen() < jose.MinRSABits || p.N.BitLen() > jose.MaxRSABits {
			return fmt.Errorf("RSA keys must have %d to %d bits", jose.MinRSABits, jose.MaxRSABits)
		}
	default:
		return fmt.Errorf("unsupported key type %T", k.Public)
	}
	if k.Alg != "" {
		if !slices.Contains(AsymmetricAlgorithms, k.Alg) {
			return fmt.Errorf("alg %q is not one of %v", k.Alg, AsymmetricAlgorithms)
		}
		if !k.Fits(k.Alg) {
			return fmt.Errorf("alg %s does not fit a %T", k.Alg, k.Public)
		}
	} else if !slices.ContainsFunc(AsymmetricAlgorithms, k.Fits) {
		return fmt.Errorf("a %T verifies none of %v", k.Public, AsymmetricAlgorithms)
	}
	return nil
}

// Lookup implements KeySource. Only the algorithms of
// AsymmetricAlgorithms are served: an RSA key without an alg would fit
// PS256 too, which agent tokens may not use.
func (ks *KeySet) Lookup(kid, alg string) (jose.Key, bool) {
	if !slices.Contains(AsymmetricAlgorithms, alg) {
		return jose.Key{}, false
	}
	var k jose.Key
	if kid == "" {
		if ks.only == nil {
			return jose.Key{}, false
		}
		k = *ks.only
	} else {
		var ok bool
		if k, ok = ks.byID[kid]; !ok {
			return jose.Key{}, false
		}
	}
	if !k.Fits(alg) {
		return jose.Key{}, false
	}
	return k, true
}

// checkAlgorithms validates Config.Algorithms and returns it, or the
// default when it is empty.
func checkAlgorithms(algs []string) ([]string, error) {
	if len(algs) == 0 {
		return AsymmetricAlgorithms, nil
	}
	seen := map[string]bool{}
	for _, alg := range algs {
		if !slices.Contains(AsymmetricAlgorithms, alg) {
			return nil, fmt.Errorf("identity: algorithm %q is not one of %v", alg, AsymmetricAlgorithms)
		}
		if seen[alg] {
			return nil, fmt.Errorf("identity: algorithm %s is listed twice", alg)
		}
		seen[alg] = true
	}
	return slices.Clone(algs), nil
}
