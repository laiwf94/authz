// Package keys holds every signing, sealing and MAC key the platform uses in
// typed key rings, so session cookies, upstream JWTs, consistency tokens and
// agent tokens share one rotation story.
//
// A Ring holds keys of one algorithm in three roles. The current key signs
// or seals. The next key is already generated and published, so verifiers
// that cache a JWKS learn it before it starts signing. Previous keys are
// retired current keys that still verify until their overlap ends, so
// tokens and cookies issued just before a rotation stay valid. Rotation
// moves next to current and current to previous, and generates a new next.
//
// Rings are read without locks: every rotation publishes a new immutable
// state, so Current and Lookup cost one atomic load and no allocation.
//
// A Set names the rings of a process, renders their public keys as one JWK
// Set, rotates them on schedule and saves them to one file. ReadKeyFile and
// ParseSecretList read the key files and environment lists the earlier
// binaries used, so existing keys move onto rings with their key ids intact.
package keys

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"
)

// Alg names what a key does. The names are the JOSE algorithm identifiers
// (RFC 7518, RFC 8037).
type Alg string

// The algorithms a ring can hold.
const (
	EdDSA   Alg = "EdDSA"   // Ed25519 signatures
	ES256   Alg = "ES256"   // ECDSA P-256 with SHA-256
	RS256   Alg = "RS256"   // RSASSA-PKCS1-v1_5 with SHA-256
	HS256   Alg = "HS256"   // HMAC-SHA256
	A256GCM Alg = "A256GCM" // AES-256-GCM sealing
)

// Algs lists every Alg in a fixed order.
var Algs = []Alg{EdDSA, ES256, RS256, HS256, A256GCM}

// Key material limits.
const (
	// RSABits is the size of generated RSA keys and the smallest accepted.
	RSABits = 2048
	// MaxRSABits is the largest RSA key accepted.
	MaxRSABits = 8192
	// MinSecretBytes is the shortest HS256 secret accepted.
	MinSecretBytes = 32
	// MaxSecretBytes is the longest HS256 secret accepted.
	MaxSecretBytes = 1024
	// SealKeyBytes is the length of an A256GCM key.
	SealKeyBytes = 32
)

// Errors returned by key operations.
var (
	ErrAlg      = errors.New("keys: unknown algorithm")
	ErrKey      = errors.New("keys: invalid key")
	ErrNoSign   = errors.New("keys: key does not sign")
	ErrNoSeal   = errors.New("keys: key does not seal")
	ErrRingAlg  = errors.New("keys: key does not belong to this ring")
	ErrNotFound = errors.New("keys: no key with that id")
)

// Valid reports whether a is one of Algs.
func (a Alg) Valid() bool {
	switch a {
	case EdDSA, ES256, RS256, HS256, A256GCM:
		return true
	}
	return false
}

// Symmetric reports whether keys of a are secrets that must never be
// published.
func (a Alg) Symmetric() bool { return a == HS256 || a == A256GCM }

// kidRe bounds key ids: they travel in token headers and file names.
var kidRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Key is one immutable key. The zero value is not usable; build keys with
// Generate, FromSigner, FromSecret or the file readers.
type Key struct {
	id      string
	alg     Alg
	created time.Time
	ed      ed25519.PrivateKey
	ec      *ecdsa.PrivateKey
	rsa     *rsa.PrivateKey
	secret  []byte
	aead    cipher.AEAD
	jwk     []byte // public JWK, asymmetric keys only
}

// Generate makes a fresh random key for alg, stamped with created.
func Generate(alg Alg, created time.Time) (*Key, error) {
	switch alg {
	case EdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return FromSigner(priv, created)
	case ES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return FromSigner(priv, created)
	case RS256:
		priv, err := rsa.GenerateKey(rand.Reader, RSABits)
		if err != nil {
			return nil, err
		}
		return FromSigner(priv, created)
	case HS256, A256GCM:
		n := MinSecretBytes
		if alg == A256GCM {
			n = SealKeyBytes
		}
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		return FromSecret(alg, "", b, created)
	}
	return nil, fmt.Errorf("%w: %q", ErrAlg, alg)
}

// FromSigner wraps an Ed25519, ECDSA P-256 or RSA private key. The algorithm
// follows from the key type and the key id is the key's RFC 7638 SHA-256
// thumbprint, the kid wicket's upstream signer always used.
func FromSigner(priv crypto.Signer, created time.Time) (*Key, error) {
	k := &Key{created: created.UTC()}
	switch p := priv.(type) {
	case ed25519.PrivateKey:
		if len(p) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: Ed25519 key of %d bytes", ErrKey, len(p))
		}
		k.alg, k.ed = EdDSA, p
	case *ecdsa.PrivateKey:
		if p.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: ECDSA keys must use P-256", ErrKey)
		}
		k.alg, k.ec = ES256, p
	case *rsa.PrivateKey:
		if n := p.N.BitLen(); n < RSABits || n > MaxRSABits {
			return nil, fmt.Errorf("%w: RSA key of %d bits (allowed %d-%d)", ErrKey, n, RSABits, MaxRSABits)
		}
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKey, err)
		}
		p.Precompute()
		k.alg, k.rsa = RS256, p
	default:
		return nil, fmt.Errorf("%w: unsupported private key type %T", ErrKey, priv)
	}
	members, canon := k.publicMembers()
	sum := sha256.Sum256([]byte(canon))
	k.id = b64(sum[:])
	members["kid"], members["alg"], members["use"] = k.id, string(k.alg), "sig"
	k.jwk, _ = json.Marshal(members)
	return k, nil
}

// FromSecret wraps an HS256 or A256GCM secret. An empty kid is derived from
// the secret, so operators only manage secrets; a given kid (toolgate's
// named keys) is kept.
func FromSecret(alg Alg, kid string, secret []byte, created time.Time) (*Key, error) {
	switch alg {
	case HS256:
		if len(secret) < MinSecretBytes || len(secret) > MaxSecretBytes {
			return nil, fmt.Errorf("%w: HS256 secret of %d bytes (allowed %d-%d)", ErrKey, len(secret), MinSecretBytes, MaxSecretBytes)
		}
	case A256GCM:
		if len(secret) != SealKeyBytes {
			return nil, fmt.Errorf("%w: A256GCM key of %d bytes, want %d", ErrKey, len(secret), SealKeyBytes)
		}
	default:
		return nil, fmt.Errorf("%w: %q is not a secret-key algorithm", ErrAlg, alg)
	}
	if kid == "" {
		kid = secretID(alg, secret)
	} else if !kidRe.MatchString(kid) {
		return nil, fmt.Errorf("%w: key id %q must be 1 to 64 letters, digits, '_' or '-'", ErrKey, kid)
	}
	k := &Key{id: kid, alg: alg, created: created.UTC(), secret: append([]byte(nil), secret...)}
	if alg == A256GCM {
		block, err := aes.NewCipher(k.secret)
		if err != nil {
			return nil, err
		}
		if k.aead, err = cipher.NewGCM(block); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func secretID(alg Alg, secret []byte) string {
	h := sha256.New()
	h.Write([]byte("authz key id\x00" + string(alg) + "\x00"))
	h.Write(secret)
	return b64(h.Sum(nil)[:12])
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// publicMembers returns the public JWK members and the RFC 7638 canonical
// form they hash to.
func (k *Key) publicMembers() (map[string]string, string) {
	switch k.alg {
	case EdDSA:
		x := b64(k.ed.Public().(ed25519.PublicKey))
		return map[string]string{"kty": "OKP", "crv": "Ed25519", "x": x},
			`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`
	case ES256:
		pt, _ := k.ec.PublicKey.Bytes() // P-256 was checked, so this can't fail
		x, y := b64(pt[1:33]), b64(pt[33:65])
		return map[string]string{"kty": "EC", "crv": "P-256", "x": x, "y": y},
			`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	default: // RS256
		n := b64(k.rsa.N.Bytes())
		e := b64(big.NewInt(int64(k.rsa.E)).Bytes())
		return map[string]string{"kty": "RSA", "n": n, "e": e},
			`{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`
	}
}

// ID returns the key id placed in token headers.
func (k *Key) ID() string { return k.id }

// Alg returns the key's algorithm.
func (k *Key) Alg() Alg { return k.alg }

// Created returns when the key was made or imported.
func (k *Key) Created() time.Time { return k.created }

// Public returns the public key of an asymmetric key and nil for secrets.
func (k *Key) Public() crypto.PublicKey {
	switch k.alg {
	case EdDSA:
		return k.ed.Public()
	case ES256:
		return &k.ec.PublicKey
	case RS256:
		return &k.rsa.PublicKey
	}
	return nil
}

// Signer returns the private key of an asymmetric key and nil for secrets.
func (k *Key) Signer() crypto.Signer {
	switch k.alg {
	case EdDSA:
		return k.ed
	case ES256:
		return k.ec
	case RS256:
		return k.rsa
	}
	return nil
}

// JWK returns the public JWK of an asymmetric key, with kid, alg and use,
// and nil for secrets.
func (k *Key) JWK() json.RawMessage {
	if k.jwk == nil {
		return nil
	}
	return append(json.RawMessage(nil), k.jwk...)
}

// Secret returns a copy of an HS256 or A256GCM secret and nil otherwise.
func (k *Key) Secret() []byte {
	if k.secret == nil {
		return nil
	}
	return append([]byte(nil), k.secret...)
}

// AEAD returns the AES-256-GCM cipher of an A256GCM key.
func (k *Key) AEAD() (cipher.AEAD, error) {
	if k.aead == nil {
		return nil, ErrNoSeal
	}
	return k.aead, nil
}

// Sign returns the JWS signature (RFC 7518) of msg: Ed25519, the fixed-width
// R || S encoding for ES256, PKCS #1 v1.5 for RS256, and the HMAC for HS256.
func (k *Key) Sign(msg []byte) ([]byte, error) {
	switch k.alg {
	case EdDSA:
		return ed25519.Sign(k.ed, msg), nil
	case ES256:
		d := sha256.Sum256(msg)
		r, s, err := ecdsa.Sign(rand.Reader, k.ec, d[:])
		if err != nil {
			return nil, err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	case RS256:
		d := sha256.Sum256(msg)
		return rsa.SignPKCS1v15(rand.Reader, k.rsa, crypto.SHA256, d[:])
	case HS256:
		m := hmac.New(sha256.New, k.secret)
		m.Write(msg)
		return m.Sum(nil), nil
	}
	return nil, ErrNoSign
}

// Verify reports whether sig is this key's signature of msg. HMACs are
// compared in constant time.
func (k *Key) Verify(msg, sig []byte) bool {
	switch k.alg {
	case EdDSA:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(k.ed.Public().(ed25519.PublicKey), msg, sig)
	case ES256:
		if len(sig) != 64 {
			return false
		}
		d := sha256.Sum256(msg)
		return ecdsa.Verify(&k.ec.PublicKey, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case RS256:
		d := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(&k.rsa.PublicKey, crypto.SHA256, d[:], sig) == nil
	case HS256:
		m := hmac.New(sha256.New, k.secret)
		m.Write(msg)
		return hmac.Equal(m.Sum(nil), sig)
	}
	return false
}
