// Package seal encrypts and authenticates small values for cookies with
// AES-256-GCM and a key ring: the newest key seals, every key opens, so keys
// can be rotated without logging everyone out.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

// Sizes and limits of the sealed format.
const (
	KeySize     = 32
	version     = 1
	kidSize     = 4
	nonceSize   = 12
	overhead    = 1 + kidSize + nonceSize + 16
	MaxEncoded  = 4096
	maxKeys     = 16
	maxPurpose  = 64
	headerBytes = 1 + kidSize
)

// ErrInvalid is returned for anything that does not open: wrong format,
// unknown key, tampering, or a value sealed for another purpose. One error
// for all cases gives an attacker nothing to distinguish.
var ErrInvalid = errors.New("seal: invalid value")

type key struct {
	id   [kidSize]byte
	aead cipher.AEAD
}

// Keyring holds the keys. It is safe for concurrent use, including
// Rotate while values are sealed and opened.
type Keyring struct {
	keys atomic.Pointer[[]key]
}

// New builds a key ring. keys[0] seals; all keys open. Each key is 32 bytes.
func New(keys [][]byte) (*Keyring, error) {
	ks, err := build(keys)
	if err != nil {
		return nil, err
	}
	kr := &Keyring{}
	kr.keys.Store(&ks)
	return kr, nil
}

// Rotate replaces the keys in place, with New's rules: keys[0] seals from
// now on and all of them open. Each Seal and Open uses one whole key list,
// the old or the new. On an error the keys in use are kept.
func (kr *Keyring) Rotate(keys [][]byte) error {
	ks, err := build(keys)
	if err != nil {
		return err
	}
	kr.keys.Store(&ks)
	return nil
}

// Len returns the number of keys in the ring.
func (kr *Keyring) Len() int { return len(*kr.keys.Load()) }

func build(keys [][]byte) ([]key, error) {
	if len(keys) == 0 || len(keys) > maxKeys {
		return nil, fmt.Errorf("seal: need 1 to %d keys, got %d", maxKeys, len(keys))
	}
	out := make([]key, 0, len(keys))
	seen := map[[kidSize]byte]bool{}
	for i, k := range keys {
		if len(k) != KeySize {
			return nil, fmt.Errorf("seal: key %d is %d bytes, want %d", i, len(k), KeySize)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		// The key id is derived from the key, so operators only manage keys.
		sum := sha256.Sum256(append([]byte("wicket seal key id\x00"), k...))
		var id [kidSize]byte
		copy(id[:], sum[:])
		if seen[id] {
			return nil, fmt.Errorf("seal: key %d is a duplicate", i)
		}
		seen[id] = true
		out = append(out, key{id: id, aead: aead})
	}
	return out, nil
}

// RandomKey returns a new random 32-byte key.
func RandomKey() []byte {
	k := make([]byte, KeySize)
	_, _ = rand.Read(k)
	return k
}

func additionalData(header []byte, purpose string) []byte {
	return append(append([]byte{}, header...), purpose...)
}

// Seal encrypts plaintext for purpose with the newest key and returns
// base64url text safe for a cookie value.
func (kr *Keyring) Seal(purpose string, plaintext []byte) string {
	if len(purpose) == 0 || len(purpose) > maxPurpose {
		panic("seal: purpose must be 1-64 bytes")
	}
	k := (*kr.keys.Load())[0]
	out := make([]byte, headerBytes+nonceSize, overhead+len(plaintext))
	out[0] = version
	copy(out[1:headerBytes], k.id[:])
	_, _ = rand.Read(out[headerBytes:])
	out = k.aead.Seal(out, out[headerBytes:], plaintext, additionalData(out[:headerBytes], purpose))
	return base64.RawURLEncoding.EncodeToString(out)
}

// Open reverses Seal. The purpose must match the one used to seal, so a
// value sealed for one cookie can't be replayed as another.
func (kr *Keyring) Open(purpose, s string) ([]byte, error) {
	// The decoder skips CR and LF even in strict mode; refusing them keeps
	// one sealed value to one string (#237).
	if len(s) > MaxEncoded || strings.ContainsAny(s, "\r\n") {
		return nil, ErrInvalid
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) < overhead || b[0] != version {
		return nil, ErrInvalid
	}
	for _, k := range *kr.keys.Load() {
		if [kidSize]byte(b[1:headerBytes]) != k.id {
			continue
		}
		nonce := b[headerBytes : headerBytes+nonceSize]
		pt, err := k.aead.Open(nil, nonce, b[headerBytes+nonceSize:], additionalData(b[:headerBytes], purpose))
		if err != nil {
			return nil, ErrInvalid
		}
		return pt, nil
	}
	return nil, ErrInvalid
}
