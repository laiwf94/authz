// Package seal encrypts and authenticates small values for cookies with
// AES-256-GCM and a key ring: the newest key seals, every key opens, so keys
// can be rotated without logging everyone out.
//
// The keys come from a list (New, Rotate) or from an A256GCM ring of
// internal/platform/keys (FromRing), which rotates on its own schedule: the
// ring's current key seals, and its retired keys open until their overlap
// ends. A key's 4-byte id in the sealed value is derived from the key the
// same way in both cases, so a key moved from a list onto a ring keeps
// opening the values it sealed.
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
	"time"

	"github.com/laiwf94/authz/internal/platform/keys"
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
// Rotate, or a rotation of its ring, while values are sealed and opened.
type Keyring struct {
	keys atomic.Pointer[[]key]

	// Set by FromRing instead of keys.
	ring   *keys.Ring
	now    func() time.Time
	rcache atomic.Pointer[ringCache]
}

// ringKey is a ring key with its seal id and cipher.
type ringKey struct {
	key
	k *keys.Key
}

// ringCache holds the ciphers of the keys the ring accepted when cur became
// current, cur first. It is rebuilt when the ring's current key changes;
// keys that a prune or drop removed since are skipped by Open, which asks
// the ring whether each key still opens.
type ringCache struct {
	cur  *keys.Key
	keys []ringKey
}

// FromRing returns a key ring on r, which must hold A256GCM keys. The
// ring's current key seals; its current key, its next key and its retired
// keys inside their overlap at now() open. now nil means time.Now. Rotating
// r, by hand or through a keys.Scheduler, takes effect on the next Seal.
func FromRing(r *keys.Ring, now func() time.Time) (*Keyring, error) {
	if r == nil {
		return nil, errors.New("seal: nil key ring")
	}
	if r.Alg() != keys.A256GCM {
		return nil, fmt.Errorf("seal: key ring holds %s keys, want %s", r.Alg(), keys.A256GCM)
	}
	if now == nil {
		now = time.Now
	}
	kr := &Keyring{ring: r, now: now}
	kr.ringKeys(r.Current())
	return kr, nil
}

// Ring returns the key ring the Keyring was built on with FromRing, or nil.
func (kr *Keyring) Ring() *keys.Ring { return kr.ring }

// ringKeys returns the cache for the ring's current key cur.
func (kr *Keyring) ringKeys(cur *keys.Key) *ringCache {
	old := kr.rcache.Load()
	if old != nil && old.cur == cur {
		return old
	}
	reuse := map[*keys.Key]ringKey{}
	if old != nil {
		for _, rk := range old.keys {
			reuse[rk.k] = rk
		}
	}
	vs := kr.ring.Verifying(kr.now())
	if vs[0] != cur { // the ring rotated again after cur was read
		vs = append([]*keys.Key{cur}, vs...)
	}
	c := &ringCache{cur: cur, keys: make([]ringKey, 0, len(vs))}
	for _, k := range vs {
		rk, ok := reuse[k]
		if !ok {
			// A256GCM keys always carry their cipher and secret.
			aead, _ := k.AEAD()
			rk = ringKey{key: key{id: keyID(k.Secret()), aead: aead}, k: k}
			reuse[k] = rk
		}
		c.keys = append(c.keys, rk)
	}
	kr.rcache.Store(c)
	return c
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
	if kr.ring != nil {
		return errors.New("seal: the keys come from a key ring; rotate the ring")
	}
	ks, err := build(keys)
	if err != nil {
		return err
	}
	kr.keys.Store(&ks)
	return nil
}

// Len returns the number of keys that open values: for a ring, the keys
// it accepts now.
func (kr *Keyring) Len() int {
	if kr.ring != nil {
		return len(kr.ring.Verifying(kr.now()))
	}
	return len(*kr.keys.Load())
}

// keyID derives the id a sealed value names its key by, so operators only
// manage keys.
func keyID(k []byte) [kidSize]byte {
	sum := sha256.Sum256(append([]byte("wicket seal key id\x00"), k...))
	var id [kidSize]byte
	copy(id[:], sum[:])
	return id
}

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
		id := keyID(k)
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
	var k key
	if kr.ring != nil {
		k = kr.ringKeys(kr.ring.Current()).keys[0].key
	} else {
		k = (*kr.keys.Load())[0]
	}
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
	if kr.ring != nil {
		return kr.openRing(purpose, b)
	}
	for _, k := range *kr.keys.Load() {
		if [kidSize]byte(b[1:headerBytes]) != k.id {
			continue
		}
		return k.open(purpose, b)
	}
	return nil, ErrInvalid
}

// openRing opens b with the ring key its header names, if the ring still
// accepts that key: a retired key whose overlap has ended, or one an
// operator dropped, no longer opens even before the cache is rebuilt.
func (kr *Keyring) openRing(purpose string, b []byte) ([]byte, error) {
	id := [kidSize]byte(b[1:headerBytes])
	c := kr.ringKeys(kr.ring.Current())
	for i, rk := range c.keys {
		if rk.id != id {
			continue
		}
		if i > 0 && kr.ring.Lookup(rk.k.ID(), kr.now()) == nil {
			continue
		}
		// Two ring keys can share a 4-byte id; try each.
		if pt, err := rk.open(purpose, b); err == nil {
			return pt, nil
		}
	}
	return nil, ErrInvalid
}

// open decrypts b, whose header names k.
func (k key) open(purpose string, b []byte) ([]byte, error) {
	nonce := b[headerBytes : headerBytes+nonceSize]
	pt, err := k.aead.Open(nil, nonce, b[headerBytes+nonceSize:], additionalData(b[:headerBytes], purpose))
	if err != nil {
		return nil, ErrInvalid
	}
	return pt, nil
}
