// Package token issues and verifies consistency tokens.
//
// A token names a store revision. Clients send it back to ask for a read that
// is at least as fresh as a write they made (the "new enemy" problem in the
// Zanzibar paper). Tokens are MACed so a client cannot invent a revision:
// a forged future revision could otherwise force reads to block or fail.
//
// The MAC keys live on an HS256 key ring (internal/platform/keys). The ring's
// current key MACs new tokens; a token verifies under the current key, any
// retired key still inside its overlap, or the next key. Rotating the ring
// therefore never invalidates an outstanding token until its key's overlap
// ends. The wire format carries no key id, so tokens issued before the move
// to rings, and by a single-key issuer, are byte for byte what they were.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/platform/keys"
)

// KeySize is the required key length in bytes.
const KeySize = 32

const (
	version = 1
	macSize = 16
	rawSize = 1 + 8 + macSize
)

// ErrInvalid is returned for any token that does not verify.
var ErrInvalid = errors.New("invalid consistency token")

// Issuer creates and verifies tokens with the keys of one HS256 ring. It is
// safe for concurrent use, including while the ring rotates.
type Issuer struct {
	ring  *keys.Ring
	now   func() time.Time
	cache atomic.Pointer[macCache]
}

// macCache holds a pool of keyed HMAC states for each key the ring accepted
// when its current key became current. hmac.New hashes the key pads and
// allocates every time; a pooled state is Reset instead, which halves the
// cost of a MAC and removes its allocations. The cache is rebuilt when the
// current key changes, so it never holds more than the ring does.
type macCache struct {
	cur   *keys.Key
	pools map[*keys.Key]*sync.Pool
}

func newPool(k *keys.Key) *sync.Pool {
	secret := k.Secret()
	return &sync.Pool{New: func() any { return hmac.New(sha256.New, secret) }}
}

// macs returns the cache for the ring's current key cur.
func (i *Issuer) macs(cur *keys.Key) *macCache {
	if c := i.cache.Load(); c != nil && c.cur == cur {
		return c
	}
	old := i.cache.Load()
	c := &macCache{cur: cur, pools: map[*keys.Key]*sync.Pool{}}
	for _, k := range i.ring.Verifying(i.now()) {
		if old != nil && old.pools[k] != nil {
			c.pools[k] = old.pools[k]
		} else {
			c.pools[k] = newPool(k)
		}
	}
	if c.pools[cur] == nil { // the ring rotated again while this was built
		c.pools[cur] = newPool(cur)
	}
	i.cache.Store(c)
	return c
}

// sum writes the truncated HMAC-SHA256 of body under k into out.
func (c *macCache) sum(k *keys.Key, body []byte, out *[sha256.Size]byte) []byte {
	p := c.pools[k]
	if p == nil {
		// A key the ring gained after this cache was built, such as one
		// restored by an operator: correct, just not pooled.
		copy(out[:], mac(k, body))
		return out[:macSize]
	}
	h := p.Get().(hash.Hash)
	h.Reset()
	h.Write(body)
	h.Sum(out[:0])
	p.Put(h)
	return out[:macSize]
}

// NewIssuer returns an issuer for one 32-byte key: a ring holding only that
// key, which never rotates on its own.
func NewIssuer(key []byte) (*Issuer, error) {
	return NewIssuerKeys(key)
}

// NewIssuerKeys returns an issuer for configured 32-byte keys, newest
// first: the first MACs new tokens and the rest only verify, with no
// expiry, so an operator rotates across restarts by prepending a new key
// and drops an old one once the tokens it MACed no longer matter.
func NewIssuerKeys(current []byte, previous ...[]byte) (*Issuer, error) {
	all := append([][]byte{current}, previous...)
	ks := make([]*keys.Key, len(all))
	for i, k := range all {
		if len(k) != KeySize {
			return nil, errors.New("token key must be 32 bytes")
		}
		var err error
		if ks[i], err = keys.FromSecret(keys.HS256, "", k, time.Time{}); err != nil {
			return nil, err
		}
	}
	r, err := keys.Configured(keys.Policy{}, time.Time{}, ks...)
	if err != nil {
		return nil, fmt.Errorf("token keys: %w", err)
	}
	return FromRing(r, nil)
}

// FromRing returns an issuer on r, which must hold HS256 keys. now is the
// clock that decides which retired keys still verify; nil means time.Now.
// Rotating r, by hand or through a keys.Scheduler, takes effect on the next
// Encode.
func FromRing(r *keys.Ring, now func() time.Time) (*Issuer, error) {
	if r == nil {
		return nil, errors.New("token: nil key ring")
	}
	if r.Alg() != keys.HS256 {
		return nil, fmt.Errorf("token: key ring holds %s keys, want %s", r.Alg(), keys.HS256)
	}
	if now == nil {
		now = time.Now
	}
	return &Issuer{ring: r, now: now}, nil
}

// Ring returns the issuer's key ring, for adding it to a keys.Set under
// keys.RingConsistency.
func (i *Issuer) Ring() *keys.Ring { return i.ring }

// RandomKey returns a fresh key from the system's secure random source.
func RandomKey() ([]byte, error) {
	k := make([]byte, KeySize)
	_, err := rand.Read(k)
	return k, err
}

// mac returns the HMAC-SHA256 of body under k. HS256 keys always sign, so
// the error is impossible.
func mac(k *keys.Key, body []byte) []byte {
	sum, _ := k.Sign(body)
	return sum
}

// Encode returns the token for rev, MACed with the ring's current key.
func (i *Issuer) Encode(rev store.Revision) string {
	raw := make([]byte, 0, rawSize)
	raw = append(raw, version)
	raw = binary.BigEndian.AppendUint64(raw, uint64(rev))
	cur := i.ring.Current()
	var out [sha256.Size]byte
	raw = append(raw, i.macs(cur).sum(cur, raw, &out)...)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// Decode verifies a token and returns its revision. The current key is
// tried first, so a token issued since the last rotation costs one MAC; a
// token that verifies under no key costs one MAC per key the ring accepts,
// at most keys.MaxPrevious+2.
func (i *Issuer) Decode(tok string) (store.Revision, error) {
	if len(tok) > base64.RawURLEncoding.EncodedLen(rawSize) {
		return 0, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) != rawSize || raw[0] != version {
		return 0, ErrInvalid
	}
	body, sum := raw[:9], raw[9:]
	cur := i.ring.Current()
	c := i.macs(cur)
	var out [sha256.Size]byte
	if !hmac.Equal(sum, c.sum(cur, body, &out)) {
		ok := false
		for _, k := range i.ring.Verifying(i.now()) {
			if k != cur && hmac.Equal(sum, c.sum(k, body, &out)) {
				ok = true
				break
			}
		}
		if !ok {
			return 0, ErrInvalid
		}
	}
	return store.Revision(binary.BigEndian.Uint64(raw[1:9])), nil
}
