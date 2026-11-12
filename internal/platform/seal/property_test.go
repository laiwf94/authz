package seal

import (
	"bytes"
	"encoding/base64"
	"errors"
	mrand "math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/keys"
)

// maxPlaintext is the longest plaintext whose sealed form still fits in
// MaxEncoded.
const maxPlaintext = MaxEncoded/4*3 - overhead

// gen draws the inputs of one property case from a seeded source, so a
// failure names the seed that reproduces it.
type gen struct{ r *mrand.Rand }

func newGen(seed uint64) gen { return gen{mrand.New(mrand.NewPCG(seed, seed^0x5ea1))} }

func (g gen) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(g.r.UintN(256))
	}
	return b
}

// plaintext is empty, short, or anything up to the limit, biased to the
// edges.
func (g gen) plaintext() []byte {
	switch g.r.IntN(4) {
	case 0:
		return g.bytes(g.r.IntN(3))
	case 1:
		return g.bytes(maxPlaintext - g.r.IntN(3))
	default:
		return g.bytes(g.r.IntN(maxPlaintext + 1))
	}
}

// purpose is 1 to 64 arbitrary bytes.
func (g gen) purpose() string { return string(g.bytes(1 + g.r.IntN(maxPurpose))) }

// keyring is a list of 1 to 16 keys, or a ring with retired keys.
func (g gen) keyring(t *testing.T) *Keyring {
	n := 1 + g.r.IntN(maxKeys)
	ks := make([][]byte, n)
	for i := range ks {
		ks[i] = g.bytes(KeySize)
	}
	if g.r.IntN(2) == 0 {
		return ring(t, ks...)
	}
	rk := make([]*keys.Key, n)
	for i, k := range ks {
		var err error
		if rk[i], err = keys.FromSecret(keys.A256GCM, "", k, t0); err != nil {
			t.Fatal(err)
		}
	}
	r, err := keys.Configured(keys.Policy{}, t0, rk...)
	if err != nil {
		t.Fatal(err)
	}
	return fromRing(t, r, nil)
}

const propertyCases = 300

// Every plaintext up to the limit, under every purpose and key ring,
// opens to itself, and its sealed form is cookie-safe base64url of
// exactly the expected length.
func TestPropertyRoundTrip(t *testing.T) {
	for seed := uint64(0); seed < propertyCases; seed++ {
		g := newGen(seed)
		kr, p, pt := g.keyring(t), g.purpose(), g.plaintext()
		s := kr.Seal(p, pt)
		if want := base64.RawURLEncoding.EncodedLen(overhead + len(pt)); len(s) != want {
			t.Fatalf("seed %d: sealed %d bytes into %d characters, want %d", seed, len(pt), len(s), want)
		}
		if len(s) > MaxEncoded {
			t.Fatalf("seed %d: %d characters, over MaxEncoded", seed, len(s))
		}
		if strings.ContainsFunc(s, func(r rune) bool {
			return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_')
		}) {
			t.Fatalf("seed %d: %q is not base64url", seed, s)
		}
		got, err := kr.Open(p, s)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("seed %d: round trip of %d bytes: %v", seed, len(pt), err)
		}
		// Sealing again gives a different value that opens the same.
		s2 := kr.Seal(p, pt)
		if s2 == s {
			t.Fatalf("seed %d: sealing is deterministic", seed)
		}
		if got, err := kr.Open(p, s2); err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("seed %d: second seal: %v", seed, err)
		}
	}
}

// A sealed value opens only for the purpose and keys it was sealed with:
// any other purpose, or a list or ring without its key, refuses it with
// ErrInvalid.
func TestPropertyBinding(t *testing.T) {
	for seed := uint64(0); seed < propertyCases; seed++ {
		g := newGen(seed)
		kr, p, pt := g.keyring(t), g.purpose(), g.bytes(g.r.IntN(256))
		s := kr.Seal(p, pt)
		other := g.purpose()
		if other != p {
			if _, err := kr.Open(other, s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("seed %d: opened under another purpose: %v", seed, err)
			}
		}
		if _, err := g.keyring(t).Open(p, s); !errors.Is(err, ErrInvalid) {
			t.Fatalf("seed %d: opened with other keys: %v", seed, err)
		}
	}
}

// Any change to a sealed value is refused, under lists and rings: flipping any bit, cutting or
// extending it, or changing its version byte. ErrInvalid is the only
// error, and nothing panics.
func TestPropertyMutations(t *testing.T) {
	for seed := uint64(0); seed < propertyCases; seed++ {
		g := newGen(seed)
		kr, p := g.keyring(t), g.purpose()
		pt := g.bytes(g.r.IntN(512))
		raw, err := base64.RawURLEncoding.DecodeString(kr.Seal(p, pt))
		if err != nil {
			t.Fatal(err)
		}
		mutated := map[string][]byte{}
		flip := append([]byte(nil), raw...)
		i := g.r.IntN(len(flip))
		flip[i] ^= 1 << g.r.UintN(8)
		mutated["bit flip"] = flip
		mutated["cut"] = raw[:g.r.IntN(len(raw))]
		mutated["extended"] = append(append([]byte(nil), raw...), g.bytes(1+g.r.IntN(16))...)
		ver := append([]byte(nil), raw...)
		ver[0] = byte(2 + g.r.IntN(254))
		mutated["version"] = ver
		for name, m := range mutated {
			_, err := kr.Open(p, base64.RawURLEncoding.EncodeToString(m))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("seed %d: %s (byte %d) accepted: %v", seed, name, i, err)
			}
		}
	}
}

// Arbitrary strings never open and never panic, whatever their length or
// alphabet.
func TestPropertyGarbage(t *testing.T) {
	kr := ring(t, RandomKey())
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/.\r\n "
	for seed := uint64(0); seed < 2000; seed++ {
		g := newGen(seed)
		n := g.r.IntN(MaxEncoded + 64)
		var b strings.Builder
		for range n {
			b.WriteByte(alphabet[g.r.IntN(len(alphabet))])
		}
		if _, err := kr.Open("p", b.String()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("seed %d: %d characters opened: %v", seed, n, err)
		}
	}
}

// A plaintext one byte over the limit seals to a value Open refuses by
// length, so nothing sealed is ever silently cut.
func TestPropertyLimit(t *testing.T) {
	kr := ring(t, RandomKey())
	at := kr.Seal("p", make([]byte, maxPlaintext))
	if len(at) > MaxEncoded {
		t.Fatalf("limit plaintext seals to %d characters", len(at))
	}
	if _, err := kr.Open("p", at); err != nil {
		t.Fatal(err)
	}
	over := kr.Seal("p", make([]byte, maxPlaintext+3))
	if _, err := kr.Open("p", over); !errors.Is(err, ErrInvalid) {
		t.Fatalf("value over MaxEncoded opened: %v", err)
	}
}

// The same keys give the same answers from a list and from a ring: every
// value one seals, the other opens.
func TestPropertyListRingAgree(t *testing.T) {
	for seed := uint64(0); seed < 100; seed++ {
		g := newGen(seed)
		n := 1 + g.r.IntN(maxKeys)
		ks := make([][]byte, n)
		rk := make([]*keys.Key, n)
		for i := range ks {
			ks[i] = g.bytes(KeySize)
			var err error
			if rk[i], err = keys.FromSecret(keys.A256GCM, "", ks[i], time.Time{}); err != nil {
				t.Fatal(err)
			}
		}
		r, err := keys.Configured(keys.Policy{}, t0, rk...)
		if err != nil {
			t.Fatal(err)
		}
		list, onRing := ring(t, ks...), fromRing(t, r, nil)
		p, pt := g.purpose(), g.bytes(g.r.IntN(256))
		// A value sealed by any single key of the list.
		one := ring(t, ks[g.r.IntN(n)]).Seal(p, pt)
		for _, kr := range []*Keyring{list, onRing} {
			for _, v := range []string{list.Seal(p, pt), onRing.Seal(p, pt), one} {
				if got, err := kr.Open(p, v); err != nil || !bytes.Equal(got, pt) {
					t.Fatalf("seed %d: list and ring disagree: %v", seed, err)
				}
			}
		}
	}
}
