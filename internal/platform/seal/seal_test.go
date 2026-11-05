package seal

import (
	"bytes"
	"encoding/base64"
	"errors"
	mrand "math/rand/v2"
	"strings"
	"testing"
)

func ring(t testing.TB, keys ...[]byte) *Keyring {
	t.Helper()
	kr, err := New(keys)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func TestRoundTripAndPurpose(t *testing.T) {
	kr := ring(t, RandomKey())
	s := kr.Seal("session", []byte("secret"))
	got, err := kr.Open("session", s)
	if err != nil || string(got) != "secret" {
		t.Fatalf("%q %v", got, err)
	}
	// A value sealed for one purpose can't be opened as another (e.g. a
	// logout token replayed as a session cookie).
	if _, err := kr.Open("login", s); !errors.Is(err, ErrInvalid) {
		t.Fatalf("purpose swap: %v", err)
	}
	if kr.Seal("session", []byte("secret")) == s {
		t.Fatal("sealing is deterministic; nonces must be random")
	}
	if got, err := kr.Open("p", kr.Seal("p", nil)); err != nil || len(got) != 0 {
		t.Fatal("empty plaintext")
	}
}

func TestRotation(t *testing.T) {
	oldKey, newKey := RandomKey(), RandomKey()
	before := ring(t, oldKey)
	during := ring(t, newKey, oldKey)
	after := ring(t, newKey)
	v := before.Seal("session", []byte("x"))
	if _, err := during.Open("session", v); err != nil {
		t.Fatalf("old cookie during rotation: %v", err)
	}
	// New cookies use the new key and open once the old key is gone.
	if _, err := after.Open("session", during.Seal("session", []byte("x"))); err != nil {
		t.Fatal(err)
	}
	// A cookie from a rotated-out key no longer opens.
	if _, err := after.Open("session", v); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rotated-out key: %v", err)
	}
}

func TestRejects(t *testing.T) {
	kr := ring(t, RandomKey())
	good := kr.Seal("p", []byte("hello"))
	raw, _ := base64.RawURLEncoding.DecodeString(good)
	wrongVersion := append([]byte{2}, raw[1:]...)
	cases := map[string]string{
		"empty":         "",
		"not base64":    "!!!",
		"padded":        good + "=",
		"short":         base64.RawURLEncoding.EncodeToString(raw[:overhead-1]),
		"wrong version": base64.RawURLEncoding.EncodeToString(wrongVersion),
		"too long":      strings.Repeat("A", MaxEncoded+1),
		"other ring":    ring(t, RandomKey()).Seal("p", []byte("hello")),
	}
	for name, v := range cases {
		if _, err := kr.Open("p", v); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNewValidation(t *testing.T) {
	k := RandomKey()
	if _, err := New(nil); err == nil {
		t.Error("no keys")
	}
	if _, err := New([][]byte{k[:16]}); err == nil {
		t.Error("short key")
	}
	if _, err := New([][]byte{k, k}); err == nil {
		t.Error("duplicate key")
	}
	many := make([][]byte, maxKeys+1)
	for i := range many {
		many[i] = RandomKey()
	}
	if _, err := New(many); err == nil {
		t.Error("too many keys")
	}
	defer func() {
		if recover() == nil {
			t.Error("empty purpose accepted")
		}
	}()
	ring(t, k).Seal("", nil)
}

// TestPropertyTamper: every single-bit change anywhere in a sealed value is
// rejected, and random plaintexts round-trip.
func TestPropertyTamper(t *testing.T) {
	kr := ring(t, RandomKey(), RandomKey())
	r := mrand.New(mrand.NewPCG(3, 4))
	for i := 0; i < 300; i++ {
		pt := make([]byte, r.IntN(200))
		for j := range pt {
			pt[j] = byte(r.Uint32())
		}
		s := kr.Seal("cookie", pt)
		got, err := kr.Open("cookie", s)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("round trip: %v", err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(s)
		pos := r.IntN(len(raw))
		raw[pos] ^= 1 << r.IntN(8)
		if _, err := kr.Open("cookie", base64.RawURLEncoding.EncodeToString(raw)); err == nil {
			t.Fatalf("bit flip at byte %d accepted", pos)
		}
	}
}

func FuzzOpen(f *testing.F) {
	kr := ring(f, RandomKey())
	seed := kr.Seal("p", []byte("x"))
	f.Add(seed)
	f.Add("AQ")
	f.Fuzz(func(t *testing.T, s string) {
		// Strict base64 has one encoding per value, so only the sealed
		// seed itself may open; anything else would be a forgery.
		if _, err := kr.Open("p", s); err == nil && s != seed {
			t.Fatalf("opened %q", s)
		}
	})
}

func BenchmarkSealOpen(b *testing.B) {
	kr := ring(b, RandomKey())
	pt := []byte("0123456789abcdef0123456789abcdef0123456789a")
	for b.Loop() {
		if _, err := kr.Open("session", kr.Seal("session", pt)); err != nil {
			b.Fatal(err)
		}
	}
}
