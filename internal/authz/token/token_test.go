package token

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/laiwf94/authz/internal/authz/store"
)

func issuer(t *testing.T, b byte) *Issuer {
	t.Helper()
	i, err := NewIssuer(bytes.Repeat([]byte{b}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestRoundTrip(t *testing.T) {
	i := issuer(t, 1)
	for _, rev := range []store.Revision{0, 1, 42, 1 << 40, ^store.Revision(0)} {
		got, err := i.Decode(i.Encode(rev))
		if err != nil || got != rev {
			t.Fatalf("rev %d: got %d, %v", rev, got, err)
		}
	}
}

func TestRejectsForgery(t *testing.T) {
	a, b := issuer(t, 1), issuer(t, 2)
	tok := a.Encode(7)
	if _, err := b.Decode(tok); !errors.Is(err, ErrInvalid) {
		t.Fatal("token from another key accepted")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	raw[8] ^= 1 // change the revision, keep the MAC
	if _, err := a.Decode(base64.RawURLEncoding.EncodeToString(raw)); !errors.Is(err, ErrInvalid) {
		t.Fatal("tampered revision accepted")
	}
	raw[8] ^= 1
	raw[0] = 9
	if _, err := a.Decode(base64.RawURLEncoding.EncodeToString(raw)); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown version accepted")
	}
	for _, bad := range []string{"", "!!!", "AAAA", tok + "AAAA", tok[:len(tok)-2]} {
		if _, err := a.Decode(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestKeys(t *testing.T) {
	if _, err := NewIssuer(make([]byte, 16)); err == nil {
		t.Fatal("short key accepted")
	}
	k1, err := RandomKey()
	if err != nil || len(k1) != KeySize {
		t.Fatal(err)
	}
	k2, _ := RandomKey()
	if bytes.Equal(k1, k2) {
		t.Fatal("random keys repeat")
	}
	// The issuer keeps its own copy of the key.
	i, _ := NewIssuer(k1)
	tok := i.Encode(5)
	k1[0] ^= 0xff
	if _, err := i.Decode(tok); err != nil {
		t.Fatal("issuer shares the caller's key slice")
	}
}
