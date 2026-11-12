package identity

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/keys"
)

func ringAuth(t testing.TB, r *keys.Ring, now *time.Time) *Authenticator {
	t.Helper()
	a, err := New(Config{Ring: r, Issuer: "toolgate", Audience: "toolgate-gw",
		Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRingConfigErrors(t *testing.T) {
	hs, err := keys.NewRing(keys.HS256, keys.Policy{}, t0)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := keys.NewRing(keys.A256GCM, keys.Policy{}, t0)
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]Config{
		"keys and ring":       {Ring: hs, Keys: map[string][]byte{"k1": keyA}, ActiveKey: "k1", Issuer: "i", Audience: "a"},
		"active key and ring": {Ring: hs, ActiveKey: "k1", Issuer: "i", Audience: "a"},
		"wrong algorithm":     {Ring: gcm, Issuer: "i", Audience: "a"},
		"no issuer":           {Ring: hs, Audience: "a"},
		"no audience":         {Ring: hs, Issuer: "i"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The ring's current key signs; after a rotation a token from the old key
// verifies until its overlap ends, even with no prune, and a dropped key
// stops at once.
func TestRingRotation(t *testing.T) {
	now := t0
	p := keys.Policy{RotateEvery: time.Minute, Overlap: 2 * time.Minute}
	r, err := keys.NewRing(keys.HS256, p, now)
	if err != nil {
		t.Fatal(err)
	}
	a := ringAuth(t, r, &now)
	first := r.Current().ID()
	old, err := a.Mint("alice-bot", "alice", []string{"files:read"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := a.Authenticate(old); err != nil || id.KeyID != first || id.Method != "signed" || id.AgentID != "alice-bot" {
		t.Fatalf("%+v %v", id, err)
	}

	now = now.Add(time.Minute)
	if err := r.Rotate(now); err != nil {
		t.Fatal(err)
	}
	fresh, err := a.Mint("alice-bot", "alice", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := a.Authenticate(fresh); err != nil || id.KeyID != r.Current().ID() || id.KeyID == first {
		t.Fatalf("new token: %+v %v", id, err)
	}
	if id, err := a.Authenticate(old); err != nil || id.KeyID != first {
		t.Fatalf("old token inside the overlap: %+v %v", id, err)
	}

	now = now.Add(2 * time.Minute)
	if _, err := a.Authenticate(old); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old token after the overlap: %v", err)
	}

	if err := r.Rotate(now); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(fresh); err != nil {
		t.Fatalf("retired key inside its overlap: %v", err)
	}
	if err := r.Drop(r.Snapshot().Previous[0].Key.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(fresh); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("token of a dropped key: %v", err)
	}
}

// A token signed with the ring's next key, as a replica that rotated
// first would sign, verifies.
func TestRingNextKey(t *testing.T) {
	now := t0
	r, err := keys.NewRing(keys.HS256, keys.Policy{}, now)
	if err != nil {
		t.Fatal(err)
	}
	ahead, err := keys.Configured(keys.Policy{}, now, r.Next())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := ringAuth(t, ahead, &now).Mint("bob-bot", "", nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := ringAuth(t, r, &now).Authenticate(tok); err != nil || id.KeyID != r.Next().ID() {
		t.Fatalf("%+v %v", id, err)
	}
}

// TOOLGATE_SIGNING_KEYS moved onto a ring keep their names, so tokens the
// list signed verify on the ring and the other way round.
func TestRingFromSigningKeys(t *testing.T) {
	now := t0
	list := newAuth(t, &now) // k1=keyA, k2=keyB, k2 active
	ks, err := keys.ParseSecretList(keys.HS256, "k2="+hex.EncodeToString(keyB)+",k1="+hex.EncodeToString(keyA), now)
	if err != nil {
		t.Fatal(err)
	}
	r, err := keys.Configured(keys.Policy{}, now, ks...)
	if err != nil {
		t.Fatal(err)
	}
	onRing := ringAuth(t, r, &now)
	fromList, err := list.Mint("alice-bot", "alice", nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := onRing.Authenticate(fromList); err != nil || id.KeyID != "k2" {
		t.Fatalf("list token on the ring: %+v %v", id, err)
	}
	fromRing, err := onRing.Mint("alice-bot", "alice", nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if fromRing[:strings.IndexByte(fromRing, '.')] != fromList[:strings.IndexByte(fromList, '.')] {
		t.Fatal("the ring signs with a different header")
	}
	if id, err := list.Authenticate(fromRing); err != nil || id.KeyID != "k2" {
		t.Fatalf("ring token with the list: %+v %v", id, err)
	}
	// The retired k1 verifies on the ring with no expiry.
	k1Only, err := New(Config{Keys: map[string][]byte{"k1": keyA}, ActiveKey: "k1", Issuer: "toolgate", Audience: "toolgate-gw",
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	tok1, err := k1Only.Mint("alice-bot", "", nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := onRing.Authenticate(tok1); err != nil || id.KeyID != "k1" {
		t.Fatalf("retired configured key: %+v %v", id, err)
	}
}
