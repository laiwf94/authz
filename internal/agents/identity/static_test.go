package identity

import (
	"crypto/sha256"
	"errors"
	"testing"
)

type fakeStatic struct {
	issued  map[[sha256.Size]byte][2]string // digest -> agent, key id
	revoked map[[sha256.Size]byte]bool
}

func (f fakeStatic) Issued(sum [sha256.Size]byte) (string, string, bool) {
	v, ok := f.issued[sum]
	return v[0], v[1], ok
}
func (f fakeStatic) ConfigActive(sum [sha256.Size]byte) bool { return !f.revoked[sum] }

func TestStaticSource(t *testing.T) {
	const (
		alice   = "tgk_alice_static_0123456789abcdefghijklmnop"
		bob     = "tgk_bob_static_0123456789abcdefghijklmnopqr"
		issued  = "tgk_issued_0123456789abcdefghijklmnopqrstu"
		orphan  = "tgk_orphan_0123456789abcdefghijklmnopqrstu"
		unknown = "tgk_unknown_0123456789abcdefghijklmnopqrst"
	)
	plain, err := New(Config{Agents: []Agent{
		{ID: "alice-bot", Owner: "alice", Scopes: []string{"files:read"}, TokenSHA256: HashToken(alice)},
		{ID: "bob-bot", Owner: "bob", TokenSHA256: HashToken(bob)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	src := fakeStatic{
		issued: map[[sha256.Size]byte][2]string{
			HashToken(issued): {"alice-bot", "0011223344556677"},
			HashToken(orphan): {"carol-bot", "8899aabbccddeeff"},
		},
		revoked: map[[sha256.Size]byte]bool{HashToken(bob): true},
	}
	a := plain.WithStatic(src)

	id, err := a.Authenticate(issued)
	if err != nil || id.AgentID != "alice-bot" || id.Owner != "alice" || len(id.Scopes) != 1 || id.Method != "static" || id.KeyID != "0011223344556677" {
		t.Fatalf("issued key: %+v %v", id, err)
	}
	if id, err := a.Authenticate(alice); err != nil || id.AgentID != "alice-bot" || id.KeyID != "" {
		t.Fatalf("configured key: %+v %v", id, err)
	}
	for name, tok := range map[string]string{"revoked": bob, "orphan": orphan, "unknown": unknown} {
		if _, err := a.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s key: %v", name, err)
		}
	}
	// The original authenticator and a copy without the source are unchanged.
	for _, b := range []*Authenticator{plain, a.WithStatic(nil)} {
		if _, err := b.Authenticate(bob); err != nil {
			t.Fatalf("without the source the configured key is refused: %v", err)
		}
		if _, err := b.Authenticate(issued); err == nil {
			t.Fatal("without the source an issued key verifies")
		}
	}
}
