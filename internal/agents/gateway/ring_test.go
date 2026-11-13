package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/platform/keys"
)

// NewRingAuthenticator signs with the ring's current key and keeps
// verifying what a retired key signed after the ring rotates under it.
func TestNewRingAuthenticator(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	ring, err := keys.NewRing(keys.HS256, keys.Policy{RotateEvery: time.Hour, Overlap: 2 * time.Hour}, now)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := e.gw.cfg.NewRingAuthenticator(ring)
	if err != nil {
		t.Fatal(err)
	}
	old, err := auth.Mint("ci-bot", "ops", []string{"files:read"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	oldKid := ring.Current().ID()
	if err := ring.Rotate(now); err != nil {
		t.Fatal(err)
	}
	fresh, err := auth.Mint("ci-bot", "ops", nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"before the rotation": old, "after it": fresh} {
		id, err := auth.Authenticate(tok)
		if err != nil || id.AgentID != "ci-bot" || id.Method != "signed" {
			t.Fatalf("%s: %+v %v", name, id, err)
		}
	}
	if id, _ := auth.Authenticate(old); id.KeyID != oldKid {
		t.Fatalf("old token verified by %s, want %s", id.KeyID, oldKid)
	}
	// The agents config's issuer, audience and max TTL apply.
	if _, err := auth.Mint("ci-bot", "", nil, 2*time.Hour); err == nil {
		t.Fatal("a token longer than max_ttl_seconds was minted")
	}
	if e.gw.cfg.MaxTokenTTL() != time.Hour {
		t.Fatalf("MaxTokenTTL %s", e.gw.cfg.MaxTokenTTL())
	}
	// Static keys keep working beside the ring.
	if id, err := auth.Authenticate(aliceKey); err != nil || id.AgentID != "alice-bot" {
		t.Fatalf("static key: %+v %v", id, err)
	}

	// No ring: static keys only, and Mint refuses.
	static, err := e.gw.cfg.NewRingAuthenticator(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := static.Mint("ci-bot", "", nil, time.Minute); err == nil {
		t.Fatal("minted without a ring")
	}
	if _, err := static.Authenticate(fresh); err == nil {
		t.Fatal("a signed token verified without a ring")
	}

	// A ring needs the tokens section, and an HS256 ring.
	c := *e.gw.cfg
	c.Tokens = nil
	if _, err := c.NewRingAuthenticator(ring); err == nil || !strings.Contains(err.Error(), "no tokens section") {
		t.Fatalf("ring without a tokens section: %v", err)
	}
	if c.MaxTokenTTL() != identity.DefaultMaxTTL {
		t.Fatalf("MaxTokenTTL without tokens: %s", c.MaxTokenTTL())
	}
	es, _ := keys.NewRing(keys.ES256, keys.Policy{}, now)
	if _, err := e.gw.cfg.NewRingAuthenticator(es); err == nil {
		t.Fatal("an ES256 ring was accepted")
	}
}
