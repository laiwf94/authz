package session

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/policy"
)

func aliceWithClaims() policy.Identity {
	id := alice()
	id.Claims = map[string][]string{"department": {"eng", "ops"}, "tenant": {"acme"}}
	return id
}

// TestClaimsSurviveRestartAndCompaction: the claims a sign-in kept for
// claim conditions are written with the session and read back unchanged
// after a restart, and after the compaction that follows it.
func TestClaimsSurviveRestartAndCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.log")
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, path, c)
	secret, _, err := s.CreateWith(aliceWithClaims(), Extra{})
	if err != nil {
		t.Fatal(err)
	}
	plainSecret, _, err := s.CreateWith(alice(), Extra{})
	if err != nil {
		t.Fatal(err)
	}
	check := func(s *Store, step string) {
		t.Helper()
		got, err := s.Lookup(secret)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		if !reflect.DeepEqual(got.Identity, aliceWithClaims()) {
			t.Fatalf("%s: identity %+v", step, got.Identity)
		}
		p, err := s.Lookup(plainSecret)
		if err != nil || p.Identity.Claims != nil {
			t.Fatalf("%s: plain session %+v %v", step, p.Identity, err)
		}
	}
	check(s, "created")
	s.Close()
	s2 := open(t, path, c)
	check(s2, "reopen")
	raw, _ := os.ReadFile(path)
	if n := strings.Count(string(raw), "\n"); n != 2 || strings.Count(string(raw), `"claims":{"department":["eng","ops"],"tenant":["acme"]}`) != 1 {
		t.Fatalf("compacted log:\n%s", raw)
	}
	s2.Close()
	check(open(t, path, c), "second reopen")
}

// TestSessionCopiesShareNothing: every session the store hands out is a
// deep copy, so a caller changing its claims or groups changes neither
// the store's session nor another caller's copy.
func TestSessionCopiesShareNothing(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, filepath.Join(t.TempDir(), "s.log"), c)
	id := aliceWithClaims()
	secret, created, err := s.CreateWith(id, Extra{})
	if err != nil {
		t.Fatal(err)
	}
	// The caller's identity is not the store's either.
	id.Claims["tenant"][0] = "caller"
	id.Groups[0] = "caller"
	created.Identity.Claims["tenant"][0] = "created"
	got, _ := s.Get(created.ID)
	got.Identity.Claims["tenant"][0] = "get"
	got.Identity.Claims["extra"] = []string{"x"}
	got.Identity.Groups[0] = "get"
	looked, _ := s.Lookup(secret)
	looked.Identity.Claims["department"][1] = "lookup"
	for _, l := range [][]Session{s.List("", 0), s.UserSessions("corp", "alice")} {
		if len(l) != 1 {
			t.Fatalf("listed %d sessions", len(l))
		}
		l[0].Identity.Claims["tenant"][0] = "list"
	}
	final, _ := s.Get(created.ID)
	if !reflect.DeepEqual(final.Identity, aliceWithClaims()) {
		t.Fatalf("the store's session changed through a copy: %+v", final.Identity)
	}

	// Copies read concurrently with writes to other copies (run with -race).
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				g, _ := s.Get(created.ID)
				g.Identity.Claims["tenant"][0] = "racer"
			}
		}()
	}
	wg.Wait()
	if final, _ := s.Get(created.ID); final.Identity.Claims["tenant"][0] != "acme" {
		t.Fatal("a racing copy changed the store")
	}
}

func TestClaimsRefused(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, filepath.Join(t.TempDir(), "s.log"), c)
	for name, claims := range map[string]map[string][]string{
		"builtin name": {"groups": {"x"}},
		"empty value":  {"a": {""}},
		"no values":    {"a": {}},
		"long value":   {"a": {strings.Repeat("v", policy.MaxClaimValueBytes+1)}},
		"bad UTF-8":    {"a": {"\xff"}},
	} {
		id := alice()
		id.Claims = claims
		if _, _, err := s.CreateWith(id, Extra{}); !errors.Is(err, ErrBadClaims) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := alice()
	bad.Claims = map[string][]string{"a": {"x", "x"}}
	sess := &Session{ID: strings.Repeat("a", 32), Identity: bad, CreatedAt: time.Unix(100, 0), LastSeen: time.Unix(100, 0),
		ExpiresAt: time.Unix(10_000, 0)}
	if err := validate(record{Op: opCreate, Session: sess}); err == nil {
		t.Error("a create record with repeated claim values is accepted on replay")
	}
	sess.Identity = aliceWithClaims()
	if err := validate(record{Op: opCreate, Session: sess}); err != nil {
		t.Fatal(err)
	}
}
