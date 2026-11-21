package session

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/policy"
)

// TestConsistencyToken: a session keeps the token of its newest
// relationship check, in memory, and never moves back to an older one.
func TestConsistencyToken(t *testing.T) {
	now := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	s, err := Open(Options{Path: t.TempDir() + "/sessions.log", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	secret, sess, err := s.Create(policy.Identity{Provider: "corp", Subject: "alice"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if sess.ConsistencyToken() != "" {
		t.Fatal("a new session has a token")
	}
	if !s.SetConsistency(sess.ID, 5, "t5") {
		t.Fatal("the first token was not kept")
	}
	for _, c := range []struct {
		rev  uint64
		tok  string
		kept bool
	}{
		{5, "t5b", false}, // the same revision changes nothing
		{4, "t4", false},  // an older one is ignored
		{0, "t0", false},
		{7, "", false}, // no token
		{8, strings.Repeat("x", MaxConsistencyTokenBytes+1), false},
		{9, "t9", true},
	} {
		if got := s.SetConsistency(sess.ID, c.rev, c.tok); got != c.kept {
			t.Errorf("SetConsistency(%d, %.8q) = %v, want %v", c.rev, c.tok, got, c.kept)
		}
	}
	got, err := s.Lookup(secret)
	if err != nil || got.ConsistencyToken() != "t9" {
		t.Fatalf("Lookup: %v %q", err, got.ConsistencyToken())
	}
	// Concurrent checks finishing in any order leave the newest.
	var wg sync.WaitGroup
	for rev := uint64(10); rev < 200; rev++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.SetConsistency(sess.ID, rev, "t"+strings.Repeat("r", int(rev%7))+string(rune('a'+rev%26)))
		}()
	}
	wg.Wait()
	if !s.SetConsistency(sess.ID, 200, "t200") {
		t.Fatal("a newer token after the race was refused")
	}
	if got, _ := s.Lookup(secret); got.ConsistencyToken() != "t200" {
		t.Fatalf("after the race: %q", got.ConsistencyToken())
	}
	// It is a cache: a restart starts without it, and an ended session
	// keeps nothing.
	s.Close()
	s, err = Open(Options{Path: s.opts.Path, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, err := s.Lookup(secret); err != nil || got.ConsistencyToken() != "" {
		t.Fatalf("after a restart: %v %q", err, got.ConsistencyToken())
	}
	if ok, err := s.Revoke(sess.ID); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.SetConsistency(sess.ID, 300, "t300") || s.SetConsistency("nope", 1, "t") {
		t.Fatal("an ended or unknown session kept a token")
	}
}
