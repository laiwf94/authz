package session

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/policy"
)

func endedIDs(es []Ended) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.ID
	}
	return out
}

func TestEndProviderSessions(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, "", c)
	bob := policy.Identity{Provider: "corp", Subject: "bob"}
	partner := policy.Identity{Provider: "partner", Subject: "alice"}
	_, a1, _ := s.CreateWith(alice(), Extra{SID: "sid-a"})
	_, a2, _ := s.CreateWith(alice(), Extra{SID: "sid-a"}) // a second app tab of the same provider session
	_, a3, _ := s.CreateWith(alice(), Extra{SID: "sid-a2"})
	_, a4, _ := s.CreateWith(alice(), Extra{}) // no sid
	c.add(time.Second) // List is oldest first
	_, b1, _ := s.CreateWith(bob, Extra{SID: "sid-b"})
	c.add(time.Second)
	_, p1, _ := s.CreateWith(partner, Extra{SID: "sid-a"}) // same handle at another provider
	if a1.SID() != "sid-a" || a4.SID() != "" {
		t.Fatalf("sid %q %q", a1.SID(), a4.SID())
	}

	// Nothing, or the wrong provider or subject, ends nothing.
	for _, q := range [][3]string{{"corp", "", ""}, {"", "alice", "sid-a"}, {"corp", "bob", "sid-a"}, {"corp", "", "sid-none"}, {"other", "alice", ""}} {
		if got, err := s.EndProviderSessions(q[0], q[1], q[2]); err != nil || len(got) != 0 {
			t.Fatalf("%q: %v %v", q, got, err)
		}
	}
	if s.Len() != 6 {
		t.Fatalf("len %d", s.Len())
	}

	// sid alone: every session of that provider session, only at corp.
	got, err := s.EndProviderSessions("corp", "", "sid-a")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{a1.ID, a2.ID}
	if a2.ID < a1.ID {
		want = []string{a2.ID, a1.ID}
	}
	if fmt.Sprint(endedIDs(got)) != fmt.Sprint(want) || got[0].Subject != "alice" {
		t.Fatalf("sid-a: %+v", got)
	}
	// Ended sessions are gone and stay gone; a replay finds nothing.
	if got, _ := s.EndProviderSessions("corp", "", "sid-a"); len(got) != 0 {
		t.Fatalf("again: %+v", got)
	}
	if l := s.List("alice", 0); len(l) != 3 {
		t.Fatalf("left: %+v", l)
	}

	// sub and sid: both must match.
	got, _ = s.EndProviderSessions("corp", "alice", "sid-a2")
	if fmt.Sprint(endedIDs(got)) != fmt.Sprint([]string{a3.ID}) {
		t.Fatalf("sub+sid: %+v", got)
	}
	// sub alone: every remaining session of the user at corp, with or
	// without a sid; partner's session with the same subject stays.
	_, a5, _ := s.CreateWith(alice(), Extra{SID: "sid-a5"})
	got, _ = s.EndProviderSessions("corp", "alice", "")
	want = []string{a4.ID, a5.ID}
	if a5.ID < a4.ID {
		want = []string{a5.ID, a4.ID}
	}
	if fmt.Sprint(endedIDs(got)) != fmt.Sprint(want) {
		t.Fatalf("sub: %+v", got)
	}
	left := s.List("", 0)
	if len(left) != 2 || left[0].ID != b1.ID || left[1].ID != p1.ID {
		t.Fatalf("left: %+v", left)
	}
	// The indexes hold nothing for ended sessions.
	s.mu.Lock()
	nSID, nSub := len(s.bySID), len(s.bySubject)
	s.mu.Unlock()
	if nSID != 2 || nSub != 2 {
		t.Fatalf("indexes: %d sid keys, %d subject keys", nSID, nSub)
	}
}

func TestSIDValidation(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, "", c)
	for _, sid := range []string{strings.Repeat("s", MaxSIDBytes+1), "a b", "a\nb", "\x7f"} {
		if _, _, err := s.CreateWith(alice(), Extra{SID: sid}); err != ErrBadSID {
			t.Errorf("%q: %v", sid, err)
		}
	}
	if _, _, err := s.CreateWith(alice(), Extra{SID: strings.Repeat("s", MaxSIDBytes)}); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatalf("len %d", s.Len())
	}
}

// The sid survives a restart and a compaction, and so does a back-channel
// logout.
func TestSIDPersists(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	path := filepath.Join(t.TempDir(), "sessions.log")
	s, err := Open(Options{Path: path, IdleTimeout: time.Hour, AbsoluteTimeout: 8 * time.Hour, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	_, a, _ := s.CreateWith(alice(), Extra{SID: "sid-a"})
	c.add(time.Second) // List is oldest first
	_, b, _ := s.CreateWith(alice(), Extra{SID: "sid-b", Refresh: "sealed"})
	_, x, _ := s.CreateWith(alice(), Extra{SID: "sid-x"})
	if _, err := s.EndProviderSessions("corp", "", "sid-x"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"sid":"sid-a"`) {
		t.Fatalf("log: %s", raw)
	}
	// Open compacts: the create records come back with their sid.
	for round := 0; round < 2; round++ {
		s, err = Open(Options{Path: path, IdleTimeout: time.Hour, AbsoluteTimeout: 8 * time.Hour, Now: c.now})
		if err != nil {
			t.Fatal(err)
		}
		if l := s.List("", 0); len(l) != 2 || l[0].ID != a.ID || l[0].SID() != "sid-a" || l[1].SID() != "sid-b" {
			t.Fatalf("round %d: %+v", round, l)
		}
		if got, _ := s.EndProviderSessions("corp", "", "sid-x"); len(got) != 0 {
			t.Fatalf("round %d: the ended session came back: %+v", round, got)
		}
		s.Close()
	}
	s, _ = Open(Options{Path: path, IdleTimeout: time.Hour, AbsoluteTimeout: 8 * time.Hour, Now: c.now})
	defer s.Close()
	if got, _ := s.EndProviderSessions("corp", "alice", "sid-b"); len(got) != 1 || got[0].ID != b.ID {
		t.Fatalf("after restart: %+v", got)
	}
	_ = x
}

// A sid is never shown: not in the session's JSON, which is what the admin
// API lists.
func TestSIDNotListed(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, "", c)
	_, sess, _ := s.CreateWith(alice(), Extra{SID: "sid-secret-handle"})
	for _, l := range s.List("", 0) {
		b, _ := json.Marshal(l)
		if strings.Contains(string(b), "sid-secret-handle") {
			t.Fatalf("listed: %s", b)
		}
	}
	_ = sess
}

// A damaged log with a malformed sid is refused, not loaded.
func TestLogRejectsBadSID(t *testing.T) {
	bad := []byte(`{"op":"create","session":{"id":"0123456789abcdef0123456789abcdef","identity":{"provider":"corp","sub":"a"},"created_at":"2026-01-01T00:00:00Z","last_seen_at":"2026-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z"},"sid":"a b"}`)
	good := []byte(strings.Replace(string(bad), `"sid":"a b"`, `"sid":"ab"`, 1))
	if _, err := parseLine([]byte(fmt.Sprintf("%08x %s\n", crc32.Checksum(good, castagnoli), good))); err != nil {
		t.Fatalf("refused a good line: %v", err)
	}
	if _, err := parseLine([]byte(fmt.Sprintf("%08x %s\n", crc32.Checksum(bad, castagnoli), bad))); err == nil {
		t.Fatal("accepted a malformed sid")
	}
}

// Ending sessions by sid among many is a map lookup, not a scan.
func BenchmarkEndProviderSessionsBySID(b *testing.B) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s, _ := Open(Options{IdleTimeout: time.Hour, AbsoluteTimeout: 8 * time.Hour, Now: c.now})
	for i := range 100_000 {
		s.CreateWith(policy.Identity{Provider: "corp", Subject: fmt.Sprint("u", i)}, Extra{SID: fmt.Sprint("sid-", i)})
	}
	i := 0
	for b.Loop() {
		s.EndProviderSessions("corp", "", fmt.Sprint("sid-missing-", i))
		i++
	}
}
