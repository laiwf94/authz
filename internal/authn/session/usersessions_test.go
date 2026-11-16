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

func TestDeviceValidation(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, "", c)
	for _, e := range []Extra{
		{Device: strings.Repeat("d", MaxDeviceBytes+1)},
		{Device: "Firefox\non Linux"},
		{Device: "café"},
		{IP: "not-an-ip"},
		{IP: "::ffff:192.0.2.1"}, // not canonical: callers unmap first
		{IP: "2001:DB8::1"},
		{IP: "192.0.2.1:443"},
		{IP: "fe80::1%eth0"},
	} {
		if _, _, err := s.CreateWith(alice(), e); err != ErrBadDevice {
			t.Errorf("%+v: %v", e, err)
		}
	}
	for _, e := range []Extra{{}, {Device: strings.Repeat("d", MaxDeviceBytes), IP: "192.0.2.1"}, {IP: "2001:db8::1"}} {
		_, sess, err := s.CreateWith(alice(), e)
		if err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
		if sess.Device() != e.Device || sess.IP() != e.IP {
			t.Fatalf("%+v: got %q %q", e, sess.Device(), sess.IP())
		}
	}
	if s.Len() != 3 {
		t.Fatalf("len %d", s.Len())
	}
}

func TestUserSessions(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, "", c)
	secret1, a1, _ := s.CreateWith(alice(), Extra{Device: "Firefox on Linux", IP: "192.0.2.1"})
	c.add(time.Second)
	_, a2, _ := s.CreateWith(alice(), Extra{Device: "Safari on iOS", IP: "2001:db8::1"})
	_, _, _ = s.CreateWith(policy.Identity{Provider: "partner", Subject: "alice"}, Extra{})
	_, _, _ = s.CreateWith(policy.Identity{Provider: "corp", Subject: "bob"}, Extra{})
	c.add(2 * time.Second)
	if _, err := s.Lookup(secret1); err != nil { // a1 is now the most recently used
		t.Fatal(err)
	}
	got := s.UserSessions("corp", "alice")
	if len(got) != 2 || got[0].ID != a1.ID || got[1].ID != a2.ID {
		t.Fatalf("%+v", got)
	}
	if got[0].Device() != "Firefox on Linux" || got[0].IP() != "192.0.2.1" || got[1].Device() != "Safari on iOS" ||
		!got[0].LastSeen.Equal(c.now()) {
		t.Fatalf("%+v", got)
	}
	if got := s.UserSessions("corp", "nobody"); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
	// Expired sessions are not listed.
	c.add(time.Hour)
	if got := s.UserSessions("corp", "alice"); len(got) != 0 {
		t.Fatalf("expired listed: %+v", got)
	}
}

// Same last use: id order, so the page is stable.
func TestUserSessionsTieOrder(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, "", c)
	for range 5 {
		s.CreateWith(alice(), Extra{})
	}
	got := s.UserSessions("corp", "alice")
	for i := 1; i < len(got); i++ {
		if got[i-1].ID > got[i].ID {
			t.Fatalf("order %d: %s > %s", i, got[i-1].ID, got[i].ID)
		}
	}
	if len(got) != 5 {
		t.Fatalf("len %d", len(got))
	}
}

func TestRevokeUser(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	path := filepath.Join(t.TempDir(), "sessions.log")
	s, err := Open(Options{Path: path, IdleTimeout: time.Hour, AbsoluteTimeout: 8 * time.Hour, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	secret, a, _ := s.CreateWith(alice(), Extra{})
	_, b, _ := s.CreateWith(policy.Identity{Provider: "corp", Subject: "bob"}, Extra{})
	_, p, _ := s.CreateWith(policy.Identity{Provider: "partner", Subject: "alice"}, Extra{})

	// Another user's session, or the same subject at another provider, is
	// not alice's to end.
	for _, q := range [][3]string{{"corp", "alice", b.ID}, {"corp", "alice", p.ID}, {"partner", "alice", a.ID},
		{"corp", "alice", strings.Repeat("0", 32)}} {
		if ok, err := s.RevokeUser(q[0], q[1], q[2]); ok || err != nil {
			t.Fatalf("%q: %v %v", q, ok, err)
		}
	}
	if s.Len() != 3 {
		t.Fatalf("len %d", s.Len())
	}
	if ok, err := s.RevokeUser("corp", "alice", a.ID); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if _, err := s.Lookup(secret); err != ErrNotFound {
		t.Fatalf("still works: %v", err)
	}
	if ok, _ := s.RevokeUser("corp", "alice", a.ID); ok {
		t.Fatal("ended twice")
	}
	s.Close()
	// The revocation survives a restart.
	s, err = Open(Options{Path: path, IdleTimeout: time.Hour, AbsoluteTimeout: 8 * time.Hour, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Len() != 2 || len(s.UserSessions("corp", "alice")) != 0 {
		t.Fatalf("after restart: %d %+v", s.Len(), s.UserSessions("corp", "alice"))
	}
	// An expired session is not found either.
	c.add(2 * time.Hour)
	if ok, _ := s.RevokeUser("corp", "bob", b.ID); ok {
		t.Fatal("ended an expired session")
	}
}

// Device and address survive a restart and a compaction, and stay out of
// the session's JSON, which is what the admin API lists.
func TestDevicePersistsNotListed(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	path := filepath.Join(t.TempDir(), "sessions.log")
	s, err := Open(Options{Path: path, IdleTimeout: time.Hour, AbsoluteTimeout: 8 * time.Hour, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	_, a, _ := s.CreateWith(alice(), Extra{Device: "Edge on Windows", IP: "198.51.100.7"})
	s.Close()
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"device":"Edge on Windows","ip":"198.51.100.7"`) {
		t.Fatalf("log: %s", raw)
	}
	for round := 0; round < 2; round++ {
		s, err = Open(Options{Path: path, IdleTimeout: time.Hour, AbsoluteTimeout: 8 * time.Hour, Now: c.now})
		if err != nil {
			t.Fatal(err)
		}
		l := s.UserSessions("corp", "alice")
		if len(l) != 1 || l[0].ID != a.ID || l[0].Device() != "Edge on Windows" || l[0].IP() != "198.51.100.7" {
			t.Fatalf("round %d: %+v", round, l)
		}
		for _, sess := range s.List("", 0) {
			b, _ := json.Marshal(sess)
			if strings.Contains(string(b), "Edge") || strings.Contains(string(b), "198.51.100.7") {
				t.Fatalf("listed: %s", b)
			}
		}
		s.Close()
	}
}

// A damaged log with a malformed device or address is refused, not loaded.
func TestLogRejectsBadDevice(t *testing.T) {
	line := func(extra string) []byte {
		b := []byte(`{"op":"create","session":{"id":"0123456789abcdef0123456789abcdef","identity":{"provider":"corp","sub":"a"},"created_at":"2026-01-01T00:00:00Z","last_seen_at":"2026-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z"}` + extra + `}`)
		return []byte(fmt.Sprintf("%08x %s\n", crc32.Checksum(b, castagnoli), b))
	}
	if _, err := parseLine(line(`,"device":"Chrome on Android","ip":"192.0.2.9"`)); err != nil {
		t.Fatalf("refused a good line: %v", err)
	}
	for _, bad := range []string{`,"device":"` + strings.Repeat("x", MaxDeviceBytes+1) + `"`, `,"device":"a\tb"`, `,"ip":"192.0.2"`} {
		if _, err := parseLine(line(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// Listing one user's sessions among many is a map lookup, not a scan.
func BenchmarkUserSessions(b *testing.B) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s, _ := Open(Options{IdleTimeout: time.Hour, AbsoluteTimeout: 8 * time.Hour, Now: c.now})
	for i := range 100_000 {
		s.CreateWith(policy.Identity{Provider: "corp", Subject: fmt.Sprint("u", i%20_000)}, Extra{Device: "Firefox on Linux", IP: "192.0.2.1"})
	}
	for b.Loop() {
		s.UserSessions("corp", "u42")
	}
}
