package session

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/policy"
)

func TestDueAndRevalidated(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, "", c)
	_, a, err := s.CreateWithRefresh(alice(), time.Time{}, "sealed-a")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Revalidated().Equal(a.CreatedAt) {
		t.Fatalf("a new session is confirmed at creation: %v", a.Revalidated())
	}
	c.add(time.Minute)
	bob := policy.Identity{Provider: "corp", Subject: "bob"}
	_, b, _ := s.CreateWithRefresh(bob, time.Time{}, "")
	other := policy.Identity{Provider: "partner", Subject: "carol"}
	_, _, _ = s.CreateWithRefresh(other, time.Time{}, "sealed-c")

	// Nothing is due before its time; then oldest confirmation first.
	if due := s.Due("corp", a.CreatedAt.Add(-time.Second), 0); len(due) != 0 {
		t.Fatalf("due early: %+v", due)
	}
	due := s.Due("corp", c.now(), 0)
	if len(due) != 2 || due[0].ID != a.ID || due[1].ID != b.ID {
		t.Fatalf("due %+v", due)
	}
	if due[0].Refresh != "sealed-a" || due[0].Subject != "alice" || due[1].Refresh != "" {
		t.Fatalf("due fields %+v", due)
	}
	if due := s.Due("corp", c.now(), 1); len(due) != 1 || due[0].ID != a.ID {
		t.Fatalf("limit: %+v", due)
	}
	if due := s.Due("partner", c.now(), 0); len(due) != 1 || due[0].Subject != "carol" {
		t.Fatalf("partner: %+v", due)
	}

	// A confirmation moves the session out of the window; a rotation
	// replaces the token.
	c.add(time.Minute)
	if err := s.Revalidated(a.ID, "", c.now()); err != nil {
		t.Fatal(err)
	}
	if due := s.Due("corp", c.now().Add(-time.Second), 0); len(due) != 1 || due[0].ID != b.ID {
		t.Fatalf("after confirming a: %+v", due)
	}
	if err := s.Revalidated(a.ID, "sealed-a2", c.now()); err != nil {
		t.Fatal(err)
	}
	// An older confirmation arriving late does not move the time back.
	if err := s.Revalidated(a.ID, "", c.now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if due := s.Due("corp", c.now(), 0); len(due) != 2 || due[1].ID != a.ID || due[1].Refresh != "sealed-a2" || !due[1].Revalidated.Equal(c.now()) {
		t.Fatalf("after rotation: %+v", due)
	}

	// Ended and expired sessions are never due and can't be confirmed.
	if _, err := s.Revoke(b.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Revalidated(b.ID, "", c.now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked: %v", err)
	}
	c.add(2 * time.Hour) // past the idle timeout
	if due := s.Due("corp", c.now(), 0); len(due) != 0 {
		t.Fatalf("expired sessions due: %+v", due)
	}
	if err := s.Revalidated(a.ID, "", c.now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}

	big := strings.Repeat("x", MaxSealedRefreshBytes+1)
	if _, _, err := s.CreateWithRefresh(alice(), time.Time{}, big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized create: %v", err)
	}
	if err := s.Revalidated(a.ID, big, c.now()); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized revalidate: %v", err)
	}
}

func TestRefreshNeverListed(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, "", c)
	sec, _, _ := s.CreateWithRefresh(alice(), time.Time{}, "sealed-secret-marker")
	got, err := s.Lookup(sec)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{got, s.List("", 0)} {
		b, _ := json.Marshal(v)
		if strings.Contains(string(b), "sealed-secret-marker") || strings.Contains(string(b), "refresh") {
			t.Fatalf("listed: %s", b)
		}
	}
}

func TestRevalidationSurvivesRestartAndCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.log")
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, path, c)
	_, a, _ := s.CreateWithRefresh(alice(), time.Time{}, "sealed-1")
	_, b, _ := s.CreateWithRefresh(policy.Identity{Provider: "corp", Subject: "bob"}, time.Time{}, "sealed-b")
	c.add(5 * time.Minute)
	if err := s.Revalidated(a.ID, "sealed-2", c.now()); err != nil {
		t.Fatal(err)
	}
	confirmed := c.now()
	s.Close()

	check := func(s *Store, step string) {
		t.Helper()
		due := s.Due("corp", c.now(), 0)
		if len(due) != 2 || due[0].ID != b.ID || due[1].ID != a.ID {
			t.Fatalf("%s: due %+v", step, due)
		}
		if due[1].Refresh != "sealed-2" || !due[1].Revalidated.Equal(confirmed) {
			t.Fatalf("%s: a %+v", step, due[1])
		}
		if due[0].Refresh != "sealed-b" || !due[0].Revalidated.Equal(b.CreatedAt) {
			t.Fatalf("%s: b %+v", step, due[0])
		}
	}
	// Open compacts: the create record carries the token and the time.
	s2 := open(t, path, c)
	check(s2, "reopen")
	raw, _ := os.ReadFile(path)
	if n := strings.Count(string(raw), "\n"); n != 2 {
		t.Fatalf("compacted log has %d records:\n%s", n, raw)
	}
	if strings.Contains(string(raw), "sealed-1") {
		t.Fatal("the rotated-out token survived compaction")
	}
	s2.Close()
	s3 := open(t, path, c)
	check(s3, "second reopen")
}

func TestRevalidateRecordReplay(t *testing.T) {
	sess := &Session{ID: strings.Repeat("a", 32), Identity: alice(), CreatedAt: time.Unix(100, 0), LastSeen: time.Unix(100, 0),
		ExpiresAt: time.Unix(10_000, 0)}
	recs := []record{
		{Op: opCreate, Session: sess, Refresh: "r1"},
		{Op: opRevalidate, ID: sess.ID, Time: time.Unix(200, 0)},
		{Op: opRevalidate, ID: sess.ID, Time: time.Unix(150, 0), Refresh: "r2"},
		{Op: opRevalidate, ID: strings.Repeat("b", 32), Time: time.Unix(300, 0)}, // unknown session
	}
	b, err := encode(recs)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := replay(strings.NewReader(string(b)))
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if got[0].refresh != "r2" || !got[0].revalidated.Equal(time.Unix(200, 0)) {
		t.Fatalf("replayed %q %v", got[0].refresh, got[0].revalidated)
	}
	for name, rec := range map[string]record{
		"no id":   {Op: opRevalidate, Time: time.Unix(1, 0)},
		"no time": {Op: opRevalidate, ID: sess.ID},
	} {
		if err := validate(rec); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRevalidatedOnDeadLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.log")
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, path, c)
	_, sess, _ := s.CreateWithRefresh(alice(), time.Time{}, "sealed-1")
	s.log.f.Close()
	ro, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ro.Seek(0, 2)
	s.log.f = ro
	c.add(time.Minute)
	if err := s.Revalidated(sess.ID, "sealed-2", c.now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("rotation on a dead log: %v", err)
	}
	// The new token is kept in memory: the provider may refuse the old one.
	due := s.Due("corp", c.now(), 0)
	if len(due) != 1 || due[0].Refresh != "sealed-2" || !due[0].Revalidated.Equal(sess.CreatedAt) {
		t.Fatalf("after a failed write: %+v", due)
	}
}
