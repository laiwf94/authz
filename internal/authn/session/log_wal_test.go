package session

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/policy"
	"github.com/laiwf94/authz/internal/platform/storage/wal"
)

// testdata/pre-wal.log was written by the session log before it moved onto
// internal/platform/storage/wal: creates, a touch, a revocation and an
// eviction. It must replay to the same sessions, and every record must
// encode to the same bytes it was read from.
func TestPreWALLogOpensUnchanged(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "pre-wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(fixture, []byte("\n"))
	lines = lines[:len(lines)-1]
	for i, line := range lines {
		rec, err := parseLine(line)
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		again, err := encode([]record{rec})
		if err != nil || !bytes.Equal(again, line) {
			t.Fatalf("line %d re-encodes as\n%s\nwant\n%s", i, again, line)
		}
	}

	path := filepath.Join(t.TempDir(), "sessions.log")
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 11, 1, 9, 30, 0, 0, time.UTC)}
	s := open(t, path, c)
	got := s.List("", 0)
	// Two of them were created in the same second, so their order is not
	// fixed.
	want := []string{"9e747c07adfa35aaf9ea3c6ba7df7756", "b93f24bcd28dfca21dee2f703a6fd615", "bfbc779d9a55079750b6eddc1f4b1744"}
	if g := ids(got); strings.Join(g, " ") != strings.Join(want, " ") {
		t.Fatalf("sessions %v, want %v", g, want)
	}
	for _, sess := range got {
		if sess.Identity.Subject == "carol" && (sess.Identity.Provider != "partner" || !sess.ExpiresAt.Equal(time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC))) {
			t.Fatalf("carol: %+v", sess)
		}
	}
	// Open compacted the log into one create per live session, in the
	// same framing.
	raw, _ := os.ReadFile(path)
	if n := bytes.Count(raw, []byte("\n")); n != 3 {
		t.Fatalf("compacted log has %d records:\n%s", n, raw)
	}
	var compacted []Session
	for i, line := range bytes.SplitAfter(raw, []byte("\n"))[:3] {
		rec, err := parseLine(line)
		if err != nil || rec.Op != opCreate {
			t.Fatalf("compacted line %d: %+v %v", i, rec, err)
		}
		compacted = append(compacted, *rec.Session)
	}
	if g := ids(compacted); strings.Join(g, " ") != strings.Join(want, " ") {
		t.Fatalf("compacted %v, want %v", g, want)
	}
}

// Compaction renames a snapshot over the log; the log's file must follow it,
// so later appends land in the new file and a swapped handle still takes
// effect.
func TestCompactionFollowsTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.log")
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, path, c)
	before := s.log.f
	for i := 0; i < 3; i++ {
		_, sess, err := s.Create(alice(), time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if i < 2 {
			s.Revoke(sess.ID)
		}
	}
	if err := s.log.compact(s.snapshot()); err != nil {
		t.Fatal(err)
	}
	if s.log.f == before || s.log.next != nil {
		t.Fatal("the log kept the file the snapshot replaced")
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot left behind: %v", err)
	}
	sec, _, err := s.Create(policy.Identity{Provider: "corp", Subject: "bob"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if n := bytes.Count(raw, []byte("\n")); n != 2 || s.log.records() != 2 {
		t.Fatalf("after compaction and a login: %d lines, %d records\n%s", n, s.log.records(), raw)
	}

	// A compaction that can't write its snapshot leaves the log as it was
	// and still taking writes.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	current := s.log.f
	if err := s.log.compact(s.snapshot()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("compact over a directory: %v", err)
	}
	if s.log.f != current || s.log.next != nil || s.log.broken != nil {
		t.Fatal("a failed compaction changed the log")
	}
	os.Remove(path + ".tmp")
	if ok, err := s.Revoke(IDFromSecret(sec)); !ok || err != nil {
		t.Fatalf("revoke after a failed compaction: %v %v", ok, err)
	}

	// Nor does one whose snapshot is written but can't be renamed into
	// place: here a non-empty directory has taken the log's name (the open
	// file lives on). The snapshot is closed and removed.
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.log.compact(s.snapshot()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("compact with a failing rename: %v", err)
	}
	if s.log.f != current || s.log.next != nil || s.log.broken != nil {
		t.Fatal("a failed rename changed the log")
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot left behind: %v", err)
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".moved", path); err != nil {
		t.Fatal(err)
	}

	// Swapping the file after a compaction still reaches the stream.
	s.log.f.Close()
	ro, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ro.Seek(0, 2)
	s.log.f = ro
	if _, _, err := s.Create(alice(), time.Time{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("create on a read-only file: %v", err)
	}
	s.Close()

	s2 := open(t, path, c)
	if got := s2.List("", 0); len(got) != 1 || got[0].Identity.Subject != "alice" {
		t.Fatalf("after restart: %+v", got)
	}
}

// A record over the limit is refused before it reaches the file, which stays
// writable; before the move such a record was written and then stopped the
// next start.
func TestOversizedSessionRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.log")
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, path, c)
	huge := alice()
	huge.Groups = []string{strings.Repeat("g", maxRecordBytes)}
	if _, _, err := s.Create(huge, time.Time{}); !errors.Is(err, ErrUnavailable) || !errors.Is(err, wal.ErrTooLarge) {
		t.Fatalf("oversized create: %v", err)
	}
	if s.Len() != 0 || s.log.broken != nil {
		t.Fatal("a refused create changed the store")
	}
	if _, _, err := s.Create(alice(), time.Time{}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s2 := open(t, path, c); s2.Len() != 1 {
		t.Fatalf("%d sessions after restart", s2.Len())
	}
}

// replay reports damage before the last line as damage, and a read error as
// itself rather than as the end of the log.
func TestReplayErrors(t *testing.T) {
	one, _ := encode([]record{{Op: opRevoke, ID: strings.Repeat("a", 32)}})
	damaged := append(append([]byte("00000000 {}\n"), one...), one...)
	if _, _, err := replay(bytes.NewReader(damaged)); err == nil || !strings.Contains(err.Error(), "damaged") || !errors.Is(err, wal.ErrCorrupt) {
		t.Fatalf("damaged first line: %v", err)
	}
	if _, _, err := replay(failingReader{}); !errors.Is(err, errRead) {
		t.Fatalf("read error: %v", err)
	}
}

var errRead = errors.New("read failed")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errRead }
