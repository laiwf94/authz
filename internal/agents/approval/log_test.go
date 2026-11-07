package approval

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/storage/wal"
)

func logConfig(c *clock) Config {
	return Config{PendingTTL: time.Minute, MaxGrantTTL: 10 * time.Minute, MaxOpen: 64, MaxOpenByAgent: 64, Now: c.now}
}

func openLog(t *testing.T, path string, c *clock) *Store {
	t.Helper()
	s, err := Open(path, logConfig(c))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// Every state a request can be in comes back after a restart, and a used
// grant does not.
func TestLogSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.wal")
	c := &clock{t: time.Unix(1000, 0)}
	s := openLog(t, path, c)
	pend, _, _ := s.Begin(bind("alice", "pending"))
	appr, _, _ := s.Begin(bind("alice", "approved"))
	used, _, _ := s.Begin(bind("alice", "used"))
	deny, _, _ := s.Begin(bind("bob", "denied"))
	for _, id := range []string{appr.ID, used.ID} {
		if _, err := s.Decide(id, true, 5*time.Minute, "ok"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Decide(deny.ID, false, 0, "no"); err != nil {
		t.Fatal(err)
	}
	if !s.Consume(used.ID) {
		t.Fatal("consume")
	}
	before := s.List()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := openLog(t, path, c)
	after := s2.List()
	if len(after) != 3 || len(before) != 3 {
		t.Fatalf("before %d, after %d requests, want 3", len(before), len(after))
	}
	for i := range before {
		b, a := before[i], after[i]
		if b.ID != a.ID || b.Status != a.Status || !b.ExpiresAt.Equal(a.ExpiresAt) || !b.CreatedAt.Equal(a.CreatedAt) ||
			!b.DecidedAt.Equal(a.DecidedAt) || b.Note != a.Note || !bytes.Equal(b.Arguments, a.Arguments) || b.ArgsHash != a.ArgsHash {
			t.Fatalf("request %d changed across the restart:\n%+v\n%+v", i, b, a)
		}
	}
	if r, out, _ := s2.Begin(bind("alice", "pending")); out != OutcomePending || r.ID != pend.ID {
		t.Fatalf("pending request: %v %+v", out, r)
	}
	if _, out, _ := s2.Begin(bind("bob", "denied")); out != OutcomeDenied {
		t.Fatalf("denial: %v", out)
	}
	if r, out, _ := s2.Begin(bind("alice", "used")); out != OutcomeOpened || r.ID == used.ID {
		t.Fatalf("a used grant came back: %v %+v", out, r)
	}
	if r, out, _ := s2.Begin(bind("alice", "approved")); out != OutcomeProceed || r.ID != appr.ID {
		t.Fatalf("grant: %v %+v", out, r)
	}
	// A decided request's waiters return at once; a pending one's wait.
	if out := s2.Wait(context.Background(), appr.ID, time.Hour); out != OutcomeProceed {
		t.Fatalf("wait on a replayed grant: %v", out)
	}
	if out := s2.Wait(context.Background(), pend.ID, time.Millisecond); out != OutcomePending {
		t.Fatalf("wait on a replayed pending request: %v", out)
	}
	if !s2.Consume(appr.ID) || s2.Consume(appr.ID) {
		t.Fatal("the replayed grant is not single use")
	}
	if s2.PendingCount() != 2 {
		t.Fatalf("pending = %d", s2.PendingCount())
	}
}

// Requests that expired while the gateway was down are not replayed.
func TestLogDropsExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.wal")
	c := &clock{t: time.Unix(1000, 0)}
	s := openLog(t, path, c)
	short, _, _ := s.Begin(bind("alice", "a"))
	long, _, _ := s.Begin(bind("alice", "b"))
	s.Decide(long.ID, true, 5*time.Minute, "")
	s.Close()
	c.add(2 * time.Minute) // past the pending TTL, inside the grant
	s2 := openLog(t, path, c)
	if _, ok := s2.Get(short.ID); ok {
		t.Fatal("an expired request was replayed")
	}
	if _, ok := s2.Get(long.ID); !ok {
		t.Fatal("a live grant was lost")
	}
}

// A crash can cut the log anywhere. Whatever prefix survives, the store
// opens and holds exactly the requests of the complete records in it; in
// particular a grant whose use was written is never back.
func TestLogCutAtEveryByte(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.wal")
	c := &clock{t: time.Unix(1000, 0)}
	s := openLog(t, path, c)
	var ids []string
	for _, a := range []string{"a", "b", "c"} {
		r, _, _ := s.Begin(bind("alice", a))
		ids = append(ids, r.ID)
	}
	s.Decide(ids[0], true, time.Minute, "")
	s.Decide(ids[1], false, 0, "")
	s.Consume(ids[0])
	s.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	lines = lines[:len(lines)-1] // empty after the final newline
	// want[k] is the state after the first k records.
	type state map[string]Status
	want := []state{{}, {ids[0]: Pending}, {ids[0]: Pending, ids[1]: Pending},
		{ids[0]: Pending, ids[1]: Pending, ids[2]: Pending},
		{ids[0]: Approved, ids[1]: Pending, ids[2]: Pending},
		{ids[0]: Approved, ids[1]: Denied, ids[2]: Pending},
		{ids[1]: Denied, ids[2]: Pending}}
	if len(lines) != len(want)-1 {
		t.Fatalf("%d records, want %d", len(lines), len(want)-1)
	}
	cut := filepath.Join(dir, "cut.wal")
	for n := 0; n <= len(data); n++ {
		if err := os.WriteFile(cut, data[:n], 0o600); err != nil {
			t.Fatal(err)
		}
		complete := bytes.Count(data[:n], []byte("\n"))
		s, err := Open(cut, logConfig(c))
		if err != nil {
			t.Fatalf("cut at %d: %v", n, err)
		}
		got := state{}
		for _, r := range s.List() {
			got[r.ID] = r.Status
		}
		w := want[complete]
		if len(got) != len(w) {
			t.Fatalf("cut at %d: %v, want %v", n, got, w)
		}
		for id, st := range w {
			if got[id] != st {
				t.Fatalf("cut at %d: %v, want %v", n, got, w)
			}
		}
		// The torn tail is gone and the store takes new records.
		if _, _, err := s.Begin(bind("zed", "after")); err != nil {
			t.Fatalf("cut at %d: append after recovery: %v", n, err)
		}
		s.Close()
	}
}

// Damage before the last record stops Open instead of guessing.
func TestLogDamage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.wal")
	c := &clock{t: time.Unix(1000, 0)}
	s := openLog(t, path, c)
	s.Begin(bind("alice", "a"))
	s.Begin(bind("alice", "b"))
	s.Close()
	data, _ := os.ReadFile(path)
	data[12] ^= 0x20
	os.WriteFile(path, data, 0o600)
	if _, err := Open(path, logConfig(c)); !errors.Is(err, wal.ErrCorrupt) {
		t.Fatalf("damaged log opened: %v", err)
	}
	// Records that are well framed but not approval records are damage too.
	for name, line := range map[string]string{
		"unknown op":  `{"op":"drop","id":"x"}`,
		"no request":  `{"op":"put"}`,
		"bad status":  `{"op":"put","request":{"id":"x","status":"maybe"}}`,
		"used no id":  `{"op":"used"}`,
		"both fields": `{"op":"used","id":"x","request":{"id":"x","status":"pending"}}`,
		"extra field": `{"op":"used","id":"x","why":1}`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		os.WriteFile(p, append(append(wal.Frame(nil, []byte(line)), '\n'), wal.Frame(nil, []byte(`{"op":"used","id":"y"}`))...), 0o600)
		if _, err := Open(p, logConfig(c)); !errors.Is(err, wal.ErrCorrupt) {
			t.Errorf("%s: opened: %v", name, err)
		}
	}
	if _, err := Open(dir, logConfig(c)); err == nil {
		t.Fatal("a directory opened as a log")
	}
}

// The log is compacted as it grows, down to the live requests.
func TestLogCompacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.wal")
	c := &clock{t: time.Unix(1000, 0)}
	s := openLog(t, path, c)
	var keep string
	for i := range 1000 {
		r, _, err := s.Begin(bind("alice", strings.Repeat("x", i%7)+string(rune('a'+i%26))+time.Duration(i).String()))
		if err != nil {
			t.Fatal(err)
		}
		if i == 500 {
			keep = r.ID
			continue
		}
		s.Decide(r.ID, true, time.Minute, "")
		s.Consume(r.ID)
	}
	if n := s.log.Records(); n > 2*compactAfter {
		t.Fatalf("the log holds %d records for 1 live request", n)
	}
	s.Close()
	s2 := openLog(t, path, c)
	if l := s2.List(); len(l) != 1 || l[0].ID != keep {
		t.Fatalf("after compaction: %+v", l)
	}
}

// faultFile fails writes or fsyncs on demand.
type faultFile struct {
	*os.File
	failWrite, failSync *atomic.Bool
}

func (f faultFile) Write(b []byte) (int, error) {
	if f.failWrite.Load() {
		return 0, errors.New("injected write failure")
	}
	return f.File.Write(b)
}

func (f faultFile) Sync() error {
	if f.failSync.Load() {
		return errors.New("injected fsync failure")
	}
	return f.File.Sync()
}

// A failed write never lets a call through and never loses an acknowledged
// state: Begin opens nothing, Decide decides nothing, Consume uses up the
// grant without the call running. The next write puts the log right.
func TestLogWriteFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.wal")
	c := &clock{t: time.Unix(1000, 0)}
	var failWrite, failSync atomic.Bool
	s, err := open(path, logConfig(c), func(p string, flag int) (wal.File, error) {
		f, err := os.OpenFile(p, flag, 0o600)
		if err != nil {
			return nil, err
		}
		return faultFile{f, &failWrite, &failSync}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, _, _ := s.Begin(bind("alice", "a"))
	b, _, _ := s.Begin(bind("alice", "b"))
	s.Decide(b.ID, true, time.Minute, "")

	failWrite.Store(true)
	if _, _, err := s.Begin(bind("alice", "c")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("begin with a failing log: %v", err)
	}
	if len(s.List()) != 2 {
		t.Fatal("an unrecorded request was kept")
	}
	failWrite.Store(false)
	failSync.Store(true)
	if _, err := s.Decide(a.ID, true, time.Minute, "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("decide with a failing fsync: %v", err)
	}
	if r, _ := s.Get(a.ID); r.Status != Pending || r.Note != "" {
		t.Fatalf("an unrecorded decision took effect: %+v", r)
	}
	if out := s.Wait(context.Background(), a.ID, time.Millisecond); out != OutcomePending {
		t.Fatal("waiters were released by an unrecorded decision")
	}
	if s.Consume(b.ID) {
		t.Fatal("a call ran although its grant's use was not recorded")
	}
	if s.Consume(b.ID) {
		t.Fatal("the grant was usable again after a failed consume")
	}
	failSync.Store(false)

	// The next write replaces the log with what the store holds.
	if _, err := s.Decide(a.ID, false, 0, ""); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2 := openLog(t, path, c)
	l := s2.List()
	if len(l) != 1 || l[0].ID != a.ID || l[0].Status != Denied {
		t.Fatalf("after recovery the log holds %+v", l)
	}
	// A snapshot that cannot be written either keeps failing closed.
	s3, _ := open(path, logConfig(c), func(p string, flag int) (wal.File, error) {
		f, err := os.OpenFile(p, flag, 0o600)
		if err != nil {
			return nil, err
		}
		return faultFile{f, &failWrite, &failSync}, nil
	})
	defer s3.Close()
	failWrite.Store(true)
	if _, _, err := s3.Begin(bind("bob", "x")); err == nil {
		t.Fatal("begin")
	}
	if _, _, err := s3.Begin(bind("bob", "y")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("snapshot with a failing log: %v", err)
	}
	failWrite.Store(false)
	if _, _, err := s3.Begin(bind("bob", "z")); err != nil {
		t.Fatal(err)
	}
}

// Many agents asking, deciding and using at once keep the log consistent
// with memory.
func TestLogConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.wal")
	c := &clock{t: time.Unix(1000, 0)}
	cfg := logConfig(c)
	cfg.MaxOpen, cfg.MaxOpenByAgent = 1024, 64
	s, err := Open(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var used atomic.Int64
	for w := range 8 {
		wg.Go(func() {
			for i := range 50 {
				r, _, err := s.Begin(bind(string(rune('a'+w)), string(rune('a'+i%26))+string(rune('a'+i/26))))
				if err != nil {
					t.Error(err)
					return
				}
				if i%3 == 0 {
					continue
				}
				s.Decide(r.ID, i%3 == 1, time.Minute, "")
				if s.Consume(r.ID) {
					used.Add(1)
				}
			}
		})
	}
	wg.Wait()
	want := s.List()
	s.Close()
	got := openLog(t, path, c).List()
	if len(got) != len(want) || used.Load() == 0 {
		t.Fatalf("replayed %d requests, memory held %d (%d used)", len(got), len(want), used.Load())
	}
	for i := range want {
		if got[i].ID != want[i].ID || got[i].Status != want[i].Status {
			t.Fatalf("request %d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestMemoryStoreClose(t *testing.T) {
	s, _ := newStore()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
