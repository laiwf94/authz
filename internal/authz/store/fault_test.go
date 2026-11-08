package store

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"syscall"
	"testing"

	"github.com/laiwf94/authz/internal/platform/storage/wal"
)

// faultyWAL is a write-ahead log file that fails chosen writes or fsyncs:
// the at-th to (at+run-1)-th operation of the chosen class. Opens is every
// file the log opened, so a test can drop them without a clean Close.
type faultyWAL struct {
	kind   string // "short write", "ENOSPC" or "fsync error"
	at     int
	run    int
	writes int
	syncs  int
	faults int
	opened []*os.File
}

type faultyFile struct {
	*os.File
	w *faultyWAL
}

func (w *faultyWAL) fire(write bool) bool {
	n := &w.syncs
	if write {
		n = &w.writes
	}
	*n++
	if w.at == 0 || (w.kind == "fsync error") == write || *n < w.at || *n >= w.at+w.run {
		return false
	}
	w.faults++
	return true
}

func (w *faultyWAL) open(path string, flag int) (wal.File, error) {
	f, err := os.OpenFile(path, flag, 0o600)
	if err != nil {
		return nil, err
	}
	w.opened = append(w.opened, f)
	return &faultyFile{File: f, w: w}, nil
}

func (f *faultyFile) Write(b []byte) (int, error) {
	if !f.w.fire(true) {
		return f.File.Write(b)
	}
	if f.w.kind == "ENOSPC" {
		n, _ := f.File.Write(b[:len(b)-1])
		return n, syscall.ENOSPC
	}
	n, _ := f.File.Write(b[:len(b)/2])
	return n, syscall.EIO
}

func (f *faultyFile) Sync() error {
	if f.w.fire(false) {
		return syscall.EIO
	}
	return f.File.Sync()
}

func allDocs(t *testing.T, s *Store) []string {
	t.Helper()
	rels, _, err := s.Read(s.Head(), Filter{ResourceType: "doc"}, "", MaxReadLimit)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(rels))
	for i, r := range rels {
		out[i] = r.String()
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// faultRun opens a store in dir on a log that fails as w says, writes the
// schema and a run of relationship writes, checks after every failed write
// that the store answers as before it, then drops the log's files without
// closing (a crash) and returns what the caller saw acknowledged.
func faultRun(t *testing.T, dir string, w *faultyWAL) (head Revision, model map[string]bool) {
	t.Helper()
	walOptions.OpenFile = w.open
	defer func() { walOptions.OpenFile = nil }()
	model = map[string]bool{}
	s, err := Open(Options{Dir: dir})
	if err != nil {
		// The checkpoint at open failed; nothing was acknowledged.
		if !errors.Is(err, syscall.EIO) && !errors.Is(err, syscall.ENOSPC) && !errors.Is(err, wal.ErrUnavailable) {
			t.Fatalf("open: %v", err)
		}
		for _, f := range w.opened {
			f.Close()
		}
		return 0, model
	}
	failed := func(what string, err error, before Revision, docs []string) {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s: %v, want ErrUnavailable", what, err)
		}
		if s.Head() != before {
			t.Fatalf("%s failed but the head moved from %d to %d", what, before, s.Head())
		}
		if got := allDocs(t, s); !reflect.DeepEqual(got, docs) {
			t.Fatalf("%s failed but the store changed:\n%v\nwas\n%v", what, got, docs)
		}
	}
	for s.Head() == 0 {
		if _, err := s.WriteSchema(testSchema); err != nil {
			failed("schema", err, 0, []string{})
		}
	}
	head = s.Head()
	for i := range 24 {
		var ups []Update
		touched := map[string]bool{}
		for j := range 1 + i%3 {
			r := mustRel(t, fmt.Sprintf("doc:d%d#viewer@user:u%d", (i+j)%7, (i*3+j)%5))
			if touched[r.String()] {
				continue
			}
			touched[r.String()] = true
			op := OpTouch
			if model[r.String()] && (i+j)%2 == 0 {
				op = OpDelete
			}
			ups = append(ups, Update{Op: op, Relationship: r})
		}
		before := allDocs(t, s)
		rev, err := s.Write(ups, nil)
		if err != nil {
			failed(fmt.Sprintf("write %d", i), err, head, before)
			continue
		}
		head = rev
		for _, u := range ups {
			if u.Op == OpDelete {
				delete(model, u.Relationship.String())
			} else {
				model[u.Relationship.String()] = true
			}
		}
	}
	if got := allDocs(t, s); !reflect.DeepEqual(got, keys(model)) {
		t.Fatalf("store disagrees with the acknowledged writes:\n%v\nwant\n%v", got, keys(model))
	}
	for _, f := range w.opened {
		f.Close()
	}
	return head, model
}

// TestWriteFaultsLeaveRecoverableLog fails every write and every fsync of
// grantd's relationship log in turn, with a short write, ENOSPC and an
// fsync error, once and three times in a row. A failed write must leave the
// store as it was and a later write must succeed; after a crash the log
// must reopen to exactly the acknowledged writes at the acknowledged head,
// and take writes again.
func TestWriteFaultsLeaveRecoverableLog(t *testing.T) {
	base := &faultyWAL{}
	faultRun(t, t.TempDir(), base)
	if base.writes < 20 || base.syncs < 20 {
		t.Fatalf("baseline run made %d writes and %d fsyncs", base.writes, base.syncs)
	}
	for _, kind := range []string{"short write", "ENOSPC", "fsync error"} {
		ops := base.writes
		if kind == "fsync error" {
			ops = base.syncs
		}
		for _, run := range []int{1, 3} {
			for at := 1; at <= ops; at++ {
				t.Run(fmt.Sprintf("%s/run%d/at%d", kind, run, at), func(t *testing.T) {
					dir := t.TempDir()
					w := &faultyWAL{kind: kind, at: at, run: run}
					head, model := faultRun(t, dir, w)
					if w.faults == 0 {
						t.Fatal("no fault injected")
					}
					s := newStore(t, dir)
					if s.Head() != head {
						t.Fatalf("recovered head %d, acknowledged %d", s.Head(), head)
					}
					if head > 0 {
						if _, src := s.Schema(); src == "" {
							t.Fatal("schema lost")
						}
					}
					if got := allDocs(t, s); !reflect.DeepEqual(got, keys(model)) {
						t.Fatalf("recovered\n%v\nacknowledged\n%v", got, keys(model))
					}
					if head == 0 {
						withSchema(t, s)
					}
					rev := write(t, s, OpTouch, "doc:after#owner@user:z")
					s.Close()
					s = newStore(t, dir)
					if s.Head() != rev || len(direct(t, s, rev, "doc", "after", "owner")) != 1 {
						t.Fatalf("write after recovery lost: head %d, want %d", s.Head(), rev)
					}
				})
			}
		}
	}
}
