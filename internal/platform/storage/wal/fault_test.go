package wal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
)

// The fault sweep runs a stream through a fixed workload of appends, durable
// appends, syncs and snapshots, and fails the k-th write or the k-th fsync
// with a short write, ENOSPC or an fsync error, for every k the workload
// reaches, once and for several operations in a row. After each run it
// "crashes" without closing and checks that what is on disk is a state
// recovery accepts and that it holds exactly the acknowledged records, both
// as the process left it and as a power cut could leave it.
//
// The disk is modelled in simDisk: a file's durable content is what it held
// at its last successful fsync, and a rename becomes durable at the next
// successful directory fsync. Real fsyncs are not issued, which keeps the
// several thousand runs fast and makes the power-cut states exact.

type faultKind int

const (
	shortWrite faultKind = iota // part of the bytes written, then EIO
	noSpace                     // all but the last byte written, then ENOSPC
	fsyncError                  // fsync or directory fsync returns EIO
)

func (k faultKind) String() string {
	return [...]string{"short write", "ENOSPC", "fsync error"}[k]
}

type simFile struct {
	*os.File
	disk   *simDisk
	synced []byte // content at the last successful fsync
}

type simDisk struct {
	mu     sync.Mutex
	kind   faultKind
	at     int // fail the at-th operation of the fault's class (1-based); 0 never
	run    int // and this many after it
	writes int
	syncs  int
	faults int // faults injected

	byName  map[string]*simFile // what each name links to now
	durable map[string]*simFile // what each name links to after a power cut
}

func newSimDisk(kind faultKind, at, run int) *simDisk {
	return &simDisk{kind: kind, at: at, run: run,
		byName: map[string]*simFile{}, durable: map[string]*simFile{}}
}

// fire counts one operation of class c and reports whether it fails.
func (d *simDisk) fire(write bool) bool {
	n := &d.syncs
	if write {
		n = &d.writes
	}
	*n++
	if d.at == 0 || (d.kind == fsyncError) == write {
		return false
	}
	if *n >= d.at && *n < d.at+d.run {
		d.faults++
		return true
	}
	return false
}

func (d *simDisk) open(path string, flag int) (File, error) {
	f, err := os.OpenFile(path, flag, 0o600)
	if err != nil {
		return nil, err
	}
	sf := &simFile{File: f, disk: d}
	if flag&os.O_TRUNC == 0 {
		sf.synced, _ = os.ReadFile(path) // what was there before is durable
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.durable[path]; !ok && flag&os.O_TRUNC == 0 {
		d.durable[path] = sf // the stream's own file, created by the workload's first Open
	}
	d.byName[path] = sf
	return sf, nil
}

func (d *simDisk) rename(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.byName[to] = d.byName[from]
	delete(d.byName, from)
	return nil
}

func (d *simDisk) syncDir(string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fire(false) {
		return syscall.EIO
	}
	for name, f := range d.byName {
		d.durable[name] = f
	}
	return nil
}

func (f *simFile) Write(b []byte) (int, error) {
	f.disk.mu.Lock()
	fail := f.disk.fire(true)
	kind := f.disk.kind
	f.disk.mu.Unlock()
	if !fail {
		return f.File.Write(b)
	}
	cut, err := len(b)/2, error(syscall.EIO)
	if kind == noSpace {
		cut, err = len(b)-1, syscall.ENOSPC
	}
	n, _ := f.File.Write(b[:cut])
	return n, err
}

func (f *simFile) Sync() error {
	f.disk.mu.Lock()
	defer f.disk.mu.Unlock()
	if f.disk.fire(false) {
		return syscall.EIO
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	b := make([]byte, fi.Size())
	if _, err := f.ReadAt(b, 0); err != nil && err != io.EOF {
		return err
	}
	f.synced = b
	return nil
}

// useSimDisk routes the package's file, rename and directory-fsync hooks
// through d until the returned function restores them.
func useSimDisk(d *simDisk) (restore func()) {
	of, rn, sd := openFile, rename, syncDir
	openFile, rename, syncDir = d.open, d.rename, d.syncDir
	return func() { openFile, rename, syncDir = of, rn, sd }
}

// workload drives a stream and keeps the caller's view: the records
// acknowledged in order, and how many of them were acknowledged as durable.
type workload struct {
	policy  SyncPolicy
	acked   []event
	durable int
	s       *Stream[event]
}

func (w *workload) ack(durable bool, recs ...event) {
	w.acked = append(w.acked, recs...)
	if durable {
		w.durable = len(w.acked)
	}
}

// heal does what every caller of a stream does when appends are refused:
// replace the file with the state it has acknowledged.
func (w *workload) heal(t *testing.T) {
	if w.s.Err() == nil {
		return
	}
	if err := w.s.Replace(w.acked); err == nil {
		w.durable = len(w.acked)
	} else if !errors.Is(err, ErrUnavailable) && !errors.Is(err, syscall.EIO) && !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("replace: unexpected error %v", err)
	}
}

func (w *workload) run(t *testing.T, ops int) {
	n := 0
	next := func() event {
		n++
		return event{Kind: "rec", Key: fmt.Sprintf("k%d", n%4), Body: fmt.Sprintf("body %d", n), N: n}
	}
	check := func(what string, err error) bool {
		if err == nil {
			return true
		}
		if !errors.Is(err, ErrUnavailable) && !errors.Is(err, syscall.EIO) && !errors.Is(err, syscall.ENOSPC) {
			t.Fatalf("op %s: unexpected error %v", what, err)
		}
		w.heal(t)
		return false
	}
	for i := range ops {
		switch {
		case i%9 == 8:
			if check("replace", w.s.Replace(w.acked)) {
				w.durable = len(w.acked)
			}
		case i%5 == 4:
			a, b := next(), next()
			if check("append batch", w.s.Append(a, b)) {
				w.ack(w.policy == SyncAlways, a, b)
			}
		case w.policy == SyncNever && i%4 == 3:
			r := next()
			if check("append sync", w.s.AppendSync(r)) {
				w.ack(true, r)
			}
		case w.policy == SyncNever && i%7 == 6:
			if check("sync", w.s.Sync()) {
				w.durable = len(w.acked)
			}
		default:
			r := next()
			if check("append", w.s.Append(r)) {
				w.ack(w.policy == SyncAlways, r)
			}
		}
	}
}

// scanBytes replays content as recovery does and returns its records.
func scanBytes(t *testing.T, content []byte) []event {
	t.Helper()
	var got []event
	if _, _, err := Scan(bytes.NewReader(content), Options[event]{}, collect(&got)); err != nil {
		t.Fatalf("recovery refused the state the fault left: %v\n%q", err, content)
	}
	return got
}

// recoverBytes opens content as a stream, checks that it takes an append
// that survives a reopen, and returns the records it recovered.
func recoverBytes(t *testing.T, content []byte) []event {
	t.Helper()
	path := filepath.Join(t.TempDir(), "recover.wal")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	var got []event
	s, err := Open(path, Options[event]{}, collect(&got))
	if err != nil {
		t.Fatalf("recovery refused the state the fault left: %v\n%q", err, content)
	}
	// A recovered stream takes appends and keeps them.
	if err := s.Append(event{Kind: "after"}); err != nil {
		t.Fatalf("append after recovery: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var again []event
	s, err = Open(path, Options[event]{}, collect(&again))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if len(again) != len(got)+1 || again[len(got)].Kind != "after" {
		t.Fatalf("append after recovery lost: %d then %d records", len(got), len(again))
	}
	return got
}

func isPrefix(prefix, of []event) bool {
	return len(prefix) <= len(of) && reflect.DeepEqual(prefix, of[:len(prefix)]) ||
		len(prefix) == 0
}

const sweepOps = 40

// sweepRun runs the workload once and checks the crash states. It returns
// how many writes and fsyncs the run made and how many faults it injected.
func sweepRun(t *testing.T, policy SyncPolicy, kind faultKind, at, run int) (writes, syncs, faults int) {
	d := newSimDisk(kind, at, run)
	restore := useSimDisk(d)
	defer restore()
	path := filepath.Join(t.TempDir(), "s.wal")
	s, err := Open(path, Options[event]{Sync: policy}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &workload{policy: policy, s: s}
	w.run(t, sweepOps)
	// Crash: the handle is dropped without Close, so nothing more is
	// written or fsynced.
	s.mu.Lock()
	f := s.f.(*simFile)
	s.f.(*simFile).File.Close()
	s.mu.Unlock()
	restore()

	// As the process left it: exactly the acknowledged records.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := recoverBytes(t, content)
	if !reflect.DeepEqual(got, w.acked) && !(len(got) == 0 && len(w.acked) == 0) {
		t.Fatalf("after a process crash recovered %d records, acknowledged %d\nrecovered %+v\nacked     %+v",
			len(got), len(w.acked), got, w.acked)
	}

	// As a power cut could leave it: the durable file under the name, with
	// any prefix of the bytes written after its last fsync. Prefixes are
	// taken at every record boundary and one byte short of it (a torn
	// record); TestCutAtEveryByte covers the bytes in between. Every record
	// acknowledged as durable survives, and nothing unacknowledged appears.
	d.mu.Lock()
	df := d.durable[path]
	d.mu.Unlock()
	states := [][]byte{df.synced}
	if df == f && bytes.HasPrefix(content, df.synced) {
		for cut := len(df.synced); cut < len(content); cut++ {
			if content[cut] == '\n' {
				states = append(states, content[:cut], content[:cut+1])
			}
		}
	}
	for _, st := range states {
		got := scanBytes(t, st)
		if !isPrefix(got, w.acked) {
			t.Fatalf("after a power cut (%d bytes) recovered records that were not acknowledged: %+v", len(st), got)
		}
		if len(got) < w.durable {
			t.Fatalf("after a power cut (%d bytes) recovered %d records; %d were acknowledged as durable",
				len(st), len(got), w.durable)
		}
	}
	return d.writes, d.syncs, d.faults
}

func TestFaultSweep(t *testing.T) {
	for _, policy := range []SyncPolicy{SyncAlways, SyncNever} {
		t.Run(policy.String(), func(t *testing.T) {
			writes, syncs, faults := sweepRun(t, policy, shortWrite, 0, 0)
			if faults != 0 || writes < sweepOps/2 || syncs < sweepOps/4 {
				t.Fatalf("baseline run: %d writes, %d fsyncs, %d faults", writes, syncs, faults)
			}
			for _, kind := range []faultKind{shortWrite, noSpace, fsyncError} {
				ops := writes
				if kind == fsyncError {
					ops = syncs
				}
				for _, run := range []int{1, 3} {
					injected := 0
					for at := 1; at <= ops; at++ {
						t.Run(fmt.Sprintf("%s/run%d/at%d", kind, run, at), func(t *testing.T) {
							_, _, f := sweepRun(t, policy, kind, at, run)
							injected += f
						})
					}
					if injected < ops {
						t.Errorf("%s run %d: only %d faults injected over %d positions", kind, run, injected, ops)
					}
				}
			}
		})
	}
}
