//go:build unix

package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clock is a settable Options.Now.
type clock struct{ ns atomic.Int64 }

func newClock() *clock {
	c := &clock{}
	c.ns.Store(fixedNow().UnixNano())
	return c
}
func (c *clock) now() time.Time      { return time.Unix(0, c.ns.Load()) }
func (c *clock) add(d time.Duration) { c.ns.Add(int64(d)) }
func callRec(i int) map[string]any {
	return map[string]any{"agent": "bot", "auth": "key", "decision": "allow", "stage": "policy", "tool": "t" + strconv.Itoa(i)}
}
func segNames(segs []SegmentResult) []string {
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = filepath.Base(s.Path)
	}
	return out
}

// chainRecords reads every record of a rotated log, oldest first, after
// VerifyChain passed.
func chainRecords(t *testing.T, path string) (ChainResult, []Record) {
	t.Helper()
	cr, err := VerifyChain(path, nil)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	var recs []Record
	for _, s := range cr.Segments {
		f, err := os.Open(s.Path)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, MaxLineBytes)
		for sc.Scan() {
			var r Record
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			recs = append(recs, r)
		}
		f.Close()
	}
	for i, r := range recs {
		if r.Seq != uint64(i+1) {
			t.Fatalf("record %d has sequence %d", i+1, r.Seq)
		}
	}
	return cr, recs
}

func openRotating(t *testing.T, path string, r Rotation, now func() time.Time) *Log {
	t.Helper()
	l, err := OpenWith(path, Options{Now: now, Schemas: Default(), Rotation: r})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func appendCalls(t *testing.T, l *Log, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		if err := l.Append("tool_call", map[string]any{"agent": "bot", "auth": "key", "decision": "allow",
			"stage": "policy", "tool": "t" + strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
}

// Size rotation: segments end at the first record that reaches MaxBytes,
// each later one opens with a segment start record naming the one before,
// and the chain verifies across them, payloads included.
func TestRotateBySize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	const max = 2048
	l := openRotating(t, path, Rotation{MaxBytes: max}, fixedNow)
	appendCalls(t, l, 0, 120)
	seq, head := l.Head()
	l.Close()

	cr, err := VerifyChain(path, Default())
	if err != nil {
		t.Fatal(err)
	}
	if cr.Records != seq || cr.Head != head {
		t.Fatalf("chain %d %s, writer %d %s", cr.Records, cr.Head, seq, head)
	}
	if len(cr.Segments) < 5 {
		t.Fatalf("only %d segments: %v", len(cr.Segments), segNames(cr.Segments))
	}
	if got := filepath.Base(cr.Segments[0].Path); got != "audit.jsonl.00000000000000000001" {
		t.Fatalf("first segment %s", got)
	}
	_, recs := chainRecords(t, path)
	calls, starts := 0, 0
	for i, s := range cr.Segments {
		fi, err := os.Stat(s.Path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", s.Path, fi.Mode())
		}
		if i < len(cr.Segments)-1 {
			// The record that reached the limit is the segment's last.
			raw, err := os.ReadFile(s.Path)
			if err != nil {
				t.Fatal(err)
			}
			lastLen := len(raw) - 1 - bytes.LastIndexByte(raw[:len(raw)-1], '\n')
			if s.Size < max || s.Size-int64(lastLen) >= max {
				t.Errorf("%s: %d bytes for a %d limit", s.Path, s.Size, max)
			}
			if s.Path != SegmentPath(path, s.First) {
				t.Errorf("%s holds records from %d", s.Path, s.First)
			}
		} else if s.Path != path {
			t.Errorf("active segment %s", s.Path)
		}
		if i == 0 {
			if s.Start != Genesis || s.Previous != "" {
				t.Errorf("first segment starts at %s after %q", s.Start, s.Previous)
			}
			continue
		}
		r := recs[s.First-1]
		var ss SegmentStarted
		if err := json.Unmarshal(r.Data, &ss); err != nil {
			t.Fatal(err)
		}
		prev := cr.Segments[i-1]
		if r.Event != EventSegmentStarted || r.Action != ActionRotate || ss.Reason != RotateSize ||
			ss.Previous != filepath.Base(prev.Path) || ss.PreviousFirst != prev.First || r.Prev != prev.Head {
			t.Errorf("segment %d starts with %+v %+v", i, r, ss)
		}
	}
	for _, r := range recs {
		switch r.Event {
		case EventToolCall:
			calls++
		case EventSegmentStarted:
			starts++
		}
	}
	if calls != 120 || starts != len(cr.Segments)-1 {
		t.Fatalf("%d calls and %d segment starts in %d segments", calls, starts, len(cr.Segments))
	}

	// Reopened, the active segment carries on the chain and keeps rotating.
	l = openRotating(t, path, Rotation{MaxBytes: max}, fixedNow)
	if s, h := l.Head(); s != seq || h != head {
		t.Fatalf("reopened at %d %s", s, h)
	}
	appendCalls(t, l, 120, 40)
	l.Close()
	cr2, recs2 := chainRecords(t, path)
	if len(cr2.Segments) <= len(cr.Segments) || len(recs2) <= len(recs) {
		t.Fatalf("no rotation after reopening: %v", segNames(cr2.Segments))
	}

	// The active file verifies on its own, as a later segment.
	res, err := verifyFile(t, path)
	if err != nil || res.First == 1 || res.Start == Genesis || res.Records != cr2.Records {
		t.Fatalf("active file alone: %+v %v", res, err)
	}
}

// Age rotation, timed from the segment's first record, also after a reopen.
func TestRotateByAge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	c := newClock()
	rot := Rotation{MaxAge: time.Hour}
	l := openRotating(t, path, rot, c.now)
	appendCalls(t, l, 0, 2)
	c.add(59 * time.Minute)
	appendCalls(t, l, 2, 1)
	if segs, _ := Segments(path); len(segs) != 0 {
		t.Fatalf("rotated early: %v", segs)
	}
	c.add(time.Minute)
	appendCalls(t, l, 3, 1) // the segment is an hour old: this one starts the next
	l.Close()
	segs, _ := Segments(path)
	if len(segs) != 1 {
		t.Fatalf("segments %v", segs)
	}
	_, recs := chainRecords(t, path)
	if len(recs) != 5 || recs[3].Event != EventSegmentStarted || !strings.Contains(string(recs[3].Data), `"reason":"age"`) {
		t.Fatalf("records %+v", recs)
	}

	// The new segment's age counts from its segment start record, read back
	// from the file by a new writer.
	c.add(30 * time.Minute)
	l = openRotating(t, path, rot, c.now)
	appendCalls(t, l, 4, 1)
	if segs, _ := Segments(path); len(segs) != 1 {
		t.Fatalf("rotated early after reopening: %v", segs)
	}
	c.add(30 * time.Minute)
	appendCalls(t, l, 5, 1)
	l.Close()
	if segs, _ := Segments(path); len(segs) != 2 {
		t.Fatalf("no age rotation after reopening: %v", segs)
	}
	chainRecords(t, path)
}

// Rotate ends the segment on demand; an empty log has nothing to rotate,
// and a rotation with no limits set works the same.
func TestRotateManual(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Rotate(); err != nil {
		t.Fatal(err)
	}
	if segs, _ := Segments(path); len(segs) != 0 {
		t.Fatalf("empty log rotated: %v", segs)
	}
	appendCalls(t, l, 0, 3)
	if err := l.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := l.Rotate(); err != nil { // the new segment holds its start record
		t.Fatal(err)
	}
	appendCalls(t, l, 3, 1)
	cr, recs := chainRecords(t, path)
	if want := []string{"audit.jsonl.00000000000000000001", "audit.jsonl.00000000000000000004", "audit.jsonl"}; fmt.Sprint(segNames(cr.Segments)) != fmt.Sprint(want) {
		t.Fatalf("segments %v", segNames(cr.Segments))
	}
	if len(recs) != 6 || !strings.Contains(string(recs[3].Data), `"reason":"manual"`) {
		t.Fatalf("records %+v", recs)
	}
	if s, h := l.Head(); s != 6 || h != cr.Head {
		t.Fatalf("head %d %s", s, h)
	}
}

// buildSegments writes a log of several segments and returns its path and
// segment paths, active file last.
func buildSegments(t *testing.T) (string, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openRotating(t, path, Rotation{MaxBytes: 1024}, fixedNow)
	appendCalls(t, l, 0, 40)
	l.Close()
	segs, err := Segments(path)
	if err != nil || len(segs) < 4 {
		t.Fatalf("segments %v %v", segs, err)
	}
	return path, append(segs, path)
}

// Every way of losing, moving or replacing a segment is named.
func TestVerifyChainDetects(t *testing.T) {
	base := func(p string) string { return filepath.Base(p) }
	cases := []struct {
		name   string
		damage func(t *testing.T, files []string)
		path   func(files []string) string // the file the error names
		want   string
	}{
		{"middle segment removed", func(t *testing.T, f []string) { must(t, os.Remove(f[1])) },
			func(f []string) string { return f[2] }, "are missing between audit.jsonl.00000000000000000001 and this segment; a segment (" + "%s) was removed"},
		{"oldest segment removed", func(t *testing.T, f []string) { must(t, os.Remove(f[0])) },
			func(f []string) string { return f[1] }, "the oldest segment starts at record"},
		{"active segment removed", func(t *testing.T, f []string) { must(t, os.Remove(f[len(f)-1])) },
			func(f []string) string { return f[len(f)-1] }, "the active segment is missing"},
		{"two segments swapped", func(t *testing.T, f []string) {
			tmp := f[1] + ".tmp"
			must(t, os.Rename(f[1], tmp))
			must(t, os.Rename(f[2], f[1]))
			must(t, os.Rename(tmp, f[2]))
		}, func(f []string) string { return f[1] }, "segment is named for record"},
		{"segment renamed to a later number", func(t *testing.T, f []string) {
			must(t, os.Rename(f[1], SegmentPath(f[len(f)-1], 1_000_000)))
		}, func(f []string) string { return f[2] }, "are missing between"},
		{"last record of a segment changed", func(t *testing.T, f []string) {
			raw, err := os.ReadFile(f[1])
			must(t, err)
			i := bytes.LastIndex(raw, []byte(`"decision":"allow"`))
			copy(raw[i:], `"decision":"allov"`)
			must(t, os.WriteFile(f[1], raw, 0o600))
		}, func(f []string) string { return f[2] }, "does not match the hash of the last record of"},
		{"segment emptied", func(t *testing.T, f []string) { must(t, os.WriteFile(f[1], nil, 0o600)) },
			func(f []string) string { return f[1] }, "segment is empty"},
		{"active segment emptied", func(t *testing.T, f []string) { must(t, os.WriteFile(f[len(f)-1], nil, 0o600)) },
			func(f []string) string { return f[len(f)-1] }, "the active segment is empty"},
		{"segment copied over the next", func(t *testing.T, f []string) {
			raw, err := os.ReadFile(f[1])
			must(t, err)
			must(t, os.WriteFile(f[2], raw, 0o600))
		}, func(f []string) string { return f[2] }, "segment is named for record"},
		{"record changed inside a segment", func(t *testing.T, f []string) {
			raw, err := os.ReadFile(f[2])
			must(t, err)
			must(t, os.WriteFile(f[2], bytes.Replace(raw, []byte(`"decision":"allow"`), []byte(`"decision":"deny"`), 1), 0o600))
		}, func(f []string) string { return f[2] }, "line 2: record does not match the hash stored in line 3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, files := buildSegments(t)
			if _, err := VerifyChain(path, Default()); err != nil {
				t.Fatal(err)
			}
			tc.damage(t, files)
			_, err := VerifyChain(path, Default())
			var se *SegmentError
			if !errors.As(err, &se) {
				t.Fatalf("got %v", err)
			}
			want := tc.want
			if strings.Contains(want, "%s") {
				want = fmt.Sprintf(want, base(files[1]))
			}
			if se.Path != tc.path(files) || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v\nwant %s: …%s", err, base(tc.path(files)), want)
			}
		})
	}

	// A segment start record anywhere but a later segment's first line.
	path, files := buildSegments(t)
	raw, _ := os.ReadFile(files[1])
	first, _, _ := bytes.Cut(raw, []byte("\n"))
	act, _ := os.ReadFile(path)
	must(t, os.WriteFile(path, append(act, append(first, '\n')...), 0o600))
	if _, err := VerifyChain(path, nil); err == nil || !strings.Contains(err.Error(), "only valid as the first line of a later segment") {
		t.Fatalf("moved segment start: %v", err)
	}
	if _, err := Verify(bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyChain(filepath.Join(t.TempDir(), "none"), nil); err == nil {
		t.Fatal("missing log verified")
	}
	if _, err := VerifyChain(filepath.Join(t.TempDir(), "no", "dir"), nil); err == nil {
		t.Fatal("missing directory verified")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Malformed segment start records fail on their line.
func TestSegmentStartRecordChecks(t *testing.T) {
	line := func(seq uint64, prev, data string) string {
		return fmt.Sprintf(`{"seq":%d,"time":"t","prev":"%s","event":"audit.segment_started","action":"audit.rotate","data":%s}`, seq, prev, data)
	}
	other := strings.Repeat("ab", 32)
	good := `{"previous":"audit.jsonl.00000000000000000001","previous_first":1,"reason":"size"}`
	for _, tc := range []struct{ name, log, want string }{
		{"at the chain's start", line(1, Genesis, good), "only valid as the first line"},
		{"sequence 1 after a record", line(1, other, good), "has sequence 1"},
		{"no previous segment", line(5, other, `{"previous":"","previous_first":1,"reason":"size"}`), "does not name the segment"},
		{"previous with a directory", line(5, other, `{"previous":"x/audit.jsonl.00000000000000000001","previous_first":1,"reason":"size"}`), "does not name the segment"},
		{"previous not a segment name", line(5, other, `{"previous":"audit.jsonl.1","previous_first":1,"reason":"size"}`), "does not name the segment"},
		{"payload not an object", line(5, other, `7`), "does not name the segment"},
	} {
		_, err := Verify(strings.NewReader(tc.log + "\n"))
		if err == nil || !strings.HasPrefix(err.Error(), "line 1: ") || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	res, err := Verify(strings.NewReader(line(5, other, good) + "\n"))
	if err != nil || res.First != 5 || res.Start != other || res.Records != 5 || res.Previous != "audit.jsonl.00000000000000000001" {
		t.Fatalf("later segment alone: %+v %v", res, err)
	}
	if _, err := VerifyWith(strings.NewReader(line(5, other, `{"previous":"audit.jsonl.00000000000000000001","reason":"size"}`)+"\n"), Default()); err == nil {
		t.Fatal("schema accepted a segment start without previous_first")
	}
}

func TestSegmentsListing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	for _, n := range []string{"audit.jsonl", "audit.jsonl.next", "audit.jsonl.12", "audit.jsonl.bak",
		"audit.jsonl.00000000000000000000", "audit.jsonl.0000000000000000000x", "other.jsonl.00000000000000000001",
		"audit.jsonl.00000000000000000100", "audit.jsonl.00000000000000000001", "audit.jsonl.99999999999999999999"} {
		must(t, os.WriteFile(filepath.Join(dir, n), nil, 0o600))
	}
	must(t, os.Mkdir(filepath.Join(dir, "audit.jsonl.00000000000000000050"), 0o700))
	segs, err := Segments(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{SegmentPath(path, 1), SegmentPath(path, 100)} // the 20 nines overflow uint64
	if fmt.Sprint(segs) != fmt.Sprint(want) {
		t.Fatalf("segments %v", segs)
	}
	// A relative path lists the working directory's segments.
	t.Chdir(dir)
	if segs, err := Segments("audit.jsonl"); err != nil || len(segs) != 2 || segs[0] != "audit.jsonl.00000000000000000001" {
		t.Fatalf("relative: %v %v", segs, err)
	}
}

func TestRotationOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, r := range []Rotation{{MaxBytes: -1}, {MaxAge: -time.Second}} {
		if _, err := OpenWith(path, Options{Rotation: r}); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
	if (Rotation{}).Enabled() || !(Rotation{MaxAge: 1}).Enabled() {
		t.Fatal("Enabled")
	}
}

// What a rotation that crashed leaves behind is cleaned up by Open: the
// .next file, and a segment link that is a second name of the active file.
// The chain is as before the rotation began, and the next rotation works.
func TestRotationCrashLeftovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openRotating(t, path, Rotation{}, fixedNow)
	appendCalls(t, l, 0, 3)
	seq, head := l.Head()
	l.Close()

	// Crashed after writing .next, before the link.
	must(t, os.WriteFile(nextPath(path), []byte("{\"seq\":4"), 0o600))
	l = openRotating(t, path, Rotation{MaxBytes: 1}, fixedNow)
	if s, h := l.Head(); s != seq || h != head {
		t.Fatalf("head %d %s", s, h)
	}
	if _, err := os.Stat(nextPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".next left: %v", err)
	}
	l.Close()

	// Crashed after the link, before the rename.
	must(t, os.WriteFile(nextPath(path), nil, 0o600))
	must(t, os.Link(path, SegmentPath(path, 1)))
	l = openRotating(t, path, Rotation{MaxBytes: 1}, fixedNow)
	if segs, _ := Segments(path); len(segs) != 0 {
		t.Fatalf("stale link kept: %v", segs)
	}
	appendCalls(t, l, 3, 1) // rotates first: the link is made again
	l.Close()
	cr, recs := chainRecords(t, path)
	if len(cr.Segments) != 2 || len(recs) != 5 || recs[3].Event != EventSegmentStarted {
		t.Fatalf("after recovery: %v %d records", segNames(cr.Segments), len(recs))
	}

	// A segment of the same name that is another file is not touched.
	other := SegmentPath(path, 4)
	must(t, os.WriteFile(other, []byte("keep\n"), 0o600))
	l = openRotating(t, path, Rotation{}, fixedNow)
	l.Close()
	if b, _ := os.ReadFile(other); string(b) != "keep\n" {
		t.Fatalf("other file changed: %q", b)
	}
}

// A rotation that cannot make its link (the segment name is taken) fails
// the append without breaking the log; once the name is free the next
// append rotates.
func TestRotationFailureRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openRotating(t, path, Rotation{MaxBytes: 1}, fixedNow)
	defer l.Close()
	appendCalls(t, l, 0, 1)
	blocker := SegmentPath(path, 1)
	must(t, os.WriteFile(blocker, []byte("x"), 0o600))
	if err := l.Append("tool_call", callRec(1)); err == nil || errors.Is(err, ErrBroken) || !l.Healthy() {
		t.Fatalf("append over a taken segment name: %v healthy=%v", err, l.Healthy())
	}
	if _, err := os.Stat(nextPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".next left after a failed rotation: %v", err)
	}
	if s, _ := l.Head(); s != 1 {
		t.Fatalf("head moved to %d", s)
	}
	must(t, os.Remove(blocker))
	if err := l.Append("tool_call", callRec(2)); err != nil {
		t.Fatal(err)
	}
	if _, recs := chainRecords(t, path); len(recs) != 3 {
		t.Fatalf("%d records", len(recs))
	}

	// .next cannot be made: also retried.
	dir := filepath.Dir(path)
	must(t, os.Chmod(dir, 0o500))
	err := l.Append("tool_call", callRec(3))
	must(t, os.Chmod(dir, 0o700))
	if os.Geteuid() != 0 && (err == nil || !l.Healthy()) {
		t.Fatalf("append in a read-only directory: %v", err)
	}
	if err := l.Append("tool_call", callRec(4)); err != nil {
		t.Fatal(err)
	}
	chainRecords(t, path)
}

// The active file removed under a writer stops it, as damage does.
func TestRotationActiveRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openRotating(t, path, Rotation{MaxBytes: 1 << 20}, fixedNow)
	defer l.Close()
	appendCalls(t, l, 0, 1)
	must(t, os.Remove(path))
	if err := l.Append("tool_call", callRec(1)); !errors.Is(err, ErrBroken) || l.Healthy() {
		t.Fatalf("append after removal: %v", err)
	}
	if err := l.Rotate(); !errors.Is(err, ErrBroken) {
		t.Fatalf("rotate on a broken log: %v", err)
	}
}

// Two writers on one file, only one of them rotating: the other follows it
// into each new segment, and the chain holds every record once.
func TestRotateSharedWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a := openRotating(t, path, Rotation{MaxBytes: 1500}, fixedNow)
	defer a.Close()
	b := openRotating(t, path, Rotation{}, fixedNow)
	defer b.Close()
	for i := range 60 {
		w := a
		if i%3 == 0 {
			w = b
		}
		if err := w.Append("tool_call", callRec(i)); err != nil {
			t.Fatal(err)
		}
	}
	sa, ha := a.Head()
	sb, hb := b.Head()
	if sa != sb || ha != hb {
		t.Fatalf("heads %d %s and %d %s", sa, ha, sb, hb)
	}
	// b only follows: its own Rotate also works on the shared file.
	if err := b.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := a.Append("tool_call", callRec(60)); err != nil {
		t.Fatal(err)
	}
	cr, recs := chainRecords(t, path)
	if len(cr.Segments) < 4 {
		t.Fatalf("segments %v", segNames(cr.Segments))
	}
	checkOnce(t, recs, 61)
	// b's earlier segments' files are closed by its next fsync.
	if err := b.Append("tool_call", callRec(61)); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	n := len(b.retired)
	b.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d retired files still open", n)
	}
}

// checkOnce requires n tool calls with distinct payloads among recs.
func checkOnce(t *testing.T, recs []Record, n int) {
	t.Helper()
	seen := map[string]bool{}
	for _, r := range recs {
		if r.Event == EventSegmentStarted {
			continue
		}
		if seen[string(r.Data)] {
			t.Fatalf("record %s written twice", r.Data)
		}
		seen[string(r.Data)] = true
	}
	if len(seen) != n {
		t.Fatalf("%d records, want %d", len(seen), n)
	}
}

// Goroutines appending through rotations: every record lands once and
// every append returned only once durable (the group commit spans
// segments).
func TestRotateConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openRotating(t, path, Rotation{MaxBytes: 4096}, nil)
	const g, each = 8, 60
	var wg sync.WaitGroup
	for w := range g {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				if err := l.Append("tool_call", callRec(w*1000+i)); err != nil {
					t.Error(err)
					return
				}
				if i%20 == 0 {
					if err := l.Rotate(); err != nil {
						t.Error(err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	l.Close()
	cr, recs := chainRecords(t, path)
	if len(cr.Segments) < 10 {
		t.Fatalf("segments %v", segNames(cr.Segments))
	}
	checkOnce(t, recs, g*each)
}

// Separate processes appending to one rotating log: each follows the
// others' rotations.
func TestRotateWriterProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	const procs = 4
	cmds := make([]*exec.Cmd, procs)
	outs := make([]bytes.Buffer, procs)
	for i := range cmds {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRotateWriterChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), "AUDIT_ROTATE_PATH="+path, "AUDIT_ROTATE_ID="+strconv.Itoa(i))
		cmd.Stdout, cmd.Stderr = &outs[i], &outs[i]
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds[i] = cmd
	}
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("writer %d: %v\n%s", i, err, outs[i].String())
		}
	}
	cr, recs := chainRecords(t, path)
	if len(cr.Segments) < 10 {
		t.Fatalf("segments %v", segNames(cr.Segments))
	}
	checkOnce(t, recs, procs*sharedEach)
	if _, err := os.Stat(nextPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".next left: %v", err)
	}
}

func TestRotateWriterChild(t *testing.T) {
	path := os.Getenv("AUDIT_ROTATE_PATH")
	if path == "" {
		t.Skip("run by TestRotateWriterProcesses")
	}
	id := os.Getenv("AUDIT_ROTATE_ID")
	// Writers disagree on the limit; whoever reaches its own rotates.
	l, err := OpenWith(path, Options{Rotation: Rotation{MaxBytes: int64(2048 * (1 + len(id)%2))}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var wg sync.WaitGroup
	for g := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range sharedEach / 3 {
				if err := l.Append("tool_call", map[string]any{"p": id, "g": g, "i": i}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// BenchmarkAppendRotating is BenchmarkAppendParallel with 64 KiB segments:
// a rotation every few hundred records.
func BenchmarkAppendRotating(b *testing.B) {
	path := filepath.Join(b.TempDir(), "audit.jsonl")
	l, err := OpenWith(path, Options{Rotation: Rotation{MaxBytes: 64 << 10}})
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	data := map[string]any{"agent": "alice-bot", "tool": "fs.read_file", "decision": "allow", "rule_id": "fs-read"}
	b.SetParallelism(16)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := l.Append("tool_call", data); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// An Open that waits for the lock while the file is rotated opens the new
// active file, not the segment the path named when it started.
func TestOpenDuringRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a := openRotating(t, path, Rotation{}, fixedNow)
	defer a.Close()
	appendCalls(t, a, 0, 2)
	a.mu.Lock()
	must(t, lockFile(a.osf))
	opened := make(chan *Log)
	go func() {
		l, err := Open(path, fixedNow)
		if err != nil {
			t.Error(err)
		}
		opened <- l
	}()
	time.Sleep(50 * time.Millisecond) // let Open block on the lock
	err := a.rotate(RotateManual)
	unlockFile(a.osf)
	a.mu.Unlock()
	must(t, err)
	b := <-opened
	if b == nil {
		t.FailNow()
	}
	defer b.Close()
	sa, ha := a.Head()
	if sb, hb := b.Head(); sb != sa || hb != ha || b.first != 3 {
		t.Fatalf("opened at %d %s (first %d), want %d %s", sb, hb, b.first, sa, ha)
	}
	appendCalls(t, b, 2, 1)
	cr, recs := chainRecords(t, path)
	if len(cr.Segments) != 2 || len(recs) != 4 {
		t.Fatalf("%v %d", segNames(cr.Segments), len(recs))
	}
}

// SegmentError unwraps to the line error inside a segment.
func TestSegmentErrorUnwraps(t *testing.T) {
	path, files := buildSegments(t)
	raw, _ := os.ReadFile(files[0])
	must(t, os.WriteFile(files[0], bytes.Replace(raw, []byte(`"seq":2,`), []byte(`"seq":9,`), 1), 0o600))
	_, err := VerifyChain(path, nil)
	var le *LineError
	if !errors.As(err, &le) || le.Line != 2 {
		t.Fatalf("got %v", err)
	}
}

// A writer that was idle through several rotations follows each segment in
// turn, not just the newest file; one whose next segment is gone stops.
func TestFollowSeveralRotations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a := openRotating(t, path, Rotation{}, fixedNow)
	defer a.Close()
	b := openRotating(t, path, Rotation{}, fixedNow)
	defer b.Close()
	appendCalls(t, b, 0, 1)
	for i := range 3 {
		appendCalls(t, a, 1+i, 1)
		must(t, a.Rotate())
	}
	appendCalls(t, b, 10, 1)
	sa, ha := a.Head()
	if sb, hb := b.Head(); sb != sa || hb != ha {
		t.Fatalf("b at %d %s, a at %d %s", sb, hb, sa, ha)
	}
	_, recs := chainRecords(t, path)
	checkOnce(t, recs, 5)

	c := openRotating(t, path, Rotation{}, fixedNow)
	defer c.Close()
	must(t, a.Rotate())
	must(t, a.Rotate())
	segs, _ := Segments(path)
	must(t, os.Remove(segs[len(segs)-1])) // the one after c's
	if err := c.Append("tool_call", callRec(20)); !errors.Is(err, ErrBroken) || !strings.Contains(err.Error(), "no segment starts at record") {
		t.Fatalf("missing next segment: %v", err)
	}
}
