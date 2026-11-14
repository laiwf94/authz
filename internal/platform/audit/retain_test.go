//go:build unix

package audit

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// openRetaining opens a signed log that rotates every 4 KiB and keeps at
// most ret's limits of rotated-out segments.
func openRetaining(t *testing.T, path string, ret Retention, now func() time.Time, onErr func(error)) *Log {
	t.Helper()
	if now == nil {
		now = fixedNow
	}
	l, err := OpenWith(path, Options{Now: now, Signer: testSigner(t), CheckpointEvery: time.Hour,
		Rotation: Rotation{MaxBytes: MinRotateBytes}, Retention: ret, OnRetainError: onErr})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// segFirsts lists the first records of the log's rotated-out segments.
func segFirsts(t *testing.T, path string) []uint64 {
	t.Helper()
	segs, err := Segments(path)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]uint64, len(segs))
	for i, p := range segs {
		out[i], _ = segmentFirst(filepath.Base(path), filepath.Base(p))
	}
	return out
}

func failOnRetainError(t *testing.T) func(error) {
	return func(err error) { t.Errorf("retention: %v", err) }
}

// Nothing is removed until a checkpoint is exported, then only the oldest
// segments that it covers, as far as the limit asks; what is left verifies,
// keeps its tree head, and proves inclusion and consistency.
func TestRetentionKeepsWhatNoExportCovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openRetaining(t, path, Retention{MaxBytes: 3 * MinRotateBytes}, nil, failOnRetainError(t))
	defer l.Close()
	appendN(t, l, 0, 400)
	before := segFirsts(t, path)
	if len(before) < 8 {
		t.Fatalf("only %d segments; the test needs more", len(before))
	}
	if _, err := os.Stat(BasePath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a base file without any export: %v", err)
	}
	wantRoot, n := refRoot(t, path)

	// Export a checkpoint: every segment it covers may go, as far as the
	// limit asks.
	note, exp, err := l.Export()
	if err != nil {
		t.Fatal(err)
	}
	if exp.Size != n || exp.Root != wantRoot {
		t.Fatalf("exported checkpoint of %d records, root %s; want %d, %s", exp.Size, exp.Root, n, wantRoot)
	}
	if got, _ := os.ReadFile(ExportedPath(path)); !bytes.Equal(got, note) {
		t.Fatal("FILE.exported is not the exported note")
	}
	after := segFirsts(t, path)
	if len(after) >= len(before) || len(after) == 0 {
		t.Fatalf("segments %v after export, %v before", after, before)
	}
	cr, err := VerifyChain(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Removed != after[0]-1 || cr.Records != n || cr.Root != wantRoot {
		t.Fatalf("after retention: removed %d, records %d, root %s; want %d, %d, %s", cr.Removed, cr.Records, cr.Root, after[0]-1, n, wantRoot)
	}
	var kept int64
	for _, s := range cr.Segments[:len(cr.Segments)-1] {
		fi, _ := os.Stat(s.Path)
		kept += fi.Size()
	}
	if kept > 3*MinRotateBytes || kept+MinRotateBytes+512 < 3*MinRotateBytes {
		t.Fatalf("the rotated-out segments left hold %d bytes; the limit is %d", kept, 3*MinRotateBytes)
	}
	if err := cr.Covers(exp); err != nil {
		t.Fatal(err)
	}

	// Many more records, far past the limit: the segments holding records
	// after the export all stay.
	appendN(t, l, 400, 300)
	got := segFirsts(t, path)
	if got[0] > exp.Size+1 || len(got) < 10 {
		t.Fatalf("segments %v are left; the one holding record %d, after the export, must be among them", got, exp.Size+1)
	}
	checkRoot(t, l, path) // the tree head still covers every record
	cr, err = VerifyChain(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cr.Covers(exp); err != nil {
		t.Fatalf("the exported checkpoint no longer verifies: %v", err)
	}
	if cr.Removed > exp.Size {
		t.Fatalf("records 1 to %d removed; the export covers %d", cr.Removed, exp.Size)
	}

	// Proofs: a record after the base, consistency from the export, and
	// a refusal for a removed record.
	pr, err := l.InclusionProof(cr.Removed+1, 0)
	if err != nil {
		t.Fatal(err)
	}
	latest := openNote(t, pr.Checkpoint)
	if err := pr.Check(latest, nil); err != nil {
		t.Fatal(err)
	}
	cons, err := l.ConsistencyProof(exp.Size, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := cons.Check(latest, &exp); err != nil {
		t.Fatalf("consistency from the exported checkpoint: %v", err)
	}
	if _, err := l.InclusionProof(cr.Removed, 0); !errors.Is(err, ErrProofRange) || !strings.Contains(err.Error(), "removed by retention") {
		t.Fatalf("proof of a removed record: %v", err)
	}
	if _, err := l.ConsistencyProof(1, 0); !errors.Is(err, ErrProofRange) {
		t.Fatalf("consistency from a removed tree: %v", err)
	}

	// Query starts at the base.
	seqs, _, err := query(t, path, QueryOptions{Full: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(seqs) == 0 || seqs[0] != cr.Removed+1 || seqs[len(seqs)-1] != cr.Records {
		t.Fatalf("query read records %d to %d; want %d to %d", seqs[0], seqs[len(seqs)-1], cr.Removed+1, cr.Records)
	}

	// Reopening takes up the saved tree; rebuilding it from the segments
	// left and the base gives the same root.
	l.Close()
	l2 := openRetaining(t, path, Retention{MaxBytes: 3 * MinRotateBytes}, nil, failOnRetainError(t))
	c1 := checkRoot(t, l2, path)
	l2.Close()
	if err := os.Remove(TreePath(path)); err != nil {
		t.Fatal(err)
	}
	l3 := openRetaining(t, path, Retention{MaxBytes: 3 * MinRotateBytes}, nil, failOnRetainError(t))
	defer l3.Close()
	if c3 := checkRoot(t, l3, path); c3.Root != c1.Root {
		t.Fatal("the rebuilt tree has another root")
	}
}

// Segments are removed by age, counted from when they were rotated out.
func TestRetentionByAge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	c := newClock()
	l := openRetaining(t, path, Retention{MaxAge: 48 * time.Hour}, c.now, failOnRetainError(t))
	defer l.Close()
	appendN(t, l, 0, 100)
	early := segFirsts(t, path)
	c.add(24 * time.Hour)
	appendN(t, l, 100, 100)
	if _, _, err := l.Export(); err != nil {
		t.Fatal(err)
	}
	if got := segFirsts(t, path); got[0] != 1 {
		t.Fatalf("segments removed a day after rotation: %v", got)
	}
	all := segFirsts(t, path)
	c.add(25 * time.Hour)
	if err := l.Retain(); err != nil {
		t.Fatal(err)
	}
	got := segFirsts(t, path)
	// The early segments were rotated out 49 hours ago; the next one, the
	// active segment then, a day later.
	if got[0] != all[len(early)] {
		t.Fatalf("after 49 hours segments %v are left; want them to start at %d (of %v)", got, all[len(early)], all)
	}
	if _, err := VerifyChain(path, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if _, err := OpenWith(path, Options{Retention: Retention{MaxBytes: MinRetainBytes}}); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("retention without a signer: %v", err)
	}
	if _, err := OpenWith(path, Options{Signer: testSigner(t), Retention: Retention{MaxBytes: -1}}); err == nil {
		t.Fatal("negative retention opened")
	}
	for _, tc := range []struct {
		bytes, age string
		ok         bool
		want       string
	}{
		{"", "", true, "no retention"},
		{"4096", "", true, "max_bytes=4096"},
		{"", "720h", true, "max_age=720h0m0s"},
		{"1048576", "24h", true, "max_bytes=1048576 max_age=24h0m0s"},
		{"4095", "", false, "under the minimum"},
		{"", "59m", false, "under the minimum"},
		{"-1", "", false, "negative"},
		{"1k", "", false, "whole number"},
		{"", "a week", false, "duration"},
	} {
		r, err := ParseRetention(tc.bytes, tc.age)
		switch {
		case tc.ok && err != nil:
			t.Errorf("%q %q: %v", tc.bytes, tc.age, err)
		case tc.ok && r.String() != tc.want:
			t.Errorf("%q %q: %s, want %s", tc.bytes, tc.age, r, tc.want)
		case !tc.ok && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%q %q: %v, want an error with %q", tc.bytes, tc.age, err, tc.want)
		}
	}
}

// Only a checkpoint of this log, signed by its key, lets segments go; a
// smaller export never replaces a larger one.
func TestRetentionExportedChecks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	var errs []error
	var mu sync.Mutex
	onErr := func(err error) { mu.Lock(); errs = append(errs, err); mu.Unlock() }
	l := openRetaining(t, path, Retention{MaxBytes: MinRetainBytes}, nil, onErr)
	defer l.Close()
	appendN(t, l, 0, 200)

	// Another log under the same key, longer than this one.
	other := filepath.Join(dir, "other.jsonl")
	ol := openSigned(t, other, Rotation{})
	appendN(t, ol, 1000, 150)
	oNote, _, err := ol.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	ol.Close()
	if err := MarkExported(path, oNote, testSigner(t).Verifier()); err != nil {
		t.Fatal(err)
	}
	if err := l.Retain(); err == nil || !strings.Contains(err.Error(), "not a checkpoint of this log") {
		t.Fatalf("retention with another log's checkpoint: %v", err)
	}
	if got := segFirsts(t, path); got[0] != 1 {
		t.Fatalf("segments %v removed under another log's checkpoint", got)
	}
	// One signed by another key is refused before it is recorded.
	other2 := filepath.Join(dir, "other2.jsonl")
	key := otherSigner(t)
	s2, err := ParseSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	ol2, err := OpenWith(other2, Options{Signer: s2, CheckpointEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	n2, _, _ := ol2.Checkpoint()
	ol2.Close()
	if err := MarkExported(path, n2, testSigner(t).Verifier()); err == nil {
		t.Fatal("a checkpoint signed by another key was recorded as exported")
	}
	// A forged one in the file is not trusted either.
	if err := os.WriteFile(ExportedPath(path), n2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Retain(); err == nil {
		t.Fatal("retention trusted a checkpoint signed by another key")
	}

	// A real export, then an older one: the newer stays recorded.
	early, _, err := l.Export()
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 200, 10)
	late, _, err := l.Export()
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkExported(path, early, testSigner(t).Verifier()); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(ExportedPath(path)); !bytes.Equal(got, late) {
		t.Fatal("an older export replaced a newer one")
	}
	if got := segFirsts(t, path); len(got) > 0 && got[0] == 1 {
		t.Fatal("nothing was removed after a real export")
	}
	if _, err := VerifyChain(path, nil); err != nil {
		t.Fatal(err)
	}
}

// A crash after the base was written and before the segments were removed
// leaves them behind: readers pass over them, and the next open removes
// them. A crash before it changes nothing.
func TestRetentionCrashLeavesCoveredSegments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l := openRetaining(t, path, Retention{MaxBytes: 2 * MinRetainBytes}, nil, failOnRetainError(t))
	appendN(t, l, 0, 300)
	saved := map[string][]byte{}
	segs, _ := Segments(path)
	for _, p := range segs {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		saved[p] = b
	}
	if _, _, err := l.Export(); err != nil {
		t.Fatal(err)
	}
	cr, err := VerifyChain(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	// Put the removed segments back, as a crash before their removal
	// leaves them.
	restored := 0
	for p, b := range saved {
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
			restored++
		}
	}
	if restored == 0 {
		t.Fatal("nothing was removed")
	}
	cr2, err := VerifyChain(path, nil)
	if err != nil {
		t.Fatalf("with the covered segments left behind: %v", err)
	}
	if cr2.Removed != cr.Removed || cr2.Root != cr.Root || len(cr2.Segments) != len(cr.Segments) {
		t.Fatalf("the left-behind segments changed the result: %+v vs %+v", cr2, cr)
	}
	if _, _, err := query(t, path, QueryOptions{Full: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := ProveInclusion(path, cr.Removed+1, cr.Records); err != nil {
		t.Fatal(err)
	}
	l = openRetaining(t, path, Retention{MaxBytes: 2 * MinRetainBytes}, nil, failOnRetainError(t))
	defer l.Close()
	if got := segFirsts(t, path); got[0] != cr.Removed+1 {
		t.Fatalf("open left segments %v; want them to start at %d", got, cr.Removed+1)
	}
}

// What retention leaves cannot be cut further without verify naming it.
func TestRetentionTampering(t *testing.T) {
	setup := func(t *testing.T) (string, ChainResult) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		l := openRetaining(t, path, Retention{MaxBytes: 2 * MinRetainBytes}, nil, failOnRetainError(t))
		appendN(t, l, 0, 400)
		if _, _, err := l.Export(); err != nil {
			t.Fatal(err)
		}
		appendN(t, l, 400, 50)
		l.Close()
		cr, err := VerifyChain(path, nil)
		if err != nil || cr.Removed == 0 || len(cr.Segments) < 3 {
			t.Fatalf("setup: %v, %+v", err, cr)
		}
		return path, cr
	}
	editBase := func(t *testing.T, path string, f func([]string)) {
		b, err := os.ReadFile(BasePath(path))
		if err != nil {
			t.Fatal(err)
		}
		ls := strings.SplitN(string(b), "\n", 7)
		f(ls)
		if err := os.WriteFile(BasePath(path), []byte(strings.Join(ls, "\n")), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		do   func(t *testing.T, path string, cr ChainResult)
		want string
	}{
		{"oldest segment left removed", func(t *testing.T, path string, cr ChainResult) {
			must(t, os.Remove(cr.Segments[0].Path))
		}, "missing between the records retention removed"},
		{"base removed", func(t *testing.T, path string, cr ChainResult) {
			must(t, os.Remove(BasePath(path)))
		}, "not 1; the segments before it"},
		{"base head changed", func(t *testing.T, path string, cr ChainResult) {
			editBase(t, path, func(ls []string) { ls[2] = strings.Repeat("ab", 32) })
		}, "does not match the hash of record"},
		{"base claims more", func(t *testing.T, path string, cr ChainResult) {
			editBase(t, path, func(ls []string) { ls[1] = "999999" })
		}, "range holds"},
		{"base names another segment", func(t *testing.T, path string, cr ChainResult) {
			editBase(t, path, func(ls []string) { ls[4] = "audit.jsonl.00000000000000000002" })
		}, "as the one before it"},
		{"base damaged", func(t *testing.T, path string, cr ChainResult) {
			must(t, os.WriteFile(BasePath(path), []byte("authz audit base\n"), 0o600))
		}, "not an audit base file"},
		{"active file emptied", func(t *testing.T, path string, cr ChainResult) {
			for _, s := range cr.Segments[:len(cr.Segments)-1] {
				must(t, os.Remove(s.Path))
			}
			must(t, os.WriteFile(path, nil, 0o600))
		}, "active segment is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, cr := setup(t)
			tc.do(t, path, cr)
			_, err := VerifyChain(path, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyChain: %v, want an error with %q", err, tc.want)
			}
		})
	}

	// A base whose range was changed verifies as a chain, but its tree
	// head is not the signed one.
	t.Run("base range changed", func(t *testing.T) {
		path, cr := setup(t)
		note, err := os.ReadFile(CheckpointPath(path))
		if err != nil {
			t.Fatal(err)
		}
		cp := openNote(t, string(note))
		editBase(t, path, func(ls []string) {
			raw, err := base64.StdEncoding.DecodeString(ls[3])
			if err != nil {
				t.Fatal(err)
			}
			raw[8+5] ^= 1 // a byte of the first subtree hash, after the size
			ls[3] = base64.StdEncoding.EncodeToString(raw)
		})
		cr2, err := VerifyChain(path, nil)
		if err != nil {
			t.Fatalf("the chain does not cover the range, so it verifies: %v", err)
		}
		if cr2.Root == cr.Root {
			t.Fatal("a changed range kept the root")
		}
		if err := cr2.Covers(cp); err == nil {
			t.Fatal("the signed checkpoint covers a log with a forged base")
		}
	})
}

// Writers sharing one file remove segments under its lock, each after
// another's rotations, and the chain stays whole.
func TestRetentionSharedWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ret := Retention{MaxBytes: 2 * MinRetainBytes}
	a := openRetaining(t, path, ret, nil, failOnRetainError(t))
	b := openRetaining(t, path, ret, nil, failOnRetainError(t))
	var wg sync.WaitGroup
	for i, l := range []*Log{a, b} {
		wg.Go(func() {
			for j := range 200 {
				if err := l.Append("tool_call", callRec(i*1000+j)); err != nil {
					t.Error(err)
					return
				}
				if j%40 == 39 {
					if _, _, err := l.Export(); err != nil {
						t.Error(err)
						return
					}
				}
			}
		})
	}
	wg.Wait()
	a.Close()
	b.Close()
	cr, err := VerifyChain(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Removed == 0 {
		t.Fatalf("nothing was removed: %+v", cr)
	}
	cp := readCheckpoint(t, path, testSigner(t).Verifier())
	if err := cr.Covers(cp); err != nil {
		t.Fatal(err)
	}
}

func TestParseBase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openRetaining(t, path, Retention{MaxBytes: MinRetainBytes}, nil, failOnRetainError(t))
	appendN(t, l, 0, 200)
	if _, _, err := l.Export(); err != nil {
		t.Fatal(err)
	}
	l.Close()
	good, err := os.ReadFile(BasePath(path))
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseBase(good)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := b.encode(); err != nil || !bytes.Equal(again, good) {
		t.Fatalf("encode does not give the file back: %v", err)
	}
	ls := strings.SplitN(string(good), "\n", 7)
	edit := func(i int, v string) []byte {
		c := append([]string(nil), ls...)
		c[i] = v
		return []byte(strings.Join(c, "\n"))
	}
	note := ls[6]
	cp := openNote(t, note)
	for _, tc := range []struct {
		name string
		b    []byte
		want string
	}{
		{"empty", nil, "not an audit base file"},
		{"magic", edit(0, "authz audit tree"), "not an audit base file"},
		{"no blank line", edit(5, "x"), "not an audit base file"},
		{"size", edit(1, "12a"), "decimal"},
		{"none removed", []byte(strings.Join([]string{ls[0], "0", Genesis, "AAAAAAAAAAA=", ls[4], "", note}, "\n")), "removes no records"},
		{"head", edit(2, "xyz"), "hex SHA-256"},
		{"range", edit(3, "!!"), "base64"},
		{"segment name", edit(4, "audit.jsonl"), "segment's file name"},
		{"segment path", edit(4, "../audit.jsonl.00000000000000000001"), "segment's file name"},
		{"note", edit(6, "not a note"), "exported checkpoint"},
		{"note too small", edit(1, "99999"), "range holds"},
	} {
		if _, err := parseBase(tc.b); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error with %q", tc.name, err, tc.want)
		}
	}
	// A base that says more were removed than its checkpoint covers.
	r := b.r.Clone()
	for range cp.Size + 1 - b.size {
		r.AppendData([]byte("x"))
	}
	big := &removedBase{size: r.Size(), head: b.head, r: r, last: b.last, note: b.note}
	enc, _ := big.encode()
	if _, err := parseBase(enc); err == nil || !strings.Contains(err.Error(), "fewer than the") {
		t.Fatalf("a base past its checkpoint: %v", err)
	}
}

// A failure to remove on open is reported, not fatal.
func TestRetentionReportsOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openRetaining(t, path, Retention{MaxBytes: MinRetainBytes}, nil, failOnRetainError(t))
	appendN(t, l, 0, 100)
	l.Close()
	if err := os.WriteFile(ExportedPath(path), []byte("not a note\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []error
	l = openRetaining(t, path, Retention{MaxBytes: MinRetainBytes}, nil, func(err error) { got = append(got, err) })
	defer l.Close()
	if len(got) != 1 || !strings.Contains(got[0].Error(), filepath.Base(ExportedPath(path))) {
		t.Fatalf("reported %v", got)
	}
	if segFirsts(t, path)[0] != 1 {
		t.Fatal("segments were removed under a damaged export")
	}
}
