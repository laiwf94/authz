//go:build unix

package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := ParseSigner(peterSigner)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// readCheckpoint opens the checkpoint stored beside the log at path.
func readCheckpoint(t *testing.T, path string, v *Verifier) Checkpoint {
	t.Helper()
	msg, err := os.ReadFile(CheckpointPath(path))
	if err != nil {
		t.Fatal(err)
	}
	c, err := OpenCheckpoint(msg, v)
	if err != nil {
		t.Fatalf("OpenCheckpoint: %v\n%s", err, msg)
	}
	return c
}

// lineHashes returns the hash of every line of a file, in order.
func lineHashes(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, MaxLineBytes)
	for sc.Scan() {
		sum := sha256.Sum256(sc.Bytes())
		out = append(out, hex.EncodeToString(sum[:]))
	}
	return out
}

func TestCheckpointText(t *testing.T) {
	c := Checkpoint{Origin: "PeterNeumann", Size: 3, Head: strings.Repeat("ab", 32),
		Time: time.Date(2026, 11, 16, 9, 30, 0, 500, time.UTC)}
	text, err := c.Text()
	if err != nil {
		t.Fatal(err)
	}
	want := "PeterNeumann\n3\nq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=\ntime 2026-11-16T09:30:00.0000005Z\n"
	if string(text) != want {
		t.Fatalf("text\n got %q\nwant %q", text, want)
	}
	back, err := ParseCheckpoint(text)
	if err != nil || back != c {
		t.Fatalf("ParseCheckpoint = %+v, %v", back, err)
	}
	empty, err := Checkpoint{Origin: "o", Head: Genesis, Time: c.Time}.Text()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCheckpoint(empty); err != nil {
		t.Fatalf("empty log: %v", err)
	}
	head := "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="
	for name, text := range map[string]string{
		"three lines":        "o\n3\n" + head + "\n",
		"extra line":         "o\n3\n" + head + "\ntime 2026-11-16T09:30:00Z\nmore\n",
		"no final newline":   "o\n3\n" + head + "\ntime 2026-11-16T09:30:00Z",
		"origin with space":  "o o\n3\n" + head + "\ntime 2026-11-16T09:30:00Z\n",
		"leading zero":       "o\n03\n" + head + "\ntime 2026-11-16T09:30:00Z\n",
		"negative":           "o\n-3\n" + head + "\ntime 2026-11-16T09:30:00Z\n",
		"short head":         "o\n3\nq6ur\ntime 2026-11-16T09:30:00Z\n",
		"not base64":         "o\n3\n!!!!\ntime 2026-11-16T09:30:00Z\n",
		"zero size, a head":  "o\n0\n" + head + "\ntime 2026-11-16T09:30:00Z\n",
		"no time keyword":    "o\n3\n" + head + "\n2026-11-16T09:30:00Z\n",
		"bad time":           "o\n3\n" + head + "\ntime yesterday\n",
		"padding bits taken": "o\n3\nq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6t=\ntime 2026-11-16T09:30:00Z\n",
	} {
		if _, err := ParseCheckpoint([]byte(text)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := (Checkpoint{Origin: "a b", Head: Genesis}).Text(); err == nil {
		t.Error("bad origin encoded")
	}
	if _, err := (Checkpoint{Origin: "o", Head: "xyz"}).Text(); err == nil {
		t.Error("bad head encoded")
	}
}

func TestCheckpointSignOpen(t *testing.T) {
	s := testSigner(t)
	v := s.Verifier()
	c := Checkpoint{Origin: s.Name(), Size: 7, Head: strings.Repeat("01", 32), Time: fixedNow().UTC()}
	msg, err := c.Sign(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenCheckpoint(msg, v)
	if err != nil || got != c {
		t.Fatalf("OpenCheckpoint = %+v, %v", got, err)
	}
	// The same checkpoint opens with any note verifier: the text is what
	// was signed, followed by one signature line.
	if !strings.HasPrefix(string(msg), "PeterNeumann\n7\n") || !strings.Contains(string(msg), "\n\n— PeterNeumann ") {
		t.Fatalf("not a signed note:\n%s", msg)
	}
	// A changed record count does not verify.
	if _, err := OpenCheckpoint([]byte(strings.Replace(string(msg), "\n7\n", "\n8\n", 1)), v); err == nil {
		t.Fatal("changed checkpoint opened")
	}
	// Another key.
	if _, err := OpenCheckpoint(msg, mustVerifier(t, enochVerifier)); err == nil {
		t.Fatal("opened with another key")
	}
	// A note by the key for another origin is not its checkpoint.
	text, _ := Checkpoint{Origin: "EnochRoot", Size: 1, Head: c.Head, Time: c.Time}.Text()
	other, err := SignNote(text, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCheckpoint(other, v); err == nil || !strings.Contains(err.Error(), "for EnochRoot") {
		t.Fatalf("other origin: %v", err)
	}
	if _, err := (Checkpoint{Origin: "EnochRoot", Head: Genesis}).Sign(s); err == nil {
		t.Fatal("signed a checkpoint for another origin")
	}
	// Signed text that is not a checkpoint.
	junk, _ := SignNote([]byte("hello\n"), s)
	if _, err := OpenCheckpoint(junk, v); err == nil {
		t.Fatal("opened a note that is not a checkpoint")
	}
}

func TestCheckpointEveryParse(t *testing.T) {
	if d, err := ParseCheckpointEvery(""); err != nil || d != DefaultCheckpointEvery {
		t.Fatalf("empty: %v, %v", d, err)
	}
	if d, err := ParseCheckpointEvery("30s"); err != nil || d != 30*time.Second {
		t.Fatalf("30s: %v, %v", d, err)
	}
	for _, s := range []string{"10", "500ms", "-1m", "0s", "soon"} {
		if _, err := ParseCheckpointEvery(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestLogCheckpoints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	s := testSigner(t)
	v := s.Verifier()
	clk := newClock()
	l, err := OpenWith(path, Options{Now: clk.now, Signer: s, CheckpointEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	// Opening signs the empty log.
	if c := readCheckpoint(t, path, v); c.Size != 0 || c.Head != Genesis || c.Origin != "PeterNeumann" {
		t.Fatalf("open checkpoint %+v", c)
	}
	for i := range 3 {
		if err := l.Append("tool_call", callRec(i)); err != nil {
			t.Fatal(err)
		}
	}
	clk.add(time.Second)
	msg, c, err := l.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	n, head := l.Head()
	if c.Size != n || c.Head != head || n != 3 || !c.Time.Equal(clk.now()) {
		t.Fatalf("checkpoint %+v, head %d %s", c, n, head)
	}
	if stored, _ := os.ReadFile(CheckpointPath(path)); string(stored) != string(msg) {
		t.Fatalf("stored checkpoint differs from the returned one")
	}
	// Nothing new: the same checkpoint, not a new signature.
	clk.add(time.Second)
	msg2, c2, err := l.Checkpoint()
	if err != nil || string(msg2) != string(msg) || c2 != c {
		t.Fatalf("second checkpoint %+v, %v", c2, err)
	}
	if err := l.Append("tool_call", callRec(3)); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Close signed the final state.
	if c := readCheckpoint(t, path, v); c.Size != 4 || c.Head != lineHashes(t, path)[3] {
		t.Fatalf("close checkpoint %+v", c)
	}
	if _, err := os.Stat(CheckpointPath(path) + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary file left: %v", err)
	}
	cr, err := VerifyChain(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cr.Covers(readCheckpoint(t, path, v)); err != nil {
		t.Fatal(err)
	}
	// Without a signer there are no checkpoints.
	l2, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if _, _, err := l2.Checkpoint(); !errors.Is(err, ErrNoSigner) {
		t.Fatalf("Checkpoint without signer: %v", err)
	}
}

func TestCheckpointTimer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	s := testSigner(t)
	l, err := OpenWith(path, Options{Signer: s, CheckpointEvery: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := range 5 {
		if err := l.Append("tool_call", callRec(i)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		msg, err := os.ReadFile(CheckpointPath(path))
		if err == nil {
			if c, err := OpenCheckpoint(msg, s.Verifier()); err == nil && c.Size == 5 {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the timer did not sign 5 records: %s", msg)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCheckpointOnRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	s := testSigner(t)
	v := s.Verifier()
	l, err := OpenWith(path, Options{Signer: s, CheckpointEvery: time.Hour, Rotation: Rotation{MaxBytes: 600}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var rotatedAt uint64
	for i := 0; rotatedAt == 0; i++ {
		before, _ := Segments(path)
		if err := l.Append("tool_call", callRec(i)); err != nil {
			t.Fatal(err)
		}
		if after, _ := Segments(path); len(after) > len(before) {
			n, _ := l.Head()
			rotatedAt = n - 1 // the segment start record; the append came after it
		}
		if i > 100 {
			t.Fatal("no rotation")
		}
	}
	c := readCheckpoint(t, path, v)
	if c.Size != rotatedAt {
		t.Fatalf("checkpoint after rotation covers %d records, want %d (through the segment start record)", c.Size, rotatedAt)
	}
	if c.Head != lineHashes(t, path)[0] {
		t.Fatal("checkpoint head is not the segment start record")
	}
	// A manual rotation signs too.
	if err := l.Rotate(); err != nil {
		t.Fatal(err)
	}
	n, head := l.Head()
	if c := readCheckpoint(t, path, v); c.Size != n || c.Head != head {
		t.Fatalf("checkpoint after Rotate %+v, head %d", c, n)
	}
	cr, err := VerifyChain(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cr.Covers(c); err != nil {
		t.Fatalf("an older checkpoint inside an earlier segment: %v", err)
	}
}

func TestOpenRefusesLogShorterThanCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	s := testSigner(t)
	l, err := OpenWith(path, Options{Signer: s})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if err := l.Append("tool_call", callRec(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	whole, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(whole), "\n")
	// Records 4 and 5 removed: the chain still verifies, the checkpoint
	// does not allow it.
	if err := os.WriteFile(path, []byte(strings.Join(lines[:3], "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(path, Options{Signer: s}); err == nil || !strings.Contains(err.Error(), "covers 5 records: records were removed from its end") {
		t.Fatalf("open of a cut log: %v", err)
	}
	// The last record changed, valid JSON and chain.
	changed := strings.Join(lines[:4], "") + strings.Replace(lines[4], `"t4"`, `"t9"`, 1)
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(path, Options{Signer: s}); err == nil || !strings.Contains(err.Error(), "the last record was changed") {
		t.Fatalf("open of a log with its last record changed: %v", err)
	}
	// Without the key, or with another, the log opens; another key's
	// checkpoint replaces this one.
	l2, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	l2.Close()
	other, err := ParseSigner(otherSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	l3, err := OpenWith(path, Options{Signer: other})
	if err != nil {
		t.Fatal(err)
	}
	l3.Close()
	if c := readCheckpoint(t, path, other.Verifier()); c.Size != 5 {
		t.Fatalf("other key's checkpoint %+v", c)
	}
}

// otherSigner is a second, generated key.
func otherSigner(t *testing.T) string {
	t.Helper()
	skey, _, err := GenerateKey(strings.NewReader(strings.Repeat("k", 64)), "Other")
	if err != nil {
		t.Fatal(err)
	}
	return skey
}

func TestCheckpointSharedWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	s := testSigner(t)
	a, err := OpenWith(path, Options{Signer: s, CheckpointEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenWith(path, Options{Signer: s, CheckpointEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var wg sync.WaitGroup
	for w, l := range []*Log{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 20 {
				if err := l.Append("tool_call", callRec(w*100+i)); err != nil {
					t.Error(err)
					return
				}
				if i%5 == 0 {
					if _, _, err := l.Checkpoint(); err != nil {
						t.Error(err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	// b signs what a wrote too; a then finds b's checkpoint and keeps it.
	msgB, cb, err := b.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	msgA, ca, err := a.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if cb.Size != 40 || ca != cb || string(msgA) != string(msgB) {
		t.Fatalf("checkpoints a %+v, b %+v", ca, cb)
	}
	if h := lineHashes(t, path); cb.Head != h[39] {
		t.Fatal("head is not record 40")
	}
}

func TestCheckpointWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	s := testSigner(t)
	// A directory where the checkpoint goes: opening fails.
	if err := os.Mkdir(CheckpointPath(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(path, Options{Signer: s}); err == nil {
		t.Fatal("opened without being able to read the checkpoint")
	}
	os.Remove(CheckpointPath(path))
	var mu sync.Mutex
	var errs []error
	l, err := OpenWith(path, Options{Signer: s, CheckpointEvery: time.Hour, Rotation: Rotation{MaxBytes: 300},
		OnCheckpointError: func(err error) { mu.Lock(); errs = append(errs, err); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	// From here the checkpoint cannot be replaced: the rename onto a
	// non-empty directory fails. Appends and rotations go on.
	os.Remove(CheckpointPath(path))
	if err := os.MkdirAll(filepath.Join(CheckpointPath(path), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		if err := l.Append("tool_call", callRec(i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if segs, _ := Segments(path); len(segs) == 0 {
		t.Fatal("no rotation")
	}
	mu.Lock()
	n := len(errs)
	mu.Unlock()
	if n == 0 {
		t.Fatal("failed checkpoints after rotations were not reported")
	}
	if _, _, err := l.Checkpoint(); err == nil {
		t.Fatal("Checkpoint succeeded")
	}
	if !l.Healthy() {
		t.Fatal("a checkpoint that could not be written broke the log")
	}
	if err := l.Close(); err == nil {
		t.Fatal("Close did not report the final checkpoint")
	}
}

func TestCovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := OpenWith(path, Options{Rotation: Rotation{MaxBytes: 400}})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 12 {
		if err := l.Append("tool_call", callRec(i)); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	cr, recs := chainRecords(t, path)
	if len(cr.Segments) < 3 {
		t.Fatalf("%d segments", len(cr.Segments))
	}
	// The hash of every record, from the files.
	var hashes []string
	for _, s := range cr.Segments {
		hashes = append(hashes, lineHashes(t, s.Path)...)
	}
	if len(hashes) != len(recs) || uint64(len(hashes)) != cr.Records {
		t.Fatalf("%d hashes, %d records", len(hashes), cr.Records)
	}
	for n := uint64(0); n <= cr.Records; n++ {
		head := Genesis
		if n > 0 {
			head = hashes[n-1]
		}
		c := Checkpoint{Origin: "o", Size: n, Head: head, Time: fixedNow()}
		if err := cr.Covers(c); err != nil {
			t.Fatalf("record %d: %v", n, err)
		}
		if n > 0 {
			c.Head = hashes[0]
			if n == 1 {
				c.Head = hashes[1]
			}
			if err := cr.Covers(c); err == nil || !strings.Contains(err.Error(), "rewritten") {
				t.Fatalf("record %d with another head: %v", n, err)
			}
		}
	}
	err = cr.Covers(Checkpoint{Origin: "o", Size: cr.Records + 1, Head: hashes[0], Time: fixedNow()})
	if err == nil || !strings.Contains(err.Error(), "removed from its end") {
		t.Fatalf("longer checkpoint: %v", err)
	}
	if err := cr.Covers(Checkpoint{Origin: "o", Size: 0, Head: hashes[0]}); err == nil {
		t.Fatal("empty checkpoint with a head")
	}
}
