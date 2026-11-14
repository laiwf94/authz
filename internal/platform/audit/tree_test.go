//go:build unix

package audit

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/merkle"
)

// refRoot is the RFC 6962 tree head of every line of every segment of the
// log at path, by the recursion of the RFC, and the number of records.
func refRoot(t *testing.T, path string) (string, uint64) {
	t.Helper()
	segs, base, err := liveSegments(path)
	if err != nil {
		t.Fatal(err)
	}
	var leaves []merkle.Hash
	for _, p := range append(segs, path) {
		for _, line := range fileLines(t, p) {
			leaves = append(leaves, merkle.LeafHash(line))
		}
	}
	if base != nil {
		// Retention removed the oldest records: their range is the
		// base's.
		r := base.r.Clone()
		for _, l := range leaves {
			r.Append(l)
		}
		return hexHash(r.Root()), r.Size()
	}
	return hexHash(merkle.RootOf(leaves)), uint64(len(leaves))
}

func openSigned(t *testing.T, path string, rot Rotation) *Log {
	t.Helper()
	l, err := OpenWith(path, Options{Now: fixedNow, Signer: testSigner(t), CheckpointEvery: time.Hour, Rotation: rot})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func appendN(t *testing.T, l *Log, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		if err := l.Append("tool_call", callRec(i)); err != nil {
			t.Fatal(err)
		}
	}
}

// checkRoot requires the log's newest checkpoint to carry the tree head of
// every record on disk, and VerifyChain to compute the same.
func checkRoot(t *testing.T, l *Log, path string) Checkpoint {
	t.Helper()
	_, c, err := l.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	want, n := refRoot(t, path)
	if c.Size != n || c.Root != want {
		t.Fatalf("checkpoint of %d records has tree head %s; the %d records on disk have %s", c.Size, c.Root, n, want)
	}
	cr, err := VerifyChain(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Root != want {
		t.Fatalf("VerifyChain tree head %s, want %s", cr.Root, want)
	}
	if err := cr.Covers(c); err != nil {
		t.Fatal(err)
	}
	// So does a result made by hand from the segments, without the tree
	// head VerifyChain computed.
	byHand := ChainResult{Segments: cr.Segments, Records: cr.Records, Head: cr.Head}
	if err := byHand.Covers(c); err != nil {
		t.Fatalf("Covers without Root: %v", err)
	}
	return c
}

func TestTreeInEveryCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSigned(t, path, Rotation{MaxBytes: 1500})
	if c := readCheckpoint(t, path, testSigner(t).Verifier()); c.Size != 0 || c.Root != EmptyRoot {
		t.Fatalf("open checkpoint %+v", c)
	}
	for i := range 40 {
		appendN(t, l, i, 1)
		checkRoot(t, l, path)
	}
	if err := l.Rotate(); err != nil {
		t.Fatal(err)
	}
	// The rotation's checkpoint covers the segment start record.
	c := readCheckpoint(t, path, testSigner(t).Verifier())
	if want, n := refRoot(t, path); c.Size != n || c.Root != want {
		t.Fatalf("rotation checkpoint %+v, want %d records with %s", c, n, want)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	segs, _ := Segments(path)
	if len(segs) < 4 {
		t.Fatalf("%d segments", len(segs))
	}
	// The saved tree names the state of the last checkpoint.
	b, err := os.ReadFile(TreePath(path))
	if err != nil {
		t.Fatal(err)
	}
	st, err := parseTree(b)
	if err != nil {
		t.Fatal(err)
	}
	final := readCheckpoint(t, path, testSigner(t).Verifier())
	if st.size != final.Size || st.head != final.Head || hexHash(st.r.Root()) != final.Root {
		t.Fatalf("saved tree %d %s, checkpoint %+v", st.size, st.head, final)
	}
	if !strings.HasPrefix(string(b), fmt.Sprintf("authz audit tree\n%d\n%s\n", final.Size, final.Head)) || final.Size < 44 {
		t.Fatalf("saved tree:\n%s", b)
	}
	if _, err := os.Stat(TreePath(path) + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file left: %v", err)
	}
}

// moveAway moves the older segments of the log at path into another
// directory, and returns a function that puts them back.
func moveAway(t *testing.T, path string) func() {
	t.Helper()
	segs, err := Segments(path)
	if err != nil || len(segs) == 0 {
		t.Fatalf("segments %v, %v", segs, err)
	}
	dir := t.TempDir()
	for _, s := range segs {
		if err := os.Rename(s, filepath.Join(dir, filepath.Base(s))); err != nil {
			t.Fatal(err)
		}
	}
	return func() {
		for _, s := range segs {
			if err := os.Rename(filepath.Join(dir, filepath.Base(s)), s); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// A reopened log takes up its saved tree and reads only the active
// segment: with the older segments moved away it still signs the right
// tree head.
func TestTreeResumesWithoutOlderSegments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSigned(t, path, Rotation{MaxBytes: 1200})
	appendN(t, l, 0, 30)
	l.Close()

	// Saved at the end of the active segment.
	back := moveAway(t, path)
	l = openSigned(t, path, Rotation{MaxBytes: 1200})
	back()
	checkRoot(t, l, path)

	// Saved in the middle of the active segment: records after the last
	// checkpoint, written by a writer without a key, are added on open.
	l.Close()
	l2, err := OpenWith(path, Options{Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l2, 30, 2)
	l2.Close()
	back = moveAway(t, path)
	l = openSigned(t, path, Rotation{MaxBytes: 1200})
	back()
	checkRoot(t, l, path)
	l.Close()

	// Saved just before the active segment began: a writer without a key
	// rotated, so the segment start record is the active segment's first.
	l2, err = OpenWith(path, Options{Now: fixedNow, Rotation: Rotation{MaxBytes: 1200}})
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Rotate(); err != nil {
		t.Fatal(err)
	}
	appendN(t, l2, 32, 1)
	l2.Close()
	b, _ := os.ReadFile(TreePath(path))
	st, _ := parseTree(b)
	cr, _ := VerifyChain(path, nil)
	if active := cr.Segments[len(cr.Segments)-1]; st.size+1 != active.First {
		t.Fatalf("saved tree of %d records, active segment starts at %d", st.size, active.First)
	}
	back = moveAway(t, path)
	l = openSigned(t, path, Rotation{MaxBytes: 1200})
	back()
	checkRoot(t, l, path)
	appendN(t, l, 33, 5)
	checkRoot(t, l, path)
	l.Close()
}

// A saved tree that is missing, damaged, stale or does not match the
// records it names is rebuilt from every segment.
func TestTreeRebuilt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSigned(t, path, Rotation{MaxBytes: 1200})
	appendN(t, l, 0, 25)
	l.Close()
	good, err := os.ReadFile(TreePath(path))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := parseTree(good)
	enc, _ := st.r.MarshalBinary()
	enc[len(enc)-1] ^= 1
	otherHashes := strings.Replace(string(good), base64.StdEncoding.EncodeToString(func() []byte { e, _ := st.r.MarshalBinary(); return e }()),
		base64.StdEncoding.EncodeToString(enc), 1)
	hashes := lineHashes(t, path)
	var longer merkle.Range
	for range st.size + 3 {
		longer.AppendData([]byte("x"))
	}
	longerText, _ := treeState{size: st.size + 3, head: hashes[0], r: &longer}.encode()
	for name, saved := range map[string]string{
		"missing":       "",
		"damaged":       fmt.Sprintf("authz audit tree\n%d\n", st.size),
		"another head":  strings.Replace(string(good), st.head, hashes[len(hashes)-2], 1),
		"from before":   "authz audit tree\n0\n" + Genesis + "\nAAAAAAAAAAA=\n",
		"longer":        string(longerText),
		"other hashes":  otherHashes, // right count and head: caught by the checkpoint
		"not a tree":    "hello\n",
		"count not hex": "authz audit tree\n25\nxyz\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			if saved == "" {
				os.Remove(TreePath(path))
			} else if err := os.WriteFile(TreePath(path), []byte(saved), 0o600); err != nil {
				t.Fatal(err)
			}
			l := openSigned(t, path, Rotation{MaxBytes: 1200})
			defer l.Close()
			checkRoot(t, l, path)
			b, _ := os.ReadFile(TreePath(path))
			if string(b) != string(good) {
				t.Fatalf("saved tree not restored:\n%s", b)
			}
		})
	}

	// Without the saved tree and with a segment gone, there is nothing to
	// build it from: Open names the gap.
	os.Remove(TreePath(path))
	segs, _ := Segments(path)
	os.Remove(segs[1])
	_, err = OpenWith(path, Options{Now: fixedNow, Signer: testSigner(t)})
	if err == nil || !strings.Contains(err.Error(), "building the Merkle tree") || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("open with a segment gone: %v", err)
	}
	// Without a key the tree is not kept, and the log opens as before.
	l2, err := OpenWith(path, Options{Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	l2.Close()
}

// A checkpoint by the log's key whose tree head is not the root of the
// records it counts is refused on open.
func TestOpenRefusesCheckpointWithAnotherTree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSigned(t, path, Rotation{})
	appendN(t, l, 0, 5)
	l.Close()
	s := testSigner(t)
	c := readCheckpoint(t, path, s.Verifier())
	c.Root = strings.Repeat("ee", 32)
	msg, err := c.Sign(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(CheckpointPath(path), msg, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = OpenWith(path, Options{Now: fixedNow, Signer: s})
	if err == nil || !strings.Contains(err.Error(), "tree head that is not the root of its 5 records") {
		t.Fatalf("open: %v", err)
	}
	cr, _ := VerifyChain(path, nil)
	if err := cr.Covers(c); err == nil || !strings.Contains(err.Error(), "not the root of records 1 to 5") {
		t.Fatalf("Covers: %v", err)
	}
}

// Writers sharing one file each keep the tree of every record, their own
// and the others'.
func TestTreeSharedWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	rot := Rotation{MaxBytes: 1500}
	a := openSigned(t, path, rot)
	b := openSigned(t, path, rot)
	defer a.Close()
	defer b.Close()
	for i := range 30 {
		w := a
		if i%3 == 0 {
			w = b
		}
		appendN(t, w, i, 1)
		if i%7 == 0 {
			checkRoot(t, a, path)
			checkRoot(t, b, path)
		}
	}
	ca, cb := checkRoot(t, a, path), checkRoot(t, b, path)
	if ca.Root != cb.Root {
		t.Fatalf("writers disagree: %s, %s", ca.Root, cb.Root)
	}
}

func TestParseTree(t *testing.T) {
	var r merkle.Range
	r.AppendData([]byte("a"))
	enc, _ := r.MarshalBinary()
	b64 := base64.StdEncoding.EncodeToString(enc)
	head := strings.Repeat("ab", 32)
	ok := "authz audit tree\n1\n" + head + "\n" + b64 + "\n"
	if st, err := parseTree([]byte(ok)); err != nil || st.size != 1 || st.head != head || st.r.Root() != r.Root() {
		t.Fatalf("parseTree = %+v, %v", st, err)
	}
	for name, s := range map[string]string{
		"no final newline": strings.TrimSuffix(ok, "\n"),
		"extra line":       ok + "x\n",
		"other magic":      strings.Replace(ok, "tree", "tre", 1),
		"leading zero":     strings.Replace(ok, "\n1\n", "\n01\n", 1),
		"upper-case head":  strings.Replace(ok, head, strings.ToUpper(head), 1),
		"short head":       strings.Replace(ok, head, head[:62], 1),
		"zero head":        strings.Replace(ok, head, Genesis, 1),
		"head for none":    "authz audit tree\n0\n" + head + "\nAAAAAAAAAAA=\n",
		"not base64":       strings.Replace(ok, b64, "!!", 1),
		"short range":      strings.Replace(ok, b64, base64.StdEncoding.EncodeToString(enc[:20]), 1),
		"other count":      strings.Replace(ok, "\n1\n", "\n2\n", 1),
		"range of 3":       strings.Replace(strings.Replace(ok, "\n1\n", "\n3\n", 1), b64, base64.StdEncoding.EncodeToString(append([]byte{0, 0, 0, 0, 0, 0, 0, 2}, make([]byte, 32)...)), 1),
	} {
		if _, err := parseTree([]byte(s)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func BenchmarkAppendSigned(b *testing.B) {
	path := filepath.Join(b.TempDir(), "audit.jsonl")
	s, err := ParseSigner(peterSigner)
	if err != nil {
		b.Fatal(err)
	}
	l, err := OpenWith(path, Options{Now: fixedNow, Signer: s, CheckpointEvery: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	data := map[string]any{"agent": "alice-bot", "tool": "fs.read_file", "decision": "allow", "rule_id": "fs-read"}
	for b.Loop() {
		if err := l.Append("tool_call", data); err != nil {
			b.Fatal(err)
		}
	}
}
