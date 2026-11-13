//go:build unix

package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// openNote opens a checkpoint note with the test key's public half.
func openNote(t *testing.T, note string) Checkpoint {
	t.Helper()
	c, err := OpenCheckpoint([]byte(note), testSigner(t).Verifier())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// allLines is every record line of the log at path, across its segments.
func allLines(t *testing.T, path string) []string {
	t.Helper()
	segs, err := Segments(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range append(segs, path) {
		for _, l := range fileLines(t, p) {
			out = append(out, string(l))
		}
	}
	return out
}

// Every record of a log rotated into several segments has an inclusion
// proof against the newest checkpoint, which it carries, and the proof
// checks with only the public key after a trip through JSON.
func TestInclusionProofAcrossSegments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSigned(t, path, Rotation{MaxBytes: 1200})
	defer l.Close()
	appendN(t, l, 0, 40)
	if segs, _ := Segments(path); len(segs) < 3 {
		t.Fatalf("%d segments; the test wants several", len(segs))
	}
	lines := allLines(t, path)
	_, cp, err := l.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if cp.Size != uint64(len(lines)) {
		t.Fatalf("checkpoint of %d records, %d on disk", cp.Size, len(lines))
	}
	for r := uint64(1); r <= cp.Size; r++ {
		p, err := l.InclusionProof(r, 0)
		if err != nil {
			t.Fatalf("record %d: %v", r, err)
		}
		if p.Entry != lines[r-1] || p.Record != r || p.Size != cp.Size || p.Checkpoint == "" {
			t.Fatalf("record %d: proof %+v", r, p)
		}
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var back Proof
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if err := back.Check(openNote(t, back.Checkpoint), nil); err != nil {
			t.Fatalf("record %d: %v", r, err)
		}
	}
}

// A consistency proof from an earlier checkpoint, kept by an auditor, to
// the newest checks, and so do inclusion proofs against the earlier one.
func TestConsistencyProof(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSigned(t, path, Rotation{MaxBytes: 1200})
	defer l.Close()
	appendN(t, l, 0, 9)
	oldNote, _, err := l.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	old := openNote(t, string(oldNote))
	appendN(t, l, 9, 30)
	if err := l.Rotate(); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 39, 3)

	p, err := l.ConsistencyProof(old.Size, 0)
	if err != nil {
		t.Fatal(err)
	}
	cp := openNote(t, p.Checkpoint)
	if p.Kind != ProofConsistency || p.From != old.Size || p.FromRoot != old.Root || p.Size != cp.Size {
		t.Fatalf("proof %+v against %+v", p, old)
	}
	if err := p.Check(cp, &old); err != nil {
		t.Fatal(err)
	}
	// Every earlier size up to the newest.
	for from := uint64(1); from <= cp.Size; from++ {
		p, err := l.ConsistencyProof(from, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Check(cp, nil); err != nil {
			t.Fatalf("from %d: %v", from, err)
		}
	}
	// A proof for the earlier size carries no checkpoint; it checks
	// against the one the auditor kept.
	ip, err := l.InclusionProof(4, old.Size)
	if err != nil {
		t.Fatal(err)
	}
	if ip.Checkpoint != "" || ip.Size != old.Size {
		t.Fatalf("proof against %d records: %+v", old.Size, ip)
	}
	if err := ip.Check(old, nil); err != nil {
		t.Fatal(err)
	}
	if err := ip.Check(cp, nil); err == nil {
		t.Fatal("a proof for the earlier size checked against the newest checkpoint")
	}
	cp2, err := l.ConsistencyProof(3, old.Size)
	if err != nil {
		t.Fatal(err)
	}
	if err := cp2.Check(old, nil); err != nil {
		t.Fatal(err)
	}
	// The earlier checkpoint must be the one the proof starts from.
	other := old
	other.Root = cp.Root
	if err := p.Check(cp, &other); err == nil {
		t.Fatal("checked against an earlier checkpoint with another tree head")
	}
	other = cp
	if err := p.Check(cp, &other); err == nil {
		t.Fatal("checked against an earlier checkpoint of another size")
	}
}

func TestProofChecksFail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSigned(t, path, Rotation{})
	defer l.Close()
	appendN(t, l, 0, 12)
	good, err := l.InclusionProof(7, 0)
	if err != nil {
		t.Fatal(err)
	}
	cp := openNote(t, good.Checkpoint)
	cons, err := l.ConsistencyProof(5, 0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := l.InclusionProof(8, 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(p *Proof){
		"entry":          func(p *Proof) { p.Entry = strings.Replace(p.Entry, `"allow"`, `"deny"`, 1); p.LeafHash = "" },
		"entry and hash": func(p *Proof) { p.Entry = strings.Replace(p.Entry, `"allow"`, `"deny"`, 1) },
		"another entry":  func(p *Proof) { p.Entry, p.LeafHash = other.Entry, other.LeafHash },
		"record number":  func(p *Proof) { p.Record = 8 },
		"record zero":    func(p *Proof) { p.Record = 0 },
		"record past":    func(p *Proof) { p.Record = 13 },
		"not a record":   func(p *Proof) { p.Entry, p.LeafHash = "not json", "" },
		"proof hash":     func(p *Proof) { p.Hashes[0] = other.Hashes[0] },
		"bad hex":        func(p *Proof) { p.Hashes[0] = strings.ToUpper(p.Hashes[0]) },
		"short":          func(p *Proof) { p.Hashes = p.Hashes[1:] },
		"root":           func(p *Proof) { p.Root = cons.FromRoot },
		"size":           func(p *Proof) { p.Size = 11 },
		"kind":           func(p *Proof) { p.Kind = "membership" },
		"consistency":    func(p *Proof) { p.Kind = ProofConsistency },
	} {
		p := good
		p.Hashes = append([]string(nil), good.Hashes...)
		change(&p)
		if err := p.Check(cp, nil); err == nil {
			t.Errorf("%s changed: the proof checks", name)
		}
	}
	for name, change := range map[string]func(p *Proof){
		"from root": func(p *Proof) { p.FromRoot = p.Root },
		"from":      func(p *Proof) { p.From = 6 },
		"from zero": func(p *Proof) { p.From = 0 },
		"from past": func(p *Proof) { p.From = 13 },
		"hash":      func(p *Proof) { p.Hashes[0] = good.Hashes[0] },
		"from hex":  func(p *Proof) { p.FromRoot = "00" },
	} {
		p := cons
		p.Hashes = append([]string(nil), cons.Hashes...)
		change(&p)
		if err := p.Check(cp, nil); err == nil {
			t.Errorf("%s changed: the consistency proof checks", name)
		}
	}
	if err := good.Check(cp, nil); err != nil {
		t.Fatal(err)
	}
}

func TestProofRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSigned(t, path, Rotation{})
	if _, err := l.InclusionProof(1, 0); !errors.Is(err, ErrProofRange) {
		t.Errorf("a proof in an empty log: %v", err)
	}
	appendN(t, l, 0, 5)
	for name, f := range map[string]func() (Proof, error){
		"record 0":         func() (Proof, error) { return l.InclusionProof(0, 0) },
		"record 6":         func() (Proof, error) { return l.InclusionProof(6, 0) },
		"past checkpoint":  func() (Proof, error) { return l.InclusionProof(1, 6) },
		"record past size": func() (Proof, error) { return l.InclusionProof(4, 3) },
		"from 0":           func() (Proof, error) { return l.ConsistencyProof(0, 0) },
		"from 6":           func() (Proof, error) { return l.ConsistencyProof(6, 0) },
		"from past size":   func() (Proof, error) { return l.ConsistencyProof(4, 3) },
	} {
		if _, err := f(); !errors.Is(err, ErrProofRange) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ProveInclusion(path, 1, 9); !errors.Is(err, ErrProofRange) {
		t.Errorf("a proof of more records than the file holds: %v", err)
	}
	l.Close()

	unsigned, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"), fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	defer unsigned.Close()
	if err := unsigned.Append("tool_call", callRec(0)); err != nil {
		t.Fatal(err)
	}
	if _, err := unsigned.InclusionProof(1, 0); !errors.Is(err, ErrNoSigner) {
		t.Errorf("a proof without a signer: %v", err)
	}
	// The file itself is still provable offline, without a checkpoint.
	p, err := ProveInclusion(unsigned.path, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Checkpoint != "" || len(p.Hashes) != 0 || p.Root != p.LeafHash {
		t.Errorf("proof of the only record: %+v", p)
	}
}

// Records changed on disk under a running log are not proved against its
// checkpoint, and a missing or replaced segment stops a proof.
func TestProofOfChangedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSigned(t, path, Rotation{MaxBytes: 1200})
	defer l.Close()
	appendN(t, l, 0, 30)
	for i := 30; len(fileLines(t, path)) == 0; i++ {
		appendN(t, l, i, 1) // records in the active file too
	}
	total := uint64(len(allLines(t, path)))
	segs, _ := Segments(path)
	if len(segs) < 2 {
		t.Fatalf("%d segments", len(segs))
	}
	b, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segs[0], []byte(strings.Replace(string(b), `"allow"`, `"deny!"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.InclusionProof(1, 0); err == nil || !strings.Contains(err.Error(), "tree head") {
		t.Errorf("a proof over a rewritten segment: %v", err)
	}
	if err := os.WriteFile(segs[0], b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.InclusionProof(1, 0); err != nil {
		t.Fatal(err)
	}

	// A middle segment removed.
	mid, err := os.ReadFile(segs[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(segs[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := ProveInclusion(path, 1, 20); err == nil || !strings.Contains(err.Error(), "named for record") {
		t.Errorf("a proof with a segment removed: %v", err)
	}
	if err := os.WriteFile(segs[1], mid, 0o600); err != nil {
		t.Fatal(err)
	}
	// The active file swapped for an older segment, as if the log had
	// rotated under the reader every time it tried.
	act, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ProveInclusion(path, 1, total); !errors.Is(err, errChanged) {
		t.Errorf("a proof with the active file replaced: %v", err)
	}
	if err := os.WriteFile(path, act, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ProveInclusion(path, total, total); err != nil {
		t.Fatal(err)
	}
}

// Proofs taken while another goroutine appends and the log rotates under
// it all check against the checkpoints they carry.
func TestProofsWhileRotating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSigned(t, path, Rotation{MaxBytes: 1200})
	defer l.Close()
	appendN(t, l, 0, 3)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 3; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := l.Append("tool_call", callRec(i)); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	n := 0
	for ; time.Now().Before(deadline) && n < 200; n++ {
		p, err := l.InclusionProof(uint64(1+n%3), 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Check(openNote(t, p.Checkpoint), nil); err != nil {
			t.Fatal(err)
		}
		c, err := l.ConsistencyProof(2, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Check(openNote(t, c.Checkpoint), nil); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if segs, _ := Segments(path); len(segs) < 2 {
		t.Fatalf("the log did not rotate during %d proofs", n)
	}
}
