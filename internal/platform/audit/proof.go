package audit

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/laiwf94/authz/internal/platform/merkle"
)

// Proofs
//
// A checkpoint's tree head (tree.go) lets an auditor holding only the
// public key check two things without the log: that a record is in it, by
// an inclusion proof, and that a later checkpoint covers everything an
// earlier one did, unchanged, by a consistency proof. Both are RFC 6962
// proofs (internal/platform/merkle) over the records as leaves: record N is
// leaf N-1, its line without the newline.
//
// A proof is computed in one pass over the segments up to the tree size it
// is for, keeping only compact ranges, so it costs a read of the log and
// O(log n) memory; nothing beyond the saved compact range is stored. A
// Proof is JSON, as GET /admin/audit/proof serves it and "authz audit
// prove" prints and checks it:
//
//	{"kind": "inclusion", "tree_size": 8, "root": "<hex tree head>",
//	 "record": 6, "entry": "<the record's line>", "leaf_hash": "<hex>",
//	 "proof": ["<hex>", ...], "checkpoint": "<signed note>"}
//
//	{"kind": "consistency", "tree_size": 8, "root": "<hex>",
//	 "from_size": 6, "from_root": "<hex>", "proof": [...], "checkpoint": "..."}
//
// checkpoint is the signed checkpoint of tree_size records when the log has
// one: the newest, for a proof against the latest state. A proof for an
// older size is checked against a checkpoint of that size the auditor kept.

// The kinds of Proof.
const (
	ProofInclusion   = "inclusion"
	ProofConsistency = "consistency"
)

// Proof is an RFC 6962 proof over a log's records.
type Proof struct {
	Kind     string   `json:"kind"`
	Size     uint64   `json:"tree_size"`
	Root     string   `json:"root"`
	Record   uint64   `json:"record,omitempty"`
	Entry    string   `json:"entry,omitempty"`
	LeafHash string   `json:"leaf_hash,omitempty"`
	From     uint64   `json:"from_size,omitempty"`
	FromRoot string   `json:"from_root,omitempty"`
	Hashes   []string `json:"proof"`
	// Checkpoint is the signed checkpoint of Size records, if the log has
	// one.
	Checkpoint string `json:"checkpoint,omitempty"`
}

// ErrProofRange means a proof was asked for a record or a size the log, or
// its newest checkpoint, does not cover.
var ErrProofRange = errors.New("audit: no such record or tree size")

// ProveInclusion proves that record is in the tree of the first size
// records of the log at path, reading its segments.
func ProveInclusion(path string, record, size uint64) (Proof, error) {
	if record == 0 || record > size {
		return Proof{}, fmt.Errorf("%w: record %d is not one of records 1 to %d", ErrProofRange, record, size)
	}
	var entry []byte
	p, err := proveFrom(path, func() (*merkle.Prover, error) { return merkle.NewInclusionProver(record-1, size) },
		func(seq uint64, line []byte) {
			if seq == record {
				entry = line
			}
		})
	if err != nil {
		return Proof{}, err
	}
	pr, err := proofOf(ProofInclusion, p)
	if err != nil {
		return Proof{}, err
	}
	pr.Record, pr.Entry, pr.LeafHash = record, string(entry), hexHash(p.Leaf())
	return pr, nil
}

// ProveConsistency proves that the tree of the first size records of the
// log at path extends the tree of the first from records, from 1 to size.
func ProveConsistency(path string, from, size uint64) (Proof, error) {
	if from == 0 || from > size {
		return Proof{}, fmt.Errorf("%w: a proof from %d records to %d must start from 1 to %d records", ErrProofRange, from, size, size)
	}
	p, err := proveFrom(path, func() (*merkle.Prover, error) { return merkle.NewConsistencyProver(from, size) }, nil)
	if err != nil {
		return Proof{}, err
	}
	pr, err := proofOf(ProofConsistency, p)
	if err != nil {
		return Proof{}, err
	}
	pr.From, pr.FromRoot = from, hexHash(p.PrefixRoot())
	return pr, nil
}

func proofOf(kind string, p *merkle.Prover) (Proof, error) {
	hs, err := p.Proof()
	if err != nil {
		return Proof{}, err
	}
	out := Proof{Kind: kind, Size: p.Size(), Root: hexHash(p.Root()), Hashes: make([]string, len(hs))}
	for i, h := range hs {
		out.Hashes[i] = hexHash(h)
	}
	return out, nil
}

// errChanged means a segment was rotated or replaced while it was read.
var errChanged = errors.New("the log changed while it was read")

// proveFrom feeds the first records of the log at path to a prover mk
// makes, as many as it needs, calling each, if set, with every one. A
// rotation while it reads starts again with a new prover.
func proveFrom(path string, mk func() (*merkle.Prover, error), each func(uint64, []byte)) (*merkle.Prover, error) {
	for try := 0; ; try++ {
		p, err := mk()
		if err != nil {
			return nil, err
		}
		err = readRecords(path, p.Size(), p.Skip, func(seq uint64, line []byte) {
			p.AddData(line)
			if each != nil {
				each(seq, line)
			}
		})
		if errors.Is(err, errChanged) && try < 3 {
			continue
		}
		if err != nil {
			return nil, err
		}
		return p, nil
	}
}

// readRecords calls each with records 1 to size of the log at path, in
// order, from the segments and then the active file. When retention removed
// the oldest records, skip is given their compact range and the records
// start after them. Each file's first record must be the one after the
// last file's, so a rotation between listing the segments and opening the
// active file is seen (errChanged). The chain is not checked: a proof that
// was computed over records changed on disk does not lead to the signed
// tree head.
func readRecords(path string, size uint64, skip func(*merkle.Range) error, each func(uint64, []byte)) error {
	segs, base, err := liveSegments(path)
	if err != nil {
		return err
	}
	var n uint64
	if base != nil {
		if err := skip(base.r); err != nil {
			if errors.Is(err, merkle.ErrPruned) {
				return fmt.Errorf("%w: records 1 to %d were removed by retention", ErrProofRange, base.size)
			}
			return fmt.Errorf("%w: %v", ErrProofRange, err)
		}
		n = base.size
	}
	for i, p := range append(segs, path) {
		if n == size {
			return nil
		}
		if i < len(segs) {
			first, _ := segmentFirst(filepath.Base(path), filepath.Base(p))
			if first != n+1 {
				return fmt.Errorf("audit: %s: segment is named for record %d, but record %d comes next; run authz audit verify", p, first, n+1)
			}
		}
		if err := readFile(p, &n, size, each); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("audit: %s: %w", p, errChanged)
			}
			return err
		}
	}
	if n < size {
		return fmt.Errorf("%w: the log holds %d records, not %d", ErrProofRange, n, size)
	}
	return nil
}

// readFile reads the records of one file into each until *n reaches size.
func readFile(p string, n *uint64, size uint64, each func(uint64, []byte)) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 64<<10)
	for start := *n; *n < size; {
		line, err := readLine(br)
		if err == io.EOF || err == errTorn {
			return nil // the end of this file, or a write in progress
		}
		if err != nil {
			return fmt.Errorf("audit: %s: %w", p, err)
		}
		if *n == start {
			var r struct {
				Seq uint64 `json:"seq"`
			}
			if err := json.Unmarshal(line, &r); err != nil {
				return fmt.Errorf("audit: %s: line 1: %v", p, err)
			}
			if r.Seq != start+1 {
				// The active file was rotated after the segments were
				// listed, or the log was rewritten.
				return fmt.Errorf("audit: %s starts at record %d, not %d: %w", p, r.Seq, start+1, errChanged)
			}
		}
		*n++
		each(*n, line)
	}
	return nil
}

// InclusionProof proves that record is in the log, against the newest
// checkpoint (signed now if records were added since the last one), or,
// when size is not zero, against the tree of the first size records, at
// most the checkpoint's. A proof of the checkpoint's size carries it.
func (l *Log) InclusionProof(record, size uint64) (Proof, error) {
	return l.prove(size, func(size uint64) (Proof, error) { return ProveInclusion(l.path, record, size) })
}

// ConsistencyProof proves that the log's newest checkpoint, or the tree of
// its first size records when size is not zero, extends the tree of its
// first from records.
func (l *Log) ConsistencyProof(from, size uint64) (Proof, error) {
	return l.prove(size, func(size uint64) (Proof, error) { return ProveConsistency(l.path, from, size) })
}

func (l *Log) prove(size uint64, prove func(uint64) (Proof, error)) (Proof, error) {
	note, cp, err := l.Checkpoint()
	if err != nil {
		return Proof{}, err
	}
	if size == 0 {
		size = cp.Size
	}
	if size > cp.Size {
		return Proof{}, fmt.Errorf("%w: the newest checkpoint covers %d records, not %d", ErrProofRange, cp.Size, size)
	}
	if size == 0 {
		return Proof{}, fmt.Errorf("%w: the log has no records", ErrProofRange)
	}
	pr, err := prove(size)
	if err != nil {
		return Proof{}, err
	}
	if size == cp.Size {
		if pr.Root != cp.Root {
			return Proof{}, fmt.Errorf("audit: the records on disk do not have the tree head of the checkpoint signed at %s; run authz audit verify", cp.Time.Format(time.RFC3339))
		}
		pr.Checkpoint = string(note)
	}
	return pr, nil
}

// Check checks the proof against cp, a checkpoint the caller opened with
// the public key (OpenCheckpoint), of the proof's tree size: that the proof
// leads to cp's tree head from the record it carries (inclusion) or from
// the tree head of its earlier size (consistency). For a consistency proof,
// old, if set, is the earlier checkpoint the auditor kept, which must be of
// the proof's from size and tree head. An inclusion proof's entry must be
// record Record of the log; its contents are the caller's to read.
func (p Proof) Check(cp Checkpoint, old *Checkpoint) error {
	if cp.Size != p.Size {
		return fmt.Errorf("the proof is for %d records, but the checkpoint covers %d", p.Size, cp.Size)
	}
	if cp.Root != p.Root {
		return errors.New("the proof's tree head is not the checkpoint's")
	}
	root, err := parseHash(p.Root, "tree head")
	if err != nil {
		return err
	}
	hashes := make([]merkle.Hash, len(p.Hashes))
	for i, s := range p.Hashes {
		if hashes[i], err = parseHash(s, fmt.Sprintf("proof hash %d", i+1)); err != nil {
			return err
		}
	}
	switch p.Kind {
	case ProofInclusion:
		if p.Record == 0 || p.Record > p.Size {
			return fmt.Errorf("record %d is not one of records 1 to %d", p.Record, p.Size)
		}
		leaf := merkle.LeafHash([]byte(p.Entry))
		if p.LeafHash != "" && p.LeafHash != hexHash(leaf) {
			return errors.New("the leaf hash is not the hash of the entry")
		}
		var r struct {
			Seq uint64 `json:"seq"`
		}
		if err := json.Unmarshal([]byte(p.Entry), &r); err != nil {
			return fmt.Errorf("the entry is not an audit record: %v", err)
		}
		if r.Seq != p.Record {
			return fmt.Errorf("the entry is record %d, not %d", r.Seq, p.Record)
		}
		if err := merkle.VerifyInclusion(p.Record-1, p.Size, leaf, hashes, root); err != nil {
			return fmt.Errorf("record %d is not in the tree the checkpoint signed: %v", p.Record, err)
		}
	case ProofConsistency:
		if p.From == 0 || p.From > p.Size {
			return fmt.Errorf("a proof from %d records to %d must start from 1 to %d records", p.From, p.Size, p.Size)
		}
		fromRoot, err := parseHash(p.FromRoot, "earlier tree head")
		if err != nil {
			return err
		}
		if old != nil {
			if old.Size != p.From {
				return fmt.Errorf("the proof starts from %d records, but the earlier checkpoint covers %d", p.From, old.Size)
			}
			if old.Root != p.FromRoot {
				return errors.New("the proof's earlier tree head is not the earlier checkpoint's")
			}
		}
		if err := merkle.VerifyConsistency(p.From, p.Size, hashes, fromRoot, root); err != nil {
			return fmt.Errorf("the tree of %d records does not extend the tree of %d: %v", p.Size, p.From, err)
		}
	default:
		return fmt.Errorf("unknown proof kind %q", p.Kind)
	}
	return nil
}

func parseHash(s, what string) (merkle.Hash, error) {
	var h merkle.Hash
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != merkle.Size || hex.EncodeToString(b) != s {
		return h, fmt.Errorf("the %s is not a lowercase hex SHA-256 hash", what)
	}
	copy(h[:], b)
	return h, nil
}
