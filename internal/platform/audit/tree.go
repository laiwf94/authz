package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/laiwf94/authz/internal/platform/merkle"
)

// The Merkle tree
//
// The records of a log are also the leaves of a Merkle tree in the manner of
// RFC 6962 (internal/platform/merkle): leaf i is record i+1's line, the
// exact bytes the chain hashes, without its newline, across every segment.
// The chain shows that nothing before the head changed; the tree head adds
// what a chain cannot give, short proofs that one record is in the log and
// that a later log extends an earlier one, without reading the records in
// between. Every checkpoint carries it.
//
// A log with a signer keeps the tree as a compact range: one hash for each
// set bit of the record count, at most 64. Each append adds its leaf. The
// range is saved beside the log as FILE.tree (see TreePath) before every
// checkpoint is signed, with the record count and the chain head it was
// computed for:
//
//	authz audit tree
//	<records>
//	<hex SHA-256 of the last record; Genesis for none>
//	<base64 of the range: records as 8 bytes big-endian, then the hashes>
//
// Open takes up the saved range where it ends, in the active segment or at
// its start, and extends it with the active segment's later records while it
// verifies them, so opening does not read the older segments. A saved range
// that is missing, damaged or does not match the records it names, or one
// from before the active segment began, is rebuilt from every segment.

// TreePath is where the log at path keeps its saved Merkle tree.
func TreePath(path string) string { return path + ".tree" }

const treeMagic = "authz audit tree"

// treeState is a saved compact range: the tree of the first size records,
// the last of them with hash head.
type treeState struct {
	size uint64
	head string
	r    *merkle.Range
}

func (st treeState) encode() ([]byte, error) {
	b, err := st.r.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "%s\n%d\n%s\n%s\n", treeMagic, st.size, st.head, base64.StdEncoding.EncodeToString(b)), nil
}

func parseTree(b []byte) (treeState, error) {
	lines := bytes.Split(b, []byte("\n"))
	if len(lines) != 5 || string(lines[0]) != treeMagic || len(lines[4]) != 0 {
		return treeState{}, errors.New("not a saved audit tree")
	}
	size, err := strconv.ParseUint(string(lines[1]), 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != string(lines[1]) {
		return treeState{}, errors.New("the record count is not a decimal number")
	}
	head := string(lines[2])
	if h, err := hex.DecodeString(head); err != nil || len(h) != sha256.Size || hex.EncodeToString(h) != head {
		return treeState{}, errors.New("the chain head is not a hex SHA-256 hash")
	}
	if (size == 0) != (head == Genesis) {
		return treeState{}, errors.New("the chain head does not fit the record count")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(string(lines[3]))
	if err != nil {
		return treeState{}, errors.New("the range is not base64")
	}
	var r merkle.Range
	if err := r.UnmarshalBinary(raw); err != nil {
		return treeState{}, err
	}
	if r.Size() != size {
		return treeState{}, fmt.Errorf("the range holds %d records, not %d", r.Size(), size)
	}
	return treeState{size: size, head: head, r: &r}, nil
}

// treeResume extends a saved range over the active segment while Open
// verifies it (verifyFrom's each).
type treeResume struct {
	st      treeState
	first   uint64 // the active segment's first record; 0 if it has none
	matched bool   // record st.size was seen with hash st.head
}

// resumeTree returns the saved range of the log at path when it can be
// taken up in the active segment, whose first record is first; nil when
// the tree must be rebuilt.
func resumeTree(path string, first uint64) *treeResume {
	b, err := os.ReadFile(TreePath(path))
	if err != nil {
		return nil
	}
	st, err := parseTree(b)
	if err != nil {
		return nil
	}
	if first == 0 && st.size != 0 || first > 0 && st.size+1 < first {
		return nil
	}
	return &treeResume{st: st, first: first}
}

func (t *treeResume) each(seq uint64, line []byte, sum [sha256.Size]byte) {
	switch {
	case seq == t.st.size:
		t.matched = hex.EncodeToString(sum[:]) == t.st.head
	case seq > t.st.size:
		t.st.r.AppendData(line)
	}
}

// tree returns the range extended to the end of the active segment res
// describes, or nil if the saved range did not match its records.
func (t *treeResume) tree(res Result) *merkle.Range {
	if t == nil || t.st.size > res.Records || t.st.r.Size() != res.Records {
		return nil
	}
	ok := t.matched
	switch {
	case t.st.size == 0:
		ok = true // parseTree checked the head
	case t.st.size+1 == t.first:
		ok = res.Start == t.st.head
	}
	if !ok {
		return nil
	}
	return t.st.r
}

// rebuildTree computes the log's tree from every segment and saves it, so
// the next open takes it up. Open calls it, holding the active file's lock,
// once the records are on disk.
func (l *Log) rebuildTree() error {
	cr, err := VerifyChain(l.path, nil)
	if err != nil {
		return fmt.Errorf("audit: building the Merkle tree of %s: %w", l.path, err)
	}
	if cr.Records != l.seq || cr.Head != l.head {
		return fmt.Errorf("audit: building the Merkle tree of %s: the segments end at record %d, not %d", l.path, cr.Records, l.seq)
	}
	l.tree = cr.tree
	if err := l.saveTree(); err != nil {
		return fmt.Errorf("audit: writing the Merkle tree: %w", err)
	}
	return nil
}

// saveTree writes the log's compact range to FILE.tree. The caller holds
// l.mu and, for a shared file, its lock, and has fsynced the records it
// covers.
func (l *Log) saveTree() error {
	b, err := treeState{size: l.seq, head: l.head, r: l.tree}.encode()
	if err != nil {
		return err
	}
	return writeFileAtomic(TreePath(l.path), b)
}

// prefix computes the tree head of the first size records of the log res
// verified, and the hash of record size, reading the segments up to it.
func (res ChainResult) prefix(size uint64) (root, head string, err error) {
	r := &merkle.Range{}
	head = Genesis
	b := res.base
	if b == nil && len(res.Segments) > 0 && res.Segments[0].First > 1 {
		// Put together by hand for a log retention cut: its base is
		// beside the active file, the last segment.
		if b, err = readBase(res.Segments[len(res.Segments)-1].Path); err != nil {
			return "", "", err
		}
	}
	if b != nil {
		if size < b.size {
			return "", "", fmt.Errorf("records 1 to %d were removed by retention, so the tree of the first %d cannot be computed", b.size, size)
		}
		r, head = b.r.Clone(), b.head
	}
	for _, s := range res.Segments {
		if r.Size() == size {
			break
		}
		if s.Records == 0 {
			continue
		}
		if err := prefixOf(s, r, size, &head); err != nil {
			return "", "", err
		}
	}
	if r.Size() != size {
		return "", "", fmt.Errorf("audit: no segment holds record %d", size)
	}
	return hexHash(r.Root()), head, nil
}

// prefixOf adds the records of segment s, up to record size, to r.
func prefixOf(s SegmentResult, r *merkle.Range, size uint64, head *string) error {
	f, err := os.Open(s.Path)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 64<<10)
	for n := s.First; n <= s.Records && r.Size() < size; n++ {
		line, err := readLine(br)
		if err == io.EOF || err == errTorn {
			return fmt.Errorf("audit: %s changed while it was read", s.Path)
		}
		if err != nil {
			return fmt.Errorf("audit: %s: %w", s.Path, err)
		}
		if n != r.Size()+1 {
			return fmt.Errorf("audit: %s changed while it was read", s.Path)
		}
		r.AppendData(line)
		sum := sha256.Sum256(line)
		*head = hex.EncodeToString(sum[:])
	}
	return nil
}
