package audit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/platform/merkle"
)

// Checkpoints
//
// With Options.Signer the log signs its own state: a checkpoint names the
// number of records, the root of the RFC 6962 Merkle tree over them (see
// tree.go) and the hash of the last one, at a time, in a signed note
// (note.go) with Ed25519. Anyone holding only the public key can then tell
// that a log they are given still holds every record the checkpoint
// covered, unchanged: "authz audit verify -key" checks it. A checkpoint is
// the head hash of "authz mcp audit verify -head", signed, so it no longer
// has to be kept somewhere the operator cannot write; its tree head is what
// inclusion and consistency proofs are checked against.
//
// The text of a checkpoint is five lines:
//
//	<origin: the signing key's name>
//	<records>
//	<base64 of the Merkle tree head of the records; SHA-256 of nothing for none>
//	chain <base64 of the SHA-256 of the last record; 32 zero bytes for none>
//	time <RFC 3339 time it was signed, UTC>
//
// in the layout of a transparency log's checkpoint (C2SP tlog-checkpoint):
// origin, tree size and root hash, then extension lines.
//
// The newest checkpoint is kept beside the log as FILE.checkpoint (see
// CheckpointPath), replaced atomically. One is written when the log opens,
// on a timer (Options.CheckpointEvery) when records were added since the
// last, after every rotation, covering the segment start record that seals
// the old segment, and on Close. Each covers only records that are on disk:
// the active segment is fsynced before it is signed. Writers sharing one
// file sign under the file's lock after reading each other's records, so
// FILE.checkpoint only moves forward; they should share one key, or each
// replaces the other's signature with its own.
//
// Opening a log whose FILE.checkpoint, signed by Options.Signer, covers more
// records than the log holds fails: records were removed from its end since
// they were signed.

// DefaultCheckpointEvery is how often a log with a signer signs its state
// when Options.CheckpointEvery is zero.
const DefaultCheckpointEvery = time.Minute

// MinCheckpointEvery is the shortest interval ParseCheckpointEvery accepts.
const MinCheckpointEvery = time.Second

// ErrNoSigner means the log was opened without Options.Signer, so it signs
// no checkpoints.
var ErrNoSigner = errors.New("audit: no signing key is configured, so the log signs no checkpoints")

// Checkpoint is a log's state at a time: Size records, whose Merkle tree
// has root Root, the last of them with hash Head.
type Checkpoint struct {
	Origin string // the name of the key that signed it
	Size   uint64
	Root   string // hex RFC 6962 tree head of records 1 to Size; EmptyRoot when Size is 0
	Head   string // hex SHA-256 of record Size; Genesis when Size is 0
	Time   time.Time
}

// EmptyRoot is the tree head of a log of no records, in hex: the SHA-256
// of nothing.
var EmptyRoot = hexHash(merkle.EmptyRoot())

func hexHash(h merkle.Hash) string { return hex.EncodeToString(h[:]) }

// CheckpointPath is where the log at path keeps its newest checkpoint.
func CheckpointPath(path string) string { return path + ".checkpoint" }

// Text is the checkpoint's text, the part a signature covers.
func (c Checkpoint) Text() ([]byte, error) {
	if !validKeyName(c.Origin) {
		return nil, fmt.Errorf("audit: checkpoint origin %q is not a key name", c.Origin)
	}
	root, err := hex.DecodeString(c.Root)
	if err != nil || len(root) != sha256.Size {
		return nil, errors.New("audit: checkpoint tree head is not a SHA-256 hash")
	}
	head, err := hex.DecodeString(c.Head)
	if err != nil || len(head) != sha256.Size {
		return nil, errors.New("audit: checkpoint head is not a SHA-256 hash")
	}
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Appendf(nil, "%s\n%d\n%s\nchain %s\ntime %s\n", c.Origin, c.Size, b64(root), b64(head),
		c.Time.UTC().Format(time.RFC3339Nano)), nil
}

// ParseCheckpoint reads a checkpoint's text.
func ParseCheckpoint(text []byte) (Checkpoint, error) {
	bad := func(msg string) (Checkpoint, error) {
		return Checkpoint{}, errors.New("audit: not an audit checkpoint: " + msg)
	}
	lines := strings.Split(string(text), "\n")
	if len(lines) != 6 || lines[5] != "" {
		return bad("it must have five lines: origin, records, tree head, chain and time")
	}
	var c Checkpoint
	if c.Origin = lines[0]; !validKeyName(c.Origin) {
		return bad("the origin is not a key name")
	}
	n, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != lines[1] {
		return bad("the record count is not a decimal number")
	}
	c.Size = n
	root, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(root) != sha256.Size {
		return bad("the tree head is not a base64 SHA-256 hash")
	}
	c.Root = hex.EncodeToString(root)
	chain, ok := strings.CutPrefix(lines[3], "chain ")
	if !ok {
		return bad(`the fourth line must be "chain <base64 hash of the last record>"`)
	}
	head, err := base64.StdEncoding.Strict().DecodeString(chain)
	if err != nil || len(head) != sha256.Size {
		return bad("the chain head is not a base64 SHA-256 hash")
	}
	c.Head = hex.EncodeToString(head)
	if c.Size == 0 && (c.Head != Genesis || c.Root != EmptyRoot) {
		return bad("a checkpoint of no records must have the empty tree head and the zero chain head")
	}
	ts, ok := strings.CutPrefix(lines[4], "time ")
	if !ok {
		return bad(`the fifth line must be "time <RFC 3339 time>"`)
	}
	if c.Time, err = time.Parse(time.RFC3339Nano, ts); err != nil {
		return bad("the time is not an RFC 3339 time")
	}
	return c, nil
}

// Sign returns the checkpoint as a note signed by s. Its origin must be s's
// name.
func (c Checkpoint) Sign(s *Signer) ([]byte, error) {
	if c.Origin != s.Name() {
		return nil, fmt.Errorf("audit: checkpoint origin %s is not the signing key's name %s", c.Origin, s.Name())
	}
	text, err := c.Text()
	if err != nil {
		return nil, err
	}
	return SignNote(text, s)
}

// OpenCheckpoint checks that msg is a checkpoint signed by v, with v's name
// as its origin, and returns it.
func OpenCheckpoint(msg []byte, v *Verifier) (Checkpoint, error) {
	text, err := OpenNote(msg, v)
	if err != nil {
		return Checkpoint{}, err
	}
	c, err := ParseCheckpoint(text)
	if err != nil {
		return Checkpoint{}, err
	}
	if c.Origin != v.Name() {
		return Checkpoint{}, fmt.Errorf("audit: the checkpoint is for %s, not %s", c.Origin, v.Name())
	}
	return c, nil
}

// ParseCheckpointEvery reads a checkpoint interval as a Go duration of at
// least MinCheckpointEvery; empty means DefaultCheckpointEvery.
func ParseCheckpointEvery(s string) (time.Duration, error) {
	if s == "" {
		return DefaultCheckpointEvery, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration such as 1m or 30s", s)
	}
	if d < MinCheckpointEvery {
		return 0, fmt.Errorf("%s is shorter than the minimum of %s", d, MinCheckpointEvery)
	}
	return d, nil
}

// Checkpoint returns the log's newest checkpoint as a signed note, after
// signing the current state if records were added since the last one. Like
// Head it first reads the records other writers of a shared file appended.
func (l *Log) Checkpoint() ([]byte, Checkpoint, error) {
	if l.signer == nil {
		return nil, Checkpoint{}, ErrNoSigner
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken {
		return nil, Checkpoint{}, ErrBroken
	}
	if l.osf != nil {
		if err := lockFile(l.osf); err != nil {
			l.broken = true
			return nil, Checkpoint{}, fmt.Errorf("audit: lock: %v: %w", err, ErrBroken)
		}
		defer func() { unlockFile(l.osf) }()
		if err := l.refresh(); err != nil {
			return nil, Checkpoint{}, err
		}
	}
	if err := l.checkpoint(); err != nil {
		return nil, Checkpoint{}, err
	}
	return l.cpNote, l.cp, nil
}

// checkpoint signs the current state unless the newest checkpoint already
// covers it. The caller holds l.mu and, for a shared file, its lock, and
// has read other writers' records.
func (l *Log) checkpoint() error {
	root := hexHash(l.tree.Root())
	if l.cpNote != nil && l.cp.Size == l.seq && l.cp.Head == l.head && l.cp.Root == root {
		return nil
	}
	path := CheckpointPath(l.path)
	// Another writer of the file may have signed this state already, and
	// saved the tree before it did.
	if msg, err := os.ReadFile(path); err == nil {
		if c, err := OpenCheckpoint(msg, l.verifier); err == nil && c.Size == l.seq && c.Head == l.head && c.Root == root {
			l.cp, l.cpNote = c, msg
			return nil
		}
	}
	// Only what is on disk is signed: a record still waiting for its
	// fsync could be lost in a crash and the checkpoint outlive it.
	if err := l.f.Sync(); err != nil {
		l.broken = true
		return fmt.Errorf("audit: fsync before checkpoint: %w", err)
	}
	// The tree is saved first, so a log that has a checkpoint of some
	// state has its tree for that state or a later one.
	if err := l.saveTree(); err != nil {
		return fmt.Errorf("audit: writing the Merkle tree: %w", err)
	}
	c := Checkpoint{Origin: l.signer.Name(), Size: l.seq, Root: root, Head: l.head, Time: l.now().UTC()}
	msg, err := c.Sign(l.signer)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, msg); err != nil {
		return fmt.Errorf("audit: writing checkpoint: %w", err)
	}
	l.cp, l.cpNote = c, msg
	return nil
}

// checkOpenCheckpoint refuses a log that ends before the records its
// stored checkpoint, signed by the log's key, covers. A checkpoint by
// another key, or one that does not open, is replaced by the next one.
func (l *Log) checkOpenCheckpoint() error {
	msg, err := os.ReadFile(CheckpointPath(l.path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("audit: %w", err)
	}
	c, err := OpenCheckpoint(msg, l.verifier)
	if err != nil {
		return nil
	}
	if c.Size > l.seq {
		return fmt.Errorf("audit: %s ends at record %d, but its checkpoint %s signed at %s covers %d records: records were removed from its end; restore them, or move the checkpoint away to start a new one",
			l.path, l.seq, filepath.Base(CheckpointPath(l.path)), c.Time.Format(time.RFC3339), c.Size)
	}
	if c.Size == l.seq && c.Head != l.head {
		return fmt.Errorf("audit: record %d of %s differs from the one its checkpoint signed at %s: the last record was changed; restore it, or move the checkpoint away to start a new one",
			l.seq, l.path, c.Time.Format(time.RFC3339))
	}
	if c.Size == l.seq && c.Root != hexHash(l.tree.Root()) {
		// The records are the ones signed, so the saved tree was wrong,
		// or the checkpoint was not computed from them.
		if err := l.rebuildTree(); err != nil {
			return err
		}
		if c.Root != hexHash(l.tree.Root()) {
			return fmt.Errorf("audit: the checkpoint of %s signed at %s has a tree head that is not the root of its %d records; move the checkpoint away to start a new one",
				l.path, c.Time.Format(time.RFC3339), c.Size)
		}
	}
	if c.Size == l.seq {
		l.cp, l.cpNote = c, msg
	}
	return nil
}

// checkpointLoop signs the log's state every interval until Close.
func (l *Log) checkpointLoop(every time.Duration) {
	defer close(l.cpDone)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-l.cpStop:
			return
		case <-t.C:
			if _, _, err := l.Checkpoint(); err != nil {
				l.checkpointFailed(err)
			}
		}
	}
}

func (l *Log) checkpointFailed(err error) {
	if l.onCPError != nil {
		l.onCPError(err)
	}
}

// writeFileAtomic replaces path with data: written to a temporary file
// beside it, fsynced, renamed over path, and the directory fsynced.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// Covers checks that the log res verified still holds the state c signed:
// at least c.Size records, record c.Size with hash c.Head, and c.Root the
// tree head of records 1 to c.Size. A log that holds fewer records lost its
// newest ones; a different hash means the records up to c.Size were
// rewritten. For a checkpoint of fewer records than the log holds, or a
// ChainResult without Root, the segments are read up to record c.Size.
func (res ChainResult) Covers(c Checkpoint) error {
	if c.Size > res.Records {
		return fmt.Errorf("the log has %d records, but the checkpoint signed at %s covers %d: records were removed from its end",
			res.Records, c.Time.Format(time.RFC3339), c.Size)
	}
	if c.Size == 0 {
		if c.Head != Genesis || c.Root != EmptyRoot {
			return errors.New("a checkpoint of no records must have the empty tree head and the zero chain head")
		}
		return nil
	}
	root, head := res.Root, res.Head
	// A ChainResult put together by hand, without VerifyChain, has no
	// tree head: compute it from the segments.
	if c.Size < res.Records || root == "" {
		var err error
		if root, head, err = res.prefix(c.Size); err != nil {
			return err
		}
	}
	if head != c.Head {
		return fmt.Errorf("record %d is not the one the checkpoint signed at %s: the log was rewritten up to there",
			c.Size, c.Time.Format(time.RFC3339))
	}
	if root != c.Root {
		return fmt.Errorf("the tree head of the checkpoint signed at %s is not the root of records 1 to %d: it was not signed over this log's records",
			c.Time.Format(time.RFC3339), c.Size)
	}
	return nil
}
