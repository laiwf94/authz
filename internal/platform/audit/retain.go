package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/platform/merkle"
)

// Retention
//
// A log with Options.Retention removes its oldest rotated-out segments once
// they are older than Retention.MaxAge, or once the rotated-out segments
// together hold more than Retention.MaxBytes. It never removes the active
// segment, and never a segment holding a record newer than the last
// exported checkpoint: a checkpoint signed by the log's key that left the
// log's hands, kept beside it as FILE.exported (see ExportedPath). Log.Export
// records one; the admin API's POST /admin/audit/export and "authz audit
// export" call it. So every record that is removed was first covered by a
// signed checkpoint that someone else holds, and that checkpoint stays
// provable: a consistency proof from it needs only records after it and the
// compact range of the ones before.
//
// What was removed is described by FILE.base (see BasePath):
//
//	authz audit base
//	<records removed: 1 to K>
//	<hex SHA-256 of record K>
//	<base64 compact range of records 1 to K (tree.go)>
//	<file name of the segment that held record K>
//	<blank line>
//	<the exported checkpoint that allowed the removal, a signed note>
//
// The oldest segment left must continue it: start at record K+1, link to
// record K's hash and name that segment as the one before it. VerifyChain,
// Query and the proofs start from the base instead of the genesis record,
// and the Merkle tree from its range, so tree heads and proofs of the
// records that are left do not change. A forged base cannot hide that it is
// one: the range is part of every later tree head, which only the signing
// key can sign.
//
// Removal runs under the active file's lock after a rotation, on open and
// on Export: the records about to go are read and their chain checked from
// the base before them, the new base is written atomically (fsynced, as is
// the directory), and only then are the segments and their time indexes
// removed, oldest first, and the directory fsynced. A crash before the base
// is replaced removes nothing; one after it leaves segments the base already
// covers, which readers pass over and the next removal deletes.

// BasePath is where the log at path describes the records retention
// removed.
func BasePath(path string) string { return path + ".base" }

// ExportedPath is where the log at path keeps the last checkpoint it
// exported, a signed note.
func ExportedPath(path string) string { return path + ".exported" }

// Retention says when rotated-out segments are removed. The zero value
// keeps every segment.
type Retention struct {
	// MaxAge removes a segment once it was rotated out this long ago (the
	// time of the next segment's start record). 0 means no age limit.
	MaxAge time.Duration
	// MaxBytes removes the oldest segments while the rotated-out segments
	// hold more than this many bytes. 0 means no size limit.
	MaxBytes int64
}

// Enabled reports whether r ever removes a segment.
func (r Retention) Enabled() bool { return r.MaxAge > 0 || r.MaxBytes > 0 }

// The smallest limits Retention.Validate accepts.
const (
	MinRetainBytes = MinRotateBytes
	MinRetainAge   = time.Hour
)

// Validate checks limits an operator configured, as Rotation.Validate
// does. The error does not name the setting.
func (r Retention) Validate() error {
	if r.MaxBytes < 0 || r.MaxAge < 0 {
		return errors.New("must not be negative")
	}
	if r.MaxBytes > 0 && r.MaxBytes < MinRetainBytes {
		return fmt.Errorf("size limit %d is under the minimum of %d bytes", r.MaxBytes, MinRetainBytes)
	}
	if r.MaxAge > 0 && r.MaxAge < MinRetainAge {
		return fmt.Errorf("age limit %s is under the minimum of %s", r.MaxAge, MinRetainAge)
	}
	return nil
}

// String describes the limits for messages.
func (r Retention) String() string {
	if !r.Enabled() {
		return "no retention"
	}
	var parts []string
	if r.MaxBytes > 0 {
		parts = append(parts, fmt.Sprintf("max_bytes=%d", r.MaxBytes))
	}
	if r.MaxAge > 0 {
		parts = append(parts, "max_age="+r.MaxAge.String())
	}
	return strings.Join(parts, " ")
}

// ParseRetention reads limits from their text form, as ParseRotation does,
// and applies Validate. The error names neither setting.
func ParseRetention(bytes, age string) (Retention, error) {
	rot, err := parseLimits(bytes, age)
	r := Retention{MaxBytes: rot.MaxBytes, MaxAge: rot.MaxAge}
	if err != nil {
		return r, err
	}
	return r, r.Validate()
}

// parseLimits reads a size and an age limit without validating them.
func parseLimits(bytes, age string) (Rotation, error) {
	var r Rotation
	if bytes != "" {
		n, err := strconv.ParseInt(bytes, 10, 64)
		if err != nil {
			return r, fmt.Errorf("size limit %q is not a whole number of bytes", bytes)
		}
		r.MaxBytes = n
	}
	if age != "" && age != "0" {
		d, err := time.ParseDuration(age)
		if err != nil {
			return r, fmt.Errorf("age limit %q is not a duration such as 24h", age)
		}
		r.MaxAge = d
	}
	return r, nil
}

// removedBase is what FILE.base says: records 1 to size were removed, the
// last with hash head, held by the segment named last.
type removedBase struct {
	size uint64
	head string
	r    *merkle.Range
	last string
	note []byte
}

const baseMagic = "authz audit base"

func (b *removedBase) encode() ([]byte, error) {
	raw, err := b.r.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out := fmt.Appendf(nil, "%s\n%d\n%s\n%s\n%s\n\n", baseMagic, b.size, b.head, base64.StdEncoding.EncodeToString(raw), b.last)
	return append(out, b.note...), nil
}

func parseBase(b []byte) (*removedBase, error) {
	parts := bytes.SplitN(b, []byte("\n"), 7)
	if len(parts) != 7 || string(parts[0]) != baseMagic || len(parts[5]) != 0 {
		return nil, errors.New("not an audit base file")
	}
	st, err := parseTree(fmt.Appendf(nil, "%s\n%s\n%s\n%s\n", treeMagic, parts[1], parts[2], parts[3]))
	if err != nil {
		return nil, err
	}
	if st.size == 0 {
		return nil, errors.New("it removes no records")
	}
	last := string(parts[4])
	if !validSegmentFile(last) {
		return nil, fmt.Errorf("%q is not a segment's file name", last)
	}
	c, err := PeekCheckpoint(parts[6])
	if err != nil {
		return nil, fmt.Errorf("the exported checkpoint: %v", err)
	}
	if c.Size < st.size {
		return nil, fmt.Errorf("the exported checkpoint covers %d records, fewer than the %d removed", c.Size, st.size)
	}
	return &removedBase{size: st.size, head: st.head, r: st.r, last: last, note: parts[6]}, nil
}

// readBase reads FILE.base: nil when there is none.
func readBase(path string) (*removedBase, error) {
	b, err := os.ReadFile(BasePath(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	base, err := parseBase(b)
	if err != nil {
		return nil, fmt.Errorf("audit: %s: %v", BasePath(path), err)
	}
	return base, nil
}

// liveSegments lists the rotated-out segments of the log at path, as
// Segments does, without those FILE.base says were removed (left by a
// removal that crashed, for the next one to delete), and returns the base.
func liveSegments(path string) ([]string, *removedBase, error) {
	segs, err := Segments(path)
	if err != nil {
		return nil, nil, err
	}
	base, err := readBase(path)
	if err != nil || base == nil {
		return segs, base, err
	}
	n := 0
	for ; n < len(segs); n++ {
		next, err := nextFirst(path, segs, n)
		if err != nil || next == 0 || next-1 > base.size {
			break
		}
	}
	return segs[n:], base, nil
}

// nextFirst is the first record of the file after segs[i]: the next
// segment's, by its name, or the active file's; 0 if that has none.
func nextFirst(path string, segs []string, i int) (uint64, error) {
	if i+1 < len(segs) {
		n, _ := segmentFirst(filepath.Base(path), filepath.Base(segs[i+1]))
		return n, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return firstSeq(f)
}

// firstRecord reads the first record of the file at p.
func firstRecord(p string) (Record, error) {
	f, err := os.Open(p)
	if err != nil {
		return Record{}, err
	}
	defer f.Close()
	line, err := readLine(bufio.NewReaderSize(io.LimitReader(f, MaxLineBytes+1), 4<<10))
	if err != nil {
		return Record{}, fmt.Errorf("%s: no first record", p)
	}
	var r Record
	if err := json.Unmarshal(line, &r); err != nil {
		return Record{}, fmt.Errorf("%s: first record: %w", p, err)
	}
	return r, nil
}

// recordHash returns the hash of record seq of the file at p, whose first
// record is first.
func recordHash(p string, first, seq uint64) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 64<<10)
	for n := first; ; n++ {
		line, err := readLine(br)
		if err != nil {
			return "", fmt.Errorf("%s holds no record %d", p, seq)
		}
		if n == seq {
			sum := sha256.Sum256(line)
			return hex.EncodeToString(sum[:]), nil
		}
	}
}

// MarkExported records note, a checkpoint of the log at path signed by v's
// key, as exported, unless the one already recorded covers as many records.
// It does not check the checkpoint against the log: Log.Export does, and
// retention checks it before it relies on it. A process that is not one of
// the log's writers must hold no lock on it.
func MarkExported(path string, note []byte, v *Verifier) error {
	c, err := OpenCheckpoint(note, v)
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(ExportedPath(path)); err == nil {
		if oc, err := OpenCheckpoint(old, v); err == nil && oc.Size >= c.Size {
			return nil
		}
	}
	if err := writeFileAtomic(ExportedPath(path), note); err != nil {
		return fmt.Errorf("audit: recording the exported checkpoint: %w", err)
	}
	return nil
}

// Export returns the log's newest checkpoint, as Checkpoint does, and
// records it as exported: from then on retention may remove the segments
// it covers. A log with Options.Retention removes what it now may before
// returning; a failure there goes to Options.OnRetainError.
func (l *Log) Export() ([]byte, Checkpoint, error) {
	if l.signer == nil {
		return nil, Checkpoint{}, ErrNoSigner
	}
	var note []byte
	var c Checkpoint
	err := l.locked(func() error {
		if err := l.checkpoint(); err != nil {
			return err
		}
		note, c = l.cpNote, l.cp
		if err := MarkExported(l.path, note, l.verifier); err != nil {
			return err
		}
		l.retainNow()
		return nil
	})
	return note, c, err
}

// Retain removes the segments the log's retention allows now. Rotations,
// Open and Export run it too.
func (l *Log) Retain() error {
	return l.locked(func() error { return l.retain() })
}

// locked runs fn holding l.mu and, for a shared file, its lock, after
// reading other writers' records.
func (l *Log) locked(fn func() error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken {
		return ErrBroken
	}
	if l.osf != nil {
		if err := lockFile(l.osf); err != nil {
			l.broken = true
			return fmt.Errorf("audit: lock: %v: %w", err, ErrBroken)
		}
		defer func() { unlockFile(l.osf) }()
		if err := l.refresh(); err != nil {
			return err
		}
	}
	return fn()
}

// retainNow runs retention, reporting a failure instead of returning it.
func (l *Log) retainNow() {
	if err := l.retain(); err != nil && l.onRetainError != nil {
		l.onRetainError(err)
	}
}

// exported returns the last exported checkpoint of the log, checked: signed
// by the log's key, within the log, and naming the hash its record has (or
// the base's, once that record was removed). Size 0 when there is none.
func (l *Log) exported(segs []string, base *removedBase) (Checkpoint, []byte, error) {
	note, err := os.ReadFile(ExportedPath(l.path))
	if errors.Is(err, os.ErrNotExist) {
		return Checkpoint{}, nil, nil
	}
	if err != nil {
		return Checkpoint{}, nil, fmt.Errorf("audit: %w", err)
	}
	name := filepath.Base(ExportedPath(l.path))
	c, err := OpenCheckpoint(note, l.verifier)
	if err != nil {
		return Checkpoint{}, nil, fmt.Errorf("audit: %s: %v", name, err)
	}
	if c.Size > l.seq {
		return Checkpoint{}, nil, fmt.Errorf("audit: %s covers %d records, but the log holds %d", name, c.Size, l.seq)
	}
	if c.Size == 0 || base != nil && c.Size < base.size {
		return c, note, nil
	}
	var head string
	switch {
	case base != nil && c.Size == base.size:
		head = base.head
	case c.Size == l.seq:
		head = l.head
	default:
		// The file that holds the record: the last that starts at or
		// before it.
		p, first := l.path, l.first
		for i := len(segs) - 1; i >= 0 && (first == 0 || first > c.Size); i-- {
			p = segs[i]
			first, _ = segmentFirst(filepath.Base(l.path), filepath.Base(p))
		}
		if head, err = recordHash(p, first, c.Size); err != nil {
			return Checkpoint{}, nil, fmt.Errorf("audit: %s: %v", name, err)
		}
	}
	if head != c.Head {
		return Checkpoint{}, nil, fmt.Errorf("audit: %s is not a checkpoint of this log: record %d differs", name, c.Size)
	}
	return c, note, nil
}

// retain removes the segments the retention limits and the last exported
// checkpoint allow, and what a crashed removal left. The caller holds l.mu
// and the active file's lock, and has read other writers' records.
func (l *Log) retain() error {
	if !l.ret.Enabled() {
		return nil
	}
	segs, err := Segments(l.path)
	if err != nil {
		return err
	}
	base, err := readBase(l.path)
	if err != nil {
		return err
	}
	exp, note, err := l.exported(segs, base)
	if err != nil {
		return err
	}
	type seg struct {
		path        string
		first, last uint64
		size        int64
	}
	var stale, live []seg
	var total int64
	for i, p := range segs {
		first, _ := segmentFirst(filepath.Base(l.path), filepath.Base(p))
		next := l.first
		if i+1 < len(segs) {
			next, _ = segmentFirst(filepath.Base(l.path), filepath.Base(segs[i+1]))
		}
		if next <= first {
			return fmt.Errorf("audit: %s: the segments are out of order; run authz audit verify", p)
		}
		fi, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		s := seg{p, first, next - 1, fi.Size()}
		if base != nil && s.last <= base.size {
			stale = append(stale, s)
			continue
		}
		live = append(live, s)
		total += s.size
	}
	now := l.now()
	var remove []seg
	for i, s := range live {
		if s.last > exp.Size {
			break
		}
		old := false
		if l.ret.MaxAge > 0 {
			next := l.path
			if i+1 < len(live) {
				next = live[i+1].path
			}
			r, err := firstRecord(next)
			if err != nil {
				return fmt.Errorf("audit: %w", err)
			}
			if t, err := time.Parse(time.RFC3339Nano, r.Time); err == nil && now.Sub(t) >= l.ret.MaxAge {
				old = true
			}
		}
		if !old && !(l.ret.MaxBytes > 0 && total > l.ret.MaxBytes) {
			break
		}
		remove = append(remove, s)
		total -= s.size
	}
	if len(remove) > 0 {
		nb, err := l.extendBase(base, remove[0].path, remove[len(remove)-1].last, len(remove))
		if err != nil {
			return err
		}
		nb.note = note
		b, err := nb.encode()
		if err != nil {
			return err
		}
		if err := writeFileAtomic(BasePath(l.path), b); err != nil {
			return fmt.Errorf("audit: writing %s: %w", filepath.Base(BasePath(l.path)), err)
		}
		stale = append(stale, remove...)
	}
	if len(stale) == 0 {
		return nil
	}
	for _, s := range stale {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("audit: removing a segment: %w", err)
		}
		if err := os.Remove(IndexPath(s.path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("audit: removing a time index: %w", err)
		}
	}
	return syncDir(filepath.Dir(l.path))
}

// extendBase reads the n segments from the one at first, up to record last,
// checking their chain from base (nil: the genesis record), and returns the
// base after them. The file after them must link to record last.
func (l *Log) extendBase(base *removedBase, first string, last uint64, n int) (*removedBase, error) {
	out := &removedBase{head: Genesis, r: &merkle.Range{}}
	if base != nil {
		out.size, out.head, out.r, out.last = base.size, base.head, base.r.Clone(), base.last
	}
	segs, err := Segments(l.path)
	if err != nil {
		return nil, err
	}
	at := -1
	for i, p := range segs {
		if p == first {
			at = i
		}
	}
	if at < 0 || at+n > len(segs) {
		return nil, fmt.Errorf("audit: %s changed while segments were being removed", l.path)
	}
	leaf := func(_ uint64, line []byte, _ [sha256.Size]byte) { out.r.AppendData(line) }
	for _, p := range segs[at : at+n] {
		res, err := verifyPath(p, nil, leaf)
		if err != nil {
			return nil, fmt.Errorf("audit: %s: %w", p, err)
		}
		switch {
		case res.Records == 0:
			return nil, fmt.Errorf("audit: %s: segment is empty", p)
		case res.First != out.size+1 || res.Start != out.head || (out.size > 0 && res.Previous != out.last):
			return nil, fmt.Errorf("audit: %s does not continue the records before it; run authz audit verify", p)
		}
		out.size, out.head, out.last = res.Records, res.Head, filepath.Base(p)
	}
	if out.size != last {
		return nil, fmt.Errorf("audit: the segments to remove end at record %d, not %d", out.size, last)
	}
	next := l.path
	if at+n < len(segs) {
		next = segs[at+n]
	}
	r, err := firstRecord(next)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if r.Seq != last+1 || r.Prev != out.head {
		return nil, fmt.Errorf("audit: %s does not continue record %d; run authz audit verify", next, last)
	}
	return out, nil
}
