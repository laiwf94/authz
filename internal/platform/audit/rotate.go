package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/platform/logging"
	"github.com/laiwf94/authz/internal/platform/merkle"
)

// Segments
//
// A rotated log is a run of files in one directory. The file at the
// configured path (say audit.jsonl) is the active segment, the only one
// written to. Older segments are named for the sequence number of their
// first record, zero-padded to 20 digits so that names sort in chain order:
//
//	audit.jsonl.00000000000000000001   records 1 to 1,204
//	audit.jsonl.00000000000000001205   records 1,205 to 2,388
//	audit.jsonl                        records 2,389 onwards
//
// Every segment after the first opens with a segment start record
// (EventSegmentStarted). It continues the chain like any other record (its
// "prev" is the hash of the last record of the segment before it) and names
// that segment, so a segment that was removed, renamed or put in another's
// place breaks the chain where VerifyChain looks for it.
//
// A rotation runs under the active file's lock, after reading what other
// writers appended, in this order: fsync the active file; write the segment
// start record to audit.jsonl.next and fsync it; hard-link audit.jsonl to its
// segment name; rename audit.jsonl.next over audit.jsonl; fsync the
// directory. The configured path therefore always names a complete log, and
// a crash at any step leaves either the old active file or the new one in
// place; Open removes what a crashed rotation left behind (the .next file,
// and a segment link that still names the active file). The new file is
// locked before it is renamed into place, so a writer that opens it waits
// for the rotation to finish.
//
// Other writers of a shared file still hold the old one open. Each append
// and Head checks under the lock whether the path still names the file it
// holds; when it does not, the writer reads the rest of the old segment,
// moves to the new file and reads on from its segment start record. The
// rotating writer fsynced the old segment, so what the others wrote there is
// durable too.

// EventSegmentStarted is the first record of every segment after the first.
const EventSegmentStarted = "audit.segment_started"

// TrackAudit is the audit log's own track: its segment records.
const TrackAudit Track = "audit"

// ActionRotate is the envelope action of a segment start record.
const ActionRotate = "audit.rotate"

// The reasons a segment ends.
const (
	RotateSize   = "size"   // the segment reached Rotation.MaxBytes
	RotateAge    = "age"    // the segment's first record is Rotation.MaxAge old
	RotateManual = "manual" // Log.Rotate
)

// SegmentStarted is the payload of a segment start record.
type SegmentStarted struct {
	// Previous is the file name (without directory) of the segment before.
	Previous string `json:"previous"`
	// PreviousFirst is the sequence number of that segment's first record.
	PreviousFirst uint64 `json:"previous_first"`
	// Reason is why the previous segment ended: size, age or manual.
	Reason string `json:"reason"`
	// MaxBytes and MaxAge are the rotating writer's limits (Rotation), so
	// the other writers of a shared file can tell whether they rotate it
	// alike. MaxAge is a Go duration such as "24h0m0s". Both are left out
	// when the writer had none, and by segment records written before
	// they were recorded.
	MaxBytes int64  `json:"max_bytes,omitempty"`
	MaxAge   string `json:"max_age,omitempty"`
}

// AuditEvent implements Payload.
func (SegmentStarted) AuditEvent() string { return EventSegmentStarted }

// Rotation says when the active segment ends. The zero value never rotates.
type Rotation struct {
	// MaxBytes ends a segment once it holds at least this many bytes: the
	// record that reaches the limit is the segment's last. 0 means no limit.
	MaxBytes int64
	// MaxAge ends a segment once its first record is this old, checked when
	// the next record is appended. 0 means no limit.
	MaxAge time.Duration
}

// Enabled reports whether r ever rotates.
func (r Rotation) Enabled() bool { return r.MaxBytes > 0 || r.MaxAge > 0 }

func (r Rotation) check() error {
	if r.MaxBytes < 0 || r.MaxAge < 0 {
		return errors.New("audit: rotation limits must not be negative")
	}
	if r.Enabled() && !canLock {
		return errors.New("audit: rotation needs flock, which this system lacks")
	}
	return nil
}

// The smallest limits Validate accepts. A smaller segment would hold only a
// few records and a younger one would rotate on nearly every append; both
// are more likely a missing unit than a plan.
const (
	MinRotateBytes = 4096
	MinRotateAge   = time.Minute
)

// Validate checks limits an operator configured: neither negative, a size
// limit of at least MinRotateBytes and an age limit of at least
// MinRotateAge. The error does not name the setting; the caller does.
func (r Rotation) Validate() error {
	if r.MaxBytes < 0 || r.MaxAge < 0 {
		return errors.New("must not be negative")
	}
	if r.MaxBytes > 0 && r.MaxBytes < MinRotateBytes {
		return fmt.Errorf("size limit %d is under the minimum of %d bytes", r.MaxBytes, MinRotateBytes)
	}
	if r.MaxAge > 0 && r.MaxAge < MinRotateAge {
		return fmt.Errorf("age limit %s is under the minimum of %s", r.MaxAge, MinRotateAge)
	}
	return nil
}

// String describes the limits for messages.
func (r Rotation) String() string {
	if !r.Enabled() {
		return "no rotation"
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

// started records r's limits in a segment start record.
func (r Rotation) started(ss SegmentStarted) SegmentStarted {
	ss.MaxBytes = r.MaxBytes
	if r.MaxAge > 0 {
		ss.MaxAge = r.MaxAge.String()
	}
	return ss
}

// ParseRotation reads limits from their text form: bytes a non-negative
// integer and age a Go duration such as "24h"; empty or "0" leaves that
// limit off. It applies Validate. The error names neither setting.
func ParseRotation(bytes, age string) (Rotation, error) {
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
	return r, r.Validate()
}

// RotationFromEnv reads limits from two environment variables, as
// ParseRotation reads them, with errors that name the variable.
func RotationFromEnv(getenv func(string) string, bytesVar, ageVar string) (Rotation, error) {
	b, a := getenv(bytesVar), getenv(ageVar)
	if _, err := ParseRotation(b, ""); err != nil {
		return Rotation{}, fmt.Errorf("%s: %v", bytesVar, err)
	}
	if _, err := ParseRotation("", a); err != nil {
		return Rotation{}, fmt.Errorf("%s: %v", ageVar, err)
	}
	return ParseRotation(b, a)
}

// CheckSameRotation reports whether a writer with limits r may share the
// log at path, whose active segment begins with the segment start record ss
// (nil when it begins the chain). A segment that a size or age rotation
// started records the limits it was cut under; every writer of the file
// must have those, or the one with the smaller limits would cut segments
// the others never would. A manual rotation, the chain's first segment and
// segment records from before limits were recorded put no limit on r.
func CheckSameRotation(path string, ss *SegmentStarted, r Rotation) error {
	if ss == nil || (ss.Reason != RotateSize && ss.Reason != RotateAge) || (ss.MaxBytes == 0 && ss.MaxAge == "") {
		return nil
	}
	var theirs Rotation
	theirs.MaxBytes = ss.MaxBytes
	if ss.MaxAge != "" {
		d, err := time.ParseDuration(ss.MaxAge)
		if err != nil {
			return fmt.Errorf("audit: %s: the segment start record has max_age %q, not a duration", path, ss.MaxAge)
		}
		theirs.MaxAge = d
	}
	if theirs != r {
		return fmt.Errorf("audit: %s is rotated with %s, but this writer has %s; every process writing one audit file must set the same rotation limits", path, theirs, r)
	}
	return nil
}

// segmentDigits is the width of a segment's number: every uint64 fits.
const segmentDigits = 20

// SegmentPath is the name the segment of the log at path whose first record
// has sequence first gets when it is rotated out.
func SegmentPath(path string, first uint64) string {
	return fmt.Sprintf("%s.%0*d", path, segmentDigits, first)
}

// segmentFirst returns the first sequence number in a segment's file name,
// given the active file's base name.
func segmentFirst(base, name string) (uint64, bool) {
	num, ok := strings.CutPrefix(name, base+".")
	if !ok || len(num) != segmentDigits {
		return 0, false
	}
	for _, c := range num {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(num, 10, 64)
	return n, err == nil && n > 0
}

// validSegmentFile reports whether name looks like a segment's file name:
// no directory, ending in a 20-digit number other than zero.
func validSegmentFile(name string) bool {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || strings.ContainsAny(name, `/\`) {
		return false
	}
	_, ok := segmentFirst(name[:i], name)
	return ok
}

// Segments lists the rotated-out segments of the log at path, oldest first.
// The active file itself is not among them.
func Segments(path string) ([]string, error) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	type seg struct {
		name  string
		first uint64
	}
	var segs []seg
	for _, e := range ents {
		if n, ok := segmentFirst(base, e.Name()); ok && !e.IsDir() {
			segs = append(segs, seg{e.Name(), n})
		}
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].first < segs[j].first })
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = filepath.Join(filepath.Dir(path), s.name)
	}
	return out, nil
}

// openActive opens (creating it if need be) the file at path and, where
// files can be locked, locks it. A rotation may replace the file between
// the open and the lock, so it retries until the locked file is the one the
// path names.
func openActive(path string) (*os.File, error) {
	for {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		if !canLock {
			return f, nil
		}
		if err := lockFile(f); err != nil {
			f.Close()
			return nil, fmt.Errorf("audit: locking %s: %w", path, err)
		}
		moved, err := movedAway(f, path)
		if err != nil {
			f.Close()
			return nil, err
		}
		if !moved {
			return f, nil
		}
		f.Close()
	}
}

// movedAway reports whether path no longer names the file f.
func movedAway(f *os.File, path string) (bool, error) {
	fi, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("audit: %w", err)
	}
	pi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		// Between a crashed rotation's link and rename the path always
		// exists, so nothing of ours removes it.
		return false, fmt.Errorf("audit: %s was removed while the log was open", path)
	}
	if err != nil {
		return false, fmt.Errorf("audit: %w", err)
	}
	return !os.SameFile(fi, pi), nil
}

// nextPath is where a rotation writes the new active file before renaming it
// into place.
func nextPath(path string) string { return path + ".next" }

// cleanRotation removes what a rotation that crashed left behind. The caller
// holds the lock on f, the file path names, whose first record has sequence
// first, so no rotation of it is under way.
func cleanRotation(path string, f *os.File, first uint64) error {
	changed := false
	if err := os.Remove(nextPath(path)); err == nil {
		changed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("audit: removing a crashed rotation's file: %w", err)
	}
	if first > 0 {
		// Linked but never replaced: the segment name is a second name of
		// the active file, and the next rotation will link it again.
		seg := SegmentPath(path, first)
		if si, err := os.Lstat(seg); err == nil {
			fi, err := f.Stat()
			if err != nil {
				return fmt.Errorf("audit: %w", err)
			}
			if os.SameFile(si, fi) {
				if err := os.Remove(seg); err != nil {
					return fmt.Errorf("audit: removing a crashed rotation's link: %w", err)
				}
				changed = true
			}
		}
	}
	if changed {
		return syncDir(filepath.Dir(path))
	}
	return nil
}

// syncDir fsyncs a directory, so renames and links in it are durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("audit: fsync of %s: %w", dir, err)
	}
	return nil
}

// parseTime reads a record's time; a missing or malformed one counts as now,
// so the segment's age starts when this writer first saw it.
func parseTime(s string, now func() time.Time) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return now()
}

// due returns why the active segment should end before the next record, or
// "" if it should not.
func (l *Log) due() string {
	if l.first == 0 || !l.rot.Enabled() {
		return ""
	}
	if l.rot.MaxBytes > 0 && l.size >= l.rot.MaxBytes {
		return RotateSize
	}
	if l.rot.MaxAge > 0 && l.now().Sub(l.started) >= l.rot.MaxAge {
		return RotateAge
	}
	return ""
}

// Rotate ends the active segment now, whatever the rotation limits, unless
// it is empty. Like an append it takes the lock and reads other writers'
// records first.
func (l *Log) Rotate() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken {
		return ErrBroken
	}
	if !canLock {
		return errors.New("audit: rotation needs flock, which this system lacks")
	}
	if err := lockFile(l.osf); err != nil {
		l.broken = true
		return fmt.Errorf("audit: lock: %v: %w", err, ErrBroken)
	}
	defer func() { unlockFile(l.osf) }()
	if err := l.refresh(); err != nil {
		return err
	}
	if err := l.rotate(RotateManual); err != nil {
		return err
	}
	return l.rotated()
}

// rotated signs a checkpoint after a rotation, when the log has a signer.
// The caller holds l.mu and the new segment's lock. A checkpoint that
// cannot be written is reported and does not fail the rotation, unless
// its fsync failed and the log is broken.
func (l *Log) rotated() error {
	if l.signer == nil {
		return nil
	}
	if err := l.checkpoint(); err != nil {
		if l.broken {
			return err
		}
		l.checkpointFailed(err)
	}
	l.retainNow()
	return nil
}

// refresh brings the Log up to the end of the chain other writers left: the
// rest of its segment and, if they rotated it, the segments after it. The
// caller holds l.mu and the lock on l.osf.
func (l *Log) refresh() error {
	for {
		if err := l.catchUp(); err != nil {
			return err
		}
		moved, err := movedAway(l.osf, l.path)
		if err != nil {
			l.broken = true
			return fmt.Errorf("%v: %w", err, ErrBroken)
		}
		if !moved {
			return nil
		}
		if err := l.follow(); err != nil {
			return err
		}
	}
}

// follow moves to the segment after the one this Log holds, once another
// writer rotated it; catchUp then reads it from its segment start record.
// The caller holds l.mu and the lock on l.osf, and has read the old segment
// to its end, so the next segment starts at record l.seq+1. That is the file
// the path names, unless it was rotated again in the meantime: then it is
// the segment named for that record, which refresh reads and follows on
// from in turn.
func (l *Log) follow() error {
	want := l.seq + 1
	for range maxFollowTries {
		nf, err := os.OpenFile(SegmentPath(l.path, want), os.O_RDWR, 0)
		if errors.Is(err, os.ErrNotExist) {
			nf, err = os.OpenFile(l.path, os.O_RDWR, 0)
		}
		if err != nil {
			l.broken = true
			return fmt.Errorf("audit: opening the next segment: %v: %w", err, ErrBroken)
		}
		if err := lockFile(nf); err != nil {
			nf.Close()
			l.broken = true
			return fmt.Errorf("audit: lock: %v: %w", err, ErrBroken)
		}
		first, err := firstSeq(nf)
		if err != nil {
			nf.Close()
			l.broken = true
			return fmt.Errorf("audit: reading the next segment: %v: %w", err, ErrBroken)
		}
		if first != want {
			// The path's file was rotated after the segment name was
			// looked up: look again.
			nf.Close()
			continue
		}
		unlockFile(l.osf)
		l.retire(nf, 0)
		// The rotating writer fsynced the old segment, records of this
		// Log included.
		l.floor = l.base
		l.first = 0
		return nil
	}
	l.broken = true
	return fmt.Errorf("audit: no segment starts at record %d: %w", want, ErrBroken)
}

// maxFollowTries bounds follow's lookups: each miss means another rotation
// finished in between, which cannot keep happening.
const maxFollowTries = 100

// firstSeq returns the sequence number of f's first record, 0 if it has none.
func firstSeq(f *os.File) (uint64, error) {
	br := bufio.NewReaderSize(io.NewSectionReader(f, 0, MaxLineBytes+1), 4<<10)
	line, err := readLine(br)
	if err == io.EOF || err == errTorn {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var r struct {
		Seq uint64 `json:"seq"`
	}
	if err := json.Unmarshal(line, &r); err != nil {
		return 0, fmt.Errorf("first record: %w", err)
	}
	return r.Seq, nil
}

// retire makes nf, holding size bytes, the active segment's file. The old
// one is closed by the next syncTo, which may still be fsyncing it.
func (l *Log) retire(nf *os.File, size int64) {
	l.retired = append(l.retired, l.f)
	l.base += l.size
	l.f, l.osf, l.size = nf, nf, size
}

// rotate ends the active segment and starts the next with a segment start
// record. The caller holds l.mu and the lock on l.osf, and has called
// refresh. An error before the rename leaves the active segment as it was,
// so the next append tries again; a failed fsync breaks the log.
func (l *Log) rotate(reason string) error {
	if l.first == 0 {
		return nil
	}
	if err := l.f.Sync(); err != nil {
		l.broken = true
		return fmt.Errorf("audit: fsync before rotation: %w", err)
	}
	l.floor = l.base + l.size
	seg := SegmentPath(l.path, l.first)
	next := nextPath(l.path)
	now := l.now()
	line, err := marshal(record{Seq: l.seq + 1, Time: now.UTC().Format(time.RFC3339Nano), Prev: l.head,
		Event: EventSegmentStarted, Envelope: Envelope{Action: ActionRotate},
		Data: l.rot.started(SegmentStarted{Previous: filepath.Base(seg), PreviousFirst: l.first, Reason: reason})})
	if err != nil {
		return fmt.Errorf("audit: encoding record: %w", err)
	}
	// Left by a rotation that failed before its rename; the lock rules out
	// a live one.
	if err := os.Remove(next); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("audit: rotation: %w", err)
	}
	nf, err := os.OpenFile(next, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("audit: rotation: %w", err)
	}
	fail := func(err error) error {
		nf.Close()
		os.Remove(next)
		return fmt.Errorf("audit: rotation: %w", err)
	}
	if err := lockFile(nf); err != nil {
		return fail(err)
	}
	if _, err := nf.Write(append(line, '\n')); err != nil {
		return fail(err)
	}
	if err := nf.Sync(); err != nil {
		return fail(err)
	}
	if _, err := nf.Seek(0, io.SeekEnd); err != nil {
		return fail(err)
	}
	if err := os.Link(l.path, seg); err != nil {
		return fail(err)
	}
	if err := os.Rename(next, l.path); err != nil {
		os.Remove(seg)
		return fail(err)
	}
	// From here the new file is the active segment, whatever happens.
	unlockFile(l.osf)
	l.retire(nf, int64(len(line))+1)
	sum := sha256.Sum256(line)
	l.seq++
	l.head = hex.EncodeToString(sum[:])
	l.first, l.started = l.seq, now
	if l.tree != nil {
		l.tree.AppendData(line)
	}
	logging.Observe(logging.SourceAudit, line)
	if err := syncDir(filepath.Dir(l.path)); err != nil {
		// The rename may not survive a crash, and the old file is no
		// longer named for what it holds next time: stop, as after a
		// failed fsync.
		l.broken = true
		return fmt.Errorf("%v: %w", err, ErrBroken)
	}
	l.floor = l.base + l.size
	return nil
}

// SegmentResult is one verified file of a log.
type SegmentResult struct {
	Path string
	Result
}

// ChainResult summarizes a log verified across its segments.
type ChainResult struct {
	Segments []SegmentResult // oldest first; the active file last
	Records  uint64
	Head     string
	Root     string // hex Merkle tree head of every record (tree.go); EmptyRoot for none
	// Removed is the number of records retention removed, 1 to Removed
	// (retain.go); the oldest segment continues them.
	Removed uint64

	tree *merkle.Range
	base *removedBase
}

// SegmentError locates a failure in one segment, or between two.
type SegmentError struct {
	Path string
	Err  error
}

func (e *SegmentError) Error() string { return e.Path + ": " + e.Err.Error() }
func (e *SegmentError) Unwrap() error { return e.Err }

// VerifyChain checks the log at path across all its segments: each file's
// chain, as Verify does (VerifyWith when s is set), and the links between
// them. The first segment must start the chain, or continue the records
// retention removed as FILE.base describes them (retain.go); each later one
// must be named for its first record, name the segment before it and
// continue that segment's chain, so a segment that was removed, reordered,
// renamed or replaced is named in the error. A log that was never rotated is
// the one file. As with Verify, the newest record's integrity needs a head
// stored elsewhere.
func VerifyChain(path string, s *Schemas) (ChainResult, error) {
	for try := 0; ; try++ {
		res, err := verifyChain(path, s)
		if errors.Is(err, errRetained) && try < 3 {
			continue // retention removed a segment while it was read
		}
		return res, err
	}
}

// errRetained means a segment was removed by retention while it was read.
var errRetained = errors.New("audit: a segment was removed by retention while the log was read")

func verifyChain(path string, s *Schemas) (ChainResult, error) {
	segs, base, err := liveSegments(path)
	if err != nil {
		return ChainResult{}, err
	}
	if _, err := os.Stat(path); err != nil {
		if (len(segs) > 0 || base != nil) && errors.Is(err, os.ErrNotExist) {
			return ChainResult{}, &SegmentError{path, errors.New("the active segment is missing; the newest records were removed")}
		}
		return ChainResult{}, fmt.Errorf("audit: %w", err)
	}
	files := append(segs, path)
	out := ChainResult{Head: Genesis, Root: EmptyRoot, tree: &merkle.Range{}}
	// What the next file must continue: the base, or the genesis record.
	prevRecords, prevHead, prevName := uint64(0), Genesis, ""
	if base != nil {
		out.Records, out.Head, out.Removed, out.tree, out.base = base.size, base.head, base.size, base.r.Clone(), base
		prevRecords, prevHead, prevName = base.size, base.head, base.last
	}
	// Leaves are only right once every link below checked out, which is
	// all a caller sees.
	leaf := func(_ uint64, line []byte, _ [sha256.Size]byte) { out.tree.AppendData(line) }
	for i, p := range files {
		res, err := verifyPath(p, s, leaf)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && i < len(segs) {
				if nb, berr := readBase(path); berr == nil && nb != nil && (base == nil || nb.size > base.size) {
					return out, errRetained
				}
			}
			return out, &SegmentError{p, err}
		}
		active := i == len(files)-1
		switch {
		case res.Records == 0 && !active:
			return out, &SegmentError{p, errors.New("segment is empty")}
		case res.Records == 0 && i > 0:
			return out, &SegmentError{p, fmt.Errorf("the active segment is empty, but %s comes before it; its records were removed", filepath.Base(files[i-1]))}
		case res.Records == 0 && base != nil:
			return out, &SegmentError{p, fmt.Errorf("the active segment is empty, but %s says records 1 to %d were removed before it; its records were removed", filepath.Base(BasePath(path)), base.size)}
		}
		if !active {
			n, _ := segmentFirst(filepath.Base(path), filepath.Base(p))
			if res.First != n {
				return out, &SegmentError{p, fmt.Errorf("segment is named for record %d but starts at record %d; it was renamed or another file put in its place", n, res.First)}
			}
		}
		if res.Records > 0 {
			switch {
			case i == 0 && base == nil:
				if res.Start != Genesis {
					return out, &SegmentError{p, fmt.Errorf("the oldest segment starts at record %d, not 1; the segments before it (%s) were removed", res.First, res.Previous)}
				}
			case i == 0 && res.First <= base.size:
				return out, &SegmentError{p, fmt.Errorf("segment starts at record %d, but %s says records 1 to %d were removed; one of them was put back or the base file was changed", res.First, filepath.Base(BasePath(path)), base.size)}
			case res.First > prevRecords+1 && i == 0:
				return out, &SegmentError{p, fmt.Errorf("records %d to %d are missing between the records retention removed and this segment; a segment (%s) was removed", prevRecords+1, res.First-1, res.Previous)}
			case res.First > prevRecords+1:
				return out, &SegmentError{p, fmt.Errorf("records %d to %d are missing between %s and this segment; a segment (%s) was removed", prevRecords+1, res.First-1, prevName, res.Previous)}
			case res.First <= prevRecords:
				return out, &SegmentError{p, fmt.Errorf("segment starts at record %d, which %s already holds; segments were reordered or copied", res.First, prevName)}
			case res.Previous != prevName:
				return out, &SegmentError{p, fmt.Errorf("segment names %s as the one before it, not %s; segments were renamed or reordered", res.Previous, prevName)}
			case res.Start != prevHead && i == 0:
				return out, &SegmentError{p, fmt.Errorf("first record does not match the hash of record %d that %s gives; that record was modified or the base file was changed", base.size, filepath.Base(BasePath(path)))}
			case res.Start != prevHead:
				return out, &SegmentError{p, fmt.Errorf("first record does not match the hash of the last record of %s; that record was modified or the segment was replaced", prevName)}
			}
			out.Records, out.Head = res.Records, res.Head
			prevRecords, prevHead = res.Records, res.Head
		}
		prevName = filepath.Base(p)
		out.Segments = append(out.Segments, SegmentResult{p, res})
	}
	out.Root = hexHash(out.tree.Root())
	return out, nil
}

func verifyPath(p string, s *Schemas, each func(uint64, []byte, [sha256.Size]byte)) (Result, error) {
	f, err := os.Open(p)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	return verifyFrom(f, false, s, Result{Head: Genesis}, 0, each)
}
