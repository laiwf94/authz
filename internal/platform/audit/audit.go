// Package audit writes the platform's tamper-evident, append-only log: what
// grantd (authz serve), wicket (authz gateway) and toolgate (authz mcp) did,
// in one hash chain.
//
// Each line is one JSON record:
//
//	{"seq":7,"time":"…","prev":"<sha256 of line 6>","event":"tool_call","data":{…}}
//
// A record may also carry the event envelope between "event" and "data":
// tenant, actor, subject, action, decision and correlation_id (see Envelope).
// Records written by Append, and every record of a toolgate log, have none, so
// those logs keep their exact bytes. "data" is the event's payload; each event
// type has a payload schema (see Schemas and the typed payloads in
// payloads.go), which Write and VerifyWith enforce.
//
// "prev" is the SHA-256 of the previous line's exact bytes (64 zeros for the
// first), so the records form a hash chain in the manner of Crosby and
// Wallach's tamper-evident logging and of Certificate Transparency. Changing,
// removing or reordering any line breaks the chain at the next line, and
// Verify names the line. The last line has no successor; to detect truncation
// or an edit of the newest record, compare the head hash with one stored
// elsewhere (the admin API serves it, and `authz mcp audit verify -head` checks
// it).
//
// Appends are durable before they return: the line is written and the file
// fsynced. Concurrent appends share fsyncs (group commit).
//
// Several processes may append to one file, so authz serve, gateway and mcp
// on one host can keep a single chain: point their audit log settings at the
// same path. Each append takes an exclusive flock on the file, first reads
// any records other writers added since its own last append (checking that
// they continue the chain), and writes its record after them. The lock is
// held for the write only; the fsync is shared as before. Opening takes the
// lock too, so a torn final line is only cut off when no live writer can be
// in the middle of it. On systems without flock (Windows) a log must have one
// writer.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/platform/logging"
)

// MaxLineBytes bounds one record.
const MaxLineBytes = 1 << 20

// Genesis is the "prev" of the first record.
var Genesis = strings.Repeat("0", 64)

// ErrBroken means an earlier write or fsync failed, so the file's state is
// unknown and nothing more will be appended.
var ErrBroken = errors.New("audit: log is unusable after a failed write; restart after checking the file")

// Record is one parsed line.
type Record struct {
	Seq   uint64 `json:"seq"`
	Time  string `json:"time"`
	Prev  string `json:"prev"`
	Event string `json:"event"`
	Envelope
	Data json.RawMessage `json:"data"`
}

type record struct {
	Seq   uint64 `json:"seq"`
	Time  string `json:"time"`
	Prev  string `json:"prev"`
	Event string `json:"event"`
	Envelope
	Data any `json:"data"`
}

// file is the part of *os.File the log uses; tests substitute failing ones.
type file interface {
	io.Writer
	Truncate(size int64) error
	Seek(offset int64, whence int) (int64, error)
	Sync() error
	Close() error
}

// Log appends records. It is safe for concurrent use.
type Log struct {
	mu     sync.Mutex // guards the fields below and the file offset
	f      file
	seq    uint64
	head   string
	size   int64
	broken bool
	now    func() time.Time
	sch    *Schemas // nil: payloads are not checked
	// osf is the file itself when other processes may share it: appends
	// lock it and read their records first. nil where flock is missing.
	osf *os.File

	syncMu sync.Mutex // serializes fsyncs
	synced int64      // file size known durable; guarded by syncMu
}

// Options configures OpenWith.
type Options struct {
	// Now stamps records; nil means time.Now.
	Now func() time.Time
	// Schemas, if set, is enforced on every append: the event type must be
	// registered and its envelope and payload must match. The records
	// already in the file are checked by the chain only; VerifyWith checks
	// their payloads.
	Schemas *Schemas
}

// Open opens or creates the log at path. An existing log is verified first; a
// torn final line (a write that was never acknowledged) is cut off, and any
// other damage stops the open with the line number.
func Open(path string, now func() time.Time) (*Log, error) {
	return OpenWith(path, Options{Now: now})
}

// OpenWith is Open with options.
func OpenWith(path string, o Options) (*Log, error) {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if canLock {
		if err := lockFile(f); err != nil {
			f.Close()
			return nil, fmt.Errorf("audit: locking %s: %w", path, err)
		}
		// Closing the file would drop the lock too, but the open's own
		// failures close it only after this returns.
		defer unlockFile(f)
	}
	res, err := verify(f, true, nil)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: %s failed verification: %w", path, err)
	}
	if res.TornBytes > 0 {
		if err := f.Truncate(res.Size); err != nil {
			f.Close()
			return nil, fmt.Errorf("audit: cutting a torn final line: %w", err)
		}
	}
	if _, err := f.Seek(res.Size, io.SeekStart); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: %w", err)
	}
	l := &Log{f: f, seq: res.Records, head: res.Head, size: res.Size, synced: res.Size, now: now, sch: o.Schemas}
	if canLock {
		l.osf = f
	}
	return l, nil
}

// Append writes one record without an envelope and returns once it is on
// disk. It is how toolgate wrote every record, byte for byte.
func (l *Log) Append(event string, data any) error {
	return l.AppendWith(event, Envelope{}, data)
}

// Write appends a typed payload under its event type with an envelope.
func (l *Log) Write(env Envelope, p Payload) error {
	if p == nil {
		return errors.New("audit: nil payload")
	}
	return l.AppendWith(p.AuditEvent(), env, p)
}

// AppendWith writes one record with an envelope and returns once it is on
// disk. The event type and envelope are checked, and with Options.Schemas
// so is the payload, before anything is written.
func (l *Log) AppendWith(event string, env Envelope, data any) error {
	if err := l.check(event, env, data); err != nil {
		return err
	}
	end, err := l.write(event, env, data)
	if err != nil {
		return err
	}
	return l.syncTo(end)
}

// WriteAll appends typed payloads in order, each under its envelope, and
// returns once all of them are on disk: one fsync covers them all, where
// Write would wait for one each. Every record is checked before any is
// written. Records of other appends may fall between them. On an error the
// records before the failing one may have been written.
func (l *Log) WriteAll(envs []Envelope, ps []Payload) error {
	if len(envs) != len(ps) {
		return errors.New("audit: WriteAll needs one envelope per payload")
	}
	for i, p := range ps {
		if p == nil {
			return errors.New("audit: nil payload")
		}
		if err := l.check(p.AuditEvent(), envs[i], p); err != nil {
			return err
		}
	}
	var end int64
	for i, p := range ps {
		e, err := l.write(p.AuditEvent(), envs[i], p)
		if err != nil {
			return err
		}
		end = e
	}
	if len(ps) == 0 {
		return nil
	}
	return l.syncTo(end)
}

// check refuses a record before anything is written: a bad event type or
// envelope, and with Options.Schemas a payload that does not match.
func (l *Log) check(event string, env Envelope, data any) error {
	if err := checkEvent(event); err != nil {
		return err
	}
	if err := env.Check(); err != nil {
		return err
	}
	if l.sch != nil {
		raw, err := marshal(data)
		if err != nil {
			return fmt.Errorf("audit: encoding %s payload: %w", event, err)
		}
		if err := l.sch.Check(event, env, raw); err != nil {
			return err
		}
	}
	return nil
}

// write appends the record under the log's mutex and, for a shared file,
// its flock, and returns the file offset the record ends at. Both are
// released before the fsync, so appends from this process and others share
// it.
func (l *Log) write(event string, env Envelope, data any) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken {
		return 0, ErrBroken
	}
	if l.osf != nil {
		if err := lockFile(l.osf); err != nil {
			// Without the lock another writer may be mid-line, so the end
			// of the file is unknown (a closed file ends up here too).
			l.broken = true
			return 0, fmt.Errorf("audit: lock: %v: %w", err, ErrBroken)
		}
		defer unlockFile(l.osf)
		if err := l.catchUp(); err != nil {
			return 0, err
		}
	}
	line, err := marshal(record{Seq: l.seq + 1, Time: l.now().UTC().Format(time.RFC3339Nano),
		Prev: l.head, Event: event, Envelope: env, Data: data})
	if err != nil {
		return 0, fmt.Errorf("audit: encoding record: %w", err)
	}
	if len(line)+1 > MaxLineBytes {
		return 0, fmt.Errorf("audit: record is larger than %d bytes", MaxLineBytes)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		// Cut off whatever part was written so the chain stays valid; if that
		// fails too, the end of the file is unknown and appends must stop.
		if terr := l.f.Truncate(l.size); terr != nil {
			l.broken = true
		} else if _, serr := l.f.Seek(l.size, io.SeekStart); serr != nil {
			l.broken = true
		}
		return 0, fmt.Errorf("audit: write: %w", err)
	}
	sum := sha256.Sum256(line)
	l.seq++
	l.head = hex.EncodeToString(sum[:])
	l.size += int64(len(line)) + 1
	// Under the lock, so watchers see records in chain order.
	logging.Observe(logging.SourceAudit, line)
	return l.size, nil
}

// catchUp takes in the records other writers appended to a shared file
// since this writer's last append, so the next record follows them. The
// caller holds the flock, so no live writer is mid-line: a torn final line
// is one a writer that died never acknowledged, and is cut off as Open
// does. Records that do not continue the chain make the log unusable, like
// a failed write.
func (l *Log) catchUp() error {
	fi, err := l.osf.Stat()
	if err != nil {
		l.broken = true
		return fmt.Errorf("audit: %v: %w", err, ErrBroken)
	}
	size := fi.Size()
	if size == l.size {
		return nil
	}
	if size < l.size {
		l.broken = true
		return fmt.Errorf("audit: the file shrank from %d to %d bytes under this writer: %w", l.size, size, ErrBroken)
	}
	start := Result{Records: l.seq, Head: l.head, Size: l.size}
	res, err := verifyFrom(io.NewSectionReader(l.osf, l.size, size-l.size), true, nil, start)
	if err != nil {
		l.broken = true
		return fmt.Errorf("audit: records another writer appended do not verify: %v: %w", err, ErrBroken)
	}
	if res.TornBytes > 0 {
		if err := l.f.Truncate(res.Size); err != nil {
			l.broken = true
			return fmt.Errorf("audit: cutting a torn final line: %v: %w", err, ErrBroken)
		}
	}
	if _, err := l.f.Seek(res.Size, io.SeekStart); err != nil {
		l.broken = true
		return fmt.Errorf("audit: %v: %w", err, ErrBroken)
	}
	l.seq, l.head, l.size = res.Records, res.Head, res.Size
	return nil
}

// syncTo returns once the file is durable up to offset end. Whoever holds
// syncMu fsyncs everything written so far, covering every append that was
// waiting behind it.
func (l *Log) syncTo(end int64) error {
	l.syncMu.Lock()
	defer l.syncMu.Unlock()
	if l.synced >= end {
		return nil
	}
	l.mu.Lock()
	target, broken := l.size, l.broken
	l.mu.Unlock()
	if broken {
		return ErrBroken
	}
	if err := l.f.Sync(); err != nil {
		// After a failed fsync the page cache can no longer be trusted to
		// reach the disk, so stop rather than retry (as PostgreSQL does).
		l.mu.Lock()
		l.broken = true
		l.mu.Unlock()
		return fmt.Errorf("audit: fsync: %w", err)
	}
	l.synced = target
	return nil
}

// Head returns the number of records and the hash of the last one. For a
// shared file it first reads the records other writers appended, so the
// head is the file's, as "authz mcp audit verify -head" expects.
func (l *Log) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.osf != nil && !l.broken {
		// A failure leaves the head as this writer last knew it, and
		// marks the log broken like a failed append would.
		if lockFile(l.osf) == nil {
			_ = l.catchUp()
			unlockFile(l.osf)
		}
	}
	return l.seq, l.head
}

// Healthy reports whether appends can still succeed.
func (l *Log) Healthy() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.broken
}

// Close closes the file.
func (l *Log) Close() error { return l.f.Close() }

// Result summarizes a verified log.
type Result struct {
	Records   uint64
	Head      string // hash of the last record, or Genesis for an empty log
	Size      int64  // bytes of complete, verified records
	TornBytes int64  // bytes of an incomplete final line (only with allowTorn)
}

// LineError locates a verification failure.
type LineError struct {
	Line int
	Msg  string
}

func (e *LineError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

// Verify reads a whole log and checks every link of the chain.
func Verify(r io.Reader) (Result, error) { return verify(r, false, nil) }

// VerifyWith is Verify that also checks every record's envelope and payload
// against s: an unregistered event type or a payload that does not match its
// schema fails on that record's line.
func VerifyWith(r io.Reader, s *Schemas) (Result, error) {
	if s == nil {
		return Result{}, errors.New("audit: VerifyWith needs schemas")
	}
	return verify(r, false, s)
}

func verify(r io.Reader, allowTorn bool, s *Schemas) (Result, error) {
	return verifyFrom(r, allowTorn, s, Result{Head: Genesis})
}

// verifyFrom verifies records that continue the chain res describes: r
// starts at byte res.Size, after res.Records records ending in res.Head.
// Line numbers in errors count from the start of the file.
func verifyFrom(r io.Reader, allowTorn bool, s *Schemas, res Result) (Result, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	for n := int(res.Records) + 1; ; n++ {
		line, err := readLine(br)
		if err == io.EOF {
			return res, nil
		}
		if err == errTorn {
			if allowTorn {
				res.TornBytes = int64(len(line))
				return res, nil
			}
			return res, &LineError{n, "incomplete final line (no newline)"}
		}
		if err != nil {
			return res, &LineError{n, err.Error()}
		}
		var rec Record
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil || dec.More() {
			return res, &LineError{n, "not a valid record; it was modified or damaged"}
		}
		if rec.Prev != res.Head {
			if n == 1 {
				return res, &LineError{n, "first record does not start the chain (records before it were removed?)"}
			}
			return res, &LineError{n - 1, fmt.Sprintf("record does not match the hash stored in line %d: it was modified, removed or reordered", n)}
		}
		if rec.Seq != res.Records+1 {
			return res, &LineError{n, fmt.Sprintf("sequence %d, expected %d: records were removed or reordered", rec.Seq, res.Records+1)}
		}
		if s != nil {
			if err := s.Check(rec.Event, rec.Envelope, rec.Data); err != nil {
				return res, &LineError{n, err.Error()}
			}
		}
		sum := sha256.Sum256(line)
		res.Head = hex.EncodeToString(sum[:])
		res.Records++
		res.Size += int64(len(line)) + 1
	}
}

var errTorn = errors.New("torn line")

// readLine returns one line without its newline, errTorn (with the partial
// bytes) when the input ends mid-line, or an error for over-long lines.
func readLine(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > MaxLineBytes {
			return nil, fmt.Errorf("line longer than %d bytes", MaxLineBytes)
		}
		switch err {
		case nil:
			return buf[:len(buf)-1], nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			if len(buf) == 0 {
				return nil, io.EOF
			}
			return buf, errTorn
		default:
			return nil, err
		}
	}
}

// marshal encodes v as compact JSON without HTML escaping, the encoding
// toolgate's records were written with.
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
