package session

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"time"

	"github.com/laiwf94/authz/internal/platform/storage/wal"
)

// Log record operations.
const (
	opCreate = "create"
	opTouch  = "touch"
	opRevoke = "revoke"
)

// maxRecordBytes bounds one log line, so a damaged file can't make replay
// allocate without limit, and a record that large is refused before it is
// written.
const maxRecordBytes = 64 << 10

type record struct {
	Op      string    `json:"op"`
	Session *Session  `json:"session,omitempty"`
	ID      string    `json:"id,omitempty"`
	Time    time.Time `json:"t,omitzero"`
}

// castagnoli is the checksum table of the log's framing (CRC-32C, as in
// internal/platform/storage/wal).
var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// codec decodes strictly: an unknown field or trailing data is damage.
var codec = wal.JSON[record]{Strict: true}

// logOptions configures the session stream. Logins and revocations go
// through AppendSync; touches are plain appends and are not fsynced, since a
// lost touch only makes a session expire earlier.
func logOptions(open func(string, int) (wal.File, error)) wal.Options[record] {
	return wal.Options[record]{
		Codec:     codec,
		Sync:      wal.SyncNever,
		MaxRecord: maxRecordBytes,
		Validate:  validate,
		OpenFile:  open,
	}
}

// logFile is the append-only session log, a wal stream of records in the
// platform's framing
//
//	<crc32c of the JSON, 8 hex digits> <JSON record>\n
//
// so logs written before the move open unchanged. A torn last line is a
// write that was never acknowledged and is dropped; a bad line anywhere else
// is damage, and loading stops rather than guessing.
type logFile struct {
	path string
	s    *wal.Stream[record]
	// f is the stream's current file. The stream reaches it through a
	// handle, so f can be swapped under a running log (the write-failure
	// test swaps in a read-only file).
	f *os.File
	// next is the snapshot compact is writing, until the stream renames it
	// into place and closes f.
	next *handle
	// broken is why the log refuses writes: the stream stopped taking
	// appends (a partial record it could not remove, or a snapshot whose
	// rename may not be durable). Unlike the stream, the log is not healed
	// by a compaction; it stays refused until a restart replays the file.
	broken error
}

func openLog(path string) (*logFile, []*Session, error) {
	l := &logFile{path: path}
	var r replayer
	s, err := wal.Open(path, logOptions(l.openFile), r.apply)
	if err != nil {
		if errors.Is(err, wal.ErrCorrupt) {
			return nil, nil, fmt.Errorf("session log damaged: %w", err)
		}
		return nil, nil, fmt.Errorf("session log: %w", err)
	}
	l.s = s
	return l, r.sessions(), nil
}

// openFile is the stream's OpenFile: the log's own file becomes l.f behind a
// forwarding handle, and a snapshot's temporary file gets a handle of its own
// until it is promoted.
func (l *logFile) openFile(path string, flag int) (wal.File, error) {
	f, err := os.OpenFile(path, flag, 0o600)
	if err != nil {
		return nil, err
	}
	if path == l.path {
		l.f = f
		return &handle{l: l}, nil
	}
	h := &handle{l: l, own: f}
	l.next = h
	return h, nil
}

// handle is a file as the stream sees it. The live handle forwards to l.f; a
// snapshot's handle holds its own file until the stream, having renamed the
// snapshot over the log, closes the live handle, which makes the snapshot's
// file l.f and its handle the live one.
type handle struct {
	l   *logFile
	own *os.File // nil for the live handle
}

func (h *handle) file() *os.File {
	if h.own != nil {
		return h.own
	}
	return h.l.f
}

func (h *handle) Read(b []byte) (int, error)                { return h.file().Read(b) }
func (h *handle) Write(b []byte) (int, error)               { return h.file().Write(b) }
func (h *handle) Seek(off int64, whence int) (int64, error) { return h.file().Seek(off, whence) }
func (h *handle) Sync() error                               { return h.file().Sync() }
func (h *handle) Truncate(n int64) error                    { return h.file().Truncate(n) }

func (h *handle) Close() error {
	if h.own != nil {
		// A snapshot that never replaced the log.
		err := h.own.Close()
		h.own, h.l.next = nil, nil
		return err
	}
	err := h.l.f.Close()
	if n := h.l.next; n != nil {
		h.l.f, n.own, h.l.next = n.own, nil, nil
	}
	return err
}

// replayer applies records in order and keeps the sessions they leave.
type replayer struct {
	byID  map[string]*Session
	order []string
}

func (r *replayer) apply(rec record) error {
	if r.byID == nil {
		r.byID = map[string]*Session{}
	}
	switch rec.Op {
	case opCreate:
		if _, dup := r.byID[rec.Session.ID]; !dup {
			r.order = append(r.order, rec.Session.ID)
		}
		rec.Session.persistedSeen = rec.Session.LastSeen
		r.byID[rec.Session.ID] = rec.Session
	case opTouch:
		if s := r.byID[rec.ID]; s != nil && rec.Time.After(s.LastSeen) {
			s.LastSeen, s.persistedSeen = rec.Time, rec.Time
		}
	case opRevoke:
		delete(r.byID, rec.ID)
	}
	return nil
}

// sessions returns the live sessions in the order they were first created.
func (r *replayer) sessions() []*Session {
	out := make([]*Session, 0, len(r.byID))
	for _, id := range r.order {
		if s, ok := r.byID[id]; ok {
			out = append(out, s)
			delete(r.byID, id) // a re-created id appears once
		}
	}
	return out
}

// replay applies every record and returns the sessions, plus the offset of
// the end of the last good record.
func replay(rd io.Reader) ([]*Session, int64, error) {
	var r replayer
	good, _, err := wal.Scan(rd, logOptions(nil), r.apply)
	if err != nil {
		if errors.Is(err, wal.ErrCorrupt) {
			return nil, 0, fmt.Errorf("damaged log: %w", err)
		}
		return nil, 0, err
	}
	return r.sessions(), good, nil
}

// parseLine checks and decodes one framed line, newline included.
func parseLine(line []byte) (record, error) {
	rec, err := wal.Decode[record](codec, bytes.TrimSuffix(line, []byte("\n")))
	if err != nil {
		return rec, err
	}
	return rec, validate(rec)
}

func validate(rec record) error {
	switch rec.Op {
	case opCreate:
		if rec.Session == nil || len(rec.Session.ID) != 32 {
			return errors.New("create without a session")
		}
	case opTouch, opRevoke:
		if len(rec.ID) != 32 {
			return errors.New("record without an id")
		}
	default:
		return fmt.Errorf("unknown op %q", rec.Op)
	}
	return nil
}

func encode(recs []record) ([]byte, error) {
	return wal.Encode[record](codec, maxRecordBytes, recs...)
}

// append writes records as one write; with sync it fsyncs before returning.
// A failed write is rolled back. If that fails too the log refuses all
// further writes rather than appending after garbage.
func (l *logFile) append(sync bool, recs []record) error {
	if l.broken != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, l.broken)
	}
	var err error
	if sync {
		err = l.s.AppendSync(recs...)
	} else {
		err = l.s.Append(recs...)
	}
	if err != nil {
		l.broken = l.s.Err()
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return nil
}

// compact atomically replaces the log with one create record per live
// session.
func (l *logFile) compact(live []*Session) error {
	if l.broken != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, l.broken)
	}
	recs := make([]record, len(live))
	for i, s := range live {
		recs[i] = record{Op: opCreate, Session: s}
	}
	if err := l.s.Replace(recs); err != nil {
		l.broken = l.s.Err()
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return nil
}

// records is how many records the file holds.
func (l *logFile) records() int { return l.s.Records() }

func (l *logFile) close() error { return l.s.Close() }
