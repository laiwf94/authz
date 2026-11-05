// Package wal is the platform's one append-only log: a typed stream of
// checksummed records in a single file, used by every track for state that
// must survive a crash (relationships, sessions, pins and approvals).
//
// A stream file is a sequence of lines:
//
//	<crc32c of payload, 8 hex digits> <payload>\n
//
// the framing grantd's write-ahead log and wicket's session log already used,
// so their existing files open unchanged. The payload is one encoded record
// (JSON unless the stream has its own codec) and never contains a newline.
//
// Recovery replays every intact record in order. A crash can leave a torn
// final line; it is dropped, because its write was never acknowledged. A bad
// record anywhere else means the file is damaged, and Open stops with
// ErrCorrupt instead of guessing. Every append is all or nothing: a failed
// write is truncated away, and if even that fails the stream refuses further
// appends rather than writing after garbage.
//
// Each stream has its own fsync policy: SyncAlways makes a record durable
// before Append returns, SyncInterval fsyncs in the background at a fixed
// interval, and SyncNever leaves it to explicit Sync calls and Close. Replace
// atomically swaps the whole file for a snapshot (write a temporary file,
// fsync, rename, fsync the directory), which is how callers compact.
package wal

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultMaxRecord bounds one framed line when Options.MaxRecord is zero.
const DefaultMaxRecord = 16 << 20

// DefaultInterval is the SyncInterval period when Options.Interval is zero.
const DefaultInterval = time.Second

// frameOverhead is the checksum, the space and the newline around a payload.
const frameOverhead = 10

// readChunk is the reader buffer; longer lines are assembled from chunks, so
// a large MaxRecord costs nothing until a record that large shows up.
const readChunk = 64 << 10

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

var (
	// ErrCorrupt means the stream is damaged somewhere other than its last
	// record, or a record failed to apply.
	ErrCorrupt = errors.New("write-ahead log is corrupt")
	// ErrUnavailable means the stream refuses appends: a partial record
	// could not be removed, or an acknowledged record may not have reached
	// the disk. Replace with the caller's full state heals it.
	ErrUnavailable = errors.New("write-ahead log unavailable")
	// ErrClosed is returned by operations on a closed stream.
	ErrClosed = errors.New("write-ahead log is closed")
	// ErrTooLarge means a record's frame would exceed the stream's MaxRecord.
	ErrTooLarge = errors.New("record too large")
)

// SyncPolicy says when appended records are fsynced.
type SyncPolicy int

const (
	// SyncAlways fsyncs before Append returns: an acknowledged record
	// survives a power cut. A failed fsync rolls the append back.
	SyncAlways SyncPolicy = iota
	// SyncInterval fsyncs in the background every Options.Interval when
	// there are unsynced records. A crash can lose up to one interval.
	SyncInterval
	// SyncNever fsyncs only on Sync and Close; appends reach the operating
	// system and survive a process crash, not a power cut.
	SyncNever
)

func (p SyncPolicy) String() string {
	switch p {
	case SyncAlways:
		return "always"
	case SyncInterval:
		return "interval"
	case SyncNever:
		return "never"
	}
	return fmt.Sprintf("SyncPolicy(%d)", int(p))
}

// Codec turns records into payloads and back. A payload must not contain a
// newline.
type Codec[T any] interface {
	Marshal(T) ([]byte, error)
	Unmarshal([]byte) (T, error)
}

// JSON is the default codec. With Strict, unknown fields and trailing data
// are decoding errors.
type JSON[T any] struct{ Strict bool }

// Marshal encodes v as compact JSON, which never holds a raw newline.
func (JSON[T]) Marshal(v T) ([]byte, error) { return json.Marshal(v) }

// Unmarshal decodes one JSON value.
func (c JSON[T]) Unmarshal(b []byte) (T, error) {
	var v T
	if !c.Strict {
		err := json.Unmarshal(b, &v)
		return v, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return v, errors.New("trailing data after record")
	}
	return v, nil
}

// Options configures a stream. The zero value is a JSON stream that fsyncs
// every append.
type Options[T any] struct {
	Codec     Codec[T]      // nil means JSON[T]{}
	Sync      SyncPolicy    // when appends are fsynced
	Interval  time.Duration // SyncInterval period; 0 means DefaultInterval
	MaxRecord int           // largest framed line in bytes; 0 means DefaultMaxRecord
	// Validate checks a decoded record during replay. A record it rejects
	// counts as damage: dropped when it is the last line, ErrCorrupt
	// anywhere else. Errors from the apply function are always ErrCorrupt.
	Validate func(T) error
}

func (o Options[T]) codec() Codec[T] {
	if o.Codec == nil {
		return JSON[T]{}
	}
	return o.Codec
}

func (o Options[T]) maxRecord() int {
	if o.MaxRecord <= 0 {
		return DefaultMaxRecord
	}
	return o.MaxRecord
}

// file is the part of *os.File a stream uses, so tests can inject faults.
type file interface {
	io.Reader
	io.Writer
	io.Seeker
	Sync() error
	Truncate(int64) error
	Close() error
}

// Hooks for fault injection in tests.
var (
	openFile = func(path string, flag int) (file, error) { return os.OpenFile(path, flag, 0o600) }
	rename   = os.Rename
	syncDir  = func(dir string) error {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
)

// Stream is an open log of records of type T. It is safe for concurrent use.
type Stream[T any] struct {
	path  string
	opts  Options[T]
	codec Codec[T]
	max   int

	mu      sync.Mutex
	f       file
	size    int64
	records int
	dirty   bool  // appended since the last fsync
	broken  error // set when appends must stop
	closed  bool

	stop     chan struct{} // closed to end the SyncInterval loop
	done     chan struct{}
	stopOnce sync.Once
}

// Open replays the stream at path through apply, drops a torn tail, and opens
// the file for appending, creating it when missing. A nil apply only
// validates.
func Open[T any](path string, opts Options[T], apply func(T) error) (*Stream[T], error) {
	f, err := openFile(path, os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	s := &Stream[T]{path: path, opts: opts, codec: opts.codec(), max: opts.maxRecord(), f: f}
	good, n, err := Scan(f, opts, apply)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	end, err := f.Seek(0, io.SeekEnd)
	if err == nil && end != good {
		// Drop the torn tail, durably, so a later append can't land
		// after it.
		if err = f.Truncate(good); err == nil {
			err = f.Sync()
		}
	}
	if err == nil {
		_, err = f.Seek(good, io.SeekStart)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	s.size, s.records = good, n
	if opts.Sync == SyncInterval {
		iv := opts.Interval
		if iv <= 0 {
			iv = DefaultInterval
		}
		s.stop, s.done = make(chan struct{}), make(chan struct{})
		go s.syncLoop(iv)
	}
	return s, nil
}

// Scan reads records from r and applies every intact one in order. It
// returns the offset where the intact prefix ends and how many records it
// holds. A torn or damaged final line is not an error; damage before the
// last line, an oversized line or an apply error is ErrCorrupt.
func Scan[T any](r io.Reader, opts Options[T], apply func(T) error) (int64, int, error) {
	codec, max := opts.codec(), opts.maxRecord()
	br := bufio.NewReaderSize(r, readChunk)
	var (
		offset int64
		n      int
		line   []byte
	)
	for {
		line = line[:0]
		var err error
		for {
			var chunk []byte
			chunk, err = br.ReadSlice('\n')
			line = append(line, chunk...)
			if len(line) > max {
				return 0, 0, fmt.Errorf("%w: record at offset %d is longer than %d bytes", ErrCorrupt, offset, max)
			}
			if !errors.Is(err, bufio.ErrBufferFull) {
				break
			}
		}
		if errors.Is(err, io.EOF) {
			// No trailing newline: a torn final write. Drop it.
			return offset, n, nil
		}
		if err != nil {
			return 0, 0, err
		}
		rec, derr := Decode(codec, line[:len(line)-1])
		if derr == nil && opts.Validate != nil {
			derr = opts.Validate(rec)
		}
		if derr != nil {
			// Damaged record: fine if it is the last thing in the file.
			if _, perr := br.Peek(1); errors.Is(perr, io.EOF) {
				return offset, n, nil
			}
			return 0, 0, fmt.Errorf("%w: record at offset %d: %v", ErrCorrupt, offset, derr)
		}
		if apply != nil {
			if err := apply(rec); err != nil {
				return 0, 0, fmt.Errorf("%w: record at offset %d: %v", ErrCorrupt, offset, err)
			}
		}
		offset += int64(len(line))
		n++
	}
}

// Frame appends one framed line holding payload to dst.
func Frame(dst, payload []byte) []byte {
	var sum [4]byte
	c := crc32.Checksum(payload, castagnoli)
	sum[0], sum[1], sum[2], sum[3] = byte(c>>24), byte(c>>16), byte(c>>8), byte(c)
	dst = hex.AppendEncode(dst, sum[:])
	dst = append(dst, ' ')
	dst = append(dst, payload...)
	return append(dst, '\n')
}

// Unframe checks one line (without its newline) and returns its payload.
func Unframe(line []byte) ([]byte, error) {
	if len(line) < frameOverhead || line[8] != ' ' {
		return nil, errors.New("malformed record")
	}
	var sum [4]byte
	if _, err := hex.Decode(sum[:], line[:8]); err != nil {
		return nil, errors.New("malformed checksum")
	}
	payload := line[9:]
	want := uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])
	if crc32.Checksum(payload, castagnoli) != want {
		return nil, errors.New("checksum mismatch")
	}
	return payload, nil
}

// Encode frames records with codec as the bytes Append would write.
func Encode[T any](codec Codec[T], max int, recs ...T) ([]byte, error) {
	var buf []byte
	for _, rec := range recs {
		payload, err := codec.Marshal(rec)
		if err != nil {
			return nil, err
		}
		if bytes.IndexByte(payload, '\n') >= 0 {
			return nil, errors.New("wal: encoded record contains a newline")
		}
		if len(payload)+frameOverhead > max {
			return nil, fmt.Errorf("%w: %d bytes framed, limit %d", ErrTooLarge, len(payload)+frameOverhead, max)
		}
		buf = Frame(buf, payload)
	}
	return buf, nil
}

// Decode checks one line (without its newline) and decodes its record.
func Decode[T any](codec Codec[T], line []byte) (T, error) {
	payload, err := Unframe(line)
	if err != nil {
		var zero T
		return zero, err
	}
	rec, err := codec.Unmarshal(payload)
	if err != nil {
		return rec, fmt.Errorf("bad payload: %v", err)
	}
	return rec, nil
}

// Append writes recs as one write. Under SyncAlways they are on disk when it
// returns. Nothing is written if any record fails to encode, and a failed
// write leaves the file as it was.
func (s *Stream[T]) Append(recs ...T) error {
	if len(recs) == 0 {
		return nil
	}
	b, err := Encode(s.codec, s.max, recs...)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	if _, err := s.f.Write(b); err != nil {
		return s.rollback(err)
	}
	if s.opts.Sync == SyncAlways {
		if err := s.f.Sync(); err != nil {
			return s.rollback(err)
		}
	} else {
		s.dirty = true
	}
	s.size += int64(len(b))
	s.records += len(recs)
	return nil
}

func (s *Stream[T]) usable() error {
	if s.closed {
		return ErrClosed
	}
	if s.broken != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, s.broken)
	}
	return nil
}

// rollback removes a partially written append so the file stays a clean
// sequence of records. If that is impossible the stream refuses further
// appends rather than writing after garbage.
func (s *Stream[T]) rollback(cause error) error {
	if err := s.f.Truncate(s.size); err != nil {
		s.broken = fmt.Errorf("could not remove a partial record after %v: %v", cause, err)
		return fmt.Errorf("%w: %v", ErrUnavailable, s.broken)
	}
	if _, err := s.f.Seek(s.size, io.SeekStart); err != nil {
		s.broken = fmt.Errorf("could not seek after removing a partial record: %v", err)
		return fmt.Errorf("%w: %v", ErrUnavailable, s.broken)
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, cause)
}

// Sync fsyncs records appended since the last fsync. A failure means
// acknowledged records may be lost, so the stream stops taking appends.
func (s *Stream[T]) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	return s.syncLocked()
}

func (s *Stream[T]) syncLocked() error {
	if !s.dirty {
		return nil
	}
	if err := s.f.Sync(); err != nil {
		s.broken = fmt.Errorf("fsync: %v", err)
		return fmt.Errorf("%w: %v", ErrUnavailable, s.broken)
	}
	s.dirty = false
	return nil
}

func (s *Stream[T]) syncLoop(iv time.Duration) {
	defer close(s.done)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.mu.Lock()
			if s.broken == nil && !s.closed {
				_ = s.syncLocked() // a failure marks the stream broken
			}
			s.mu.Unlock()
		}
	}
}

// Replace atomically swaps the stream's contents for recs: a crash leaves
// either the old file or the new one, never a mix. It is how callers compact
// a stream into a snapshot of their state, and since that state holds only
// acknowledged records, it also heals a stream that stopped taking appends.
func (s *Stream[T]) Replace(recs []T) error {
	b, err := Encode(s.codec, s.max, recs...)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	tmpPath := s.path + ".tmp"
	tmp, err := openFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := rename(tmpPath, s.path); err != nil {
		return fail(err)
	}
	// The new file is the stream from here on, whatever happens next.
	s.f.Close()
	s.f, s.size, s.records, s.dirty, s.broken = tmp, int64(len(b)), len(recs), false, nil
	if err := syncDir(filepath.Dir(s.path)); err != nil {
		// The rename may not survive a power cut, so appends after it
		// could be lost with it.
		s.broken = fmt.Errorf("fsync directory after replace: %v", err)
		return fmt.Errorf("%w: %v", ErrUnavailable, s.broken)
	}
	return nil
}

// Close fsyncs unsynced records and closes the file. Closing twice is a
// no-op.
func (s *Stream[T]) Close() error {
	if s.stop != nil {
		s.stopOnce.Do(func() {
			close(s.stop)
			<-s.done
		})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.broken == nil {
		err = s.syncLocked()
	}
	if cerr := s.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Path returns the stream's file.
func (s *Stream[T]) Path() string { return s.path }

// Size returns the bytes of intact records in the file.
func (s *Stream[T]) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size
}

// Records returns how many records the file holds: those replayed at Open or
// written by Replace, plus every append since.
func (s *Stream[T]) Records() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records
}

// Err reports why the stream refuses appends, or nil.
func (s *Stream[T]) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, s.broken)
	}
	return nil
}
