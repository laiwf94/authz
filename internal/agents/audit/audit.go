// Package audit writes a tamper-evident, append-only log of what agents did.
//
// Each line is one JSON record:
//
//	{"seq":7,"time":"…","prev":"<sha256 of line 6>","event":"tool_call","data":{…}}
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

	"github.com/laiwf94/authz/internal/agents/jsonrpc"
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
	Seq   uint64          `json:"seq"`
	Time  string          `json:"time"`
	Prev  string          `json:"prev"`
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

type record struct {
	Seq   uint64 `json:"seq"`
	Time  string `json:"time"`
	Prev  string `json:"prev"`
	Event string `json:"event"`
	Data  any    `json:"data"`
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

	syncMu sync.Mutex // serializes fsyncs
	synced int64      // file size known durable; guarded by syncMu
}

// Open opens or creates the log at path. An existing log is verified first; a
// torn final line (a write that was never acknowledged) is cut off, and any
// other damage stops the open with the line number.
func Open(path string, now func() time.Time) (*Log, error) {
	if now == nil {
		now = time.Now
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	res, err := verify(f, true)
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
	return &Log{f: f, seq: res.Records, head: res.Head, size: res.Size, synced: res.Size, now: now}, nil
}

// Append writes one record and returns once it is on disk.
func (l *Log) Append(event string, data any) error {
	l.mu.Lock()
	if l.broken {
		l.mu.Unlock()
		return ErrBroken
	}
	line, err := jsonrpc.Marshal(record{Seq: l.seq + 1, Time: l.now().UTC().Format(time.RFC3339Nano),
		Prev: l.head, Event: event, Data: data})
	if err != nil {
		l.mu.Unlock()
		return fmt.Errorf("audit: encoding record: %w", err)
	}
	if len(line)+1 > MaxLineBytes {
		l.mu.Unlock()
		return fmt.Errorf("audit: record is larger than %d bytes", MaxLineBytes)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		// Cut off whatever part was written so the chain stays valid; if that
		// fails too, the end of the file is unknown and appends must stop.
		if terr := l.f.Truncate(l.size); terr != nil {
			l.broken = true
		} else if _, serr := l.f.Seek(l.size, io.SeekStart); serr != nil {
			l.broken = true
		}
		l.mu.Unlock()
		return fmt.Errorf("audit: write: %w", err)
	}
	sum := sha256.Sum256(line)
	l.seq++
	l.head = hex.EncodeToString(sum[:])
	l.size += int64(len(line)) + 1
	end := l.size
	l.mu.Unlock()
	return l.syncTo(end)
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

// Head returns the number of records and the hash of the last one.
func (l *Log) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
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
func Verify(r io.Reader) (Result, error) { return verify(r, false) }

func verify(r io.Reader, allowTorn bool) (Result, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	res := Result{Head: Genesis}
	for n := 1; ; n++ {
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
