package store

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
)

// The write-ahead log is a sequence of lines:
//
//	<crc32c of payload, 8 hex digits> <JSON payload>\n
//
// A record is durable once append returns (the file is fsynced). A crash can
// leave a torn final line; recovery drops it, because its write was never
// acknowledged. A bad record anywhere else means the file is damaged and
// recovery stops instead of guessing.

const (
	walName       = "grantd.wal"
	recWrite      = "write"
	recSchema     = "schema"
	recCheckpoint = "checkpoint"
	maxRecordSize = 512 << 20
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// ErrCorrupt means the log is damaged somewhere other than its last record.
var ErrCorrupt = errors.New("write-ahead log is corrupt")

type walRecord struct {
	Rev     Revision       `json:"rev"`
	Type    string         `json:"type"`
	Changes []Change       `json:"changes,omitempty"`
	Schema  string         `json:"schema,omitempty"`
	Rels    []Relationship `json:"rels,omitempty"`
}

type wal struct {
	mu     sync.Mutex
	dir    string
	f      *os.File
	size   int64
	broken error // set when the file may hold a partial record we could not remove
}

func encodeRecord(rec walRecord) ([]byte, error) {
	payload, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	line := make([]byte, 0, len(payload)+10)
	var sum [4]byte
	c := crc32.Checksum(payload, crcTable)
	sum[0], sum[1], sum[2], sum[3] = byte(c>>24), byte(c>>16), byte(c>>8), byte(c)
	line = hex.AppendEncode(line, sum[:])
	line = append(line, ' ')
	line = append(line, payload...)
	return append(line, '\n'), nil
}

func decodeRecord(line []byte) (walRecord, error) {
	var rec walRecord
	if len(line) < 10 || line[8] != ' ' {
		return rec, errors.New("malformed record")
	}
	var sum [4]byte
	if _, err := hex.Decode(sum[:], line[:8]); err != nil {
		return rec, errors.New("malformed checksum")
	}
	payload := line[9:]
	want := uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])
	if crc32.Checksum(payload, crcTable) != want {
		return rec, errors.New("checksum mismatch")
	}
	if err := json.Unmarshal(payload, &rec); err != nil {
		return rec, fmt.Errorf("bad payload: %v", err)
	}
	return rec, nil
}

// openWAL replays the log in dir through apply, drops a torn tail, and opens
// the file for appending.
func openWAL(dir string, apply func(walRecord) error) (*wal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, walName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	good, err := replayFile(f, apply)
	if err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Truncate(good); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(good, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return &wal{dir: dir, f: f, size: good}, nil
}

// replayFile applies every intact record and returns the offset where the
// intact prefix ends.
func replayFile(r io.Reader, apply func(walRecord) error) (int64, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	var offset int64
	for {
		line, err := br.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			// No trailing newline: a torn final write. Drop it.
			return offset, nil
		}
		if err != nil {
			return 0, err
		}
		if len(line) > maxRecordSize {
			return 0, fmt.Errorf("%w: record at offset %d is too large", ErrCorrupt, offset)
		}
		rec, derr := decodeRecord(bytes.TrimSuffix(line, []byte{'\n'}))
		if derr != nil {
			// Damaged record: fine if it is the last thing in the file.
			if _, perr := br.Peek(1); errors.Is(perr, io.EOF) {
				return offset, nil
			}
			return 0, fmt.Errorf("%w: record at offset %d: %v", ErrCorrupt, offset, derr)
		}
		if err := apply(rec); err != nil {
			return 0, fmt.Errorf("%w: record at offset %d: %v", ErrCorrupt, offset, err)
		}
		offset += int64(len(line))
	}
}

func (w *wal) append(rec walRecord) error {
	line, err := encodeRecord(rec)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.broken != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, w.broken)
	}
	if _, err := w.f.Write(line); err != nil {
		return w.rollback(err)
	}
	if err := w.f.Sync(); err != nil {
		return w.rollback(err)
	}
	w.size += int64(len(line))
	return nil
}

// rollback removes a partially written record so the log stays a clean
// sequence of records. If that is impossible, the log refuses further writes
// rather than appending after garbage.
func (w *wal) rollback(cause error) error {
	if err := w.f.Truncate(w.size); err != nil {
		w.broken = fmt.Errorf("could not remove a partial record after %v: %v", cause, err)
		return fmt.Errorf("%w: %v", ErrUnavailable, w.broken)
	}
	if _, err := w.f.Seek(w.size, io.SeekStart); err != nil {
		w.broken = err
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return fmt.Errorf("%w: write-ahead log: %v", ErrUnavailable, cause)
}

// checkpoint atomically replaces the log with a single record holding the
// full current state.
func (w *wal) checkpoint(head Revision, schemaSrc string, rels []Relationship) error {
	line, err := encodeRecord(walRecord{Rev: head, Type: recCheckpoint, Schema: schemaSrc, Rels: rels})
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	tmpPath := filepath.Join(w.dir, walName+".tmp")
	tmp, err := os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := tmp.Write(line); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(w.dir, walName)); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := syncDir(w.dir); err != nil {
		tmp.Close()
		return err
	}
	w.f.Close()
	w.f = tmp
	w.size = int64(len(line))
	_, err = w.f.Seek(w.size, io.SeekStart)
	return err
}

func (w *wal) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
