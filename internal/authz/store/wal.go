package store

import (
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"

	"github.com/laiwf94/authz/internal/platform/storage/wal"
)

// The write-ahead log is a stream of the platform's shared log
// (internal/platform/storage/wal) in <dir>/grantd.wal, one JSON record per
// line:
//
//	<crc32c of payload, 8 hex digits> <JSON payload>\n
//
// A record is durable once append returns (the stream fsyncs every append).
// A crash can leave a torn final line; recovery drops it, because its write
// was never acknowledged. A bad record anywhere else means the file is
// damaged and recovery stops instead of guessing.

const (
	walName       = "grantd.wal"
	recWrite      = "write"
	recSchema     = "schema"
	recCheckpoint = "checkpoint"
	maxRecordSize = 512 << 20
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// ErrCorrupt means the log is damaged somewhere other than its last record.
var ErrCorrupt = wal.ErrCorrupt

type walRecord struct {
	Rev     Revision       `json:"rev"`
	Type    string         `json:"type"`
	Changes []Change       `json:"changes,omitempty"`
	Schema  string         `json:"schema,omitempty"`
	Rels    []Relationship `json:"rels,omitempty"`
}

var walOptions = wal.Options[walRecord]{Sync: wal.SyncAlways, MaxRecord: maxRecordSize}

// walLog is the store's stream; f is the open stream.
type walLog struct {
	f *wal.Stream[walRecord]
}

func encodeRecord(rec walRecord) ([]byte, error) {
	return wal.Encode[walRecord](wal.JSON[walRecord]{}, maxRecordSize, rec)
}

func decodeRecord(line []byte) (walRecord, error) {
	return wal.Decode[walRecord](wal.JSON[walRecord]{}, line)
}

// openWAL replays the log in dir through apply, drops a torn tail, and opens
// it for appending.
func openWAL(dir string, apply func(walRecord) error) (*walLog, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := wal.Open(filepath.Join(dir, walName), walOptions, apply)
	if err != nil {
		return nil, err
	}
	return &walLog{f: f}, nil
}

func (w *walLog) append(rec walRecord) error {
	if err := w.f.Append(rec); err != nil {
		return fmt.Errorf("%w: write-ahead log: %v", ErrUnavailable, err)
	}
	return nil
}

// checkpoint atomically replaces the log with a single record holding the
// full current state.
func (w *walLog) checkpoint(head Revision, schemaSrc string, rels []Relationship) error {
	return w.f.Replace([]walRecord{{Rev: head, Type: recCheckpoint, Schema: schemaSrc, Rels: rels}})
}

func (w *walLog) close() error { return w.f.Close() }
