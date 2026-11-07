// Package pins detects tool definitions that change after they were trusted
// (a "rug pull": a server shows a harmless description, then swaps in one
// that carries injected instructions or a wider schema).
//
// The first definition seen for each tool is pinned by its SHA-256 (trust on
// first use). If the upstream later serves a different definition, the tool
// is quarantined: hidden from agents and refused, until an administrator
// approves the new definition by its exact hash. Pins are persisted in a
// wal stream, one fsynced record per change and compacted into a snapshot
// as it grows, so a restart does not reset trust.
package pins

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/agents/jsonrpc"
	"github.com/laiwf94/authz/internal/platform/storage/wal"
)

// Errors.
var (
	ErrNotFound    = errors.New("pins: no such tool")
	ErrNoChange    = errors.New("pins: tool is not quarantined")
	ErrHashChanged = errors.New("pins: the quarantined definition has a different hash; review it again")
)

// Pin records the trusted definition of one tool and any pending change.
type Pin struct {
	Tool       string          `json:"tool"`
	Hash       string          `json:"hash"`
	Definition json.RawMessage `json:"definition"`
	FirstSeen  time.Time       `json:"first_seen"`
	ApprovedAt time.Time       `json:"approved_at"`
	ApprovedBy string          `json:"approved_by"` // "first-use" or "admin"

	PendingHash       string          `json:"pending_hash,omitempty"`
	PendingDefinition json.RawMessage `json:"pending_definition,omitempty"`
	ChangedAt         time.Time       `json:"changed_at,omitzero"`
}

// Quarantined reports whether the upstream's current definition differs from
// the trusted one.
func (p Pin) Quarantined() bool { return p.PendingHash != "" }

// Hash returns the hex SHA-256 of a canonical tool definition.
func Hash(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// Store holds pins. It is safe for concurrent use.
type Store struct {
	mu   sync.Mutex
	pins map[string]*Pin
	path string // empty: memory only
	now  func() time.Time

	log   *wal.Stream[Pin] // nil when memory only
	ident os.FileInfo      // the log's file, as last opened or replaced
	// resync is set after a write failed: the file may lack state the
	// store holds in memory, so the next write rewrites it whole.
	resync bool
}

// The pin log is a wal stream at the store's path: one record per change,
// each the whole pin after it, so the last record for a tool wins on replay.
// Records are written compact and without HTML escaping, so each definition
// is stored as the exact bytes its hash covers.
type codec struct{}

func (codec) Marshal(p Pin) ([]byte, error) { return jsonrpc.Marshal(p) }

func (codec) Unmarshal(b []byte) (Pin, error) { return wal.JSON[Pin]{Strict: true}.Unmarshal(b) }

// maxRecord bounds one pin record: two tool definitions and their hashes.
const maxRecord = 4 << 20

// compactAfter is the smallest log, in records, that is compacted; above it
// a log is rewritten once it holds four records per tool.
const compactAfter = 256

func valid(p Pin) error {
	if p.Tool == "" || p.Hash != Hash(p.Definition) || p.PendingHash != "" && p.PendingHash != Hash(p.PendingDefinition) {
		return errors.New("an entry's hash does not match its definition")
	}
	return nil
}

// Open loads pins from path, or starts empty if the file does not exist. An
// empty path keeps pins in memory only.
//
// The file is a wal stream. A file in the old format, one JSON array written
// whole on every change, is read and converted in place on first open.
func Open(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	s := &Store{pins: map[string]*Pin{}, path: path, now: now}
	if path == "" {
		return s, nil
	}
	legacy, err := readLegacy(path)
	if err != nil {
		return nil, err
	}
	if legacy != nil {
		// Convert first and open after, so a failed conversion leaves
		// the old file as it was.
		if err := convert(path, legacy); err != nil {
			return nil, fmt.Errorf("pins: converting %s: %w", path, err)
		}
	}
	opts := wal.Options[Pin]{Codec: codec{}, Sync: wal.SyncAlways, MaxRecord: maxRecord, Validate: valid}
	s.log, err = wal.Open(path, opts, func(p Pin) error {
		s.pins[p.Tool] = &p
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("pins: %s is damaged: %w", path, err)
	}
	if s.ident, err = os.Stat(path); err != nil {
		s.log.Close()
		return nil, fmt.Errorf("pins: %w", err)
	}
	return s, nil
}

// readLegacy returns the pins of an old-format file, nil for a wal stream or
// a missing or empty file, and an error for a file that is neither.
func readLegacy(path string) ([]*Pin, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pins: %w", err)
	}
	defer f.Close()
	head := make([]byte, 9)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("pins: %w", err)
	}
	head = head[:n]
	if n > 0 && head[0] == '[' {
		data, err := io.ReadAll(io.MultiReader(bytes.NewReader(head), f))
		if err != nil {
			return nil, fmt.Errorf("pins: %w", err)
		}
		var list []*Pin
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&list); err != nil {
			return nil, fmt.Errorf("pins: %s is damaged: %w", path, err)
		}
		for _, p := range list {
			if p == nil || valid(*p) != nil {
				return nil, fmt.Errorf("pins: %s has an entry whose hash does not match its definition", path)
			}
		}
		if list == nil {
			list = []*Pin{}
		}
		return list, nil
	}
	// A wal stream starts with eight hex digits and a space. A crash can
	// tear the first record, but never into anything else.
	for i, c := range head {
		if i < 8 && !isHex(c) || i == 8 && c != ' ' {
			return nil, fmt.Errorf("pins: %s is damaged: neither a pin log nor an old pin file", path)
		}
	}
	return nil, nil
}

// convert replaces an old-format file with a pin log of the same pins: a
// temporary file, fsynced, renamed over the old one, and the directory
// fsynced.
func convert(path string, list []*Pin) error {
	recs := make([]Pin, len(list))
	for i, p := range list {
		recs[i] = *p
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Tool < recs[j].Tool })
	data, err := wal.Encode[Pin](codec{}, maxRecord, recs...)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := createTemp(dir, ".pins-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Hooks for fault injection in tests.
var (
	createTemp = os.CreateTemp
	rename     = os.Rename
)

func isHex(c byte) bool { return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' }

// Close closes the pin log. A memory-only store has nothing to close.
func (s *Store) Close() error {
	if s.log == nil {
		return nil
	}
	return s.log.Close()
}

// Observe records the definition an upstream currently serves for tool and
// reports whether the tool may be used. New tools are trusted on first use.
// A failure to persist a new pin is returned, and the tool must then not be
// used.
func (s *Store) Observe(tool string, canonical []byte) (trusted bool, newlyQuarantined bool, err error) {
	h := Hash(canonical)
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pins[tool]
	now := s.now().UTC()
	switch {
	case !ok:
		p = &Pin{Tool: tool, Hash: h, Definition: bytes.Clone(canonical), FirstSeen: now, ApprovedAt: now, ApprovedBy: "first-use"}
		s.pins[tool] = p
		if err := s.writeLocked(p); err != nil {
			delete(s.pins, tool)
			return false, false, err
		}
		return true, false, nil
	case p.Hash == h:
		if p.PendingHash != "" {
			// The upstream went back to the trusted definition.
			old := *p
			p.PendingHash, p.PendingDefinition, p.ChangedAt = "", nil, time.Time{}
			if err := s.writeLocked(p); err != nil {
				*p = old
				return false, false, err
			}
		}
		return true, false, nil
	case p.PendingHash == h:
		return false, false, nil
	default:
		p.PendingHash, p.PendingDefinition, p.ChangedAt = h, bytes.Clone(canonical), now
		// Quarantine holds in memory even if persisting fails; the next
		// observation retries the write.
		return false, true, s.writeLocked(p)
	}
}

// Approve trusts the quarantined definition of tool. hash must be the hash
// the administrator reviewed, so a definition that changed again in the
// meantime is not approved by accident.
func (s *Store) Approve(tool, hash string) (Pin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pins[tool]
	if !ok {
		return Pin{}, ErrNotFound
	}
	if p.PendingHash == "" {
		return *p, ErrNoChange
	}
	if p.PendingHash != hash {
		return *p, ErrHashChanged
	}
	old := *p
	p.Hash, p.Definition = p.PendingHash, p.PendingDefinition
	p.PendingHash, p.PendingDefinition, p.ChangedAt = "", nil, time.Time{}
	p.ApprovedAt, p.ApprovedBy = s.now().UTC(), "admin"
	if err := s.writeLocked(p); err != nil {
		*p = old
		return old, err
	}
	return *p, nil
}

// Trusted reports whether hash is the trusted definition of tool and no
// different definition is waiting for review.
func (s *Store) Trusted(tool, hash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pins[tool]
	return ok && p.Hash == hash && p.PendingHash == ""
}

// Get returns one pin.
func (s *Store) Get(tool string) (Pin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pins[tool]
	if !ok {
		return Pin{}, false
	}
	return *p, true
}

// List returns every pin, sorted by tool.
func (s *Store) List() []Pin {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Pin, 0, len(s.pins))
	for _, p := range s.pins {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

// QuarantinedCount returns the number of quarantined tools.
func (s *Store) QuarantinedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.pins {
		if p.Quarantined() {
			n++
		}
	}
	return n
}

// writeLocked makes p, the new state of one tool, durable. It appends one
// record, or rewrites the whole log when a previous write failed or the
// file at the store's path is no longer the one the log appends to (removed
// or replaced while the gateway ran, where appends would be lost).
func (s *Store) writeLocked(p *Pin) error {
	if s.log == nil {
		return nil
	}
	cur, err := os.Stat(s.path)
	if s.resync || err != nil || !os.SameFile(cur, s.ident) {
		return s.snapshotLocked()
	}
	if err := s.log.Append(*p); err != nil {
		s.resync = true
		return fmt.Errorf("pins: %w", err)
	}
	if n := s.log.Records(); n > compactAfter && n > 4*len(s.pins) {
		// The record is durable already; a failed compaction only
		// means the next write tries again.
		_ = s.snapshotLocked()
	}
	return nil
}

// snapshotLocked rewrites the log as one record per tool, atomically.
func (s *Store) snapshotLocked() error {
	list := make([]Pin, 0, len(s.pins))
	for _, p := range s.pins {
		list = append(list, *p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Tool < list[j].Tool })
	err := s.log.Replace(list)
	if err == nil {
		s.ident, err = os.Stat(s.path)
	}
	if err != nil {
		s.resync = true
		return fmt.Errorf("pins: %w", err)
	}
	s.resync = false
	return nil
}
