package keys

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Static keys are bearer credentials that are not signed: long random
// strings an agent presents as is. Only their SHA-256 digests are kept, so
// neither the configuration nor the static key file holds a secret.
//
// Two kinds of static key are merged into one key set:
//
//   - Configured keys: the digests the agents configuration lists, one per
//     agent. The file never copies them; it records only that one was
//     revoked, or rotated and verifies until a time, keyed by its digest,
//     so a revoked configured key stays revoked across restarts and
//     configuration reloads until the operator lists another digest.
//   - Issued keys: created or rotated in through the admin API, held in the
//     file with their agent, creation time and, once rotated, the end of
//     their overlap.
//
// Every change names the key set version it was computed against and fails
// with ErrVersion when another change came first (compare and set), so two
// administrators never undo each other. A change is saved to the file
// before it takes effect, and the file is replaced atomically, so a crash
// leaves either the old key set or the new one.

// StaticFileVersion is the static key file format version.
const StaticFileVersion = 1

// Static key limits.
const (
	// MaxStaticKeys bounds the issued keys and the recorded revocations
	// of a static key file, each.
	MaxStaticKeys = 1024
	// MaxStaticKeysPerAgent bounds the issued keys one agent holds at
	// once, the ones still inside a rotation overlap included.
	MaxStaticKeysPerAgent = 16
	// MaxStaticOverlap is the longest a rotated key keeps verifying.
	MaxStaticOverlap = 7 * 24 * time.Hour
	maxStaticAgent   = 128
)

// Static key sources.
const (
	StaticConfig = "config" // listed in the agents configuration
	StaticIssued = "issued" // created through the admin API
)

// Errors returned by static key changes.
var (
	// ErrVersion is returned when a change names a key set version that is
	// no longer current. Read the key set again and retry.
	ErrVersion = errors.New("keys: the static key set changed since that version")
	// ErrStaticLimit is returned when a change would exceed a limit.
	ErrStaticLimit = errors.New("keys: too many static keys")
)

// StaticKeyID is the id of the static key with digest sum: the first eight
// bytes of the digest in hex. It names the key in the admin API, logs and
// audit records without revealing anything that helps guess the key.
func StaticKeyID(sum [sha256.Size]byte) string { return hex.EncodeToString(sum[:8]) }

// ConfigKey is a static key the agents configuration lists.
type ConfigKey struct {
	Agent  string
	SHA256 [sha256.Size]byte
}

// StaticKey is one static key of the merged key set.
type StaticKey struct {
	ID      string            `json:"id"`
	Agent   string            `json:"agent"`
	Source  string            `json:"source"` // StaticConfig or StaticIssued
	SHA256  [sha256.Size]byte `json:"-"`
	Created time.Time         `json:"created,omitzero"` // issued keys
	// Until is when a rotated key stops verifying; zero means until it is
	// revoked or rotated.
	Until time.Time `json:"until,omitzero"`
}

// revocation is a configured key's recorded end: it verifies until Until,
// and never once Until is zero or past.
type revocation struct {
	Agent   string
	SHA256  [sha256.Size]byte
	Revoked time.Time
	Until   time.Time
}

type staticState struct {
	version uint64
	issued  []StaticKey // in creation order
	revoked []revocation
	bySum   map[[sha256.Size]byte]int // into issued
	revSum  map[[sha256.Size]byte]int // into revoked
}

func newStaticState(version uint64, issued []StaticKey, revoked []revocation) *staticState {
	s := &staticState{version: version, issued: issued, revoked: revoked,
		bySum: make(map[[sha256.Size]byte]int, len(issued)), revSum: make(map[[sha256.Size]byte]int, len(revoked))}
	for i, k := range issued {
		s.bySum[k.SHA256] = i
	}
	for i, r := range revoked {
		s.revSum[r.SHA256] = i
	}
	return s
}

// StaticStore is the static key file of one process. Lookups are
// lock-free; changes are serialized. It is safe for concurrent use.
type StaticStore struct {
	path string

	mu    sync.Mutex        // serializes changes
	sum   [sha256.Size]byte // of the bytes last read or written; zero while the file does not exist
	state atomic.Pointer[staticState]
}

// OpenStatic reads the static key file at path, or starts an empty key set
// when there is none yet; the file is written by the first change. An
// empty path keeps the key set in memory: issued keys and revocations are
// lost on restart.
func OpenStatic(path string) (*StaticStore, error) {
	s := &StaticStore{path: path}
	s.state.Store(newStaticState(0, nil, nil))
	if path == "" {
		return s, nil
	}
	removeStaleTemps(path)
	b, err := readLimited(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	st, err := unmarshalStatic(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.state.Store(st)
	s.sum = sha256.Sum256(b)
	return s, nil
}

// Path returns the file's path, empty for a key set kept in memory.
func (s *StaticStore) Path() string { return s.path }

// Version returns the key set version: 0 before the first change, then one
// more for every change.
func (s *StaticStore) Version() uint64 { return s.state.Load().version }

// Issued returns the agent and key id of the issued key with digest sum
// when it verifies at now.
func (s *StaticStore) Issued(sum [sha256.Size]byte, now time.Time) (agent, id string, ok bool) {
	st := s.state.Load()
	i, found := st.bySum[sum]
	if !found {
		return "", "", false
	}
	k := st.issued[i]
	if !k.Until.IsZero() && !now.Before(k.Until) {
		return "", "", false
	}
	return k.Agent, k.ID, true
}

// ConfigActive reports whether the configured key with digest sum still
// verifies at now: it was never revoked, or it was rotated and its overlap
// has not ended.
func (s *StaticStore) ConfigActive(sum [sha256.Size]byte, now time.Time) bool {
	st := s.state.Load()
	i, found := st.revSum[sum]
	if !found {
		return true
	}
	u := st.revoked[i].Until
	return !u.IsZero() && now.Before(u)
}

// List returns the version and the keys that verify at now: the
// configured keys of cfg first, in its order, then the issued keys, oldest
// first.
func (s *StaticStore) List(cfg []ConfigKey, now time.Time) (uint64, []StaticKey) {
	st := s.state.Load()
	return st.version, st.list(cfg, now)
}

func (st *staticState) list(cfg []ConfigKey, now time.Time) []StaticKey {
	out := make([]StaticKey, 0, len(cfg)+len(st.issued))
	for _, c := range cfg {
		k := StaticKey{ID: StaticKeyID(c.SHA256), Agent: c.Agent, Source: StaticConfig, SHA256: c.SHA256}
		if i, found := st.revSum[c.SHA256]; found {
			r := st.revoked[i]
			if r.Until.IsZero() || !now.Before(r.Until) {
				continue
			}
			k.Until = r.Until
		}
		out = append(out, k)
	}
	for _, k := range st.issued {
		if k.Until.IsZero() || now.Before(k.Until) {
			out = append(out, k)
		}
	}
	return out
}

// find returns the key with id that verifies at now.
func (st *staticState) find(cfg []ConfigKey, id string, now time.Time) (StaticKey, bool) {
	for _, k := range st.list(cfg, now) {
		if k.ID == id {
			return k, true
		}
	}
	return StaticKey{}, false
}

// Create issues a key for agent with digest sum, against key set version
// ifVersion. cfg is the configured keys, which a new key may not repeat.
// It returns the key and the new version.
func (s *StaticStore) Create(ifVersion uint64, cfg []ConfigKey, agent string, sum [sha256.Size]byte, now time.Time) (StaticKey, uint64, error) {
	if err := checkStaticAgent(agent); err != nil {
		return StaticKey{}, 0, err
	}
	var k StaticKey
	v, err := s.change(ifVersion, now, func(st *staticState, issued []StaticKey, revoked []revocation) ([]StaticKey, []revocation, error) {
		if err := st.fresh(cfg, sum); err != nil {
			return nil, nil, err
		}
		k = StaticKey{ID: StaticKeyID(sum), Agent: agent, Source: StaticIssued, SHA256: sum, Created: now.UTC()}
		issued, err := addIssued(issued, k, now)
		return issued, revoked, err
	})
	return k, v, err
}

// Rotate replaces the key id with a new key for the same agent with
// digest sum, against key set version ifVersion. The old key keeps
// verifying for overlap (at most MaxStaticOverlap; zero ends it at once).
// It returns the old key, with its new Until, the new key and the new
// version.
func (s *StaticStore) Rotate(ifVersion uint64, cfg []ConfigKey, id string, sum [sha256.Size]byte, overlap time.Duration, now time.Time) (old, key StaticKey, version uint64, err error) {
	if overlap < 0 || overlap > MaxStaticOverlap {
		return old, key, 0, fmt.Errorf("keys: a rotation overlap must be from 0 to %s", MaxStaticOverlap)
	}
	version, err = s.change(ifVersion, now, func(st *staticState, issued []StaticKey, revoked []revocation) ([]StaticKey, []revocation, error) {
		var found bool
		if old, found = st.find(cfg, id, now); !found {
			return nil, nil, ErrNotFound
		}
		if err := st.fresh(cfg, sum); err != nil {
			return nil, nil, err
		}
		until := now.Add(overlap).UTC()
		if overlap == 0 {
			until = now.UTC()
		}
		// A key already inside an overlap keeps the earlier end.
		if !old.Until.IsZero() && old.Until.Before(until) {
			until = old.Until
		}
		var err error
		if issued, revoked, err = st.end(issued, revoked, old, until, now); err != nil {
			return nil, nil, err
		}
		old.Until = until
		key = StaticKey{ID: StaticKeyID(sum), Agent: old.Agent, Source: StaticIssued, SHA256: sum, Created: now.UTC()}
		issued, err = addIssued(issued, key, now)
		return issued, revoked, err
	})
	if err != nil {
		return StaticKey{}, StaticKey{}, 0, err
	}
	return old, key, version, nil
}

// Revoke stops the key id from verifying at once, against key set version
// ifVersion, and returns it with the new version.
func (s *StaticStore) Revoke(ifVersion uint64, cfg []ConfigKey, id string, now time.Time) (StaticKey, uint64, error) {
	var k StaticKey
	v, err := s.change(ifVersion, now, func(st *staticState, issued []StaticKey, revoked []revocation) ([]StaticKey, []revocation, error) {
		var found bool
		if k, found = st.find(cfg, id, now); !found {
			return nil, nil, ErrNotFound
		}
		k.Until = now.UTC()
		return st.end(issued, revoked, k, time.Time{}, now)
	})
	return k, v, err
}

// end makes k stop verifying at until (zero: now, for good): an issued
// key gets the end, or goes, and a configured key gets a revocation.
func (st *staticState) end(issued []StaticKey, revoked []revocation, k StaticKey, until, now time.Time) ([]StaticKey, []revocation, error) {
	if k.Source == StaticIssued {
		i := slices.IndexFunc(issued, func(x StaticKey) bool { return x.SHA256 == k.SHA256 })
		if until.IsZero() || !now.Before(until) {
			return slices.Delete(issued, i, i+1), revoked, nil
		}
		issued[i].Until = until
		return issued, revoked, nil
	}
	r := revocation{Agent: k.Agent, SHA256: k.SHA256, Revoked: now.UTC(), Until: until}
	if !until.IsZero() && !now.Before(until) {
		r.Until = time.Time{}
	}
	if i := slices.IndexFunc(revoked, func(x revocation) bool { return x.SHA256 == k.SHA256 }); i >= 0 {
		revoked[i] = r
		return issued, revoked, nil
	}
	if len(revoked) >= MaxStaticKeys {
		return nil, nil, fmt.Errorf("%w: %d revoked configured keys are recorded; replace them in the configuration", ErrStaticLimit, len(revoked))
	}
	return issued, append(revoked, r), nil
}

// fresh refuses a digest the key set already holds, configured, issued or
// revoked, so a key is never issued twice or brought back.
func (st *staticState) fresh(cfg []ConfigKey, sum [sha256.Size]byte) error {
	_, issued := st.bySum[sum]
	_, revoked := st.revSum[sum]
	if issued || revoked || slices.ContainsFunc(cfg, func(c ConfigKey) bool { return c.SHA256 == sum }) {
		return errors.New("keys: that static key is already in use or was revoked")
	}
	return nil
}

func addIssued(issued []StaticKey, k StaticKey, now time.Time) ([]StaticKey, error) {
	if slices.ContainsFunc(issued, func(x StaticKey) bool { return x.ID == k.ID }) {
		return nil, errors.New("keys: a static key with that id exists; generate another key")
	}
	if len(issued) >= MaxStaticKeys {
		return nil, fmt.Errorf("%w: %d issued keys; revoke some first", ErrStaticLimit, len(issued))
	}
	n := 0
	for _, x := range issued {
		if x.Agent == k.Agent {
			n++
		}
	}
	if n >= MaxStaticKeysPerAgent {
		return nil, fmt.Errorf("%w: agent %s holds %d issued keys; revoke one first", ErrStaticLimit, k.Agent, n)
	}
	return append(issued, k), nil
}

// change applies fn to a copy of the key set, with issued keys whose
// overlap ended at now dropped, saves the result and only then puts it in
// force.
func (s *StaticStore) change(ifVersion uint64, now time.Time, fn func(*staticState, []StaticKey, []revocation) ([]StaticKey, []revocation, error)) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state.Load()
	if ifVersion != st.version {
		return st.version, fmt.Errorf("%w: it is at version %d, not %d", ErrVersion, st.version, ifVersion)
	}
	issued := make([]StaticKey, 0, len(st.issued)+1)
	for _, k := range st.issued {
		if k.Until.IsZero() || now.Before(k.Until) {
			issued = append(issued, k)
		}
	}
	revoked := slices.Clone(st.revoked)
	issued, revoked, err := fn(st, issued, revoked)
	if err != nil {
		return st.version, err
	}
	next := newStaticState(st.version+1, issued, revoked)
	if s.path != "" {
		if err := s.save(next); err != nil {
			return st.version, err
		}
	}
	s.state.Store(next)
	return next.version, nil
}

// save writes next to the file, refusing with ErrConflict when the file
// is no longer what this store last read or wrote.
func (s *StaticStore) save(next *staticState) error {
	cur, err := readLimited(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if s.sum != ([sha256.Size]byte{}) {
			return fmt.Errorf("%w (%s was removed)", ErrConflict, s.path)
		}
	case err != nil:
		return err
	case sha256.Sum256(cur) != s.sum:
		return fmt.Errorf("%w (%s)", ErrConflict, s.path)
	}
	b, err := marshalStatic(next)
	if err != nil {
		return err
	}
	if err := saveBytes(s.path, b); err != nil {
		return err
	}
	syncDir(filepath.Dir(s.path))
	s.sum = sha256.Sum256(b)
	return nil
}

// removeStaleTemps removes the temporary files of saves a killed process
// never renamed, so crashes don't pile them up next to the key file.
func removeStaleTemps(path string) {
	stale, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "."+globEscape(filepath.Base(path))+".*"))
	for _, p := range stale {
		_ = os.Remove(p)
	}
}

func globEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`).Replace(s)
}

// syncDir makes a rename in dir durable across a power loss. Failures are
// ignored: some file systems can't sync a directory, and the rename itself
// already happened.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

func checkStaticAgent(agent string) error {
	if agent == "" || len(agent) > maxStaticAgent || !utf8.ValidString(agent) ||
		strings.ContainsFunc(agent, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("keys: agent %q must be 1 to %d bytes of text", agent, maxStaticAgent)
	}
	return nil
}

type staticFileKey struct {
	Agent   string     `json:"agent"`
	SHA256  string     `json:"sha256"`
	Created time.Time  `json:"created"`
	Until   *time.Time `json:"until,omitempty"`
}

type staticFileRevocation struct {
	Agent   string     `json:"agent"`
	SHA256  string     `json:"sha256"`
	Revoked time.Time  `json:"revoked"`
	Until   *time.Time `json:"until,omitempty"`
}

type staticFile struct {
	Format  int                    `json:"format"`
	Version uint64                 `json:"version"`
	Issued  []staticFileKey        `json:"issued"`
	Revoked []staticFileRevocation `json:"revoked"`
}

func marshalStatic(st *staticState) ([]byte, error) {
	f := staticFile{Format: StaticFileVersion, Version: st.version,
		Issued: []staticFileKey{}, Revoked: []staticFileRevocation{}}
	opt := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		return &t
	}
	for _, k := range st.issued {
		f.Issued = append(f.Issued, staticFileKey{Agent: k.Agent, SHA256: hex.EncodeToString(k.SHA256[:]),
			Created: k.Created, Until: opt(k.Until)})
	}
	for _, r := range st.revoked {
		f.Revoked = append(f.Revoked, staticFileRevocation{Agent: r.Agent, SHA256: hex.EncodeToString(r.SHA256[:]),
			Revoked: r.Revoked, Until: opt(r.Until)})
	}
	b, err := json.MarshalIndent(f, "", "  ")
	return append(b, '\n'), err
}

func unmarshalStatic(b []byte) (*staticState, error) {
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("keys: static key file is larger than %d bytes", MaxFileBytes)
	}
	var f staticFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("keys: static key file: %w", err)
	}
	if dec.More() {
		return nil, errors.New("keys: static key file: data after the document")
	}
	if f.Format != StaticFileVersion {
		return nil, fmt.Errorf("keys: static key file format %d; this build reads %d", f.Format, StaticFileVersion)
	}
	if len(f.Issued) > MaxStaticKeys || len(f.Revoked) > MaxStaticKeys {
		return nil, fmt.Errorf("%w: the file holds more than %d keys or revocations", ErrStaticLimit, MaxStaticKeys)
	}
	seen := map[[sha256.Size]byte]bool{}
	ids := map[string]bool{}
	digest := func(what, v string) ([sha256.Size]byte, error) {
		var sum [sha256.Size]byte
		h, err := hex.DecodeString(v)
		if err != nil || len(h) != sha256.Size || hex.EncodeToString(h) != v {
			return sum, fmt.Errorf("keys: static key file: %s: sha256 must be 64 lower-case hex characters", what)
		}
		copy(sum[:], h)
		if seen[sum] {
			return sum, fmt.Errorf("keys: static key file: %s: digest %s appears twice", what, StaticKeyID(sum))
		}
		seen[sum] = true
		return sum, nil
	}
	val := func(t *time.Time) time.Time {
		if t == nil {
			return time.Time{}
		}
		return t.UTC()
	}
	perAgent := map[string]int{}
	issued := make([]StaticKey, 0, len(f.Issued))
	for i, fk := range f.Issued {
		what := fmt.Sprintf("issued[%d]", i)
		if err := checkStaticAgent(fk.Agent); err != nil {
			return nil, fmt.Errorf("keys: static key file: %s: %w", what, err)
		}
		sum, err := digest(what, fk.SHA256)
		if err != nil {
			return nil, err
		}
		id := StaticKeyID(sum)
		if ids[id] {
			return nil, fmt.Errorf("keys: static key file: %s: key id %s appears twice", what, id)
		}
		ids[id] = true
		if perAgent[fk.Agent]++; perAgent[fk.Agent] > MaxStaticKeysPerAgent {
			return nil, fmt.Errorf("%w: agent %s holds more than %d issued keys", ErrStaticLimit, fk.Agent, MaxStaticKeysPerAgent)
		}
		if fk.Created.IsZero() {
			return nil, fmt.Errorf("keys: static key file: %s: created is required", what)
		}
		issued = append(issued, StaticKey{ID: id, Agent: fk.Agent, Source: StaticIssued, SHA256: sum,
			Created: fk.Created.UTC(), Until: val(fk.Until)})
	}
	revoked := make([]revocation, 0, len(f.Revoked))
	for i, fr := range f.Revoked {
		what := fmt.Sprintf("revoked[%d]", i)
		if err := checkStaticAgent(fr.Agent); err != nil {
			return nil, fmt.Errorf("keys: static key file: %s: %w", what, err)
		}
		sum, err := digest(what, fr.SHA256)
		if err != nil {
			return nil, err
		}
		revoked = append(revoked, revocation{Agent: fr.Agent, SHA256: sum, Revoked: fr.Revoked.UTC(), Until: val(fr.Until)})
	}
	if f.Version == 0 && (len(issued) > 0 || len(revoked) > 0) {
		return nil, errors.New("keys: static key file: version 0 holds no keys")
	}
	return newStaticState(f.Version, issued, revoked), nil
}
