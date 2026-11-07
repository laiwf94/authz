// Package approval parks tool calls that need a human decision.
//
// An approval is bound to one agent, one tool and one exact argument hash, and
// is used up by the first call it lets through. A grant therefore cannot be
// replayed, moved to another agent, or stretched to cover different
// arguments. Requests and grants expire, and the store holds a bounded number
// of them.
//
// A store made by New keeps everything in memory. One made by Open also
// keeps it in a wal stream, so pending requests, decisions and unused grants
// survive a restart, and a grant used up before a crash stays used up: the
// record of its use is fsynced before Consume lets the call run.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/platform/storage/wal"
)

// Status of a request.
type Status string

// Statuses.
const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Denied   Status = "denied"
)

// Outcome tells the caller what to do with the call.
type Outcome int

// Outcomes.
const (
	OutcomePending Outcome = iota + 1 // not decided yet
	OutcomeOpened                     // not decided yet; this call opened the request
	OutcomeProceed                    // approved; call Consume just before running the call
	OutcomeDenied                     // a human said no
)

// Errors.
var (
	ErrNotFound   = errors.New("approval: no such request")
	ErrNotPending = errors.New("approval: request is no longer pending")
	ErrTooMany    = errors.New("approval: too many open requests")
	// ErrUnavailable wraps a failure to write the approval log; the
	// operation did not happen.
	ErrUnavailable = errors.New("approval: the approval log cannot be written")
)

// Binding identifies exactly what is being approved.
type Binding struct {
	AgentID   string
	Owner     string
	Tool      string          // namespaced tool name
	ArgsHash  string          // hex SHA-256 of the canonical arguments
	Arguments json.RawMessage // canonical arguments, shown to the approver
	RuleID    string          // the policy rule that required approval
}

func (b Binding) key() string { return b.AgentID + "\x00" + b.Tool + "\x00" + b.ArgsHash }

// Request is a snapshot of an approval request.
type Request struct {
	ID        string          `json:"id"`
	Status    Status          `json:"status"`
	AgentID   string          `json:"agent_id"`
	Owner     string          `json:"owner,omitempty"`
	Tool      string          `json:"tool"`
	ArgsHash  string          `json:"arguments_sha256"`
	Arguments json.RawMessage `json:"arguments"`
	RuleID    string          `json:"rule_id"`
	CreatedAt time.Time       `json:"created_at"`
	// ExpiresAt is when a pending request lapses, when an approval stops
	// being usable, or when a denial is forgotten.
	ExpiresAt time.Time `json:"expires_at"`
	DecidedAt time.Time `json:"decided_at,omitzero"`
	Note      string    `json:"note,omitempty"`
}

type entry struct {
	Request
	key  string
	done chan struct{} // closed when decided
}

// Config sets the store's limits.
type Config struct {
	PendingTTL     time.Duration // how long a request waits for a decision
	MaxGrantTTL    time.Duration // longest an approval stays usable
	MaxOpen        int           // requests and unused grants, in total
	MaxOpenByAgent int
	Now            func() time.Time
}

// Store holds requests. It is safe for concurrent use.
type Store struct {
	mu        sync.Mutex
	cfg       Config
	byID      map[string]*entry
	byBinding map[string]*entry

	log *wal.Stream[record] // nil for a memory-only store
	// resync is set after a failed write: the log may disagree with
	// memory, so the next write replaces it with a snapshot.
	resync bool
}

// record is one change in the approval log: a request as it now stands
// ("put", for an opened or a decided request), or a grant used up ("used").
type record struct {
	Op      string   `json:"op"`
	Request *Request `json:"request,omitempty"`
	ID      string   `json:"id,omitempty"`
}

const (
	opPut  = "put"
	opUsed = "used"
)

func validRecord(r record) error {
	switch {
	case r.Op == opPut && r.Request != nil && r.Request.ID != "" && r.ID == "" &&
		(r.Request.Status == Pending || r.Request.Status == Approved || r.Request.Status == Denied):
		return nil
	case r.Op == opUsed && r.Request == nil && r.ID != "":
		return nil
	}
	return errors.New("not an approval record")
}

// maxRecord bounds one record. Arguments are canonical tool arguments,
// which the gateway already caps far below this.
const maxRecord = 4 << 20

// compactAfter is the smallest log, in records, that is compacted; above it
// a log is rewritten once it holds four records per live request.
const compactAfter = 256

// New returns an empty store that keeps nothing on disk, filling in
// defaults for zero limits.
func New(cfg Config) *Store {
	if cfg.PendingTTL <= 0 {
		cfg.PendingTTL = 10 * time.Minute
	}
	if cfg.MaxGrantTTL <= 0 {
		cfg.MaxGrantTTL = time.Hour
	}
	if cfg.MaxOpen <= 0 {
		cfg.MaxOpen = 1024
	}
	if cfg.MaxOpenByAgent <= 0 {
		cfg.MaxOpenByAgent = 16
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Store{cfg: cfg, byID: map[string]*entry{}, byBinding: map[string]*entry{}}
}

// Open returns a store kept in the wal stream at path, creating the file if
// it is missing. Requests that expired while the store was closed are
// dropped; the rest come back as they were, decided ones included.
//
// Opening a request is written without an fsync, since losing one to a power
// cut only means the agent asks again. A decision and the use of a grant are
// fsynced before they take effect, and that fsync also covers every record
// before them.
func Open(path string, cfg Config) (*Store, error) { return open(path, cfg, nil) }

// open is Open with the stream's OpenFile, for fault injection in tests.
func open(path string, cfg Config, openFile func(string, int) (wal.File, error)) (*Store, error) {
	s := New(cfg)
	opts := wal.Options[record]{Codec: wal.JSON[record]{Strict: true}, Sync: wal.SyncNever,
		MaxRecord: maxRecord, Validate: validRecord, OpenFile: openFile}
	l, err := wal.Open(path, opts, s.replay)
	if err != nil {
		return nil, fmt.Errorf("approval: %w", err)
	}
	s.log = l
	s.sweepLocked(s.cfg.Now())
	return s, nil
}

// replay applies one record from the log.
func (s *Store) replay(r record) error {
	if r.Op == opUsed {
		if e, ok := s.byID[r.ID]; ok {
			s.removeLocked(e)
		}
		return nil
	}
	q := *r.Request
	e := &entry{Request: q, key: Binding{AgentID: q.AgentID, Tool: q.Tool, ArgsHash: q.ArgsHash}.key(), done: make(chan struct{})}
	if old, ok := s.byID[q.ID]; ok {
		s.removeLocked(old)
	}
	if q.Status != Pending {
		close(e.done)
	}
	s.byID[e.ID] = e
	s.byBinding[e.key] = e
	return nil
}

// Close closes the approval log. A memory-only store has nothing to close.
func (s *Store) Close() error {
	if s.log == nil {
		return nil
	}
	return s.log.Close()
}

// writeLocked makes r part of the log, fsynced when durable is set. It
// writes a snapshot instead when an earlier write failed.
func (s *Store) writeLocked(r record, durable bool) error {
	if s.log == nil {
		return nil
	}
	if s.resync {
		return s.snapshotLocked()
	}
	var err error
	if durable {
		err = s.log.AppendSync(r)
	} else {
		err = s.log.Append(r)
	}
	if err != nil {
		s.resync = true
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if n := s.log.Records(); n > compactAfter && n > 4*len(s.byID) {
		// r is in the log already; a failed compaction only means the
		// next write tries again.
		_ = s.snapshotLocked()
	}
	return nil
}

// snapshotLocked replaces the log with the live requests, oldest first. The
// replacement is fsynced, so it is durable whatever the record it stands in
// for asked.
func (s *Store) snapshotLocked() error {
	s.sweepLocked(s.cfg.Now())
	recs := make([]record, 0, len(s.byID))
	for _, e := range s.byID {
		q := e.Request
		recs = append(recs, record{Op: opPut, Request: &q})
	}
	sort.Slice(recs, func(i, j int) bool { return less(*recs[i].Request, *recs[j].Request) })
	if err := s.log.Replace(recs); err != nil {
		s.resync = true
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	s.resync = false
	return nil
}

func less(a, b Request) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	return a.ID < b.ID
}

// MaxGrantTTL is the longest grant Decide accepts.
func (s *Store) MaxGrantTTL() time.Duration { return s.cfg.MaxGrantTTL }

func (s *Store) removeLocked(e *entry) {
	delete(s.byID, e.ID)
	if s.byBinding[e.key] == e {
		delete(s.byBinding, e.key)
	}
}

// sweepLocked forgets every entry past its expiry.
func (s *Store) sweepLocked(now time.Time) {
	for _, e := range s.byID {
		if !now.Before(e.ExpiresAt) {
			s.removeLocked(e)
		}
	}
}

// Begin looks up the binding. An unused approval is reported
// (OutcomeProceed) but not used up: the caller consumes it with Consume once
// nothing else can stop the call, so a call refused later (quota, a busy
// upstream) does not waste a human's approval. A recent denial is reported;
// otherwise the existing pending request is returned (OutcomePending), or a
// new one is opened (OutcomeOpened).
func (s *Store) Begin(b Binding) (Request, Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	s.sweepLocked(now)
	if e, ok := s.byBinding[b.key()]; ok {
		switch e.Status {
		case Approved:
			return e.Request, OutcomeProceed, nil
		case Denied:
			return e.Request, OutcomeDenied, nil
		default:
			return e.Request, OutcomePending, nil
		}
	}
	if len(s.byID) >= s.cfg.MaxOpen {
		return Request{}, 0, ErrTooMany
	}
	n := 0
	for _, e := range s.byID {
		if e.AgentID == b.AgentID {
			n++
		}
	}
	if n >= s.cfg.MaxOpenByAgent {
		return Request{}, 0, ErrTooMany
	}
	e := &entry{key: b.key(), done: make(chan struct{}), Request: Request{
		ID: "apr_" + rand.Text(), Status: Pending, AgentID: b.AgentID, Owner: b.Owner, Tool: b.Tool,
		ArgsHash: b.ArgsHash, Arguments: b.Arguments, RuleID: b.RuleID,
		CreatedAt: now, ExpiresAt: now.Add(s.cfg.PendingTTL)}}
	s.byID[e.ID] = e
	s.byBinding[e.key] = e
	q := e.Request
	if err := s.writeLocked(record{Op: opPut, Request: &q}, false); err != nil {
		s.removeLocked(e)
		return Request{}, 0, err
	}
	return e.Request, OutcomeOpened, nil
}

// Wait blocks until request id is decided, maxWait passes or ctx ends.
func (s *Store) Wait(ctx context.Context, id string, maxWait time.Duration) Outcome {
	s.mu.Lock()
	e, ok := s.byID[id]
	s.mu.Unlock()
	if !ok {
		return OutcomePending
	}
	t := time.NewTimer(maxWait)
	defer t.Stop()
	select {
	case <-e.done:
	case <-t.C:
		return OutcomePending
	case <-ctx.Done():
		return OutcomePending
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case e.Status == Denied:
		return OutcomeDenied
	case s.byID[id] == e && s.cfg.Now().Before(e.ExpiresAt):
		return OutcomeProceed
	default:
		return OutcomePending // another call consumed the grant, or it lapsed
	}
}

// Consume uses up approval id. It succeeds for exactly one caller, and only
// while the approval is unexpired; the call may run only if it returns true.
// With a log, the use is fsynced first. If that fails the grant is still
// used up, without the call running: no crash can make it usable twice.
func (s *Store) Consume(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok || e.Status != Approved || !s.cfg.Now().Before(e.ExpiresAt) {
		return false
	}
	s.removeLocked(e)
	return s.writeLocked(record{Op: opUsed, ID: id}, true) == nil
}

// Decide approves or denies a pending request. An approval stays usable for
// ttl (capped at MaxGrantTTL); a denial is remembered for the pending TTL so
// that retries of the same call are refused without asking again.
func (s *Store) Decide(id string, approve bool, ttl time.Duration, note string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	s.sweepLocked(now)
	e, ok := s.byID[id]
	if !ok {
		return Request{}, ErrNotFound
	}
	if e.Status != Pending {
		return e.Request, ErrNotPending
	}
	old := e.Request
	e.DecidedAt, e.Note = now, note
	if approve {
		ttl = min(max(ttl, time.Second), s.cfg.MaxGrantTTL)
		e.Status, e.ExpiresAt = Approved, now.Add(ttl)
	} else {
		e.Status, e.ExpiresAt = Denied, now.Add(s.cfg.PendingTTL)
	}
	q := e.Request
	if err := s.writeLocked(record{Op: opPut, Request: &q}, true); err != nil {
		e.Request = old
		return old, err
	}
	close(e.done)
	return e.Request, nil
}

// Get returns one request.
func (s *Store) Get(id string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.cfg.Now())
	e, ok := s.byID[id]
	if !ok {
		return Request{}, false
	}
	return e.Request, true
}

// List returns every live request, oldest first.
func (s *Store) List() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.cfg.Now())
	out := make([]Request, 0, len(s.byID))
	for _, e := range s.byID {
		out = append(out, e.Request)
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

// PendingCount returns the number of requests awaiting a decision.
func (s *Store) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	now := s.cfg.Now()
	for _, e := range s.byID {
		if e.Status == Pending && now.Before(e.ExpiresAt) {
			n++
		}
	}
	return n
}
