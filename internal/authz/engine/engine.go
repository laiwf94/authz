// Package engine is grantd's query and write API as a Go interface, shared
// by the HTTP handlers of authz serve and by in-process callers: the
// gateway and the MCP proxy ask the same engine in the same process, with
// no network hop, and the consistency tokens they get back are the same
// tokens the HTTP API issues and accepts.
//
// Local is the implementation over a store. The HTTP layer adds
// authentication, request parsing, timeouts and audit records on top of it;
// everything that decides an answer (which snapshot a read sees, how a
// token is checked, the limits on a request) lives here, so an in-process
// caller and an HTTP client asking the same question get the same answer
// at the same revision.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

// Engine answers permission queries and writes relationships. Every read
// names the snapshot it wants through a Consistency and reports the
// snapshot it used; every write reports the snapshot at which it is
// visible. Implementations are safe for concurrent use.
type Engine interface {
	// Check reports whether a subject has a permission on one object.
	Check(ctx context.Context, req CheckRequest) (CheckResult, error)
	// CheckBulk answers up to MaxBulkChecks checks at one snapshot. A check
	// that is invalid on its own (an unknown type, say) is answered with an
	// error in its result; an error that affects them all (the snapshot
	// expired, the store is unavailable, ctx ended) is returned instead.
	CheckBulk(ctx context.Context, req CheckBulkRequest) (CheckBulkResult, error)
	// LookupResources pages through the objects of a type on which a
	// subject has a permission, in ID order.
	LookupResources(ctx context.Context, req LookupResourcesRequest) (LookupResourcesResult, error)
	// Expand returns the userset tree of a permission on one object: who
	// holds it, through which relations and operators.
	Expand(ctx context.Context, req ExpandRequest) (ExpandResult, error)
	// LookupSubjects pages through the subjects of a type that hold a
	// permission on one object, in ID order, a wildcard first with the
	// IDs it leaves out.
	LookupSubjects(ctx context.Context, req LookupSubjectsRequest) (LookupSubjectsResult, error)
	// ReadRelationships pages through the stored relationships matching a
	// filter, in their text order.
	ReadRelationships(ctx context.Context, req ReadRequest) (ReadResult, error)
	// Write applies relationship updates atomically once every
	// precondition holds.
	Write(ctx context.Context, req WriteRequest) (WriteResult, error)
}

// Mode names how fresh a read's snapshot must be.
type Mode string

// Consistency modes. The zero Mode is MinimizeLatency.
const (
	// MinimizeLatency reads a recent snapshot that is shared between
	// requests for up to the engine's quantum, so repeated checks can be
	// served from the cache.
	MinimizeLatency Mode = "minimize_latency"
	// AtLeastAsFresh reads a snapshot no older than Token's.
	AtLeastAsFresh Mode = "at_least_as_fresh"
	// AtExactSnapshot reads exactly Token's snapshot.
	AtExactSnapshot Mode = "at_exact_snapshot"
	// FullyConsistent reads the newest committed revision.
	FullyConsistent Mode = "fully_consistent"
)

// Consistency picks the snapshot a read uses. Token is a consistency token
// from an earlier result (or from the HTTP API) and is used only with
// AtLeastAsFresh and AtExactSnapshot.
type Consistency struct {
	Mode  Mode   `json:"mode,omitempty"`
	Token string `json:"token,omitempty"`
}

// Snapshot is the revision a result was read at, or a write became visible
// at, with its consistency token.
type Snapshot struct {
	Revision store.Revision
	Token    string
}

// Request limits.
const (
	MaxBulkChecks = 100
	// DefaultQuantum is how long MinimizeLatency shares a snapshot when
	// Options.Quantum is zero.
	DefaultQuantum = 100 * time.Millisecond
	maxCursorBytes = 1024
)

// ErrInvalidArgument is matched (with errors.Is) by errors about a request
// that can never succeed as written: an unknown consistency mode, a token
// where none is used, a limit out of range. The error's text is the reason
// alone. Errors from the store and the check engine keep their own
// sentinels (store.ErrInvalid, check.ErrUnknownType, token.ErrInvalid...).
var ErrInvalidArgument = errors.New("invalid argument")

type argError string

func (e argError) Error() string        { return string(e) }
func (e argError) Is(target error) bool { return target == ErrInvalidArgument }

func invalid(format string, args ...any) error { return argError(fmt.Sprintf(format, args...)) }

// CheckRequest is one permission check. Subject may be a userset
// (group:eng#member).
type CheckRequest struct {
	ResourceType string
	ResourceID   string
	Permission   string // relation or permission name
	Subject      store.Subject
	Consistency  Consistency
}

// CheckResult answers a CheckRequest.
type CheckResult struct {
	Allowed bool
	At      Snapshot
}

// CheckItem is one check of a bulk request.
type CheckItem struct {
	ResourceType string
	ResourceID   string
	Permission   string
	Subject      store.Subject
}

// CheckBulkRequest is a set of checks answered at one snapshot.
type CheckBulkRequest struct {
	Items       []CheckItem
	Consistency Consistency
}

// CheckBulkResult answers a CheckBulkRequest: Results[i] answers Items[i].
type CheckBulkResult struct {
	Results []ItemResult
	At      Snapshot
}

// ItemResult is the answer to one check of a bulk request. Err is set,
// and Allowed false, when that check alone was invalid or too expensive.
type ItemResult struct {
	Allowed bool
	Err     error
}

// LookupResourcesRequest asks which objects of ResourceType Subject has
// Permission on. Cursor is the last ID of the previous page ("" to start);
// Limit is at most check.MaxLookupLimit, and 0 means
// check.DefaultLookupLimit.
type LookupResourcesRequest struct {
	ResourceType string
	Permission   string
	Subject      store.Subject
	Consistency  Consistency
	Cursor       string
	Limit        int
}

// LookupResourcesResult is one page of a lookup. Cursor continues it, and
// is "" when the scan is complete.
type LookupResourcesResult struct {
	ResourceIDs []string
	Cursor      string
	At          Snapshot
}

// ExpandRequest asks for the userset tree of Permission on
// ResourceType:ResourceID. Recursive expands every userset and arrow
// target the tree reaches; without it the tree stops at usersets, as
// Zanzibar's Expand does. MaxNodes is at most check.MaxTraceNodes, and 0
// means check.DefaultTraceNodes. check.Engine.Expand describes the tree.
type ExpandRequest struct {
	ResourceType string
	ResourceID   string
	Permission   string
	Recursive    bool
	MaxNodes     int
	Consistency  Consistency
}

// ExpandResult is the tree an ExpandRequest asked for. Tree.Truncated
// reports that it reached MaxNodes and is incomplete.
type ExpandResult struct {
	Tree *check.Trace
	At   Snapshot
}

// LookupSubjectsRequest asks which subjects of SubjectType (usersets of
// SubjectRelation, when it is set) hold Permission on
// ResourceType:ResourceID. Cursor is the last subject ID of the previous
// page ("" to start, check.Wildcard after a wildcard); Limit is at most
// check.MaxLookupLimit, and 0 means check.DefaultLookupLimit.
// check.Engine.LookupSubjects describes the answer.
type LookupSubjectsRequest struct {
	ResourceType    string
	ResourceID      string
	Permission      string
	SubjectType     string
	SubjectRelation string
	Consistency     Consistency
	Cursor          string
	Limit           int
}

// LookupSubjectsResult is one page of a subject lookup. Cursor continues
// it, and is "" when the list is complete.
type LookupSubjectsResult struct {
	Subjects []check.FoundSubject
	Cursor   string
	At       Snapshot
}

// ReadRequest pages through stored relationships. Limit is at most
// store.MaxReadLimit, and 0 means store.DefaultReadLimit.
type ReadRequest struct {
	Filter      store.Filter
	Consistency Consistency
	Cursor      string
	Limit       int
}

// ReadResult is one page of a read. Cursor continues it, and is "" when
// there are no more.
type ReadResult struct {
	Relationships []store.Relationship
	Cursor        string
	At            Snapshot
}

// WriteRequest is an atomic relationship write.
type WriteRequest struct {
	Updates       []store.Update
	Preconditions []store.Precondition
}

// WriteResult reports where a write is visible: reads at At, or with
// At.Token and AtLeastAsFresh, see it.
type WriteResult struct {
	At Snapshot
}

// Options configures a Local engine.
type Options struct {
	Store  *store.Store
	Tokens *token.Issuer
	// CacheSize is the number of check sub-results kept across requests;
	// 0 or less disables the cache.
	CacheSize int
	// Quantum is how stale MinimizeLatency reads may be; 0 means
	// DefaultQuantum. It is ignored when Snapshot is set.
	Quantum time.Duration
	// Snapshot, when set, is the revision MinimizeLatency reads use, in
	// place of the engine's own quantized head. It lets a server keep one
	// shared snapshot for its HTTP handlers and its in-process callers.
	Snapshot func() store.Revision
	// Metrics receives the check metrics (grantd_check_duration_seconds,
	// grantd_check_dispatches_total, grantd_check_cache_hits_total); nil
	// keeps them in a private registry.
	Metrics *metrics.Registry
}

// Local is the Engine over a store in this process. It is safe for
// concurrent use.
type Local struct {
	st       *store.Store
	tokens   *token.Issuer
	eng      *check.Engine
	snapshot func() store.Revision

	checkTime  *metrics.Histogram
	dispatches *metrics.Counter
	cacheHits  *metrics.Counter

	quantum  time.Duration
	snapMu   sync.Mutex
	snapRev  store.Revision
	snapTime time.Time
}

var _ Engine = (*Local)(nil)

// New returns a Local engine over opts.Store.
func New(opts Options) (*Local, error) {
	if opts.Store == nil || opts.Tokens == nil {
		return nil, errors.New("engine: store and token issuer are required")
	}
	m := opts.Metrics
	if m == nil {
		m = metrics.New()
	}
	e := &Local{st: opts.Store, tokens: opts.Tokens, eng: check.New(opts.Store, check.NewCache(opts.CacheSize)),
		snapshot: opts.Snapshot, quantum: opts.Quantum,
		checkTime:  m.Histogram("grantd_check_duration_seconds", "", "Time to evaluate one check."),
		dispatches: m.Counter("grantd_check_dispatches_total", "", "object#relation evaluations across all checks."),
		cacheHits:  m.Counter("grantd_check_cache_hits_total", "", "Check sub-results served from the cache."),
	}
	if e.quantum <= 0 {
		e.quantum = DefaultQuantum
	}
	if e.snapshot == nil {
		e.snapshot = e.quantizedHead
	}
	return e, nil
}

// Tokens returns the issuer that encodes and verifies the engine's
// consistency tokens.
func (e *Local) Tokens() *token.Issuer { return e.tokens }

func (e *Local) quantizedHead() store.Revision {
	e.snapMu.Lock()
	defer e.snapMu.Unlock()
	if time.Since(e.snapTime) >= e.quantum {
		e.snapRev, e.snapTime = e.st.Head(), time.Now()
	}
	return e.snapRev
}

// Resolve returns the snapshot c selects. It is what every read of the
// engine starts with; callers that read the store themselves (a watch, a
// schema read) use it to honour the same consistency rules.
func (e *Local) Resolve(c Consistency) (Snapshot, error) {
	rev, err := e.resolve(c)
	if err != nil {
		return Snapshot{}, err
	}
	return e.at(rev), nil
}

func (e *Local) at(rev store.Revision) Snapshot {
	return Snapshot{Revision: rev, Token: e.tokens.Encode(rev)}
}

func (e *Local) resolve(c Consistency) (store.Revision, error) {
	switch c.Mode {
	case "", MinimizeLatency:
		if c.Token != "" {
			return 0, invalid("consistency.token is only used with at_least_as_fresh or at_exact_snapshot")
		}
		return e.snapshot(), nil
	case FullyConsistent:
		if c.Token != "" {
			return 0, invalid("consistency.token is only used with at_least_as_fresh or at_exact_snapshot")
		}
		return e.st.Head(), nil
	case AtLeastAsFresh, AtExactSnapshot:
		if c.Token == "" {
			return 0, invalid("consistency mode %s needs a token", c.Mode)
		}
		rev, err := e.tokens.Decode(c.Token)
		if err != nil {
			return 0, err
		}
		head := e.st.Head()
		if rev > head {
			// A valid MAC with a future revision means the key is shared with a
			// store that has more history (e.g. restored from an old backup).
			return 0, invalid("token is from a newer revision than this server has")
		}
		if c.Mode == AtExactSnapshot {
			return rev, nil
		}
		if q := e.snapshot(); q >= rev {
			return q, nil
		}
		return head, nil
	default:
		return 0, invalid("unknown consistency mode %q", c.Mode)
	}
}

// run evaluates one check and records its metrics.
func (e *Local) run(ctx context.Context, sc *schema.Schema, rev store.Revision, q check.Request) (bool, error) {
	start := time.Now()
	ok, stats, err := e.eng.Check(ctx, sc, rev, q)
	e.checkTime.Observe(time.Since(start))
	e.dispatches.Add(uint64(stats.Dispatches))
	e.cacheHits.Add(uint64(stats.CacheHits))
	return ok, err
}

// Check implements Engine.
func (e *Local) Check(ctx context.Context, req CheckRequest) (CheckResult, error) {
	rev, err := e.resolve(req.Consistency)
	if err != nil {
		return CheckResult{}, err
	}
	sc, _ := e.st.Schema()
	ok, err := e.run(ctx, sc, rev, check.Request{ResourceType: req.ResourceType, ResourceID: req.ResourceID,
		Permission: req.Permission, Subject: req.Subject})
	if err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Allowed: ok, At: e.at(rev)}, nil
}

// CheckBulk implements Engine. An empty request resolves the snapshot and
// checks nothing.
func (e *Local) CheckBulk(ctx context.Context, req CheckBulkRequest) (CheckBulkResult, error) {
	if len(req.Items) > MaxBulkChecks {
		return CheckBulkResult{}, invalid("items must have between 1 and %d checks", MaxBulkChecks)
	}
	rev, err := e.resolve(req.Consistency)
	if err != nil {
		return CheckBulkResult{}, err
	}
	sc, _ := e.st.Schema()
	results := make([]ItemResult, len(req.Items))
	for i, it := range req.Items {
		ok, err := e.run(ctx, sc, rev, check.Request{ResourceType: it.ResourceType, ResourceID: it.ResourceID,
			Permission: it.Permission, Subject: it.Subject})
		if err != nil {
			if ctx.Err() != nil {
				return CheckBulkResult{}, ctx.Err()
			}
			if errors.Is(err, store.ErrUnavailable) || errors.Is(err, store.ErrSnapshotExpired) {
				return CheckBulkResult{}, err
			}
			results[i].Err = err
			continue
		}
		results[i].Allowed = ok
	}
	return CheckBulkResult{Results: results, At: e.at(rev)}, nil
}

// LookupResources implements Engine.
func (e *Local) LookupResources(ctx context.Context, req LookupResourcesRequest) (LookupResourcesResult, error) {
	if req.Limit < 0 || req.Limit > check.MaxLookupLimit {
		return LookupResourcesResult{}, invalid("limit must be between 0 and %d (0 uses the default of %d)", check.MaxLookupLimit, check.DefaultLookupLimit)
	}
	if req.Cursor != "" && !store.ValidID(req.Cursor) {
		return LookupResourcesResult{}, invalid("cursor is not valid")
	}
	rev, err := e.resolve(req.Consistency)
	if err != nil {
		return LookupResourcesResult{}, err
	}
	sc, _ := e.st.Schema()
	res, err := e.eng.LookupResources(ctx, sc, e.st, rev, req.ResourceType, req.Permission, req.Subject, req.Cursor, req.Limit)
	if err != nil {
		return LookupResourcesResult{}, err
	}
	ids := res.IDs
	if ids == nil {
		ids = []string{}
	}
	return LookupResourcesResult{ResourceIDs: ids, Cursor: res.Next, At: e.at(rev)}, nil
}

// Expand implements Engine. Its dispatches count in
// grantd_check_dispatches_total with the checks'.
func (e *Local) Expand(ctx context.Context, req ExpandRequest) (ExpandResult, error) {
	if req.MaxNodes < 0 || req.MaxNodes > check.MaxTraceNodes {
		return ExpandResult{}, invalid("max_nodes must be between 0 and %d (0 uses the default of %d)", check.MaxTraceNodes, check.DefaultTraceNodes)
	}
	rev, err := e.resolve(req.Consistency)
	if err != nil {
		return ExpandResult{}, err
	}
	sc, _ := e.st.Schema()
	tree, stats, err := e.eng.Expand(ctx, sc, rev, check.ExpandRequest{ResourceType: req.ResourceType, ResourceID: req.ResourceID,
		Permission: req.Permission, Recursive: req.Recursive, MaxNodes: req.MaxNodes})
	e.dispatches.Add(uint64(stats.Dispatches))
	if err != nil {
		return ExpandResult{}, err
	}
	return ExpandResult{Tree: tree, At: e.at(rev)}, nil
}

// LookupSubjects implements Engine. Its dispatches count in
// grantd_check_dispatches_total with the checks'.
func (e *Local) LookupSubjects(ctx context.Context, req LookupSubjectsRequest) (LookupSubjectsResult, error) {
	if req.Limit < 0 || req.Limit > check.MaxLookupLimit {
		return LookupSubjectsResult{}, invalid("limit must be between 0 and %d (0 uses the default of %d)", check.MaxLookupLimit, check.DefaultLookupLimit)
	}
	if req.Cursor != "" && req.Cursor != check.Wildcard && !store.ValidID(req.Cursor) {
		return LookupSubjectsResult{}, invalid("cursor is not valid")
	}
	rev, err := e.resolve(req.Consistency)
	if err != nil {
		return LookupSubjectsResult{}, err
	}
	sc, _ := e.st.Schema()
	res, stats, err := e.eng.LookupSubjects(ctx, sc, rev, check.LookupSubjectsRequest{ResourceType: req.ResourceType,
		ResourceID: req.ResourceID, Permission: req.Permission, SubjectType: req.SubjectType,
		SubjectRelation: req.SubjectRelation, After: req.Cursor, Limit: req.Limit})
	e.dispatches.Add(uint64(stats.Dispatches))
	if err != nil {
		return LookupSubjectsResult{}, err
	}
	subjects := res.Subjects
	if subjects == nil {
		subjects = []check.FoundSubject{}
	}
	return LookupSubjectsResult{Subjects: subjects, Cursor: res.Next, At: e.at(rev)}, nil
}

// ReadRelationships implements Engine.
func (e *Local) ReadRelationships(ctx context.Context, req ReadRequest) (ReadResult, error) {
	if req.Limit < 0 || req.Limit > store.MaxReadLimit {
		return ReadResult{}, invalid("limit must be between 0 and %d (0 uses the default of %d)", store.MaxReadLimit, store.DefaultReadLimit)
	}
	if len(req.Cursor) > maxCursorBytes {
		return ReadResult{}, invalid("cursor is too long")
	}
	rev, err := e.resolve(req.Consistency)
	if err != nil {
		return ReadResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ReadResult{}, err
	}
	rels, next, err := e.st.Read(rev, req.Filter, req.Cursor, req.Limit)
	if err != nil {
		return ReadResult{}, err
	}
	if rels == nil {
		rels = []store.Relationship{}
	}
	return ReadResult{Relationships: rels, Cursor: next, At: e.at(rev)}, nil
}

// Write implements Engine. A ctx that has already ended stops the write
// before it starts; once the store has the write it runs to completion.
func (e *Local) Write(ctx context.Context, req WriteRequest) (WriteResult, error) {
	if err := ctx.Err(); err != nil {
		return WriteResult{}, err
	}
	rev, err := e.st.Write(req.Updates, req.Preconditions)
	if err != nil {
		return WriteResult{}, err
	}
	return WriteResult{At: e.at(rev)}, nil
}
