package store

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/platform/clock"
)

// Revision identifies a consistent snapshot. Every committed write gets the
// next revision; reads name the revision they want to see.
type Revision uint64

// Limits on a single request.
const (
	MaxUpdatesPerWrite   = 1000
	MaxPreconditions     = 100
	DefaultRetention     = 100_000 // revisions of history kept for snapshot reads and watch
	gcEvery              = 128
	MaxReadLimit         = 1000
	DefaultReadLimit     = 100
	maxCandidatesPerType = 1 << 20
)

// Errors returned by the store. ErrInvalid is defined in relationship.go.
var (
	ErrConflict         = errors.New("conflict")
	ErrPrecondition     = errors.New("precondition failed")
	ErrSnapshotExpired  = errors.New("snapshot expired")
	ErrFutureRevision   = errors.New("revision is newer than the store")
	ErrNoSchema         = errors.New("no schema has been written")
	ErrUnavailable      = errors.New("store unavailable")
	ErrTooManyCandidate = errors.New("too many objects to scan")
)

// Op is a write operation.
type Op string

const (
	OpTouch  Op = "touch"  // create, or keep if it already exists
	OpCreate Op = "create" // create; fail with ErrConflict if it exists
	OpDelete Op = "delete" // delete if it exists
)

// Update is one change in a write.
type Update struct {
	Op           Op           `json:"op"`
	Relationship Relationship `json:"relationship"`
	// ExpiresAt, on a touch or create, ends the relationship: it stops
	// being visible at the first revision whose commit time is at or after
	// it. Zero means it never expires. Touching a relationship that exists
	// with another expiry, or none, replaces its expiry. Deletes ignore it.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// Precondition guards a write: it must hold at the moment of the write.
type Precondition struct {
	MustExist bool   `json:"must_exist"` // false means "must not exist"
	Filter    Filter `json:"filter"`
}

// Filter selects relationships. ResourceType is required; empty fields match
// anything. SubjectRelation only applies when SubjectType is set; use "..."
// to match subjects without a relation.
type Filter struct {
	ResourceType    string `json:"resource_type"`
	ResourceID      string `json:"resource_id,omitempty"`
	Relation        string `json:"relation,omitempty"`
	SubjectType     string `json:"subject_type,omitempty"`
	SubjectID       string `json:"subject_id,omitempty"`
	SubjectRelation string `json:"subject_relation,omitempty"`
}

// NoRelation in a filter matches subjects that have no relation.
const NoRelation = "..."

// Validate checks filter syntax.
func (f Filter) Validate() error {
	switch {
	case !typeRe.MatchString(f.ResourceType):
		return invalid("filter needs a valid resource_type")
	case f.ResourceID != "" && !ValidID(f.ResourceID):
		return invalid("filter resource_id %q is not valid", f.ResourceID)
	case f.Relation != "" && !typeRe.MatchString(f.Relation):
		return invalid("filter relation %q is not valid", f.Relation)
	case f.SubjectType != "" && !typeRe.MatchString(f.SubjectType):
		return invalid("filter subject_type %q is not valid", f.SubjectType)
	case f.SubjectID != "" && f.SubjectID != "*" && !ValidID(f.SubjectID):
		return invalid("filter subject_id %q is not valid", f.SubjectID)
	case f.SubjectRelation != "" && f.SubjectRelation != NoRelation && !typeRe.MatchString(f.SubjectRelation):
		return invalid("filter subject_relation %q is not valid", f.SubjectRelation)
	case f.SubjectID != "" && f.SubjectType == "":
		return invalid("filter subject_id needs subject_type")
	}
	return nil
}

func (f Filter) matches(r Relationship) bool {
	return r.ResourceType == f.ResourceType &&
		(f.ResourceID == "" || r.ResourceID == f.ResourceID) &&
		(f.Relation == "" || r.Relation == f.Relation) &&
		(f.SubjectType == "" || r.SubjectType == f.SubjectType) &&
		(f.SubjectID == "" || r.SubjectID == f.SubjectID) &&
		(f.SubjectRelation == "" || (f.SubjectRelation == NoRelation && r.SubjectRelation == "") || r.SubjectRelation == f.SubjectRelation)
}

// Change is one committed relationship change, for Watch.
type Change struct {
	Revision     Revision     `json:"revision"`
	Op           Op           `json:"op"` // OpTouch or OpDelete
	Relationship Relationship `json:"relationship"`
	// ExpiresAt is the expiry a touch set, in UTC; zero for none and on
	// deletes. A relationship that reaches its expiry has no change of its
	// own: it is simply not visible from that revision on.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// Stored is a relationship as a snapshot holds it, with its expiry.
type Stored struct {
	Relationship
	ExpiresAt time.Time // in UTC; zero when it never expires
}

// version is one life of a relationship: visible from revision created
// until revision deleted (0: not deleted), and only at revisions whose
// commit time is before expires (Unix nanoseconds, 0: never expires).
// Commit times never go backwards, so an expired version stays expired.
type version struct {
	created, deleted Revision
	expires          int64
}

func (v version) visibleAt(rev Revision, t int64) bool {
	return v.created <= rev && (v.deleted == 0 || v.deleted > rev) && (v.expires == 0 || t < v.expires)
}

// entry holds every kept version of one relationship. rel never carries an
// expiry; each version has its own. At most one version, the last, is open
// (not deleted).
type entry struct {
	rel      Relationship
	versions []version
}

// open returns the last version when it is not deleted, expired or not.
func (e *entry) open() (*version, bool) {
	if e == nil || len(e.versions) == 0 || e.versions[len(e.versions)-1].deleted != 0 {
		return nil, false
	}
	return &e.versions[len(e.versions)-1], true
}

// liveAt returns the open version when it has not expired at commit time t:
// the relationship exists for a write committed at t.
func (e *entry) liveAt(t int64) (version, bool) {
	v, ok := e.open()
	if !ok || (v.expires != 0 && t >= v.expires) {
		return version{}, false
	}
	return *v, true
}

// visibleAt returns the version the snapshot at rev, committed at t, sees.
func (e *entry) visibleAt(rev Revision, t int64) (version, bool) {
	for i := len(e.versions) - 1; i >= 0; i-- {
		if v := e.versions[i]; v.visibleAt(rev, t) {
			return v, true
		}
	}
	return version{}, false
}

func (e *entry) stored(v version) Stored {
	return Stored{Relationship: e.rel, ExpiresAt: expiryTime(v.expires)}
}

// Store is a multi-version relationship store. It is safe for concurrent use.
type Store struct {
	mu        sync.RWMutex
	head      Revision
	minRev    Revision                                // oldest revision that can still be read
	byType    map[string]map[string]map[string]*entry // resource type -> "id#relation" -> subject key -> entry
	changes   []Change                                // committed changes with revision > minRev, in order
	schema    *schema.Schema
	schemaSrc string
	retention Revision
	wal       *walLog
	notify    chan struct{} // closed and replaced after every commit
	clock     clock.Clock
	// times holds the commit time, in Unix nanoseconds, of every revision
	// from minRev to head: times[rev-minRev]. They never go backwards.
	times []int64
	// expiring counts open versions with an expiry. While it is zero no
	// visibility depends on commit times, and log records leave the time
	// out (see logTimeLocked).
	expiring int
}

// Options configures a Store.
type Options struct {
	Dir       string   // directory for the write-ahead log; empty keeps everything in memory
	Retention Revision // history kept for snapshot reads; 0 means DefaultRetention
	// Clock stamps each revision with its commit time, which decides when
	// relationships with an expiry stop being visible; nil is the wall
	// clock.
	Clock clock.Clock
}

// Open creates a store, recovering state from the write-ahead log in
// opts.Dir when one exists.
func Open(opts Options) (*Store, error) {
	s := &Store{
		byType:    map[string]map[string]map[string]*entry{},
		retention: opts.Retention,
		notify:    make(chan struct{}),
		clock:     clock.Or(opts.Clock),
		times:     []int64{0},
	}
	if s.retention == 0 {
		s.retention = DefaultRetention
	}
	if opts.Dir == "" {
		return s, nil
	}
	w, err := openWAL(opts.Dir, s.replay)
	if err != nil {
		return nil, err
	}
	s.wal = w
	// Compact the log into a checkpoint so recovery time stays bounded.
	// Relationships already expired at the head are left out of it.
	headTime := s.headTimeLocked()
	if err := w.checkpoint(s.head, headTime, s.schemaSrc, s.liveLocked(headTime)); err != nil {
		w.close()
		return nil, err
	}
	s.minRev = s.head
	s.times = []int64{headTime}
	s.changes = nil
	s.gcExpiredLocked()
	return s, nil
}

// Close releases the write-ahead log.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wal == nil {
		return nil
	}
	err := s.wal.close()
	s.wal = nil
	return err
}

// Head returns the newest committed revision.
func (s *Store) Head() Revision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.head
}

// MinRevision returns the oldest revision that can still be read.
func (s *Store) MinRevision() Revision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.minRev
}

// RevisionTime returns the commit time of rev, for any revision from
// MinRevision to Head. Commit times never go backwards: a revision gets the
// clock's time or its predecessor's, whichever is later. Revision 0, before
// any write, and revisions recovered from a log written before commit times
// were recorded have the zero time.
func (s *Store) RevisionTime(rev Revision) (time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.snapshotLocked(rev)
	if err != nil || t == 0 {
		return time.Time{}, err
	}
	return time.Unix(0, t).UTC(), nil
}

func (s *Store) headTimeLocked() int64 { return s.times[len(s.times)-1] }

// nextTimeLocked is the commit time the next revision gets: the clock's
// time, but never before the head's, so an expired relationship never
// becomes visible again.
func (s *Store) nextTimeLocked() int64 {
	return max(s.clock.Now().UnixNano(), s.headTimeLocked())
}

// setTimeLocked records t as rev's commit time, raised to the head's when
// it is earlier (records from logs without times carry 0).
func (s *Store) setTimeLocked(rev Revision, t int64) {
	t = max(t, s.headTimeLocked())
	for Revision(len(s.times)) <= rev-s.minRev {
		s.times = append(s.times, t)
	}
}

// logTimeLocked is the commit time to put in the log record of a revision
// committed at t: t when an open version has an expiry or the revision
// sets one, else 0, which leaves it out. Commit times only decide what a
// snapshot sees when some relationship can expire, so a log written by a
// store that never held one is byte for byte the log of a store without
// expiry, and a store that never sees an expiry writes the same log as
// before it had commit times. Recovery gives a record without a time its
// predecessor's; no recovered visibility depends on it.
func (s *Store) logTimeLocked(t int64, changes []Change) int64 {
	if s.expiring > 0 {
		return t
	}
	for _, c := range changes {
		if !c.ExpiresAt.IsZero() {
			return t
		}
	}
	return 0
}

// Schema returns the current schema and its source, or nil before one is written.
func (s *Store) Schema() (*schema.Schema, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.schema, s.schemaSrc
}

// WriteSchema replaces the schema. It fails if any stored relationship would
// break the new schema, so data and schema never disagree.
func (s *Store) WriteSchema(src string) (Revision, error) {
	sc, err := schema.Parse(src)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	canonical := sc.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.nextTimeLocked()
	for _, r := range s.aliveLocked(t) {
		if err := checkAgainst(sc, r); err != nil {
			return 0, fmt.Errorf("%w: existing relationship %s would no longer be valid: %v", ErrPrecondition, r, err)
		}
	}
	rev := s.head + 1
	if s.wal != nil {
		if err := s.wal.append(walRecord{Rev: rev, Time: s.logTimeLocked(t, nil), Type: recSchema, Schema: canonical}); err != nil {
			return 0, err
		}
	}
	s.applySchema(rev, t, sc, canonical)
	s.commitLocked(rev)
	return rev, nil
}

// MaxBrokenListed is the most broken relationships a schema dry run lists;
// it counts all of them.
const MaxBrokenListed = 1000

// Broken is a stored relationship a new schema would not allow.
type Broken struct {
	Relationship Relationship
	Reason       string // why the new schema refuses it
}

// SchemaDryRun is what WriteSchema would find, without writing anything.
type SchemaDryRun struct {
	Schema   *schema.Schema // the parsed new schema
	Source   string         // its canonical form
	Previous *schema.Schema // the schema in force, nil before one is written
	Revision Revision       // the snapshot the relationships were checked at, less those expired by now
	// Broken holds the first limit broken relationships in text order and
	// BrokenCount how many there are in all. WriteSchema refuses the schema
	// exactly when BrokenCount is not zero.
	Broken      []Broken
	BrokenCount int
}

// DryRunSchema checks src as WriteSchema would and reports every stored
// relationship it would break, listing at most limit of them (at most
// MaxBrokenListed; zero means that many). It changes nothing.
func (s *Store) DryRunSchema(src string, limit int) (SchemaDryRun, error) {
	if limit < 0 || limit > MaxBrokenListed {
		return SchemaDryRun{}, invalid("limit must be between 1 and %d", MaxBrokenListed)
	}
	if limit == 0 {
		limit = MaxBrokenListed
	}
	sc, err := schema.Parse(src)
	if err != nil {
		return SchemaDryRun{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	out := SchemaDryRun{Schema: sc, Source: sc.String(), Broken: []Broken{}}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out.Previous, out.Revision = s.schema, s.head
	for _, r := range s.aliveLocked(s.nextTimeLocked()) {
		err := checkAgainst(sc, r)
		if err == nil {
			continue
		}
		out.BrokenCount++
		if len(out.Broken) < limit {
			out.Broken = append(out.Broken, Broken{Relationship: r, Reason: strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")})
		}
	}
	return out, nil
}

func (s *Store) applySchema(rev Revision, t int64, sc *schema.Schema, src string) {
	s.schema, s.schemaSrc = sc, src
	s.setTimeLocked(rev, t)
	s.head = rev
}

// CheckAgainst reports whether sc allows r: its resource type is defined, its
// relation is a relation (not a permission) and the relation allows its
// subject. Write applies the same rule to every update.
func CheckAgainst(sc *schema.Schema, r Relationship) error { return checkAgainst(sc, r) }

func checkAgainst(sc *schema.Schema, r Relationship) error {
	d, ok := sc.Defs[r.ResourceType]
	if !ok {
		return invalid("type %q is not defined in the schema", r.ResourceType)
	}
	rel, ok := d.Relations[r.Relation]
	if !ok {
		if d.IsPermission(r.Relation) {
			return invalid("%s#%s is a permission; relationships can only be written to relations", r.ResourceType, r.Relation)
		}
		return invalid("%q has no relation %q", r.ResourceType, r.Relation)
	}
	if !rel.Allows(r.SubjectType, r.SubjectID, r.SubjectRelation) {
		sub := r.SubjectType
		if r.SubjectID == "*" {
			sub += ":*"
		} else if r.SubjectRelation != "" {
			sub += "#" + r.SubjectRelation
		}
		allowed := make([]string, len(rel.Allowed))
		for i, a := range rel.Allowed {
			allowed[i] = a.String()
		}
		return invalid("%s#%s does not allow %s (allowed: %s)", r.ResourceType, r.Relation, sub, strings.Join(allowed, ", "))
	}
	return nil
}

func subjectKey(r Relationship) string { return r.Subject().String() }

func objectKey(id, rel string) string { return id + "#" + rel }

func (s *Store) lookup(r Relationship) *entry {
	return s.byType[r.ResourceType][objectKey(r.ResourceID, r.Relation)][subjectKey(r)]
}

// Write applies updates atomically, after checking preconditions and the
// schema. It returns the revision at which the write is visible. A write
// that changes nothing returns the current head.
func (s *Store) Write(updates []Update, preconds []Precondition) (Revision, error) {
	if len(updates) == 0 {
		return 0, invalid("a write needs at least one update")
	}
	if len(updates) > MaxUpdatesPerWrite {
		return 0, invalid("a write can have at most %d updates", MaxUpdatesPerWrite)
	}
	if len(preconds) > MaxPreconditions {
		return 0, invalid("a write can have at most %d preconditions", MaxPreconditions)
	}
	seen := make(map[string]bool, len(updates))
	for i, u := range updates {
		if u.Op != OpTouch && u.Op != OpCreate && u.Op != OpDelete {
			return 0, invalid("update %d: op must be touch, create or delete", i)
		}
		if err := u.Relationship.Validate(); err != nil {
			return 0, fmt.Errorf("update %d: %w", i, err)
		}
		if err := validExpiry(u.ExpiresAt); err != nil {
			return 0, fmt.Errorf("update %d: %w", i, err)
		}
		k := u.Relationship.String()
		if seen[k] {
			return 0, invalid("update %d: %s appears more than once in the same write", i, k)
		}
		seen[k] = true
	}
	for i, p := range preconds {
		if err := p.Filter.Validate(); err != nil {
			return 0, fmt.Errorf("precondition %d: %w", i, err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.schema == nil {
		return 0, ErrNoSchema
	}
	// Preconditions and existence are judged at the commit time the write
	// will get, so a relationship that has expired by then counts as gone.
	t := s.nextTimeLocked()
	for i, u := range updates {
		if u.Op == OpDelete {
			continue // deleting something the schema no longer allows is always fine
		}
		if err := checkAgainst(s.schema, u.Relationship); err != nil {
			return 0, fmt.Errorf("update %d: %w", i, err)
		}
	}
	if err := s.preconditionsLocked(preconds, t); err != nil {
		return 0, err
	}

	var changes []Change
	for _, u := range updates {
		cur, alive := s.lookup(u.Relationship).liveAt(t)
		exp := expiryNano(u.ExpiresAt)
		switch u.Op {
		case OpCreate:
			if alive {
				return 0, fmt.Errorf("%w: %s already exists", ErrConflict, u.Relationship)
			}
			changes = append(changes, Change{Op: OpTouch, Relationship: u.Relationship, ExpiresAt: expiryTime(exp)})
		case OpTouch:
			// Touching with another expiry, or none, replaces the expiry.
			if !alive || cur.expires != exp {
				changes = append(changes, Change{Op: OpTouch, Relationship: u.Relationship, ExpiresAt: expiryTime(exp)})
			}
		case OpDelete:
			if alive {
				changes = append(changes, Change{Op: OpDelete, Relationship: u.Relationship})
			}
		}
	}
	if len(changes) == 0 {
		return s.head, nil
	}
	rev := s.head + 1
	for i := range changes {
		changes[i].Revision = rev
	}
	if s.wal != nil {
		if err := s.wal.append(walRecord{Rev: rev, Time: s.logTimeLocked(t, changes), Type: recWrite, Changes: changes}); err != nil {
			return 0, err
		}
	}
	s.applyChanges(rev, t, changes)
	s.commitLocked(rev)
	return rev, nil
}

// MaxDeletesPerFilter is the most relationships one DeleteByFilter call
// removes, the same bound as the updates of one Write, so one revision never
// carries more changes than a watch page can hold.
const MaxDeletesPerFilter = MaxUpdatesPerWrite

// DeleteRequest deletes the relationships matching Filter in one revision.
type DeleteRequest struct {
	Filter Filter
	// Limit is the most relationships to delete; 0 means
	// MaxDeletesPerFilter.
	Limit int
	// AllowPartial deletes the first Limit matches, in text order, when more
	// match. Without it a call that matches more than Limit deletes nothing
	// and fails with ErrPrecondition.
	AllowPartial bool
	// Preconditions must hold at the moment of the delete, as in Write.
	Preconditions []Precondition
}

// DeleteResult reports a delete by filter.
type DeleteResult struct {
	// Revision is the revision at which the delete is visible, or the
	// current head when nothing matched.
	Revision Revision
	// Deleted is how many relationships the delete removed.
	Deleted int
	// Partial is true when more relationships still match the filter: the
	// call hit Limit with AllowPartial set. Calling again deletes the next
	// ones.
	Partial bool
}

// DeleteByFilter removes the relationships alive at the head that match
// req.Filter, after checking req.Preconditions, as one revision. The log
// holds it as one write record listing every deleted relationship, so
// recovery and watch see the same changes the caller was told about, and a
// crash keeps all of them or none.
func (s *Store) DeleteByFilter(req DeleteRequest) (DeleteResult, error) {
	if err := req.Filter.Validate(); err != nil {
		return DeleteResult{}, fmt.Errorf("filter: %w", err)
	}
	if req.Limit < 0 || req.Limit > MaxDeletesPerFilter {
		return DeleteResult{}, invalid("limit must be between 0 and %d", MaxDeletesPerFilter)
	}
	limit := req.Limit
	if limit == 0 {
		limit = MaxDeletesPerFilter
	}
	if len(req.Preconditions) > MaxPreconditions {
		return DeleteResult{}, invalid("a delete can have at most %d preconditions", MaxPreconditions)
	}
	for i, p := range req.Preconditions {
		if err := p.Filter.Validate(); err != nil {
			return DeleteResult{}, fmt.Errorf("precondition %d: %w", i, err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.schema == nil {
		return DeleteResult{}, ErrNoSchema
	}
	t := s.nextTimeLocked()
	if err := s.preconditionsLocked(req.Preconditions, t); err != nil {
		return DeleteResult{}, err
	}
	// Keep the limit+1 smallest matches in text order: enough to delete the
	// first limit and to know whether more remain, in memory bounded by the
	// limit however many relationships match.
	h := &relHeap{}
	s.scanLocked(s.head, t, req.Filter, func(st Stored) bool {
		r := st.Relationship
		if h.Len() <= limit {
			heap.Push(h, r)
		} else if compareText(r, (*h)[0]) < 0 {
			(*h)[0] = r
			heap.Fix(h, 0)
		}
		return true
	})
	if h.Len() == 0 {
		return DeleteResult{Revision: s.head}, nil
	}
	partial := h.Len() > limit
	if partial && !req.AllowPartial {
		return DeleteResult{}, fmt.Errorf("%w: more than %d relationships match the filter; set allow_partial to delete them in pages", ErrPrecondition, limit)
	}
	sort.Slice(*h, func(i, j int) bool { return compareText((*h)[i], (*h)[j]) < 0 })
	matched := *h
	if partial {
		matched = matched[:limit]
	}
	rev := s.head + 1
	changes := make([]Change, len(matched))
	for i, r := range matched {
		changes[i] = Change{Revision: rev, Op: OpDelete, Relationship: r}
	}
	if s.wal != nil {
		if err := s.wal.append(walRecord{Rev: rev, Time: s.logTimeLocked(t, changes), Type: recWrite, Changes: changes}); err != nil {
			return DeleteResult{}, err
		}
	}
	s.applyChanges(rev, t, changes)
	s.commitLocked(rev)
	return DeleteResult{Revision: rev, Deleted: len(changes), Partial: partial}, nil
}

// relHeap is a max-heap in text order: its root is the last relationship
// kept.
type relHeap []Relationship

func (h relHeap) Len() int           { return len(h) }
func (h relHeap) Less(i, j int) bool { return compareText(h[i], h[j]) > 0 }
func (h relHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *relHeap) Push(x any)        { *h = append(*h, x.(Relationship)) }
func (h *relHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// compareText orders relationships as strings.Compare orders their String
// forms, without building them. String joins the same eleven parts for
// every relationship, so the first part that differs decides, unless one is
// a prefix of the other: then the shorter one's next byte decides against
// the longer one's, and only a tie there needs a byte-by-byte walk.
func compareText(a, b Relationship) int {
	for i := range numParts {
		x, y := textPart(a, i), textPart(b, i)
		if x == y {
			continue
		}
		n := min(len(x), len(y))
		if x[:n] != y[:n] {
			return strings.Compare(x, y)
		}
		if len(x) < len(y) {
			if c := cmpByte(nextByte(a, i), int(y[n])); c != 0 {
				return c
			}
		} else if c := cmpByte(int(x[n]), nextByte(b, i)); c != 0 {
			return c
		}
		return compareBytes(a, b, i)
	}
	return 0
}

const numParts = 11

// textPart is the i-th of the parts String joins.
func textPart(r Relationship, i int) string {
	switch i {
	case 0:
		return r.ResourceType
	case 1, 7:
		return ":"
	case 2:
		return r.ResourceID
	case 3:
		return "#"
	case 4:
		return r.Relation
	case 5:
		return "@"
	case 6:
		return r.SubjectType
	case 8:
		return r.SubjectID
	case 9:
		if r.SubjectRelation != "" {
			return "#"
		}
		return ""
	default:
		return r.SubjectRelation
	}
}

// nextByte is the byte of r's text form after part i, or -1 at the end.
func nextByte(r Relationship, i int) int {
	for i++; i < numParts; i++ {
		if p := textPart(r, i); p != "" {
			return int(p[0])
		}
	}
	return -1
}

func cmpByte(x, y int) int {
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

// compareBytes compares a and b byte by byte from part i on, where both
// text forms agree up to the start of part i.
func compareBytes(a, b Relationship, i int) int {
	j, ai, bi := i, 0, 0
	for {
		for i < numParts && ai == len(textPart(a, i)) {
			i, ai = i+1, 0
		}
		for j < numParts && bi == len(textPart(b, j)) {
			j, bi = j+1, 0
		}
		switch {
		case i == numParts && j == numParts:
			return 0
		case i == numParts:
			return -1
		case j == numParts:
			return 1
		}
		if c := cmpByte(int(textPart(a, i)[ai]), int(textPart(b, j)[bi])); c != 0 {
			return c
		}
		ai, bi = ai+1, bi+1
	}
}

// preconditionsLocked checks preconditions at the head, less what has
// expired by commit time t.
func (s *Store) preconditionsLocked(preconds []Precondition, t int64) error {
	for i, p := range preconds {
		found := s.anyLocked(s.head, t, p.Filter)
		if found != p.MustExist {
			want := "exist"
			if !p.MustExist {
				want = "not exist"
			}
			return fmt.Errorf("%w: precondition %d: matching relationships must %s", ErrPrecondition, i, want)
		}
	}
	return nil
}

// applyChanges applies the changes of revision rev, committed at t. A
// touch closes the open version, if any, and opens one with the change's
// expiry; a delete closes the open version.
func (s *Store) applyChanges(rev Revision, t int64, changes []Change) {
	for _, c := range changes {
		r := c.Relationship
		objs := s.byType[r.ResourceType]
		if objs == nil {
			objs = map[string]map[string]*entry{}
			s.byType[r.ResourceType] = objs
		}
		ok := objectKey(r.ResourceID, r.Relation)
		subs := objs[ok]
		if subs == nil {
			subs = map[string]*entry{}
			objs[ok] = subs
		}
		sk := subjectKey(r)
		e := subs[sk]
		if v, ok := e.open(); ok {
			v.deleted = rev
			if v.expires != 0 {
				s.expiring--
			}
		}
		if c.Op == OpTouch {
			if e == nil {
				e = &entry{rel: r}
				subs[sk] = e
			}
			exp := expiryNano(c.ExpiresAt)
			e.versions = append(e.versions, version{created: rev, expires: exp})
			if exp != 0 {
				s.expiring++
			}
		}
	}
	s.setTimeLocked(rev, t)
	s.head = rev
	s.changes = append(s.changes, changes...)
}

// commitLocked publishes a new head: it wakes watchers and garbage-collects
// history that fell out of the retention window.
func (s *Store) commitLocked(rev Revision) {
	close(s.notify)
	s.notify = make(chan struct{})
	if rev%gcEvery == 0 && rev > s.retention {
		s.gcLocked(rev - s.retention)
	}
}

// gcLocked drops the history before newMin: versions deleted at or before
// it, and versions whose expiry is at or before newMin's commit time, which
// no kept revision can see because commit times never go backwards.
func (s *Store) gcLocked(newMin Revision) {
	if newMin <= s.minRev {
		return
	}
	s.times = append([]int64(nil), s.times[newMin-s.minRev:]...)
	s.minRev = newMin
	s.collectLocked(newMin)
	i := sort.Search(len(s.changes), func(i int) bool { return s.changes[i].Revision > newMin })
	s.changes = append([]Change(nil), s.changes[i:]...)
}

// gcExpiredLocked drops versions that expired by minRev's commit time,
// without moving minRev.
func (s *Store) gcExpiredLocked() { s.collectLocked(s.minRev) }

// collectLocked removes every version no revision from minRev on can see:
// deleted at or before minRev, or expired by minRev's commit time. It
// removes entries and objects left with nothing.
func (s *Store) collectLocked(minRev Revision) {
	tmin := s.times[0]
	for t, objs := range s.byType {
		for ok, subs := range objs {
			for sk, e := range subs {
				kept := e.versions[:0]
				for _, v := range e.versions {
					gone := v.deleted != 0 && v.deleted <= minRev
					expired := v.expires != 0 && v.expires <= tmin
					if !gone && !expired {
						kept = append(kept, v)
					} else if v.deleted == 0 && v.expires != 0 {
						s.expiring--
					}
				}
				e.versions = kept
				if len(kept) == 0 {
					delete(subs, sk)
				}
			}
			if len(subs) == 0 {
				delete(objs, ok)
			}
		}
		if len(objs) == 0 {
			delete(s.byType, t)
		}
	}
}

// snapshotLocked checks that rev can be read and returns its commit time.
func (s *Store) snapshotLocked(rev Revision) (int64, error) {
	if rev < s.minRev {
		return 0, fmt.Errorf("%w: revision %d is older than the oldest kept revision %d", ErrSnapshotExpired, rev, s.minRev)
	}
	if rev > s.head {
		return 0, ErrFutureRevision
	}
	return s.times[rev-s.minRev], nil
}

// ReadDirect returns the relationships stored on one object relation at a
// revision, in a stable order.
func (s *Store) ReadDirect(rev Revision, resourceType, resourceID, relation string) ([]Relationship, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.snapshotLocked(rev)
	if err != nil {
		return nil, err
	}
	subs := s.byType[resourceType][objectKey(resourceID, relation)]
	out := make([]Relationship, 0, len(subs))
	for _, e := range subs {
		if _, ok := e.visibleAt(rev, t); ok {
			out = append(out, e.rel)
		}
	}
	sort.Slice(out, func(i, j int) bool { return subjectKey(out[i]) < subjectKey(out[j]) })
	return out, nil
}

// Read returns relationships matching filter at rev, ordered by their text
// form, starting after cursor (exclusive). It returns the cursor for the next
// page, or "" when there are no more.
func (s *Store) Read(rev Revision, f Filter, after string, limit int) ([]Relationship, string, error) {
	st, next, err := s.ReadStored(rev, f, after, limit)
	if err != nil {
		return nil, "", err
	}
	var out []Relationship
	if st != nil {
		out = make([]Relationship, len(st))
		for i, r := range st {
			out[i] = r.Relationship
		}
	}
	return out, next, nil
}

// ReadStored is Read with each relationship's expiry.
func (s *Store) ReadStored(rev Revision, f Filter, after string, limit int) ([]Stored, string, error) {
	if err := f.Validate(); err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = DefaultReadLimit
	}
	if limit > MaxReadLimit {
		limit = MaxReadLimit
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.snapshotLocked(rev)
	if err != nil {
		return nil, "", err
	}
	var all []Stored
	s.scanLocked(rev, t, f, func(r Stored) bool {
		if k := r.String(); k > after {
			all = append(all, r)
		}
		return true
	})
	sort.Slice(all, func(i, j int) bool { return all[i].String() < all[j].String() })
	if len(all) > limit {
		return all[:limit], all[limit-1].String(), nil
	}
	return all, "", nil
}

// scanLocked calls fn with each relationship matching f in the snapshot at
// rev, committed at t, until fn returns false.
func (s *Store) scanLocked(rev Revision, t int64, f Filter, fn func(Stored) bool) {
	objs := s.byType[f.ResourceType]
	visit := func(subs map[string]*entry) bool {
		for _, e := range subs {
			if !f.matches(e.rel) {
				continue
			}
			if v, ok := e.visibleAt(rev, t); ok && !fn(e.stored(v)) {
				return false
			}
		}
		return true
	}
	if f.ResourceID != "" && f.Relation != "" {
		visit(objs[objectKey(f.ResourceID, f.Relation)])
		return
	}
	for _, subs := range objs {
		if !visit(subs) {
			return
		}
	}
}

func (s *Store) anyLocked(rev Revision, t int64, f Filter) bool {
	found := false
	s.scanLocked(rev, t, f, func(Stored) bool { found = true; return false })
	return found
}

// ObjectIDs returns, in order, the IDs of objects of resourceType that have at
// least one relationship visible at rev. Objects without relationships cannot
// hold any permission, so this is the complete candidate set for lookups.
func (s *Store) ObjectIDs(rev Revision, resourceType string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, err := s.snapshotLocked(rev)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for ok, subs := range s.byType[resourceType] {
		id := ok[:strings.LastIndexByte(ok, '#')]
		if seen[id] {
			continue
		}
		for _, e := range subs {
			if _, ok := e.visibleAt(rev, t); ok {
				seen[id] = true
				break
			}
		}
		if len(seen) > maxCandidatesPerType {
			return nil, ErrTooManyCandidate
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// Changes returns up to limit changes committed after revision after.
func (s *Store) Changes(after Revision, limit int) ([]Change, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if after < s.minRev {
		return nil, fmt.Errorf("%w: changes before revision %d are no longer kept", ErrSnapshotExpired, s.minRev)
	}
	if after > s.head {
		return nil, ErrFutureRevision
	}
	i := sort.Search(len(s.changes), func(i int) bool { return s.changes[i].Revision > after })
	end := len(s.changes)
	if limit > 0 && end-i > limit {
		end = i + limit
		// never split one revision across pages
		for end < len(s.changes) && s.changes[end].Revision == s.changes[end-1].Revision {
			end++
		}
	}
	return append([]Change(nil), s.changes[i:end]...), nil
}

// WaitForRevision blocks until the head is newer than after or ctx ends.
func (s *Store) WaitForRevision(ctx context.Context, after Revision) error {
	for {
		s.mu.RLock()
		head, ch := s.head, s.notify
		s.mu.RUnlock()
		if head > after {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// aliveLocked returns, in text order, the relationships open at the head
// that have not expired by commit time t.
func (s *Store) aliveLocked(t int64) []Relationship {
	var out []Relationship
	for _, st := range s.liveLocked(t) {
		out = append(out, st.Relationship)
	}
	return out
}

// liveLocked is aliveLocked with each relationship's expiry.
func (s *Store) liveLocked(t int64) []Stored {
	var out []Stored
	for _, objs := range s.byType {
		for _, subs := range objs {
			for _, e := range subs {
				if v, ok := e.liveAt(t); ok {
					out = append(out, e.stored(v))
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// replay applies one recovered log record. It runs during Open, before the
// store is shared.
func (s *Store) replay(rec walRecord) error {
	if rec.Rev <= s.head && rec.Type != recCheckpoint {
		return fmt.Errorf("log record revision %d is not after %d", rec.Rev, s.head)
	}
	switch rec.Type {
	case recCheckpoint:
		s.byType = map[string]map[string]map[string]*entry{}
		s.minRev, s.times, s.expiring = rec.Rev, []int64{rec.Time}, 0
		s.schema, s.schemaSrc = nil, ""
		if rec.Schema != "" {
			sc, err := schema.Parse(rec.Schema)
			if err != nil {
				return fmt.Errorf("checkpoint schema: %v", err)
			}
			s.schema, s.schemaSrc = sc, rec.Schema
		}
		changes := make([]Change, 0, len(rec.Rels)+len(rec.Expiring))
		for _, r := range rec.Rels {
			changes = append(changes, Change{Revision: rec.Rev, Op: OpTouch, Relationship: r})
		}
		for _, x := range rec.Expiring {
			if err := x.Relationship.Validate(); err != nil {
				return fmt.Errorf("checkpoint: %v", err)
			}
			if x.ExpiresAt <= 0 {
				return fmt.Errorf("checkpoint: %s has expiry %d", x.Relationship, x.ExpiresAt)
			}
			changes = append(changes, Change{Revision: rec.Rev, Op: OpTouch, Relationship: x.Relationship, ExpiresAt: expiryTime(x.ExpiresAt)})
		}
		s.applyChanges(rec.Rev, rec.Time, changes)
		s.changes = nil
	case recSchema:
		sc, err := schema.Parse(rec.Schema)
		if err != nil {
			return fmt.Errorf("schema record: %v", err)
		}
		s.applySchema(rec.Rev, rec.Time, sc, rec.Schema)
	case recWrite:
		for _, c := range rec.Changes {
			if err := c.Relationship.Validate(); err != nil {
				return fmt.Errorf("write record: %v", err)
			}
		}
		s.applyChanges(rec.Rev, rec.Time, rec.Changes)
	default:
		return fmt.Errorf("unknown log record type %q", rec.Type)
	}
	return nil
}
