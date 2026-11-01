package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/laiwf94/authz/internal/authz/schema"
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
}

type version struct{ created, deleted Revision } // deleted == 0: still alive

type entry struct {
	rel      Relationship
	versions []version
}

func (e *entry) alive() bool {
	return len(e.versions) > 0 && e.versions[len(e.versions)-1].deleted == 0
}

func (e *entry) visibleAt(rev Revision) bool {
	for i := len(e.versions) - 1; i >= 0; i-- {
		v := e.versions[i]
		if v.created <= rev && (v.deleted == 0 || v.deleted > rev) {
			return true
		}
	}
	return false
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
	wal       *wal
	notify    chan struct{} // closed and replaced after every commit
}

// Options configures a Store.
type Options struct {
	Dir       string   // directory for the write-ahead log; empty keeps everything in memory
	Retention Revision // history kept for snapshot reads; 0 means DefaultRetention
}

// Open creates a store, recovering state from the write-ahead log in
// opts.Dir when one exists.
func Open(opts Options) (*Store, error) {
	s := &Store{
		byType:    map[string]map[string]map[string]*entry{},
		retention: opts.Retention,
		notify:    make(chan struct{}),
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
	if err := w.checkpoint(s.head, s.schemaSrc, s.aliveLocked()); err != nil {
		w.close()
		return nil, err
	}
	s.minRev = s.head
	s.changes = nil
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
	for _, r := range s.aliveLocked() {
		if err := checkAgainst(sc, r); err != nil {
			return 0, fmt.Errorf("%w: existing relationship %s would no longer be valid: %v", ErrPrecondition, r, err)
		}
	}
	rev := s.head + 1
	if s.wal != nil {
		if err := s.wal.append(walRecord{Rev: rev, Type: recSchema, Schema: canonical}); err != nil {
			return 0, err
		}
	}
	s.applySchema(rev, sc, canonical)
	s.commitLocked(rev)
	return rev, nil
}

func (s *Store) applySchema(rev Revision, sc *schema.Schema, src string) {
	s.schema, s.schemaSrc = sc, src
	s.head = rev
}

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
	for i, u := range updates {
		if u.Op == OpDelete {
			continue // deleting something the schema no longer allows is always fine
		}
		if err := checkAgainst(s.schema, u.Relationship); err != nil {
			return 0, fmt.Errorf("update %d: %w", i, err)
		}
	}
	for i, p := range preconds {
		found := s.anyLocked(s.head, p.Filter)
		if found != p.MustExist {
			want := "exist"
			if !p.MustExist {
				want = "not exist"
			}
			return 0, fmt.Errorf("%w: precondition %d: matching relationships must %s", ErrPrecondition, i, want)
		}
	}

	var changes []Change
	for _, u := range updates {
		e := s.lookup(u.Relationship)
		alive := e != nil && e.alive()
		switch u.Op {
		case OpCreate:
			if alive {
				return 0, fmt.Errorf("%w: %s already exists", ErrConflict, u.Relationship)
			}
			changes = append(changes, Change{Op: OpTouch, Relationship: u.Relationship})
		case OpTouch:
			if !alive {
				changes = append(changes, Change{Op: OpTouch, Relationship: u.Relationship})
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
		if err := s.wal.append(walRecord{Rev: rev, Type: recWrite, Changes: changes}); err != nil {
			return 0, err
		}
	}
	s.applyChanges(rev, changes)
	s.commitLocked(rev)
	return rev, nil
}

func (s *Store) applyChanges(rev Revision, changes []Change) {
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
		if c.Op == OpTouch {
			if e == nil {
				e = &entry{rel: r}
				subs[sk] = e
			}
			e.versions = append(e.versions, version{created: rev})
		} else if e != nil && e.alive() {
			e.versions[len(e.versions)-1].deleted = rev
		}
	}
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

func (s *Store) gcLocked(newMin Revision) {
	if newMin <= s.minRev {
		return
	}
	s.minRev = newMin
	for t, objs := range s.byType {
		for ok, subs := range objs {
			for sk, e := range subs {
				kept := e.versions[:0]
				for _, v := range e.versions {
					if v.deleted == 0 || v.deleted > newMin {
						kept = append(kept, v)
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
	i := sort.Search(len(s.changes), func(i int) bool { return s.changes[i].Revision > newMin })
	s.changes = append([]Change(nil), s.changes[i:]...)
}

func (s *Store) checkRev(rev Revision) error {
	if rev < s.minRev {
		return fmt.Errorf("%w: revision %d is older than the oldest kept revision %d", ErrSnapshotExpired, rev, s.minRev)
	}
	if rev > s.head {
		return ErrFutureRevision
	}
	return nil
}

// ReadDirect returns the relationships stored on one object relation at a
// revision, in a stable order.
func (s *Store) ReadDirect(rev Revision, resourceType, resourceID, relation string) ([]Relationship, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkRev(rev); err != nil {
		return nil, err
	}
	subs := s.byType[resourceType][objectKey(resourceID, relation)]
	out := make([]Relationship, 0, len(subs))
	for _, e := range subs {
		if e.visibleAt(rev) {
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
	if err := s.checkRev(rev); err != nil {
		return nil, "", err
	}
	var all []Relationship
	s.scanLocked(rev, f, func(r Relationship) bool {
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

func (s *Store) scanLocked(rev Revision, f Filter, fn func(Relationship) bool) {
	objs := s.byType[f.ResourceType]
	visit := func(subs map[string]*entry) bool {
		for _, e := range subs {
			if f.matches(e.rel) && e.visibleAt(rev) && !fn(e.rel) {
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

func (s *Store) anyLocked(rev Revision, f Filter) bool {
	found := false
	s.scanLocked(rev, f, func(Relationship) bool { found = true; return false })
	return found
}

// ObjectIDs returns, in order, the IDs of objects of resourceType that have at
// least one relationship visible at rev. Objects without relationships cannot
// hold any permission, so this is the complete candidate set for lookups.
func (s *Store) ObjectIDs(rev Revision, resourceType string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkRev(rev); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for ok, subs := range s.byType[resourceType] {
		id := ok[:strings.LastIndexByte(ok, '#')]
		if seen[id] {
			continue
		}
		for _, e := range subs {
			if e.visibleAt(rev) {
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

func (s *Store) aliveLocked() []Relationship {
	var out []Relationship
	for _, objs := range s.byType {
		for _, subs := range objs {
			for _, e := range subs {
				if e.alive() {
					out = append(out, e.rel)
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
		s.schema, s.schemaSrc = nil, ""
		if rec.Schema != "" {
			sc, err := schema.Parse(rec.Schema)
			if err != nil {
				return fmt.Errorf("checkpoint schema: %v", err)
			}
			s.schema, s.schemaSrc = sc, rec.Schema
		}
		changes := make([]Change, len(rec.Rels))
		for i, r := range rec.Rels {
			changes[i] = Change{Revision: rec.Rev, Op: OpTouch, Relationship: r}
		}
		s.applyChanges(rec.Rev, changes)
		s.changes = nil
	case recSchema:
		sc, err := schema.Parse(rec.Schema)
		if err != nil {
			return fmt.Errorf("schema record: %v", err)
		}
		s.applySchema(rec.Rev, sc, rec.Schema)
	case recWrite:
		s.applyChanges(rec.Rev, rec.Changes)
	default:
		return fmt.Errorf("unknown log record type %q", rec.Type)
	}
	return nil
}
