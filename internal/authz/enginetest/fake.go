package enginetest

import (
	"bytes"
	"context"
	"fmt"
	"iter"
	"sort"
	"strings"
	"sync"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
)

// TokenKey is the consistency token key of every Fake and of the engines
// NewLocal returns, so the same revision always has the same token. It is
// a fixed test key: never use it outside tests.
var TokenKey = bytes.Repeat([]byte{0x5a}, token.KeySize)

// MaxFakeWork bounds the node evaluations of one Fake query, as
// check.MaxDispatchesPerCheck bounds a real check: past it the query fails
// with check.ErrTooMuchWork.
const MaxFakeWork = 2_000_000

// maxCursorBytes is the engine's limit on a read cursor.
const maxCursorBytes = 1024

// Fake is a deterministic in-memory engine.Engine for tests. It keeps every
// revision of its relationships, so any token it issued stays readable
// until ExpireBefore drops it, and answers every query by solving the
// schema's rules as equations over whole relationship sets: a different
// strategy from the real engine's depth-first walk, held to the same
// contract (Run).
//
// It is deterministic: revisions count up from 1 (the schema), tokens use
// TokenKey, MinimizeLatency reads the newest revision, and results come in
// a fixed order. Unlike the real engine it has no depth limit; a schema
// whose data puts an exclusion inside a cycle has no stable answer, and
// the fake reports check.ErrTooMuchWork for it. It is safe for concurrent
// use.
type Fake struct {
	sc     *schema.Schema
	tokens *token.Issuer

	mu     sync.RWMutex
	head   store.Revision
	minRev store.Revision
	byRel  map[string]*fakeEntry // relationship text -> entry
	byNode map[node][]*fakeEntry // object#relation -> entries, in subject order
	fail   error
}

type span struct{ created, deleted store.Revision } // deleted == 0: still alive

type fakeEntry struct {
	rel   store.Relationship
	spans []span
}

func (e *fakeEntry) visibleAt(rev store.Revision) bool {
	for _, s := range e.spans {
		if s.created <= rev && (s.deleted == 0 || s.deleted > rev) {
			return true
		}
	}
	return false
}

func (e *fakeEntry) alive() bool { return e.spans[len(e.spans)-1].deleted == 0 }

var _ engine.Engine = (*Fake)(nil)

// NewFake returns a Fake whose schema, parsed from schemaSrc, is revision
// 1. Relationships given in their text form ("doc:plan#viewer@user:alice")
// are written in one more revision.
func NewFake(schemaSrc string, relationships ...string) (*Fake, error) {
	sc, err := schema.Parse(schemaSrc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", store.ErrInvalid, err)
	}
	tok, err := token.NewIssuer(TokenKey)
	if err != nil {
		return nil, err
	}
	f := &Fake{sc: sc, tokens: tok, head: 1, byRel: map[string]*fakeEntry{}, byNode: map[node][]*fakeEntry{}}
	if len(relationships) > 0 {
		ups := make([]store.Update, len(relationships))
		for i, s := range relationships {
			r, err := store.ParseRelationship(s)
			if err != nil {
				return nil, err
			}
			ups[i] = store.Update{Op: store.OpTouch, Relationship: r}
		}
		if _, err := f.Write(context.Background(), engine.WriteRequest{Updates: ups}); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// Tokens returns the issuer of the fake's consistency tokens.
func (f *Fake) Tokens() *token.Issuer { return f.tokens }

// Schema returns the fake's schema.
func (f *Fake) Schema() *schema.Schema { return f.sc }

// Head returns the newest revision.
func (f *Fake) Head() store.Revision {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.head
}

// Fail makes every call fail with err, before it reads or writes anything,
// until Fail(nil). Tests use it to see how a caller handles an engine that
// is unavailable (store.ErrUnavailable) or a snapshot that expired.
func (f *Fake) Fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = err
}

// ExpireBefore drops the history before rev, as the store's retention
// does: reads at an older revision then fail with store.ErrSnapshotExpired.
// rev is capped at the head.
func (f *Fake) ExpireBefore(rev store.Revision) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rev > f.head {
		rev = f.head
	}
	if rev > f.minRev {
		f.minRev = rev
	}
}

// begin starts a call: the injected failure, then ctx.
func (f *Fake) begin(ctx context.Context) error {
	if f.fail != nil {
		return f.fail
	}
	return ctx.Err()
}

func (f *Fake) at(rev store.Revision) engine.Snapshot {
	return engine.Snapshot{Revision: rev, Token: f.tokens.Encode(rev)}
}

func (f *Fake) checkRev(rev store.Revision) error {
	if rev < f.minRev {
		return fmt.Errorf("%w: revision %d is older than the oldest kept revision %d", store.ErrSnapshotExpired, rev, f.minRev)
	}
	return nil
}

// resolve applies the engine's consistency rules with no staleness:
// MinimizeLatency reads the head. f.mu is held.
func (f *Fake) resolve(c engine.Consistency) (store.Revision, error) {
	switch c.Mode {
	case "", engine.MinimizeLatency, engine.FullyConsistent:
		if c.Token != "" {
			return 0, engine.InvalidArgument("consistency.token is only used with at_least_as_fresh or at_exact_snapshot")
		}
		return f.head, nil
	case engine.AtLeastAsFresh, engine.AtExactSnapshot:
		if c.Token == "" {
			return 0, engine.InvalidArgument("consistency mode %s needs a token", c.Mode)
		}
		rev, err := f.tokens.Decode(c.Token)
		if err != nil {
			return 0, err
		}
		if rev > f.head {
			return 0, engine.InvalidArgument("token is from a newer revision than this server has")
		}
		if c.Mode == engine.AtExactSnapshot {
			return rev, nil
		}
		return f.head, nil
	default:
		return 0, engine.InvalidArgument("unknown consistency mode %q", c.Mode)
	}
}

// read starts a read call and resolves its snapshot; it returns with f.mu
// read-locked when err is nil.
func (f *Fake) read(ctx context.Context, c engine.Consistency) (store.Revision, error) {
	f.mu.RLock()
	if err := f.begin(ctx); err != nil {
		f.mu.RUnlock()
		return 0, err
	}
	rev, err := f.resolve(c)
	if err != nil {
		f.mu.RUnlock()
		return 0, err
	}
	return rev, nil
}

// direct yields the relationships on one object relation at rev, in
// subject order. f.mu is held.
func (f *Fake) direct(rev store.Revision, typ, id, rel string) iter.Seq[store.Relationship] {
	return func(yield func(store.Relationship) bool) {
		for _, e := range f.byNode[node{typ, id, rel}] {
			if e.visibleAt(rev) && !yield(e.rel) {
				return
			}
		}
	}
}

// visible returns every relationship at rev in text order. f.mu is held.
func (f *Fake) visible(rev store.Revision) []store.Relationship {
	keys := make([]string, 0, len(f.byRel))
	for k, e := range f.byRel {
		if e.visibleAt(rev) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make([]store.Relationship, len(keys))
	for i, k := range keys {
		out[i] = f.byRel[k].rel
	}
	return out
}

// Check implements engine.Engine.
func (f *Fake) Check(ctx context.Context, req engine.CheckRequest) (engine.CheckResult, error) {
	rev, err := f.read(ctx, req.Consistency)
	if err != nil {
		return engine.CheckResult{}, err
	}
	defer f.mu.RUnlock()
	ok, err := f.check(ctx, rev, check.Request{ResourceType: req.ResourceType, ResourceID: req.ResourceID,
		Permission: req.Permission, Subject: req.Subject})
	if err != nil {
		return engine.CheckResult{}, err
	}
	return engine.CheckResult{Allowed: ok, At: f.at(rev)}, nil
}

func (f *Fake) check(ctx context.Context, rev store.Revision, q check.Request) (bool, error) {
	if err := q.Validate(f.sc); err != nil {
		return false, err
	}
	if err := f.checkRev(rev); err != nil {
		return false, err
	}
	n := node{q.ResourceType, q.ResourceID, q.Permission}
	vals, err := f.solve(ctx, rev, q.Subject, []node{n})
	if err != nil {
		return false, err
	}
	return vals[n], nil
}

// CheckBulk implements engine.Engine.
func (f *Fake) CheckBulk(ctx context.Context, req engine.CheckBulkRequest) (engine.CheckBulkResult, error) {
	if len(req.Items) > engine.MaxBulkChecks {
		return engine.CheckBulkResult{}, engine.InvalidArgument("items must have between 1 and %d checks", engine.MaxBulkChecks)
	}
	rev, err := f.read(ctx, req.Consistency)
	if err != nil {
		return engine.CheckBulkResult{}, err
	}
	defer f.mu.RUnlock()
	if len(req.Items) > 0 {
		if err := f.checkRev(rev); err != nil {
			return engine.CheckBulkResult{}, err
		}
	}
	results := make([]engine.ItemResult, len(req.Items))
	for i, it := range req.Items {
		ok, err := f.check(ctx, rev, check.Request{ResourceType: it.ResourceType, ResourceID: it.ResourceID,
			Permission: it.Permission, Subject: it.Subject})
		if err != nil {
			if ctx.Err() != nil {
				return engine.CheckBulkResult{}, ctx.Err()
			}
			results[i].Err = err
			continue
		}
		results[i].Allowed = ok
	}
	return engine.CheckBulkResult{Results: results, At: f.at(rev)}, nil
}

// LookupResources implements engine.Engine with the real engine's paging:
// candidates are the objects of the type that have a relationship, in ID
// order, and a full page continues from its last ID.
func (f *Fake) LookupResources(ctx context.Context, req engine.LookupResourcesRequest) (engine.LookupResourcesResult, error) {
	if req.Limit < 0 || req.Limit > check.MaxLookupLimit {
		return engine.LookupResourcesResult{}, engine.InvalidArgument("limit must be between 0 and %d (0 uses the default of %d)", check.MaxLookupLimit, check.DefaultLookupLimit)
	}
	if req.Cursor != "" && !store.ValidID(req.Cursor) {
		return engine.LookupResourcesResult{}, engine.InvalidArgument("cursor is not valid")
	}
	rev, err := f.read(ctx, req.Consistency)
	if err != nil {
		return engine.LookupResourcesResult{}, err
	}
	defer f.mu.RUnlock()
	probe := check.Request{ResourceType: req.ResourceType, ResourceID: "probe", Permission: req.Permission, Subject: req.Subject}
	if err := probe.Validate(f.sc); err != nil {
		return engine.LookupResourcesResult{}, err
	}
	if err := f.checkRev(rev); err != nil {
		return engine.LookupResourcesResult{}, err
	}
	limit := req.Limit
	if limit == 0 {
		limit = check.DefaultLookupLimit
	}
	seen := map[string]bool{}
	for _, r := range f.visible(rev) {
		if r.ResourceType == req.ResourceType {
			seen[r.ResourceID] = true
		}
	}
	var ids []string
	for id := range seen {
		if id > req.Cursor {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > check.MaxLookupEvaluations {
		ids = ids[:check.MaxLookupEvaluations+1] // the extra one only says more remain
	}
	roots := make([]node, len(ids))
	for i, id := range ids {
		roots[i] = node{req.ResourceType, id, req.Permission}
	}
	vals, err := f.solve(ctx, rev, req.Subject, roots)
	if err != nil {
		return engine.LookupResourcesResult{}, err
	}
	out := engine.LookupResourcesResult{ResourceIDs: []string{}, At: f.at(rev)}
	for i, id := range ids {
		if i == check.MaxLookupEvaluations {
			out.Cursor = ids[i-1]
			break
		}
		if !vals[roots[i]] {
			continue
		}
		out.ResourceIDs = append(out.ResourceIDs, id)
		if len(out.ResourceIDs) == limit {
			if i+1 < len(ids) {
				out.Cursor = id
			}
			break
		}
	}
	return out, nil
}

// LookupSubjects implements engine.Engine. Its candidates are every ID of
// the subject type that a relationship names, the resource itself when it
// is of that type, and one ID no relationship names: when that one holds
// the permission, a wildcard does, and the result is the wildcard with the
// candidates that do not hold it.
func (f *Fake) LookupSubjects(ctx context.Context, req engine.LookupSubjectsRequest) (engine.LookupSubjectsResult, error) {
	if req.Limit < 0 || req.Limit > check.MaxLookupLimit {
		return engine.LookupSubjectsResult{}, engine.InvalidArgument("limit must be between 0 and %d (0 uses the default of %d)", check.MaxLookupLimit, check.DefaultLookupLimit)
	}
	if req.Cursor != "" && req.Cursor != check.Wildcard && !store.ValidID(req.Cursor) {
		return engine.LookupSubjectsResult{}, engine.InvalidArgument("cursor is not valid")
	}
	rev, err := f.read(ctx, req.Consistency)
	if err != nil {
		return engine.LookupSubjectsResult{}, err
	}
	defer f.mu.RUnlock()
	q := check.LookupSubjectsRequest{ResourceType: req.ResourceType, ResourceID: req.ResourceID, Permission: req.Permission,
		SubjectType: req.SubjectType, SubjectRelation: req.SubjectRelation, After: req.Cursor, Limit: req.Limit}
	if err := q.Validate(f.sc); err != nil {
		return engine.LookupSubjectsResult{}, err
	}
	if err := f.checkRev(rev); err != nil {
		return engine.LookupSubjectsResult{}, err
	}
	limit := req.Limit
	if limit == 0 {
		limit = check.DefaultLookupLimit
	}
	named := map[string]bool{}
	if req.ResourceType == req.SubjectType {
		named[req.ResourceID] = true
	}
	for _, r := range f.visible(rev) {
		if r.ResourceType == req.SubjectType {
			named[r.ResourceID] = true
		}
		if r.SubjectType == req.SubjectType && r.SubjectID != check.Wildcard {
			named[r.SubjectID] = true
		}
	}
	candidates := make([]string, 0, len(named)+1)
	for id := range named {
		candidates = append(candidates, id)
	}
	sort.Strings(candidates)
	unnamed := ""
	if req.SubjectRelation == "" {
		unnamed = "enginetest.unnamed"
		for named[unnamed] {
			unnamed += "_"
		}
		candidates = append(candidates, unnamed)
	}
	root := node{req.ResourceType, req.ResourceID, req.Permission}
	holds := map[string]bool{}
	for _, id := range candidates {
		vals, err := f.solve(ctx, rev, store.Subject{Type: req.SubjectType, ID: id, Relation: req.SubjectRelation}, []node{root})
		if err != nil {
			return engine.LookupSubjectsResult{}, err
		}
		holds[id] = vals[root]
	}
	out := engine.LookupSubjectsResult{Subjects: []check.FoundSubject{}, At: f.at(rev)}
	if unnamed != "" && holds[unnamed] {
		if req.Cursor == "" {
			ex := []string{}
			for _, id := range candidates {
				if !holds[id] {
					ex = append(ex, id)
				}
			}
			out.Subjects = append(out.Subjects, check.FoundSubject{ID: check.Wildcard, Excluded: ex})
		}
		return out, nil
	}
	for _, id := range candidates {
		if !holds[id] || (req.Cursor != "" && req.Cursor != check.Wildcard && id <= req.Cursor) {
			continue
		}
		if len(out.Subjects) == limit {
			out.Cursor = out.Subjects[limit-1].ID
			break
		}
		out.Subjects = append(out.Subjects, check.FoundSubject{ID: id})
	}
	return out, nil
}

// ReadRelationships implements engine.Engine.
func (f *Fake) ReadRelationships(ctx context.Context, req engine.ReadRequest) (engine.ReadResult, error) {
	if req.Limit < 0 || req.Limit > store.MaxReadLimit {
		return engine.ReadResult{}, engine.InvalidArgument("limit must be between 0 and %d (0 uses the default of %d)", store.MaxReadLimit, store.DefaultReadLimit)
	}
	if len(req.Cursor) > maxCursorBytes {
		return engine.ReadResult{}, engine.InvalidArgument("cursor is too long")
	}
	rev, err := f.read(ctx, req.Consistency)
	if err != nil {
		return engine.ReadResult{}, err
	}
	defer f.mu.RUnlock()
	if err := req.Filter.Validate(); err != nil {
		return engine.ReadResult{}, err
	}
	if err := f.checkRev(rev); err != nil {
		return engine.ReadResult{}, err
	}
	limit := req.Limit
	if limit == 0 {
		limit = store.DefaultReadLimit
	}
	out := engine.ReadResult{Relationships: []store.Relationship{}, At: f.at(rev)}
	for _, r := range f.visible(rev) {
		if !matches(req.Filter, r) || r.String() <= req.Cursor {
			continue
		}
		if len(out.Relationships) == limit {
			out.Cursor = out.Relationships[limit-1].String()
			break
		}
		out.Relationships = append(out.Relationships, r)
	}
	return out, nil
}

func matches(fl store.Filter, r store.Relationship) bool {
	return r.ResourceType == fl.ResourceType &&
		(fl.ResourceID == "" || r.ResourceID == fl.ResourceID) &&
		(fl.Relation == "" || r.Relation == fl.Relation) &&
		(fl.SubjectType == "" || r.SubjectType == fl.SubjectType) &&
		(fl.SubjectID == "" || r.SubjectID == fl.SubjectID) &&
		(fl.SubjectRelation == "" || (fl.SubjectRelation == store.NoRelation && r.SubjectRelation == "") || r.SubjectRelation == fl.SubjectRelation)
}

// Write implements engine.Engine with the store's rules: every update is
// checked against the schema (deletes excepted), the preconditions hold at
// the head, a create of a live relationship conflicts, and a write that
// changes nothing returns the head without a new revision.
func (f *Fake) Write(ctx context.Context, req engine.WriteRequest) (engine.WriteResult, error) {
	if err := validateWrite(req); err != nil {
		return engine.WriteResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx); err != nil {
		return engine.WriteResult{}, err
	}
	for i, u := range req.Updates {
		if u.Op == store.OpDelete {
			continue
		}
		if err := store.CheckAgainst(f.sc, u.Relationship); err != nil {
			return engine.WriteResult{}, fmt.Errorf("update %d: %w", i, err)
		}
	}
	if err := f.preconditions(req.Preconditions); err != nil {
		return engine.WriteResult{}, err
	}
	var touch, del []store.Relationship
	for _, u := range req.Updates {
		e := f.byRel[u.Relationship.String()]
		alive := e != nil && e.alive()
		switch {
		case u.Op == store.OpCreate && alive:
			return engine.WriteResult{}, fmt.Errorf("%w: %s already exists", store.ErrConflict, u.Relationship)
		case u.Op != store.OpDelete && !alive:
			touch = append(touch, u.Relationship)
		case u.Op == store.OpDelete && alive:
			del = append(del, u.Relationship)
		}
	}
	if len(touch)+len(del) == 0 {
		return engine.WriteResult{At: f.at(f.head)}, nil
	}
	return engine.WriteResult{At: f.at(f.commit(touch, del))}, nil
}

func validateWrite(req engine.WriteRequest) error {
	if len(req.Updates) == 0 {
		return fmt.Errorf("%w: a write needs at least one update", store.ErrInvalid)
	}
	if len(req.Updates) > store.MaxUpdatesPerWrite {
		return fmt.Errorf("%w: a write can have at most %d updates", store.ErrInvalid, store.MaxUpdatesPerWrite)
	}
	seen := make(map[string]bool, len(req.Updates))
	for i, u := range req.Updates {
		if u.Op != store.OpTouch && u.Op != store.OpCreate && u.Op != store.OpDelete {
			return fmt.Errorf("%w: update %d: op must be touch, create or delete", store.ErrInvalid, i)
		}
		if err := u.Relationship.Validate(); err != nil {
			return fmt.Errorf("update %d: %w", i, err)
		}
		k := u.Relationship.String()
		if seen[k] {
			return fmt.Errorf("%w: update %d: %s appears more than once in the same write", store.ErrInvalid, i, k)
		}
		seen[k] = true
	}
	return validatePreconditions(req.Preconditions)
}

func validatePreconditions(ps []store.Precondition) error {
	if len(ps) > store.MaxPreconditions {
		return fmt.Errorf("%w: at most %d preconditions", store.ErrInvalid, store.MaxPreconditions)
	}
	for i, p := range ps {
		if err := p.Filter.Validate(); err != nil {
			return fmt.Errorf("precondition %d: %w", i, err)
		}
	}
	return nil
}

// preconditions checks ps at the head. f.mu is held.
func (f *Fake) preconditions(ps []store.Precondition) error {
	for i, p := range ps {
		found := false
		for _, e := range f.byRel {
			if e.alive() && matches(p.Filter, e.rel) {
				found = true
				break
			}
		}
		if found != p.MustExist {
			want := "exist"
			if !p.MustExist {
				want = "not exist"
			}
			return fmt.Errorf("%w: precondition %d: matching relationships must %s", store.ErrPrecondition, i, want)
		}
	}
	return nil
}

// commit applies one revision of changes. f.mu is held.
func (f *Fake) commit(touch, del []store.Relationship) store.Revision {
	rev := f.head + 1
	for _, r := range touch {
		k := r.String()
		e := f.byRel[k]
		if e == nil {
			e = &fakeEntry{rel: r}
			f.byRel[k] = e
			nk := node{r.ResourceType, r.ResourceID, r.Relation}
			list := append(f.byNode[nk], e)
			sort.Slice(list, func(i, j int) bool { return list[i].rel.Subject().String() < list[j].rel.Subject().String() })
			f.byNode[nk] = list
		}
		e.spans = append(e.spans, span{created: rev})
	}
	for _, r := range del {
		e := f.byRel[r.String()]
		e.spans[len(e.spans)-1].deleted = rev
	}
	f.head = rev
	return rev
}

// DeleteRelationships implements engine.Engine with the store's rules.
func (f *Fake) DeleteRelationships(ctx context.Context, req engine.DeleteRequest) (engine.DeleteResult, error) {
	if err := req.Filter.Validate(); err != nil {
		return engine.DeleteResult{}, fmt.Errorf("filter: %w", err)
	}
	if req.Limit < 0 || req.Limit > store.MaxDeletesPerFilter {
		return engine.DeleteResult{}, fmt.Errorf("%w: limit must be between 0 and %d", store.ErrInvalid, store.MaxDeletesPerFilter)
	}
	if err := validatePreconditions(req.Preconditions); err != nil {
		return engine.DeleteResult{}, err
	}
	limit := req.Limit
	if limit == 0 {
		limit = store.MaxDeletesPerFilter
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin(ctx); err != nil {
		return engine.DeleteResult{}, err
	}
	if err := f.preconditions(req.Preconditions); err != nil {
		return engine.DeleteResult{}, err
	}
	var matched []store.Relationship
	for _, r := range f.visible(f.head) {
		if matches(req.Filter, r) {
			matched = append(matched, r)
		}
	}
	if len(matched) == 0 {
		return engine.DeleteResult{At: f.at(f.head)}, nil
	}
	partial := len(matched) > limit
	if partial {
		if !req.AllowPartial {
			return engine.DeleteResult{}, fmt.Errorf("%w: more than %d relationships match the filter; set allow_partial to delete them in pages", store.ErrPrecondition, limit)
		}
		matched = matched[:limit]
	}
	rev := f.commit(nil, matched)
	return engine.DeleteResult{Deleted: len(matched), Partial: partial, At: f.at(rev)}, nil
}

// node is one object#relation.
type node struct{ typ, id, rel string }

// solver solves, for one subject at one revision, the equations the schema
// makes of the stored relationships: one boolean per object#relation.
//
// Exclusion is not monotone, so the least fixpoint of the whole system is
// not defined; the solver computes the alternating fixpoint instead. gamma
// reads the subtracted side of every exclusion from an assumption and
// solves the rest as an ordinary least fixpoint; starting from "nothing
// holds", gamma applied twice climbs to the answer. When the data has no
// cycle through an exclusion, as with every schema whose cycles are
// unions, intersections and arrows only, this is the stratified answer,
// the one the real engine gives. When it does, the answer is not two
// valued, and solve reports check.ErrTooMuchWork.
type solver struct {
	f     *Fake
	ctx   context.Context
	rev   store.Revision
	sub   store.Subject
	nodes []node
	index map[node]bool
	work  int
}

func (f *Fake) solve(ctx context.Context, rev store.Revision, sub store.Subject, roots []node) (map[node]bool, error) {
	s := &solver{f: f, ctx: ctx, rev: rev, sub: sub, index: map[node]bool{}}
	for _, n := range roots {
		s.add(n)
	}
	truth := map[node]bool{}
	for {
		maybe, err := s.gamma(truth)
		if err != nil {
			return nil, err
		}
		next, err := s.gamma(maybe)
		if err != nil {
			return nil, err
		}
		if same(next, truth) {
			if !same(maybe, truth) {
				return nil, fmt.Errorf("%w: the data puts an exclusion inside a cycle, which has no stable answer", check.ErrTooMuchWork)
			}
			return truth, nil
		}
		truth = next
	}
}

func same(a, b map[node]bool) bool {
	count := 0
	for n, v := range a {
		if v {
			if !b[n] {
				return false
			}
			count++
		}
	}
	for _, v := range b {
		if v {
			count--
		}
	}
	return count == 0
}

func (s *solver) add(n node) {
	if !s.index[n] {
		s.index[n] = true
		s.nodes = append(s.nodes, n)
	}
}

// gamma is the least solution with every subtracted side read from
// assumed. Each pass evaluates every node seen so far; nodes it meets are
// added, and passes repeat until nothing changes.
func (s *solver) gamma(assumed map[node]bool) (map[node]bool, error) {
	v := map[node]bool{}
	for changed := true; changed; {
		changed = false
		for i := 0; i < len(s.nodes); i++ { // s.nodes grows during the pass
			n := s.nodes[i]
			if v[n] {
				continue
			}
			s.work++
			if s.work > MaxFakeWork {
				return nil, check.ErrTooMuchWork
			}
			if s.work%1024 == 0 {
				if err := s.ctx.Err(); err != nil {
					return nil, err
				}
			}
			if s.value(n, v, assumed) {
				v[n] = true
				changed = true
			}
		}
	}
	return v, nil
}

// value evaluates n's equation once.
func (s *solver) value(n node, v, assumed map[node]bool) bool {
	if n.typ == s.sub.Type && n.id == s.sub.ID && n.rel == s.sub.Relation {
		return true // a userset contains itself
	}
	d := s.f.sc.Defs[n.typ]
	if p, ok := d.Permissions[n.rel]; ok {
		return s.expr(n, p.Expr, v, assumed)
	}
	// No short cuts: every node an equation names joins the system the
	// first time the equation is evaluated, so the set of nodes never
	// depends on the values being assumed.
	ok := false
	for r := range s.f.direct(s.rev, n.typ, n.id, n.rel) {
		if r.SubjectType == s.sub.Type &&
			((r.SubjectID == check.Wildcard && s.sub.Relation == "") ||
				(r.SubjectID == s.sub.ID && r.SubjectRelation == s.sub.Relation)) {
			ok = true
		}
		if r.SubjectRelation == "" {
			continue
		}
		if sd, known := s.f.sc.Defs[r.SubjectType]; !known || !sd.Has(r.SubjectRelation) {
			continue
		}
		if s.get(node{r.SubjectType, r.SubjectID, r.SubjectRelation}, v) {
			ok = true
		}
	}
	return ok
}

// get reads a node's current value, adding it to the system when new.
func (s *solver) get(n node, v map[node]bool) bool {
	s.add(n)
	return v[n]
}

// expr evaluates e on object n with positive references read from v and
// negative ones (under the subtracted side of an exclusion) from assumed.
func (s *solver) expr(n node, e schema.Expr, v, assumed map[node]bool) bool {
	switch e := e.(type) {
	case *schema.Ref:
		return s.get(node{n.typ, n.id, e.Name}, v)
	case *schema.Arrow:
		ok := false
		for r := range s.f.direct(s.rev, n.typ, n.id, e.Tupleset) {
			if d, ok := s.f.sc.Defs[r.SubjectType]; !ok || !d.Has(e.Computed) || r.SubjectID == check.Wildcard {
				continue
			}
			if s.get(node{r.SubjectType, r.SubjectID, e.Computed}, v) {
				ok = true
			}
		}
		return ok
	case *schema.Union:
		l := s.expr(n, e.L, v, assumed)
		r := s.expr(n, e.R, v, assumed)
		return l || r
	case *schema.Intersection:
		l := s.expr(n, e.L, v, assumed)
		r := s.expr(n, e.R, v, assumed)
		return l && r
	case *schema.Exclusion:
		l := s.expr(n, e.L, v, assumed)
		r := s.expr(n, e.R, assumed, v)
		return l && !r
	}
	panic(fmt.Sprintf("enginetest: unsupported expression %T", e))
}

// Expand implements engine.Engine. It builds the tree check.Engine.Expand
// documents, in the same order, so the two engines return equal trees for
// equal data.
func (f *Fake) Expand(ctx context.Context, req engine.ExpandRequest) (engine.ExpandResult, error) {
	if req.MaxNodes < 0 || req.MaxNodes > check.MaxTraceNodes {
		return engine.ExpandResult{}, engine.InvalidArgument("max_nodes must be between 0 and %d (0 uses the default of %d)", check.MaxTraceNodes, check.DefaultTraceNodes)
	}
	rev, err := f.read(ctx, req.Consistency)
	if err != nil {
		return engine.ExpandResult{}, err
	}
	defer f.mu.RUnlock()
	q := check.ExpandRequest{ResourceType: req.ResourceType, ResourceID: req.ResourceID, Permission: req.Permission}
	if err := q.Validate(f.sc); err != nil {
		return engine.ExpandResult{}, err
	}
	if err := f.checkRev(rev); err != nil {
		return engine.ExpandResult{}, err
	}
	max := req.MaxNodes
	if max == 0 {
		max = check.DefaultTraceNodes
	}
	b := &builder{f: f, ctx: ctx, rev: rev, recursive: req.Recursive, max: max,
		done: map[string]bool{}, active: map[string]bool{}}
	var top check.TraceNode
	if err := b.node(&top, req.ResourceType, req.ResourceID, req.Permission, 0); err != nil {
		return engine.ExpandResult{}, err
	}
	return engine.ExpandResult{Tree: &check.Trace{Root: top.Children[0], Nodes: b.n, Truncated: b.truncated}, At: f.at(rev)}, nil
}

type builder struct {
	f            *Fake
	ctx          context.Context
	rev          store.Revision
	recursive    bool
	max, n       int
	truncated    bool
	done, active map[string]bool
}

// add records n under parent, or counts it as omitted past the limit.
func (b *builder) add(parent *check.TraceNode, n check.TraceNode) *check.TraceNode {
	if b.n == b.max {
		parent.Omitted++
		b.truncated = true
		return nil
	}
	b.n++
	p := &n
	parent.Children = append(parent.Children, p)
	return p
}

func (b *builder) node(parent *check.TraceNode, typ, id, rel string, depth int) error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	if depth > check.DefaultMaxDepth {
		return check.ErrDepthExceeded
	}
	d := b.f.sc.Defs[typ]
	n := check.TraceNode{Kind: check.KindRelation, Object: typ + ":" + id, Relation: rel}
	if d.IsPermission(rel) {
		n.Kind = check.KindPermission
	}
	k := typ + ":" + id + "#" + rel
	switch {
	case b.active[k]:
		n.Cut = true
		b.add(parent, n)
		return nil
	case b.done[k]:
		n.Memo = true
		b.add(parent, n)
		return nil
	}
	p := b.add(parent, n)
	if p == nil {
		return nil
	}
	b.done[k], b.active[k] = true, true
	defer delete(b.active, k)
	if perm, ok := d.Permissions[rel]; ok {
		return b.expr(p, typ, id, perm.Expr, depth)
	}
	for r := range b.f.direct(b.rev, typ, id, rel) {
		if r.SubjectRelation != "" {
			if sd, known := b.f.sc.Defs[r.SubjectType]; !known || !sd.Has(r.SubjectRelation) {
				continue
			}
			if b.recursive {
				if err := b.node(p, r.SubjectType, r.SubjectID, r.SubjectRelation, depth+1); err != nil {
					return err
				}
				continue
			}
		}
		b.add(p, check.TraceNode{Kind: check.KindSubject, Object: typ + ":" + id, Relation: rel, Subject: r.Subject().String()})
	}
	return nil
}

func (b *builder) expr(parent *check.TraceNode, typ, id string, e schema.Expr, depth int) error {
	obj := typ + ":" + id
	var kind check.TraceKind
	var l, r schema.Expr
	switch e := e.(type) {
	case *schema.Ref:
		return b.node(parent, typ, id, e.Name, depth)
	case *schema.Arrow:
		p := b.add(parent, check.TraceNode{Kind: check.KindArrow, Object: obj, Expr: e.String()})
		if p == nil {
			return nil
		}
		for rel := range b.f.direct(b.rev, typ, id, e.Tupleset) {
			if d, ok := b.f.sc.Defs[rel.SubjectType]; !ok || !d.Has(e.Computed) || rel.SubjectID == check.Wildcard {
				continue
			}
			if b.recursive {
				if err := b.node(p, rel.SubjectType, rel.SubjectID, e.Computed, depth+1); err != nil {
					return err
				}
				continue
			}
			b.add(p, check.TraceNode{Kind: check.KindSubject, Object: obj, Relation: e.Tupleset,
				Subject: rel.SubjectType + ":" + rel.SubjectID + "#" + e.Computed})
		}
		return nil
	case *schema.Union:
		kind, l, r = check.KindUnion, e.L, e.R
	case *schema.Intersection:
		kind, l, r = check.KindIntersection, e.L, e.R
	case *schema.Exclusion:
		kind, l, r = check.KindExclusion, e.L, e.R
	default:
		panic(fmt.Sprintf("enginetest: unsupported expression %T", e))
	}
	p := b.add(parent, check.TraceNode{Kind: kind, Object: obj, Expr: exprString(e)})
	if p == nil {
		return nil
	}
	if err := b.expr(p, typ, id, l, depth); err != nil {
		return err
	}
	return b.expr(p, typ, id, r, depth)
}

// exprString prints a permission expression with only the parentheses its
// shape needs, as trace and expand nodes show it: "viewer + edit - banned".
// "->" binds tightest, then "&", "+" and "-"; all associate to the left.
func exprString(e schema.Expr) string {
	var b strings.Builder
	writeExpr(&b, e)
	return b.String()
}

func precedence(e schema.Expr) int {
	switch e.(type) {
	case *schema.Exclusion:
		return 1
	case *schema.Union:
		return 2
	case *schema.Intersection:
		return 3
	}
	return 4
}

func writeExpr(b *strings.Builder, e schema.Expr) {
	var l, r schema.Expr
	var op string
	switch e := e.(type) {
	case *schema.Union:
		l, r, op = e.L, e.R, " + "
	case *schema.Intersection:
		l, r, op = e.L, e.R, " & "
	case *schema.Exclusion:
		l, r, op = e.L, e.R, " - "
	default:
		b.WriteString(e.String())
		return
	}
	p := precedence(e)
	for i, x := range []schema.Expr{l, r} {
		wrap := precedence(x) < p || (i == 1 && precedence(x) == p)
		if i == 1 {
			b.WriteString(op)
		}
		if wrap {
			b.WriteByte('(')
		}
		writeExpr(b, x)
		if wrap {
			b.WriteByte(')')
		}
	}
}
