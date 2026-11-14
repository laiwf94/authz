package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/clock"
)

var t0 = time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)

// skewClock is a fake clock that can also step back, as a wall clock can.
type skewClock struct {
	*clock.Fake
	skew time.Duration
}

func (c *skewClock) Now() time.Time { return c.Fake.Now().Add(c.skew) }

func clockStore(t *testing.T, dir string, c clock.Clock, retention Revision) *Store {
	t.Helper()
	s, err := Open(Options{Dir: dir, Clock: c, Retention: retention})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func expiring(t *testing.T, s *Store, op Op, rel string, at time.Time) Revision {
	t.Helper()
	rev, err := s.Write([]Update{{Op: op, Relationship: mustRel(t, rel), ExpiresAt: at}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

func revTime(t *testing.T, s *Store, rev Revision) time.Time {
	t.Helper()
	at, err := s.RevisionTime(rev)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func stored(t *testing.T, s *Store, rev Revision, f Filter) map[string]time.Time {
	t.Helper()
	rels, _, err := s.ReadStored(rev, f, "", MaxReadLimit)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]time.Time{}
	for _, r := range rels {
		out[r.String()] = r.ExpiresAt
	}
	return out
}

func TestRevisionTimes(t *testing.T) {
	c := &skewClock{Fake: clock.NewFake(t0)}
	s := clockStore(t, "", c, 0)
	if at := revTime(t, s, 0); !at.IsZero() {
		t.Fatalf("revision 0 has time %v", at)
	}
	withSchema(t, s)
	c.Advance(time.Second)
	r2 := write(t, s, OpTouch, "doc:a#viewer@user:x")
	if got := revTime(t, s, 1); !got.Equal(t0) || got.Location() != time.UTC {
		t.Fatalf("revision 1 at %v, want %v in UTC", got, t0)
	}
	if got := revTime(t, s, r2); !got.Equal(t0.Add(time.Second)) {
		t.Fatalf("revision 2 at %v", got)
	}
	// A clock that steps back does not move commit times back.
	c.skew = -time.Hour
	r3 := write(t, s, OpTouch, "doc:b#viewer@user:x")
	if got := revTime(t, s, r3); !got.Equal(t0.Add(time.Second)) {
		t.Fatalf("revision after a clock step back at %v, want its predecessor's", got)
	}
	// A write that changes nothing makes no revision.
	if rev := write(t, s, OpTouch, "doc:b#viewer@user:x"); rev != r3 {
		t.Fatalf("no-op write made revision %d", rev)
	}
	if _, err := s.RevisionTime(r3 + 1); !errors.Is(err, ErrFutureRevision) {
		t.Fatalf("future revision time: %v", err)
	}
}

func TestRevisionTimesAreTrimmedWithHistory(t *testing.T) {
	c := clock.NewFake(t0)
	s := clockStore(t, "", c, 10)
	withSchema(t, s)
	for range 3 * gcEvery {
		c.Advance(time.Millisecond)
		write(t, s, OpTouch, "doc:a#viewer@user:x")
		write(t, s, OpDelete, "doc:a#viewer@user:x")
	}
	min := s.MinRevision()
	if min == 0 {
		t.Fatal("no garbage collection ran")
	}
	if _, err := s.RevisionTime(min - 1); !errors.Is(err, ErrSnapshotExpired) {
		t.Fatalf("time of a collected revision: %v", err)
	}
	s.mu.RLock()
	n := len(s.times)
	s.mu.RUnlock()
	if want := int(s.Head()-min) + 1; n != want {
		t.Fatalf("%d commit times kept for %d revisions", n, want)
	}
	prev := revTime(t, s, min)
	for rev := min + 1; rev <= s.Head(); rev++ {
		at := revTime(t, s, rev)
		if at.Before(prev) {
			t.Fatalf("revision %d at %v is before its predecessor at %v", rev, at, prev)
		}
		prev = at
	}
}

func TestExpiryAtRevisionBoundaries(t *testing.T) {
	c := clock.NewFake(t0)
	s := clockStore(t, "", c, 0)
	withSchema(t, s)
	exp := t0.Add(10 * time.Second)
	r2 := expiring(t, s, OpTouch, "doc:a#viewer@user:x", exp)
	f := Filter{ResourceType: "doc"}
	if got := stored(t, s, r2, f); !got["doc:a#viewer@user:x"].Equal(exp) {
		t.Fatalf("read at the writing revision: %v", got)
	}

	// One nanosecond before the expiry it still grants.
	c.Set(exp.Add(-time.Nanosecond))
	r3 := write(t, s, OpTouch, "doc:b#viewer@user:x")
	if got := direct(t, s, r3, "doc", "a", "viewer"); len(got) != 1 {
		t.Fatalf("expired a nanosecond early: %v", got)
	}
	// At the expiry it stops, from the revision committed then on.
	c.Set(exp)
	r4 := write(t, s, OpTouch, "doc:c#viewer@user:x")
	if got := direct(t, s, r4, "doc", "a", "viewer"); len(got) != 0 {
		t.Fatalf("still visible at the revision committed at its expiry: %v", got)
	}
	// Nothing else expired, and older snapshots keep what they saw.
	if got := stored(t, s, r4, f); len(got) != 2 || !got["doc:b#viewer@user:x"].IsZero() {
		t.Fatalf("head after expiry: %v", got)
	}
	for _, rev := range []Revision{r2, r3} {
		if got := direct(t, s, rev, "doc", "a", "viewer"); len(got) != 1 {
			t.Fatalf("revision %d lost the relationship: %v", rev, got)
		}
	}
	if ids, _ := s.ObjectIDs(r4, "doc"); strings.Join(ids, ",") != "b,c" {
		t.Fatalf("object IDs after expiry: %v", ids)
	}
	if ids, _ := s.ObjectIDs(r3, "doc"); strings.Join(ids, ",") != "a,b" {
		t.Fatalf("object IDs before expiry: %v", ids)
	}
	// The clock alone does not change a snapshot: the head keeps its commit
	// time however far the clock moves.
	c.Advance(time.Hour)
	if got := direct(t, s, r3, "doc", "a", "viewer"); len(got) != 1 {
		t.Fatalf("snapshot changed with the clock: %v", got)
	}
	// Watch carries the expiry the touch set.
	changes, err := s.Changes(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 3 || !changes[0].ExpiresAt.Equal(exp) || !changes[1].ExpiresAt.IsZero() {
		t.Fatalf("changes: %+v", changes)
	}
}

func TestExpiryWriteSemantics(t *testing.T) {
	c := clock.NewFake(t0)
	s := clockStore(t, "", c, 0)
	withSchema(t, s)
	rel := "doc:a#viewer@user:x"
	exp := t0.Add(time.Minute)
	r2 := expiring(t, s, OpCreate, rel, exp)

	// Create fails while it exists, touching with the same expiry is a no-op
	// and touching with another one replaces it in a new revision.
	if _, err := s.Write([]Update{{Op: OpCreate, Relationship: mustRel(t, rel)}}, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("create over a live relationship: %v", err)
	}
	if rev := expiring(t, s, OpTouch, rel, exp.In(time.FixedZone("x", 3600))); rev != r2 {
		t.Fatalf("touch with the same expiry made revision %d", rev)
	}
	later := exp.Add(time.Hour)
	r3 := expiring(t, s, OpTouch, rel, later)
	if r3 != r2+1 {
		t.Fatalf("touch with a new expiry: revision %d", r3)
	}
	f := Filter{ResourceType: "doc"}
	if got := stored(t, s, r2, f)[rel]; !got.Equal(exp) {
		t.Fatalf("old snapshot sees expiry %v", got)
	}
	if got := stored(t, s, r3, f)[rel]; !got.Equal(later) {
		t.Fatalf("new snapshot sees expiry %v", got)
	}
	// Touching without an expiry makes it permanent.
	r4 := write(t, s, OpTouch, rel)
	c.Set(later.Add(time.Hour))
	r5 := write(t, s, OpTouch, "doc:z#viewer@user:x")
	if got, ok := stored(t, s, r5, f)[rel]; !ok || !got.IsZero() {
		t.Fatalf("permanent relationship at %d: %v %v", r4, got, ok)
	}

	// Once expired, it is gone for writes too: delete is a no-op, create
	// succeeds, and a precondition no longer finds it.
	other := "doc:b#viewer@user:y"
	expiring(t, s, OpTouch, other, c.Now().Add(time.Second))
	c.Advance(time.Second)
	head := s.Head()
	if rev := write(t, s, OpDelete, other); rev != head {
		t.Fatalf("deleting an expired relationship made revision %d", rev)
	}
	must := []Precondition{{MustExist: true, Filter: Filter{ResourceType: "doc", ResourceID: "b"}}}
	if _, err := s.Write([]Update{{Op: OpTouch, Relationship: mustRel(t, "doc:q#viewer@user:x")}}, must); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("precondition matched an expired relationship: %v", err)
	}
	if res, err := s.DeleteByFilter(DeleteRequest{Filter: Filter{ResourceType: "doc", ResourceID: "b"}}); err != nil || res.Deleted != 0 {
		t.Fatalf("delete by filter of an expired relationship: %+v %v", res, err)
	}
	r6 := expiring(t, s, OpCreate, other, c.Now().Add(time.Minute))
	if got := direct(t, s, r6, "doc", "b", "viewer"); len(got) != 1 {
		t.Fatalf("recreated relationship: %v", got)
	}
	// Delete by filter reports deletes without the expiry.
	res, err := s.DeleteByFilter(DeleteRequest{Filter: Filter{ResourceType: "doc", ResourceID: "b"}})
	if err != nil || res.Deleted != 1 {
		t.Fatalf("delete by filter: %+v %v", res, err)
	}
	changes, _ := s.Changes(res.Revision-1, 0)
	if len(changes) != 1 || changes[0].Op != OpDelete || !changes[0].ExpiresAt.IsZero() {
		t.Fatalf("delete change: %+v", changes)
	}
}

func TestExpiryValidation(t *testing.T) {
	s := clockStore(t, "", clock.NewFake(t0), 0)
	withSchema(t, s)
	for _, at := range []time.Time{time.Unix(0, 0), time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC)} {
		_, err := s.Write([]Update{{Op: OpTouch, Relationship: mustRel(t, "doc:a#viewer@user:x"), ExpiresAt: at}}, nil)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("expires_at %v: %v", at, err)
		}
	}
	// An expiry already in the past is accepted and never visible.
	rev := expiring(t, s, OpTouch, "doc:a#viewer@user:x", t0.Add(-time.Hour))
	if got := direct(t, s, rev, "doc", "a", "viewer"); len(got) != 0 {
		t.Fatalf("already-expired relationship is visible: %v", got)
	}
	// A delete ignores the expiry, but it must still be in range.
	if _, err := s.Write([]Update{{Op: OpDelete, Relationship: mustRel(t, "doc:a#viewer@user:x"), ExpiresAt: time.Unix(0, 0)}}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("delete with an out-of-range expiry: %v", err)
	}
}

func TestExpiredRelationshipsDoNotBlockSchemaChanges(t *testing.T) {
	c := clock.NewFake(t0)
	s := clockStore(t, "", c, 0)
	withSchema(t, s)
	expiring(t, s, OpTouch, "doc:a#owner@user:x", t0.Add(time.Second))
	noOwner := strings.Replace(testSchema, "relation owner: user\n", "", 1)
	noOwner = strings.Replace(noOwner, "viewer + owner", "viewer", 1)
	if _, err := s.WriteSchema(noOwner); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("schema change over a live relationship: %v", err)
	}
	c.Advance(time.Second)
	dry, err := s.DryRunSchema(noOwner, 0)
	if err != nil || dry.BrokenCount != 0 {
		t.Fatalf("dry run after expiry: %+v %v", dry, err)
	}
	if _, err := s.WriteSchema(noOwner); err != nil {
		t.Fatalf("schema change after expiry: %v", err)
	}
}

func TestExpiredVersionsAreCollected(t *testing.T) {
	c := clock.NewFake(t0)
	s := clockStore(t, "", c, 10)
	withSchema(t, s)
	r := expiring(t, s, OpTouch, "doc:gone#viewer@user:x", t0.Add(time.Second))
	expiring(t, s, OpTouch, "doc:kept#viewer@user:x", t0.Add(time.Hour))
	expiring(t, s, OpTouch, "doc:kept#viewer@user:y", t0.Add(time.Second))
	expiring(t, s, OpTouch, "doc:kept#viewer@user:y", t0.Add(2*time.Hour)) // replaced before it expired
	c.Advance(time.Second)
	for range 2 * gcEvery {
		write(t, s, OpTouch, "doc:busy#viewer@user:x")
		write(t, s, OpDelete, "doc:busy#viewer@user:x")
	}
	if s.MinRevision() <= r {
		t.Fatalf("history at %d still reaches revision %d", s.MinRevision(), r)
	}
	s.mu.RLock()
	_, gone := s.byType["doc"]["gone#viewer"]
	kept := len(s.byType["doc"]["kept#viewer"])
	yVersions := len(s.byType["doc"]["kept#viewer"]["user:y"].versions)
	open := s.expiring
	s.mu.RUnlock()
	if gone || kept != 2 || yVersions != 1 {
		t.Fatalf("after collection: gone kept=%v, kept entries %d, user:y versions %d", gone, kept, yVersions)
	}
	if open != 2 {
		t.Fatalf("%d open expiring versions counted, want 2", open)
	}
}

func TestExpiryRecovery(t *testing.T) {
	dir := t.TempDir()
	c := clock.NewFake(t0)
	s := clockStore(t, dir, c, 0)
	withSchema(t, s)
	write(t, s, OpTouch, "doc:p#viewer@user:x")
	// A store that never held an expiry writes no commit times.
	log, err := os.ReadFile(filepath.Join(dir, walName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), `"time"`) {
		t.Fatalf("log of a store without expiries has commit times:\n%s", log)
	}
	c.Advance(time.Second)
	expiring(t, s, OpTouch, "doc:a#viewer@user:x", t0.Add(2*time.Second))
	expiring(t, s, OpTouch, "doc:b#viewer@user:x", t0.Add(time.Hour))
	c.Advance(2 * time.Second)
	head := write(t, s, OpTouch, "doc:c#viewer@user:x")
	headAt := revTime(t, s, head)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Recovery replays the times: the head keeps its commit time, doc:a has
	// expired there and is left out of the checkpoint, doc:b keeps its
	// expiry.
	behind := clock.NewFake(t0.Add(-time.Hour)) // a clock behind the log does not revive doc:a
	s2 := clockStore(t, dir, behind, 0)
	if got := revTime(t, s2, head); !got.Equal(headAt) {
		t.Fatalf("head time after recovery %v, want %v", got, headAt)
	}
	got := stored(t, s2, head, Filter{ResourceType: "doc"})
	if len(got) != 3 || !got["doc:b#viewer@user:x"].Equal(t0.Add(time.Hour)) || !got["doc:p#viewer@user:x"].IsZero() {
		t.Fatalf("recovered %v", got)
	}
	r := write(t, s2, OpTouch, "doc:d#viewer@user:x")
	if got := direct(t, s2, r, "doc", "a", "viewer"); len(got) != 0 {
		t.Fatalf("expired relationship came back: %v", got)
	}
	if ck, _ := os.ReadFile(filepath.Join(dir, walName)); strings.Contains(string(ck), "doc:a") || !strings.Contains(string(ck), `"expiring"`) {
		t.Fatalf("checkpoint:\n%s", ck)
	}
	s2.Close()

	// And again from the checkpoint: doc:b expires on the restored clock.
	s3 := clockStore(t, dir, clock.NewFake(t0.Add(time.Hour)), 0)
	r = write(t, s3, OpTouch, "doc:e#viewer@user:x")
	if got := direct(t, s3, r, "doc", "b", "viewer"); len(got) != 0 {
		t.Fatalf("doc:b outlived its expiry: %v", got)
	}
	if got := direct(t, s3, r, "doc", "c", "viewer"); len(got) != 1 {
		t.Fatalf("doc:c lost: %v", got)
	}
}

func TestBadExpiringCheckpointIsRefused(t *testing.T) {
	for name, line := range map[string]walRecord{
		"no expiry":            {Rev: 1, Type: recCheckpoint, Expiring: []expiringRel{{Relationship: Relationship{ResourceType: "doc", ResourceID: "a", Relation: "viewer", SubjectType: "user", SubjectID: "x"}}}},
		"invalid relationship": {Rev: 1, Type: recCheckpoint, Expiring: []expiringRel{{Relationship: Relationship{ResourceType: "doc"}, ExpiresAt: 1}}},
		"invalid write":        {Rev: 1, Type: recWrite, Changes: []Change{{Revision: 1, Op: OpTouch, Relationship: Relationship{ResourceType: "Doc"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			b, err := encodeRecord(line)
			if err != nil {
				t.Fatal(err)
			}
			// A second record makes the bad one not the torn tail.
			next, _ := encodeRecord(walRecord{Rev: 2, Type: recSchema, Schema: testSchema})
			if err := os.WriteFile(filepath.Join(dir, walName), append(b, next...), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(Options{Dir: dir}); err == nil {
				t.Fatal("opened a log with a bad record")
			}
		})
	}
}
