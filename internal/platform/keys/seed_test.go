package keys

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/clock"
)

func TestEnsureSeedsMissingRing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	fc := clock.NewFake(t0)
	f := openFile(t, path, fc)
	a, _ := Generate(ES256, t0.Add(-time.Hour))
	b, _ := Generate(ES256, t0.Add(-2*time.Hour))
	sp := specUp
	sp.Seed = []*Key{a, b}
	rings, err := f.Ensure(sp)
	if err != nil {
		t.Fatal(err)
	}
	r := rings[0]
	if r.Current() != a || r.Next() == nil || r.Next() == a || r.Next() == b {
		t.Fatalf("seeded ring: current %s next %v", r.Current().ID(), r.Next())
	}
	if r.Lookup(b.ID(), t0.Add(daily.Overlap-time.Second)) != b {
		t.Fatal("retired seed key does not verify inside the overlap")
	}
	if r.Lookup(b.ID(), t0.Add(daily.Overlap)) != nil {
		t.Fatal("retired seed key verifies after the overlap")
	}
	// The seeded ring is saved: a reopened file holds the same keys.
	g := openFile(t, path, fc)
	got := g.Set().Ring(RingUpstream)
	if got == nil || got.Current().ID() != a.ID() || got.Next().ID() != r.Next().ID() || len(got.Snapshot().Previous) != 1 {
		t.Fatalf("reopened ring %+v", got)
	}
	// A ring the file holds ignores its seed.
	c, _ := Generate(ES256, t0)
	sp.Seed = []*Key{c}
	again, err := g.Ensure(sp)
	if err != nil || again[0].Current().ID() != a.ID() {
		t.Fatalf("Ensure on a held ring took the seed: %v", err)
	}
	// The ring rotates on schedule like any other: the seed key retires.
	fc.Advance(daily.RotateEvery)
	if changed, err := f.Check(); err != nil || len(changed) != 1 {
		t.Fatalf("Check: %v %v", changed, err)
	}
	if r.Current() == a || r.Lookup(a.ID(), fc.Now()) != a {
		t.Fatal("the seed key did not retire with an overlap")
	}
}

func TestSeeded(t *testing.T) {
	a, _ := Generate(HS256, t0)
	b, _ := Generate(HS256, t0)
	r, err := Seeded(HS256, Policy{}, t0, a, b)
	if err != nil {
		t.Fatal(err)
	}
	if p := r.Snapshot().Previous; len(p) != 1 || !p[0].Until.IsZero() {
		t.Fatalf("no overlap should retire seeds with no expiry: %+v", p)
	}
	if _, err := Seeded(HS256, Policy{}, t0); err == nil {
		t.Error("no seed keys accepted")
	}
	if _, err := Seeded(ES256, daily, t0, a); err == nil {
		t.Error("an HS256 seed accepted on an ES256 ring")
	}
	if _, err := Seeded(HS256, daily, t0, a, a); err == nil {
		t.Error("a repeated seed key accepted")
	}
	many := make([]*Key, MaxPrevious+2)
	for i := range many {
		many[i], _ = Generate(HS256, t0)
	}
	if _, err := Seeded(HS256, daily, t0, many...); err == nil {
		t.Error("too many seed keys accepted")
	}
	if _, err := Seeded(Alg("none"), daily, t0, a); err == nil {
		t.Error("a bad alg accepted")
	}
	f := openFile(t, filepath.Join(t.TempDir(), "k.json"), clock.NewFake(t0))
	if _, err := f.Ensure(Spec{Name: RingAgent, Alg: HS256, Policy: daily, Seed: []*Key{a, a}}); err == nil {
		t.Error("Ensure accepted a bad seed")
	}
	if len(f.Set().Names()) != 0 {
		t.Error("a refused seed changed the set")
	}
}

// The channel Start returns closes only once its context has ended and the
// last user's rotations have stopped.
func TestStartStopped(t *testing.T) {
	f := openFile(t, filepath.Join(t.TempDir(), "keys.json"), clock.NewFake(t0))
	a, stopA := context.WithCancel(context.Background())
	b, stopB := context.WithCancel(context.Background())
	sa, sb := f.Start(a), f.Start(b)
	stopA()
	<-sa
	select {
	case <-sb:
		t.Fatal("closed before its context ended")
	default:
	}
	f.mu.Lock()
	running := f.users
	f.mu.Unlock()
	if running != 1 {
		t.Fatalf("%d users after the first stopped", running)
	}
	stopB()
	<-sb
	f.mu.Lock()
	done := f.done
	f.mu.Unlock()
	select {
	case <-done:
	default:
		t.Fatal("rotations still running after the last user stopped")
	}
}
