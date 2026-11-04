package keys

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/jose"
)

var hourly = Policy{RotateEvery: time.Hour, Overlap: 2 * time.Hour}

func newRing(t testing.TB, alg Alg, p Policy) *Ring {
	t.Helper()
	r, err := NewRing(alg, p, t0)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPolicyCheck(t *testing.T) {
	ok := []Policy{{}, {Overlap: time.Hour}, hourly, {RotateEvery: time.Second, Overlap: 15 * time.Second}}
	for _, p := range ok {
		if err := p.Check(); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := []Policy{
		{RotateEvery: -1},
		{Overlap: -1},
		{RotateEvery: time.Millisecond, Overlap: time.Second},
		{RotateEvery: time.Hour},
		{RotateEvery: time.Second, Overlap: 16 * time.Second},
	}
	for _, p := range bad {
		if err := p.Check(); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
}

func TestRingRoles(t *testing.T) {
	r := newRing(t, ES256, hourly)
	if r.Alg() != ES256 || r.Policy() != hourly {
		t.Fatal("alg or policy")
	}
	cur, next := r.Current(), r.Next()
	if cur == nil || next == nil || cur.ID() == next.ID() {
		t.Fatal("NewRing must make distinct current and next keys")
	}
	if r.Lookup(cur.ID(), t0) != cur || r.Lookup(next.ID(), t0) != next || r.Lookup("nope", t0) != nil {
		t.Error("Lookup")
	}
	if r.Due(t0.Add(59*time.Minute)) || !r.Due(t0.Add(time.Hour)) {
		t.Error("Due")
	}

	kid, sig, err := r.Sign([]byte("m"))
	if err != nil || kid != cur.ID() {
		t.Fatalf("Sign %s %v", kid, err)
	}
	at := t0.Add(time.Hour)
	if err := r.Rotate(at); err != nil {
		t.Fatal(err)
	}
	if r.Current() != next || r.Next() == nil || r.Next() == next {
		t.Fatal("rotation must make next current and generate a new next")
	}
	s := r.Snapshot()
	if !s.Activated.Equal(at) || len(s.Previous) != 1 || s.Previous[0].Key != cur || !s.Previous[0].Until.Equal(at.Add(2*time.Hour)) {
		t.Fatalf("snapshot %+v", s)
	}
	// The retired key verifies inside the overlap and not after it.
	if err := r.Verify(kid, []byte("m"), sig, at.Add(2*time.Hour-time.Nanosecond)); err != nil {
		t.Errorf("inside overlap: %v", err)
	}
	if err := r.Verify(kid, []byte("m"), sig, at.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Errorf("after overlap: %v", err)
	}
	if err := r.Verify(kid, []byte("x"), sig, at); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("wrong message: %v", err)
	}
	if got := r.Verifying(at); len(got) != 3 || got[0] != next || got[1] != cur || got[2] != r.Next() {
		t.Errorf("Verifying inside overlap: %v", got)
	}
	if got := r.Verifying(at.Add(3 * time.Hour)); len(got) != 2 {
		t.Errorf("Verifying after overlap: %d keys", len(got))
	}
	if r.Prune(at.Add(time.Hour)) {
		t.Error("Prune dropped a key inside its overlap")
	}
	if !r.Prune(at.Add(2*time.Hour)) || len(r.Snapshot().Previous) != 0 {
		t.Error("Prune kept an expired key")
	}
	if r.Prune(at.Add(5 * time.Hour)) {
		t.Error("Prune reported a change with nothing to drop")
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	r := newRing(t, HS256, hourly)
	_ = r.Rotate(t0.Add(time.Hour))
	s := r.Snapshot()
	s.Previous[0].Key = nil
	if r.Snapshot().Previous[0].Key == nil {
		t.Error("Snapshot shares the ring's slice")
	}
}

func TestRotateKeepsAtMostMaxPrevious(t *testing.T) {
	p := Policy{RotateEvery: time.Second, Overlap: MaxPrevious * time.Second}
	r := newRing(t, HS256, p)
	at := t0
	for i := 0; i < MaxPrevious+5; i++ {
		// Rotating faster than the schedule keeps every retired key alive.
		at = at.Add(time.Millisecond)
		if err := r.Rotate(at); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(r.Snapshot().Previous); n != MaxPrevious {
		t.Fatalf("%d previous keys, want %d", n, MaxPrevious)
	}
}

func TestManualRingWithoutOverlapKeepsRetiredKeys(t *testing.T) {
	r := newRing(t, EdDSA, Policy{})
	old := r.Current()
	if r.Due(t0.Add(1000 * time.Hour)) {
		t.Error("a ring without a schedule is never due")
	}
	_ = r.Rotate(t0)
	if p := r.Snapshot().Previous; len(p) != 1 || !p[0].Until.IsZero() {
		t.Fatalf("previous %+v", p)
	}
	if r.Lookup(old.ID(), t0.Add(1000*time.Hour)) != old {
		t.Error("a retired key without expiry stopped verifying")
	}
}

func TestDrop(t *testing.T) {
	r := newRing(t, HS256, hourly)
	a := r.Current()
	_ = r.Rotate(t0)
	b := r.Current()
	_ = r.Rotate(t0)
	if err := r.Drop(a.ID()); err != nil {
		t.Fatal(err)
	}
	if r.Lookup(a.ID(), t0) != nil || r.Lookup(b.ID(), t0) != b {
		t.Error("Drop removed the wrong key")
	}
	if err := r.Drop(r.Current().ID()); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Drop(current) = %v", err)
	}
	if err := r.Drop(r.Next().ID()); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Drop(next) = %v", err)
	}
	if err := r.Drop("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Drop(unknown) = %v", err)
	}
}

func TestConfiguredRing(t *testing.T) {
	a, b := mustGen(t, A256GCM), mustGen(t, A256GCM)
	r, err := Configured(Policy{}, t0, a, b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Current() != a || r.Next() != nil || r.Lookup(b.ID(), t0.Add(1e6*time.Hour)) != b {
		t.Fatal("configured ring roles")
	}
	if got := r.Verifying(t0); len(got) != 2 {
		t.Errorf("Verifying %d", len(got))
	}
	// The first rotation of a configured ring generates current and next.
	if err := r.Rotate(t0); err != nil {
		t.Fatal(err)
	}
	if r.Current() == a || r.Current() == b || r.Next() == nil || len(r.Snapshot().Previous) != 2 {
		t.Fatalf("after rotation %+v", r.Snapshot())
	}
	if _, err := Configured(Policy{}, t0); err == nil {
		t.Error("Configured with no keys")
	}
}

func TestRestoreRefuses(t *testing.T) {
	h, h2, e := mustGen(t, HS256), mustGen(t, HS256), mustGen(t, ES256)
	many := make([]Retired, MaxPrevious+1)
	for i := range many {
		many[i] = Retired{Key: mustGen(t, HS256)}
	}
	cases := map[string]struct {
		alg Alg
		p   Policy
		s   Snapshot
	}{
		"bad alg":       {"HS1", Policy{}, Snapshot{Current: h}},
		"bad policy":    {HS256, Policy{RotateEvery: time.Hour}, Snapshot{Current: h}},
		"no current":    {HS256, Policy{}, Snapshot{}},
		"wrong alg":     {HS256, Policy{}, Snapshot{Current: e}},
		"wrong next":    {HS256, Policy{}, Snapshot{Current: h, Next: e}},
		"dup next":      {HS256, Policy{}, Snapshot{Current: h, Next: h}},
		"nil previous":  {HS256, Policy{}, Snapshot{Current: h, Previous: []Retired{{}}}},
		"dup previous":  {HS256, Policy{}, Snapshot{Current: h, Next: h2, Previous: []Retired{{Key: h2}}}},
		"too many prev": {HS256, Policy{}, Snapshot{Current: h, Previous: many}},
	}
	for name, tc := range cases {
		if _, err := Restore(tc.alg, tc.p, tc.s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := NewRing("nope", Policy{}, t0); !errors.Is(err, ErrAlg) {
		t.Errorf("NewRing(nope) = %v", err)
	}
	if _, err := NewRing(HS256, Policy{RotateEvery: time.Hour}, t0); err == nil {
		t.Error("NewRing with a bad policy")
	}
}

var errGen = errors.New("entropy ran out")

func failAfter(n int) func(Alg, time.Time) (*Key, error) {
	var calls atomic.Int32
	return func(a Alg, at time.Time) (*Key, error) {
		if int(calls.Add(1)) > n {
			return nil, errGen
		}
		return Generate(a, at)
	}
}

func TestRotateGenerationFailureKeepsState(t *testing.T) {
	r := newRing(t, HS256, hourly)
	before := r.Snapshot()
	r.gen = failAfter(0)
	if err := r.Rotate(t0); !errors.Is(err, errGen) {
		t.Fatalf("Rotate = %v", err)
	}
	if r.Current() != before.Current || r.Next() != before.Next {
		t.Error("a failed rotation changed the ring")
	}
	c := mustConfigured(t, mustGen(t, HS256))
	c.gen = failAfter(0)
	if err := c.Rotate(t0); !errors.Is(err, errGen) {
		t.Errorf("configured Rotate = %v", err)
	}
	c.gen = failAfter(1)
	if err := c.Rotate(t0); !errors.Is(err, errGen) {
		t.Errorf("configured Rotate, second key = %v", err)
	}
}

func TestLookupDoesNotAllocate(t *testing.T) {
	r := newRing(t, HS256, hourly)
	_ = r.Rotate(t0)
	kid := r.Snapshot().Previous[0].Key.ID()
	if n := testing.AllocsPerRun(1000, func() {
		if r.Lookup(kid, t0) == nil || r.Current() == nil {
			panic("missing")
		}
	}); n != 0 {
		t.Errorf("Lookup allocates %.0f times", n)
	}
}

// Signers on every ring keep signing while the rings rotate as fast as the
// policy allows; every signature verifies by its kid until the overlap
// ends, and nothing fails in between. The fake clock moves only after every
// signer has finished a whole sign-and-verify started since the last tick,
// so no signature is older than two ticks (1 s) when it is checked: the
// overlap of 3 s must cover that, as it must cover a token's lifetime.
func TestRotationUnderLoad(t *testing.T) {
	set := NewSet()
	p := Policy{RotateEvery: time.Second, Overlap: 3 * time.Second}
	for _, alg := range []Alg{EdDSA, ES256, HS256} {
		if err := set.Add(strings.ToLower(string(alg)), newRing(t, alg, p)); err != nil {
			t.Fatal(err)
		}
	}
	var clock atomic.Int64
	clock.Store(t0.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var signed, failed atomic.Int64
	var done [12]atomic.Int64
	for n, name := range set.Names() {
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func(r *Ring, w int, done *atomic.Int64) {
				defer wg.Done()
				for i := 0; ctx.Err() == nil; i++ {
					msg := []byte(fmt.Sprintf("%d-%d", w, i))
					kid, sig, err := r.Sign(msg)
					if err == nil {
						err = r.Verify(kid, msg, sig, now())
					}
					if err != nil {
						failed.Add(1)
						t.Errorf("%s: %v", r.Alg(), err)
						return
					}
					signed.Add(1)
					done.Add(1)
				}
			}(set.Ring(name), w, &done[4*n+w])
		}
	}
	rotations := 0
	for i := 0; i < 24; i++ {
		var marks [len(done)]int64
		for j := range done {
			marks[j] = done[j].Load()
		}
		deadline := time.Now().Add(10 * time.Second)
		for j := range done {
			for done[j].Load() < marks[j]+2 && failed.Load() == 0 {
				if time.Now().After(deadline) {
					t.Fatal("a signer made no progress for 10 s")
				}
				runtime.Gosched()
			}
		}
		clock.Add(int64(500 * time.Millisecond))
		before := set.Ring("hs256").Current()
		if _, err := set.Tick(now()); err != nil {
			t.Fatal(err)
		}
		if set.Ring("hs256").Current() != before {
			rotations++
		}
	}
	cancel()
	wg.Wait()
	if failed.Load() != 0 || signed.Load() == 0 || rotations != 12 {
		t.Fatalf("signed %d, failed %d, rotations %d", signed.Load(), failed.Load(), rotations)
	}
	ks, err := jose.ParseKeySet(set.JWKS(now()))
	if err != nil {
		t.Fatal(err)
	}
	// Current, next and the retired keys inside a 3 s overlap rotating every
	// second, for the two asymmetric rings.
	if len(ks.Keys) < 6 || len(ks.Keys) > 10 {
		t.Errorf("JWKS holds %d keys", len(ks.Keys))
	}
}

func BenchmarkLookup(b *testing.B) {
	r := newRing(b, HS256, hourly)
	_ = r.Rotate(t0)
	kid := r.Snapshot().Previous[0].Key.ID()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if r.Lookup(kid, t0) == nil {
				b.Fatal("missing")
			}
		}
	})
}

func BenchmarkSign(b *testing.B) {
	msg := []byte("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9")
	for _, alg := range []Alg{EdDSA, ES256, RS256, HS256} {
		b.Run(string(alg), func(b *testing.B) {
			k := mustGen(b, alg)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := k.Sign(msg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
