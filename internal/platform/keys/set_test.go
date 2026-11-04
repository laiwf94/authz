package keys

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/jose"
)

func TestSetAdd(t *testing.T) {
	s := NewSet()
	r := newRing(t, HS256, hourly)
	for _, name := range []string{RingSession, RingUpstream, RingConsistency, RingAgent} {
		if err := s.Add(name, r); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Join(s.Names(), ","); got != "session,upstream,consistency,agent" {
		t.Errorf("Names %s", got)
	}
	if s.Ring(RingAgent) != r || s.Ring("other") != nil {
		t.Error("Ring")
	}
	for _, name := range []string{"", "Upper", "1st", "has space", strings.Repeat("a", 33)} {
		if err := s.Add(name, r); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	if err := s.Add("agent", r); err == nil {
		t.Error("duplicate name accepted")
	}
	if err := s.Add("nil", nil); err == nil {
		t.Error("nil ring accepted")
	}
}

func TestSetTick(t *testing.T) {
	s := NewSet()
	fast := newRing(t, HS256, Policy{RotateEvery: time.Minute, Overlap: time.Minute})
	slow := newRing(t, ES256, hourly)
	_ = slow.Rotate(t0) // a retired key that expires at t0+2h
	static := mustConfigured(t, mustGen(t, A256GCM))
	_ = s.Add("fast", fast)
	_ = s.Add("slow", slow)
	_ = s.Add("static", static)

	if changed, err := s.Tick(t0.Add(30 * time.Second)); err != nil || len(changed) != 0 {
		t.Fatalf("early tick %v %v", changed, err)
	}
	if changed, err := s.Tick(t0.Add(time.Minute)); err != nil || strings.Join(changed, ",") != "fast" {
		t.Fatalf("tick at 1m %v %v", changed, err)
	}
	// At 2h fast rotates again (its last rotation was at 1m), slow is due
	// too, and the static ring never changes.
	changed, err := s.Tick(t0.Add(2 * time.Hour))
	if err != nil || strings.Join(changed, ",") != "fast,slow" {
		t.Fatalf("tick at 2h %v %v", changed, err)
	}
	// Slow's retired key from t0 is pruned on a tick where it isn't due.
	slow2 := newRing(t, ES256, hourly)
	_ = slow2.Rotate(t0)
	s2 := NewSet()
	_ = s2.Add("slow", slow2)
	if changed, _ := s2.Tick(t0.Add(30 * time.Minute)); len(changed) != 0 {
		t.Errorf("tick inside overlap %v", changed)
	}
	slow2.policy.RotateEvery = 10 * time.Hour
	if changed, _ := s2.Tick(t0.Add(2 * time.Hour)); strings.Join(changed, ",") != "slow" || len(slow2.Snapshot().Previous) != 0 {
		t.Errorf("prune tick %v", changed)
	}
}

func TestSetTickReportsFailuresAndContinues(t *testing.T) {
	s := NewSet()
	bad := newRing(t, HS256, hourly)
	bad.gen = failAfter(0)
	good := newRing(t, HS256, hourly)
	_ = s.Add("bad", bad)
	_ = s.Add("good", good)
	changed, err := s.Tick(t0.Add(time.Hour))
	if !errors.Is(err, errGen) || !strings.Contains(err.Error(), "ring bad") {
		t.Errorf("err %v", err)
	}
	if strings.Join(changed, ",") != "good" {
		t.Errorf("changed %v", changed)
	}
}

func TestJWKSRoles(t *testing.T) {
	r := newRing(t, EdDSA, hourly)
	old := r.Current()
	_ = r.Rotate(t0)
	cur, next := r.Current(), r.Next()
	ids := func(at time.Time) []string {
		ks, err := jose.ParseKeySet(JWKS(at, r, newRing(t, HS256, hourly)))
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, k := range ks.Keys {
			out = append(out, k.ID)
		}
		return out
	}
	if got := strings.Join(ids(t0), ","); got != cur.ID()+","+next.ID()+","+old.ID() {
		t.Errorf("JWKS inside overlap: %s", got)
	}
	if got := strings.Join(ids(t0.Add(2*time.Hour)), ","); got != cur.ID()+","+next.ID() {
		t.Errorf("JWKS after overlap: %s", got)
	}
	if string(JWKS(t0)) != `{"keys":[]}` {
		t.Errorf("empty JWKS %s", JWKS(t0))
	}
	static := mustConfigured(t, mustGen(t, ES256), mustGen(t, ES256))
	if ks, _ := jose.ParseKeySet(JWKS(t0.Add(1e5*time.Hour), static)); len(ks.Keys) != 2 {
		t.Error("configured previous keys must stay published")
	}
}

func TestSchedulerTicks(t *testing.T) {
	s := NewSet()
	r := newRing(t, HS256, Policy{RotateEvery: time.Minute, Overlap: time.Minute})
	_ = s.Add("agent", r)
	ticks := make(chan time.Time)
	var at atomic.Int64
	at.Store(t0.UnixNano())
	got := make(chan []string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	sc := &Scheduler{Set: s, Ticks: ticks, Now: func() time.Time { return time.Unix(0, at.Load()) },
		OnChange: func(c []string) error { got <- c; return nil }}
	go func() { done <- sc.Run(ctx) }()
	ticks <- time.Time{} // not due: no change
	at.Add(int64(time.Minute))
	ticks <- time.Time{}
	if c := <-got; strings.Join(c, ",") != "agent" {
		t.Errorf("changed %v", c)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run = %v", err)
	}
	if len(got) != 0 {
		t.Error("OnChange called for a tick that changed nothing")
	}
}

func TestSchedulerErrors(t *testing.T) {
	s := NewSet()
	r := newRing(t, HS256, Policy{RotateEvery: time.Second, Overlap: time.Second})
	_ = s.Add("agent", r)
	errSave := errors.New("disk full")
	ticks := make(chan time.Time, 1)
	clock := t0
	now := func() time.Time { clock = clock.Add(time.Second); return clock }

	// Without OnError the first failure stops Run.
	ticks <- time.Time{}
	sc := &Scheduler{Set: s, Ticks: ticks, Now: now, OnChange: func([]string) error { return errSave }}
	if err := sc.Run(context.Background()); !errors.Is(err, errSave) {
		t.Fatalf("Run = %v", err)
	}

	// With OnError failures are reported and Run keeps going.
	r.gen = failAfter(0)
	reported := make(chan error, 2)
	ctx, cancel := context.WithCancel(context.Background())
	sc = &Scheduler{Set: s, Ticks: ticks, Now: now, OnError: func(err error) { reported <- err }}
	done := make(chan error)
	go func() { done <- sc.Run(ctx) }()
	ticks <- time.Time{}
	ticks <- time.Time{}
	for i := 0; i < 2; i++ {
		if err := <-reported; !errors.Is(err, errGen) {
			t.Errorf("reported %v", err)
		}
	}
	cancel()
	<-done
}

func TestSchedulerRealTicker(t *testing.T) {
	s := NewSet()
	r := newRing(t, HS256, Policy{RotateEvery: time.Second, Overlap: time.Second})
	_ = s.Add("agent", r)
	first := r.Current()
	changed := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := t0
	sc := &Scheduler{Set: s, Every: time.Millisecond, Now: func() time.Time { clock = clock.Add(time.Second); return clock },
		OnChange: func([]string) error {
			select {
			case changed <- struct{}{}:
			default:
			}
			return nil
		}}
	go func() { _ = sc.Run(ctx) }()
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("the ticker never rotated the ring")
	}
	if r.Current() == first {
		t.Error("ring did not rotate")
	}
	// Every <= 0 falls back to one second; Now nil is the wall clock.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel2()
	if err := (&Scheduler{Set: NewSet()}).Run(ctx2); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Run = %v", err)
	}
}
