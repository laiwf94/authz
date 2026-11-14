package part

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/enginetest"
	"github.com/laiwf94/authz/internal/authz/store"
)

func TestEngineAlone(t *testing.T) {
	var h Host
	h.ProvideEngine(newFake(t, enginetest.SharingSchema)) // nothing to hand it to
	if e, err := h.Engine(context.Background()); e != nil || !errors.Is(err, ErrNoEngine) {
		t.Fatalf("a subcommand alone: %v %v, want ErrNoEngine", e, err)
	}
}

// Parts asking before serve has its engine wait for it, all get the same
// one, and a check through it answers as the engine does.
func TestEngineWaitsForServe(t *testing.T) {
	s := NewEngines()
	h := Host{Engines: s}
	fake := newFake(t, enginetest.SharingSchema, enginetest.SharingRelationships...)
	const waiters = 8
	got := make(chan engine.Engine, waiters)
	var wg sync.WaitGroup
	for range waiters {
		wg.Go(func() {
			e, err := h.Engine(context.Background())
			if err != nil {
				t.Error(err)
			}
			got <- e
		})
	}
	select {
	case e := <-got:
		t.Fatalf("Engine returned %v before serve provided one", e)
	case <-time.After(20 * time.Millisecond):
	}
	h.ProvideEngine(fake)
	wg.Wait()
	close(got)
	for e := range got {
		if e != engine.Engine(fake) {
			t.Fatalf("a waiter got %v, not serve's engine", e)
		}
	}
	// A later Provide does not replace the engine the parts hold.
	s.Provide(newFake(t, enginetest.SharingSchema))
	e, err := h.Engine(context.Background())
	if err != nil || e != engine.Engine(fake) {
		t.Fatalf("after a second Provide: %v %v", e, err)
	}
	res, err := e.Check(context.Background(), engine.CheckRequest{ResourceType: "doc", ResourceID: "readme",
		Permission: "view", Subject: store.Subject{Type: "user", ID: "anyone"}})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := fake.Check(context.Background(), engine.CheckRequest{ResourceType: "doc", ResourceID: "readme",
		Permission: "view", Subject: store.Subject{Type: "user", ID: "anyone"}})
	if res != want {
		t.Fatalf("check through the Host: %+v, want %+v", res, want)
	}
}

func TestEngineWaitEndsWithContext(t *testing.T) {
	h := Host{Engines: NewEngines()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if e, err := h.Engine(ctx); e != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v %v, want the context's error", e, err)
	}
}

func TestEngineStop(t *testing.T) {
	boom := errors.New("GRANTD_TOKEN_KEY is bad")
	for _, tc := range []struct {
		name    string
		provide bool
		err     error
		want    string
	}{
		{"before provide, failed", false, boom, "the in-process engine stopped: GRANTD_TOKEN_KEY is bad"},
		{"before provide, clean", false, nil, "the in-process engine stopped"},
		{"after provide, clean", true, nil, "the in-process engine stopped"},
		{"after provide, failed", true, boom, "the in-process engine stopped: GRANTD_TOKEN_KEY is bad"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewEngines()
			h := Host{Engines: s}
			waiting := make(chan error, 1)
			go func() { _, err := h.Engine(context.Background()); waiting <- err }()
			fake := newFake(t, enginetest.SharingSchema)
			if tc.provide {
				h.ProvideEngine(fake)
				if err := <-waiting; err != nil {
					t.Fatal(err)
				}
			}
			s.Stop(tc.err)
			if !tc.provide {
				if err := <-waiting; !errors.Is(err, ErrEngineStopped) {
					t.Fatalf("a waiter: %v", err)
				}
			}
			s.Provide(fake) // too late
			s.Stop(errors.New("later"))
			e, err := h.Engine(context.Background())
			if e != nil || !errors.Is(err, ErrEngineStopped) || err.Error() != tc.want {
				t.Fatalf("%v %v, want %q", e, err, tc.want)
			}
			if tc.err != nil && !errors.Is(err, boom) {
				t.Fatalf("%v does not wrap serve's error", err)
			}
		})
	}
}

func newFake(t *testing.T, schema string, rels ...string) *enginetest.Fake {
	t.Helper()
	f, err := enginetest.NewFake(schema, rels...)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
