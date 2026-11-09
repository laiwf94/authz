package httpserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func named(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, name) }
}

// joinAll has each part join s from its own goroutine, as the subcommands
// of "authz run" do, and returns each part's Server and error in order.
func joinAll(s *Shared, parts [][]Spec, opts []Options) ([]Server, []error) {
	srvs := make([]Server, len(parts))
	errs := make([]error, len(parts))
	var wg sync.WaitGroup
	for i, specs := range parts {
		o := Options{}
		if opts != nil {
			o = opts[i]
		}
		wg.Go(func() { srvs[i], errs[i] = s.Part(i)(o, specs...) })
	}
	wg.Wait()
	return srvs, errs
}

// Three parts join from their own goroutines; each gets its own listeners
// back in its own order, all answer, one readiness flip covers all of them
// and one drain lets a request in flight on one part finish before every
// part's Serve returns.
func TestSharedGroup(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	slow := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		io.WriteString(w, "slow done")
	})
	s := NewShared(Options{DrainDelay: 200 * time.Millisecond}, 3)
	if s.Ready() {
		t.Error("ready before binding")
	}
	if o, f := s.Conns(); o != 0 || f != 0 {
		t.Errorf("conns before binding: %d %d", o, f)
	}
	srvs, errs := joinAll(s, [][]Spec{
		{{Name: "api", Addr: "127.0.0.1:0", Handler: named("api"), ReadyPath: "/readyz"}},
		{{Name: "public", Addr: "127.0.0.1:0", Handler: named("public")},
			{Name: "admin", Addr: "127.0.0.1:0", Handler: named("admin"), ReadyPath: "/readyz"}},
		{{Name: "agent", Addr: "127.0.0.1:0", Handler: slow},
			{Name: "mcpadmin", Addr: "127.0.0.1:0", Handler: named("mcpadmin"), ReadyPath: "/readyz"}},
	}, nil)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	if n := len(s.Addrs()); n != 5 {
		t.Fatalf("%d addresses, want 5", n)
	}
	want := [][]string{{"api"}, {"public", "admin"}, {"agent", "mcpadmin"}}
	for i, srv := range srvs {
		if len(srv.Addrs()) != len(want[i]) {
			t.Fatalf("part %d has %d addresses, want %d", i, len(srv.Addrs()), len(want[i]))
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx) }()
	for i, srv := range srvs {
		for j, a := range srv.Addrs() {
			if want[i][j] == "agent" {
				continue
			}
			if code, body := get(t, "http://"+a+"/"); code != 200 || body != want[i][j] {
				t.Errorf("part %d listener %d: %d %q, want %q", i, j, code, body, want[i][j])
			}
		}
	}

	partDone := make(chan error, len(srvs))
	for _, srv := range srvs {
		go func() { partDone <- srv.Serve(context.Background()) }()
	}
	if !s.Ready() {
		t.Error("not ready while serving")
	}
	reply := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + srvs[2].Addrs()[0] + "/")
		if err != nil {
			reply <- err.Error()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		reply <- string(b)
	}()
	<-entered
	if _, inflight := s.Conns(); inflight != 1 {
		t.Errorf("%d requests in flight, want 1", inflight)
	}
	cancel()
	// Every part's probe flips together.
	for _, a := range []string{srvs[0].Addrs()[0], srvs[1].Addrs()[1], srvs[2].Addrs()[1]} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			code, body := get(t, "http://"+a+"/readyz")
			if code == 503 && body == `{"status":"draining"}`+"\n" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s/readyz still %d %q", a, code, body)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	select {
	case err := <-partDone:
		t.Fatalf("a part returned (%v) while a request was in flight", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if got := <-reply; got != "slow done" {
		t.Fatalf("in-flight request got %q", got)
	}
	if err := <-served; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	for range srvs {
		if err := <-partDone; err != nil {
			t.Fatalf("part Serve: %v", err)
		}
	}
	if s.Ready() {
		t.Error("ready after the drain")
	}
	if err := s.Serve(context.Background()); err == nil {
		t.Error("a second Serve did not fail")
	}
	if _, err := s.Part(1)(Options{}, Spec{Name: "again", Addr: "127.0.0.1:0", Handler: named("again")}); err == nil {
		t.Error("a part joined twice")
	}
	for _, i := range []int{-1, 3} {
		if _, err := s.Part(i)(Options{}, Spec{Name: "x", Addr: "127.0.0.1:0", Handler: named("x")}); err == nil {
			t.Errorf("part %d of 3 joined", i)
		}
	}
}

// A part with its own TLS or drain settings is refused, and the parts
// waiting for it fail too, with nothing left bound.
func TestSharedRefusesOwnSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"tls", Options{TLS: &TLSFiles{CertFile: "c", KeyFile: "k"}}},
		{"delay", Options{DrainDelay: time.Second}},
		{"timeout", Options{DrainTimeout: time.Minute}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hold, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := hold.Addr().String()
			hold.Close()
			s := NewShared(Options{}, 2)
			_, errs := joinAll(s, [][]Spec{
				{{Name: "first", Addr: addr, Handler: named("first")}},
				{{Name: "own", Addr: "127.0.0.1:0", Handler: named("own")}},
			}, []Options{{}, tc.opts})
			if errs[1] == nil || !strings.Contains(errs[1].Error(), "own listener is in a shared group") {
				t.Fatalf("own settings: %v", errs[1])
			}
			if !errors.Is(errs[0], ErrAborted) {
				t.Fatalf("the waiting part: %v, want ErrAborted", errs[0])
			}
			if !errors.Is(s.Err(), ErrAborted) || s.Addrs() != nil || s.Ready() {
				t.Fatalf("group after the refusal: %v %v %v", s.Err(), s.Addrs(), s.Ready())
			}
			// Nothing was bound: the first part's address is free.
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatalf("%s is still bound: %v", addr, err)
			}
			ln.Close()
			if err := s.Serve(context.Background()); !errors.Is(err, ErrAborted) {
				t.Fatalf("Serve after the refusal: %v", err)
			}
		})
	}
	// The default drain timeout, set explicitly, is not a setting of its own.
	s := NewShared(Options{}, 1)
	srv, err := s.Part(0)(Options{DrainTimeout: DefaultDrainTimeout}, Spec{Name: "x", Addr: "127.0.0.1:0", Handler: named("x")})
	if err != nil || len(srv.Addrs()) != 1 {
		t.Fatalf("default drain timeout: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Serve(ctx); err != nil {
		t.Fatal(err)
	}
}

// A part that fails before joining aborts the group: the parts already
// waiting and the ones still to come fail with its error.
func TestSharedAbort(t *testing.T) {
	s := NewShared(Options{}, 3)
	waiting := make(chan error, 1)
	go func() {
		_, err := s.Part(0)(Options{}, Spec{Name: "a", Addr: "127.0.0.1:0", Handler: named("a")})
		waiting <- err
	}()
	cause := errors.New("opening store: disk on fire")
	time.Sleep(20 * time.Millisecond)
	s.Abort(cause)
	s.Abort(errors.New("a second abort changes nothing"))
	err := <-waiting
	if !errors.Is(err, ErrAborted) || !errors.Is(err, cause) {
		t.Fatalf("waiting part: %v", err)
	}
	if _, err := s.Part(1)(Options{}, Spec{Name: "b", Addr: "127.0.0.1:0", Handler: named("b")}); !errors.Is(err, cause) {
		t.Fatalf("late part: %v", err)
	}
	<-s.Bound()

	s = NewShared(Options{}, 1)
	s.Abort(nil)
	if err := s.Err(); !errors.Is(err, ErrAborted) || !strings.Contains(err.Error(), "no reason given") {
		t.Fatalf("abort without a reason: %v", err)
	}

	// No listeners is refused like Listen refuses it.
	s = NewShared(Options{}, 2)
	if _, err := s.Part(0)(Options{}); err == nil || !errors.Is(s.Err(), ErrAborted) {
		t.Fatalf("no listeners: %v %v", err, s.Err())
	}

	// Abort after binding does nothing.
	s = NewShared(Options{}, 1)
	if _, err := s.Part(0)(Options{}, Spec{Name: "c", Addr: "127.0.0.1:0", Handler: named("c")}); err != nil {
		t.Fatal(err)
	}
	s.Abort(cause)
	if s.Err() != nil {
		t.Fatalf("abort after binding: %v", s.Err())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Serve(ctx); err != nil {
		t.Fatal(err)
	}

	// Serve whose context ends before every part joined aborts the group.
	s = NewShared(Options{}, 2)
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if err := s.Serve(ctx); !errors.Is(err, ErrAborted) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve cancelled before binding: %v", err)
	}
}

// One bind for every part: an address in use fails all of them, and the
// listeners bound before it are closed.
func TestSharedBindFailure(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freeAddr := free.Addr().String()
	free.Close()
	s := NewShared(Options{}, 2)
	_, errs := joinAll(s, [][]Spec{
		{{Name: "first", Addr: freeAddr, Handler: named("first")}},
		{{Name: "second", Addr: busy.Addr().String(), Handler: named("second")}},
	}, nil)
	for i, err := range errs {
		if err == nil || errors.Is(err, ErrAborted) {
			t.Fatalf("part %d: %v, want the bind error", i, err)
		}
	}
	ln, err := net.Listen("tcp", freeAddr)
	if err != nil {
		t.Fatalf("the first part's listener was left bound: %v", err)
	}
	ln.Close()
}

// A listener failing while the group serves stops every part, and each
// part's Serve reports the failure.
func TestSharedListenerFailure(t *testing.T) {
	s := NewShared(Options{}, 2)
	srvs, errs := joinAll(s, [][]Spec{
		{{Name: "a", Addr: "127.0.0.1:0", Handler: named("a")}},
		{{Name: "b", Addr: "127.0.0.1:0", Handler: named("b")}},
	}, nil)
	if errs[0] != nil || errs[1] != nil {
		t.Fatal(errs)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve(context.Background()) }()
	time.Sleep(20 * time.Millisecond)
	s.g.listeners[1].Close() // the accept loop fails
	err := <-served
	if err == nil {
		t.Fatal("Serve returned nil after a listener failed")
	}
	for i, srv := range srvs {
		if got := srv.Serve(context.Background()); got != err {
			t.Fatalf("part %d: %v, want %v", i, got, err)
		}
	}
}

// Bind is Listen as a Binder, and a Group is a Server.
func TestBind(t *testing.T) {
	var b Binder = Bind
	srv, err := b(Options{}, Spec{Name: "x", Addr: "127.0.0.1:0", Handler: named("x")})
	if err != nil {
		t.Fatal(err)
	}
	if len(srv.Addrs()) != 1 {
		t.Fatalf("addresses: %v", srv.Addrs())
	}
	srv.(*Group).Close()
	if _, err := b(Options{}); err == nil {
		t.Fatal("Bind with no listeners")
	}
}
