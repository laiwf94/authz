package httpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestSIGTERMDrainsThousandsInFlight holds 2,000 requests in flight, each
// on its own connection and each with half of its body already sent, then
// sends the process SIGTERM. Every one of them must finish with its full
// body: no connection reset, no truncated response. Requests sent during
// the drain delay must be answered too, and after it the listener must
// refuse new connections. Serve must return nil once the last request
// finishes, well inside the drain bound.
func TestSIGTERMDrainsThousandsInFlight(t *testing.T) {
	const (
		n     = 2000
		late  = 200 // requests sent during the drain delay
		delay = 750 * time.Millisecond
		bound = 30 * time.Second
	)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	var started atomic.Int64
	allStarted := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if r.URL.Path == "/fast" {
			io.WriteString(w, "fast "+id)
			return
		}
		io.WriteString(w, "first half of "+id+"\n")
		w.(http.Flusher).Flush()
		if started.Add(1) == n {
			close(allStarted)
		}
		<-release
		io.WriteString(w, "second half of "+id+"\n")
	})
	g, err := Listen(Options{DrainDelay: delay, DrainTimeout: bound},
		Spec{Name: "public", Addr: "127.0.0.1:0", Handler: h, ReadyPath: "/readyz"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stopSignals()
	var serveErr error
	served := make(chan struct{})
	go func() { serveErr = g.Serve(ctx); close(served) }()
	t.Cleanup(func() {
		releaseAll()
		g.Close()
		<-served
	})
	addr := g.Addrs()[0]

	tr := &http.Transport{MaxIdleConnsPerHost: n, MaxConnsPerHost: 0}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 2 * bound}
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		failed []string
	)
	fail := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		failed = append(failed, fmt.Sprintf(format, args...))
	}
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprint(i)
			resp, err := c.Get("http://" + addr + "/slow?id=" + id)
			if err != nil {
				fail("request %s: %v (reset: %v)", id, err, errors.Is(err, syscall.ECONNRESET))
				return
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				fail("request %s body: %v (reset: %v)", id, err, errors.Is(err, syscall.ECONNRESET))
				return
			}
			want := "first half of " + id + "\nsecond half of " + id + "\n"
			if resp.StatusCode != 200 || string(b) != want {
				fail("request %s: %d %q", id, resp.StatusCode, b)
			}
		}()
	}
	select {
	case <-allStarted:
	case <-time.After(60 * time.Second):
		t.Fatalf("only %d of %d requests reached the handler", started.Load(), n)
	}
	if open, inflight := g.Conns(); open < n || inflight != n {
		t.Fatalf("before SIGTERM: %d connections, %d in flight; want %d of each", open, inflight, n)
	}

	signalled := time.Now()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for g.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if g.Ready() {
		t.Fatal("readiness did not flip on SIGTERM")
	}

	// During the delay: new connections are still accepted and answered,
	// each told to close.
	lateTr := &http.Transport{}
	defer lateTr.CloseIdleConnections()
	lc := &http.Client{Transport: lateTr, Timeout: 10 * time.Second}
	resp, err := lc.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Errorf("probe during the drain: %d", resp.StatusCode)
	}
	var lwg sync.WaitGroup
	for i := range late {
		lwg.Add(1)
		go func() {
			defer lwg.Done()
			id := fmt.Sprint(i)
			resp, err := lc.Get("http://" + addr + "/fast?id=" + id)
			if err != nil {
				fail("late request %s: %v", id, err)
				return
			}
			b, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != 200 || string(b) != "fast "+id || !resp.Close {
				fail("late request %s: %d %q %v close=%v", id, resp.StatusCode, b, err, resp.Close)
			}
		}()
	}
	lwg.Wait()
	if time.Since(signalled) >= delay {
		t.Fatalf("the late requests took longer than the %s drain delay; the test cannot tell them from refused ones", delay)
	}

	// After the delay the listener refuses connections while the 2,000
	// requests are still running.
	deadline = time.Now().Add(delay + 5*time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			break
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("listener still accepting after the drain delay")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-served:
		t.Fatalf("Serve returned with %d requests in flight: %v", n, serveErr)
	default:
	}
	if _, inflight := g.Conns(); inflight != n {
		t.Fatalf("%d requests in flight after the listener closed; want %d", inflight, n)
	}

	released := time.Now()
	releaseAll()
	wg.Wait()
	select {
	case <-served:
		if serveErr != nil {
			t.Fatalf("Serve: %v", serveErr)
		}
	case <-time.After(bound):
		t.Fatal("Serve did not return within the drain bound")
	}
	t.Logf("SIGTERM to drained: %s; release to drained: %s", time.Since(signalled), time.Since(released))
	if len(failed) > 0 {
		max := min(len(failed), 10)
		t.Fatalf("%d of %d requests failed; first %d:\n%v", len(failed), n+late, max, failed[:max])
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		open, inflight := g.Conns()
		if open == 0 && inflight == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the drain: %d connections, %d in flight", open, inflight)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
