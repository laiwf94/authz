package httpserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ok(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }

// serveGroup runs g.Serve in the background; the returned function cancels
// it and waits for its error.
func serveGroup(t *testing.T, g *Group) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx) }()
	var stopped atomic.Bool
	t.Cleanup(func() {
		if !stopped.Load() {
			cancel()
			<-done
		}
	})
	return func() error {
		stopped.Store(true)
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("Serve did not return")
			return nil
		}
	}
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestLimitsDefaultsAndOverrides(t *testing.T) {
	g, err := Listen(Options{},
		Spec{Name: "a", Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)},
		Spec{Name: "b", Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok),
			Limits: Limits{WriteTimeout: 6 * time.Minute, MaxHeaderBytes: 32 << 10}})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	a, b := g.servers[0], g.servers[1]
	if a.ReadHeaderTimeout != DefaultReadHeaderTimeout || a.ReadTimeout != DefaultReadTimeout ||
		a.WriteTimeout != DefaultWriteTimeout || a.IdleTimeout != DefaultIdleTimeout || a.MaxHeaderBytes != DefaultMaxHeaderBytes {
		t.Errorf("defaults not applied: %+v", a)
	}
	if b.WriteTimeout != 6*time.Minute || b.MaxHeaderBytes != 32<<10 || b.ReadTimeout != DefaultReadTimeout {
		t.Errorf("overrides not applied: write %s, header %d, read %s", b.WriteTimeout, b.MaxHeaderBytes, b.ReadTimeout)
	}
	if g.opts.DrainTimeout != DefaultDrainTimeout {
		t.Errorf("drain timeout %s", g.opts.DrainTimeout)
	}
	if addrs := g.Addrs(); len(addrs) != 2 || addrs[0] == addrs[1] || strings.HasSuffix(addrs[0], ":0") {
		t.Errorf("addrs %v", addrs)
	}
}

func TestMaxHeaderBytes(t *testing.T) {
	g, err := Listen(Options{}, Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok), Limits: Limits{MaxHeaderBytes: 1 << 10}})
	if err != nil {
		t.Fatal(err)
	}
	serveGroup(t, g)
	req, _ := http.NewRequest("GET", "http://"+g.Addrs()[0]+"/", nil)
	req.Header.Set("X-Big", strings.Repeat("a", 8<<10))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("status %d, want 431", resp.StatusCode)
	}
}

func TestReadHeaderTimeout(t *testing.T) {
	g, err := Listen(Options{}, Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok),
		Limits: Limits{ReadHeaderTimeout: 100 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	serveGroup(t, g)
	c, err := net.Dial("tcp", g.Addrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n") // never finishes the headers
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("the server did not close a slow client: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("closed after %s", d)
	}
}

func TestReadiness(t *testing.T) {
	own := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "own probe") })
	g, err := Listen(Options{},
		Spec{Name: "default", Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok), ReadyPath: "/readyz"},
		Spec{Name: "own", Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok), ReadyPath: "/readyz", Ready: own},
		Spec{Name: "none", Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)})
	if err != nil {
		t.Fatal(err)
	}
	serveGroup(t, g)
	a := g.Addrs()
	if code, body := get(t, "http://"+a[0]+"/readyz"); code != 200 || body != `{"status":"ready"}`+"\n" {
		t.Errorf("default probe: %d %q", code, body)
	}
	if code, body := get(t, "http://"+a[1]+"/readyz"); code != 200 || body != "own probe" {
		t.Errorf("own probe: %d %q", code, body)
	}
	if code, body := get(t, "http://"+a[2]+"/readyz"); code != 200 || body != "ok" {
		t.Errorf("no probe should reach the handler: %d %q", code, body)
	}
	// Other methods and paths reach the handler.
	resp, err := http.Post("http://"+a[0]+"/readyz", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok" {
		t.Errorf("POST /readyz answered %q", b)
	}
	if !g.Ready() {
		t.Error("not ready while serving")
	}
}

// TestDrain: SIGTERM's path. Readiness flips at once, requests sent during
// the delay are still served, and a request in flight when the listeners
// close finishes and is answered before Serve returns nil.
func TestDrain(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			started <- struct{}{}
			<-release
		}
		io.WriteString(w, "done")
	})
	g, err := Listen(Options{DrainDelay: 300 * time.Millisecond, DrainTimeout: 10 * time.Second},
		Spec{Addr: "127.0.0.1:0", Handler: h, ReadyPath: "/readyz"})
	if err != nil {
		t.Fatal(err)
	}
	stop := serveGroup(t, g)
	base := "http://" + g.Addrs()[0]

	slow := make(chan string, 1)
	go func() {
		resp, err := http.Get(base + "/slow")
		if err != nil {
			slow <- "error: " + err.Error()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		slow <- string(b)
	}()
	<-started
	if open, inflight := g.Conns(); open < 1 || inflight != 1 {
		t.Errorf("conns %d, in flight %d", open, inflight)
	}

	served := make(chan error, 1)
	go func() { served <- stop() }()
	deadline := time.Now().Add(5 * time.Second)
	for g.Ready() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if g.Ready() {
		t.Fatal("readiness did not flip")
	}
	// Within the delay: the probe says 503, other requests are served, and
	// the server asks the client to close the connection.
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr}
	resp, err := c.Get(base + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 503 || string(b) != `{"status":"draining"}`+"\n" || !resp.Close {
		t.Errorf("probe while draining: %d %q close=%v", resp.StatusCode, b, resp.Close)
	}
	resp, err = c.Get(base + "/other")
	if err != nil {
		t.Fatalf("request during the drain delay: %v", err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "done" || !resp.Close {
		t.Errorf("request during the delay: %q close=%v", b, resp.Close)
	}

	time.Sleep(400 * time.Millisecond) // past the delay: listeners closed
	if _, err := net.DialTimeout("tcp", g.Addrs()[0], time.Second); err == nil {
		t.Error("listener still accepting after the drain delay")
	}
	select {
	case err := <-served:
		t.Fatalf("Serve returned with a request in flight: %v", err)
	default:
	}
	close(release)
	if got := <-slow; got != "done" {
		t.Errorf("in-flight request: %q", got)
	}
	if err := <-served; err != nil {
		t.Errorf("Serve: %v", err)
	}
}

func TestDrainTimeout(t *testing.T) {
	started := make(chan struct{}, 2)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done() // never finishes on its own
	})
	g, err := Listen(Options{DrainTimeout: 200 * time.Millisecond}, Spec{Addr: "127.0.0.1:0", Handler: h})
	if err != nil {
		t.Fatal(err)
	}
	stop := serveGroup(t, g)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			resp, err := http.Get("http://" + g.Addrs()[0] + "/")
			if err == nil {
				resp.Body.Close()
			}
			errs <- err
		}()
	}
	<-started
	<-started
	start := time.Now()
	err = stop()
	if !errors.Is(err, ErrDrainTimeout) || !strings.Contains(err.Error(), "2 request(s)") {
		t.Errorf("Serve: %v", err)
	}
	if d := time.Since(start); d < 200*time.Millisecond || d > 5*time.Second {
		t.Errorf("drain took %s for a 200ms bound", d)
	}
	for range 2 {
		if err := <-errs; err == nil {
			t.Error("a request cut at the bound was answered")
		}
	}
}

func TestListenErrors(t *testing.T) {
	if _, err := Listen(Options{}); err == nil {
		t.Error("no specs accepted")
	}
	if _, err := Listen(Options{DrainTimeout: -1}, Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)}); err == nil {
		t.Error("negative drain timeout accepted")
	}
	if _, err := Listen(Options{}, Spec{Name: "admin", Addr: "127.0.0.1:0"}); err == nil || !strings.Contains(err.Error(), "admin") {
		t.Errorf("nil handler: %v", err)
	}
	if _, err := Listen(Options{TLS: &TLSFiles{CertFile: "x"}}, Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)}); err == nil {
		t.Error("TLS without a key accepted")
	}

	// A failure on the second listener releases the first.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	firstAddr := first.Addr().String()
	first.Close()
	if _, err := Listen(Options{},
		Spec{Addr: firstAddr, Handler: http.HandlerFunc(ok)},
		Spec{Addr: busy.Addr().String(), Handler: http.HandlerFunc(ok)}); err == nil {
		t.Fatal("listening on a busy address succeeded")
	}
	again, err := net.Listen("tcp", firstAddr)
	if err != nil {
		t.Fatalf("the first listener was not released: %v", err)
	}
	again.Close()
}

// One listener failing stops the group: the others close and Serve returns
// the failure.
func TestListenerFailureStopsGroup(t *testing.T) {
	g, err := Listen(Options{},
		Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)},
		Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- g.Serve(context.Background()) }()
	if code, _ := get(t, "http://"+g.Addrs()[1]+"/"); code != 200 {
		t.Fatalf("status %d", code)
	}
	g.listeners[0].Close()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after a listener failed")
	}
	if g.Ready() {
		t.Error("still ready after a failure")
	}
	if _, err := net.DialTimeout("tcp", g.Addrs()[1], time.Second); err == nil {
		t.Error("the other listener is still open")
	}
}

func TestListenerFailureDuringDelay(t *testing.T) {
	g, err := Listen(Options{DrainDelay: time.Minute}, Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx) }()
	get(t, "http://"+g.Addrs()[0]+"/") // serving
	cancel()
	for g.Ready() {
		time.Sleep(time.Millisecond)
	}
	g.listeners[0].Close()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Serve returned nil after its listener failed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a failure during the drain delay waited out the delay")
	}
}

func TestServeOnceAndClose(t *testing.T) {
	g, err := Listen(Options{}, Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)})
	if err != nil {
		t.Fatal(err)
	}
	stop := serveGroup(t, g)
	get(t, "http://"+g.Addrs()[0]+"/") // the first Serve is running
	if err := g.Serve(context.Background()); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("second Serve: %v", err)
	}
	if err := stop(); err != nil {
		t.Errorf("Serve: %v", err)
	}

	// Close releases a group that was never served.
	g, err = Listen(Options{}, Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)})
	if err != nil {
		t.Fatal(err)
	}
	addr := g.Addrs()[0]
	g.Close()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Close did not release %s: %v", addr, err)
	}
	ln.Close()
}

func TestFromEnv(t *testing.T) {
	env := func(kv ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	o, err := FromEnv(env(), "X_")
	if err != nil || o.TLS != nil || o.DrainDelay != 0 || o.DrainTimeout != DefaultDrainTimeout {
		t.Errorf("defaults: %+v %v", o, err)
	}
	o, err = FromEnv(env("X_TLS_CERT", "c", "X_TLS_KEY", "k", "X_TLS_CLIENT_CA", "ca",
		"X_DRAIN_DELAY", "5s", "X_DRAIN_TIMEOUT", "1m"), "X_")
	if err != nil || o.TLS == nil || o.TLS.CertFile != "c" || o.TLS.KeyFile != "k" || o.TLS.ClientCAFile != "ca" ||
		o.DrainDelay != 5*time.Second || o.DrainTimeout != time.Minute {
		t.Errorf("set: %+v %v", o, err)
	}
	if o, err = FromEnv(env("X_DRAIN_DELAY", "0"), "X_"); err != nil || o.DrainDelay != 0 {
		t.Errorf("0: %+v %v", o, err)
	}
	for name, e := range map[string]func(string) string{
		"X_TLS_CERT and X_TLS_KEY must be set together":  env("X_TLS_CERT", "c"),
		"X_TLS_CERT and X_TLS_KEY must be set together ": env("X_TLS_KEY", "k"),
		"X_TLS_CLIENT_CA needs":                          env("X_TLS_CLIENT_CA", "ca"),
		"X_DRAIN_DELAY must be a duration":               env("X_DRAIN_DELAY", "soon"),
		"X_DRAIN_DELAY must be a duration ":              env("X_DRAIN_DELAY", "-1s"),
		"X_DRAIN_TIMEOUT must be a duration":             env("X_DRAIN_TIMEOUT", "2h"),
		"X_DRAIN_TIMEOUT must be more than 0s":           env("X_DRAIN_TIMEOUT", "0s"),
	} {
		if _, err := FromEnv(e, "X_"); err == nil || !strings.Contains(err.Error(), strings.TrimSpace(name)) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// Close while serving stops Serve at once, without an error.
func TestCloseWhileServing(t *testing.T) {
	g, err := Listen(Options{}, Spec{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(ok)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- g.Serve(context.Background()) }()
	get(t, "http://"+g.Addrs()[0]+"/")
	g.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve after Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}
