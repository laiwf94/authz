// Package httpserver is the platform's one HTTP server setup. authz serve,
// authz gateway and authz mcp each built their own http.Server with their
// own timeouts and their own shutdown; now each describes its listeners as
// Specs and a Group binds them, applies the same TLS defaults, timeouts and
// header limits, answers a readiness probe and drains them all within one
// bound when its context ends.
//
// Stopping happens in three steps:
//
//  1. Readiness flips: every Spec's ReadyPath answers 503 from now on, and
//     keep-alives stop, so each client's next request opens a connection a
//     load balancer can send elsewhere.
//  2. For Options.DrainDelay the listeners keep accepting, so requests sent
//     before the load balancer noticed the probe still land.
//  3. The listeners close and in-flight requests run to completion, for at
//     most Options.DrainTimeout. Connections still busy at the bound are
//     closed and Serve reports how many.
package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults for a Spec's Limits fields left at zero, and for Options.
const (
	DefaultReadHeaderTimeout = 5 * time.Second
	DefaultReadTimeout       = 15 * time.Second
	DefaultWriteTimeout      = 30 * time.Second
	DefaultIdleTimeout       = 120 * time.Second
	DefaultMaxHeaderBytes    = 16 << 10
	DefaultDrainTimeout      = 20 * time.Second
)

// Limits bound one listener's connections. A zero field takes the default.
type Limits struct {
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	// WriteTimeout bounds one response; a listener that holds long polls
	// or waits for approvals sets it above its longest wait.
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxHeaderBytes int
}

func (l Limits) withDefaults() Limits {
	if l.ReadHeaderTimeout == 0 {
		l.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if l.ReadTimeout == 0 {
		l.ReadTimeout = DefaultReadTimeout
	}
	if l.WriteTimeout == 0 {
		l.WriteTimeout = DefaultWriteTimeout
	}
	if l.IdleTimeout == 0 {
		l.IdleTimeout = DefaultIdleTimeout
	}
	if l.MaxHeaderBytes == 0 {
		l.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	return l
}

// Spec is one listener.
type Spec struct {
	// Name says which listener an error is about ("public", "admin").
	Name string
	// Addr is the address to listen on, such as ":8080" or "127.0.0.1:0".
	Addr    string
	Handler http.Handler
	Limits  Limits
	// ReadyPath, when set, is the readiness probe: GET or HEAD on it
	// answers 503 once the group is stopping. While the group is ready it
	// is answered by Ready, or with 200 {"status":"ready"} when Ready is
	// nil. A handler that already serves its own probe passes itself.
	ReadyPath string
	Ready     http.Handler
}

// Options apply to every listener of a Group.
type Options struct {
	// TLS, when set, serves every listener over TLS with these files.
	TLS *TLSFiles
	// DrainDelay is how long the group keeps accepting after readiness
	// flips. Zero closes the listeners at once.
	DrainDelay time.Duration
	// DrainTimeout bounds how long in-flight requests may run once the
	// listeners close; zero is DefaultDrainTimeout.
	DrainTimeout time.Duration
	// ErrorLog receives the servers' own errors (failed TLS handshakes,
	// recovered panics); nil is the standard logger, as http.Server's.
	ErrorLog *log.Logger
}

// ErrDrainTimeout is wrapped by the error Serve returns when requests were
// still running at Options.DrainTimeout.
var ErrDrainTimeout = errors.New("drain timeout exceeded")

// Group is a set of bound listeners served and drained together.
type Group struct {
	opts      Options
	servers   []*http.Server
	listeners []net.Listener
	certs     *certReloader
	stopping  atomic.Bool
	inflight  atomic.Int64 // requests being handled
	conns     atomic.Int64 // open connections

	served atomic.Bool
}

// Listen validates the options, loads the TLS files and binds every Spec.
// If any step fails, the listeners already bound are closed. The returned
// group is ready; Serve starts answering.
func Listen(opts Options, specs ...Spec) (*Group, error) {
	if len(specs) == 0 {
		return nil, errors.New("httpserver: no listeners")
	}
	if opts.DrainDelay < 0 || opts.DrainTimeout < 0 {
		return nil, errors.New("httpserver: drain delay and timeout must not be negative")
	}
	if opts.DrainTimeout == 0 {
		opts.DrainTimeout = DefaultDrainTimeout
	}
	g := &Group{opts: opts}
	var tlsConfig *tls.Config
	if opts.TLS != nil {
		r, cfg, err := opts.TLS.config()
		if err != nil {
			return nil, err
		}
		g.certs, tlsConfig = r, cfg
	}
	for _, s := range specs {
		if s.Handler == nil {
			g.closeListeners()
			return nil, fmt.Errorf("httpserver: %s listener has no handler", s.Name)
		}
		ln, err := net.Listen("tcp", s.Addr)
		if err != nil {
			g.closeListeners()
			return nil, err
		}
		lim := s.Limits.withDefaults()
		hs := &http.Server{
			Handler:           g.wrap(s),
			ReadHeaderTimeout: lim.ReadHeaderTimeout,
			ReadTimeout:       lim.ReadTimeout,
			WriteTimeout:      lim.WriteTimeout,
			IdleTimeout:       lim.IdleTimeout,
			MaxHeaderBytes:    lim.MaxHeaderBytes,
			ConnState:         g.connState,
			ErrorLog:          opts.ErrorLog,
		}
		if tlsConfig != nil {
			hs.TLSConfig = tlsConfig.Clone()
		}
		g.servers = append(g.servers, hs)
		g.listeners = append(g.listeners, ln)
	}
	return g, nil
}

// Addrs returns the bound addresses in Spec order, with ports chosen.
func (g *Group) Addrs() []string {
	out := make([]string, len(g.listeners))
	for i, ln := range g.listeners {
		out[i] = ln.Addr().String()
	}
	return out
}

// Ready reports whether the readiness probes answer 200.
func (g *Group) Ready() bool { return !g.stopping.Load() }

// Serve answers on every listener until ctx ends, then drains as the
// package documentation describes, or until one listener fails, then
// closes the others and returns that error. It returns nil after a clean
// drain. Serve may be called once; Close releases a group never served.
func (g *Group) Serve(ctx context.Context) error {
	if !g.served.CompareAndSwap(false, true) {
		return errors.New("httpserver: Serve called twice")
	}
	return g.serve(ctx)
}

func (g *Group) serve(ctx context.Context) error {
	errc := make(chan error, len(g.servers))
	for i, hs := range g.servers {
		ln := g.listeners[i]
		go func() {
			if hs.TLSConfig != nil {
				errc <- hs.ServeTLS(ln, "", "")
			} else {
				errc <- hs.Serve(ln)
			}
		}()
	}
	select {
	case err := <-errc:
		g.stopping.Store(true)
		for _, hs := range g.servers {
			hs.Close()
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil // Close was called
		}
		return err
	case <-ctx.Done():
	}
	g.stopping.Store(true)
	for _, hs := range g.servers {
		hs.SetKeepAlivesEnabled(false)
	}
	if g.opts.DrainDelay > 0 {
		t := time.NewTimer(g.opts.DrainDelay)
		select {
		case <-t.C:
		case err := <-errc:
			t.Stop()
			for _, hs := range g.servers {
				hs.Close()
			}
			return err
		}
	}
	return g.drain()
}

func (g *Group) drain() error {
	dctx, cancel := context.WithTimeout(context.Background(), g.opts.DrainTimeout)
	defer cancel()
	var wg sync.WaitGroup
	errs := make([]error, len(g.servers))
	for i, hs := range g.servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = hs.Shutdown(dctx)
		}()
	}
	wg.Wait()
	err := errors.Join(errs...)
	if !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	busy := g.inflight.Load()
	for _, hs := range g.servers {
		hs.Close()
	}
	return fmt.Errorf("httpserver: %w after %s; closed the connections of %d request(s) still in flight",
		ErrDrainTimeout, g.opts.DrainTimeout, busy)
}

// Close closes every listener and connection at once, without draining.
func (g *Group) Close() error {
	g.stopping.Store(true)
	var errs []error
	for _, hs := range g.servers {
		errs = append(errs, hs.Close())
	}
	g.closeListeners()
	return errors.Join(errs...)
}

func (g *Group) closeListeners() {
	for _, ln := range g.listeners {
		ln.Close()
	}
}

// Conns reports the open connections and the requests being handled.
func (g *Group) Conns() (open, inflight int64) { return g.conns.Load(), g.inflight.Load() }

func (g *Group) connState(_ net.Conn, s http.ConnState) {
	switch s {
	case http.StateNew:
		g.conns.Add(1)
	case http.StateHijacked, http.StateClosed:
		g.conns.Add(-1)
	}
}

// track counts requests in flight. ConnState cannot: a connection closed
// mid-request goes from active to closed without passing through idle, and
// one HTTP/2 connection carries many requests.
func (g *Group) track(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.inflight.Add(1)
		defer g.inflight.Add(-1)
		h.ServeHTTP(w, r)
	})
}

func (g *Group) wrap(s Spec) http.Handler {
	h := s.Handler
	if s.ReadyPath == "" {
		return g.track(h)
	}
	ready := s.Ready
	if ready == nil {
		ready = http.HandlerFunc(readyOK)
	}
	return g.track(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != s.ReadyPath || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			h.ServeHTTP(w, r)
			return
		}
		if g.stopping.Load() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusServiceUnavailable)
			if r.Method == http.MethodGet {
				w.Write([]byte(`{"status":"draining"}` + "\n"))
			}
			return
		}
		ready.ServeHTTP(w, r)
	}))
}

func readyOK(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write([]byte(`{"status":"ready"}` + "\n"))
	}
}
