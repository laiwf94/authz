package httpserver

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Server is a set of bound listeners: a *Group, or one part's share of a
// Shared group. Subcommands bind through a Binder and serve through this,
// so the same code runs alone or next to the other subcommands in one
// process.
type Server interface {
	// Addrs returns the bound addresses in Spec order.
	Addrs() []string
	// Serve answers until ctx ends and drains, as Group.Serve does.
	Serve(ctx context.Context) error
}

// Binder binds one subcommand's listeners. Bind gives the subcommand a
// Group of its own; Shared.Part gives it a share of one group.
type Binder func(opts Options, specs ...Spec) (Server, error)

// Bind is Listen as a Binder.
func Bind(opts Options, specs ...Spec) (Server, error) {
	g, err := Listen(opts, specs...)
	if err != nil {
		return nil, err
	}
	return g, nil
}

// ErrAborted is wrapped by the error a Shared part's Binder returns when another
// part of the process failed before every part had joined.
var ErrAborted = errors.New("httpserver: another part of the process failed to start")

// Shared is one Group for several parts of one process, such as authz serve,
// authz gateway and authz mcp under "authz run". Part i binds through
// Part(i), as it would through Bind; once every part has joined, every
// listener is bound in one Listen (all or none) with the Shared's Options,
// in part order whatever order the parts joined in, and the parts get
// their share. The process then calls Serve once: one readiness flip, one
// drain delay and one drain bound cover every listener, and each part's
// Server.Serve returns when that drain is over.
//
// A part's own TLS and drain settings are refused rather than ignored: in a
// shared group they come from the Options given to NewShared.
type Shared struct {
	opts Options

	mu     sync.Mutex
	joined int
	slots  [][]Spec      // by part; nil until the part joins
	offs   []int         // each part's first listener in the group
	bound  chan struct{} // closed once g or err is set
	g      *Group
	err    error

	served   chan struct{} // closed when Serve returns
	serveErr error
	serving  bool
}

// NewShared returns a group the given number of parts will join.
func NewShared(opts Options, parts int) *Shared {
	return &Shared{opts: opts, slots: make([][]Spec, parts), offs: make([]int, parts),
		bound: make(chan struct{}), served: make(chan struct{})}
}

// Part is the Binder of part i: it adds the part's listeners and waits
// until every part has joined and the group is bound, or until it fails.
// opts must carry no TLS files and no drain settings other than the
// defaults. A part joins once.
func (s *Shared) Part(i int) Binder {
	return func(opts Options, specs ...Spec) (Server, error) { return s.join(i, opts, specs) }
}

func (s *Shared) join(i int, opts Options, specs []Spec) (Server, error) {
	if i < 0 || i >= len(s.slots) {
		return nil, fmt.Errorf("httpserver: part %d of a shared group of %d", i, len(s.slots))
	}
	if len(specs) == 0 {
		err := errors.New("httpserver: no listeners")
		s.Abort(err)
		return nil, err
	}
	if opts.TLS != nil || opts.DrainDelay != 0 || (opts.DrainTimeout != 0 && opts.DrainTimeout != DefaultDrainTimeout) {
		err := fmt.Errorf("httpserver: the %s listener is in a shared group, which takes its TLS and drain settings from the process, not from the listener", specs[0].Name)
		s.Abort(err)
		return nil, err
	}
	s.mu.Lock()
	if s.slots[i] != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("httpserver: part %d has already joined the shared group", i)
	}
	select {
	case <-s.bound:
		err := s.err
		s.mu.Unlock()
		return nil, err
	default:
	}
	s.slots[i] = specs
	s.joined++
	if s.joined == len(s.slots) {
		var all []Spec
		for j, sp := range s.slots {
			s.offs[j] = len(all)
			all = append(all, sp...)
		}
		s.g, s.err = Listen(s.opts, all...)
		close(s.bound)
	}
	s.mu.Unlock()
	<-s.bound
	if s.err != nil {
		return nil, s.err
	}
	return &share{s: s, off: s.offs[i], n: len(specs)}, nil
}

// Abort fails the parts waiting to join and those still to come with err,
// wrapped in ErrAborted. It does nothing once the group is bound.
func (s *Shared) Abort(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.bound:
		return
	default:
	}
	if err == nil {
		err = errors.New("no reason given")
	}
	s.err = fmt.Errorf("%w: %w", ErrAborted, err)
	close(s.bound)
}

// Bound is closed once every part has joined and the group is bound, or
// binding failed or was aborted; Err then says which.
func (s *Shared) Bound() <-chan struct{} { return s.bound }

// Err is the error binding failed with, after Bound is closed.
func (s *Shared) Err() error {
	<-s.bound
	return s.err
}

// Addrs returns every bound address: part 0's listeners in Spec order,
// then part 1's, and so on.
func (s *Shared) Addrs() []string {
	<-s.bound
	if s.g == nil {
		return nil
	}
	return s.g.Addrs()
}

// Ready reports whether the readiness probes answer 200.
func (s *Shared) Ready() bool {
	select {
	case <-s.bound:
		return s.g != nil && s.g.Ready()
	default:
		return false
	}
}

// Serve waits until the group is bound, serves every listener until ctx
// ends and drains them, as Group.Serve does. The parts' Servers return
// once it has. It returns the binding error if binding failed.
func (s *Shared) Serve(ctx context.Context) error {
	s.mu.Lock()
	if s.serving {
		s.mu.Unlock()
		return errors.New("httpserver: Serve called twice")
	}
	s.serving = true
	s.mu.Unlock()
	defer close(s.served)
	select {
	case <-s.bound:
	case <-ctx.Done():
		s.Abort(ctx.Err())
		<-s.bound
	}
	if s.err != nil {
		s.serveErr = s.err
		return s.err
	}
	s.serveErr = s.g.Serve(ctx)
	return s.serveErr
}

// Conns reports the open connections and the requests being handled across
// every part.
func (s *Shared) Conns() (open, inflight int64) {
	select {
	case <-s.bound:
		if s.g != nil {
			return s.g.Conns()
		}
	default:
	}
	return 0, 0
}

// share is one part's listeners in a Shared group.
type share struct {
	s      *Shared
	off, n int
}

func (p *share) Addrs() []string { return p.s.g.Addrs()[p.off : p.off+p.n] }

// Serve returns when the shared group's Serve has returned, with its error.
// The process drives the drain with Shared.Serve; ctx is not used, since a
// part cancels it only after the process context has ended.
func (p *share) Serve(context.Context) error {
	<-p.s.served
	return p.s.serveErr
}
