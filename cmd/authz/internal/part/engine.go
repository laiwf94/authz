package part

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/laiwf94/authz/internal/authz/engine"
)

// ErrNoEngine is returned by Host.Engine when no part of the process
// serves grantd's engine: the subcommand runs alone, or "authz run" was
// started without its serve part.
var ErrNoEngine = errors.New("no in-process engine: run authz run with its serve part")

// ErrEngineStopped is matched by Host.Engine's error once the serve part
// has returned, or failed before it had an engine to hand over.
var ErrEngineStopped = errors.New("the in-process engine stopped")

// Engines hands the engine of the process's serve part to its other parts,
// so the gateway and mcp ask grantd in process: no network hop, the same
// check cache, the same minimize_latency snapshot and the same consistency
// tokens as the serve part's HTTP API. A token from either is good for the
// other.
//
// The serve part calls Provide once its engine exists and Stop when it
// returns; the other parts call Host.Engine when they need the engine, at
// request time rather than while starting: until Provide, Wait blocks.
type Engines struct {
	once  sync.Once
	ready chan struct{} // closed by the first Provide or Stop

	mu  sync.Mutex
	eng engine.Engine
	err error // set by Stop
}

// NewEngines returns Engines for a process whose serve part will call
// Provide.
func NewEngines() *Engines { return &Engines{ready: make(chan struct{})} }

// Provide hands e to every waiting and later caller of Wait. Only the
// first call counts, and none counts after Stop.
func (s *Engines) Provide(e engine.Engine) {
	s.mu.Lock()
	if s.eng == nil && s.err == nil {
		s.eng = e
	}
	s.mu.Unlock()
	s.once.Do(func() { close(s.ready) })
}

// Stop withdraws the engine: the serve part returned, with err (nil after
// a clean shutdown). Every later Wait fails with an error matching
// ErrEngineStopped, and so does every waiting one.
func (s *Engines) Stop(err error) {
	s.mu.Lock()
	if s.err == nil {
		if err == nil {
			s.err = ErrEngineStopped
		} else {
			s.err = fmt.Errorf("%w: %w", ErrEngineStopped, err)
		}
		s.eng = nil
	}
	s.mu.Unlock()
	s.once.Do(func() { close(s.ready) })
}

// Wait returns the engine once the serve part has provided it, or the
// error of a serve part that stopped, or ctx's error.
func (s *Engines) Wait(ctx context.Context) (engine.Engine, error) {
	select {
	case <-s.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return s.eng, nil
}

// Engine returns the process's grantd engine, waiting until the serve part
// has one: ErrNoEngine without one in this process (no Engines), an error
// matching ErrEngineStopped once serve has returned.
func (h Host) Engine(ctx context.Context) (engine.Engine, error) {
	if h.Engines == nil {
		return nil, ErrNoEngine
	}
	return h.Engines.Wait(ctx)
}

// ProvideEngine is the serve part handing its engine to the process; it
// does nothing when the subcommand runs alone.
func (h Host) ProvideEngine(e engine.Engine) {
	if h.Engines != nil {
		h.Engines.Provide(e)
	}
}
