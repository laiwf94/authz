package keys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/platform/clock"
)

// Ring names used by the platform. A Set may hold others.
const (
	RingSession     = "session"     // A256GCM: gateway session and state cookies
	RingUpstream    = "upstream"    // ES256: JWTs the gateway passes to upstreams
	RingConsistency = "consistency" // HS256: consistency tokens
	RingAgent       = "agent"       // HS256: signed agent tokens
)

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// Set is the named rings of one process. It is safe for concurrent use.
type Set struct {
	mu    sync.RWMutex
	names []string
	rings map[string]*Ring
}

// NewSet returns an empty set.
func NewSet() *Set { return &Set{rings: map[string]*Ring{}} }

// Add names a ring. Names are 1 to 32 lower-case letters, digits, '_' or
// '-', starting with a letter, and unique.
func (s *Set) Add(name string, r *Ring) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("keys: ring name %q must be 1 to 32 lower-case letters, digits, '_' or '-', starting with a letter", name)
	}
	if r == nil {
		return fmt.Errorf("keys: ring %s is nil", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.rings[name]; dup {
		return fmt.Errorf("keys: ring %s added twice", name)
	}
	s.names = append(s.names, name)
	s.rings[name] = r
	return nil
}

// Ring returns the ring called name, or nil.
func (s *Set) Ring(name string) *Ring {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rings[name]
}

// replace swaps the ring called name, which the set holds, for r.
func (s *Set) replace(name string, r *Ring) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rings[name] = r
}

// Names returns the ring names in the order they were added.
func (s *Set) Names() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.names...)
}

// Tick rotates every ring that is due at now and prunes expired retired
// keys from the rest. It returns the names of the rings that changed; a
// ring that fails to rotate is reported and the others still run.
func (s *Set) Tick(now time.Time) ([]string, error) {
	var changed []string
	var errs []error
	for _, name := range s.Names() {
		r := s.Ring(name)
		if r.Due(now) {
			if err := r.Rotate(now); err != nil {
				errs = append(errs, fmt.Errorf("ring %s: %w", name, err))
				continue
			}
			changed = append(changed, name)
		} else if r.Prune(now) {
			changed = append(changed, name)
		}
	}
	return changed, errors.Join(errs...)
}

// JWKS renders the public keys of every asymmetric ring as one JWK Set
// (RFC 7517): per ring the current key, then next, then the retired keys
// still inside their overlap at now. Secret keys are never included.
func (s *Set) JWKS(now time.Time) []byte {
	var rings []*Ring
	for _, n := range s.Names() {
		rings = append(rings, s.Ring(n))
	}
	return JWKS(now, rings...)
}

// JWKS renders the public keys of the given rings as one JWK Set. Rings of
// secret keys are skipped.
func JWKS(now time.Time, rings ...*Ring) []byte {
	var b bytes.Buffer
	b.WriteString(`{"keys":[`)
	first := true
	add := func(k *Key) {
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.Write(k.jwk)
	}
	for _, r := range rings {
		if r.alg.Symmetric() {
			continue
		}
		st := r.state.Load()
		add(st.Current)
		if st.Next != nil {
			add(st.Next)
		}
		for _, p := range st.Previous {
			if p.Until.IsZero() || now.Before(p.Until) {
				add(p.Key)
			}
		}
	}
	b.WriteString("]}")
	return b.Bytes()
}

// Scheduler rotates a set's rings on their schedules.
type Scheduler struct {
	Set *Set
	// Every is how often rings are checked. Zero means once a second.
	Every time.Duration
	// Clock tells the time and drives the ticker; nil is the wall clock.
	// Tests pass a *clock.Fake and advance it.
	Clock clock.Clock
	// OnChange is called after a tick that changed rings, with their names:
	// the place to save the ring file and refresh published JWKS.
	OnChange func(changed []string) error
	// OnError receives rotation and OnChange failures. When nil, Run stops
	// and returns the first one.
	OnError func(error)
}

// Run checks the rings until ctx ends, then returns ctx.Err().
func (sc *Scheduler) Run(ctx context.Context) error {
	c := clock.Or(sc.Clock)
	every := sc.Every
	if every <= 0 {
		every = time.Second
	}
	t := c.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C():
		}
		changed, err := sc.Set.Tick(c.Now())
		if len(changed) > 0 && sc.OnChange != nil {
			err = errors.Join(err, sc.OnChange(changed))
		}
		if err != nil {
			if sc.OnError == nil {
				return err
			}
			sc.OnError(err)
		}
	}
}
