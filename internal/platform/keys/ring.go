package keys

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// MaxPrevious bounds the retired keys a ring keeps, so a misconfigured
// overlap can't grow a ring without limit. When a rotation would exceed it
// the oldest retired key goes first.
const MaxPrevious = 15

// MinRotateEvery is the shortest rotation period a ring accepts.
const MinRotateEvery = time.Second

// Policy says when a ring rotates and how long retired keys verify.
type Policy struct {
	// RotateEvery is how long a key stays current. Zero means the ring only
	// rotates when Rotate is called.
	RotateEvery time.Duration
	// Overlap is how long a retired key keeps verifying. It must cover the
	// longest lifetime of anything the ring signs or seals: tokens issued
	// just before a rotation must still verify until they expire.
	Overlap time.Duration
}

// Check reports whether p is usable.
func (p Policy) Check() error {
	switch {
	case p.RotateEvery < 0 || p.Overlap < 0:
		return errors.New("keys: rotation period and overlap can't be negative")
	case p.RotateEvery > 0 && p.RotateEvery < MinRotateEvery:
		return fmt.Errorf("keys: rotation period %s is shorter than %s", p.RotateEvery, MinRotateEvery)
	case p.RotateEvery > 0 && p.Overlap == 0:
		return errors.New("keys: a ring that rotates on schedule needs an overlap, or every rotation invalidates what the old key signed")
	case p.RotateEvery > 0 && p.Overlap > MaxPrevious*p.RotateEvery:
		return fmt.Errorf("keys: overlap %s is longer than %d rotation periods", p.Overlap, MaxPrevious)
	}
	return nil
}

// Retired is a key that stopped being current and verifies until Until. A
// zero Until never expires: keys an operator lists in configuration stay
// until the operator removes them.
type Retired struct {
	Key   *Key
	Until time.Time
}

// Snapshot is the state of a ring at one moment.
type Snapshot struct {
	Current   *Key
	Activated time.Time // when Current became current
	Next      *Key      // nil until the first rotation of a configured ring
	Previous  []Retired // newest first
}

// Ring holds the keys of one algorithm. Reads are lock-free; rotations are
// serialized. It is safe for concurrent use.
type Ring struct {
	alg    Alg
	policy Policy
	gen    func(Alg, time.Time) (*Key, error)

	mu    sync.Mutex // serializes writers
	state atomic.Pointer[Snapshot]
}

// NewRing makes a ring with freshly generated current and next keys.
func NewRing(alg Alg, p Policy, now time.Time) (*Ring, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrAlg, alg)
	}
	cur, err := Generate(alg, now)
	if err != nil {
		return nil, err
	}
	next, err := Generate(alg, now)
	if err != nil {
		return nil, err
	}
	return Restore(alg, p, Snapshot{Current: cur, Activated: now, Next: next})
}

// Restore makes a ring from a saved or configured state: the keys a ring
// file holds, or the keys a configuration lists, first one current.
func Restore(alg Alg, p Policy, s Snapshot) (*Ring, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrAlg, alg)
	}
	if err := p.Check(); err != nil {
		return nil, err
	}
	if s.Current == nil {
		return nil, errors.New("keys: a ring needs a current key")
	}
	if len(s.Previous) > MaxPrevious {
		return nil, fmt.Errorf("keys: %d previous keys; at most %d", len(s.Previous), MaxPrevious)
	}
	seen := map[string]bool{}
	check := func(k *Key, role string) error {
		if k == nil {
			return fmt.Errorf("keys: %s key is missing", role)
		}
		if k.alg != alg {
			return fmt.Errorf("%w: %s key %s is %s, the ring holds %s", ErrRingAlg, role, k.id, k.alg, alg)
		}
		if seen[k.id] {
			return fmt.Errorf("keys: key id %s appears twice", k.id)
		}
		seen[k.id] = true
		return nil
	}
	if err := check(s.Current, "current"); err != nil {
		return nil, err
	}
	if s.Next != nil {
		if err := check(s.Next, "next"); err != nil {
			return nil, err
		}
	}
	for _, r := range s.Previous {
		if err := check(r.Key, "previous"); err != nil {
			return nil, err
		}
	}
	s.Activated = s.Activated.UTC()
	s.Previous = append([]Retired(nil), s.Previous...)
	r := &Ring{alg: alg, policy: p, gen: Generate}
	r.state.Store(&s)
	return r, nil
}

// Alg returns the algorithm of every key in the ring.
func (r *Ring) Alg() Alg { return r.alg }

// Policy returns the ring's rotation policy.
func (r *Ring) Policy() Policy { return r.policy }

// Current returns the key that signs or seals now.
func (r *Ring) Current() *Key { return r.state.Load().Current }

// Next returns the key that becomes current at the next rotation, or nil.
func (r *Ring) Next() *Key { return r.state.Load().Next }

// Snapshot returns the ring's state. The slice is the caller's.
func (r *Ring) Snapshot() Snapshot {
	s := *r.state.Load()
	s.Previous = append([]Retired(nil), s.Previous...)
	return s
}

// Lookup returns the key with id kid that may verify or open: the current
// key, a retired key inside its overlap at now, or the next key. Expired
// keys still in the ring because no prune has run yet are refused.
func (r *Ring) Lookup(kid string, now time.Time) *Key {
	s := r.state.Load()
	if s.Current.id == kid {
		return s.Current
	}
	for _, p := range s.Previous {
		if p.Key.id == kid {
			if !p.Until.IsZero() && !now.Before(p.Until) {
				return nil
			}
			return p.Key
		}
	}
	if s.Next != nil && s.Next.id == kid {
		return s.Next
	}
	return nil
}

// Verifying returns every key that verifies at now: current, the retired
// keys inside their overlap (newest first), then next.
func (r *Ring) Verifying(now time.Time) []*Key {
	s := r.state.Load()
	out := make([]*Key, 0, 2+len(s.Previous))
	out = append(out, s.Current)
	for _, p := range s.Previous {
		if p.Until.IsZero() || now.Before(p.Until) {
			out = append(out, p.Key)
		}
	}
	if s.Next != nil {
		out = append(out, s.Next)
	}
	return out
}

// Sign signs msg with the current key and returns its id with the
// signature.
func (r *Ring) Sign(msg []byte) (kid string, sig []byte, err error) {
	k := r.Current()
	sig, err = k.Sign(msg)
	return k.id, sig, err
}

// Verify checks sig over msg with the key named kid, if that key verifies
// at now.
func (r *Ring) Verify(kid string, msg, sig []byte, now time.Time) error {
	k := r.Lookup(kid, now)
	if k == nil {
		return ErrNotFound
	}
	if !k.Verify(msg, sig) {
		return errors.New("keys: signature does not verify")
	}
	return nil
}

// Due reports whether the current key has been current for RotateEvery.
func (r *Ring) Due(now time.Time) bool {
	return r.policy.RotateEvery > 0 && !now.Before(r.state.Load().Activated.Add(r.policy.RotateEvery))
}

// Rotate retires the current key for Overlap, makes next current and
// generates a new next. A ring without a next key (one built from
// configured keys) generates both.
func (r *Ring) Rotate(now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.state.Load()
	cur := old.Next
	if cur == nil {
		var err error
		if cur, err = r.gen(r.alg, now); err != nil {
			return err
		}
	}
	next, err := r.gen(r.alg, now)
	if err != nil {
		return err
	}
	until := now.Add(r.policy.Overlap).UTC()
	if r.policy.Overlap == 0 {
		// Manually rotated rings with no overlap keep the old key until an
		// operator drops it, like configured keys.
		until = time.Time{}
	}
	prev := append([]Retired{{Key: old.Current, Until: until}}, live(old.Previous, now)...)
	if len(prev) > MaxPrevious {
		prev = prev[:MaxPrevious]
	}
	r.state.Store(&Snapshot{Current: cur, Activated: now.UTC(), Next: next, Previous: prev})
	return nil
}

// Prune drops retired keys whose overlap has ended at now and reports
// whether any went.
func (r *Ring) Prune(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.state.Load()
	prev := live(old.Previous, now)
	if len(prev) == len(old.Previous) {
		return false
	}
	s := *old
	s.Previous = prev
	r.state.Store(&s)
	return true
}

// Drop removes the retired key kid at once, for an operator retiring a
// compromised key. The current and next keys can't be dropped: rotate
// first.
func (r *Ring) Drop(kid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.state.Load()
	for i, p := range old.Previous {
		if p.Key.id == kid {
			s := *old
			s.Previous = append(append([]Retired(nil), old.Previous[:i]...), old.Previous[i+1:]...)
			r.state.Store(&s)
			return nil
		}
	}
	if old.Current.id == kid || (old.Next != nil && old.Next.id == kid) {
		return fmt.Errorf("keys: %s is the current or next key; rotate before dropping it", kid)
	}
	return ErrNotFound
}

func live(prev []Retired, now time.Time) []Retired {
	out := make([]Retired, 0, len(prev))
	for _, p := range prev {
		if p.Until.IsZero() || now.Before(p.Until) {
			out = append(out, p)
		}
	}
	return out
}
