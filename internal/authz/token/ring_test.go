package token

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/platform/keys"
)

var t0 = time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)

type fakeClock struct{ ns atomic.Int64 }

func newClock(t time.Time) *fakeClock {
	c := &fakeClock{}
	c.ns.Store(t.UnixNano())
	return c
}
func (c *fakeClock) Now() time.Time       { return time.Unix(0, c.ns.Load()).UTC() }
func (c *fakeClock) Add(d time.Duration)  { c.ns.Add(int64(d)) }
func (c *fakeClock) Set(t time.Time)      { c.ns.Store(t.UnixNano()) }
func (c *fakeClock) since() time.Duration { return c.Now().Sub(t0) }
func (c *fakeClock) String() string       { return c.since().String() }
func ringIssuer(t testing.TB, p keys.Policy, c *fakeClock) *Issuer {
	t.Helper()
	r, err := keys.NewRing(keys.HS256, p, c.Now())
	if err != nil {
		t.Fatal(err)
	}
	i, err := FromRing(r, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

// The wire format did not change with the move to rings: version byte,
// big-endian revision, then the first 16 bytes of HMAC-SHA256 over both.
func TestFormatUnchanged(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	i, err := NewIssuer(key)
	if err != nil {
		t.Fatal(err)
	}
	body := binary.BigEndian.AppendUint64([]byte{1}, 1234567)
	m := hmac.New(sha256.New, key)
	m.Write(body)
	want := base64.RawURLEncoding.EncodeToString(append(body, m.Sum(nil)[:16]...))
	if got := i.Encode(1234567); got != want {
		t.Fatalf("Encode = %s, want %s", got, want)
	}
	if i.Ring().Alg() != keys.HS256 || i.Ring().Policy() != (keys.Policy{}) {
		t.Fatalf("single-key ring: %s %+v", i.Ring().Alg(), i.Ring().Policy())
	}
}

func TestRotationKeepsOutstandingTokens(t *testing.T) {
	c := newClock(t0)
	p := keys.Policy{RotateEvery: time.Hour, Overlap: 90 * time.Minute}
	i := ringIssuer(t, p, c)
	r := i.Ring()

	before := i.Encode(10)
	c.Add(time.Hour)
	if !r.Due(c.Now()) {
		t.Fatal("ring not due after RotateEvery")
	}
	if err := r.Rotate(c.Now()); err != nil {
		t.Fatal(err)
	}
	after := i.Encode(10)
	if after == before {
		t.Fatal("rotation did not change the MAC key")
	}
	for _, tok := range []string{before, after} {
		if rev, err := i.Decode(tok); err != nil || rev != 10 {
			t.Fatalf("after one rotation: %d, %v", rev, err)
		}
	}

	// A second rotation inside the first key's overlap keeps it verifying.
	c.Add(time.Hour)
	if err := r.Rotate(c.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Decode(before); err != nil {
		t.Fatalf("token from two keys ago, inside its overlap: %v", err)
	}
	// The first key retired at t0+1h for 90 minutes: at t0+2h30 it is gone,
	// even before a prune removes it from the ring.
	c.Set(t0.Add(150 * time.Minute))
	if _, err := i.Decode(before); !errors.Is(err, ErrInvalid) {
		t.Fatalf("token past its key's overlap accepted: %v", err)
	}
	if _, err := i.Decode(after); err != nil {
		t.Fatalf("token from the previous key: %v", err)
	}
	if !r.Prune(c.Now()) {
		t.Fatal("expired key not pruned")
	}
	if _, err := i.Decode(before); !errors.Is(err, ErrInvalid) {
		t.Fatal("pruned key verifies")
	}
}

// A process that has already rotated a shared ring issues tokens under what
// is still the next key here; they verify before this process rotates.
func TestNextKeyVerifies(t *testing.T) {
	c := newClock(t0)
	p := keys.Policy{RotateEvery: time.Hour, Overlap: time.Hour}
	here := ringIssuer(t, p, c)
	s := here.Ring().Snapshot()
	ahead, err := keys.Restore(keys.HS256, p, keys.Snapshot{Current: s.Next, Activated: t0,
		Previous: []keys.Retired{{Key: s.Current, Until: t0.Add(time.Hour)}}})
	if err != nil {
		t.Fatal(err)
	}
	other, err := FromRing(ahead, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	if rev, err := here.Decode(other.Encode(99)); err != nil || rev != 99 {
		t.Fatalf("token under the next key: %d, %v", rev, err)
	}
	if rev, err := other.Decode(here.Encode(98)); err != nil || rev != 98 {
		t.Fatalf("token under the retired key: %d, %v", rev, err)
	}
}

func TestDroppedKeyStopsAtOnce(t *testing.T) {
	c := newClock(t0)
	i := ringIssuer(t, keys.Policy{RotateEvery: time.Hour, Overlap: time.Hour}, c)
	r := i.Ring()
	old := r.Current().ID()
	tok := i.Encode(3)
	if err := r.Rotate(c.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Decode(tok); err != nil {
		t.Fatal(err)
	}
	if err := r.Drop(old); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Decode(tok); !errors.Is(err, ErrInvalid) {
		t.Fatal("token under a dropped key accepted")
	}
}

func TestNewIssuerKeys(t *testing.T) {
	k1, k2, k3 := bytes.Repeat([]byte{1}, KeySize), bytes.Repeat([]byte{2}, KeySize), bytes.Repeat([]byte{3}, KeySize)
	old1, _ := NewIssuer(k2)
	old2, _ := NewIssuer(k3)
	i, err := NewIssuerKeys(k1, k2, k3)
	if err != nil {
		t.Fatal(err)
	}
	only1, _ := NewIssuer(k1)
	if i.Encode(5) != only1.Encode(5) {
		t.Fatal("new tokens are not MACed with the first key")
	}
	for n, tok := range []string{old1.Encode(6), old2.Encode(7)} {
		if rev, err := i.Decode(tok); err != nil || rev != store.Revision(6+n) {
			t.Fatalf("previous key %d: %d, %v", n+1, rev, err)
		}
	}
	// Configured previous keys never expire on their own.
	if v := i.Ring().Verifying(t0.Add(100 * 365 * 24 * time.Hour)); len(v) != 3 {
		t.Fatalf("%d keys verify a century later, want 3", len(v))
	}
	if _, err := only1.Decode(old1.Encode(6)); !errors.Is(err, ErrInvalid) {
		t.Fatal("single-key issuer accepts another key")
	}
	if _, err := NewIssuerKeys(k1, make([]byte, 31)); err == nil {
		t.Fatal("short previous key accepted")
	}
	if _, err := NewIssuerKeys(k1, k2, k1); err == nil {
		t.Fatal("repeated key accepted")
	}
	if _, err := NewIssuerKeys(nil); err == nil {
		t.Fatal("missing key accepted")
	}
}

func TestFromRingRefuses(t *testing.T) {
	if _, err := FromRing(nil, nil); err == nil {
		t.Fatal("nil ring accepted")
	}
	for _, alg := range []keys.Alg{keys.A256GCM, keys.ES256} {
		r, err := keys.NewRing(alg, keys.Policy{}, t0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := FromRing(r, nil); err == nil {
			t.Fatalf("%s ring accepted", alg)
		}
	}
	// A nil clock is the wall clock: a fresh ring's keys verify now.
	r, _ := keys.NewRing(keys.HS256, keys.Policy{}, time.Now())
	i, err := FromRing(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.Decode(i.Encode(1)); err != nil {
		t.Fatal(err)
	}
}

// Readers and writers keep issuing and verifying while the ring rotates
// under them as fast as it can. Every token issued in the last overlap must
// verify: zero failures.
func TestRotationUnderLoad(t *testing.T) {
	c := newClock(t0)
	// Overlap covers MaxPrevious rotations; tokens are checked against the
	// rotations that happened since they were issued.
	p := keys.Policy{RotateEvery: time.Second, Overlap: keys.MaxPrevious * time.Second}
	i := ringIssuer(t, p, c)
	r := i.Ring()

	var rotations atomic.Int64
	stop := make(chan struct{})
	var rot sync.WaitGroup
	rot.Add(1)
	go func() {
		defer rot.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			c.Add(time.Second)
			if err := r.Rotate(c.Now()); err != nil {
				t.Error(err)
				return
			}
			rotations.Add(1)
		}
	}()

	const workers, perWorker = 8, 2000
	var failures, crossed atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for n := 0; n < perWorker; n++ {
				rev := store.Revision(w*perWorker + n)
				start := rotations.Load()
				tok := i.Encode(rev)
				got, err := i.Decode(tok)
				if rotations.Load() != start {
					crossed.Add(1)
				}
				// A token can only fail if more rotations than the overlap
				// covers ran between Encode and Decode; count those apart.
				if err != nil && rotations.Load()-start < keys.MaxPrevious-1 {
					failures.Add(1)
				}
				if err == nil && got != rev {
					failures.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	rot.Wait()
	if f := failures.Load(); f != 0 {
		t.Fatalf("%d of %d tokens failed across %d rotations", f, workers*perWorker, rotations.Load())
	}
	if rotations.Load() == 0 {
		t.Fatal("ring never rotated")
	}
	t.Logf("%d tokens, %d rotations, %d tokens crossed a rotation between Encode and Decode",
		workers*perWorker, rotations.Load(), crossed.Load())
}

func benchIssuer(b *testing.B, previous int) (*Issuer, []string) {
	c := newClock(t0)
	i := ringIssuer(b, keys.Policy{RotateEvery: time.Second, Overlap: keys.MaxPrevious * time.Second}, c)
	var old []string
	for n := 0; n < previous; n++ {
		old = append(old, i.Encode(store.Revision(n)))
		c.Add(time.Second)
		if err := i.Ring().Rotate(c.Now()); err != nil {
			b.Fatal(err)
		}
	}
	return i, old
}

func BenchmarkEncode(b *testing.B) {
	i, _ := benchIssuer(b, 0)
	b.ReportAllocs()
	for b.Loop() {
		i.Encode(12345)
	}
}

func BenchmarkDecode(b *testing.B) {
	i, _ := benchIssuer(b, keys.MaxPrevious)
	tok := i.Encode(12345)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := i.Decode(tok); err != nil {
			b.Fatal(err)
		}
	}
}

// The oldest key a full ring still accepts: the slowest valid token.
func BenchmarkDecodeOldest(b *testing.B) {
	i, old := benchIssuer(b, keys.MaxPrevious)
	tok := old[0]
	b.ReportAllocs()
	for b.Loop() {
		if _, err := i.Decode(tok); err != nil {
			b.Fatal(err)
		}
	}
}

// A forged token on a full ring: the worst case an attacker can force.
func BenchmarkDecodeForged(b *testing.B) {
	i, _ := benchIssuer(b, keys.MaxPrevious)
	raw, _ := base64.RawURLEncoding.DecodeString(i.Encode(12345))
	raw[len(raw)-1] ^= 1
	tok := base64.RawURLEncoding.EncodeToString(raw)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := i.Decode(tok); err == nil {
			b.Fatal("forged token verified")
		}
	}
}

// A key the MAC cache was built without (here because the clock went back
// inside the old key's overlap) still verifies, through the unpooled path.
func TestUncachedKeyVerifies(t *testing.T) {
	c := newClock(t0)
	i := ringIssuer(t, keys.Policy{RotateEvery: time.Hour, Overlap: time.Hour}, c)
	old := i.Encode(4)
	if err := i.Ring().Rotate(c.Now()); err != nil {
		t.Fatal(err)
	}
	c.Add(2 * time.Hour)
	i.Encode(5) // builds the cache without the expired key
	if _, err := i.Decode(old); !errors.Is(err, ErrInvalid) {
		t.Fatal("expired key verifies")
	}
	c.Set(t0.Add(time.Minute))
	if rev, err := i.Decode(old); err != nil || rev != 4 {
		t.Fatalf("uncached key inside its overlap: %d, %v", rev, err)
	}
}
