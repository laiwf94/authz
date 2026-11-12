package seal

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/keys"
)

var t0 = time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)

// fakeNow is a clock the test moves by hand.
type fakeNow struct{ ns atomic.Int64 }

func newFakeNow() *fakeNow {
	f := &fakeNow{}
	f.ns.Store(t0.UnixNano())
	return f
}
func (f *fakeNow) now() time.Time          { return time.Unix(0, f.ns.Load()).UTC() }
func (f *fakeNow) advance(d time.Duration) { f.ns.Add(int64(d)) }

func sealRing(t testing.TB, p keys.Policy, now time.Time) *keys.Ring {
	t.Helper()
	r, err := keys.NewRing(keys.A256GCM, p, now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func fromRing(t testing.TB, r *keys.Ring, now func() time.Time) *Keyring {
	t.Helper()
	kr, err := FromRing(r, now)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func TestFromRingErrors(t *testing.T) {
	if _, err := FromRing(nil, nil); err == nil {
		t.Fatal("nil ring accepted")
	}
	hs, err := keys.NewRing(keys.HS256, keys.Policy{}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromRing(hs, nil); err == nil {
		t.Fatal("HS256 ring accepted")
	}
	kr := fromRing(t, sealRing(t, keys.Policy{}, t0), nil) // nil clock: time.Now
	if got, err := kr.Open("p", kr.Seal("p", []byte("v"))); err != nil || string(got) != "v" {
		t.Fatalf("%q %v", got, err)
	}
	if err := kr.Rotate([][]byte{RandomKey()}); err == nil {
		t.Fatal("Rotate on a ring-backed Keyring succeeded")
	}
	if kr.Ring() == nil || ring(t, RandomKey()).Ring() != nil {
		t.Fatal("Ring() does not report the ring")
	}
}

// A key moved from a cookie key list onto a ring keeps its seal id, so
// cookies sealed before the move open after it and the other way round.
func TestFromRingKeepsListKeys(t *testing.T) {
	a, b := RandomKey(), RandomKey()
	list := ring(t, a, b)
	ka, err := keys.FromSecret(keys.A256GCM, "", a, t0)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := keys.FromSecret(keys.A256GCM, "", b, t0)
	if err != nil {
		t.Fatal(err)
	}
	r, err := keys.Configured(keys.Policy{}, t0, ka, kb)
	if err != nil {
		t.Fatal(err)
	}
	onRing := fromRing(t, r, nil)
	if got, err := onRing.Open("session", list.Seal("session", []byte("x"))); err != nil || string(got) != "x" {
		t.Fatalf("list value on the ring: %q %v", got, err)
	}
	if got, err := list.Open("session", onRing.Seal("session", []byte("y"))); err != nil || string(got) != "y" {
		t.Fatalf("ring value with the list: %q %v", got, err)
	}
	// A value sealed under the second, retired key opens too.
	if got, err := onRing.Open("session", ring(t, b).Seal("session", []byte("z"))); err != nil || string(got) != "z" {
		t.Fatalf("retired key: %q %v", got, err)
	}
	if onRing.Len() != 2 {
		t.Fatalf("Len %d, want 2", onRing.Len())
	}
}

// Rotation keeps values sealed under the old key opening until its overlap
// ends, even before a prune removes it, and a dropped key stops at once.
func TestFromRingRotation(t *testing.T) {
	clk := newFakeNow()
	r := sealRing(t, keys.Policy{RotateEvery: time.Minute, Overlap: 2 * time.Minute}, clk.now())
	kr := fromRing(t, r, clk.now)

	before := kr.Seal("session", []byte("old"))
	if kr.Len() != 2 {
		t.Fatalf("Len %d, want current and next", kr.Len())
	}

	clk.advance(time.Minute)
	if err := r.Rotate(clk.now()); err != nil {
		t.Fatal(err)
	}
	after := kr.Seal("session", []byte("new"))
	if got, err := kr.Open("session", before); err != nil || string(got) != "old" {
		t.Fatalf("old value inside the overlap: %q %v", got, err)
	}
	if kr.Len() != 3 {
		t.Fatalf("Len %d, want current, next and one retired", kr.Len())
	}

	// Overlap over: refused although the ring was not pruned and the cache
	// was built while the key was still accepted.
	clk.advance(2*time.Minute + time.Nanosecond)
	if _, err := kr.Open("session", before); !errors.Is(err, ErrInvalid) {
		t.Fatalf("value of an expired key: %v", err)
	}
	if got, err := kr.Open("session", after); err != nil || string(got) != "new" {
		t.Fatalf("current key: %q %v", got, err)
	}

	// Drop: the retired key goes at once.
	if err := r.Rotate(clk.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Open("session", after); err != nil {
		t.Fatalf("retired key inside the overlap: %v", err)
	}
	old := r.Snapshot().Previous[0].Key.ID()
	if err := r.Drop(old); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Open("session", after); !errors.Is(err, ErrInvalid) {
		t.Fatalf("value of a dropped key: %v", err)
	}
}

// A value sealed with the ring's next key, as a replica that already
// rotated would, opens here.
func TestFromRingNextKeyOpens(t *testing.T) {
	r := sealRing(t, keys.Policy{}, t0)
	kr := fromRing(t, r, nil)
	nk, err := keys.Configured(keys.Policy{}, t0, r.Next())
	if err != nil {
		t.Fatal(err)
	}
	v := fromRing(t, nk, nil).Seal("session", []byte("n"))
	if got, err := kr.Open("session", v); err != nil || string(got) != "n" {
		t.Fatalf("%q %v", got, err)
	}
	// A key the ring never held does not.
	if _, err := kr.Open("session", ring(t, RandomKey()).Seal("session", []byte("n"))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign key: %v", err)
	}
}

// Seal and Open run while the ring rotates on every step, under -race;
// every value opens inside its overlap.
func TestFromRingConcurrentRotation(t *testing.T) {
	clk := newFakeNow()
	p := keys.Policy{RotateEvery: time.Second, Overlap: 3 * time.Second}
	r := sealRing(t, p, clk.now())
	kr := fromRing(t, r, clk.now)

	var stop atomic.Bool
	var fails, opened atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			type held struct {
				v  string
				at time.Time
			}
			var hold []held
			for !stop.Load() {
				// The time is read before sealing: the key that seals was
				// current at or after it, so it opens until at+overlap.
				at := clk.now()
				hold = append(hold, held{kr.Seal("session", []byte("v")), at})
				if len(hold) > 32 {
					hold = hold[1:]
				}
				for _, h := range hold {
					_, err := kr.Open("session", h.v)
					// Only a value younger than the overlap must open.
					if err != nil && clk.now().Sub(h.at) < p.Overlap {
						fails.Add(1)
					}
					opened.Add(1)
				}
			}
		}()
	}
	for i := 0; i < 120; i++ {
		clk.advance(250 * time.Millisecond)
		if r.Due(clk.now()) {
			if err := r.Rotate(clk.now()); err != nil {
				t.Error(err)
			}
		} else {
			r.Prune(clk.now())
		}
		for n := opened.Load(); opened.Load() < n+64; {
			time.Sleep(50 * time.Microsecond)
		}
	}
	stop.Store(true)
	wg.Wait()
	if fails.Load() != 0 {
		t.Fatalf("%d of %d opens failed inside the overlap", fails.Load(), opened.Load())
	}
}

// BenchmarkSealOpenRing is BenchmarkSealOpen on a ring with retired keys.
func BenchmarkSealOpenRing(b *testing.B) {
	clk := newFakeNow()
	r := sealRing(b, keys.Policy{RotateEvery: time.Second, Overlap: 10 * time.Second}, clk.now())
	for range 4 {
		clk.advance(time.Second)
		if err := r.Rotate(clk.now()); err != nil {
			b.Fatal(err)
		}
	}
	kr := fromRing(b, r, clk.now)
	pt := []byte("0123456789abcdef0123456789abcdef0123456789a")
	old := kr.Seal("session", pt)
	clk.advance(time.Second)
	if err := r.Rotate(clk.now()); err != nil {
		b.Fatal(err)
	}
	b.Run("current", func(b *testing.B) {
		for b.Loop() {
			if _, err := kr.Open("session", kr.Seal("session", pt)); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("retired", func(b *testing.B) {
		for b.Loop() {
			if _, err := kr.Open("session", old); err != nil {
				b.Fatal(err)
			}
		}
	})
}
