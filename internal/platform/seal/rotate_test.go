package seal

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// Rotate changes the keys of a ring in place: values sealed before open
// while the old key is still listed, and stop opening once it is dropped.
func TestRotateInPlace(t *testing.T) {
	oldKey, newKey := RandomKey(), RandomKey()
	kr := ring(t, oldKey)
	before := kr.Seal("session", []byte("v"))

	if err := kr.Rotate([][]byte{newKey, oldKey}); err != nil {
		t.Fatal(err)
	}
	if kr.Len() != 2 {
		t.Fatalf("Len %d, want 2", kr.Len())
	}
	if got, err := kr.Open("session", before); err != nil || string(got) != "v" {
		t.Fatalf("old value during the overlap: %q %v", got, err)
	}
	during := kr.Seal("session", []byte("w"))
	if _, err := ring(t, newKey).Open("session", during); err != nil {
		t.Fatalf("the first key does not seal after Rotate: %v", err)
	}

	if err := kr.Rotate([][]byte{newKey}); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Open("session", before); !errors.Is(err, ErrInvalid) {
		t.Fatalf("value of a dropped key: %v", err)
	}
	if got, err := kr.Open("session", during); err != nil || string(got) != "w" {
		t.Fatalf("value of the kept key: %q %v", got, err)
	}
}

// A rejected Rotate keeps the keys in use.
func TestRotateRefused(t *testing.T) {
	k := RandomKey()
	kr := ring(t, k)
	v := kr.Seal("p", []byte("x"))
	for name, keys := range map[string][][]byte{
		"none":      nil,
		"short":     {k[:16]},
		"duplicate": {k, k},
		"too many":  make([][]byte, maxKeys+1),
	} {
		if err := kr.Rotate(keys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if kr.Len() != 1 {
		t.Fatalf("Len %d after refused rotations", kr.Len())
	}
	if _, err := kr.Open("p", v); err != nil {
		t.Fatalf("keys changed by a refused Rotate: %v", err)
	}
}

// Sealing and opening while the ring rotates: every value sealed with a key
// that every version lists opens, whichever version seals and opens it.
func TestRotateConcurrent(t *testing.T) {
	shared, a, b := RandomKey(), RandomKey(), RandomKey()
	kr := ring(t, shared, a)
	versions := [][][]byte{{shared, a}, {shared, b}, {shared, a, b}, {shared}}
	var stop atomic.Bool
	var wg sync.WaitGroup
	var failures atomic.Int64
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if _, err := kr.Open("p", kr.Seal("p", []byte("x"))); err != nil {
					failures.Add(1)
				}
			}
		}()
	}
	for i := range 2000 {
		if err := kr.Rotate(versions[i%len(versions)]); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d values did not open across rotations", n)
	}
}
