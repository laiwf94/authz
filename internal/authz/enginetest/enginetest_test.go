package enginetest

import (
	"testing"

	"github.com/laiwf94/authz/internal/authz/engine"
)

func TestLocal(t *testing.T) {
	Run(t, func(t testing.TB, schemaSrc string) engine.Engine {
		return NewLocal(t, schemaSrc, engine.Options{})
	})
}

// The shared check cache must not change an answer across revisions.
func TestLocalCached(t *testing.T) {
	Run(t, func(t testing.TB, schemaSrc string) engine.Engine {
		return NewLocal(t, schemaSrc, engine.Options{CacheSize: 10_000})
	})
}

func TestFake(t *testing.T) {
	Run(t, func(t testing.TB, schemaSrc string) engine.Engine {
		f, err := NewFake(schemaSrc)
		if err != nil {
			t.Fatal(err)
		}
		return f
	})
}
