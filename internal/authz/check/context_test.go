package check

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authz/store"
)

// contextOfSize returns a context whose JSON is exactly n bytes.
func contextOfSize(t *testing.T, n int) map[string]any {
	t.Helper()
	const overhead = len(`{"k":""}`)
	ctx := map[string]any{"k": strings.Repeat("y", n-overhead)}
	enc, err := json.Marshal(ctx)
	if err != nil || len(enc) != n {
		t.Fatalf("built a context of %d bytes, want %d (%v)", len(enc), n, err)
	}
	return ctx
}

func TestValidateContextLimit(t *testing.T) {
	if err := ValidateContext(contextOfSize(t, MaxContextSize)); err != nil {
		t.Errorf("a context of exactly %d bytes: %v", MaxContextSize, err)
	}
	err := ValidateContext(contextOfSize(t, MaxContextSize+1))
	if !errors.Is(err, store.ErrInvalid) || !strings.Contains(err.Error(), "max 16384") {
		t.Errorf("a context of %d bytes: %v", MaxContextSize+1, err)
	}
}

func TestValidateContextShapes(t *testing.T) {
	for _, ctx := range []map[string]any{nil, {}} {
		if err := ValidateContext(ctx); err != nil {
			t.Errorf("ValidateContext(%v): %v", ctx, err)
		}
	}
	if err := ValidateContext(map[string]any{"x": make(chan int)}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("an unencodable value: %v", err)
	}
}

// The check cache keys on the context's hash, so equal contexts must hash
// equal however they were built, and different ones must not.
func TestRequestContextHash(t *testing.T) {
	a, err := newRequestContext(map[string]any{"a": 1, "b": "x", "c": []any{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(`{"c":[1,2],"b":"x","a":1}`), &decoded); err != nil {
		t.Fatal(err)
	}
	b, err := newRequestContext(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if a.hash != b.hash {
		t.Errorf("equal contexts hash %q and %q", a.hash, b.hash)
	}
	c, err := newRequestContext(map[string]any{"a": 2, "b": "x", "c": []any{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if c.hash == a.hash {
		t.Errorf("different contexts share hash %q", c.hash)
	}
	none, err := newRequestContext(nil)
	if err != nil || none.hash != "-" || none.vals != nil {
		t.Errorf("no context: %+v, %v", none, err)
	}
}
