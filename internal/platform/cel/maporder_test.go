package cel

import (
	"strings"
	"testing"
)

// A map with more than one bad entry is refused naming the same entry
// every time, the first in key order, whatever order Go iterates it in
// (#255, found by FuzzEvalContext).
func TestMapInputErrorIsDeterministic(t *testing.T) {
	env := testEnv(t)
	c, err := env.Compile(`ms.filter(k, ms[k] == s)`)
	if err != nil {
		t.Fatal(err)
	}
	p := c.Program(20000)
	ms := map[string]any{"": []any{1.0, 1.0}, "0": 1.0, "1": "8", "2": true, "3": 2.0}
	var first string
	for i := range 200 {
		_, err := p.Eval(map[string]any{"ms": ms, "s": "x"})
		if err == nil {
			t.Fatal("a map with bad entries was accepted")
		}
		if i == 0 {
			first = err.Error()
			continue
		}
		if err.Error() != first {
			t.Fatalf("the error changed between runs: %q, then %q", first, err.Error())
		}
	}
	if !strings.Contains(first, "ms [] ") {
		t.Fatalf("the error names %q, want the first key in order, \"\"", first)
	}
	// A good map still converts.
	r, err := p.Eval(map[string]any{"ms": map[string]any{"a": "x", "b": "y"}, "s": "x"})
	if err != nil || r.Value == nil {
		t.Fatalf("good map: %v %v", r, err)
	}
	// Keys of different Go types that print alike sort by type too.
	md, err := env.Compile(`size(md) > 0`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := md.Program(20000).Eval(map[string]any{"md": map[any]any{1: "a", int64(1): "b"}}); err == nil {
		t.Fatal("map<string, dyn> with int keys accepted")
	}
}
