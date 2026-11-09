package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/store"
)

// BenchmarkInProcessCheck measures what the engine adds to a check over
// the raw check engine: resolving the consistency, reading the schema,
// metrics and the result's token. raw calls check.Engine.Check with the
// schema and revision in hand; engine calls Local.Check with the default
// minimize_latency consistency; engine/token passes a token with
// at_least_as_fresh, which also verifies the token's MAC. Both sides walk
// the same small graph (a doc viewer through a permission with an
// exclusion) with the cross-request cache off, so the walk is short and
// the difference is the overhead alone. The roadmap's bar is under 2 µs
// (#80).
func BenchmarkInProcessCheck(b *testing.B) {
	f := newFixture(b, Options{})
	f.schema(b)
	var ops []string
	for i := range 20 {
		ops = append(ops, fmt.Sprintf("touch doc:plan#viewer@user:u%d", i))
	}
	w := f.write(b, ops...)
	sc, _ := f.st.Schema()
	rev := f.st.Head()
	raw := check.New(f.st, nil)
	user := store.Subject{Type: "user", ID: "u19"}
	q := check.Request{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: user}
	ctx := context.Background()
	if ok, _, err := raw.Check(ctx, sc, rev, q); err != nil || !ok {
		b.Fatalf("raw check = %v %v", ok, err)
	}

	b.Run("raw", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if ok, _, err := raw.Check(ctx, sc, rev, q); err != nil || !ok {
				b.Fatal(ok, err)
			}
		}
	})
	req := CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view", Subject: user}
	b.Run("engine", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if res, err := f.e.Check(ctx, req); err != nil || !res.Allowed {
				b.Fatal(res, err)
			}
		}
	})
	req.Consistency = Consistency{Mode: AtLeastAsFresh, Token: w.Token}
	b.Run("engine/token", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if res, err := f.e.Check(ctx, req); err != nil || !res.Allowed {
				b.Fatal(res, err)
			}
		}
	})
}
