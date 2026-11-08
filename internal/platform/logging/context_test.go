package logging

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const validTP = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func TestParseTraceparent(t *testing.T) {
	for _, c := range []struct {
		in, want string
	}{
		{validTP, "4bf92f3577b34da6a3ce929d0e0e4736"},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00", "4bf92f3577b34da6a3ce929d0e0e4736"},
		// A later version: the first 55 characters are read as version 00.
		{"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "4bf92f3577b34da6a3ce929d0e0e4736"},
		{"cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-09-what-the-future-holds", "4bf92f3577b34da6a3ce929d0e0e4736"},
	} {
		if got, ok := ParseTraceparent(c.in); !ok || got != c.want {
			t.Errorf("ParseTraceparent(%q) = %q, %v; want %q", c.in, got, ok, c.want)
		}
	}
	for _, in := range []string{
		"",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",        // short
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-",    // version 00 with more
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01x",    // version 00 with more
		"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01x",    // later version, no dash
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",     // version ff is invalid
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",     // uppercase
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",     // zero trace
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",     // zero parent
		"00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",     // separator
		"00-4bf92f3577b34da6a3ce929d0e0e4736_00f067aa0ba902b7-01",     // separator
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7_01",     // separator
		"0g-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",     // version hex
		"00-4bf92f3577b34da6a3ce929d0e0e473z-00f067aa0ba902b7-01",     // trace hex
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902bz-01",     // parent hex
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0z",     // flags hex
		" 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",    // leading space
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 ",    // trailing space
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\x00", // trailing NUL
	} {
		if got, ok := ParseTraceparent(in); ok {
			t.Errorf("ParseTraceparent(%q) = %q, accepted", in, got)
		}
	}
}

func FuzzParseTraceparent(f *testing.F) {
	f.Add(validTP)
	f.Add("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-x")
	f.Add("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		id, ok := ParseTraceparent(in)
		if !ok {
			if id != "" {
				t.Fatalf("refused but returned %q", id)
			}
			return
		}
		if len(id) != 32 || !lowerHex(id) || allZero(id) || !strings.Contains(in, id) {
			t.Fatalf("bad trace ID %q from %q", id, in)
		}
		// What is accepted can be sent on, and reads back the same.
		tp := Traceparent(id)
		if back, ok := ParseTraceparent(tp); !ok || back != id {
			t.Fatalf("Traceparent(%q) = %q does not parse back", id, tp)
		}
	})
}

func TestNewCorrelationID(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id := NewCorrelationID()
		if len(id) != 32 || !lowerHex(id) || allZero(id) || seen[id] {
			t.Fatalf("bad or repeated ID %q", id)
		}
		seen[id] = true
	}
}

func TestTraceparent(t *testing.T) {
	id := NewCorrelationID()
	tp := Traceparent(id)
	if len(tp) != 55 || !strings.HasPrefix(tp, "00-"+id+"-") || !strings.HasSuffix(tp, "-00") {
		t.Fatalf("Traceparent = %q", tp)
	}
	if Traceparent(id) == tp {
		t.Error("parent ID should be new each time")
	}
	for _, bad := range []string{"", "abc", strings.Repeat("0", 32), strings.ToUpper(id), id + "0", "req-123"} {
		if got := Traceparent(bad); got != "" {
			t.Errorf("Traceparent(%q) = %q, want empty", bad, got)
		}
	}
}

func TestFromRequestAndMiddleware(t *testing.T) {
	var got []string
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, CorrelationID(r.Context()))
	}))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(HeaderTraceparent, validTP)
	h.ServeHTTP(httptest.NewRecorder(), r)

	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set(HeaderTraceparent, "garbage")
	h.ServeHTTP(httptest.NewRecorder(), r)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	// An ID already in the context (set by an outer layer) is kept.
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set(HeaderTraceparent, validTP)
	h.ServeHTTP(httptest.NewRecorder(), r.WithContext(WithCorrelationID(r.Context(), "outer")))

	if got[0] != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("from traceparent: %q", got[0])
	}
	for _, id := range got[1:3] {
		if len(id) != 32 || id == got[0] {
			t.Errorf("generated: %q", id)
		}
	}
	if got[1] == got[2] {
		t.Error("generated IDs repeat")
	}
	if got[3] != "outer" {
		t.Errorf("outer ID replaced: %q", got[3])
	}
}

func TestContextAccessors(t *testing.T) {
	ctx := context.Background()
	var nilCtx context.Context // a Handler can be called with one directly
	if CorrelationID(ctx) != "" || Tenant(ctx) != "" || CorrelationID(nilCtx) != "" || Tenant(nilCtx) != "" {
		t.Fatal("empty context has values")
	}
	ctx = WithTenant(WithCorrelationID(ctx, "c"), "t")
	if CorrelationID(ctx) != "c" || Tenant(ctx) != "t" {
		t.Fatal("values lost")
	}
}

func TestCorrelate(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(HeaderTraceparent, validTP)
	r2, id := Correlate(r)
	if id != "4bf92f3577b34da6a3ce929d0e0e4736" || CorrelationID(r2.Context()) != id {
		t.Fatalf("Correlate = %q, context %q", id, CorrelationID(r2.Context()))
	}
	// Already correlated: the same request comes back.
	if r3, id3 := Correlate(r2); r3 != r2 || id3 != id {
		t.Fatalf("second Correlate = %p %q, want %p %q", r3, id3, r2, id)
	}
	r4, gen := Correlate(httptest.NewRequest("GET", "/", nil))
	if len(gen) != 32 || CorrelationID(r4.Context()) != gen || Traceparent(gen) == "" {
		t.Fatalf("generated %q", gen)
	}
}

func TestPropagate(t *testing.T) {
	const id = "4bf92f3577b34da6a3ce929d0e0e4736"
	h := http.Header{}
	h.Set(HeaderTraceparent, "00-11111111111111111111111111111111-2222222222222222-01")
	if !Propagate(WithCorrelationID(context.Background(), id), h) {
		t.Fatal("Propagate refused a trace ID")
	}
	got, ok := ParseTraceparent(h.Get(HeaderTraceparent))
	if !ok || got != id || len(h.Values(HeaderTraceparent)) != 1 {
		t.Fatalf("traceparent = %q", h.Values(HeaderTraceparent))
	}
	for _, ctx := range []context.Context{context.Background(), WithCorrelationID(context.Background(), "req-1")} {
		h := http.Header{}
		if Propagate(ctx, h) || len(h) != 0 {
			t.Fatalf("Propagate(%q) set %v", CorrelationID(ctx), h)
		}
	}
}
