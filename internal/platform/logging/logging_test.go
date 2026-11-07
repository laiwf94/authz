package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/slogtest"
	"time"
)

// lines decodes buf's JSON lines.
func lines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func one(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	ls := lines(t, buf)
	if len(ls) != 1 {
		t.Fatalf("got %d lines, want 1: %s", len(ls), buf)
	}
	return ls[0]
}

func TestSlogtest(t *testing.T) {
	var buf bytes.Buffer
	slogtest.Run(t, func(*testing.T) slog.Handler {
		buf.Reset()
		return New(&buf, Options{})
	}, func(t *testing.T) map[string]any {
		return one(t, &buf)
	})
}

// TestSlogtestWithContext runs the slog conformance suite with a
// correlation ID and tenant in every context, which takes the paths that
// add attributes; the suite ignores keys it did not ask for.
func TestSlogtestWithContext(t *testing.T) {
	var buf bytes.Buffer
	ctx := WithTenant(WithCorrelationID(context.Background(), "abc"), "t1")
	h := func() slog.Handler {
		buf.Reset()
		return New(&buf, Options{Subcommand: "serve"})
	}
	slogtest.Run(t, func(*testing.T) slog.Handler { return ctxHandler{h(), ctx} },
		func(t *testing.T) map[string]any {
			m := one(t, &buf)
			if m[KeySubcommand] != "serve" {
				t.Errorf("subcommand = %v", m[KeySubcommand])
			}
			// Records the suite drops never reach here.
			if m[KeyCorrelationID] != "abc" || m[KeyTenant] != "t1" {
				t.Errorf("context attributes missing: %v", m)
			}
			delete(m, KeySubcommand)
			delete(m, KeyCorrelationID)
			delete(m, KeyTenant)
			return m
		})
}

// ctxHandler replaces the context of every Handle call, so slogtest's
// records carry a correlation ID and tenant.
type ctxHandler struct {
	slog.Handler
	ctx context.Context
}

func (c ctxHandler) Handle(_ context.Context, r slog.Record) error { return c.Handler.Handle(c.ctx, r) }
func (c ctxHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return ctxHandler{c.Handler.WithAttrs(a), c.ctx}
}
func (c ctxHandler) WithGroup(n string) slog.Handler {
	return ctxHandler{c.Handler.WithGroup(n), c.ctx}
}

// TestSameBytesAsJSONHandler: without a subcommand, tenant or context
// values the Handler writes exactly what slog's JSON handler writes, so the
// subcommands can move to it without changing a log line.
func TestSameBytesAsJSONHandler(t *testing.T) {
	ts := time.Date(2026, 11, 7, 1, 2, 3, 4, time.UTC)
	logAll := func(h slog.Handler) {
		h = h.WithAttrs([]slog.Attr{slog.String("component", "x")})
		for _, hh := range []slog.Handler{h, h.WithGroup("g").WithAttrs([]slog.Attr{slog.Int("n", 1)})} {
			r := slog.NewRecord(ts, slog.LevelWarn, "hello \"you\"", 0)
			r.AddAttrs(slog.String("addr", "127.0.0.1:1"), slog.Bool("persistent", true),
				slog.Uint64("revision", 7), slog.Duration("d", time.Second), slog.Any("err", errors.New("boom")),
				slog.Group("sub", slog.Float64("f", 1.5)), slog.Any("m", map[string]int{"a": 1}))
			if err := hh.Handle(context.Background(), r); err != nil {
				t.Fatal(err)
			}
		}
	}
	var a, b bytes.Buffer
	logAll(slog.NewJSONHandler(&a, nil))
	logAll(New(&b, Options{}))
	if a.String() != b.String() {
		t.Fatalf("output differs:\nslog: %s\nours: %s", a.String(), b.String())
	}
	if a.Len() == 0 {
		t.Fatal("nothing written")
	}
}

func TestContextAttributes(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, Options{Subcommand: "gateway", Tenant: "acme"})
	ctx := WithCorrelationID(context.Background(), "4bf92f3577b34da6a3ce929d0e0e4736")

	log.InfoContext(ctx, "one", "k", "v")
	m := one(t, &buf)
	for k, want := range map[string]any{
		KeySubcommand: "gateway", KeyCorrelationID: "4bf92f3577b34da6a3ce929d0e0e4736",
		KeyTenant: "acme", "k": "v", "msg": "one",
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v", k, m[k], want)
		}
	}

	buf.Reset()
	log.InfoContext(WithTenant(ctx, "other"), "two")
	if m := one(t, &buf); m[KeyTenant] != "other" {
		t.Errorf("context tenant: %v", m[KeyTenant])
	}

	buf.Reset()
	NewLogger(&buf, Options{}).InfoContext(context.Background(), "three")
	m = one(t, &buf)
	for _, k := range []string{KeySubcommand, KeyCorrelationID, KeyTenant} {
		if _, ok := m[k]; ok {
			t.Errorf("%s present without a value: %v", k, m)
		}
	}

	// A nil context, which a direct Handle call can pass, adds nothing and
	// does not panic.
	buf.Reset()
	var nilCtx context.Context
	if err := New(&buf, Options{}).Handle(nilCtx, slog.NewRecord(time.Time{}, slog.LevelInfo, "nil", 0)); err != nil {
		t.Fatal(err)
	}
	if m := one(t, &buf); len(m) != 2 {
		t.Errorf("nil context: %v", m)
	}
}

// TestContextAttributesOutsideGroups: the correlation ID and tenant stay at
// the top level of a record however many groups the logger opened, and the
// record's own attributes stay in the groups.
func TestContextAttributesOutsideGroups(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, Options{Subcommand: "mcp"}).With("a", 1).WithGroup("req").With("b", 2).WithGroup("inner")
	ctx := WithTenant(WithCorrelationID(context.Background(), "cid"), "t")
	log.InfoContext(ctx, "m", "c", 3)
	got := strings.TrimSpace(buf.String())
	// Field order is part of the format: time, level, msg, then attributes.
	i := strings.Index(got, `"msg":"m",`)
	if i < 0 {
		t.Fatalf("no msg: %s", got)
	}
	want := `"msg":"m","subcommand":"mcp","correlation_id":"cid","tenant":"t","a":1,"req":{"b":2,"inner":{"c":3}}}`
	if got[i:] != want {
		t.Fatalf("got  %s\nwant %s", got[i:], want)
	}

	// Without context values the groups are written as slog writes them.
	buf.Reset()
	log.Info("m", "c", 3)
	if !strings.HasSuffix(strings.TrimSpace(buf.String()), `"msg":"m","subcommand":"mcp","a":1,"req":{"b":2,"inner":{"c":3}}}`) {
		t.Fatalf("got %s", buf.String())
	}
}

// TestNoDuplicateKeys: a correlation ID or tenant the logger or the record
// already has at the top level is not added a second time.
func TestNoDuplicateKeys(t *testing.T) {
	ctx := WithTenant(WithCorrelationID(context.Background(), "ctx-id"), "ctx-tenant")
	for _, c := range []struct {
		name string
		log  func(*slog.Logger)
		want map[string]string
	}{
		{"logger has both", func(l *slog.Logger) {
			l.With(KeyCorrelationID, "own", KeyTenant, "own-t").InfoContext(ctx, "m")
		}, map[string]string{KeyCorrelationID: "own", KeyTenant: "own-t"}},
		{"logger has correlation", func(l *slog.Logger) {
			l.With(KeyCorrelationID, "own").InfoContext(ctx, "m")
		}, map[string]string{KeyCorrelationID: "own", KeyTenant: "ctx-tenant"}},
		{"record has correlation", func(l *slog.Logger) {
			l.InfoContext(ctx, "m", KeyCorrelationID, "rec")
		}, map[string]string{KeyCorrelationID: "rec", KeyTenant: "ctx-tenant"}},
		{"record has both", func(l *slog.Logger) {
			l.InfoContext(ctx, "m", KeyTenant, "rt", "x", 1, KeyCorrelationID, "rec")
		}, map[string]string{KeyCorrelationID: "rec", KeyTenant: "rt"}},
		{"record has tenant, many attributes", func(l *slog.Logger) {
			l.InfoContext(ctx, "m", "a", 1, "b", 2, "c", 3, "d", 4, "e", 5, "f", 6, KeyTenant, "rt")
		}, map[string]string{KeyCorrelationID: "ctx-id", KeyTenant: "rt"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			c.log(NewLogger(&buf, Options{}))
			for k, v := range c.want {
				if n := strings.Count(buf.String(), `"`+k+`":`); n != 1 {
					t.Errorf("%s appears %d times: %s", k, n, buf.String())
				}
				if m := one(t, &buf); m[k] != v {
					t.Errorf("%s = %v, want %v", k, m[k], v)
				}
			}
		})
	}
}

// TestGroupedKeyIsNotTopLevel: a correlation_id inside a group does not
// stand for the record's, so the context's is still added.
func TestGroupedKeyIsNotTopLevel(t *testing.T) {
	var buf bytes.Buffer
	ctx := WithCorrelationID(context.Background(), "ctx-id")
	NewLogger(&buf, Options{}).WithGroup("g").With(KeyCorrelationID, "grouped").InfoContext(ctx, "m")
	if !strings.HasSuffix(strings.TrimSpace(buf.String()), `"correlation_id":"ctx-id","g":{"correlation_id":"grouped"}}`) {
		t.Fatalf("got %s", buf.String())
	}
}

// TestRecordNotModified: Handle never appends to the caller's record, which
// another handler may hold too.
func TestRecordNotModified(t *testing.T) {
	h := New(io.Discard, Options{Tenant: "t"})
	ctx := WithCorrelationID(context.Background(), "c")
	r := slog.NewRecord(time.Time{}, slog.LevelInfo, "m", 0)
	r.AddAttrs(slog.Int("a", 1), slog.Int("b", 2), slog.Int("c", 3), slog.Int("d", 4), slog.Int("e", 5), slog.Int("f", 6))
	for range 3 {
		if err := h.Handle(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if r.NumAttrs() != 6 {
		t.Fatalf("record has %d attributes, want 6", r.NumAttrs())
	}
	r2 := r // a copy sharing storage: appending to either would panic in slog
	r2.AddAttrs(slog.Int("g", 7))
}

func TestWithEmpty(t *testing.T) {
	h := New(io.Discard, Options{})
	if h.WithAttrs(nil) != slog.Handler(h) || h.WithGroup("") != slog.Handler(h) {
		t.Fatal("empty WithAttrs or WithGroup should return the handler")
	}
}

func TestLevelReloadsLive(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	log := NewLogger(&buf, Options{Level: lv}).With("x", 1).WithGroup("g")
	log.Debug("hidden")
	if buf.Len() != 0 {
		t.Fatalf("debug written at info: %s", buf.String())
	}
	lv.Set(slog.LevelDebug)
	log.Debug("shown")
	if !strings.Contains(buf.String(), `"msg":"shown"`) {
		t.Fatalf("debug not written after the change: %s", buf.String())
	}
	lv.Set(slog.LevelError)
	buf.Reset()
	log.Warn("hidden")
	if buf.Len() != 0 {
		t.Fatalf("warn written at error: %s", buf.String())
	}
}

func TestAddSourceAndUserReplaceAttr(t *testing.T) {
	var buf bytes.Buffer
	var seen []string
	log := NewLogger(&buf, Options{AddSource: true, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == "password" || a.Key == "s" {
			seen = append(seen, a.Value.String())
		}
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}})
	log.Info("m", "password", "hunter2", "s", Secret("x"))
	m := one(t, &buf)
	if _, ok := m["time"]; ok {
		t.Error("user ReplaceAttr did not run")
	}
	if _, ok := m["source"]; !ok {
		t.Error("AddSource ignored")
	}
	if fmt.Sprint(seen) != "[[REDACTED] [REDACTED]]" {
		t.Errorf("user ReplaceAttr saw %v; it must run after redaction", seen)
	}
}

// TestConcurrent logs from many goroutines through shared derived
// loggers while the level changes, for the race detector.
func TestConcurrent(t *testing.T) {
	var mu sync.Mutex
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	base := NewLogger(lockedWriter{&mu, &buf}, Options{Level: lv, Subcommand: "serve"})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log := base.With("worker", i)
			if i%2 == 0 {
				log = log.WithGroup("g")
			}
			ctx := WithCorrelationID(context.Background(), fmt.Sprintf("c%d", i))
			for j := range 200 {
				if j%50 == 0 {
					lv.Set(slog.Level((j / 50 % 2) * 4))
				}
				log.WarnContext(ctx, "m", "j", j, "token", "t")
			}
		}()
	}
	wg.Wait()
	for _, m := range lines(t, &buf) {
		if m[KeyCorrelationID] == nil || m[KeySubcommand] != "serve" {
			t.Fatalf("missing attributes: %v", m)
		}
	}
	if strings.Contains(buf.String(), `"t"`) {
		t.Fatal("token value written")
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
