package logging

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{
		"debug": slog.LevelDebug, "INFO": slog.LevelInfo, " Warn ": slog.LevelWarn, "error": slog.LevelError,
		"warn+2": slog.LevelWarn + 2, "DEBUG-4": slog.LevelDebug - 4,
	} {
		if got, err := ParseLevel(in); err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "verbose", "info+", "7"} {
		if _, err := ParseLevel(in); err == nil {
			t.Errorf("ParseLevel(%q) accepted", in)
		}
	}
}

func TestSetLevel(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	log := NewLogger(&buf, Options{Level: lv})

	old, err := SetLevel(lv, "error", log)
	if err != nil || old != slog.LevelInfo || lv.Level() != slog.LevelError {
		t.Fatalf("SetLevel: %v %v %v", old, err, lv.Level())
	}
	// Logged at ERROR, so it is written at the new level.
	m := one(t, &buf)
	if m["msg"] != "log level changed" || m["from"] != "INFO" || m["to"] != "ERROR" || m["level"] != "ERROR" {
		t.Fatalf("got %v", m)
	}

	buf.Reset()
	if _, err := SetLevel(lv, "error", log); err != nil || buf.Len() != 0 {
		t.Fatalf("no change should log nothing: %v %s", err, buf.String())
	}
	if _, err := SetLevel(lv, "debug", log); err != nil {
		t.Fatal(err)
	}
	if m := one(t, &buf); m["level"] != "ERROR" || m["to"] != "DEBUG" {
		t.Fatalf("lowering is logged at the old level: %v", m)
	}
	buf.Reset()
	if _, err := SetLevel(lv, "bogus", log); err == nil || lv.Level() != slog.LevelDebug || buf.Len() != 0 {
		t.Fatalf("bad level: %v %v %s", err, lv.Level(), buf.String())
	}
	if _, err := SetLevel(lv, "warn", nil); err != nil || lv.Level() != slog.LevelWarn {
		t.Fatal("nil logger")
	}
}

func TestReloadLevel(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	log := NewLogger(lockedWriter{new(sync.Mutex), &buf}, Options{Level: lv})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reload := make(chan struct{})
	reads := make(chan struct {
		s   string
		err error
	}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ReloadLevel(ctx, reload, lv, func() (string, error) {
			r := <-reads
			return r.s, r.err
		}, log)
	}()
	step := func(s string, err error) {
		reads <- struct {
			s   string
			err error
		}{s, err}
		reload <- struct{}{}
	}
	step("debug", nil)
	step("nonsense", nil)
	step("", errors.New("config unreadable"))
	step("warn", nil)
	// The fourth reload has been read once the channel takes another send.
	reads <- struct {
		s   string
		err error
	}{"warn", nil}
	reload <- struct{}{}
	if lv.Level() != slog.LevelWarn {
		t.Fatalf("level %v, want WARN", lv.Level())
	}
	close(reload)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ReloadLevel did not return when the channel closed")
	}
	out := buf.String()
	for _, want := range []string{`"to":"DEBUG"`, `"msg":"log level not reloaded","error":"log level \"nonsense\"`, `"error":"config unreadable"`, `"to":"WARN"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}

	// It returns when the context ends, and works without a logger.
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	r2 := make(chan struct{})
	go func() {
		defer close(done2)
		ReloadLevel(ctx2, r2, lv, func() (string, error) { return "", errors.New("x") }, nil)
	}()
	r2 <- struct{}{}
	cancel2()
	select {
	case <-done2:
	case <-time.After(5 * time.Second):
		t.Fatal("ReloadLevel did not return when the context ended")
	}
}

func TestLevelHandler(t *testing.T) {
	var buf bytes.Buffer
	lv := new(slog.LevelVar)
	h := LevelHandler(lv, NewLogger(&buf, Options{Level: lv}))
	do := func(method, body string) (int, string, http.Header) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/admin/log-level", strings.NewReader(body)))
		return rec.Code, strings.TrimSpace(rec.Body.String()), rec.Header()
	}
	if code, body, hdr := do("GET", ""); code != 200 || body != `{"level":"INFO"}` || hdr.Get("Content-Type") != "application/json" || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("GET: %d %s %v", code, body, hdr)
	}
	if code, body, _ := do("PUT", `{"level":"debug"}`); code != 200 || body != `{"level":"DEBUG"}` || lv.Level() != slog.LevelDebug {
		t.Fatalf("PUT: %d %s", code, body)
	}
	if !strings.Contains(buf.String(), `"msg":"log level changed"`) {
		t.Errorf("change not logged: %s", buf.String())
	}
	for _, bad := range []string{``, `{}`, `{"level":"loud"}`, `{"level":1}`, `{"level":"info","x":1}`, `{"level":"info"} {}`,
		`{"level":"` + strings.Repeat("a", maxLevelBody) + `"}`} {
		if code, body, _ := do("PUT", bad); code != 400 || !strings.Contains(body, `"error"`) {
			t.Errorf("PUT %.40q: %d %s", bad, code, body)
		}
	}
	if lv.Level() != slog.LevelDebug {
		t.Fatal("a refused PUT changed the level")
	}
	if code, _, hdr := do("POST", `{"level":"info"}`); code != 405 || hdr.Get("Allow") != "GET, HEAD, PUT" {
		t.Fatalf("POST: %d %v", code, hdr)
	}
	if code, _, _ := do("HEAD", ""); code != 200 {
		t.Fatalf("HEAD: %d", code)
	}
}
