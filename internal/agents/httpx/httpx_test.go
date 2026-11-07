package httpx

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/platform/metrics"
)

func newServer(logs io.Writer) *Server {
	return &Server{Name: "test", Prefix: "tg", Log: slog.New(slog.NewJSONHandler(logs, nil)), Metrics: metrics.New()}
}

func TestWrap(t *testing.T) {
	var logs bytes.Buffer
	s := newServer(&logs)
	h := s.Wrap("/x", func(w http.ResponseWriter, r *http.Request) {
		if RequestID(r.Context()) == "" {
			t.Error("no request id in context")
		}
		WriteJSON(w, http.StatusCreated, map[string]string{"a": "<b>"})
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set(HeaderRequestID, "client-id-1")
	h.ServeHTTP(rec, req)
	if rec.Code != 201 || len(rec.Header().Get(HeaderRequestID)) != 24 || rec.Body.String() != "{\"a\":\"<b>\"}\n" {
		t.Fatalf("got %d %q %q", rec.Code, rec.Header().Get(HeaderRequestID), rec.Body.String())
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("security headers missing")
	}
	// Unsafe client IDs are replaced.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/x", nil)
	req.Header.Set(HeaderRequestID, "bad id\nwith newline")
	h.ServeHTTP(rec, req)
	if id := rec.Header().Get(HeaderRequestID); len(id) != 24 {
		t.Fatalf("unsafe id kept: %q", id)
	}
	// Panics become a 500 with the envelope; status defaults to 200.
	p := s.Wrap("/p", func(http.ResponseWriter, *http.Request) { panic("boom") })
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/p", nil))
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), `"code":"internal"`) {
		t.Fatalf("panic: %d %s", rec.Code, rec.Body.String())
	}
	e := s.Wrap("/e", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) })
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest("GET", "/e", nil))
	f := s.Wrap("/f", func(w http.ResponseWriter, r *http.Request) {})
	f.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/f", nil))
	var m bytes.Buffer
	_ = s.Metrics.Write(&m)
	for _, want := range []string{`tg_http_requests_total{server="test",route="/x",code="201"} 2`, `route="/p",code="500"} 1`, `route="/e",code="200"} 1`, `route="/f",code="200"} 1`} {
		if !strings.Contains(m.String(), want) {
			t.Errorf("metrics missing %s", want)
		}
	}
	if !strings.Contains(logs.String(), `"client_request_id":"client-id-1"`) {
		t.Fatal("client request id not logged")
	}
	if !strings.Contains(logs.String(), `"msg":"panic"`) {
		t.Fatal("panic not logged")
	}
	rec = httptest.NewRecorder()
	WriteJSON(rec, 200, func() {})
	if rec.Code != 500 {
		t.Fatal("unencodable value")
	}
}

func TestDecodeAndFail(t *testing.T) {
	type body struct {
		A int `json:"a"`
	}
	run := func(ct, payload string, limit int64) (body, error) {
		var b body
		req := httptest.NewRequest("POST", "/", strings.NewReader(payload))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		err := DecodeJSON(httptest.NewRecorder(), req, limit, &b)
		return b, err
	}
	if b, err := run("application/json; charset=utf-8", `{"a":3}`, 100); err != nil || b.A != 3 {
		t.Fatalf("%v %v", b, err)
	}
	if _, err := run("application/json", ``, 100); err != nil {
		t.Fatalf("empty body: %v", err)
	}
	for name, c := range map[string][3]string{
		"type":     {"text/plain", `{"a":1}`, "Content-Type"},
		"unknown":  {"application/json", `{"b":1}`, "unknown field"},
		"trailing": {"application/json", `{"a":1}{}`, "single JSON object"},
		"syntax":   {"application/json", `{`, "invalid JSON"},
	} {
		if _, err := run(c[0], c[1], 100); err == nil || !strings.Contains(err.Error(), c[2]) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err := run("application/json", `{"a":1234567}`, 5)
	var mbe *http.MaxBytesError
	if !errors.As(err, &mbe) {
		t.Fatalf("limit: %v", err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	for _, c := range []struct {
		err    error
		status int
	}{{BadRequest("x %d", 1), 400}, {err, 413}, {errors.New("secret detail"), 500}} {
		rec := httptest.NewRecorder()
		Fail(rec, httptest.NewRequest("GET", "/", nil), log, c.err)
		if rec.Code != c.status || strings.Contains(rec.Body.String(), "secret detail") {
			t.Errorf("%v: %d %s", c.err, rec.Code, rec.Body.String())
		}
	}
	if (&Error{Msg: "m"}).Error() != "m" {
		t.Fatal("Error()")
	}
}

func TestBearerAndTokens(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if Bearer(req) != "" {
		t.Fatal("no header")
	}
	req.Header.Set("Authorization", "bearer  abc ")
	if Bearer(req) != "abc" {
		t.Fatalf("got %q", Bearer(req))
	}
	req.Header.Set("Authorization", "Basic abc")
	if Bearer(req) != "" {
		t.Fatal("basic accepted")
	}
	if !TokenMatches("s3cret", "s3cret") || TokenMatches("s3cret", "s3cre") || TokenMatches("", "") || TokenMatches("a", "") {
		t.Fatal("TokenMatches")
	}
	if !IsJSON("Application/JSON ; charset=utf-8") || IsJSON("application/jsonx") {
		t.Fatal("IsJSON")
	}
}
