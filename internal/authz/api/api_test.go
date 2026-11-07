package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

const apiKey = "test-key-0123456789"

const schemaSrc = `
definition user {}
definition group { relation member: user | group#member }
definition doc {
  relation owner: user
  relation viewer: user | group#member
  relation banned: user
  permission view = (viewer + owner) - banned
}`

type harness struct {
	t   *testing.T
	srv *httptest.Server
	st  *store.Store
	api *Server
}

func newHarness(t *testing.T, quantum time.Duration) *harness {
	t.Helper()
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{7}, token.KeySize))
	s, err := New(Config{Store: st, Tokens: tok, APIKeys: []string{apiKey, "second-key-0123456789"}, Metrics: metrics.New(),
		CacheSize: 1000, Quantum: quantum, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, srv: httptest.NewServer(s), st: st, api: s}
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) do(method, path string, body any, key string) (int, map[string]any, http.Header) {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		buf, _ := json.Marshal(b)
		rd = bytes.NewReader(buf)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(raw, &out); err != nil {
			h.t.Fatalf("bad JSON from %s: %s", path, raw)
		}
	} else {
		out["text"] = string(raw)
	}
	return resp.StatusCode, out, resp.Header
}

func (h *harness) call(method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	code, out, _ := h.do(method, path, body, apiKey)
	return code, out
}

func (h *harness) ok(method, path string, body any) map[string]any {
	h.t.Helper()
	code, out := h.call(method, path, body)
	if code != 200 {
		h.t.Fatalf("%s %s = %d %v", method, path, code, out)
	}
	return out
}

func errCode(out map[string]any) string {
	e, _ := out["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func (h *harness) setup() string {
	h.ok("PUT", "/v1/schema", map[string]any{"schema": schemaSrc})
	out := h.ok("POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{
		{"op": "touch", "relationship": "group:eng#member@user:alice"},
		{"op": "touch", "relationship": "doc:plan#viewer@group:eng#member"},
		{"op": "touch", "relationship": "doc:plan#owner@user:olga"},
		{"op": "touch", "relationship": "doc:memo#viewer@user:alice"},
	}})
	return out["written_at"].(string)
}

func TestEndToEnd(t *testing.T) {
	h := newHarness(t, time.Hour) // a long quantum proves tokens, not timing, give freshness
	written := h.setup()

	out := h.ok("POST", "/v1/check", map[string]any{"resource": "doc:plan", "permission": "view", "subject": "user:alice",
		"consistency": map[string]string{"mode": "at_least_as_fresh", "token": written}})
	if out["allowed"] != true || out["checked_at"] == "" {
		t.Fatalf("alice should view plan: %v", out)
	}
	ban := h.ok("POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{{"op": "create", "relationship": "doc:plan#banned@user:alice"}}})
	// The new-enemy problem: a check with the write's token must see the ban.
	out = h.ok("POST", "/v1/check", map[string]any{"resource": "doc:plan", "permission": "view", "subject": "user:alice",
		"consistency": map[string]string{"mode": "at_least_as_fresh", "token": ban["written_at"].(string)}})
	if out["allowed"] != false {
		t.Fatal("check with the write token did not see the ban")
	}
	// At the exact older snapshot, alice could still view.
	out = h.ok("POST", "/v1/check", map[string]any{"resource": "doc:plan", "permission": "view", "subject": "user:alice",
		"consistency": map[string]string{"mode": "at_exact_snapshot", "token": written}})
	if out["allowed"] != true {
		t.Fatal("exact snapshot read did not see the old state")
	}
	out = h.ok("POST", "/v1/check", map[string]any{"resource": "doc:plan", "permission": "view", "subject": "user:olga",
		"consistency": map[string]string{"mode": "fully_consistent"}})
	if out["allowed"] != true {
		t.Fatal("owner cannot view")
	}

	bulk := h.ok("POST", "/v1/check/bulk", map[string]any{"consistency": map[string]string{"mode": "fully_consistent"}, "items": []map[string]string{
		{"resource": "doc:memo", "permission": "view", "subject": "user:alice"},
		{"resource": "doc:plan", "permission": "view", "subject": "user:alice"},
		{"resource": "doc:plan", "permission": "nope", "subject": "user:alice"},
	}})
	res := bulk["results"].([]any)
	if res[0].(map[string]any)["allowed"] != true || res[1].(map[string]any)["allowed"] != false || res[2].(map[string]any)["error"] == nil {
		t.Fatalf("bulk results: %v", res)
	}

	look := h.ok("POST", "/v1/lookup/resources", map[string]any{"resource_type": "doc", "permission": "view", "subject": "user:alice",
		"consistency": map[string]string{"mode": "fully_consistent"}})
	if ids := look["resource_ids"].([]any); len(ids) != 1 || ids[0] != "memo" {
		t.Fatalf("lookup: %v", look)
	}
	look = h.ok("POST", "/v1/lookup/resources", map[string]any{"resource_type": "doc", "permission": "view", "subject": "user:nobody",
		"consistency": map[string]string{"mode": "fully_consistent"}})
	if ids := look["resource_ids"].([]any); len(ids) != 0 {
		t.Fatalf("empty lookup: %v", look)
	}

	read := h.ok("POST", "/v1/relationships/read", map[string]any{"filter": map[string]string{"resource_type": "doc", "resource_id": "plan"},
		"consistency": map[string]string{"mode": "fully_consistent"}, "limit": 2})
	if rels := read["relationships"].([]any); len(rels) != 2 || read["cursor"] == "" {
		t.Fatalf("read page 1: %v", read)
	}
	read2 := h.ok("POST", "/v1/relationships/read", map[string]any{"filter": map[string]string{"resource_type": "doc", "resource_id": "plan"},
		"consistency": map[string]string{"mode": "fully_consistent"}, "cursor": read["cursor"], "limit": 2})
	if rels := read2["relationships"].([]any); len(rels) != 1 || read2["cursor"] != "" {
		t.Fatalf("read page 2: %v", read2)
	}

	sc := h.ok("GET", "/v1/schema", nil)
	if !strings.Contains(sc["schema"].(string), "permission view = (viewer + owner) - banned") {
		t.Fatalf("schema: %v", sc)
	}
}

func TestAuth(t *testing.T) {
	h := newHarness(t, 0)
	for _, key := range []string{"", "wrong-key-0123456789", apiKey + "x"} {
		code, out, hdr := h.do("GET", "/v1/schema", nil, key)
		if code != 401 || errCode(out) != "unauthenticated" || hdr.Get("WWW-Authenticate") == "" {
			t.Fatalf("key %q: %d %v", key, code, out)
		}
	}
	if code, _, _ := h.do("GET", "/v1/schema", nil, "second-key-0123456789"); code == 401 {
		t.Fatal("second key rejected")
	}
	if code, _, _ := h.do("GET", "/healthz", nil, ""); code != 200 {
		t.Fatal("health check needs auth")
	}
	if code, _, _ := h.do("GET", "/metrics", nil, ""); code != 401 {
		t.Fatal("metrics are public")
	}
	req, _ := http.NewRequest("GET", h.srv.URL+"/v1/schema", nil)
	req.Header.Set("Authorization", "Basic "+apiKey)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("non-bearer scheme accepted")
	}
}

func TestConfigValidation(t *testing.T) {
	st, _ := store.Open(store.Options{})
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{1}, token.KeySize))
	for _, c := range []Config{{}, {Store: st, Tokens: tok}, {Store: st, Tokens: tok, APIKeys: []string{"short"}}} {
		if _, err := New(c); err == nil {
			t.Errorf("config %+v accepted", c)
		}
	}
	s, err := New(Config{Store: st, Tokens: tok, APIKeys: []string{apiKey}})
	if err != nil || s.quantum != DefaultQuantum || s.timeout != DefaultTimeout {
		t.Fatalf("defaults: %v", err)
	}
}

func TestErrors(t *testing.T) {
	h := newHarness(t, 0)
	if code, out := h.call("GET", "/v1/schema", nil); code != 424 || errCode(out) != "no_schema" {
		t.Fatalf("schema before write: %d %v", code, out)
	}
	if code, out := h.call("POST", "/v1/check", map[string]any{"resource": "doc:a", "permission": "view", "subject": "user:x"}); code != 424 {
		t.Fatalf("check before schema: %d %v", code, out)
	}
	written := h.setup()
	other, _ := token.NewIssuer(bytes.Repeat([]byte{9}, token.KeySize))
	cases := []struct {
		name, method, path string
		body               any
		code               int
		errc               string
	}{
		{"unknown route", "GET", "/v1/nope", nil, 404, "not_found"},
		{"wrong content type", "POST", "/v1/check", nil, 415, "invalid_argument"},
		{"bad json", "POST", "/v1/check", "{", 400, "invalid_argument"},
		{"unknown field", "POST", "/v1/check", map[string]any{"resource": "doc:a", "permission": "view", "subject": "user:x", "extra": 1}, 400, "invalid_argument"},
		{"two objects", "POST", "/v1/check", `{"resource":"doc:a","permission":"view","subject":"user:x"} {}`, 400, "invalid_argument"},
		{"resource without id", "POST", "/v1/check", map[string]any{"resource": "doc", "permission": "view", "subject": "user:x"}, 400, "invalid_argument"},
		{"wildcard subject", "POST", "/v1/check", map[string]any{"resource": "doc:a", "permission": "view", "subject": "user:*"}, 400, "invalid_argument"},
		{"unknown type", "POST", "/v1/check", map[string]any{"resource": "ghost:a", "permission": "view", "subject": "user:x"}, 400, "invalid_argument"},
		{"unknown permission", "POST", "/v1/check", map[string]any{"resource": "doc:a", "permission": "fly", "subject": "user:x"}, 400, "invalid_argument"},
		{"bad mode", "POST", "/v1/check", map[string]any{"resource": "doc:a", "permission": "view", "subject": "user:x", "consistency": map[string]string{"mode": "eventually"}}, 400, "invalid_argument"},
		{"token without mode", "POST", "/v1/check", map[string]any{"resource": "doc:a", "permission": "view", "subject": "user:x", "consistency": map[string]string{"token": written}}, 400, "invalid_argument"},
		{"token on full", "POST", "/v1/check", map[string]any{"resource": "doc:a", "permission": "view", "subject": "user:x", "consistency": map[string]string{"mode": "fully_consistent", "token": written}}, 400, "invalid_argument"},
		{"mode without token", "POST", "/v1/check", map[string]any{"resource": "doc:a", "permission": "view", "subject": "user:x", "consistency": map[string]string{"mode": "at_least_as_fresh"}}, 400, "invalid_argument"},
		{"forged token", "POST", "/v1/check", map[string]any{"resource": "doc:a", "permission": "view", "subject": "user:x", "consistency": map[string]string{"mode": "at_least_as_fresh", "token": other.Encode(1)}}, 400, "invalid_argument"},
		{"future token", "POST", "/v1/check", map[string]any{"resource": "doc:a", "permission": "view", "subject": "user:x", "consistency": map[string]string{"mode": "at_least_as_fresh", "token": h.api.tokens.Encode(999)}}, 400, "invalid_argument"},
		{"empty schema", "PUT", "/v1/schema", map[string]any{"schema": "  "}, 400, "invalid_argument"},
		{"bad schema", "PUT", "/v1/schema", map[string]any{"schema": "definition {"}, 400, "invalid_argument"},
		{"schema orphans data", "PUT", "/v1/schema", map[string]any{"schema": "definition user {}"}, 412, "failed_precondition"},
		{"bad relationship", "POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{{"op": "touch", "relationship": "nonsense"}}}, 400, "invalid_argument"},
		{"no updates", "POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{}}, 400, "invalid_argument"},
		{"create conflict", "POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{{"op": "create", "relationship": "doc:plan#owner@user:olga"}}}, 409, "already_exists"},
		{"precondition", "POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{{"op": "touch", "relationship": "doc:x#owner@user:y"}},
			"preconditions": []map[string]any{{"must_exist": true, "filter": map[string]string{"resource_type": "doc", "resource_id": "nothing"}}}}, 412, "failed_precondition"},
		{"read limit", "POST", "/v1/relationships/read", map[string]any{"filter": map[string]string{"resource_type": "doc"}, "limit": 5000}, 400, "invalid_argument"},
		{"read cursor", "POST", "/v1/relationships/read", map[string]any{"filter": map[string]string{"resource_type": "doc"}, "cursor": strings.Repeat("a", 2000)}, 400, "invalid_argument"},
		{"read filter", "POST", "/v1/relationships/read", map[string]any{"filter": map[string]string{}}, 400, "invalid_argument"},
		{"bulk empty", "POST", "/v1/check/bulk", map[string]any{"items": []any{}}, 400, "invalid_argument"},
		{"bulk too big", "POST", "/v1/check/bulk", map[string]any{"items": make([]checkItem, MaxBulkChecks+1)}, 400, "invalid_argument"},
		{"lookup limit", "POST", "/v1/lookup/resources", map[string]any{"resource_type": "doc", "permission": "view", "subject": "user:x", "limit": -1}, 400, "invalid_argument"},
		{"lookup cursor", "POST", "/v1/lookup/resources", map[string]any{"resource_type": "doc", "permission": "view", "subject": "user:x", "cursor": "a b"}, 400, "invalid_argument"},
		{"lookup subject", "POST", "/v1/lookup/resources", map[string]any{"resource_type": "doc", "permission": "view", "subject": "x"}, 400, "invalid_argument"},
		{"lookup type", "POST", "/v1/lookup/resources", map[string]any{"resource_type": "ghost", "permission": "view", "subject": "user:x"}, 400, "invalid_argument"},
		{"watch wait", "POST", "/v1/watch", map[string]any{"after": written, "wait_seconds": 99}, 400, "invalid_argument"},
		{"watch token", "POST", "/v1/watch", map[string]any{"after": "garbage"}, 400, "invalid_argument"},
		{"watch future", "POST", "/v1/watch", map[string]any{"after": h.api.tokens.Encode(999)}, 400, "invalid_argument"},
		{"body too large", "POST", "/v1/check", `{"resource":"` + strings.Repeat("a", MaxBodyBytes) + `"}`, 413, "invalid_argument"},
	}
	for _, c := range cases {
		code, out := h.call(c.method, c.path, c.body)
		if code != c.code || errCode(out) != c.errc {
			t.Errorf("%s: %d %v, want %d %s", c.name, code, out, c.code, c.errc)
		}
		if c.code >= 400 {
			e, _ := out["error"].(map[string]any)
			if e["request_id"] == "" {
				t.Errorf("%s: error has no request id", c.name)
			}
		}
	}
}

func TestRequestIDs(t *testing.T) {
	h := newHarness(t, 0)
	req, _ := http.NewRequest("GET", h.srv.URL+"/healthz", nil)
	req.Header.Set("X-Request-Id", "trace-123")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.Header.Get("X-Request-Id") != "trace-123" {
		t.Fatal("valid request id not propagated")
	}
	req.Header.Set("X-Request-Id", "bad id\twith spaces")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if id := resp.Header.Get("X-Request-Id"); id == "" || strings.Contains(id, " ") {
		t.Fatalf("unsafe request id echoed: %q", id)
	}
}

func TestWatch(t *testing.T) {
	h := newHarness(t, 0)
	h.setup()
	start := h.ok("POST", "/v1/watch", map[string]any{})
	next := start["next"].(string)
	if len(start["changes"].([]any)) != 0 {
		t.Fatal("first watch call should start at the head")
	}
	got := make(chan map[string]any, 1)
	go func() {
		_, out := h.call("POST", "/v1/watch", map[string]any{"after": next, "wait_seconds": 5})
		got <- out
	}()
	time.Sleep(50 * time.Millisecond)
	h.ok("POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{{"op": "touch", "relationship": "doc:new#owner@user:z"}}})
	select {
	case out := <-got:
		ch := out["changes"].([]any)
		if len(ch) != 1 || ch[0].(map[string]any)["relationship"] != "doc:new#owner@user:z" || ch[0].(map[string]any)["op"] != "touch" {
			t.Fatalf("watch: %v", out)
		}
		if out["next"] == next {
			t.Fatal("next token did not advance")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watch did not return after a write")
	}
	// A watch with nothing new returns at the deadline with the same position.
	head := h.ok("POST", "/v1/watch", map[string]any{})["next"].(string)
	out := h.ok("POST", "/v1/watch", map[string]any{"after": head, "wait_seconds": 0})
	if len(out["changes"].([]any)) != 0 || out["next"] != head {
		t.Fatalf("idle watch: %v", out)
	}
	// A schema write moves the head without relationship changes.
	h.ok("PUT", "/v1/schema", map[string]any{"schema": schemaSrc})
	out = h.ok("POST", "/v1/watch", map[string]any{"after": head})
	if out["next"] == head {
		t.Fatal("watch did not advance past a schema write")
	}
}

func TestMinimizeLatencyUsesSharedSnapshot(t *testing.T) {
	h := newHarness(t, time.Hour)
	h.setup()
	ask := func() any {
		return h.ok("POST", "/v1/check", map[string]any{"resource": "doc:plan", "permission": "view", "subject": "user:zoe"})["allowed"]
	}
	if ask() != false {
		t.Fatal("zoe should not view yet")
	}
	h.ok("POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{{"op": "touch", "relationship": "doc:plan#viewer@user:zoe"}}})
	if ask() != false {
		t.Fatal("minimize_latency should keep using the shared snapshot within the quantum")
	}
	h.api.snapMu.Lock()
	h.api.snapTime = time.Time{} // quantum elapsed
	h.api.snapMu.Unlock()
	if ask() != true {
		t.Fatal("snapshot did not refresh after the quantum")
	}
}

func TestMetricsAndHealth(t *testing.T) {
	h := newHarness(t, 0)
	h.setup()
	h.ok("POST", "/v1/check", map[string]any{"resource": "doc:plan", "permission": "view", "subject": "user:alice"})
	code, out := h.call("GET", "/metrics", nil)
	text, _ := out["text"].(string)
	for _, want := range []string{`grantd_http_requests_total{route="/v1/check",code="200"} 1`, "grantd_check_duration_seconds_count 1", "grantd_head_revision 2"} {
		if code != 200 || !strings.Contains(text, want) {
			t.Errorf("metrics missing %q:\n%s", want, text)
		}
	}
	health := h.ok("GET", "/healthz", nil)
	if health["status"] != "ok" || health["revision"] != "2" {
		t.Fatalf("health: %v", health)
	}
}

func TestPanicsBecome500(t *testing.T) {
	h := newHarness(t, 0)
	h.api.route("GET /boom", func(http.ResponseWriter, *http.Request) error { panic("kaboom") }, false)
	code, out, _ := h.do("GET", "/boom", nil, "")
	if code != 500 || errCode(out) != "internal" || strings.Contains(fmt.Sprint(out), "kaboom") {
		t.Fatalf("panic: %d %v", code, out)
	}
}

func TestFailMapping(t *testing.T) {
	h := newHarness(t, 0)
	cases := map[error]int{
		context.DeadlineExceeded:        504,
		context.Canceled:                499,
		store.ErrUnavailable:            503,
		store.ErrSnapshotExpired:        410,
		store.ErrTooManyCandidate:       422,
		fmt.Errorf("surprise"):          500,
		&apiError{418, "teapot", "tea"}: 418,
	}
	for err, want := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		h.api.fail(rec, req, err)
		if rec.Code != want {
			t.Errorf("%v -> %d, want %d", err, rec.Code, want)
		}
		if want == 500 && strings.Contains(rec.Body.String(), "surprise") {
			t.Error("internal error details leaked to the client")
		}
	}
}

func TestConcurrentWritesAndChecks(t *testing.T) {
	h := newHarness(t, time.Millisecond)
	h.setup()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(2)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				out := h.ok("POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{
					{"op": "touch", "relationship": fmt.Sprintf("doc:w%d_%d#viewer@user:u%d", w, i, w)}}})
				// Read-your-writes with the returned token, under concurrency.
				chk := h.ok("POST", "/v1/check", map[string]any{"resource": fmt.Sprintf("doc:w%d_%d", w, i), "permission": "view",
					"subject": fmt.Sprintf("user:u%d", w), "consistency": map[string]string{"mode": "at_least_as_fresh", "token": out["written_at"].(string)}})
				if chk["allowed"] != true {
					t.Errorf("writer %d lost its own write %d", w, i)
					return
				}
			}
		}(w)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				h.ok("POST", "/v1/check", map[string]any{"resource": "doc:plan", "permission": "view", "subject": "user:alice"})
			}
		}()
	}
	wg.Wait()
}

func TestLimitErrorMentionsZeroDefault(t *testing.T) {
	h := newHarness(t, 0)
	h.setup()
	for _, c := range []struct {
		path string
		body map[string]any
	}{
		{"/v1/relationships/read", map[string]any{"filter": map[string]string{"resource_type": "doc"}}},
		{"/v1/lookup/resources", map[string]any{"resource_type": "doc", "permission": "view", "subject": "user:x"}},
	} {
		c.body["limit"] = 0
		h.ok("POST", c.path, c.body)
		c.body["limit"] = -1
		code, out := h.call("POST", c.path, c.body)
		msg, _ := out["error"].(map[string]any)["message"].(string)
		if code != 400 || !strings.Contains(msg, "between 0 and") || !strings.Contains(msg, "default") {
			t.Errorf("%s: got %d %q", c.path, code, msg)
		}
	}
}
