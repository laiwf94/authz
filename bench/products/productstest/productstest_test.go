package productstest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/laiwf94/authz/bench/datasets"
)

const key = "productstest-key-0123456789"

func send(t *testing.T, h http.Handler, method, path, auth, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Body)
	return rec.Code, string(bytes.TrimSpace(b))
}

// The fake SpiceDB takes what the real gateway takes and refuses what it
// would refuse.
func TestSpiceDB(t *testing.T) {
	f := &SpiceDB{Engine: NewEngine(t, key)}
	sb, _ := json.Marshal(map[string]string{"schema": datasets.Schema})
	schema := string(sb)
	touch := func(rel string) string {
		return `{"updates":[{"operation":"OPERATION_TOUCH","relationship":{"resource":{"objectType":"doc","objectId":"d1"},"relation":"owner","subject":{"object":` + rel + `}}}]}`
	}
	for _, c := range []struct {
		path, auth, body string
		want             int
	}{
		{"/v1/relationships/write", "", touch(`{"objectType":"user","objectId":"u1"}`), 401},
		{"/v1/relationships/write", key, touch(`{"objectType":"user","objectId":"u1"}`), 200},
		{"/v1/relationships/write", key, touch(`{"objectType":"nope","objectId":"u1"}`), 400},
		{"/v1/relationships/write", key, `{"updates":[{"operation":"OPERATION_DELETE"}]}`, 400},
		{"/v1/relationships/write", key, `{"writes":[]}`, 400},
		{"/v1/relationships/write", key, `{"updates":[` + strings.Repeat(`{"operation":"OPERATION_TOUCH"},`, spiceDBMaxBatch) + `{"operation":"OPERATION_TOUCH"}]}`, 400},
		{"/v1/schema/write", key, schema, 200},
		{"/v1/schema/write", key, `{"schema":"definition"}`, 400},
		{"/v1/permissions/check", key, `{"consistency":{"fullyConsistent":true},"resource":{"objectType":"doc","objectId":"d1"},"permission":"edit","subject":{"object":{"objectType":"user","objectId":"u1"}}}`, 200},
		{"/v1/permissions/check", key, `{"consistency":{"minimizeLatency":true},"resource":{"objectType":"doc","objectId":"d1"},"permission":"nope","subject":{"object":{"objectType":"user","objectId":"u1"}}}`, 400},
		{"/v1/permissions/check", key, `{"consistency":{},"resource":{"objectType":"doc","objectId":"d1"},"permission":"edit","subject":{"object":{"objectType":"user","objectId":"u1"}}}`, 400},
		{"/v1/other", key, `{}`, 404},
	} {
		if code, b := send(t, f, http.MethodPost, c.path, c.auth, c.body); code != c.want {
			t.Errorf("%s %.60s: %d %s, want %d", c.path, c.body, code, b, c.want)
		}
	}
	if n, largest := f.Writes(); n != 1 || largest != 1 {
		t.Errorf("writes %d, largest %d", n, largest)
	}
}

// The fake OpenFGA keeps stores and models and checks what a write and a
// check name.
func TestOpenFGA(t *testing.T) {
	f := &OpenFGA{Engine: NewEngine(t, key)}
	code, b := send(t, f, http.MethodPost, "/stores", key, `{"name":"s"}`)
	var store struct{ ID string }
	if json.Unmarshal([]byte(b), &store); code != 201 || store.ID == "" {
		t.Fatalf("create store: %d %s", code, b)
	}
	base := "/stores/" + store.ID
	if code, b := send(t, f, http.MethodGet, base+"/authorization-models", key, ""); code != 200 || b != `{"authorization_models":null}` {
		t.Errorf("no models: %d %s", code, b)
	}
	code, b = send(t, f, http.MethodPost, base+"/authorization-models", key, `{"schema_version":"1.1","type_definitions":[]}`)
	var model struct {
		ID string `json:"authorization_model_id"`
	}
	if json.Unmarshal([]byte(b), &model); code != 201 || model.ID == "" {
		t.Fatalf("write model: %d %s", code, b)
	}
	write := func(m, dup, user string) string {
		return `{"authorization_model_id":"` + m + `","writes":{"on_duplicate":"` + dup + `","tuple_keys":[{"user":"` + user + `","relation":"owner","object":"doc:d1"}]}}`
	}
	check := func(m, consistency string) string {
		return `{"authorization_model_id":"` + m + `","consistency":"` + consistency + `","tuple_key":{"user":"user:u1","relation":"edit","object":"doc:d1"}}`
	}
	for _, c := range []struct {
		method, path, auth, body string
		want                     int
		answer                   string
	}{
		{"GET", "/stores?name=s", key, "", 200, `{"continuation_token":"","stores":[{"id":"` + store.ID + `","name":"s"}]}`},
		{"GET", "/stores?name=t", key, "", 200, `{"continuation_token":"","stores":null}`},
		{"GET", "/stores", "wrong", "", 401, ""},
		{"POST", base + "/write", key, write(model.ID, "ignore", "user:u1"), 200, `{}`},
		{"POST", base + "/write", key, write(model.ID, "error", "user:u1"), 400, ""},
		{"POST", base + "/write", key, write("old", "ignore", "user:u1"), 400, ""},
		{"POST", base + "/write", key, write(model.ID, "ignore", "robot:r1"), 400, ""},
		{"POST", "/stores/nope/write", key, write(model.ID, "ignore", "user:u1"), 404, ""},
		{"GET", "/stores/nope/authorization-models", key, "", 404, ""},
		{"POST", base + "/check", key, check(model.ID, "HIGHER_CONSISTENCY"), 200, `{"allowed":true,"resolution":""}`},
		{"POST", base + "/check", key, check(model.ID, "SOMETIMES"), 400, ""},
		{"POST", base + "/check", key, check("", "MINIMIZE_LATENCY"), 400, ""},
		{"POST", base + "/check", key, `{"tuple_key":{"user":"user:u1","relation":"nope","object":"doc:d1"},"authorization_model_id":"m","consistency":"MINIMIZE_LATENCY"}`, 400, ""},
		{"POST", base + "/check", key, `{"bogus":1}`, 400, ""},
		{"POST", base + "/other", key, `{}`, 404, ""},
	} {
		code, b := send(t, f, c.method, c.path, c.auth, c.body)
		if code != c.want || (c.answer != "" && b != c.answer) {
			t.Errorf("%s %s %.50s: %d %s, want %d %s", c.method, c.path, c.body, code, b, c.want, c.answer)
		}
	}
	if stores, models, writes, largest := f.Counts(); stores != 1 || models != 1 || writes != 1 || largest != 1 {
		t.Errorf("counts %d %d %d %d", stores, models, writes, largest)
	}
}
