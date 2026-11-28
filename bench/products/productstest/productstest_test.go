package productstest

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	if method == http.MethodPost || method == http.MethodPut {
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
		{"/v1/permissions/check", key, `{"bogus":1}`, 400},
		{"/v1/permissions/checkbulk", key, `{"consistency":{"maybe":true},"items":[]}`, 400},
		{"/v1/permissions/checkbulk", key, `{"bogus":1}`, 400},
		{"/v1/permissions/resources", key, `{"consistency":{},"resourceObjectType":"doc","permission":"edit","subject":{"object":{"objectType":"user","objectId":"u1"}}}`, 400},
		{"/v1/permissions/resources", key, `{"consistency":{"minimizeLatency":true},"resourceObjectType":"doc","permission":"edit","subject":{"object":{"objectType":"user","objectId":"u1"}},"optionalLimit":1001}`, 400},
		{"/v1/permissions/resources", key, `{"consistency":{"minimizeLatency":true},"resourceObjectType":"doc","permission":"nope","subject":{"object":{"objectType":"user","objectId":"u1"}}}`, 400},
		{"/v1/permissions/resources", key, `{"bogus":1}`, 400},
		{"/v1/other", key, `{}`, 404},
	} {
		if code, b := send(t, f, http.MethodPost, c.path, c.auth, c.body); code != c.want {
			t.Errorf("%s %.60s: %d %s, want %d", c.path, c.body, code, b, c.want)
		}
	}
	// A bulk check answers each item, in order, with an item or an error.
	item := func(perm string) string {
		return `{"resource":{"objectType":"doc","objectId":"d1"},"permission":"` + perm + `","subject":{"object":{"objectType":"user","objectId":"u1"}}}`
	}
	code, b := send(t, f, http.MethodPost, "/v1/permissions/checkbulk", key, `{"consistency":{"fullyConsistent":true},"items":[`+item("edit")+`,`+item("nope")+`,`+item("view")+`]}`)
	var bulk struct {
		Pairs []struct {
			Item  *struct{ Permissionship string } `json:"item"`
			Error *struct{ Code int }              `json:"error"`
		} `json:"pairs"`
	}
	if json.Unmarshal([]byte(b), &bulk); code != 200 || len(bulk.Pairs) != 3 ||
		bulk.Pairs[0].Item == nil || bulk.Pairs[0].Item.Permissionship != "PERMISSIONSHIP_HAS_PERMISSION" ||
		bulk.Pairs[1].Error == nil || bulk.Pairs[2].Item == nil {
		t.Errorf("checkbulk: %d %s", code, b)
	}
	// LookupResources streams one result a line, and nothing for none.
	lookup := func(user string, limit int) (int, string) {
		return send(t, f, http.MethodPost, "/v1/permissions/resources", key, fmt.Sprintf(`{"consistency":{"fullyConsistent":true},`+
			`"resourceObjectType":"doc","permission":"edit","subject":{"object":{"objectType":"user","objectId":%q}},"optionalLimit":%d}`, user, limit))
	}
	if code, b := lookup("u1", 0); code != 200 || b != `{"result":{"lookedUpAt":{"token":"GhUK"},"permissionship":"LOOKUP_PERMISSIONSHIP_HAS_PERMISSION","resourceObjectId":"d1"}}` {
		t.Errorf("lookup: %d %s", code, b)
	}
	if code, b := lookup("u2", 10); code != 200 || b != "" {
		t.Errorf("lookup of none: %d %q", code, b)
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
	batch := func(m, consistency string, ids ...string) string {
		var checks []string
		for i, id := range ids {
			rel := "edit"
			if i == 1 {
				rel = "nope"
			}
			checks = append(checks, `{"tuple_key":{"user":"user:u1","relation":"`+rel+`","object":"doc:d1"},"correlation_id":"`+id+`"}`)
		}
		return `{"authorization_model_id":"` + m + `","consistency":"` + consistency + `","checks":[` + strings.Join(checks, ",") + `]}`
	}
	ids := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprint(i)
		}
		return out
	}
	list := func(m, rel, user string) string {
		return `{"authorization_model_id":"` + m + `","consistency":"MINIMIZE_LATENCY","type":"doc","relation":"` + rel + `","user":"` + user + `"}`
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
		{"POST", base + "/batch-check", key, batch(model.ID, "MINIMIZE_LATENCY", "0", "0"), 400, ""},
		{"POST", base + "/batch-check", key, batch(model.ID, "MINIMIZE_LATENCY", ids(openFGAMaxChecks+1)...), 400, ""},
		{"POST", base + "/batch-check", key, batch("", "MINIMIZE_LATENCY", "0"), 400, ""},
		{"POST", "/stores/nope/batch-check", key, batch(model.ID, "MINIMIZE_LATENCY", "0"), 404, ""},
		{"POST", base + "/list-objects", key, list(model.ID, "edit", "user:u1"), 200, `{"objects":["doc:d1"]}`},
		{"POST", base + "/list-objects", key, list(model.ID, "edit", "user:u2"), 200, `{"objects":[]}`},
		{"POST", base + "/list-objects", key, list(model.ID, "nope", "user:u1"), 400, ""},
		{"POST", base + "/list-objects", key, list("", "edit", "user:u1"), 400, ""},
		{"POST", "/stores/nope/list-objects", key, list(model.ID, "edit", "user:u1"), 404, ""},
		{"POST", "/stores/nope/check", key, check(model.ID, "MINIMIZE_LATENCY"), 404, ""},
		{"POST", base + "/other", key, `{}`, 404, ""},
	} {
		code, b := send(t, f, c.method, c.path, c.auth, c.body)
		if code != c.want || (c.answer != "" && b != c.answer) {
			t.Errorf("%s %s %.50s: %d %s, want %d %s", c.method, c.path, c.body, code, b, c.want, c.answer)
		}
	}
	// A batch check answers every correlation ID, a refused one with an
	// error.
	code, b = send(t, f, http.MethodPost, base+"/batch-check", key, batch(model.ID, "HIGHER_CONSISTENCY", "a", "b"))
	var res struct {
		Result map[string]struct {
			Allowed *bool
			Error   *struct{ Message string }
		}
	}
	if json.Unmarshal([]byte(b), &res); code != 200 || len(res.Result) != 2 || res.Result["a"].Allowed == nil || !*res.Result["a"].Allowed ||
		res.Result["b"].Error == nil || res.Result["b"].Error.Message == "" {
		t.Errorf("batch check: %d %s", code, b)
	}
	if stores, models, writes, largest := f.Counts(); stores != 1 || models != 1 || writes != 1 || largest != 1 {
		t.Errorf("counts %d %d %d %d", stores, models, writes, largest)
	}
}

// The fake Keycloak takes what Keycloak 26's admin API takes and refuses
// what it refuses.
func TestKeycloak(t *testing.T) {
	f := &Keycloak{AdminUser: "admin", AdminPassword: "pass", TokenLife: 300}
	signIn := func(form string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/realms/master/protocol/openid-connect/token", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, _ := signIn("grant_type=password&client_id=admin-cli&username=admin&password=wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", code)
	}
	code, body := signIn("grant_type=password&client_id=admin-cli&username=admin&password=pass")
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.Unmarshal([]byte(body), &tok); code != http.StatusOK || tok.ExpiresIn != 300 || tok.AccessToken == "" {
		t.Fatalf("sign-in: %d %s", code, body)
	}
	at := tok.AccessToken
	realm := `{"realm":"r","enabled":true,"bruteForceProtected":true,"clients":[{"clientId":"c","secret":"s","redirectUris":["http://x/cb"]}]}`
	user := func(name, group string) string {
		return `{"username":"` + name + `","email":"` + name + `@x","enabled":true,"groups":["/` + group + `"],"credentials":[{"type":"password","value":"pw","temporary":false}]}`
	}
	for _, c := range []struct {
		name, method, path, auth, body string
		want                           int
	}{
		{"no token", http.MethodGet, "/admin/realms/r", "", "", http.StatusUnauthorized},
		{"other path", http.MethodGet, "/realms/r/account", at, "", http.StatusNotFound},
		{"missing realm", http.MethodGet, "/admin/realms/r", at, "", http.StatusNotFound},
		{"list realms", http.MethodGet, "/admin/realms", at, "", http.StatusNotFound},
		{"unknown field", http.MethodPost, "/admin/realms", at, `{"realm":"r","sslRequired":"none"}`, http.StatusBadRequest},
		{"create realm", http.MethodPost, "/admin/realms", at, realm, http.StatusCreated},
		{"realm again", http.MethodPost, "/admin/realms", at, realm, http.StatusConflict},
		{"get realm", http.MethodGet, "/admin/realms/r", at, "", http.StatusOK},
		{"update realm", http.MethodPut, "/admin/realms/r", at, `{"realm":"r","enabled":true}`, http.StatusNoContent},
		{"bad realm update", http.MethodPut, "/admin/realms/r", at, `{"realm":1}`, http.StatusBadRequest},
		{"client again", http.MethodPost, "/admin/realms/r/clients", at, `{"clientId":"c"}`, http.StatusConflict},
		{"bad client", http.MethodPost, "/admin/realms/r/clients", at, `{"clientId":"d","bogus":1}`, http.StatusBadRequest},
		{"put missing client", http.MethodPut, "/admin/realms/r/clients/nope", at, `{"clientId":"c"}`, http.StatusNotFound},
		{"bad client put", http.MethodPut, "/admin/realms/r/clients/nope", at, `{"clientId":2}`, http.StatusBadRequest},
		{"group without path", http.MethodPost, "/admin/realms/r/partialImport", at,
			`{"ifResourceExists":"SKIP","groups":[{"name":"g1"}]}`, http.StatusInternalServerError},
		{"overwrite", http.MethodPost, "/admin/realms/r/partialImport", at,
			`{"ifResourceExists":"OVERWRITE","groups":[{"name":"g1","path":"/g1"}]}`, http.StatusBadRequest},
		{"unknown group", http.MethodPost, "/admin/realms/r/partialImport", at,
			`{"ifResourceExists":"SKIP","users":[` + user("u1", "g9") + `]}`, http.StatusBadRequest},
		{"no password", http.MethodPost, "/admin/realms/r/partialImport", at,
			`{"ifResourceExists":"SKIP","users":[{"username":"u1"}]}`, http.StatusBadRequest},
		{"bad import", http.MethodPost, "/admin/realms/r/partialImport", at, `{"users":{}}`, http.StatusBadRequest},
		{"group and user", http.MethodPost, "/admin/realms/r/partialImport", at,
			`{"ifResourceExists":"SKIP","groups":[{"name":"g1","path":"/g1"}],"users":[` + user("u1", "g1") + `]}`, http.StatusOK},
		{"user of an existing group", http.MethodPost, "/admin/realms/r/partialImport", at,
			`{"ifResourceExists":"SKIP","users":[` + user("u2", "g1") + `]}`, http.StatusOK},
		{"groups of a missing user", http.MethodGet, "/admin/realms/r/users/nope/groups", at, "", http.StatusNotFound},
		{"other admin path", http.MethodDelete, "/admin/realms/r/users", at, "", http.StatusNotFound},
	} {
		if code, body := send(t, f, c.method, c.path, c.auth, c.body); code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, code, body, c.want)
		}
	}
	// PUT needs a JSON body.
	req := httptest.NewRequest(http.MethodPut, "/admin/realms/r", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+at)
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("PUT without a content type: %d", rec.Code)
	}

	code, body = send(t, f, http.MethodPost, "/admin/realms/r/partialImport", at,
		`{"ifResourceExists":"SKIP","groups":[{"name":"g1","path":"/g1"}],"users":[`+user("u1", "g1")+`]}`)
	if code != http.StatusOK || !strings.Contains(body, `"added":0`) || !strings.Contains(body, `"skipped":2`) {
		t.Errorf("import again: %d %s", code, body)
	}
	code, body = send(t, f, http.MethodGet, "/admin/realms/r/users?username=u1&exact=true", at, "")
	var users []struct{ ID string }
	if json.Unmarshal([]byte(body), &users); code != http.StatusOK || len(users) != 1 {
		t.Fatalf("users: %d %s", code, body)
	}
	if code, body := send(t, f, http.MethodGet, "/admin/realms/r/users/"+users[0].ID+"/groups", at, ""); code != http.StatusOK ||
		!strings.Contains(body, `"name":"g1"`) || !strings.Contains(body, `"path":"/g1"`) {
		t.Errorf("groups: %d %s", code, body)
	}
	if code, body := send(t, f, http.MethodGet, "/admin/realms/r/users?username=u1", at, ""); code != http.StatusOK || body != "[]" {
		t.Errorf("a search that is not exact: %d %s", code, body)
	}
	r := f.Realm("r")
	if len(r.Users) != 2 || r.Imports != 3 || r.Users["u1"].Password != "pw" || f.Realm("none") != nil {
		t.Errorf("realm state: %+v", r)
	}
	// PUT keeps the mappers; POST of a new client adds it.
	if code, body := send(t, f, http.MethodPost, "/admin/realms/r/clients", at, `{"clientId":"d"}`); code != http.StatusCreated {
		t.Errorf("new client: %d %s", code, body)
	}
	id := f.Realm("r").Clients["c"]["id"].(string)
	if code, body := send(t, f, http.MethodPut, "/admin/realms/r/clients/"+id, at, `{"clientId":"c","secret":"t"}`); code != http.StatusNoContent {
		t.Errorf("put client: %d %s", code, body)
	}
	if got := f.Realm("r").Clients["c"]["secret"]; got != "t" {
		t.Errorf("secret after PUT: %v", got)
	}
	f.Expire()
	if code, _ := send(t, f, http.MethodGet, "/admin/realms/r", at, ""); code != http.StatusUnauthorized {
		t.Errorf("expired token: %d", code)
	}
	if f.SignIns() != 1 {
		t.Errorf("%d sign-ins", f.SignIns())
	}
}
