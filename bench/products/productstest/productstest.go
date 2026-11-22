// Package productstest has fakes of the products in bench/products for
// tests: SpiceDB's HTTP gateway and OpenFGA's HTTP API, each answering
// from a real authz engine in process, so that what they accept is what
// the real products would store and what they answer is what the dataset
// means.
package productstest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/bench/datasets"
	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

const (
	spiceDBMaxBatch = 1000 // SpiceDB's default --write-relationships-max-updates-per-call
	openFGAMaxBatch = 100  // OpenFGA's default --max-tuples-per-write
)

// Engine is a real authz API in process, holding the dataset's schema.
// The fake SpiceDB and OpenFGA servers translate their products' requests
// into its requests, so a request the fakes accept carries exactly the
// relationships and checks the dataset means.
type Engine struct {
	// Handler is the authz API; Key is its API key.
	Handler http.Handler
	Key     string
}

// NewAPI is an empty authz API in process, with no schema, whose API key
// is key.
func NewAPI(t testing.TB, key string) http.Handler {
	t.Helper()
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{7}, token.KeySize))
	s, err := api.New(api.Config{Store: st, Tokens: tok, APIKeys: []string{key}, Metrics: metrics.New(),
		CacheSize: 1000, Quantum: time.Second, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// NewEngine starts an engine with the dataset's schema whose API key is key.
func NewEngine(t testing.TB, key string) *Engine {
	t.Helper()
	e := &Engine{NewAPI(t, key), key}
	if code, b := e.Do(http.MethodPut, "/v1/schema", map[string]string{"schema": datasets.Schema}); code != http.StatusOK {
		t.Fatalf("schema: %d %s", code, b)
	}
	return e
}

// Do sends one request to the engine and returns the status and body.
func (e *Engine) Do(method, path string, body any) (int, []byte) {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+e.Key)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.Handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// Check asks a fully consistent check.
func (e *Engine) Check(resource, permission, subject string) (bool, int, []byte) {
	code, b := e.Do(http.MethodPost, "/v1/check", map[string]any{"resource": resource, "permission": permission,
		"subject": subject, "consistency": map[string]string{"mode": "fully_consistent"}})
	var out struct{ Allowed bool }
	json.Unmarshal(b, &out)
	return out.Allowed, code, b
}

// Touch writes rels (type:id#relation@subject) as touches.
func (e *Engine) Touch(rels []string) (int, []byte) {
	ups := make([]map[string]string, len(rels))
	for i, r := range rels {
		ups[i] = map[string]string{"op": "touch", "relationship": r}
	}
	return e.Do(http.MethodPost, "/v1/relationships/write", map[string]any{"updates": ups})
}

func authorized(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Header.Get("Authorization") != "Bearer "+want || r.Header.Get("Content-Type") != "application/json" && r.Method == http.MethodPost {
		http.Error(w, `{"message":"unauthenticated"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// SpiceDB answers SpiceDB's HTTP gateway API (schema write, relationship
// writes, checks) from an engine. It refuses fields SpiceDB does not have,
// more updates than SpiceDB's default limit, and any operation but a
// touch. Its key is the engine's.
type SpiceDB struct {
	Engine *Engine
	// Answer, when set, is the permissionship every check answers.
	Answer string

	mu       sync.Mutex
	writes   int
	maxBatch int
}

// Writes is how many writes the fake took and the most updates one had.
func (f *SpiceDB) Writes() (n, largest int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes, f.maxBatch
}

type spiceObject struct {
	Type string `json:"objectType"`
	ID   string `json:"objectId"`
}

type spiceRef struct {
	Object   spiceObject `json:"object"`
	Relation string      `json:"optionalRelation,omitempty"`
}

func (s spiceRef) String() string {
	out := s.Object.Type + ":" + s.Object.ID
	if s.Relation != "" {
		out += "#" + s.Relation
	}
	return out
}

// ServeHTTP implements http.Handler.
func (f *SpiceDB) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !authorized(w, r, f.Engine.Key) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/v1/schema/write":
		var in struct{ Schema string }
		if !decode(w, r, &in) {
			return
		}
		code, b := f.Engine.Do(http.MethodPut, "/v1/schema", map[string]string{"schema": in.Schema})
		if code != http.StatusOK {
			http.Error(w, string(b), http.StatusBadRequest)
			return
		}
		reply(w, 200, map[string]any{"writtenAt": map[string]string{"token": "GhUK"}})
	case "/v1/relationships/write":
		var in struct {
			Updates []struct {
				Operation    string `json:"operation"`
				Relationship struct {
					Resource spiceObject `json:"resource"`
					Relation string      `json:"relation"`
					Subject  spiceRef    `json:"subject"`
				} `json:"relationship"`
			} `json:"updates"`
		}
		if !decode(w, r, &in) {
			return
		}
		if len(in.Updates) > spiceDBMaxBatch {
			http.Error(w, "too many updates", http.StatusBadRequest)
			return
		}
		rels := make([]string, len(in.Updates))
		for i, u := range in.Updates {
			if u.Operation != "OPERATION_TOUCH" {
				http.Error(w, "not a touch: "+u.Operation, http.StatusBadRequest)
				return
			}
			rel := u.Relationship
			rels[i] = rel.Resource.Type + ":" + rel.Resource.ID + "#" + rel.Relation + "@" + rel.Subject.String()
		}
		if code, b := f.Engine.Touch(rels); code != http.StatusOK {
			http.Error(w, string(b), http.StatusBadRequest)
			return
		}
		f.writes++
		f.maxBatch = max(f.maxBatch, len(rels))
		reply(w, 200, map[string]any{"writtenAt": map[string]string{"token": "GhUK"}})
	case "/v1/permissions/check":
		var in struct {
			Consistency map[string]bool `json:"consistency"`
			Resource    spiceObject     `json:"resource"`
			Permission  string          `json:"permission"`
			Subject     spiceRef        `json:"subject"`
		}
		if !decode(w, r, &in) {
			return
		}
		if len(in.Consistency) != 1 || !(in.Consistency["fullyConsistent"] || in.Consistency["minimizeLatency"]) {
			http.Error(w, "bad consistency", http.StatusBadRequest)
			return
		}
		ok, code, b := f.Engine.Check(in.Resource.Type+":"+in.Resource.ID, in.Permission, in.Subject.String())
		if code != http.StatusOK {
			http.Error(w, string(b), http.StatusBadRequest)
			return
		}
		p := "PERMISSIONSHIP_NO_PERMISSION"
		if ok {
			p = "PERMISSIONSHIP_HAS_PERMISSION"
		}
		if f.Answer != "" {
			p = f.Answer
		}
		reply(w, 200, map[string]any{"checkedAt": map[string]string{"token": "GhUK"}, "permissionship": p})
	default:
		http.NotFound(w, r)
	}
}

// OpenFGA answers OpenFGA's HTTP API (stores, models, writes, checks)
// from an engine, with stores and models as OpenFGA keeps them. Writes
// must name the newest model, carry at most 100 tuples and ignore
// duplicates; a check must name a model. The engine already has the
// dataset's schema: the fake does not compile models. Its key is the
// engine's.
type OpenFGA struct {
	Engine *Engine
	// DropUsersets ignores written tuples whose subject is a set such as
	// group:g1#member, so that it answers some checks wrongly.
	DropUsersets bool

	mu       sync.Mutex
	stores   map[string]string // name -> id
	models   []json.RawMessage // newest last, as written
	writes   int
	maxBatch int
}

// Counts is how many stores and models the fake holds, how many writes it
// took and the most tuples one had.
func (f *OpenFGA) Counts() (stores, models, writes, largest int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.stores), len(f.models), f.writes, f.maxBatch
}

// ServeHTTP implements http.Handler.
func (f *OpenFGA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !authorized(w, r, f.Engine.Key) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stores == nil {
		f.stores = map[string]string{}
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/stores":
		var list []map[string]string
		for name, id := range f.stores {
			if q := r.URL.Query().Get("name"); q == "" || q == name {
				list = append(list, map[string]string{"id": id, "name": name})
			}
		}
		reply(w, 200, map[string]any{"stores": list, "continuation_token": ""})
	case r.Method == http.MethodPost && r.URL.Path == "/stores":
		var in struct{ Name string }
		if !decode(w, r, &in) {
			return
		}
		id := fmt.Sprintf("01STORE%d", len(f.stores)+1)
		f.stores[in.Name] = id
		reply(w, http.StatusCreated, map[string]string{"id": id, "name": in.Name})
	case len(parts) == 3 && parts[0] == "stores" && parts[2] == "authorization-models":
		if !f.known(parts[1]) {
			http.Error(w, "no store", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet {
			var newest []json.RawMessage
			if n := len(f.models); n > 0 {
				newest = append(newest, f.models[n-1])
			}
			reply(w, 200, map[string]any{"authorization_models": newest})
			return
		}
		var model map[string]any
		if !decode(w, r, &model) {
			return
		}
		id := fmt.Sprintf("01MODEL%d", len(f.models)+1)
		model["id"] = id
		b, _ := json.Marshal(model)
		f.models = append(f.models, b)
		reply(w, http.StatusCreated, map[string]string{"authorization_model_id": id})
	case len(parts) == 3 && parts[0] == "stores" && parts[2] == "write":
		var in struct {
			Model  string `json:"authorization_model_id"`
			Writes struct {
				OnDuplicate string `json:"on_duplicate"`
				Tuples      []struct {
					User     string `json:"user"`
					Relation string `json:"relation"`
					Object   string `json:"object"`
				} `json:"tuple_keys"`
			} `json:"writes"`
		}
		if !f.known(parts[1]) {
			http.Error(w, "no store", http.StatusNotFound)
			return
		}
		if !decode(w, r, &in) {
			return
		}
		if in.Model != f.newest() || in.Writes.OnDuplicate != "ignore" || len(in.Writes.Tuples) > openFGAMaxBatch {
			http.Error(w, "bad write", http.StatusBadRequest)
			return
		}
		var rels []string
		for _, k := range in.Writes.Tuples {
			if f.DropUsersets && strings.Contains(k.User, "#") {
				continue
			}
			rels = append(rels, k.Object+"#"+k.Relation+"@"+k.User)
		}
		if code, b := f.Engine.Touch(rels); code != http.StatusOK && len(rels) > 0 {
			http.Error(w, string(b), http.StatusBadRequest)
			return
		}
		f.writes++
		f.maxBatch = max(f.maxBatch, len(in.Writes.Tuples))
		reply(w, 200, map[string]any{})
	case len(parts) == 3 && parts[0] == "stores" && parts[2] == "check":
		var in struct {
			Model       string `json:"authorization_model_id"`
			Consistency string `json:"consistency"`
			Tuple       struct {
				User     string `json:"user"`
				Relation string `json:"relation"`
				Object   string `json:"object"`
			} `json:"tuple_key"`
		}
		if !f.known(parts[1]) {
			http.Error(w, "no store", http.StatusNotFound)
			return
		}
		if !decode(w, r, &in) {
			return
		}
		if in.Model == "" || (in.Consistency != "HIGHER_CONSISTENCY" && in.Consistency != "MINIMIZE_LATENCY") {
			http.Error(w, "bad check", http.StatusBadRequest)
			return
		}
		ok, code, b := f.Engine.Check(in.Tuple.Object, in.Tuple.Relation, in.Tuple.User)
		if code != http.StatusOK {
			http.Error(w, string(b), http.StatusBadRequest)
			return
		}
		reply(w, 200, map[string]any{"allowed": ok, "resolution": ""})
	default:
		http.NotFound(w, r)
	}
}

func (f *OpenFGA) known(id string) bool {
	for _, s := range f.stores {
		if s == id {
			return true
		}
	}
	return false
}

func (f *OpenFGA) newest() string {
	if len(f.models) == 0 {
		return ""
	}
	var m struct{ ID string }
	json.Unmarshal(f.models[len(f.models)-1], &m)
	return m.ID
}
