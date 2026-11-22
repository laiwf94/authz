package datasets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

const testKey = "datasets-key-0123456789"

func newAPI(t *testing.T) string {
	t.Helper()
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{7}, token.KeySize))
	s, err := api.New(api.Config{Store: st, Tokens: tok, APIKeys: []string{testKey}, Metrics: metrics.New(),
		CacheSize: 1000, Quantum: time.Second, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return srv.URL
}

// oracle answers doc view from the relationships alone, by the schema's
// rules written out by hand, independent of the engine.
type oracle struct {
	userGroups   map[int][]int
	groupParents map[int][]int
	folderParent map[int]int
	folderUsers  map[int][]int
	folderGroups map[int][]int
	public       map[int]bool
	docParent    map[int]int
	docUsers     map[int][]int // owner and user editors
	docGroups    map[int][]int
	banned       map[int][]int
}

func newOracle(t *testing.T, g Graph) *oracle {
	o := &oracle{map[int][]int{}, map[int][]int{}, map[int]int{}, map[int][]int{}, map[int][]int{}, map[int]bool{},
		map[int]int{}, map[int][]int{}, map[int][]int{}, map[int][]int{}}
	err := g.Each(func(r *Relationship) error {
		switch r.ResourceType + "#" + r.Relation + "@" + r.SubjectType {
		case "group#member@user":
			o.userGroups[r.Subject] = append(o.userGroups[r.Subject], r.Resource)
		case "group#member@group":
			o.groupParents[r.Subject] = append(o.groupParents[r.Subject], r.Resource)
		case "folder#parent@folder":
			o.folderParent[r.Resource] = r.Subject
		case "folder#viewer@user":
			if r.Subject == Wildcard {
				o.public[r.Resource] = true
			} else {
				o.folderUsers[r.Resource] = append(o.folderUsers[r.Resource], r.Subject)
			}
		case "folder#viewer@group":
			o.folderGroups[r.Resource] = append(o.folderGroups[r.Resource], r.Subject)
		case "doc#parent@folder":
			o.docParent[r.Resource] = r.Subject
		case "doc#owner@user", "doc#editor@user":
			o.docUsers[r.Resource] = append(o.docUsers[r.Resource], r.Subject)
		case "doc#editor@group":
			o.docGroups[r.Resource] = append(o.docGroups[r.Resource], r.Subject)
		case "doc#banned@user":
			o.banned[r.Resource] = append(o.banned[r.Resource], r.Subject)
		default:
			return fmt.Errorf("unexpected relationship %s", r)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func (o *oracle) groupsOf(u int) map[int]bool {
	in := map[int]bool{}
	var up func(int)
	up = func(x int) {
		if in[x] {
			return
		}
		in[x] = true
		for _, p := range o.groupParents[x] {
			up(p)
		}
	}
	for _, x := range o.userGroups[u] {
		up(x)
	}
	return in
}

func has(xs []int, x int) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func anyIn(xs []int, set map[int]bool) bool {
	for _, x := range xs {
		if set[x] {
			return true
		}
	}
	return false
}

func (o *oracle) view(d, u int) bool {
	if has(o.banned[d], u) {
		return false
	}
	groups := o.groupsOf(u)
	if has(o.docUsers[d], u) || anyIn(o.docGroups[d], groups) {
		return true
	}
	for f, ok := o.docParent[d], true; ok; f, ok = o.folderParent[f] {
		if o.public[f] || has(o.folderUsers[f], u) || anyIn(o.folderGroups[f], groups) {
			return true
		}
	}
	return false
}

// TestLoadMatchesOracle loads a graph into the real authorization API and
// checks sampled documents and users against the oracle: every
// relationship is accepted by the schema, and the dataset asks checks with
// both answers.
func TestLoadMatchesOracle(t *testing.T) {
	url := newAPI(t)
	g := mustSize(t, 40_000, 11)
	var progress atomic.Int64
	l := &Loader{URL: url, Key: testKey, Batch: 700, Workers: 3, Progress: func(n int64) {
		for {
			old := progress.Load()
			if n <= old || progress.CompareAndSwap(old, n) {
				return
			}
		}
	}}
	ctx := context.Background()
	if err := l.PutSchema(ctx, Schema); err != nil {
		t.Fatal(err)
	}
	res, err := l.Load(ctx, g, 0, g.Count())
	if err != nil {
		t.Fatal(err)
	}
	wantWrites := (g.Count() + 699) / 700
	if res.Relationships != g.Count() || res.Writes != wantWrites || progress.Load() != g.Count() || res.PerSecond() <= 0 {
		t.Fatalf("loaded %+v, progress %d; want %d relationships in %d writes", res, progress.Load(), g.Count(), wantWrites)
	}
	// Loading again is idempotent: touches of what is there.
	if res, err := l.Load(ctx, g, g.Count()-10, g.Count()); err != nil || res.Relationships != 10 || res.Writes != 1 {
		t.Fatalf("reload of the last 10: %+v, %v", res, err)
	}
	var read struct {
		Relationships []json.RawMessage `json:"relationships"`
	}
	post(t, url+"/v1/relationships/read", `{"filter":{"resource_type":"folder"},"consistency":{"mode":"fully_consistent"},"limit":1000}`, &read)
	if want := min(2*g.Folders-g.folderRoots(), 1000); len(read.Relationships) != want {
		t.Errorf("read %d folder relationships, want %d", len(read.Relationships), want)
	}

	o := newOracle(t, g)
	r := rand.New(rand.NewPCG(3, 4))
	allowed := 0
	const samples = 600
	for i := range samples {
		d, u := r.IntN(g.Docs), r.IntN(g.Users)
		if i%3 == 0 { // ask the document's owner or a banned user now and then
			if b := o.banned[d]; len(b) > 0 {
				u = b[0]
			} else {
				u = o.docUsers[d][0]
			}
		}
		var ans struct {
			Allowed bool `json:"allowed"`
		}
		post(t, url+"/v1/check", fmt.Sprintf(`{"resource":"doc:d%d","permission":"view","subject":"user:u%d","consistency":{"mode":"fully_consistent"}}`, d, u), &ans)
		if want := o.view(d, u); ans.Allowed != want {
			t.Fatalf("doc:d%d view user:u%d: engine says %v, oracle %v", d, u, ans.Allowed, want)
		}
		if ans.Allowed {
			allowed++
		}
	}
	t.Logf("%d relationships loaded in %v (%.0f/s); %d of %d sampled checks allowed", res.Relationships, res.Elapsed, res.PerSecond(), allowed, samples)
	if allowed < samples/20 || allowed > samples*19/20 {
		t.Errorf("%d of %d checks allowed: the dataset should give both answers", allowed, samples)
	}
}

func post(t *testing.T, url, body string, out any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", url, resp.StatusCode, b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}

func TestLoaderRetriesAndFails(t *testing.T) {
	var calls atomic.Int64
	fail := atomic.Int64{}
	status := atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer k" || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "headers", http.StatusUnauthorized)
			return
		}
		if fail.Add(-1) >= 0 {
			http.Error(w, "busy", int(status.Load()))
			return
		}
		var body struct {
			Updates []struct {
				Op           string `json:"op"`
				Relationship string `json:"relationship"`
			} `json:"updates"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, u := range body.Updates {
			if _, err := store.ParseRelationship(u.Relationship); err != nil || u.Op != "touch" {
				http.Error(w, "bad update", http.StatusBadRequest)
				return
			}
		}
		w.Write([]byte(`{"written_at":"x"}`))
	}))
	defer srv.Close()
	g := mustSize(t, 1_000, 1)
	ctx := context.Background()

	// 503 and 429 are retried.
	for _, code := range []int64{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		fail.Store(2)
		status.Store(code)
		l := &Loader{URL: srv.URL + "/", Key: "k", Batch: 100, Workers: 1}
		res, err := l.Load(ctx, g, 0, g.Count())
		if err != nil || res.Retries != 2 || res.Relationships != g.Count() || res.Writes != 10 {
			t.Fatalf("status %d: %+v, %v", code, res, err)
		}
	}
	// A 400 is not retried and stops the load.
	fail.Store(1)
	status.Store(http.StatusBadRequest)
	calls.Store(0)
	l := &Loader{URL: srv.URL, Key: "k", Batch: 10, Workers: 2}
	if _, err := l.Load(ctx, g, 0, g.Count()); err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("a 400 gave %v", err)
	}
	if calls.Load() >= 100 {
		t.Errorf("%d calls after a failure; the load should stop", calls.Load())
	}
	// Retries run out.
	fail.Store(100)
	status.Store(http.StatusBadGateway)
	l = &Loader{URL: srv.URL, Key: "k", Retries: 2}
	if err := l.PutSchema(ctx, Schema); err == nil || !strings.Contains(err.Error(), "PUT /v1/schema: status 502") {
		t.Fatalf("exhausted retries gave %v", err)
	}
	// Bad settings and an unreachable server.
	for _, bad := range []*Loader{{Batch: MaxBatch + 1}, {Batch: -1}, {Workers: -1}} {
		if _, err := bad.Load(ctx, g, 0, 1); err == nil {
			t.Errorf("loader %+v accepted", bad)
		}
	}
	if _, err := (&Loader{URL: "http://\x00"}).Load(ctx, g, 0, 1); err == nil {
		t.Error("a bad URL loaded")
	}
	if _, err := (&Loader{URL: srv.URL, Key: "k"}).Load(ctx, g, 0, g.Count()+1); err == nil {
		t.Error("a range past the end loaded")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	fail.Store(0)
	if _, err := (&Loader{URL: srv.URL, Key: "k", Batch: 1}).Load(cctx, g, 0, g.Count()); err == nil {
		t.Error("a cancelled load succeeded")
	}
}

func TestLoaderStopsWhenCancelledDuringBackoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := (&Loader{URL: srv.URL, Key: "k", Retries: 50}).PutSchema(ctx, Schema)
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("cancelled retries: %v after %v", err, time.Since(start))
	}
}
