package products

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/laiwf94/authz/bench/datasets"
	"github.com/laiwf94/authz/bench/products/productstest"
)

const key = "products-test-key-0123456789"

// reply writes v as a JSON answer.
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// spiceRef is a SpiceDB subject reference as the gateway's JSON has it.
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

func loadAll(t *testing.T, tg Target, g datasets.Graph) datasets.LoadResult {
	t.Helper()
	if err := tg.Setup(context.Background()); err != nil {
		t.Fatalf("%s setup: %v", tg.Name(), err)
	}
	res, err := tg.Loader().Load(context.Background(), g, 0, g.Count())
	if err != nil {
		t.Fatalf("%s load: %v", tg.Name(), err)
	}
	if res.Relationships != g.Count() {
		t.Fatalf("%s load wrote %d of %d", tg.Name(), res.Relationships, g.Count())
	}
	return res
}

// One dataset loaded into authz and through the SpiceDB and OpenFGA write
// formats into two more engines answers every sampled question the same
// three ways; an OpenFGA that loses the bans is caught.
func TestLoadAndCrossCheck(t *testing.T) {
	g, err := datasets.Size(20_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	// authz gets the schema from Setup; the fakes' engines have it.
	authzSrv := httptest.NewServer(productstest.NewAPI(t, key))
	defer authzSrv.Close()
	spice := &productstest.SpiceDB{Engine: productstest.NewEngine(t, key)}
	spiceSrv := httptest.NewServer(spice)
	defer spiceSrv.Close()
	fga := &productstest.OpenFGA{Engine: productstest.NewEngine(t, key)}
	fgaSrv := httptest.NewServer(fga)
	defer fgaSrv.Close()

	a := NewAuthz(nil, authzSrv.URL, key)
	s := NewSpiceDB(nil, spiceSrv.URL, key)
	o := NewOpenFGA(nil, fgaSrv.URL, key, "bench")
	loadAll(t, a, g)
	sres := loadAll(t, s, g)
	ores := loadAll(t, o, g)
	if n, largest := spice.Writes(); largest != SpiceDBMaxBatch || int64(n) != sres.Writes {
		t.Errorf("spicedb: %d writes of up to %d, loader counted %d", n, largest, sres.Writes)
	}
	if _, _, n, largest := fga.Counts(); largest != OpenFGAMaxBatch || int64(n) != ores.Writes {
		t.Errorf("openfga: %d writes of up to %d, loader counted %d", n, largest, ores.Writes)
	}

	// Setup again finds the store and its model instead of making new ones.
	store, model := o.Store, o.Model
	o2 := NewOpenFGA(nil, fgaSrv.URL, key, "bench")
	if err := o2.Setup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stores, models, _, _ := fga.Counts(); o2.Store != store || o2.Model != model || stores != 1 || models != 1 {
		t.Errorf("second setup: store %s model %s (first %s %s), %d stores %d models",
			o2.Store, o2.Model, store, model, stores, models)
	}

	qs := Sample(g, 900, 1)
	rep, err := CrossCheck(context.Background(), []Target{a, s, o2}, qs, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(rep)
	if len(rep.Disagreements) != 0 || rep.Questions != len(qs) {
		t.Fatalf("cross-check: %v", rep)
	}
	if rep.Allowed < len(qs)/5 || rep.Allowed > len(qs)*4/5 {
		t.Errorf("%d of %d allowed: the sample should give both answers often", rep.Allowed, len(qs))
	}
	// Fast reads give the same answers once the data has settled.
	for _, tg := range []Target{a, s, o2} {
		q := qs[2]
		fast, err := tg.Check(context.Background(), q.Resource, q.Permission, q.Subject, false)
		fresh, err2 := tg.Check(context.Background(), q.Resource, q.Permission, q.Subject, true)
		if err != nil || err2 != nil || fast != fresh {
			t.Errorf("%s %s: fast %v %v, fresh %v %v", tg.Name(), q, fast, err, fresh, err2)
		}
	}

	// An OpenFGA that lost the group usersets disagrees where groups grant.
	lossy := &productstest.OpenFGA{Engine: productstest.NewEngine(t, key), DropUsersets: true}
	lossySrv := httptest.NewServer(lossy)
	defer lossySrv.Close()
	bad := NewOpenFGA(nil, lossySrv.URL, key, "bench")
	loadAll(t, bad, g)
	rep, err = CrossCheck(context.Background(), []Target{a, bad}, qs, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Disagreements) == 0 {
		t.Fatal("cross-check missed the dropped usersets")
	}
	for _, d := range rep.Disagreements {
		if !d.Answers["authz"] || d.Answers["openfga"] {
			t.Errorf("%s: %v, want the lossy store to deny what authz allows", d.Question, d.Answers)
		}
	}
	if !strings.Contains(rep.String(), "disagreements; doc:") {
		t.Errorf("report: %s", rep)
	}
}

func TestSample(t *testing.T) {
	g, _ := datasets.Size(50_000, 2)
	a, b := Sample(g, 300, 9), Sample(g, 300, 9)
	if len(a) != 300 || fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatal("the same seed must draw the same questions")
	}
	if fmt.Sprint(Sample(g, 300, 10)) == fmt.Sprint(a) {
		t.Error("another seed drew the same questions")
	}
	perms, groups := map[string]int{}, 0
	for _, q := range a {
		perms[q.Permission]++
		if strings.HasPrefix(q.Subject, "group:") {
			if !strings.HasSuffix(q.Subject, "#member") {
				t.Errorf("group subject without #member: %s", q)
			}
			groups++
		}
		if !strings.HasPrefix(q.Resource, "doc:d") {
			t.Errorf("resource %s is not a document", q.Resource)
		}
	}
	if perms["view"] < 150 || perms["edit"] < 30 || groups == 0 {
		t.Errorf("permissions %v, %d group subjects", perms, groups)
	}
}

// SpiceDB's write body round-trips every kind of relationship the dataset
// has: a wildcard, a subject relation and a plain subject.
func TestSpiceDBWrites(t *testing.T) {
	rels := []datasets.Relationship{
		{ResourceType: "folder", Resource: 3, Relation: "viewer", SubjectType: "user", Subject: datasets.Wildcard},
		{ResourceType: "doc", Resource: 12, Relation: "editor", SubjectType: "group", Subject: 4, SubjectRelation: "member"},
		{ResourceType: "doc", Resource: 0, Relation: "owner", SubjectType: "user", Subject: 99},
	}
	b := SpiceDBWrites.Begin(nil)
	for i := range rels {
		if i > 0 {
			b = append(b, ',')
		}
		b = SpiceDBWrites.Append(b, &rels[i])
	}
	b = SpiceDBWrites.End(b)
	var body struct {
		Updates []struct {
			Operation    string
			Relationship struct {
				Resource spiceObject
				Relation string
				Subject  spiceRef
			}
		}
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	for i, u := range body.Updates {
		got := u.Relationship.Resource.Type + ":" + u.Relationship.Resource.ID + "#" + u.Relationship.Relation + "@" + u.Relationship.Subject.String()
		if got != rels[i].String() || u.Operation != "OPERATION_TOUCH" {
			t.Errorf("update %d: %s %s, want touch %s", i, u.Operation, got, rels[i])
		}
	}
}

func TestCheckAnswers(t *testing.T) {
	e := productstest.NewEngine(t, key)
	e.Touch([]string{"doc:d1#owner@user:u1"})
	spice := &productstest.SpiceDB{Engine: e}
	srv := httptest.NewServer(spice)
	defer srv.Close()
	s := NewSpiceDB(srv.Client(), srv.URL, key)
	ctx := context.Background()
	if ok, err := s.Check(ctx, "doc:d1", "edit", "user:u1", false); !ok || err != nil {
		t.Errorf("owner edit: %v %v", ok, err)
	}
	if ok, err := s.Check(ctx, "doc:d1", "edit", "user:u2", true); ok || err != nil {
		t.Errorf("stranger edit: %v %v", ok, err)
	}
	spice.Answer = "PERMISSIONSHIP_CONDITIONAL_PERMISSION"
	if _, err := s.Check(ctx, "doc:d1", "edit", "user:u1", true); err == nil || !strings.Contains(err.Error(), "CONDITIONAL") {
		t.Errorf("conditional answer: %v", err)
	}
	for _, bad := range [][2]string{{"doc", "user:u1"}, {"doc:d1#owner", "user:u1"}, {"doc:d1", "user:"}, {"doc:d1", ":u1"}} {
		if _, err := s.Check(ctx, bad[0], "edit", bad[1], true); err == nil {
			t.Errorf("check %q %q: no error", bad[0], bad[1])
		}
	}
	// A wrong key is refused with the answer's status.
	if _, err := NewSpiceDB(nil, srv.URL, "wrong-key-0123456789").Check(ctx, "doc:d1", "edit", "user:u1", true); err == nil || !strings.Contains(err.Error(), "status 401") {
		t.Errorf("wrong key: %v", err)
	}
	if err := NewSpiceDB(nil, "http://127.0.0.1:1", key).Setup(ctx); err == nil {
		t.Error("setup against nothing: no error")
	}

	// Answers without the field each API promises are errors, not denials.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reply(w, 200, map[string]any{}) }))
	defer empty.Close()
	o := NewOpenFGA(nil, empty.URL, key, "bench")
	if _, err := o.Check(ctx, "doc:d1", "view", "user:u1", true); err == nil || !strings.Contains(err.Error(), "before setup") {
		t.Errorf("openfga check before setup: %v", err)
	}
	o.Store, o.Model = "s", "m"
	for _, tg := range []Target{NewAuthz(nil, empty.URL, key), NewSpiceDB(nil, empty.URL, key), o} {
		if _, err := tg.Check(ctx, "doc:d1", "view", "user:u1", true); err == nil {
			t.Errorf("%s: an empty answer is not an error", tg.Name())
		}
	}
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "{") }))
	defer garbage.Close()
	if _, err := NewAuthz(nil, garbage.URL, key).Check(ctx, "doc:d1", "view", "user:u1", true); err == nil {
		t.Error("a broken answer is not an error")
	}
	if err := NewOpenFGA(nil, garbage.URL, key, "bench").Setup(ctx); err == nil {
		t.Error("openfga setup on a broken answer: no error")
	}
	// CrossCheck stops at a failed check and needs two targets.
	if _, err := CrossCheck(ctx, []Target{s}, Sample(datasets.Graph{Docs: 1, Users: 1}, 1, 1), 1); err == nil {
		t.Error("cross-check of one target: no error")
	}
	if _, err := CrossCheck(ctx, []Target{s, NewAuthz(nil, garbage.URL, key)}, []Question{{"doc:d1", "edit", "user:u1"}}, 1); err == nil {
		t.Error("cross-check with a failing target: no error")
	}
}

// Every image compose.yaml runs is pinned by a version tag and a digest,
// and README.md names the same version of each.
func TestComposePinned(t *testing.T) {
	f, err := os.Open("compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	pinned := regexp.MustCompile(`^([a-z0-9./-]+):(v?[0-9][0-9A-Za-z.-]*)@sha256:[0-9a-f]{64}$`)
	images := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		ref, ok := strings.CutPrefix(line, "image: ")
		if !ok {
			continue
		}
		if ref == "authz:bench" {
			images[ref] = true
			continue // built from this checkout
		}
		m := pinned.FindStringSubmatch(ref)
		if m == nil {
			t.Errorf("image %q is not pinned as name:version@sha256:digest", ref)
			continue
		}
		images[m[1]] = true
		if !bytes.Contains(readme, []byte("`"+m[1]+":"+m[2]+"`")) {
			t.Errorf("README.md does not name %s:%s", m[1], m[2])
		}
	}
	for _, want := range []string{"authz:bench", "authzed/spicedb", "openfga/openfga", "openfga/cli", "postgres"} {
		if !images[want] {
			t.Errorf("compose.yaml runs no %s image", want)
		}
	}
}

// OpenFGAModel has the types and relations of the dataset's model.
func TestOpenFGAModel(t *testing.T) {
	var m struct {
		Version string `json:"schema_version"`
		Types   []struct {
			Type      string                     `json:"type"`
			Relations map[string]json.RawMessage `json:"relations"`
		} `json:"type_definitions"`
	}
	if err := json.Unmarshal(OpenFGAModel, &m); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, td := range m.Types {
		got = append(got, "type "+td.Type)
		for rel := range td.Relations {
			got = append(got, td.Type+"."+rel)
		}
	}
	var want []string
	typ := ""
	for _, line := range strings.Split(datasets.OpenFGAModel, "\n") {
		line = strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(line, "type "); ok {
			typ = name
			want = append(want, line)
		} else if def, ok := strings.CutPrefix(line, "define "); ok {
			name, _, _ := strings.Cut(def, ":")
			want = append(want, typ+"."+name)
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if m.Version != "1.1" || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("model %s %v, want 1.1 %v", m.Version, got, want)
	}
	if _, same := sameModel(OpenFGAModel); !same {
		t.Error("the model is not the same as itself")
	}
	if _, same := sameModel([]byte(`{"schema_version":"1.1","type_definitions":[]}`)); same {
		t.Error("an empty model is the same as the dataset's")
	}
}
