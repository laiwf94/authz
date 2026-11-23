package ops

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/laiwf94/authz/bench/datasets"
	"github.com/laiwf94/authz/bench/products"
	"github.com/laiwf94/authz/bench/products/productstest"
)

const productKey = "ops-products-key-0123456789"

// dataKeys draws from a dataset of 5,000 relationships: its documents and
// users, as authzdata manifest names them.
func dataKeys(t *testing.T) (datasets.Graph, Keyspace) {
	t.Helper()
	g, err := datasets.Size(5_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	return g, Keyspace{ResourceType: "doc", ResourcePrefix: "d", Resources: g.Docs,
		SubjectType: "user", SubjectPrefix: "u", Subjects: g.Users, Zipf: 1.1}
}

type productSetup struct {
	name    string
	api     *API
	written func(resource, permission, subject string) bool
}

// productAPIs loads g into authz, the SpiceDB fake and the OpenFGA fake
// (list objects bounded at 100, as compose.yaml sets it) and returns an
// API for each.
func productAPIs(t *testing.T, g datasets.Graph) []productSetup {
	t.Helper()
	ctx := context.Background()
	client, err := NewClient(8, "")
	if err != nil {
		t.Fatal(err)
	}
	load := func(tg products.Target) {
		if err := tg.Setup(ctx); err != nil {
			t.Fatalf("%s setup: %v", tg.Name(), err)
		}
		if _, err := tg.Loader().Load(ctx, g, 0, g.Count()); err != nil {
			t.Fatalf("%s load: %v", tg.Name(), err)
		}
	}
	authzEngine := productstest.NewEngine(t, productKey)
	authzSrv := httptest.NewServer(authzEngine.Handler)
	t.Cleanup(authzSrv.Close)
	load(products.NewAuthz(nil, authzSrv.URL, productKey))

	spice := &productstest.SpiceDB{Engine: productstest.NewEngine(t, productKey)}
	spiceSrv := httptest.NewServer(spice)
	t.Cleanup(spiceSrv.Close)
	load(products.NewSpiceDB(nil, spiceSrv.URL, productKey))

	fga := &productstest.OpenFGA{Engine: productstest.NewEngine(t, productKey), ListObjectsMaxResults: 100}
	fgaSrv := httptest.NewServer(fga)
	t.Cleanup(fgaSrv.Close)
	o := products.NewOpenFGA(nil, fgaSrv.URL, productKey, "bench")
	load(o)
	found := products.NewOpenFGA(nil, fgaSrv.URL, productKey, "bench")
	if err := found.Find(ctx); err != nil || found.Store != o.Store || found.Model != o.Model {
		t.Fatalf("find: %v, store %s model %s, set up %s %s", err, found.Store, found.Model, o.Store, o.Model)
	}
	has := func(e *productstest.Engine) func(string, string, string) bool {
		return func(r, p, s string) bool { ok, _, _ := e.Check(r, p, s); return ok }
	}
	return []productSetup{
		{"authz", &API{Client: client, URL: authzSrv.URL, Key: productKey}, has(authzEngine)},
		{"spicedb", &API{Client: client, URL: spiceSrv.URL, Key: productKey, Product: ProductSpiceDB}, has(spice.Engine)},
		{"openfga", &API{Client: client, URL: fgaSrv.URL, Key: productKey, Product: ProductOpenFGA,
			Store: found.Store, Model: found.Model}, has(fga.Engine)},
	}
}

// Every operation succeeds against every product with the dataset loaded,
// at both consistencies, and a write lands in the product's data.
func TestProductOperations(t *testing.T) {
	g, k := dataKeys(t)
	for _, p := range productAPIs(t, g) {
		t.Run(p.name, func(t *testing.T) {
			ctx := context.Background()
			for _, consistency := range []string{"", "fully_consistent"} {
				p.api.Consistency = consistency
				if err := p.api.Validate(); err != nil {
					t.Fatal(err)
				}
				mix := []interface {
					Name() string
					Do(context.Context, int, *rand.Rand) error
				}{
					&Check{API: p.api, Keys: k, Permission: "view"},
					&BulkCheck{API: p.api, Keys: k, Permission: "edit", Items: 20},
					&Lookup{API: p.api, Keys: k, Permission: "view", Limit: 100},
					&Write{API: p.api, Keys: k, Relation: "editor"},
				}
				for _, op := range mix {
					rng := rand.New(rand.NewPCG(1, 2))
					for i := range 60 {
						if err := op.Do(ctx, 0, rng); err != nil {
							t.Fatalf("%s %q #%d: %v", op.Name(), consistency, i, err)
						}
					}
				}
			}
			w := &Write{API: p.api, Keys: Keyspace{ResourceType: "doc", ResourcePrefix: "new", Resources: 1,
				SubjectType: "user", SubjectPrefix: "u", Subjects: 1}, Relation: "editor"}
			if p.written("doc:new0", "edit", "user:u0") {
				t.Fatal("doc:new0 is editable before the write")
			}
			if err := w.Do(ctx, 0, rand.New(rand.NewPCG(1, 1))); err != nil {
				t.Fatal(err)
			}
			if !p.written("doc:new0", "edit", "user:u0") {
				t.Fatal("the write did not reach the product")
			}
		})
	}
}

// A lookup answer over the limit fails, so an OpenFGA left at its default
// of 1,000 results is not compared with products answering 100.
func TestLookupOverLimit(t *testing.T) {
	g, _ := dataKeys(t)
	p := productAPIs(t, g)
	for _, s := range p {
		// user:u0 sees well over 3 documents in this graph.
		l := &Lookup{API: s.api, Keys: Keyspace{ResourceType: "doc", Resources: 1, SubjectType: "user",
			SubjectPrefix: "u", Subjects: 1}, Permission: "view", Limit: 100}
		if err := l.Do(context.Background(), 0, rand.New(rand.NewPCG(1, 1))); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if s.name == "openfga" {
			// The fake answers up to 100, whatever the request says.
			l.Limit = 3
			if err := l.Do(context.Background(), 0, rand.New(rand.NewPCG(1, 1))); err == nil || !strings.Contains(err.Error(), "over the limit of 3") {
				t.Fatalf("openfga at limit 3: %v", err)
			}
		}
	}
}

func TestAPIValidate(t *testing.T) {
	for _, c := range []struct {
		api  API
		want string
	}{
		{API{}, ""},
		{API{Product: ProductAuthz, Consistency: "at_least_as_fresh"}, ""},
		{API{Product: ProductSpiceDB}, ""},
		{API{Product: ProductSpiceDB, Consistency: "fully_consistent"}, ""},
		{API{Product: ProductSpiceDB, Consistency: "at_least_as_fresh"}, "no equivalent"},
		{API{Product: ProductOpenFGA, Store: "s", Model: "m", Consistency: "minimize_latency"}, ""},
		{API{Product: ProductOpenFGA, Store: "s"}, "store and authorization model"},
		{API{Product: "zanzibar"}, `product "zanzibar"`},
	} {
		err := c.api.Validate()
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%+v: %v, want %q", c.api, err, c.want)
		}
	}
}

// Each product's operations fail on an answer that has the right status
// but the wrong content.
func TestProductOperationsCheckTheAnswer(t *testing.T) {
	k := Keyspace{ResourceType: "doc", ResourcePrefix: "d", Resources: 5, SubjectType: "user", SubjectPrefix: "u", Subjects: 5}
	const okPair = `{"request":{"resource":{"objectType":"doc","objectId":"x9"}},"item":{"permissionship":"PERMISSIONSHIP_HAS_PERMISSION"}}`
	for _, c := range []struct {
		product, op string
		status      int
		body        string
		want        string
	}{
		{ProductSpiceDB, "check", 200, `{"permissionship":"PERMISSIONSHIP_CONDITIONAL_PERMISSION"}`, "CONDITIONAL"},
		{ProductSpiceDB, "check", 200, `{}`, "no permissionship"},
		{ProductSpiceDB, "check", 403, `{"code":7,"message":"denied"}`, "status 403"},
		{ProductSpiceDB, "bulk", 200, `{"pairs":[]}`, "answered 0 of 2"},
		{ProductSpiceDB, "bulk", 200, `{"pairs":[{"request":{},"error":{"code":9,"message":"no such permission"}},` + okPair + `]}`, "code 9: no such permission"},
		{ProductSpiceDB, "bulk", 200, `{"pairs":[` + okPair + `,` + okPair + `]}`, "answers doc:x9, asked doc:d"},
		{ProductSpiceDB, "lookup", 200, `{"result":{"resourceObjectId":"d1","permissionship":"LOOKUP_PERMISSIONSHIP_HAS_PERMISSION"}}` + "\n" +
			`{"error":{"code":4,"message":"deadline exceeded"}}` + "\n", "code 4: deadline exceeded"},
		{ProductSpiceDB, "lookup", 200, `{"result":{"resourceObjectId":"d1","permissionship":"LOOKUP_PERMISSIONSHIP_CONDITIONAL_PERMISSION"}}`, "CONDITIONAL"},
		{ProductSpiceDB, "lookup", 200, `{"result":{}}`, "no resource"},
		{ProductSpiceDB, "lookup", 200, `not json`, "not the expected JSON stream"},
		{ProductSpiceDB, "lookup", 200, strings.Repeat(`{"result":{"resourceObjectId":"d1","permissionship":"LOOKUP_PERMISSIONSHIP_HAS_PERMISSION"}}`+"\n", 3), "3 resources, over the limit of 2"},
		{ProductSpiceDB, "lookup", 400, `{"error":{"code":9}}`, "status 400"},
		{ProductSpiceDB, "write", 200, `{}`, "no writtenAt"},
		{ProductOpenFGA, "check", 200, `{}`, "no allowed"},
		{ProductOpenFGA, "bulk", 200, `{"result":{"0":{"allowed":true}}}`, "answered 1 of 2"},
		{ProductOpenFGA, "bulk", 200, `{"result":{"0":{"allowed":true},"7":{"allowed":true}}}`, "item 1 is not answered"},
		{ProductOpenFGA, "bulk", 200, `{"result":{"0":{"allowed":true},"1":{"error":{"input_error":"validation_error","message":"invalid relation"}}}}`, "item 1: invalid relation"},
		{ProductOpenFGA, "bulk", 200, `{"result":{"0":{"allowed":true},"1":{}}}`, "item 1 has no allowed"},
		{ProductOpenFGA, "lookup", 200, `{}`, "no objects"},
		{ProductOpenFGA, "lookup", 200, `{"objects":["folder:f1"]}`, "not a doc"},
		{ProductOpenFGA, "lookup", 200, `{"objects":["doc:d1","doc:d2","doc:d3"]}`, "over the limit of 2"},
		{ProductOpenFGA, "write", 200, `null`, "not an object"},
		{ProductOpenFGA, "write", 400, `{"code":"validation_error"}`, "status 400"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+productKey {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(c.status)
			fmt.Fprint(w, c.body)
		}))
		c2, _ := NewClient(1, "")
		api := &API{Client: c2, URL: srv.URL, Key: productKey, Product: c.product, Store: "s", Model: "m"}
		var err error
		rng := rand.New(rand.NewPCG(3, 3))
		switch c.op {
		case "check":
			err = (&Check{API: api, Keys: k, Permission: "view"}).Do(context.Background(), 0, rng)
		case "bulk":
			err = (&BulkCheck{API: api, Keys: k, Permission: "view", Items: 2}).Do(context.Background(), 0, rng)
		case "lookup":
			err = (&Lookup{API: api, Keys: k, Permission: "view", Limit: 2}).Do(context.Background(), 0, rng)
		case "write":
			err = (&Write{API: api, Keys: k, Relation: "editor"}).Do(context.Background(), 0, rng)
		}
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s %d %s: %v, want %q", c.product, c.op, c.status, c.body, err, c.want)
		}
	}
}
