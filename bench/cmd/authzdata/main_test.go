package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/bench/datasets"
	"github.com/laiwf94/authz/bench/products/productstest"
	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

const key = "authzdata-key-0123456789"

func env(k string) string {
	switch k {
	case "AUTHZBENCH_API_KEY", "AUTHZBENCH_SPICEDB_KEY", "AUTHZBENCH_OPENFGA_KEY",
		"AUTHZBENCH_KEYCLOAK_ADMIN_PASSWORD", "AUTHZBENCH_KEYCLOAK_CLIENT_SECRET":
		return key
	}
	return ""
}

func runCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, env, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestManifestAndSchema(t *testing.T) {
	code, out, _ := runCmd(t, "manifest", "-size", "100m", "-seed", "3")
	var m datasets.Manifest
	if code != 0 || json.Unmarshal([]byte(out), &m) != nil {
		t.Fatalf("manifest: %d %q", code, out)
	}
	if m.Relationships != 99_999_998 || m.Docs != 23_466_026 || m.Seed != 3 || !strings.Contains(strings.Join(m.BenchFlags, " "), "-resources 23466026") {
		t.Errorf("manifest %+v", m)
	}
	if code, out, _ := runCmd(t, "schema"); code != 0 || out != datasets.Schema {
		t.Errorf("schema: %d", code)
	}
	if code, out, _ := runCmd(t, "schema", "-format", "openfga"); code != 0 || out != datasets.OpenFGAModel {
		t.Errorf("schema openfga: %d", code)
	}
}

func TestGraphUsersTools(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "g.txt")
	if code, _, e := runCmd(t, "graph", "-size", "10k", "-seed", "2", "-o", file); code != 0 {
		t.Fatalf("graph: %d %s", code, e)
	}
	g, _ := datasets.Size(10_000, 2)
	var want bytes.Buffer
	datasets.WriteGraph(&want, g, datasets.FormatTuples, 0, g.Count())
	if got, _ := os.ReadFile(file); !bytes.Equal(got, want.Bytes()) {
		t.Error("graph -o differs from WriteGraph")
	}
	code, out, _ := runCmd(t, "graph", "-size", "10k", "-seed", "2", "-format", "openfga", "-from", "5", "-to", "8")
	if code != 0 || strings.Count(out, "\n") != 3 || !strings.HasPrefix(out, `{"user":"user:u2"`) {
		t.Errorf("graph range: %d %q", code, out)
	}
	code, out, _ = runCmd(t, "users", "-size", "10k", "-seed", "2", "-n", "3", "-format", "credentials")
	if lines := strings.Split(strings.TrimSpace(out), "\n"); code != 0 || len(lines) != 3 || lines[2] != "u2:"+g.Password(2) {
		t.Errorf("users: %d, %d lines", code, len(lines))
	}
	code, out, _ = runCmd(t, "users", "-size", "10k")
	if code != 0 || strings.Count(out, "\n") != g.Users {
		t.Errorf("all users: %d, %d lines, want %d", code, strings.Count(out, "\n"), g.Users)
	}
	code, out, _ = runCmd(t, "tools", "-n", "7")
	var cat struct{ Tools []datasets.Tool }
	if code != 0 || json.Unmarshal([]byte(out), &cat) != nil || len(cat.Tools) != 7 {
		t.Errorf("tools: %d %q", code, out)
	}
	callsFile := filepath.Join(dir, "calls.json")
	if code, _, _ := runCmd(t, "tools", "-n", "7", "-calls", "20", "-o", callsFile); code != 0 {
		t.Fatalf("calls: %d", code)
	}
	b, _ := os.ReadFile(callsFile)
	var calls []datasets.Call
	if json.Unmarshal(b, &calls) != nil || len(calls) != 20 || calls[0].Name == "" {
		t.Errorf("calls file %s", b)
	}
}

func TestLoad(t *testing.T) {
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{5}, token.KeySize))
	s, err := api.New(api.Config{Store: st, Tokens: tok, APIKeys: []string{key}, Metrics: metrics.New(),
		CacheSize: 100, Quantum: time.Second, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	defer srv.Close()
	code, out, e := runCmd(t, "load", "-size", "5k", "-api", srv.URL, "-schema", "-batch", "300", "-workers", "2")
	g, _ := datasets.Size(5_000, 1)
	if code != 0 || !strings.HasPrefix(out, "loaded 4997 relationships in 17 writes (0 retried)") {
		t.Fatalf("load: %d %q %s (%d relationships)", code, out, e, g.Count())
	}
	// A relationship of the dataset is there.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/check", strings.NewReader(
		`{"resource":"doc:d0","permission":"edit","subject":"user:u`+strings.TrimPrefix(firstOwner(t, g), "user:u")+`","consistency":{"mode":"fully_consistent"}}`))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ans struct{ Allowed bool }
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if json.Unmarshal(b, &ans) != nil || !ans.Allowed {
		t.Errorf("the owner of doc:d0 cannot edit it after the load: %d %s", resp.StatusCode, b)
	}
	// Without the schema the engine refuses the types: exit 1.
	srv2 := httptest.NewServer(mustAPI(t))
	defer srv2.Close()
	if code, _, e := runCmd(t, "load", "-size", "1k", "-api", srv2.URL); code != 1 || !strings.Contains(e, "status 424") {
		t.Errorf("load without a schema: %d %s", code, e)
	}
}

func mustAPI(t *testing.T) http.Handler {
	st, _ := store.Open(store.Options{})
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{6}, token.KeySize))
	s, err := api.New(api.Config{Store: st, Tokens: tok, APIKeys: []string{key}, Metrics: metrics.New(), Quantum: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func firstOwner(t *testing.T, g datasets.Graph) string {
	var owner string
	g.Each(func(r *datasets.Relationship) error {
		if r.ResourceType == datasets.TypeDoc && r.Resource == 0 && r.Relation == "owner" {
			owner = string(datasets.AppendObject(nil, r.SubjectType, r.Subject))
		}
		return nil
	})
	if owner == "" {
		t.Fatal("doc:d0 has no owner")
	}
	return owner
}

func TestBadArguments(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"nope"},
		{"graph", "-size", "lots"},
		{"graph", "-size", "1k", "-format", "csv"},
		{"graph", "-size", "1k", "-from", "5", "-to", "2"},
		{"graph", "-size", "1k", "-to", "100000"},
		{"graph", "extra"},
		{"graph", "-bogus"},
		{"manifest", "-size", "5"},
		{"schema", "-format", "yaml"},
		{"users", "-size", "1k", "-n", "1000000"},
		{"users", "-size", "1k", "-format", "xml"},
		{"tools", "-n", "0"},
		{"tools", "-calls", "-1"},
		{"load", "-size", "1k"},
		{"load", "-size", "1k", "-api", "http://127.0.0.1:1", "-batch", "5000"},
		{"load", "-size", "1"},
		{"load", "-size", "1k", "-api", "http://127.0.0.1:1", "-target", "zanzibar"},
		{"load", "-size", "1k", "-api", "http://127.0.0.1:1", "-target", "openfga", "-batch", "101"},
		{"load", "-size", "1k", "-api", "http://127.0.0.1:1", "-batch", "-1"},
		{"crosscheck", "-size", "1k", "-authz", "http://127.0.0.1:1"},
		{"crosscheck", "-size", "1k", "-authz", "http://127.0.0.1:1", "-spicedb", "http://127.0.0.1:2", "-n", "0"},
		{"crosscheck", "-size", "lots"},
	} {
		if code, _, _ := runCmd(t, args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
	if code, out, _ := runCmd(t, "help"); code != 0 || !strings.Contains(out, "usage: authzdata") {
		t.Errorf("help: %d", code)
	}
	if code, _, _ := runCmd(t, "graph", "-h"); code != 0 {
		t.Errorf("graph -h: %d", code)
	}
	if code, _, _ := runCmd(t, "graph", "-size", "1k", "-o", filepath.Join(t.TempDir(), "no", "such", "dir")); code != 1 {
		t.Errorf("unwritable output: %d", code)
	}
	if code, _, _ := runCmd(t, "load", "-size", "1k", "-api", "http://127.0.0.1:1", "-schema"); code != 1 {
		t.Errorf("unreachable API: %d", code)
	}
}

// The same dataset loaded into authz and the SpiceDB and OpenFGA fakes
// gives the same answers; an OpenFGA that lost the group usersets fails
// the cross-check with exit status 1.
func TestLoadTargetsAndCrossCheck(t *testing.T) {
	authz := httptest.NewServer(productstest.NewAPI(t, key))
	defer authz.Close()
	spice := httptest.NewServer(&productstest.SpiceDB{Engine: productstest.NewEngine(t, key)})
	defer spice.Close()
	fga := &productstest.OpenFGA{Engine: productstest.NewEngine(t, key)}
	fgaSrv := httptest.NewServer(fga)
	defer fgaSrv.Close()
	for _, args := range [][]string{
		{"-api", authz.URL, "-schema"},
		{"-target", "spicedb", "-api", spice.URL, "-schema", "-workers", "2"},
		{"-target", "openfga", "-api", fgaSrv.URL, "-workers", "8"},
		// Again: the store and model are found, and the writes change nothing.
		{"-target", "openfga", "-api", fgaSrv.URL, "-to", "500", "-batch", "50"},
	} {
		code, out, e := runCmd(t, append([]string{"load", "-size", "3k"}, args...)...)
		if code != 0 || !strings.HasPrefix(out, "loaded ") {
			t.Fatalf("load %q: %d %q %s", args, code, out, e)
		}
	}
	if stores, models, _, largest := fga.Counts(); stores != 1 || models != 1 || largest != 100 {
		t.Errorf("openfga holds %d stores and %d models, largest write %d", stores, models, largest)
	}
	code, out, e := runCmd(t, "crosscheck", "-size", "3k", "-n", "300",
		"-authz", authz.URL, "-spicedb", spice.URL, "-openfga", fgaSrv.URL)
	if code != 0 || !strings.HasPrefix(out, "300 questions, ") || !strings.Contains(out, " 0 disagreements") {
		t.Fatalf("crosscheck: %d %q %s", code, out, e)
	}

	lossy := httptest.NewServer(&productstest.OpenFGA{Engine: productstest.NewEngine(t, key), DropUsersets: true})
	defer lossy.Close()
	if code, out, e := runCmd(t, "load", "-size", "3k", "-target", "openfga", "-api", lossy.URL); code != 0 {
		t.Fatalf("lossy load: %d %q %s", code, out, e)
	}
	code, out, e = runCmd(t, "crosscheck", "-size", "3k", "-n", "300", "-authz", authz.URL, "-openfga", lossy.URL)
	if code != 1 || !strings.Contains(e, "answered differently") || strings.Contains(out, " 0 disagreements") {
		t.Errorf("crosscheck against the lossy store: %d %q %s", code, out, e)
	}
	// A product that refuses the check is a failed run, not a disagreement.
	if code, _, e := runCmd(t, "crosscheck", "-size", "3k", "-n", "10", "-authz", authz.URL, "-spicedb", fgaSrv.URL); code != 1 || !strings.Contains(e, "spicedb") {
		t.Errorf("crosscheck against the wrong API: %d %s", code, e)
	}
	// Setup failures exit 1.
	if code, _, _ := runCmd(t, "crosscheck", "-size", "3k", "-authz", authz.URL, "-openfga", "http://127.0.0.1:1"); code != 1 {
		t.Errorf("crosscheck against no openfga: %d", code)
	}
	noKey := func(string) string { return "" }
	var o, eb bytes.Buffer
	if code := run(context.Background(), []string{"load", "-size", "1k", "-target", "spicedb", "-api", spice.URL}, noKey, &o, &eb); code != 2 || !strings.Contains(eb.String(), "AUTHZBENCH_SPICEDB_KEY") {
		t.Errorf("load without the key: %d %s", code, eb.String())
	}
}

// import sets Keycloak up, imports the population, reads it back, and a
// second run skips everything.
func TestImport(t *testing.T) {
	fake := &productstest.Keycloak{AdminUser: "bench-admin", AdminPassword: key}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	code, out, errOut := runCmd(t, "import", "-size", "100k", "-n", "120", "-batch", "25", "-api", srv.URL, "-verify", "-1")
	if code != 0 {
		t.Fatalf("import: %d %s %s", code, out, errOut)
	}
	if !strings.Contains(out, "imported 120 users in") || !strings.Contains(out, " 0 skipped") ||
		!strings.Contains(out, "verified 120 users") {
		t.Errorf("import said %q", out)
	}
	realm := fake.Realm("bench")
	if len(realm.Users) != 120 || realm.Clients["bench-proxy"]["secret"] != key {
		t.Fatalf("realm after import: %d users, clients %v", len(realm.Users), realm.Clients)
	}
	uris, _ := realm.Clients["bench-proxy"]["redirectUris"].([]any)
	if len(uris) != 2 || uris[0] != "http://127.0.0.1:14180/oauth2/callback" {
		t.Errorf("redirect URIs %v", uris)
	}
	code, out, _ = runCmd(t, "import", "-size", "100k", "-n", "120", "-api", srv.URL, "-verify", "0")
	if code != 0 || !strings.Contains(out, " 0 added") || strings.Contains(out, "verified") {
		t.Errorf("second import: %d %q", code, out)
	}
	code, out, _ = runCmd(t, "import", "-size", "100k", "-n", "-1", "-api", srv.URL, "-verify", "10")
	if code != 0 || !strings.Contains(out, "verified 10 users") {
		t.Errorf("every user: %d %q", code, out)
	}
	if got := len(fake.Realm("bench").Users); got != 2346 {
		t.Errorf("-n -1 imported %d users, want the 100k graph's 2346", got)
	}

	// A provider that refuses fails with status 1.
	fake.SetFail(func(r *http.Request) int {
		if strings.HasSuffix(r.URL.Path, "/users") {
			return http.StatusForbidden
		}
		return 0
	})
	if code, _, errOut := runCmd(t, "import", "-size", "100k", "-n", "5", "-api", srv.URL); code != 1 || !strings.Contains(errOut, "status 403") {
		t.Errorf("refused verify: %d %s", code, errOut)
	}
	fake.SetFail(func(*http.Request) int { return http.StatusBadRequest })
	if code, _, _ := runCmd(t, "import", "-size", "100k", "-n", "5", "-api", srv.URL); code != 1 {
		t.Errorf("refused setup: %d", code)
	}
	fake.SetFail(func(r *http.Request) int {
		if strings.HasSuffix(r.URL.Path, "/partialImport") {
			return http.StatusBadRequest
		}
		return 0
	})
	if code, out, _ := runCmd(t, "import", "-size", "100k", "-n", "5", "-api", srv.URL); code != 1 || !strings.Contains(out, "imported 5 users") {
		t.Errorf("refused import: %d %q", code, out)
	}

	for _, args := range [][]string{
		{"-api", srv.URL, "-target", "zitadel"},
		{"-api", srv.URL, "-n", "-2"},
		{"-api", srv.URL, "-n", "100000"},
		{"-api", srv.URL, "-batch", "0"},
		{"-api", srv.URL, "-workers", "0"},
		{"-api", srv.URL, "-verify", "-2"},
		{"-size", "nope", "-api", srv.URL},
		{"-n", "5"},
		{"-api", srv.URL, "extra"},
	} {
		if code, _, _ := runCmd(t, append([]string{"import", "-size", "100k"}, args...)...); code != 2 {
			t.Errorf("import %v: status %d, want 2", args, code)
		}
	}
	var out2, errOut2 bytes.Buffer
	noSecret := func(k string) string {
		if k == "AUTHZBENCH_KEYCLOAK_CLIENT_SECRET" {
			return ""
		}
		return env(k)
	}
	if code := run(context.Background(), []string{"import", "-size", "100k", "-api", srv.URL}, noSecret, &out2, &errOut2); code != 2 ||
		!strings.Contains(errOut2.String(), "AUTHZBENCH_KEYCLOAK_CLIENT_SECRET") {
		t.Errorf("no client secret: %d %s", code, errOut2.String())
	}
}
