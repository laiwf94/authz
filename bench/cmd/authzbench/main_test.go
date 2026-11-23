package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/bench/datasets"
	"github.com/laiwf94/authz/bench/hdr"
	"github.com/laiwf94/authz/bench/products"
	"github.com/laiwf94/authz/bench/products/productstest"
	"github.com/laiwf94/authz/internal/agents/fakeserver"
	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

const (
	benchKey = "bench-key-0123456789"
	agentKey = "agent-key-0123456789"
)

// newAPI serves the authorization API in process with doc:N viewable by
// user:N for N below 50.
func newAPI(t *testing.T) string {
	t.Helper()
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{3}, token.KeySize))
	s, err := api.New(api.Config{Store: st, Tokens: tok, APIKeys: []string{benchKey}, Metrics: metrics.New(),
		CacheSize: 1000, Quantum: 100 * time.Millisecond, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	send := func(method, path, body string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+benchKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s %s: %d", method, path, resp.StatusCode)
		}
	}
	send("PUT", "/v1/schema", `{"schema": "definition user {}\ndefinition doc {\n relation viewer: user\n permission view = viewer\n}"}`)
	var ups []string
	for i := range 50 {
		ups = append(ups, fmt.Sprintf(`{"op":"touch","relationship":"doc:%d#viewer@user:%d"}`, i, i))
	}
	send("POST", "/v1/relationships/write", `{"updates":[`+strings.Join(ups, ",")+`]}`)
	return srv.URL
}

// newSSO is a one-server sign-in: /login shows a form, its POST sets the
// session cookie for the right password, and /auth answers forward-auth
// for that cookie.
func newSSO(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login" && r.Method == http.MethodGet:
			fmt.Fprint(w, `<form method="post" action="/login"><input name="username"><input type="password" name="password"></form>`)
		case r.URL.Path == "/login":
			r.ParseForm()
			if r.Form.Get("password") != r.Form.Get("username")+"-pass" {
				fmt.Fprint(w, `<form method="post"><input name="username"><input type="password" name="password"></form>`)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "s-" + r.Form.Get("username")})
			http.Redirect(w, r, "/", http.StatusFound)
		case r.URL.Path == "/":
			fmt.Fprint(w, "home")
		case r.URL.Path == "/auth":
			if c, err := r.Cookie("sid"); err != nil || !strings.HasPrefix(c.Value, "s-") || r.Header.Get("X-Forwarded-Host") != "app" {
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func newMCP(t *testing.T) string {
	t.Helper()
	fs, err := fakeserver.New(fakeserver.Config{Sandbox: t.TempDir(), Token: agentKey})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fs.Close() })
	srv := httptest.NewServer(fs)
	t.Cleanup(srv.Close)
	return srv.URL + "/mcp"
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var keys = map[string]string{"AUTHZBENCH_API_KEY": benchKey, "AUTHZBENCH_MCP_KEY": agentKey}

func runBench(t *testing.T, e map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb strings.Builder
	code := run(context.Background(), args, env(e), &out, &errb)
	return code, out.String(), errb.String()
}

// The whole mix in one run: every operation against a real server, the
// table on stdout and the result file with histograms that read back.
func TestRunEveryOperation(t *testing.T) {
	apiURL, sso, mcpURL := newAPI(t), newSSO(t), newMCP(t)
	dir := t.TempDir()
	sessions := filepath.Join(dir, "sessions.txt")
	os.WriteFile(sessions, []byte("# from an earlier sign-in\nsid=s-carol\n\n"), 0o600)
	creds := filepath.Join(dir, "creds.txt")
	os.WriteFile(creds, []byte("alice:alice-pass\nbob:bob-pass\n"), 0o600)
	out := filepath.Join(dir, "result.json")
	code, stdout, stderr := runBench(t, keys,
		"-mix", "check=40,bulk_check=10,lookup=10,write=10,forward_auth=20,oidc_login=5,mcp_call=5",
		"-rate", "300", "-warmup", "100ms", "-duration", "700ms", "-workers", "16", "-arrival", "poisson",
		"-api", apiURL, "-resources", "50", "-subjects", "50", "-zipf", "1.2",
		"-forward-url", sso+"/auth", "-forward-host", "app", "-forward-paths", "/a, /b,", "-sessions", "3", "-sessions-file", sessions,
		"-login-start", sso+"/login", "-login-credentials", "@"+creds, "-login-cookie", "sid",
		"-mcp-url", mcpURL, "-mcp-tools", `[{"name":"echo","arguments":{"text":"hi"}}]`,
		"-label", "test", "-out", out)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"operation", "check", "bulk_check", "lookup", "write", "forward_auth", "oidc_login", "mcp_call", "all", "offered 300.0/s", "pass\n"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Label  string `json:"label"`
		Pass   bool   `json:"pass"`
		Config struct {
			Args []string `json:"args"`
			Seed uint64   `json:"seed"`
		} `json:"config"`
		Scheduled, Sent, Unsent int64
		Ops                     []struct {
			Name    string `json:"name"`
			Weight  int    `json:"weight"`
			OK      int64  `json:"ok"`
			Errors  int64  `json:"errors"`
			Latency struct {
				P99  int64          `json:"p99_ns"`
				Hist *hdr.Histogram `json:"histogram"`
			} `json:"latency"`
		} `json:"ops"`
		Total struct {
			OK int64 `json:"ok"`
		} `json:"total"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if r.Label != "test" || !r.Pass || r.Config.Seed != 1 || len(r.Config.Args) == 0 || len(r.Ops) != 7 || r.Unsent != 0 {
		t.Fatalf("result %s", b)
	}
	var sum int64
	for _, o := range r.Ops {
		if o.Errors != 0 || o.Latency.Hist == nil || o.Latency.Hist.Count() != o.OK ||
			o.OK > 0 && int64(o.Latency.Hist.Quantile(0.99)) != o.Latency.P99 {
			t.Errorf("%s: %+v", o.Name, o)
		}
		sum += o.OK
	}
	if sum != r.Total.OK || sum != r.Scheduled {
		t.Fatalf("ops add to %d, total %d, scheduled %d", sum, r.Total.OK, r.Scheduled)
	}
	if strings.Contains(string(b), benchKey) || strings.Contains(string(b), agentKey) || strings.Contains(stdout, benchKey) {
		t.Fatal("a key leaked into the result")
	}
}

// A server refusing the requests fails the run with exit 1 and the error
// samples on stdout.
func TestRunFailsOnErrors(t *testing.T) {
	apiURL := newAPI(t)
	code, stdout, _ := runBench(t, map[string]string{"AUTHZBENCH_API_KEY": "wrong-key-0123456789"},
		"-api", apiURL, "-rate", "100", "-warmup", "0s", "-duration", "200ms")
	if code != 1 || !strings.Contains(stdout, "check error: status 401") || !strings.Contains(stdout, "FAIL") {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
}

func TestRunUsage(t *testing.T) {
	apiURL := newAPI(t)
	dir := t.TempDir()
	badSessions := filepath.Join(dir, "bad.txt")
	os.WriteFile(badSessions, []byte("novalue\n"), 0o600)
	for _, tc := range []struct {
		args []string
		env  map[string]string
		want string
	}{
		{[]string{"-rate"}, keys, "flag needs an argument"},
		{[]string{"extra"}, keys, `unexpected argument "extra"`},
		{[]string{"-mix", "check"}, keys, "not NAME=WEIGHT"},
		{[]string{"-mix", "check=0"}, keys, "not NAME=WEIGHT"},
		{[]string{"-mix", "check=1,check=2"}, keys, "named twice"},
		{[]string{"-mix", "teleport=1"}, keys, `unknown operation "teleport"`},
		{[]string{"-mix", "check=1"}, keys, "check needs -api"},
		{[]string{"-mix", "bulk_check=1", "-api", apiURL}, nil, "AUTHZBENCH_API_KEY"},
		{[]string{"-mix", "lookup=1", "-api", apiURL, "-resources", "0"}, keys, "counts must be positive"},
		{[]string{"-mix", "write=1"}, keys, "write needs -api"},
		{[]string{"-mix", "bulk_check=1", "-api", apiURL, "-bulk-items", "101"}, keys, "-bulk-items 101"},
		{[]string{"-mix", "forward_auth=1"}, keys, "needs -forward-url and -forward-host"},
		{[]string{"-mix", "forward_auth=1", "-forward-url", "http://x/auth", "-forward-host", "x", "-sessions-file", filepath.Join(dir, "none")}, keys, "no such file"},
		{[]string{"-mix", "forward_auth=1", "-forward-url", "http://x/auth", "-forward-host", "x", "-sessions-file", badSessions}, keys, "not NAME=VALUE"},
		{[]string{"-mix", "forward_auth=1", "-forward-url", "http://x/auth", "-forward-host", "x", "-sessions", "1"}, keys, "needs -login-start"},
		{[]string{"-mix", "forward_auth=1", "-forward-url", "http://x/auth", "-forward-host", "x", "-sessions", "1",
			"-login-start", "http://127.0.0.1:1/login", "-login-credentials", "a:b"}, keys, "signing in for session 1"},
		{[]string{"-mix", "oidc_login=1", "-login-start", "http://x/login"}, keys, "none given"},
		{[]string{"-mix", "oidc_login=1", "-login-start", "http://x/login", "-login-credentials", "nocolon"}, keys, "want USER:PASSWORD"},
		{[]string{"-mix", "oidc_login=1", "-login-start", "http://x/login", "-login-credentials", "@" + filepath.Join(dir, "none")}, keys, "no such file"},
		{[]string{"-mix", "mcp_call=1"}, keys, "needs -mcp-url and -mcp-tools"},
		{[]string{"-mix", "mcp_call=1", "-mcp-url", "http://x/mcp", "-mcp-tools", "[]"}, keys, "non-empty JSON list"},
		{[]string{"-mix", "mcp_call=1", "-mcp-url", "http://x/mcp", "-mcp-tools", `[{}]`}, keys, "a tool has no name"},
		{[]string{"-mix", "mcp_call=1", "-mcp-url", "http://x/mcp", "-mcp-tools", "@" + filepath.Join(dir, "none")}, keys, "no such file"},
		{[]string{"-mix", "mcp_call=1", "-mcp-url", "http://x/mcp", "-mcp-tools", `[{"name":"echo"}]`, "-mcp-protocol", "1999"}, keys, `-mcp-protocol "1999"`},
		{[]string{"-api", apiURL, "-cacert", filepath.Join(dir, "none")}, keys, "no such file"},
		{[]string{"-api", apiURL, "-arrival", "bursty"}, keys, "unknown arrival"},
		{[]string{"-api", apiURL, "-rate", "50", "-warmup", "0s", "-duration", "100ms", "-out", filepath.Join(dir, "no", "such", "dir.json")}, keys, "no such file"},
	} {
		code, _, stderr := runBench(t, tc.env, tc.args...)
		if code != 2 || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d, stderr %q, want 2 and %q", tc.args, code, stderr, tc.want)
		}
	}
	if code, _, stderr := runBench(t, nil, "-h"); code != 0 || !strings.Contains(stderr, "-mix") {
		t.Fatalf("-h: %d %q", code, stderr)
	}
}

// The session revision of MCP and a cancelled run.
func TestRunMCPSessionAndCancel(t *testing.T) {
	mcpURL := newMCP(t)
	tools := filepath.Join(t.TempDir(), "tools.json")
	os.WriteFile(tools, []byte(`[{"name":"echo","arguments":{"text":"a"}},{"name":"translate","arguments":{"text":"b","language":"fr"}}]`), 0o600)
	code, stdout, stderr := runBench(t, keys, "-mix", "mcp_call=1", "-mcp-url", mcpURL, "-mcp-tools", "@"+tools,
		"-mcp-protocol", "2025-06-18", "-rate", "200", "-warmup", "50ms", "-duration", "300ms", "-workers", "4")
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb strings.Builder
	if code := run(ctx, []string{"-mix", "mcp_call=1", "-mcp-url", mcpURL, "-mcp-tools", "@" + tools}, env(keys), &out, &errb); code != 2 ||
		!strings.Contains(errb.String(), "context canceled") {
		t.Fatalf("cancelled: %d %q", code, errb.String())
	}
}

// productServers loads one small dataset into the SpiceDB and OpenFGA
// fakes and returns their URLs and the keyspace flags for it.
func productServers(t *testing.T) (spiceURL, fgaURL string, flags []string) {
	t.Helper()
	g, err := datasets.Size(3_000, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	spice := httptest.NewServer(&productstest.SpiceDB{Engine: productstest.NewEngine(t, benchKey)})
	t.Cleanup(spice.Close)
	fga := httptest.NewServer(&productstest.OpenFGA{Engine: productstest.NewEngine(t, benchKey), ListObjectsMaxResults: 100})
	t.Cleanup(fga.Close)
	for _, tg := range []products.Target{products.NewSpiceDB(nil, spice.URL, benchKey), products.NewOpenFGA(nil, fga.URL, benchKey, "bench")} {
		if err := tg.Setup(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := tg.Loader().Load(ctx, g, 0, g.Count()); err != nil {
			t.Fatal(err)
		}
	}
	return spice.URL, fga.URL, []string{"-resource-prefix", "d", "-resources", fmt.Sprint(g.Docs),
		"-subject-prefix", "u", "-subjects", fmt.Sprint(g.Users), "-relation", "editor"}
}

// The four authorization operations against SpiceDB's and OpenFGA's APIs,
// keyed from their own variables, with no errors.
func TestRunProducts(t *testing.T) {
	spiceURL, fgaURL, flags := productServers(t)
	for _, tc := range []struct {
		target, url, env string
		extra            []string
	}{
		{"spicedb", spiceURL, "AUTHZBENCH_SPICEDB_KEY", nil},
		{"openfga", fgaURL, "AUTHZBENCH_OPENFGA_KEY", []string{"-openfga-store", "bench", "-consistency", "fully_consistent"}},
	} {
		args := append([]string{"-target", tc.target, "-api", tc.url, "-mix", "check=40,bulk_check=20,lookup=20,write=20",
			"-rate", "200", "-warmup", "100ms", "-duration", "500ms", "-workers", "8", "-bulk-items", "50"}, flags...)
		code, stdout, stderr := runBench(t, map[string]string{tc.env: benchKey}, append(args, tc.extra...)...)
		if code != 0 || !strings.Contains(stdout, "pass\n") || !strings.Contains(stdout, "bulk_check") {
			t.Fatalf("%s: exit %d\n%s\n%s", tc.target, code, stdout, stderr)
		}
	}
}

func TestRunProductsUsage(t *testing.T) {
	spiceURL, fgaURL, _ := productServers(t)
	spiceKey := map[string]string{"AUTHZBENCH_SPICEDB_KEY": benchKey}
	fgaKey := map[string]string{"AUTHZBENCH_OPENFGA_KEY": benchKey}
	for _, tc := range []struct {
		args []string
		env  map[string]string
		want string
	}{
		{[]string{"-target", "zanzibar"}, keys, `-target "zanzibar"`},
		{[]string{"-target", "spicedb", "-api", spiceURL}, keys, "AUTHZBENCH_SPICEDB_KEY"},
		{[]string{"-target", "openfga", "-api", fgaURL}, keys, "AUTHZBENCH_OPENFGA_KEY"},
		{[]string{"-target", "spicedb", "-api", spiceURL, "-consistency", "at_least_as_fresh"}, spiceKey, "no equivalent"},
		{[]string{"-target", "openfga", "-api", fgaURL, "-openfga-store", "missing"}, fgaKey, `no store named "missing"`},
		{[]string{"-target", "openfga", "-api", fgaURL, "-openfga-store", "bench", "-mix", "bulk_check=1", "-bulk-items", "51"}, fgaKey, "want 1 to 50 for openfga"},
		{[]string{"-target", "spicedb", "-api", spiceURL, "-mix", "check=1,lookup=1", "-resources", "0"}, spiceKey, "counts must be positive"},
	} {
		code, _, stderr := runBench(t, tc.env, tc.args...)
		if code != 2 || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d, stderr %q, want 2 and %q", tc.args, code, stderr, tc.want)
		}
	}
}
