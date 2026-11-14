package runcmd

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/cmd/authz/internal/part"
	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/platform/httpserver"
)

const engineSchema = `definition user {}

definition group {
  relation member: user
}

definition doc {
  relation viewer: user | group#member
  permission view = viewer
}
`

// threeParts is the configuration of serve, gateway and mcp in one
// process, all on 127.0.0.1:0.
func threeParts(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	up := httptest.NewServer(http.NotFoundHandler()) // mcp asks its upstream only when an agent calls
	t.Cleanup(up.Close)
	gw := `{"public_url": "https://auth.example.com",
	  "providers": [{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "CORP_SECRET"}],
	  "apps": [{"id": "app", "hosts": ["app.example.com"], "providers": ["corp"], "allow": {"any_user": true}}]}`
	mcp := fmt.Sprintf(`{"tokens":{"issuer":"authz","audience":"engine-test"},
	  "agents":[{"id":"bot","owner":"alice","scopes":["s"],"token_sha256":%q}],
	  "upstreams":[{"name":"up","url":"%s/mcp"}]}`, fmt.Sprintf("%x", sha256.Sum256([]byte("tgk_engine_test_agent_0123456789abcdef"))), up.URL)
	pol := `{"version":1,"rules":[{"id":"r","effect":"allow","scopes":["s"],"upstreams":["up"],"tools":["echo"]}]}`
	return map[string]string{
		"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": apiKey, "GRANTD_TOKEN_KEY": strings.Repeat("ab", 32),
		"WICKET_CONFIG": write("wicket.json", gw), "WICKET_ADDR": "127.0.0.1:0", "WICKET_ADMIN_ADDR": "127.0.0.1:0",
		"WICKET_COOKIE_KEYS": strings.Repeat("cd", 32), "CORP_SECRET": "s",
		"AUTHZ_MCP_ADDR": "127.0.0.1:0", "AUTHZ_MCP_ADMIN_ADDR": "127.0.0.1:0",
		"AUTHZ_MCP_ADMIN_TOKEN": "engine-test-mcp-admin-token-0123456789",
		"AUTHZ_MCP_CONFIG":      write("mcp.json", mcp), "AUTHZ_MCP_POLICY": write("policy.json", pol),
		"AUTHZ_MCP_AUDIT_LOG": filepath.Join(dir, "mcp-audit.jsonl"), "AUTHZ_MCP_AUDIT_KEY": strings.Repeat("ef", 32),
		"AUTHZ_MCP_POLICY_POLL": "0",
	}
}

// hostRecorder wraps the starters so a test sees the Host each part was
// given. Tests using it do not run in parallel.
type hostRecorder struct {
	mu    sync.Mutex
	hosts map[string]part.Host
}

func recordHosts(t *testing.T) *hostRecorder {
	t.Helper()
	r := &hostRecorder{hosts: map[string]part.Host{}}
	saved := starters
	wrapped := map[string]starter{}
	for name, s := range saved {
		wrapped[name] = func(ctx context.Context, h part.Host, getenv func(string) string, path string, logOut io.Writer, hup <-chan os.Signal) error {
			r.mu.Lock()
			r.hosts[name] = h
			r.mu.Unlock()
			return s(ctx, h, getenv, path, logOut, hup)
		}
	}
	starters = wrapped
	t.Cleanup(func() { starters = saved })
	return r
}

func (r *hostRecorder) host(t *testing.T, name string) part.Host {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.hosts[name]
	if !ok {
		t.Fatalf("part %s was not started", name)
	}
	return h
}

// api calls serve's HTTP API and decodes the JSON answer.
func api(t *testing.T, base, method, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, base+path, strings.NewReader(string(b)))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func metricValue(t *testing.T, base, name string) float64 {
	t.Helper()
	req, _ := http.NewRequest("GET", base+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	m := regexp.MustCompile(`(?m)^` + name + `(?:\{\})? (\S+)$`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("/metrics has no %s:\n%s", name, b)
	}
	v, err := strconv.ParseFloat(string(m[1]), 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestOneEngineThreePaths starts serve, gateway and mcp in one process and
// checks one relationship from all three: over serve's HTTP API, and in
// process through the engine the gateway's and mcp's Hosts hand out. Each
// path takes the token another returned, answers at the same revision and
// returns the same token, a write through one is seen by the others with
// its token, and the in-process checks are counted in the one registry
// every /metrics shows.
func TestOneEngineThreePaths(t *testing.T) {
	rec := recordHosts(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readyc := make(chan *httpserver.Shared, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, Parts, httpserver.Options{}, env(threeParts(t)), "", io.Discard, nil, func(s *httpserver.Shared) { readyc <- s })
	}()
	var shared *httpserver.Shared
	select {
	case shared = <-readyc:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(15 * time.Second):
		t.Fatal("did not start")
	}
	if n := len(shared.Addrs()); n != 5 {
		t.Fatalf("%d listeners, want serve's, the gateway's two and mcp's two: %v", n, shared.Addrs())
	}
	base := "http://" + shared.Addrs()[0] // serve joins first

	wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
	defer wcancel()
	viaGateway, err := rec.host(t, "gateway").Engine(wctx)
	if err != nil {
		t.Fatal("gateway:", err)
	}
	viaMCP, err := rec.host(t, "mcp").Engine(wctx)
	if err != nil {
		t.Fatal("mcp:", err)
	}
	viaServe, err := rec.host(t, "serve").Engine(wctx)
	if err != nil {
		t.Fatal("serve:", err)
	}
	if viaGateway != viaMCP || viaMCP != viaServe {
		t.Fatal("the parts were handed different engines")
	}
	if _, ok := viaGateway.(*engine.Local); !ok {
		t.Fatalf("the in-process engine is a %T, want serve's *engine.Local", viaGateway)
	}

	if code, out := api(t, base, "PUT", "/v1/schema", map[string]string{"schema": engineSchema}); code != 200 {
		t.Fatalf("schema: %d %v", code, out)
	}
	code, out := api(t, base, "POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{
		{"op": "touch", "relationship": "group:eng#member@user:alice"},
		{"op": "touch", "relationship": "doc:plan#viewer@group:eng#member"},
	}})
	written, _ := out["written_at"].(string)
	if code != 200 || written == "" {
		t.Fatalf("write: %d %v", code, out)
	}

	alice := store.Subject{Type: "user", ID: "alice"}
	httpCheck := func(subject string, c engine.Consistency) (bool, string) {
		t.Helper()
		code, out := api(t, base, "POST", "/v1/check", map[string]any{"resource": "doc:plan", "permission": "view",
			"subject": subject, "consistency": c})
		allowed, ok1 := out["allowed"].(bool)
		at, ok2 := out["checked_at"].(string)
		if code != 200 || !ok1 || !ok2 {
			t.Fatalf("check over HTTP: %d %v", code, out)
		}
		return allowed, at
	}
	inProcess := func(e engine.Engine, subj store.Subject, c engine.Consistency) engine.CheckResult {
		t.Helper()
		res, err := e.Check(ctx, engine.CheckRequest{ResourceType: "doc", ResourceID: "plan", Permission: "view",
			Subject: subj, Consistency: c})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	checksBefore := metricValue(t, base, "grantd_check_duration_seconds_count")
	// One token, three paths, the same answer at the same snapshot.
	for _, mode := range []engine.Mode{engine.AtLeastAsFresh, engine.AtExactSnapshot} {
		c := engine.Consistency{Mode: mode, Token: written}
		allowed, at := httpCheck("user:alice", c)
		gw := inProcess(viaGateway, alice, c)
		mc := inProcess(viaMCP, alice, c)
		if !allowed || !gw.Allowed || !mc.Allowed {
			t.Fatalf("%s: http %v, gateway %v, mcp %v; want allowed on every path", mode, allowed, gw.Allowed, mc.Allowed)
		}
		if gw.At.Token != at || mc.At.Token != at {
			t.Fatalf("%s: tokens differ: http %s, gateway %s, mcp %s", mode, at, gw.At.Token, mc.At.Token)
		}
		if mode == engine.AtExactSnapshot && at != written {
			t.Fatalf("at_exact_snapshot answered at %s, not the write's %s", at, written)
		}
	}
	if got := metricValue(t, base, "grantd_check_duration_seconds_count") - checksBefore; got != 6 {
		t.Fatalf("serve's /metrics counted %v checks, want the 6 of all three paths", got)
	}

	// A write in process, through mcp's engine, is seen over HTTP and
	// through the gateway with its token, and the old token still reads
	// the old snapshot on every path.
	w, err := viaMCP.Write(ctx, engine.WriteRequest{Updates: []store.Update{{Op: store.OpDelete,
		Relationship: store.Relationship{ResourceType: "group", ResourceID: "eng", Relation: "member", SubjectType: "user", SubjectID: "alice"}}}})
	if err != nil {
		t.Fatal(err)
	}
	after := engine.Consistency{Mode: engine.AtLeastAsFresh, Token: w.At.Token}
	if allowed, _ := httpCheck("user:alice", after); allowed {
		t.Fatal("HTTP did not see mcp's in-process delete with its token")
	}
	if inProcess(viaGateway, alice, after).Allowed {
		t.Fatal("the gateway did not see mcp's in-process delete with its token")
	}
	before := engine.Consistency{Mode: engine.AtExactSnapshot, Token: written}
	if allowed, _ := httpCheck("user:alice", before); !allowed || !inProcess(viaGateway, alice, before).Allowed {
		t.Fatal("the write's own snapshot changed")
	}

	// And the other way: a write over HTTP, read in process with its token.
	code, out = api(t, base, "POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{
		{"op": "touch", "relationship": "doc:plan#viewer@user:bob"}}})
	tok, _ := out["written_at"].(string)
	if code != 200 || tok == "" {
		t.Fatalf("write: %d %v", code, out)
	}
	bob := store.Subject{Type: "user", ID: "bob"}
	for name, e := range map[string]engine.Engine{"gateway": viaGateway, "mcp": viaMCP} {
		if !inProcess(e, bob, engine.Consistency{Mode: engine.AtLeastAsFresh, Token: tok}).Allowed {
			t.Fatalf("%s did not see the HTTP write with its token", name)
		}
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Once serve has returned, the engine is withdrawn.
	if _, err := rec.host(t, "gateway").Engine(context.Background()); !errors.Is(err, part.ErrEngineStopped) {
		t.Fatalf("after shutdown: %v, want ErrEngineStopped", err)
	}
}

// Without a serve part there is no engine to ask, and the parts are told
// so at once; a serve part that cannot start leaves the others an error,
// not a wait.
func TestNoEngineWithoutServe(t *testing.T) {
	rec := recordHosts(t)
	vars := threeParts(t)
	ctx, cancel := context.WithCancel(context.Background())
	readyc := make(chan *httpserver.Shared, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"gateway", "mcp"}, httpserver.Options{}, env(vars), "", io.Discard, nil, func(s *httpserver.Shared) { readyc <- s })
	}()
	select {
	case <-readyc:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(15 * time.Second):
		t.Fatal("did not start")
	}
	for _, p := range []string{"gateway", "mcp"} {
		if e, err := rec.host(t, p).Engine(ctx); e != nil || !errors.Is(err, part.ErrNoEngine) {
			t.Fatalf("%s: %v %v, want ErrNoEngine", p, e, err)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	vars["GRANTD_TOKEN_KEY"] = "short"
	err := run(context.Background(), Parts, httpserver.Options{}, env(vars), "", io.Discard, nil, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "serve: ") {
		t.Fatalf("run: %v", err)
	}
	for _, p := range []string{"gateway", "mcp"} {
		_, err := rec.host(t, p).Engine(context.Background())
		if !errors.Is(err, part.ErrEngineStopped) || !strings.Contains(err.Error(), "GRANTD_TOKEN_KEY") {
			t.Fatalf("%s: %v, want ErrEngineStopped with serve's error", p, err)
		}
	}
}
