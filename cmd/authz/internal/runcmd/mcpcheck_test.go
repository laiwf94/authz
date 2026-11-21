package runcmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/fakeserver"
	"github.com/laiwf94/authz/internal/agents/mcp"
	"github.com/laiwf94/authz/internal/platform/httpserver"
)

const mcpCheckSchema = `definition user {}

definition project {
  relation editor: user
  permission edit = editor
}
`

// TestMCPToolRulesAskServesEngine runs serve and mcp in one process with a
// tool rule that asks the engine: an agent may echo a project's name only
// while the user behind it can edit the project. Relationships written over
// serve's HTTP API decide the agent's next call, with no network hop
// between mcp and the engine.
func TestMCPToolRulesAskServesEngine(t *testing.T) {
	vars := threeParts(t)
	dir := t.TempDir()
	fake, err := fakeserver.New(fakeserver.Config{Sandbox: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })
	up := httptest.NewServer(fake)
	t.Cleanup(up.Close)
	const agentKey = "tgk_engine_test_agent_0123456789abcdef"
	cfg := fmt.Sprintf(`{"tokens":{"issuer":"authz","audience":"engine-test"},
	  "agents":[{"id":"bot","owner":"alice","token_sha256":"%x"}],
	  "upstreams":[{"name":"up","url":"%s/mcp"}]}`, sha256.Sum256([]byte(agentKey)), up.URL)
	pol := `{"version":1,"rules":[{"id":"edit-projects","effect":"allow","agents":["*"],"upstreams":["up"],"tools":["echo"],
	  "check":{"resource":"project:{args.text}","permission":"edit"}}]}`
	for name, src := range map[string]string{"AUTHZ_MCP_CONFIG": cfg, "AUTHZ_MCP_POLICY": pol} {
		p := filepath.Join(dir, name+".json")
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		vars[name] = p
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readyc := make(chan *httpserver.Shared, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"serve", "mcp"}, httpserver.Options{}, env(vars), "", io.Discard, nil, func(s *httpserver.Shared) { readyc <- s })
	}()
	var shared *httpserver.Shared
	select {
	case shared = <-readyc:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(15 * time.Second):
		t.Fatal("did not start")
	}
	addrs := shared.Addrs()
	if len(addrs) != 3 {
		t.Fatalf("listeners %v, want serve's and mcp's two", addrs)
	}
	base, gateway := "http://"+addrs[0], "http://"+addrs[1]+"/mcp"

	call := func(text string) map[string]any {
		t.Helper()
		params := map[string]any{"name": "up.echo", "arguments": map[string]any{"text": text},
			"_meta": map[string]any{mcp.MetaProtocolVersion: mcp.VersionModern, mcp.MetaClientCapabilities: map[string]any{},
				mcp.MetaClientInfo: map[string]any{"name": "runcmd-test", "version": "1"}}}
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
		req, _ := http.NewRequest("POST", gateway, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+agentKey)
		req.Header.Set(mcp.HeaderProtocolVersion, mcp.VersionModern)
		req.Header.Set(mcp.HeaderMethod, "tools/call")
		req.Header.Set(mcp.HeaderName, "up.echo")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("%d: %v", resp.StatusCode, err)
		}
		return out
	}
	code := func(out map[string]any) int {
		e, _ := out["error"].(map[string]any)
		c, _ := e["code"].(float64)
		return int(c)
	}

	if c, out := api(t, base, "PUT", "/v1/schema", map[string]string{"schema": mcpCheckSchema}); c != 200 {
		t.Fatalf("schema: %d %v", c, out)
	}
	if out := call("p1"); code(out) != mcp.CodePolicyDenied {
		t.Fatalf("before the relationship: %v", out)
	}
	if c, out := api(t, base, "POST", "/v1/relationships/write", map[string]any{"updates": []map[string]string{
		{"op": "touch", "relationship": "project:p1#editor@user:alice"}}}); c != 200 {
		t.Fatalf("write: %d %v", c, out)
	}
	// minimize_latency shares a snapshot for the engine's quantum, so the
	// write is seen within it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		out := call("p1")
		if res, ok := out["result"].(map[string]any); ok {
			if s := fmt.Sprint(res["content"]); !strings.Contains(s, "p1") {
				t.Fatalf("result %v", res)
			}
			break
		}
		if code(out) != mcp.CodePolicyDenied || time.Now().After(deadline) {
			t.Fatalf("after the write: %v", out)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if out := call("p2"); code(out) != mcp.CodePolicyDenied {
		t.Fatalf("another project: %v", out)
	}
	if v := metricValue(t, base, `toolgate_relationship_checks_total\{result="allowed"\}`); v != 1 {
		t.Errorf("serve's /metrics shows %v allowed tool rule checks, want 1", v)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
