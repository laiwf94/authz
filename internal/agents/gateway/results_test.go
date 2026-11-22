package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/agents/mcp"
	"github.com/laiwf94/authz/internal/platform/audit"
)

// ghToken is a GitHub token shape the built-in github_token pattern finds.
var ghToken = "ghp_" + strings.Repeat("A1b2", 9)

// resultServer is an upstream whose tools return fixed results: text with a
// token, structured content with an internal marker, an image whose base64
// data happens to hold the token, a plain text, and an error whose message
// holds the token.
func resultServer(t *testing.T) *httptest.Server {
	t.Helper()
	results := map[string]string{
		"token_text": `{"content":[{"type":"text","text":"your token is ` + ghToken + `"}]}`,
		"structured": `{"content":[{"type":"text","text":"2 rows"}],"structuredContent":{"rows":[{"id":1},{"note":"see INTERNAL-ONLY-42"}]}}`,
		"in_key":     `{"content":[{"type":"text","text":"ok"}],"structuredContent":{"INTERNAL-ONLY-7":true}}`,
		"image":      `{"content":[{"type":"image","mimeType":"image/png","data":"` + ghToken + `"}]}`,
		"plain":      `{"content":[{"type":"text","text":"nothing to see AKIAIOSFODNN7EXAMPLE"}]}`,
		"both":       `{"content":[{"type":"text","text":"INTERNAL-ONLY-1"},{"type":"text","text":"` + ghToken + `"}],"isError":true}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &m)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case m.Method == "tools/list":
			var tools []string
			for _, n := range []string{"token_text", "structured", "in_key", "image", "plain", "both", "fail"} {
				tools = append(tools, fmt.Sprintf(`{"name":%q,"inputSchema":{"type":"object"}}`, n))
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[%s]}}`, m.ID, strings.Join(tools, ","))
		case m.Params.Name == "fail":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"login with %s failed"}}`, m.ID, ghToken)
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, m.ID, results[m.Params.Name])
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const resultPolicy = `{"version":1,"rules":[
 {"id":"results","effect":"allow","agents":["*"],"upstreams":["res"],"tools":["*"],
  "output":{"redact":["aws_access_key_id"],"deny":["github_token"],"deny_patterns":["INTERNAL-ONLY-[0-9]+"]}}]}`

func resultEnv(t *testing.T) *env {
	srv := resultServer(t)
	e := newEnv(t, func(c *Config) {
		c.Upstreams = append(c.Upstreams, UpstreamConfig{Name: "res", URL: srv.URL, TimeoutMS: 2000,
			MaxResponseBytes: 1 << 16, MaxConcurrency: 4, ToolsTTLSeconds: 30})
		c.Limits.ToolRPS = 0
	})
	writePolicy(t, e, resultPolicy)
	return e
}

func TestResultRulesRefuseModern(t *testing.T) {
	e := resultEnv(t)
	cases := []struct {
		tool, pattern string
	}{
		{"res.token_text", "github_token"},
		{"res.structured", "deny_patterns[0]"},
		{"res.in_key", "deny_patterns[0]"},
		// Both patterns match; the one the rule lists first is reported.
		{"res.both", "github_token"},
	}
	for _, c := range cases {
		r := e.call(bobKey, c.tool, nil)
		if r.status != http.StatusOK || r.errCode() != mcp.CodeResultRefused {
			t.Errorf("%s: %d %s", c.tool, r.status, r.raw)
			continue
		}
		d := r.errData()
		if d["rule_id"] != "results" || d["pattern"] != c.pattern {
			t.Errorf("%s: data %v", c.tool, d)
		}
		if strings.Contains(r.raw, ghToken) || strings.Contains(r.raw, "INTERNAL-ONLY-") {
			t.Errorf("%s: refusal leaks the result: %s", c.tool, r.raw)
		}
	}
	// Base64 payloads are not scanned, as they are not redacted.
	if r := e.call(bobKey, "res.image", nil); r.errCode() != 0 || !strings.Contains(r.raw, ghToken) {
		t.Errorf("image: %s", r.raw)
	}
	// With no deny match the redaction patterns still apply.
	if r := e.call(bobKey, "res.plain", nil); r.text() != "nothing to see [REDACTED]" {
		t.Errorf("plain: %s", r.raw)
	}
	// An upstream error message that matches is withheld, not redacted.
	r := e.call(bobKey, "res.fail", nil)
	if r.status != http.StatusBadGateway || r.errCode() != mcp.CodeUpstreamError || strings.Contains(r.raw, "ghp_") ||
		r.errData()["pattern"] != "github_token" || r.errData()["upstream_code"] != float64(-32603) {
		t.Errorf("fail: %d %s", r.status, r.raw)
	}

	completed := map[string]audit.ToolCall{}
	for _, rec := range e.auditRecords() {
		var tc audit.ToolCall
		if rec.Event != audit.EventToolCall || json.Unmarshal(rec.Data, &tc) != nil || tc.Stage != "completed" {
			continue
		}
		completed[tc.Tool] = tc
	}
	want := map[string][3]string{ // outcome, result, result_pattern
		"token_text": {"result_refused", "refuse", "github_token"},
		"structured": {"result_refused", "refuse", "deny_patterns[0]"},
		"both":       {"result_refused", "refuse", "github_token"},
		"image":      {"ok", "allow", ""},
		"plain":      {"ok", "redact", ""},
		"fail":       {"upstream_error", "refuse", "github_token"},
	}
	for tool, w := range want {
		tc, ok := completed[tool]
		if !ok || tc.Outcome != w[0] || tc.Result != w[1] || tc.ResultPattern != w[2] {
			t.Errorf("%s: completed record %+v, want %v", tool, tc, w)
		}
	}
	if tc := completed["token_text"]; tc.ResponseBytes == 0 || tc.Redactions != 0 {
		t.Errorf("a refused result records the size received and no redactions: %+v", tc)
	}
	data, err := os.ReadFile(e.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), ghToken) {
		t.Fatal("the audit log holds the refused token")
	}
	f, err := os.Open(e.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := audit.VerifyWith(f, audit.Default()); err != nil {
		t.Fatalf("result records do not match the schemas: %v", err)
	}
	m := e.admin("GET", "/metrics", "").raw
	if !strings.Contains(m, `toolgate_tool_calls_total{upstream="res",tool="token_text",outcome="result_refused"} 1`) {
		t.Errorf("refusals are not counted by outcome:\n%s", m)
	}
}

func TestResultRulesRefuseLegacy(t *testing.T) {
	e := resultEnv(t)
	init := e.post(e.gwURL, bobKey, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"old","version":"1"}}}`), nil)
	sid := init.header.Get(mcp.HeaderSessionID)
	if sid == "" {
		t.Fatalf("no session: %s", init.raw)
	}
	h := map[string]string{mcp.HeaderSessionID: sid, mcp.HeaderProtocolVersion: mcp.Version250618}
	e.post(e.gwURL, bobKey, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), h)
	r := e.post(e.gwURL, bobKey, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"res.structured","arguments":{}}}`), h)
	if r.status != http.StatusOK || r.errCode() != mcp.CodeResultRefused || r.errData()["pattern"] != "deny_patterns[0]" ||
		strings.Contains(r.raw, "INTERNAL-ONLY-") {
		t.Fatalf("legacy refusal: %d %s", r.status, r.raw)
	}
	// The upstream error keeps its code and, in a 2025 session, gets 200.
	r = e.post(e.gwURL, bobKey, []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"res.fail","arguments":{}}}`), h)
	if r.status != http.StatusOK || r.errCode() != mcp.CodeUpstreamError || strings.Contains(r.raw, "ghp_") {
		t.Fatalf("legacy upstream error: %d %s", r.status, r.raw)
	}
	r = e.post(e.gwURL, bobKey, []byte(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"res.plain","arguments":{}}}`), h)
	if r.errCode() != 0 || r.text() != "nothing to see [REDACTED]" {
		t.Fatalf("legacy plain: %s", r.raw)
	}
}

// TestResultRulesCountAgainstQuota: the upstream ran a call whose result was
// refused, so it counts against the daily quota like any other.
func TestResultRulesCountAgainstQuota(t *testing.T) {
	srv := resultServer(t)
	e := newEnv(t, func(c *Config) {
		c.Upstreams = append(c.Upstreams, UpstreamConfig{Name: "res", URL: srv.URL, TimeoutMS: 2000,
			MaxResponseBytes: 1 << 16, MaxConcurrency: 4, ToolsTTLSeconds: 30})
	})
	writePolicy(t, e, strings.Replace(resultPolicy, `"agents":["*"]`, `"agents":["quota-bot"]`, 1))
	for i := 0; i < 2; i++ {
		if r := e.call(quotaKey, "res.token_text", nil); r.errCode() != mcp.CodeResultRefused {
			t.Fatalf("call %d: %s", i, r.raw)
		}
	}
	if r := e.call(quotaKey, "res.plain", nil); r.errCode() != mcp.CodeQuotaExceeded {
		t.Fatalf("refused results were refunded: %s", r.raw)
	}
}
