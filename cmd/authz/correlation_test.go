package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/fakeserver"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/logging"
)

// A traceparent a caller (a proxy, an agent framework, an app) sends.
const (
	corrTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	corrTP    = "00-" + corrTrace + "-00f067aa0ba902b7-01"
)

// lineLog keeps every JSON log line a child writes, for looking up request
// lines after the fact.
type lineLog struct {
	mu    sync.Mutex
	lines []map[string]any
}

func collect(ch <-chan map[string]any) *lineLog {
	l := &lineLog{}
	go func() {
		for m := range ch {
			l.mu.Lock()
			l.lines = append(l.lines, m)
			l.mu.Unlock()
		}
	}()
	return l
}

// requestLine waits for the request line whose request_id is rid and
// returns its correlation_id.
func (l *lineLog) requestLine(t *testing.T, rid string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		for _, m := range l.lines {
			if m["msg"] == "request" && m["request_id"] == rid {
				l.mu.Unlock()
				c, _ := m["correlation_id"].(string)
				return c
			}
		}
		l.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no request line with request_id %q", rid)
	return ""
}

// auditCorrelations verifies the chain at path and returns the correlation
// ID of each record of the event, in order.
func auditCorrelations(t *testing.T, path, event string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(bytes.NewReader(raw)); err != nil {
		t.Fatalf("%s does not verify: %v", path, err)
	}
	var out []string
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var r audit.Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		if r.Event == event {
			out = append(out, r.CorrelationID)
		}
	}
	return out
}

// send makes one request and returns the response's request ID.
func send(t *testing.T, method, url, body, traceparent string, hdr map[string]string) string {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if traceparent != "" {
		req.Header.Set("Traceparent", traceparent)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("%s %s: %d", method, url, resp.StatusCode)
	}
	return resp.Header.Get("X-Request-Id")
}

// TestMainCorrelationAcrossSubcommands runs serve, gateway and mcp as the
// one binary does and sends each a request with a traceparent and one
// without. Each request's correlation ID, the traceparent's trace ID or a
// generated trace ID, is on its request log line and in the audit record it
// writes, and mcp carries it to its upstream as a traceparent.
func TestMainCorrelationAcrossSubcommands(t *testing.T) {
	dir := t.TempDir()

	t.Run("serve", func(t *testing.T) {
		path := filepath.Join(dir, "serve-audit.log")
		const key = "main-test-key-0123456"
		cmd, ch := startChild(t, "authz", "serve", false, "GRANTD_ADDR=127.0.0.1:0", "GRANTD_API_KEYS="+key,
			"GRANTD_DATA_DIR=", "GRANTD_TOKEN_KEY=", "GRANTD_AUDIT_LOG="+path)
		logs := collect(ch)
		addr := waitAddr(t, logs)
		hdr := map[string]string{"Authorization": "Bearer " + key, "Content-Type": "application/json"}
		r1 := send(t, "PUT", "http://"+addr+"/v1/schema", `{"schema":"definition user {}"}`, corrTP, hdr)
		r2 := send(t, "PUT", "http://"+addr+"/v1/schema", `{"schema":"definition user {}\ndefinition doc {}"}`, "", hdr)
		stop(t, cmd)
		checkCorrelation(t, logs, []string{r1, r2}, auditCorrelations(t, path, audit.EventSchemaWritten))
	})

	t.Run("gateway", func(t *testing.T) {
		path := filepath.Join(dir, "gateway-audit.log")
		cmd, ch := startChild(t, "authz", "gateway", false, "WICKET_CONFIG="+writeGatewayConfig(t, dir),
			"WICKET_COOKIE_KEYS="+gatewayCookieKey, "WICKET_ADDR=127.0.0.1:0", "WICKET_ADMIN_ADDR=127.0.0.1:0",
			"WICKET_SESSION_FILE="+filepath.Join(dir, "s.log"), "WICKET_SIGNING_KEYS=", "WICKET_ADMIN_TOKEN=",
			"CORP_SECRET=s", "WICKET_AUDIT_LOG="+path)
		logs := collect(ch)
		admin := waitAdminAddr(t, logs)
		r1 := send(t, "POST", "http://"+admin+"/admin/reload", "", corrTP, nil)
		r2 := send(t, "POST", "http://"+admin+"/admin/reload", "", "", nil)
		stop(t, cmd)
		// The first config_loaded is the start, outside any request.
		loads := auditCorrelations(t, path, audit.EventConfigLoaded)
		if len(loads) != 3 || loads[0] != "" {
			t.Fatalf("config_loaded correlation IDs %q, want the start's empty and two reloads", loads)
		}
		checkCorrelation(t, logs, []string{r1, r2}, loads[1:])
	})

	t.Run("mcp", func(t *testing.T) {
		box := filepath.Join(dir, "box")
		os.MkdirAll(box, 0o700)
		os.WriteFile(filepath.Join(box, "a.txt"), []byte("hello from the box"), 0o600)
		fs, err := fakeserver.New(fakeserver.Config{Sandbox: box})
		if err != nil {
			t.Fatal(err)
		}
		// The upstream remembers the traceparent of each tools/call.
		var mu sync.Mutex
		var upstream []string
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(peek(r), `"method":"tools/call"`) {
				mu.Lock()
				upstream = append(upstream, r.Header.Get("Traceparent"))
				mu.Unlock()
			}
			fs.ServeHTTP(w, r)
		}))
		defer up.Close()

		const agentKey = "tgk_main_test_0123456789abcdefghijklmnop"
		cfg := fmt.Sprintf(`{"tokens":{"issuer":"authz","audience":"main-test"},
		  "agents":[{"id":"bot","owner":"alice","scopes":["files:read"],"token_sha256":%q}],
		  "upstreams":[{"name":"fake","url":"%s/mcp"}]}`, sha256Hex(agentKey), up.URL)
		pol := `{"version":1,"rules":[{"id":"files","effect":"allow","scopes":["files:read"],"upstreams":["fake"],"tools":["read_file"]}]}`
		os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600)
		os.WriteFile(filepath.Join(dir, "policy.json"), []byte(pol), 0o600)
		path := filepath.Join(dir, "mcp-audit.jsonl")
		cmd, ch := startChild(t, "authz", "mcp serve", false, "AUTHZ_MCP_ADDR=127.0.0.1:0", "AUTHZ_MCP_ADMIN_ADDR=127.0.0.1:0",
			"AUTHZ_MCP_ADMIN_TOKEN=admin-0123456789abcdefghijklmnopqrstuv",
			"AUTHZ_MCP_CONFIG="+filepath.Join(dir, "config.json"), "AUTHZ_MCP_POLICY="+filepath.Join(dir, "policy.json"),
			"AUTHZ_MCP_AUDIT_LOG="+path, "AUTHZ_MCP_AUDIT_KEY="+strings.Repeat("ab", 32), "AUTHZ_MCP_POLICY_POLL=0")
		logs := collect(ch)
		addr := waitAddr(t, logs)
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake.read_file","arguments":{"path":"a.txt"},` +
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
		hdr := map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
			"Authorization": "Bearer " + agentKey, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "fake.read_file"}
		r1 := send(t, "POST", "http://"+addr+"/mcp", body, corrTP, hdr)
		r2 := send(t, "POST", "http://"+addr+"/mcp", body, "", hdr)
		stop(t, cmd)
		// Each call writes two tool_call records, its decision and its
		// outcome, under the same ID.
		calls := auditCorrelations(t, path, "tool_call")
		if len(calls) != 4 || calls[0] != calls[1] || calls[2] != calls[3] {
			t.Fatalf("tool_call correlation IDs %q, want two per call", calls)
		}
		corrs := checkCorrelation(t, logs, []string{r1, r2}, []string{calls[0], calls[2]})

		// Each call reached the upstream once, with its correlation ID as
		// the trace ID under a parent ID of the gateway's own.
		mu.Lock()
		defer mu.Unlock()
		if len(upstream) != 2 {
			t.Fatalf("upstream saw %d tools/call requests, want 2: %q", len(upstream), upstream)
		}
		for i, tp := range upstream {
			if id, ok := logging.ParseTraceparent(tp); !ok || id != corrs[i] || tp == corrTP {
				t.Errorf("call %d: upstream traceparent %q, want trace ID %s", i+1, tp, corrs[i])
			}
		}
	})
}

// checkCorrelation requires one audit record per request, the first under
// corrTrace and the second under a generated trace ID, each the same as its
// request line's correlation_id. It returns the two IDs.
func checkCorrelation(t *testing.T, logs *lineLog, rids, recs []string) []string {
	t.Helper()
	if len(recs) != len(rids) {
		t.Fatalf("%d audit records for %d requests: %q", len(recs), len(rids), recs)
	}
	got := make([]string, len(rids))
	for i, rid := range rids {
		got[i] = logs.requestLine(t, rid)
		if got[i] != recs[i] {
			t.Errorf("request %s: log line correlation ID %q, audit record %q", rid, got[i], recs[i])
		}
	}
	if got[0] != corrTrace {
		t.Errorf("traced request: correlation ID %q, want %s", got[0], corrTrace)
	}
	if logging.Traceparent(got[1]) == "" || got[1] == corrTrace {
		t.Errorf("untraced request: correlation ID %q is not a new trace ID", got[1])
	}
	return got
}

// peek returns r's body and leaves it readable.
func peek(r *http.Request) string {
	var b bytes.Buffer
	b.ReadFrom(r.Body)
	r.Body.Close()
	r.Body = readCloser{bytes.NewReader(b.Bytes())}
	return b.String()
}

type readCloser struct{ *bytes.Reader }

func (readCloser) Close() error { return nil }

func waitAddr(t *testing.T, l *lineLog) string { return waitField(t, l, "listening", "addr") }

func waitAdminAddr(t *testing.T, l *lineLog) string {
	return waitField(t, l, "listening", "admin_addr")
}

// waitField waits for the line with message msg and returns its field key.
func waitField(t *testing.T, l *lineLog, msg, key string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		for _, m := range l.lines {
			if m["msg"] == msg {
				if v, ok := m[key].(string); ok {
					l.mu.Unlock()
					return v
				}
			}
		}
		l.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %q line with %s", msg, key)
	return ""
}

// stop ends a child with SIGTERM, which drains it, and wants exit 0.
func stop(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitExit(t, cmd); err != nil {
		t.Fatalf("exited with %v, want a clean exit 0", err)
	}
}
