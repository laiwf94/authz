package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/fakeserver"
)

// Approvals across SIGKILL: `authz mcp serve` keeps approval requests,
// decisions and grant uses in a wal stream in its state directory. The
// gateway is killed between asking and deciding, between deciding and
// using, and right after using, and every restart must agree with what was
// acknowledged before the kill:
//
//   - a pending request is still pending under the same id;
//   - an approved grant lets the call through exactly once;
//   - a used grant is never usable again;
//   - a denial is still a denial.
//
// Then rounds of identical concurrent calls race for one grant while the
// gateway is killed at a random moment: the upstream may see the call at
// most once, before or after the restart.
func TestMCPApprovalSurvivesSIGKILL(t *testing.T) {
	const (
		agentKey   = "tgk_approval_test_0123456789abcdefghijklm"
		upToken    = "up-approval-0123456789"
		adminToken = "admin-0123456789abcdefghijklmnopqrstuv"
		races      = 6
		racers     = 6
	)
	dir := t.TempDir()
	box, state := filepath.Join(dir, "box"), filepath.Join(dir, "state")
	for _, d := range []string{box, state} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fake, err := fakeserver.New(fakeserver.Config{Sandbox: box, Token: upToken})
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	var seenMu sync.Mutex
	seen := map[string]int{} // echo text -> calls the upstream received
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var msg struct {
			Method string
			Params struct{ Arguments struct{ Text string } }
		}
		if json.Unmarshal(body, &msg) == nil && msg.Method == "tools/call" {
			seenMu.Lock()
			seen[msg.Params.Arguments.Text]++
			seenMu.Unlock()
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		fake.ServeHTTP(w, r)
	}))
	defer up.Close()
	upstreamSaw := func(text string) int {
		seenMu.Lock()
		defer seenMu.Unlock()
		return seen[text]
	}

	cfg := fmt.Sprintf(`{"tokens":{"issuer":"authz","audience":"approval-test"},
	  "agents":[{"id":"bot","owner":"alice","scopes":["s"],"token_sha256":%q}],
	  "upstreams":[{"name":"up","url":"%s/mcp","credential_env":"UP_TOKEN","max_concurrency":32,"tools_ttl_seconds":3600}],
	  "limits":{"agent_rps":100000,"agent_burst":100000,"tool_rps":100000,"tool_burst":100000,"daily_quota":10000000},
	  "approvals":{"wait_seconds":0,"pending_ttl_seconds":600,"max_grant_ttl_seconds":600}}`,
		sha256Hex(agentKey), up.URL)
	pol := `{"version":1,"rules":[{"id":"echo","effect":"allow","scopes":["s"],"upstreams":["up"],"tools":["echo"],"requires_approval":true}]}`
	for name, body := range map[string]string{"config.json": cfg, "policy.json": pol} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	env := []string{
		"AUTHZ_MCP_ADDR=127.0.0.1:0", "AUTHZ_MCP_ADMIN_ADDR=127.0.0.1:0", "AUTHZ_MCP_ADMIN_TOKEN=" + adminToken,
		"AUTHZ_MCP_CONFIG=" + filepath.Join(dir, "config.json"), "AUTHZ_MCP_POLICY=" + filepath.Join(dir, "policy.json"),
		"AUTHZ_MCP_AUDIT_LOG=" + logPath, "AUTHZ_MCP_AUDIT_KEY=" + strings.Repeat("ef", 32),
		"AUTHZ_MCP_STATE_DIR=" + state, "AUTHZ_MCP_POLICY_POLL=0", "UP_TOKEN=" + upToken,
	}
	for _, k := range []string{"ADDR", "ADMIN_ADDR", "ADMIN_TOKEN", "CONFIG", "POLICY", "AUDIT_LOG", "AUDIT_KEY", "STATE_DIR", "POLICY_POLL", "LOG_LEVEL"} {
		env = append(env, "TOOLGATE_"+k+"=")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	type reply struct {
		ok       bool   // the tool ran and echoed the text
		code     int    // JSON-RPC error code otherwise
		approval string // approval_id from the error data
		status   string // status from the error data
	}
	// call returns false when no answer arrived (the gateway was killed).
	call := func(addr, text string) (reply, bool) {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"up.echo","arguments":{"text":%q},`+
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`, text)
		req, _ := http.NewRequest("POST", "http://"+addr+"/mcp", strings.NewReader(body))
		for k, v := range map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
			"Authorization": "Bearer " + agentKey, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "up.echo"} {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return reply{}, false
		}
		defer resp.Body.Close()
		var out struct {
			Result struct{ Content []struct{ Text string } }
			Error  *struct {
				Code int
				Data struct {
					ApprovalID string `json:"approval_id"`
					Status     string
				}
			}
		}
		if json.NewDecoder(resp.Body).Decode(&out) != nil {
			return reply{}, false
		}
		if out.Error != nil {
			return reply{code: out.Error.Code, approval: out.Error.Data.ApprovalID, status: out.Error.Data.Status}, true
		}
		if len(out.Result.Content) != 1 || out.Result.Content[0].Text != text {
			t.Errorf("call %q: unexpected result %+v", text, out.Result)
			return reply{}, false
		}
		return reply{ok: true}, true
	}
	mustCall := func(addr, text string) reply {
		t.Helper()
		r, ok := call(addr, text)
		if !ok {
			t.Fatalf("call %q got no answer", text)
		}
		return r
	}
	admin := func(addr, method, path, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	type gateway struct{ addr, admin string }
	var kill func()
	start := func() gateway {
		t.Helper()
		gw, sc := startMain(t, "mcp serve", env...)
		addr, adminAddr := listenAddrs(t, sc)
		kill = func() {
			t.Helper()
			if err := gw.Process.Signal(syscall.SIGKILL); err != nil {
				t.Fatal(err)
			}
			waitExit(t, gw)
		}
		return gateway{addr, adminAddr}
	}
	restart := func() gateway { kill(); return start() }
	const pending, denied = -31004, -31005

	// Killed between the request and the decision.
	g := start()
	r := mustCall(g.addr, "A")
	if r.code != pending || r.approval == "" {
		t.Fatalf("first call: %+v, want a pending approval", r)
	}
	idA := r.approval
	g = restart()
	if code, body := admin(g.admin, "GET", "/admin/approvals/"+idA, ""); code != 200 || body["status"] != "pending" {
		t.Fatalf("after restart the request is %d %v, want pending", code, body)
	}
	if r := mustCall(g.addr, "A"); r.code != pending || r.approval != idA {
		t.Fatalf("retry after restart: %+v, want the same pending request %s", r, idA)
	}
	if code, _ := admin(g.admin, "POST", "/admin/approvals/"+idA+"/approve", `{"ttl_seconds":300}`); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	// Killed between the decision and the call that uses it.
	g = restart()
	if upstreamSaw("A") != 0 {
		t.Fatal("the upstream saw the call before it was retried")
	}
	if r := mustCall(g.addr, "A"); !r.ok {
		t.Fatalf("the approved call after a restart: %+v, want it to run", r)
	}
	// Killed right after the grant was used.
	g = restart()
	r = mustCall(g.addr, "A")
	if r.code != pending || r.approval == idA || r.approval == "" {
		t.Fatalf("a used grant came back after a restart: %+v", r)
	}
	if n := upstreamSaw("A"); n != 1 {
		t.Fatalf("the upstream saw the approved call %d times, want 1", n)
	}

	// A denial survives a restart.
	r = mustCall(g.addr, "B")
	if code, _ := admin(g.admin, "POST", "/admin/approvals/"+r.approval+"/deny", `{"note":"no"}`); code != 200 {
		t.Fatalf("deny: %d", code)
	}
	g = restart()
	if r := mustCall(g.addr, "B"); r.code != denied {
		t.Fatalf("denied call after a restart: %+v", r)
	}

	// Identical calls race for one grant while the gateway dies.
	rng := rand.New(rand.NewPCG(2, uint64(time.Now().UnixNano())))
	for round := range races {
		text := fmt.Sprintf("race%d", round)
		r := mustCall(g.addr, text)
		if code, _ := admin(g.admin, "POST", "/admin/approvals/"+r.approval+"/approve", `{}`); code != 200 {
			t.Fatalf("round %d: approve: %d", round, code)
		}
		var wg sync.WaitGroup
		for range racers {
			wg.Go(func() { call(g.addr, text) })
		}
		time.Sleep(time.Duration(rng.IntN(3000)) * time.Microsecond)
		g = restart()
		wg.Wait()
		// Whatever the kill interrupted, one more call settles it: the
		// grant runs now only if no call ran before the kill.
		before := upstreamSaw(text)
		after := mustCall(g.addr, text)
		switch {
		case before > 1:
			t.Fatalf("round %d: the upstream ran one approved call %d times", round, before)
		case before == 1 && after.ok:
			t.Fatalf("round %d: the grant was used before the kill and again after it", round)
		case !after.ok && after.code != pending:
			t.Fatalf("round %d: after the restart: %+v", round, after)
		}
		if n := upstreamSaw(text); n > 1 {
			t.Fatalf("round %d: the upstream ran one approved call %d times", round, n)
		}
		t.Logf("round %d: upstream ran it %d time(s) before the kill, after: %+v", round, before, after)
	}

	kill()
	if code, out := runMain(t, "mcp audit verify "+logPath, env...); code != 0 {
		t.Fatalf("authz mcp audit verify exited %d: %s", code, out)
	}
}

// listenAddrs waits for `authz mcp serve`'s listening line and returns its
// agent and admin addresses.
func listenAddrs(t *testing.T, sc *bufio.Scanner) (string, string) {
	t.Helper()
	type addrs struct{ addr, admin string }
	ch := make(chan addrs, 1)
	go func() {
		for sc.Scan() {
			var line struct {
				Msg, Addr string
				AdminAddr string `json:"admin_addr"`
			}
			if json.Unmarshal(sc.Bytes(), &line) == nil && line.Msg == "listening" {
				ch <- addrs{line.Addr, line.AdminAddr}
				for sc.Scan() {
				}
				return
			}
		}
		ch <- addrs{}
	}()
	select {
	case a := <-ch:
		if a.addr == "" || a.admin == "" {
			t.Fatal("exited before listening")
		}
		return a.addr, a.admin
	case <-time.After(10 * time.Second):
		t.Fatal("did not start")
		return "", ""
	}
}
