package main

import (
	"encoding/json"
	"fmt"
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

// Static agent keys across SIGKILL: `authz mcp serve` keeps the keys the
// admin API issues, rotates and revokes in static-keys.json in its state
// directory. The gateway is killed after each kind of change, and every
// restart must agree with what was acknowledged before the kill: an issued
// key verifies, a revoked configured or issued key doesn't, a rotated key
// keeps verifying through its overlap next to its replacement, and the key
// set version carries on. Then rounds of key issues race a kill at a
// random moment: every key whose issue was answered verifies after the
// restart, and the version is the last one answered, or one more when the
// kill came between the save and the answer.
func TestMCPStaticKeysSurviveSIGKILL(t *testing.T) {
	const (
		agentKey   = "tgk_static_crash_test_0123456789abcdefghij"
		upToken    = "up-static-0123456789"
		adminToken = "admin-0123456789abcdefghijklmnopqrstuv"
		rounds     = 6
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
	up := httptest.NewServer(fake)
	defer up.Close()
	cfg := fmt.Sprintf(`{"agents":[{"id":"bot","owner":"alice","scopes":["s"],"token_sha256":%q}],
	  "upstreams":[{"name":"up","url":"%s/mcp","credential_env":"UP_TOKEN","tools_ttl_seconds":3600}],
	  "limits":{"agent_rps":100000,"agent_burst":100000}}`, sha256Hex(agentKey), up.URL)
	pol := `{"version":1,"rules":[{"id":"echo","effect":"allow","scopes":["s"],"upstreams":["up"],"tools":["echo"]}]}`
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
	// agent returns the status of a tools/list with token.
	agent := func(addr, token string) int {
		t.Helper()
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` +
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
		req, _ := http.NewRequest("POST", "http://"+addr+"/mcp", strings.NewReader(body))
		for k, v := range map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
			"Authorization": "Bearer " + token, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"} {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("tools/list: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// admin returns the status and body of an admin call, and false when
	// no answer arrived (the gateway was killed).
	admin := func(addr, method, path, body string) (int, map[string]any, bool) {
		req, _ := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, false
		}
		defer resp.Body.Close()
		var out map[string]any
		if json.NewDecoder(resp.Body).Decode(&out) != nil {
			return 0, nil, false
		}
		return resp.StatusCode, out, true
	}
	mustAdmin := func(addr, method, path, body string, want int) map[string]any {
		t.Helper()
		code, out, ok := admin(addr, method, path, body)
		if !ok || code != want {
			t.Fatalf("%s %s %s: %d %v, want %d", method, path, body, code, out, want)
		}
		return out
	}
	version := func(addr string) uint64 {
		t.Helper()
		return uint64(mustAdmin(addr, "GET", "/admin/keys", "", 200)["version"].(float64))
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
	keyID := func(token string) string { return sha256Hex(token)[:16] }

	// Killed after an issue.
	g := start()
	s1 := mustAdmin(g.admin, "POST", "/admin/keys", `{"agent":"bot","version":0}`, 201)["secret"].(string)
	g = restart()
	if agent(g.addr, s1) != 200 || agent(g.addr, agentKey) != 200 || version(g.admin) != 1 {
		t.Fatal("after an issue and a restart")
	}
	// Killed after a rotation with an hour of overlap.
	s2 := mustAdmin(g.admin, "POST", "/admin/keys/"+keyID(s1)+"/rotate", `{"version":1,"overlap_seconds":3600}`, 200)["secret"].(string)
	g = restart()
	if agent(g.addr, s1) != 200 || agent(g.addr, s2) != 200 {
		t.Fatal("after a rotation and a restart, a key inside its overlap or its replacement is refused")
	}
	// Killed after revoking the configured key and the rotated one.
	mustAdmin(g.admin, "POST", "/admin/keys/"+keyID(agentKey)+"/revoke", `{"version":2}`, 200)
	mustAdmin(g.admin, "POST", "/admin/keys/"+keyID(s1)+"/revoke", `{"version":3}`, 200)
	g = restart()
	if agent(g.addr, agentKey) != 401 || agent(g.addr, s1) != 401 || agent(g.addr, s2) != 200 || version(g.admin) != 4 {
		t.Fatal("after revocations and a restart")
	}

	// Issues race a kill.
	live := []string{s2}
	rng := rand.New(rand.NewPCG(5, uint64(time.Now().UnixNano())))
	for round := range rounds {
		v := version(g.admin)
		addr := g.admin
		var mu sync.Mutex
		var acked []string
		last := v
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			cur := v
			for {
				select {
				case <-stop:
					return
				default:
				}
				code, out, ok := admin(addr, "POST", "/admin/keys", fmt.Sprintf(`{"agent":"bot","version":%d}`, cur))
				if !ok {
					return
				}
				if code != 201 {
					t.Errorf("round %d: issue at version %d: %d %v", round, cur, code, out)
					return
				}
				mu.Lock()
				acked = append(acked, out["secret"].(string))
				cur = uint64(out["version"].(float64))
				last = cur
				mu.Unlock()
				// Stay under the per-agent limit: revoke the oldest issued key.
				mu.Lock()
				full := len(acked) >= 8
				mu.Unlock()
				if full {
					mu.Lock()
					old := acked[0]
					acked = acked[1:]
					mu.Unlock()
					code, out, ok := admin(addr, "POST", "/admin/keys/"+keyID(old)+"/revoke", fmt.Sprintf(`{"version":%d}`, cur))
					if !ok {
						// Unknown whether the revocation was saved.
						mu.Lock()
						acked = append([]string{"?" + old}, acked...)
						mu.Unlock()
						return
					}
					if code != 200 {
						t.Errorf("round %d: revoke: %d %v", round, code, out)
						return
					}
					mu.Lock()
					last = uint64(out["version"].(float64))
					cur = last
					mu.Unlock()
				}
			}
		})
		time.Sleep(time.Duration(5+rng.IntN(40)) * time.Millisecond)
		g = restart()
		close(stop)
		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
		mu.Lock()
		got := version(g.admin)
		if got != last && got != last+1 {
			t.Fatalf("round %d: version %d after the restart; the last change answered made it %d", round, got, last)
		}
		for _, s := range append(live[:len(live):len(live)], acked...) {
			if strings.HasPrefix(s, "?") {
				continue
			}
			if code := agent(g.addr, s); code != 200 {
				t.Fatalf("round %d: a key whose issue was answered is refused after the restart: %d", round, code)
			}
		}
		t.Logf("round %d: %d keys issued and answered, version %d (last answered %d)", round, len(acked), got, last)
		// Start the next round from a clean slate of issued keys.
		_, set, _ := admin(g.admin, "GET", "/admin/keys", "")
		v = got
		for _, k := range set["keys"].([]any) {
			m := k.(map[string]any)
			if m["id"] == keyID(s2) {
				continue
			}
			mustAdmin(g.admin, "POST", "/admin/keys/"+m["id"].(string)+"/revoke", fmt.Sprintf(`{"version":%d}`, v), 200)
			v++
		}
		mu.Unlock()
	}
	if agent(g.addr, s2) != 200 || agent(g.addr, agentKey) != 401 {
		t.Fatal("at the end")
	}

	kill()
	if stale, _ := filepath.Glob(filepath.Join(state, ".static-keys.json.*")); len(stale) > 1 {
		t.Fatalf("temporary files pile up: %v", stale)
	}
	if code, out := runMain(t, "mcp audit verify "+logPath, env...); code != 0 {
		t.Fatalf("authz mcp audit verify exited %d: %s", code, out)
	}
	b, _ := os.ReadFile(logPath)
	for _, s := range []string{agentKey, s1, s2} {
		if strings.Contains(string(b), s) {
			t.Fatal("a static key is in the audit log")
		}
	}
}
