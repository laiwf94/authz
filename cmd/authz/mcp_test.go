package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// listenAddr reads JSON log lines until the "listening" one and returns its
// addr field, then keeps draining so the child never blocks on a full pipe.
func listenAddr(t *testing.T, sc *bufio.Scanner) string {
	t.Helper()
	addr := make(chan string, 1)
	go func() {
		for sc.Scan() {
			var line struct{ Msg, Addr string }
			if json.Unmarshal(sc.Bytes(), &line) == nil && line.Msg == "listening" {
				addr <- line.Addr
				for sc.Scan() {
				}
				return
			}
		}
		addr <- ""
	}()
	select {
	case a := <-addr:
		if a == "" {
			t.Fatal("exited before listening")
		}
		return a
	case <-time.After(10 * time.Second):
		t.Fatal("did not start")
		return ""
	}
}

// The MCP gateway and its fake upstream run as subcommands of the one
// binary, with the real signal wiring: the gateway answers through the
// upstream, survives SIGHUP (it reloads its policy on it, unlike serve), and
// SIGTERM stops both cleanly.
func TestMainMCPAndMCPFake(t *testing.T) {
	dir := t.TempDir()
	box := filepath.Join(dir, "box")
	if err := os.MkdirAll(box, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(box, "a.txt"), []byte("hello from the box"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake, fakeLog := startMain(t, "mcpfake", "AUTHZ_MCPFAKE_ADDR=127.0.0.1:0", "AUTHZ_MCPFAKE_SANDBOX="+box,
		"AUTHZ_MCPFAKE_TOKEN=up-0123456789", "MCPFAKE_ADDR=", "MCPFAKE_SANDBOX=", "MCPFAKE_TOKEN=")
	upstream := listenAddr(t, fakeLog)

	// The config holds the static key's SHA-256, as "authz mcp token new" prints it.
	const agentKey = "tgk_main_test_0123456789abcdefghijklmnop"
	sum := sha256Hex(agentKey)
	cfg := fmt.Sprintf(`{"tokens":{"issuer":"authz","audience":"main-test"},
	  "agents":[{"id":"bot","owner":"alice","scopes":["files:read"],"token_sha256":%q}],
	  "upstreams":[{"name":"fake","url":"http://%s/mcp","credential_env":"UP_TOKEN"}]}`, sum, upstream)
	pol := `{"version":1,"rules":[{"id":"files","effect":"allow","scopes":["files:read"],"upstreams":["fake"],"tools":["read_file"]}]}`
	for name, body := range map[string]string{"config.json": cfg, "policy.json": pol} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Old and new names mixed, as in a deployment halfway through renaming.
	gw, gwLog := startMain(t, "mcp serve",
		"AUTHZ_MCP_ADDR=127.0.0.1:0", "TOOLGATE_ADMIN_ADDR=127.0.0.1:0",
		"AUTHZ_MCP_ADMIN_TOKEN=admin-0123456789abcdefghijklmnopqrstuv",
		"TOOLGATE_CONFIG="+filepath.Join(dir, "config.json"), "AUTHZ_MCP_POLICY="+filepath.Join(dir, "policy.json"),
		"TOOLGATE_AUDIT_LOG="+filepath.Join(dir, "audit.jsonl"), "AUTHZ_MCP_AUDIT_KEY="+strings.Repeat("ab", 32),
		"TOOLGATE_POLICY_POLL=0", "UP_TOKEN=up-0123456789")
	addr := listenAddr(t, gwLog)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake.read_file","arguments":{"path":"a.txt"},` +
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	call := func() string {
		t.Helper()
		req, _ := http.NewRequest("POST", "http://"+addr+"/mcp", strings.NewReader(body))
		for k, v := range map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
			"Authorization": "Bearer " + agentKey, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "fake.read_file"} {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct{ Result json.RawMessage }
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return string(out.Result)
	}
	if got := call(); !strings.Contains(got, "hello from the box") {
		t.Fatalf("call through the gateway: %s", got)
	}
	if err := gw.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := call(); !strings.Contains(got, "hello from the box") {
		t.Fatalf("after SIGHUP the gateway must still serve: %s", got)
	}
	if err := gw.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := fake.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitExit(t, gw); err != nil {
		t.Fatalf("mcp exited with %v, want a clean exit 0", err)
	}
	if err := waitExit(t, fake); err != nil {
		t.Fatalf("mcpfake exited with %v, want a clean exit 0", err)
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
