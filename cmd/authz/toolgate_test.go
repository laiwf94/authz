package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// buildWithLegacyLinks builds the authz binary into a temporary directory
// and links the old command names to it, as the toolgate image does.
func buildWithLegacyLinks(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "authz")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}
	for _, n := range names {
		// Relative, like the links in the image.
		if err := os.Symlink("authz", filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// runLinked runs a linked binary to completion and returns its exit code,
// stdout and stderr.
func runLinked(t *testing.T, path string, env []string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(path, args...)
	cmd.Env = env
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out.String(), errOut.String()
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, out.String(), errOut.String()
}

// startLinked starts a linked binary and returns the address its JSON log
// reports it listening on.
func startLinked(t *testing.T, path string, env []string) (*exec.Cmd, string) {
	t.Helper()
	cmd := exec.Command(path)
	cmd.Env = env
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd, listenAddr(t, bufio.NewScanner(stdout))
}

// An existing toolgate deployment keeps working through the "toolgate" and
// "mcpfake" links to the one binary, with only its old variable names: the
// fake upstream serves the example sandbox, a call goes through the
// gateway, "toolgate audit verify" checks the log it wrote, "toolgate policy
// test" runs the example cases, and SIGTERM stops both with exit 0.
func TestMainToolgateLinks(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatal("the go command is needed to build the binary under test")
	}
	bin := buildWithLegacyLinks(t, "toolgate", "mcpfake")
	dir := t.TempDir()
	base := []string{"PATH=" + os.Getenv("PATH")}

	fake, upstream := startLinked(t, filepath.Join(bin, "mcpfake"), append(base,
		"MCPFAKE_ADDR=127.0.0.1:0", "MCPFAKE_SANDBOX=../../toolgate/examples/sandbox", "MCPFAKE_TOKEN=up-0123456789"))

	const agentKey = "tgk_link_test_0123456789abcdefghijklmnop"
	cfg := fmt.Sprintf(`{"tokens":{"issuer":"toolgate","audience":"link-test"},
	  "agents":[{"id":"bot","owner":"alice","scopes":["files:read"],"token_sha256":%q}],
	  "upstreams":[{"name":"fake","url":"http://%s/mcp","credential_env":"UP_TOKEN"}]}`, sha256Hex(agentKey), upstream)
	pol := `{"version":1,"rules":[{"id":"files","effect":"allow","scopes":["files:read"],"upstreams":["fake"],"tools":["read_file"]}]}`
	for name, body := range map[string]string{"config.json": cfg, "policy.json": pol} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	auditLog := filepath.Join(dir, "audit.jsonl")
	gw, addr := startLinked(t, filepath.Join(bin, "toolgate"), append(base,
		"TOOLGATE_ADDR=127.0.0.1:0", "TOOLGATE_ADMIN_ADDR=127.0.0.1:0",
		"TOOLGATE_ADMIN_TOKEN=admin-0123456789abcdefghijklmnopqrstuv",
		"TOOLGATE_CONFIG="+filepath.Join(dir, "config.json"), "TOOLGATE_POLICY="+filepath.Join(dir, "policy.json"),
		"TOOLGATE_AUDIT_LOG="+auditLog, "TOOLGATE_AUDIT_KEY="+strings.Repeat("cd", 32),
		"TOOLGATE_POLICY_POLL=0", "UP_TOKEN=up-0123456789"))

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake.read_file","arguments":{"path":"reports/q1.txt"},` +
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	req, _ := http.NewRequest("POST", "http://"+addr+"/mcp", strings.NewReader(body))
	for k, v := range map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
		"Authorization": "Bearer " + agentKey, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "fake.read_file"} {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Result json.RawMessage }
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if !strings.Contains(string(out.Result), "Q1 revenue grew 12%") {
		t.Fatalf("call through toolgate to the example sandbox: %s", out.Result)
	}

	for _, p := range []*exec.Cmd{gw, fake} {
		if err := p.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		if err := waitExit(t, p); err != nil {
			t.Fatalf("%s exited with %v, want a clean exit 0", filepath.Base(p.Path), err)
		}
	}

	code, stdout, stderr := runLinked(t, filepath.Join(bin, "toolgate"), base, "audit", "verify", auditLog)
	if code != 0 || !strings.HasPrefix(stdout, "OK "+auditLog+": ") || !strings.Contains(stdout, " records, head ") || stderr != "" {
		t.Fatalf("toolgate audit verify: exit %d %q %q", code, stdout, stderr)
	}
	if log, err := os.ReadFile(auditLog); err != nil || !strings.Contains(string(log), `"tool":"read_file"`) {
		t.Fatalf("the audit log has no record of the call (%v):\n%s", err, log)
	}
	code, stdout, stderr = runLinked(t, filepath.Join(bin, "toolgate"), base, "policy", "test",
		"../../toolgate/examples/policy.json", "../../toolgate/examples/policy_cases.json")
	if code != 0 || stdout != "PASS 17 cases: 17 passed, 0 failed\n" || stderr != "" {
		t.Fatalf("toolgate policy test: exit %d %q %q", code, stdout, stderr)
	}
	code, _, stderr = runLinked(t, filepath.Join(bin, "toolgate"), base, "bogus")
	if code != 1 || !strings.HasPrefix(stderr, "toolgate: usage: toolgate [serve] |") {
		t.Fatalf("toolgate bogus: exit %d %q", code, stderr)
	}
	code, _, stderr = runLinked(t, filepath.Join(bin, "mcpfake"), base, "-h")
	if code != 0 || !strings.HasPrefix(stderr, "usage: mcpfake\n") {
		t.Fatalf("mcpfake -h: exit %d %q", code, stderr)
	}
	// The binary under its own name is still the dispatcher.
	code, stdout, _ = runLinked(t, filepath.Join(bin, "authz"), base, "help")
	if code != 0 || !strings.Contains(stdout, "  mcp ") || strings.Contains(stdout, "toolgate") {
		t.Fatalf("authz help: exit %d %q", code, stdout)
	}
}
