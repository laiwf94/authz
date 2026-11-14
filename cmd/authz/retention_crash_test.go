//go:build unix

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
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
)

// The retention crash harness: `authz mcp serve` rotates its signed audit
// log every 4 KiB and keeps at most 8 KiB of rotated-out segments, while
// agents call through it and an auditor exports checkpoints through POST
// /admin/audit/export. It is killed with SIGKILL round after round, often
// in the middle of a rotation or a removal, and started again. After each
// restart it checks what docs/DESIGN.md promises for retention:
//
//   - the log verifies across its segments, starting from FILE.base;
//   - no record was removed that the last exported checkpoint (FILE.exported)
//     does not cover;
//   - every checkpoint the auditor received that covers the base still
//     verifies against the log, and the newest is proven consistent with
//     the log's own;
//   - what a removal that was cut short left behind is gone after the open.
func TestMCPRetentionSurvivesSIGKILL(t *testing.T) {
	const (
		rounds   = 10
		workers  = 4
		agentKey = "tgk_retain_test_0123456789abcdefghijklmnop"
		upToken  = "up-retain-0123456789"
		admin    = "admin-retain-0123456789abcdefghijklmnopq"
	)
	dir := t.TempDir()
	box := filepath.Join(dir, "box")
	state := filepath.Join(dir, "state")
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

	cfg := fmt.Sprintf(`{"tokens":{"issuer":"authz","audience":"retain-test"},
	  "agents":[{"id":"bot","owner":"alice","scopes":["s"],"token_sha256":%q}],
	  "upstreams":[{"name":"up","url":"%s/mcp","credential_env":"UP_TOKEN","max_concurrency":32,"tools_ttl_seconds":3600}],
	  "limits":{"agent_rps":100000,"agent_burst":100000,"tool_rps":100000,"tool_burst":100000,"daily_quota":10000000}}`,
		sha256Hex(agentKey), up.URL)
	pol := `{"version":1,"rules":[{"id":"echo","effect":"allow","scopes":["s"],"upstreams":["up"],"tools":["echo"]}]}`
	for name, body := range map[string]string{"config.json": cfg, "policy.json": pol} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	skey, vkey, err := audit.GenerateKey(rand.Reader, "audit.retain.test")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := audit.ParseVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "audit.key")
	if err := os.WriteFile(keyFile, []byte(skey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	env := []string{
		"AUTHZ_MCP_ADDR=127.0.0.1:0", "AUTHZ_MCP_ADMIN_ADDR=127.0.0.1:0", "AUTHZ_MCP_ADMIN_TOKEN=" + admin,
		"AUTHZ_MCP_CONFIG=" + filepath.Join(dir, "config.json"), "AUTHZ_MCP_POLICY=" + filepath.Join(dir, "policy.json"),
		"AUTHZ_MCP_AUDIT_LOG=" + logPath, "AUTHZ_MCP_AUDIT_KEY=" + strings.Repeat("cd", 32),
		"AUTHZ_MCP_AUDIT_ROTATE_BYTES=4096", "AUTHZ_MCP_STATE_DIR=" + state, "AUTHZ_MCP_POLICY_POLL=0",
		"AUTHZ_AUDIT_SIGNING_KEY_FILE=" + keyFile, "AUTHZ_AUDIT_SIGNING_KEY=", "AUTHZ_AUDIT_CHECKPOINT_INTERVAL=1s",
		"AUTHZ_AUDIT_RETAIN_BYTES=8192", "AUTHZ_AUDIT_RETAIN_AGE=",
		"UP_TOKEN=" + upToken,
	}
	for _, k := range []string{"ADDR", "ADMIN_ADDR", "ADMIN_TOKEN", "CONFIG", "POLICY", "AUDIT_LOG", "AUDIT_KEY", "STATE_DIR", "POLICY_POLL", "LOG_LEVEL"} {
		env = append(env, "TOOLGATE_"+k+"=")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	call := func(addr string, n int) bool {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"up.echo","arguments":{"text":"r%06d"},`+
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`, n)
		req, _ := http.NewRequest("POST", "http://"+addr+"/mcp", strings.NewReader(body))
		for k, v := range map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
			"Authorization": "Bearer " + agentKey, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "up.echo"} {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode == http.StatusOK
	}
	// The auditor's copies of every checkpoint it was handed.
	var notesMu sync.Mutex
	var notes []audit.Checkpoint
	export := func(adminAddr string) bool {
		req, _ := http.NewRequest("POST", "http://"+adminAddr+"/admin/audit/export", nil)
		req.Header.Set("Authorization", "Bearer "+admin)
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK {
			return false
		}
		c, err := audit.OpenCheckpoint(b, verifier)
		if err != nil {
			t.Errorf("the exported checkpoint does not open: %v\n%s", err, b)
			return false
		}
		notesMu.Lock()
		notes = append(notes, c)
		notesMu.Unlock()
		return true
	}

	// check verifies what retention promises, with the gateway idle.
	maxRemoved := uint64(0)
	check := func(round int) {
		t.Helper()
		cr, err := audit.VerifyChain(logPath, audit.Default())
		if err != nil {
			t.Fatalf("round %d: the log does not verify: %v", round, err)
		}
		if cr.Removed < maxRemoved {
			t.Fatalf("round %d: records 1 to %d are removed, fewer than the %d removed before", round, cr.Removed, maxRemoved)
		}
		maxRemoved = cr.Removed
		if cr.Removed > 0 {
			b, err := os.ReadFile(audit.ExportedPath(logPath))
			if err != nil {
				t.Fatalf("round %d: records were removed without an exported checkpoint: %v", round, err)
			}
			exp, err := audit.OpenCheckpoint(b, verifier)
			if err != nil {
				t.Fatal(err)
			}
			if cr.Removed > exp.Size {
				t.Fatalf("round %d: records 1 to %d were removed, but the exported checkpoint covers %d", round, cr.Removed, exp.Size)
			}
		}
		segs, err := audit.Segments(logPath)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range segs {
			var first uint64
			fmt.Sscanf(strings.TrimPrefix(p, logPath+"."), "%d", &first)
			if first <= cr.Removed {
				t.Fatalf("round %d: %s, which retention removed, is still there after the open", round, filepath.Base(p))
			}
		}
		notesMu.Lock()
		defer notesMu.Unlock()
		for _, c := range notes {
			if c.Size < cr.Removed {
				continue // a later export let its records go
			}
			if err := cr.Covers(c); err != nil {
				t.Fatalf("round %d: the auditor's checkpoint of %d records no longer verifies: %v", round, c.Size, err)
			}
		}
	}

	rng := mrand.New(mrand.NewPCG(7, uint64(time.Now().UnixNano())))
	n := 0
	for round := 1; round <= rounds; round++ {
		gw, gwLog := startMain(t, "mcp serve", env...)
		addr, adminAddr := listenAddrs(t, gwLog)
		check(round)
		if !call(addr, n) {
			t.Fatalf("round %d: the first call after a restart failed", round)
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var callMu sync.Mutex
		for range workers {
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					callMu.Lock()
					n++
					i := n
					callMu.Unlock()
					call(addr, i)
				}
			})
		}
		seed := rng.Uint64()
		wg.Go(func() {
			jitter := mrand.New(mrand.NewPCG(seed, 1))
			for {
				select {
				case <-stop:
					return
				case <-time.After(time.Duration(5+jitter.IntN(20)) * time.Millisecond):
					export(adminAddr)
				}
			}
		})
		delay := time.Duration(rng.IntN(300)+50) * time.Millisecond
		time.Sleep(delay)
		if err := gw.Process.Signal(syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		err := waitExit(t, gw)
		close(stop)
		wg.Wait()
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("round %d: gateway ended with %v, want death by SIGKILL", round, err)
		}
		if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Fatalf("round %d: gateway ended with %v, want death by SIGKILL", round, err)
		}
		segs, _ := audit.Segments(logPath)
		t.Logf("round %d: killed after %v; %d segments on disk, %d checkpoints exported", round, delay, len(segs), len(notes))
	}

	// One clean start after the last kill, an export, then a normal stop.
	gw, gwLog := startMain(t, "mcp serve", env...)
	addr, adminAddr := listenAddrs(t, gwLog)
	check(rounds + 1)
	if !call(addr, n+1) || !export(adminAddr) {
		t.Fatal("the call or export after the last restart failed")
	}
	if err := gw.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitExit(t, gw); err != nil {
		t.Fatalf("mcp exited with %v after SIGTERM, want 0", err)
	}
	check(rounds + 2)
	if maxRemoved == 0 {
		t.Fatal("retention removed nothing; the load was too light to prove anything")
	}

	// The auditor, holding only the public key, checks the log against its
	// newest checkpoint and the log's own, and proves that the log's own
	// extends the auditor's.
	last := notes[len(notes)-1]
	saved := filepath.Join(dir, "auditor.checkpoint")
	note, err := os.ReadFile(audit.ExportedPath(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := audit.OpenCheckpoint(note, verifier); c != last {
		t.Fatalf("FILE.exported is %+v, not the last checkpoint exported, %+v", c, last)
	}
	if err := os.WriteFile(saved, note, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := runMain(t, "audit verify -key "+vkey+" -checkpoint "+saved+" "+logPath, env...)
	if code != 0 || !strings.Contains(out, "removed by retention") {
		t.Fatalf("authz audit verify -key after the crashes: %d %s", code, out)
	}
	code, out = runMain(t, fmt.Sprintf("audit prove -from %d %s", last.Size, logPath), env...)
	if code != 0 {
		t.Fatalf("authz audit prove -from %d: %d %s", last.Size, code, out)
	}
	proofFile := filepath.Join(dir, "proof.json")
	if err := os.WriteFile(proofFile, bytes.TrimSpace([]byte(out)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := runMain(t, "audit prove -check "+proofFile+" -key "+vkey+" -old "+saved, env...); code != 0 {
		t.Fatalf("authz audit prove -check: %d %s", code, out)
	}
	t.Logf("records 1 to %d removed by retention over %d kills, %d checkpoints exported", maxRemoved, rounds, len(notes))
}
