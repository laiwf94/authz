package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/audit"
	"github.com/laiwf94/authz/internal/agents/fakeserver"
)

// The crash harness: `authz mcp serve` is killed with SIGKILL while agents
// are calling through it, then started again on the same audit log and
// state directory, round after round. It checks the promises docs/DESIGN.md
// makes for a crash:
//
//   - the gateway always starts again, and the log verifies at the end;
//   - every call the upstream saw has a durable "started" record (the record
//     is on disk before the upstream is contacted);
//   - every answer an agent received, allowed or denied, has its records on
//     disk (they are written before the reply);
//   - a "completed" record always follows its "started" one;
//   - pins.json survives, so the tool stays trusted after every restart;
//   - a torn final line is cut on start, and a log changed while stopped
//     stops the gateway from starting.
//
// The upstream runs in the test process, so what it saw outlives the kill.
func TestMCPSurvivesSIGKILL(t *testing.T) {
	const (
		rounds   = 8
		tornAt   = 4 // after this round's kill, a torn write is left behind
		workers  = 6
		agentKey = "tgk_crash_test_0123456789abcdefghijklmnop"
		upToken  = "up-crash-0123456789"
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
	var seenMu sync.Mutex
	seen := map[string]bool{} // echo texts the upstream was asked for
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var msg struct {
			Method string
			Params struct {
				Name      string
				Arguments struct{ Text string }
			}
		}
		if json.Unmarshal(body, &msg) == nil && msg.Method == "tools/call" {
			seenMu.Lock()
			seen[msg.Params.Arguments.Text] = true
			seenMu.Unlock()
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		fake.ServeHTTP(w, r)
	}))
	defer up.Close()

	cfg := fmt.Sprintf(`{"tokens":{"issuer":"authz","audience":"crash-test"},
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
	logPath := filepath.Join(dir, "audit.jsonl")
	env := []string{
		"AUTHZ_MCP_ADDR=127.0.0.1:0", "AUTHZ_MCP_ADMIN_ADDR=127.0.0.1:0",
		"AUTHZ_MCP_ADMIN_TOKEN=admin-0123456789abcdefghijklmnopqrstuv",
		"AUTHZ_MCP_CONFIG=" + filepath.Join(dir, "config.json"), "AUTHZ_MCP_POLICY=" + filepath.Join(dir, "policy.json"),
		"AUTHZ_MCP_AUDIT_LOG=" + logPath, "AUTHZ_MCP_AUDIT_KEY=" + strings.Repeat("cd", 32),
		"AUTHZ_MCP_STATE_DIR=" + state, "AUTHZ_MCP_POLICY_POLL=0",
		"UP_TOKEN=" + upToken,
	}
	for _, k := range []string{"ADDR", "ADMIN_ADDR", "ADMIN_TOKEN", "CONFIG", "POLICY", "AUDIT_LOG", "AUDIT_KEY", "STATE_DIR", "POLICY_POLL", "LOG_LEVEL"} {
		env = append(env, "TOOLGATE_"+k+"=") // the environment the test runs in must not leak in
	}

	client := &http.Client{Timeout: 5 * time.Second}
	var nonce atomic.Int64
	type answer struct{ requestID, decision, text string }
	var ansMu sync.Mutex
	var answers []answer
	// call makes one tools/call and records the answer when one arrives.
	// Connection errors are expected once the gateway is killed.
	call := func(addr, tool string) (answer, bool) {
		text := fmt.Sprintf("n%06d", nonce.Add(1))
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"up.%s","arguments":{"text":%q,"path":"x"},`+
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`, tool, text)
		if tool == "read_file" {
			body = strings.Replace(body, fmt.Sprintf(`"text":%q,`, text), "", 1)
		} else {
			body = strings.Replace(body, `,"path":"x"`, "", 1)
		}
		req, _ := http.NewRequest("POST", "http://"+addr+"/mcp", strings.NewReader(body))
		for k, v := range map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
			"Authorization": "Bearer " + agentKey, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "up." + tool} {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return answer{}, false
		}
		defer resp.Body.Close()
		var out struct {
			Result struct {
				Content []struct{ Text string }
			}
			Error *struct{ Code int }
		}
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&out) != nil {
			return answer{}, false
		}
		a := answer{requestID: resp.Header.Get("X-Request-Id")}
		switch {
		case tool == "echo" && out.Error == nil && len(out.Result.Content) == 1 && out.Result.Content[0].Text == text:
			a.decision, a.text = "allow", text
		case tool == "read_file" && out.Error != nil:
			a.decision = "deny"
		default:
			t.Errorf("unexpected answer to %s: %+v", tool, out)
			return answer{}, false
		}
		if a.requestID == "" {
			t.Errorf("answer without X-Request-Id")
			return answer{}, false
		}
		ansMu.Lock()
		answers = append(answers, a)
		ansMu.Unlock()
		return a, true
	}

	rng := rand.New(rand.NewPCG(1, uint64(time.Now().UnixNano())))
	for round := 1; round <= rounds; round++ {
		gw, gwLog := startMain(t, "mcp serve", env...)
		addr := listenAddr(t, gwLog)
		if round == tornAt+1 {
			// Before any call: had start not cut the torn write, later
			// appends could hide it by writing over it.
			readRecords(t, logPath)
		}
		// The first call of a round proves the restart kept the tool trusted:
		// a lost pin store would re-pin, a corrupt one would refuse to start.
		if _, ok := call(addr, "echo"); !ok {
			t.Fatalf("round %d: the first call after a restart failed", round)
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for w := range workers {
			wg.Go(func() {
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					tool := "echo"
					if (w+i)%5 == 0 {
						tool = "read_file" // denied by policy
					}
					call(addr, tool)
				}
			})
		}
		delay := time.Duration(rng.IntN(150)+10) * time.Millisecond
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
		t.Logf("round %d: killed after %v, %d answers so far", round, delay, len(answers))
		if round == tornAt {
			leaveTornWrite(t, logPath)
		}
	}

	// One clean start after the last kill, then a normal stop.
	gw, gwLog := startMain(t, "mcp serve", env...)
	addr := listenAddr(t, gwLog)
	if _, ok := call(addr, "echo"); !ok {
		t.Fatal("the call after the last restart failed")
	}
	if err := gw.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitExit(t, gw); err != nil {
		t.Fatalf("mcp exited with %v after SIGTERM, want 0", err)
	}

	if code, out := runMain(t, "mcp audit verify "+logPath, env...); code != 0 {
		t.Fatalf("authz mcp audit verify exited %d after the crashes: %s", code, out)
	}
	recs := readRecords(t, logPath)

	type stages struct{ started, completed uint64 }
	byRequest := map[string]*stages{}
	decided := map[string]string{} // request id -> decision of its first tool_call record
	startedText := map[string]bool{}
	for _, r := range recs {
		if r.Event != "tool_call" {
			continue
		}
		var d struct {
			RequestID   string `json:"request_id"`
			Stage       string
			Decision    string
			Outcome     string
			ArgsPreview string `json:"args_preview"`
		}
		if err := json.Unmarshal(r.Data, &d); err != nil {
			t.Fatalf("record %d: %v", r.Seq, err)
		}
		if _, ok := decided[d.RequestID]; !ok {
			decided[d.RequestID] = d.Decision
		}
		s := byRequest[d.RequestID]
		if s == nil {
			s = &stages{}
			byRequest[d.RequestID] = s
		}
		switch d.Stage {
		case "started":
			if s.started != 0 {
				t.Errorf("request %s started twice", d.RequestID)
			}
			s.started = r.Seq
			var args struct{ Text string }
			if err := json.Unmarshal([]byte(d.ArgsPreview), &args); err != nil {
				t.Fatalf("record %d: args_preview %q: %v", r.Seq, d.ArgsPreview, err)
			}
			startedText[args.Text] = true
		case "completed":
			if s.started == 0 {
				t.Errorf("record %d: request %s completed without a started record before it", r.Seq, d.RequestID)
			}
			s.completed = r.Seq
		}
	}

	seenMu.Lock()
	for text := range seen {
		if !startedText[text] {
			t.Errorf("the upstream ran echo %q, but no started record for it is on disk", text)
		}
	}
	nSeen := len(seen)
	seenMu.Unlock()
	allowed, denied := 0, 0
	for _, a := range answers {
		switch a.decision {
		case "allow":
			allowed++
			s := byRequest[a.requestID]
			if s == nil || s.started == 0 || s.completed == 0 {
				t.Errorf("request %s (%q) was answered, but its records are not all on disk: %+v", a.requestID, a.text, s)
			}
		case "deny":
			denied++
			if decided[a.requestID] != "deny" {
				t.Errorf("request %s was refused, but no deny record for it is on disk", a.requestID)
			}
		}
	}
	if allowed < rounds+1 || denied == 0 {
		t.Fatalf("the load was too light to prove anything: %d allowed and %d denied answers", allowed, denied)
	}
	t.Logf("%d records; %d allowed and %d denied answers, %d upstream calls, %d calls started but never answered",
		len(recs), allowed, denied, nSeen, len(startedText)-allowed)

	// A log changed while the gateway was stopped must stop it from starting.
	tampered := filepath.Join(dir, "tampered.jsonl")
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	second := bytes.IndexByte(raw, '\n') + 1
	i := second + bytes.Index(raw[second:], []byte(`"event":"`)) + len(`"event":"`)
	raw[i] ^= 0x01
	if err := os.WriteFile(tampered, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := runMain(t, "mcp serve", append(env, "AUTHZ_MCP_AUDIT_LOG="+tampered)...)
	if code == 0 || !strings.Contains(out, "line 2") {
		t.Fatalf("mcp serve on a tampered log exited %d, want a failure naming line 2: %s", code, out)
	}
}

// leaveTornWrite appends the first half of a well-formed next record without
// its newline, as a write cut short by power loss leaves it. The gateway must
// cut it on start: it was never acknowledged.
func leaveTornWrite(t *testing.T, path string) {
	t.Helper()
	recs := readRecords(t, path)
	last := recs[len(recs)-1]
	line := fmt.Sprintf(`{"seq":%d,"time":"2026-11-03T00:00:00Z","prev":"%s","event":"tool_call","data":{"stage":"started"}}`,
		last.Seq+1, strings.Repeat("0", 64))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line[:len(line)/2]); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(mustOpen(t, path)); err == nil {
		t.Fatal("the torn write must make strict verification fail")
	}
}

func mustOpen(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// readRecords verifies the log strictly and returns its records.
func readRecords(t *testing.T, path string) []audit.Record {
	t.Helper()
	if _, err := audit.Verify(mustOpen(t, path)); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var recs []audit.Record
	sc := bufio.NewScanner(mustOpen(t, path))
	sc.Buffer(make([]byte, 0, 64<<10), audit.MaxLineBytes)
	for sc.Scan() {
		var r audit.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return recs
}

// runMain runs main with args to completion and returns its exit code and
// combined output.
func runMain(t *testing.T, args string, extraEnv ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), append([]string{"AUTHZ_TEST_MAIN_ARGS=" + args}, extraEnv...)...)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}
