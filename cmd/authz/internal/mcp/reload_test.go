package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/platform/audit"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
)

const carolKey = "tgk_carol_0123456789abcdefghijklmnopqrstu"

var rotatedKey = strings.Repeat("5a", 32)

// fileSetup is a gateway configured by a platform file. Its getenv still
// has every TOOLGATE_ variable of the environment setup, which the file
// replaces.
type fileSetup struct {
	*setup
	path     string // the platform file
	agents   string // the agents config
	keysFile string // signing_keys
	section  map[string]any
	mu       sync.Mutex
	n        int
}

func newFileSetup(t *testing.T) *fileSetup {
	t.Helper()
	s := newSetup(t)
	f := &fileSetup{setup: s, path: filepath.Join(s.dir, "authz.json"), agents: s.env["TOOLGATE_CONFIG"],
		keysFile: filepath.Join(s.dir, "signing-keys")}
	for name, v := range map[string]string{"admin-token": adminToken, "audit-key": auditKey, "signing-keys": s.env["TOOLGATE_SIGNING_KEYS"]} {
		f.write(t, filepath.Join(s.dir, name), v)
	}
	f.section = map[string]any{
		"addr":         "127.0.0.1:0",
		"admin_addr":   "127.0.0.1:0",
		"admin_token":  map[string]string{"file": filepath.Join(s.dir, "admin-token")},
		"config":       f.agents,
		"policy":       s.policy,
		"audit_log":    s.env["TOOLGATE_AUDIT_LOG"],
		"audit_key":    map[string]string{"file": filepath.Join(s.dir, "audit-key")},
		"state_dir":    s.env["TOOLGATE_STATE_DIR"],
		"signing_keys": map[string]string{"file": f.keysFile},
		"policy_poll":  "0s", // only the configuration watcher looks at the policy
		"log_level":    "info",
	}
	f.writeDoc(t, nil)
	// Not used with a file: a wrong value would stop the gateway.
	s.env["TOOLGATE_ADDR"] = "not an address"
	return f
}

// write replaces path atomically.
func (f *fileSetup) write(t testing.TB, path, content string) {
	t.Helper()
	f.mu.Lock()
	f.n++
	tmp := filepath.Join(f.dir, fmt.Sprintf(".tmp%d", f.n))
	f.mu.Unlock()
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// overwrite rewrites path in place, so a reader can see it half written.
func (f *fileSetup) overwrite(t testing.TB, path, content string) {
	t.Helper()
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	fh.WriteString(content[:len(content)/2])
	fh.Sync()
	time.Sleep(5 * time.Millisecond)
	fh.WriteString(content[len(content)/2:])
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
}

// writeDoc writes the platform file: the mcp section with extra merged in
// (nil deletes a member), and serve and gateway sections that "authz mcp"
// must skip, however wrong they are.
func (f *fileSetup) writeDoc(t testing.TB, extra map[string]any) {
	t.Helper()
	m := maps.Clone(f.section)
	for k, v := range extra {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, err := json.Marshal(map[string]any{"version": 1, "mcp": m,
		"serve": map[string]any{"no_such_member": true}, "gateway": map[string]any{"cookie_keys": 7}})
	if err != nil {
		t.Fatal(err)
	}
	f.write(t, f.path, string(b))
}

// agentsDoc is the agents config of the setup with carol added when
// withCarol is set and the upstream timeout given.
func (f *fileSetup) agentsDoc(t testing.TB, withCarol bool, timeoutMS int) string {
	t.Helper()
	var c map[string]any
	src, err := os.ReadFile(f.agents + ".orig")
	if os.IsNotExist(err) {
		if src, err = os.ReadFile(f.agents); err == nil {
			err = os.WriteFile(f.agents+".orig", src, 0o600)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(src, &c); err != nil {
		t.Fatal(err)
	}
	if withCarol {
		h := identity.HashToken(carolKey)
		c["agents"] = append(c["agents"].([]any), map[string]any{"id": "carol-bot", "owner": "carol",
			"scopes": []string{"files:read"}, "token_sha256": hex.EncodeToString(h[:])})
	}
	if timeoutMS > 0 {
		c["upstreams"].([]any)[0].(map[string]any)["timeout_ms"] = timeoutMS
	}
	b, _ := json.Marshal(c)
	return string(b)
}

func (f *fileSetup) start(t *testing.T) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{cancel: cancel, done: make(chan int, 1), logs: &syncBuffer{}}
	ready := make(chan struct{})
	go func() {
		code := 0
		if err := serveFile(ctx, f.path, f.getenv, r.logs, func(gw, admin string) {
			r.gw, r.admin = "http://"+gw, "http://"+admin
			close(ready)
		}); err != nil {
			fmt.Fprintln(r.logs, "serveFile:", err)
			code = 1
		}
		r.done <- code
	}()
	select {
	case <-ready:
	case code := <-r.done:
		t.Fatalf("exited with %d: %s", code, r.logs.String())
	case <-time.After(10 * time.Second):
		t.Fatal("gateway did not start")
	}
	return r
}

// within waits up to five seconds for ok and returns how long it took.
func within(t *testing.T, what string, ok func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !ok() {
		if time.Since(start) > 5*time.Second {
			t.Fatalf("%s: not within 5s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return time.Since(start)
}

func readFile(t *testing.T, r *running, tok string) map[string]any {
	t.Helper()
	return mcpCall(t, r.gw, tok, "tools/call", map[string]any{"name": "fake.read_file", "arguments": map[string]any{"path": "notes/a.txt"}})
}

func ok(res map[string]any) bool { return strings.Contains(fmt.Sprint(res["result"]), "hello") }

func mint(t *testing.T, s *setup, keys string) string {
	t.Helper()
	env := maps.Clone(s.env)
	env["TOOLGATE_SIGNING_KEYS"] = keys
	var out bytes.Buffer
	if code := cli(context.Background(), []string{"token", "mint", "-sub", "ci-bot", "-scope", "files:read"},
		func(k string) string { return env[k] }, nil, &out, io.Discard, nil); code != 0 {
		t.Fatal("token mint failed")
	}
	return strings.TrimSpace(out.String())
}

func TestServeFileStartsAndReloads(t *testing.T) {
	f := newFileSetup(t)
	r := f.start(t)
	logs := r.logs.String()
	if !strings.Contains(logs, `"msg":"TOOLGATE_ variables are ignored with a configuration file; use its AUTHZ_MCP_ overrides"`) ||
		!strings.Contains(logs, `"TOOLGATE_ADDR"`) || !strings.Contains(logs, `"msg":"configuration loaded"`) ||
		!strings.Contains(logs, `"sources":6`) {
		t.Fatalf("start-up log: %s", logs)
	}
	if res := readFile(t, r, agentKey); !ok(res) {
		t.Fatalf("call: %v", res)
	}
	oldTok := mint(t, f.setup, f.env["TOOLGATE_SIGNING_KEYS"])
	if res := readFile(t, r, oldTok); !ok(res) {
		t.Fatalf("signed token: %v", res)
	}

	// Signing keys rotate: the old ones stop verifying, the new one works.
	f.write(t, f.keysFile, "k3="+rotatedKey)
	d := within(t, "signing key rotation", func() bool { return readFile(t, r, oldTok)["error"] != nil })
	if res := readFile(t, r, mint(t, f.setup, "k3="+rotatedKey)); !ok(res) {
		t.Fatalf("token from the new key: %v", res)
	}
	t.Logf("signing_keys applied after %v", d.Round(time.Millisecond))
	within(t, "reload logged", func() bool {
		return strings.Contains(r.logs.String(), `"msg":"configuration reloaded","applied":["signing_keys"]`)
	})

	// An agent is added to the agents config.
	if res := readFile(t, r, carolKey); res["error"] == nil {
		t.Fatalf("carol before she is added: %v", res)
	}
	f.write(t, f.agents, f.agentsDoc(t, true, 0))
	d = within(t, "new agent", func() bool { return ok(readFile(t, r, carolKey)) })
	t.Logf("config (agents) applied after %v", d.Round(time.Millisecond))

	// The policy changes; policy_poll is off, so the configuration watcher
	// is what notices.
	h1 := adminGet(t, r.admin, "/admin/policy")["hash"]
	f.write(t, f.policy, `{"version":1,"rules":[]}`)
	d = within(t, "policy", func() bool { return readFile(t, r, agentKey)["error"] != nil })
	h2 := adminGet(t, r.admin, "/admin/policy")["hash"]
	if h2 == h1 {
		t.Fatal("policy hash did not change")
	}
	t.Logf("policy applied after %v", d.Round(time.Millisecond))

	// A broken policy is refused by both the watcher and the store.
	f.write(t, f.policy, `{"version":1,"rules":[`)
	within(t, "broken policy refused", func() bool {
		l := r.logs.String()
		return strings.Contains(l, `"msg":"policy reload rejected; the previous policy stays in force"`) &&
			strings.Contains(l, `"msg":"configuration change refused; keeping the running configuration","error":"$.mcp.policy`)
	})
	if h := adminGet(t, r.admin, "/admin/policy")["hash"]; h != h2 {
		t.Fatalf("broken policy replaced the policy: %v", h)
	}
	f.write(t, f.policy, `{"version":1,"rules":[{"id":"files","effect":"allow","scopes":["files:read"],"upstreams":["fake"],"tools":["read_file","echo"]}]}`)
	within(t, "policy restored", func() bool { return ok(readFile(t, r, agentKey)) })

	// A broken agents config is refused and the agents in force kept.
	f.write(t, f.agents, `{"agents": [`)
	within(t, "broken agents config refused", func() bool {
		return strings.Contains(r.logs.String(), `"error":"$.mcp.config: `)
	})
	if !ok(readFile(t, r, carolKey)) || !ok(readFile(t, r, agentKey)) {
		t.Fatal("agents lost after a refused change")
	}

	// Upstreams apply on restart, as do the listeners; carol goes at once.
	// SIGHUP reads the files without waiting for the next poll.
	f.write(t, f.agents, f.agentsDoc(t, false, 9000))
	f.writeDoc(t, map[string]any{"admin_addr": "127.0.0.1:1", "log_level": "debug"})
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	within(t, "restart-only members logged", func() bool {
		return strings.Contains(r.logs.String(), `"msg":"configuration changes apply when authz mcp restarts","members":["admin_addr","config.upstreams"]`)
	})
	if !strings.Contains(r.logs.String(), `"applied":["config","log_level"],"on_restart":["admin_addr","config.upstreams"]`) {
		t.Fatalf("reload log: %s", r.logs.String())
	}
	if readFile(t, r, carolKey)["error"] == nil {
		t.Fatal("carol still authenticates after she was removed")
	}
	if !ok(readFile(t, r, agentKey)) {
		t.Fatal("call after restart-only change")
	}

	// A file without the mcp section is refused.
	f.write(t, f.path, `{"version": 1, "serve": {}}`)
	within(t, "missing section refused", func() bool {
		return strings.Contains(r.logs.String(), `"error":"$.mcp: the file has no mcp section (nor any AUTHZ_MCP_ variable)"`)
	})
	if !ok(readFile(t, r, agentKey)) {
		t.Fatal("call after a refused file")
	}
	r.stop(t)

	// The policy changes are in the audit chain, which still verifies.
	src, err := os.ReadFile(f.env["TOOLGATE_AUDIT_LOG"])
	if err != nil {
		t.Fatal(err)
	}
	res, err := audit.Verify(bytes.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{`"policy_applied"`, `"policy_rejected"`} {
		if !bytes.Contains(src, []byte(ev)) {
			t.Errorf("audit log has no %s record (%d records)", ev, res.Records)
		}
	}
}

// Requests from an agent every version keeps never fail while the agents
// config, the signing keys, the policy, the level and the file itself
// change under them, completely, half written or broken.
func TestServeFileReloadUnderLoad(t *testing.T) {
	f := newFileSetup(t)
	r := f.start(t)
	allow := `{"version":1,"rules":[{"id":"files","effect":"allow","scopes":["files:read"],"upstreams":["fake"],"tools":["read_file","echo"]}%s]}`

	var stop atomic.Bool
	var calls, failures atomic.Int64
	var firstFailure atomic.Value
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				calls.Add(1)
				if res := readFile(t, r, agentKey); !ok(res) {
					failures.Add(1)
					firstFailure.CompareAndSwap(nil, fmt.Sprint(res))
				}
			}
		}()
	}
	steps := []func(){
		func() { f.write(t, f.agents, f.agentsDoc(t, true, 0)) },
		func() { f.write(t, f.keysFile, "k3="+rotatedKey) },
		func() {
			f.write(t, f.policy, fmt.Sprintf(allow, `,{"id":"no-echo","effect":"deny","scopes":["files:read"],"upstreams":["fake"],"tools":["echo"]}`))
		},
		func() { f.overwrite(t, f.agents, f.agentsDoc(t, false, 0)) },
		func() { f.write(t, f.policy, `{"version":1,"rules":[`) },
		func() { f.overwrite(t, f.policy, fmt.Sprintf(allow, "")) },
		func() { f.write(t, f.agents, `not json`) },
		func() { f.writeDoc(t, map[string]any{"log_level": "warn"}) },
		func() { f.overwrite(t, f.keysFile, "k4="+strings.Repeat("6b", 32)+",k3="+rotatedKey) },
		func() { f.write(t, f.agents, f.agentsDoc(t, true, 0)) },
		func() { f.write(t, f.path, `{"version": 1, "mcp": `) },
		func() { f.writeDoc(t, map[string]any{"log_level": "info"}) },
	}
	for _, step := range steps {
		step()
		time.Sleep(400 * time.Millisecond)
	}
	// The last version is in force: carol (added last) authenticates, and
	// so does a token from the newest signing key.
	k4 := mint(t, f.setup, "k4="+strings.Repeat("6b", 32))
	d := within(t, "last version", func() bool { return ok(readFile(t, r, carolKey)) && ok(readFile(t, r, k4)) })
	stop.Store(true)
	wg.Wait()
	r.stop(t)
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d of %d requests failed; first: %v", n, calls.Load(), firstFailure.Load())
	}
	logs := r.logs.String()
	reloads, refusals := strings.Count(logs, `"msg":"configuration reloaded"`), strings.Count(logs, `"msg":"configuration change refused`)
	// Steps closer together than a poll are loaded as one, and the reloads
	// made while the level was warn are not logged.
	if reloads < 1 || refusals < 2 {
		t.Fatalf("%d reloads, %d refusals: %s", reloads, refusals, logs)
	}
	t.Logf("%d requests, 0 failures, %d reloads, %d refusals; last change applied after %v",
		calls.Load(), reloads, refusals, d.Round(time.Millisecond))
}

// A section starts the gateway with what the same TOOLGATE_ values give,
// and AUTHZ_MCP_ variables override its members.
func TestSectionConfigMatchesEnv(t *testing.T) {
	f := newFileSetup(t)
	f.env["TOOLGATE_ADDR"] = "127.0.0.1:0"
	f.env["TOOLGATE_ALLOWED_ORIGINS"] = "https://a.example, https://b.example"
	f.writeDoc(t, map[string]any{"allowed_origins": []string{"https://a.example", " https://b.example", ""}, "log_level": "warn"})
	want, err := loadConfig(f.getenv)
	if err != nil {
		t.Fatal(err)
	}
	sc := Schema(f.getenv)
	c, err := sc.Load(f.path, sc.Environ(f.getenv))
	if err != nil {
		t.Fatal(err)
	}
	got, err := sectionConfig(pcfg.Get[Settings](c, SectionName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("section:\n%+v\nenvironment:\n%+v", got, want)
	}

	over := func(k string) string {
		switch k {
		case "AUTHZ_MCP_ADMIN_ADDR":
			return "127.0.0.1:9"
		case "AUTHZ_MCP_LOG_LEVEL":
			return "error"
		}
		return f.getenv(k)
	}
	sc = Schema(over)
	if c, err = sc.Load(f.path, sc.Environ(over)); err != nil {
		t.Fatal(err)
	}
	if got, err = sectionConfig(pcfg.Get[Settings](c, SectionName)); err != nil || got.adminAddr != "127.0.0.1:9" || got.logLevel.String() != "ERROR" {
		t.Fatalf("overrides: %+v, %v", got, err)
	}
	// A section the check did not pass is not started from.
	unchecked := *pcfg.Get[Settings](c, SectionName)
	unchecked.agents = nil
	if _, err := sectionConfig(&unchecked); err == nil || !strings.Contains(err.Error(), "was not checked") {
		t.Fatalf("unchecked section: %v", err)
	}
	for name, s := range map[string]Settings{"audit key": {}, "log level": {LogLevel: "loud"}} {
		bad := *pcfg.Get[Settings](c, SectionName)
		if name == "audit key" {
			bad.AuditKey = s.AuditKey
		} else {
			bad.LogLevel = s.LogLevel
		}
		if _, err := sectionConfig(&bad); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestServeFileStartErrors(t *testing.T) {
	f := newFileSetup(t)
	run := func(args []string, env map[string]string) (int, string) {
		var errb bytes.Buffer
		getenv := func(k string) string {
			if v, ok := env[k]; ok {
				return v
			}
			return f.getenv(k)
		}
		code := Run(context.Background(), args, getenv, nil, io.Discard, &errb)
		return code, errb.String()
	}
	missing := filepath.Join(f.dir, "missing.json")
	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
		code int
		want string
	}{
		"missing file":          {[]string{"serve", "-config", missing}, nil, 1, "authz mcp: config: open " + missing},
		"missing file, --flag=": {[]string{"serve", "--config=" + missing}, nil, 1, "authz mcp: config: open " + missing},
		"AUTHZ_CONFIG":          {nil, map[string]string{"AUTHZ_CONFIG": missing}, 1, "authz mcp: config: open " + missing},
		"AUTHZ_CONFIG, serve":   {[]string{"serve"}, map[string]string{"AUTHZ_CONFIG": missing}, 1, "authz mcp: config: open " + missing},
		"positional argument":   {[]string{"serve", "extra"}, nil, 2, `authz mcp serve: unexpected argument "extra"`},
		"unknown flag":          {[]string{"serve", "-nope"}, nil, 2, "flag provided but not defined: -nope"},
		"help":                  {[]string{"serve", "-h"}, nil, 0, "usage: authz mcp [serve]\n       authz mcp serve -config file\n"},
		// The file replaces the TOOLGATE_ variables, so two spellings
		// that disagree are no longer a conflict.
		"no conflict with a file": {[]string{"serve", "-config", missing}, map[string]string{"AUTHZ_MCP_STATE_DIR": "/x"}, 1, "authz mcp: config: open"},
	} {
		code, errOut := run(tc.args, tc.env)
		if code != tc.code || !strings.Contains(errOut, tc.want) {
			t.Errorf("%s: exit %d, %q; want %d, %q", name, code, errOut, tc.code, tc.want)
		}
	}
	var errb bytes.Buffer
	if code := Toolgate(context.Background(), []string{"serve", "extra"}, f.getenv, nil, io.Discard, &errb); code != 2 ||
		!strings.HasPrefix(errb.String(), `toolgate serve: unexpected argument "extra"`) {
		t.Errorf("toolgate: exit %d, %q", code, errb.String())
	}

	for name, tc := range map[string]struct {
		doc  string
		want string
	}{
		"no mcp section":   {`{"version": 1, "serve": {"addr": ":1"}}`, "$.mcp: the file has no mcp section"},
		"section problems": {`{"version": 1, "mcp": {"config": "` + f.agents + `"}}`, "$.mcp.admin_token: is required"},
		"not JSON":         {`{"version": 1,`, "invalid JSON"},
	} {
		f.write(t, f.path, tc.doc)
		code, errOut := run([]string{"serve", "-config", f.path}, nil)
		if code != 1 || !strings.Contains(errOut, tc.want) {
			t.Errorf("%s: exit %d, %q", name, code, errOut)
		}
	}
}

func TestRestartOnly(t *testing.T) {
	f := newFileSetup(t)
	sc := Schema(f.getenv)
	c, err := sc.Load(f.path, sc.Environ(f.getenv))
	if err != nil {
		t.Fatal(err)
	}
	s := pcfg.Get[Settings](c, SectionName)
	a, err := sectionConfig(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := restartOnly(a, a, s.agents, s.agents); len(got) != 0 {
		t.Fatalf("no change: %v", got)
	}
	b := a
	b.addr, b.adminAddr, b.adminToken, b.policyPath, b.auditPath = "x", "x", "x", "x", "x"
	b.auditKey, b.stateDir, b.origins, b.poll = []byte("x"), "x", []string{"x"}, time.Hour
	b.http.DrainDelay = time.Second
	b.http.TLS = s.tlsFiles()
	gb := *s.agents
	gb.Approvals.WaitSeconds++
	gb.Upstreams = nil
	want := []string{"addr", "admin_addr", "admin_token", "config.upstreams", "config.approvals", "policy", "audit_log",
		"audit_key", "state_dir", "allowed_origins", "policy_poll", "drain"}
	if got := restartOnly(a, b, s.agents, &gb); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart-only:\n got %v\nwant %v", got, want)
	}
	if !sameKeys(a, a) || sameKeys(a, config{}) {
		t.Fatal("sameKeys")
	}
	if s2 := (&Settings{TLSCert: "c", TLSKey: "k"}).tlsFiles(); s2 == nil || s2.CertFile != "c" {
		t.Fatalf("tlsFiles: %+v", s2)
	}
	if v := toolgateVars(func(k string) string {
		if k == "TOOLGATE_POLICY" || k == "TOOLGATE_ADDR" || k == "TOOLGATE_UPSTREAM_SECRET" {
			return "x"
		}
		return ""
	}); !reflect.DeepEqual(v, []string{"TOOLGATE_ADDR", "TOOLGATE_POLICY"}) {
		t.Fatalf("toolgateVars: %v", v)
	}
}
