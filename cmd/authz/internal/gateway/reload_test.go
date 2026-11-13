package gateway

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/policy"
	"github.com/laiwf94/authz/internal/authn/session"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/httpserver"
	"github.com/laiwf94/authz/internal/platform/seal"
)

// Every WICKET_ variable "authz gateway -h" documents, but WICKET_CONFIG,
// whose contents are the section's wicket members, is a member of the
// gateway section under its lower-case name.
func TestSectionHasEveryVariable(t *testing.T) {
	members := map[string]bool{}
	st := reflect.TypeFor[Settings]()
	for i := range st.NumField() {
		name, _, _ := strings.Cut(st.Field(i).Tag.Get("json"), ",")
		members[name] = true
	}
	var stderr bytes.Buffer
	Run(context.Background(), []string{"-h"}, env(nil), nil, io.Discard, &stderr)
	seen := map[string]bool{}
	for _, v := range regexp.MustCompile(`\bWICKET_[A-Z_]+\b`).FindAllString(stderr.String(), -1) {
		if v == "WICKET_CONFIG" || seen[v] {
			continue
		}
		seen[v] = true
		if !members[strings.ToLower(strings.TrimPrefix(v, "WICKET_"))] {
			t.Errorf("%s has no member in the gateway section", v)
		}
	}
	if len(seen) != 22 {
		t.Errorf("%d WICKET_ settings documented, want 22: %v", len(seen), seen)
	}
}

// The section starts the gateway with the settings the same values as
// WICKET_ variables give.
func TestSectionSettingsMatchVariables(t *testing.T) {
	dir := t.TempDir()
	var pemOut bytes.Buffer
	subcommand("gensigningkey", &pemOut)
	keyFile := filepath.Join(dir, "sign.pem")
	os.WriteFile(keyFile, pemOut.Bytes(), 0o600)
	other := hex.EncodeToString(seal.RandomKey())
	vars := map[string]string{
		"WICKET_CONFIG": "/c.json", "WICKET_COOKIE_KEYS": cookieKey + "," + other,
		"WICKET_ADDR": ":8443", "WICKET_ADMIN_ADDR": "0.0.0.0:9443", "WICKET_ADMIN_TOKEN": "admin-token-0123456789",
		"WICKET_SESSION_FILE": "/var/lib/s.log", "WICKET_SIGNING_KEYS": keyFile, "WICKET_TRUSTED_PROXIES": "10.0.0.0/8,192.168.0.0/16",
		"WICKET_LOGIN_RATE": "60", "WICKET_LOG_LEVEL": "debug", "WICKET_AUDIT_LOG": "/var/log/audit",
		"WICKET_DRAIN_DELAY": "5s", "WICKET_DRAIN_TIMEOUT": "40s",
	}
	want, err := loadSettings(env(vars))
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, _ := json.Marshal(keyFile)
	doc := `{"version": 1, "gateway": {"cookie_keys": {"env": "CK"},
	  "addr": ":8443", "admin_addr": "0.0.0.0:9443", "admin_token": {"env": "AT"},
	  "session_file": "/var/lib/s.log", "signing_keys": [` + string(keyJSON) + `],
	  "trusted_proxies": ["10.0.0.0/8", "192.168.0.0/16"], "login_rate": 60, "log_level": "debug",
	  "audit_log": "/var/log/audit", "drain_delay": "5s", "drain_timeout": "40s", ` + wicketDoc + `}}`
	r := Schema(env(map[string]string{"CORP_SECRET": "s"})).Check([]byte(doc),
		[]string{"CK=" + cookieKey + ", " + other, "AT=admin-token-0123456789"})
	if len(r.Problems) != 0 {
		t.Fatal(r.Problems)
	}
	got, err := sectionSettings(pcfg.Get[Settings](r.Config, SectionName))
	if err != nil {
		t.Fatal(err)
	}
	want.configPath = ""
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("section:\n%+v\nvariables:\n%+v", got, want)
	}

	// The defaults are wicket's too, apart from the login rate, which the
	// section spells out and the server reads 0 as.
	r = Schema(env(map[string]string{"CORP_SECRET": "s"})).Check([]byte(`{"version": 1, "gateway": {"cookie_keys": {"env": "CK"}, `+wicketDoc+`}}`), []string{"CK=" + cookieKey})
	got, err = sectionSettings(pcfg.Get[Settings](r.Config, SectionName))
	if err != nil {
		t.Fatal(err)
	}
	want, _ = loadSettings(env(map[string]string{"WICKET_CONFIG": "/c.json", "WICKET_COOKIE_KEYS": cookieKey}))
	want.configPath, want.loginRate = "", 30
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("defaults:\n%+v\nwicket's:\n%+v", got, want)
	}
}

func TestSectionHTTPChecks(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.pem")
	sc := Schema(env(map[string]string{"CORP_SECRET": "s"}))
	for name, c := range map[string]struct{ members, path, msg string }{
		"cert alone":  {`"tls_cert": "c.pem"`, "$.gateway.tls_cert", "must be set together"},
		"ca alone":    {`"tls_client_ca": "ca.pem"`, "$.gateway.tls_client_ca", "needs tls_cert and tls_key"},
		"no files":    {`"tls_cert": "` + missing + `", "tls_key": "` + missing + `"`, "$.gateway.tls_cert", "no such file"},
		"long delay":  {`"drain_delay": "2h"`, "$.gateway.drain_delay", "at most 1h"},
		"no timeout":  {`"drain_timeout": "0s"`, "$.gateway.drain_timeout", "more than 0s"},
		"long drain":  {`"drain_timeout": "61m"`, "$.gateway.drain_timeout", "more than 0s"},
		"same cookie": {`"drain_delay": "1s"`, "", ""},
	} {
		ck := cookieKey
		if c.path == "" {
			ck = cookieKey + "," + cookieKey
		}
		doc := `{"version": 1, "gateway": {"cookie_keys": {"env": "CK"}, ` + c.members + `, ` + wicketDoc + `}}`
		r := sc.Check([]byte(doc), []string{"CK=" + ck})
		if c.path == "" {
			// A key listed twice passes the section checks but the key ring
			// refuses it, so the watcher refuses the file.
			if r.Problems.Err() != nil {
				t.Errorf("%s: %v", name, r.Problems)
			} else if err := validateFile(r.Config); err == nil || !strings.Contains(err.Error(), "duplicate") {
				t.Errorf("%s: validate %v", name, err)
			}
			continue
		}
		if r.Problems.Count(pcfg.SeverityError) != 1 || r.Problems[0].Path != c.path || !strings.Contains(r.Problems[0].Message, c.msg) {
			t.Errorf("%s: %v, want %s: %s", name, r.Problems, c.path, c.msg)
		}
	}
}

// The -config flag and AUTHZ_CONFIG.
func TestConfigFlag(t *testing.T) {
	dir := t.TempDir()
	call := func(e map[string]string, args ...string) (int, string) {
		var errb bytes.Buffer
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // a gateway that starts stops at once
		code := cli(ctx, "authz gateway", args, env(e), io.Discard, &errb, make(chan os.Signal))
		return code, errb.String()
	}
	for _, args := range [][]string{{"-config"}, {"-config="}, {"--config", ""}, {"-config", "a", "b"}} {
		if code, errb := call(nil, args...); code != 2 || errb == "" {
			t.Errorf("%q: %d %q", args, code, errb)
		}
	}
	if code, errb := call(nil, "-config", "a", "b"); code != 2 || !strings.Contains(errb, `unexpected argument "b"`) {
		t.Errorf("-config a b: %d %q", code, errb)
	}
	if code, errb := call(nil, "-config", "x", "-h"); code != 0 || !strings.HasPrefix(errb, "usage: authz gateway\n") {
		t.Errorf("-config x -h: %d %q", code, errb)
	}
	// "-configx" is not the flag.
	if code, errb := call(nil, "-configx"); code != 2 || !strings.Contains(errb, `unknown command "-configx"`) {
		t.Errorf("-configx: %d %q", code, errb)
	}
	missing := filepath.Join(dir, "missing.json")
	for _, args := range [][]string{{"-config", missing}, {"-config=" + missing}, {"--config=" + missing}} {
		if code, errb := call(nil, args...); code != 1 || !strings.Contains(errb, "missing.json") {
			t.Errorf("%q: %d %q", args, code, errb)
		}
	}
	if code, errb := call(map[string]string{ConfigEnv: missing}); code != 1 || !strings.Contains(errb, "missing.json") {
		t.Errorf("AUTHZ_CONFIG: %d %q", code, errb)
	}
	// A file without a gateway section has nothing to run.
	only := filepath.Join(dir, "serve.json")
	os.WriteFile(only, []byte(`{"version": 1, "serve": {"anything": "goes"}}`), 0o600)
	if code, errb := call(nil, "-config", only); code != 1 || !strings.Contains(errb, "no gateway section") {
		t.Errorf("serve only: %d %q", code, errb)
	}
	// A broken gateway section is reported with its path.
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"version": 1, "gateway": {"cookie_keys": {"env": "CK"}, `+wicketDoc+`}}`), 0o600)
	if code, errb := call(map[string]string{"CORP_SECRET": "s", "CK": "nope"}, "-config", bad); code != 1 || !strings.Contains(errb, "$.gateway.cookie_keys") {
		t.Errorf("bad section: %d %q", code, errb)
	}
	// The flag wins over AUTHZ_CONFIG, and a good file starts and stops,
	// here with the cookie keys from their AUTHZ_GATEWAY_ override.
	good := filepath.Join(dir, "good.json")
	os.WriteFile(good, []byte(`{"version": 1, "gateway": {
	  "addr": "127.0.0.1:0", "admin_addr": "127.0.0.1:0", `+wicketDoc+`}}`), 0o600)
	if code, errb := call(map[string]string{"CORP_SECRET": "s", "AUTHZ_GATEWAY_COOKIE_KEYS": cookieKey, ConfigEnv: missing}, "-config", good); code != 0 {
		t.Errorf("good: %d %q", code, errb)
	}
	if code, errb := call(map[string]string{"CORP_SECRET": "s", "AUTHZ_GATEWAY_COOKIE_KEYS": cookieKey, ConfigEnv: good}); code != 0 {
		t.Errorf("AUTHZ_CONFIG good: %d %q", code, errb)
	}
}

// fileGateway is "authz gateway -config" running on ephemeral ports.
type fileGateway struct {
	t                    *testing.T
	dir, config, keyFile string
	public, admin        string
	log                  *syncBuf
	hup                  chan os.Signal
	done                 chan error
	cancel               context.CancelFunc
	secret               string // a session in the session file
}

// The file's gateway section, with every member a test changes.
type gatewayDoc struct {
	logLevel   string
	extraHosts []string
	loginRate  int
}

func (g *fileGateway) write(d gatewayDoc) {
	g.t.Helper()
	keyJSON, _ := json.Marshal(g.keyFile)
	sessJSON, _ := json.Marshal(filepath.Join(g.dir, "sessions.log"))
	hosts, _ := json.Marshal(append([]string{"app.example.com"}, d.extraHosts...))
	if d.logLevel == "" {
		d.logLevel = "info"
	}
	if d.loginRate == 0 {
		d.loginRate = 30
	}
	doc := fmt.Sprintf(`{"version": 1,
  "serve": {"not": "read by the gateway"},
  "gateway": {
    "addr": "127.0.0.1:0", "admin_addr": "127.0.0.1:0",
    "cookie_keys": {"file": %s}, "session_file": %s,
    "log_level": %q, "login_rate": %d,
    "public_url": "https://auth.example.com",
    "providers": [{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "CORP_SECRET"}],
    "apps": [{"id": "app", "hosts": %s, "providers": ["corp"], "allow": {"any_user": true}}]
  },
  "mcp": {"is": ["skipped", "too"]}}`, keyJSON, sessJSON, d.logLevel, d.loginRate, hosts)
	replaceFile(g.t, g.config, doc)
}

func replaceFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path+".tmp", []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

func startFileGateway(t *testing.T, keys ...string) *fileGateway {
	t.Helper()
	dir := t.TempDir()
	g := &fileGateway{t: t, dir: dir, config: filepath.Join(dir, "authz.json"), keyFile: filepath.Join(dir, "cookie-keys"),
		log: &syncBuf{}, hup: make(chan os.Signal, 1), done: make(chan error, 1)}
	// A signed-in user, in the session file the gateway opens.
	st, err := session.Open(session.Options{Path: filepath.Join(dir, "sessions.log")})
	if err != nil {
		t.Fatal(err)
	}
	if g.secret, _, err = st.Create(policy.Identity{Provider: "corp", Subject: "alice"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	replaceFile(t, g.keyFile, strings.Join(keys, ",")+"\n")
	g.write(gatewayDoc{})

	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	addrs := make(chan [2]string, 1)
	go func() {
		g.done <- serveFrom(ctx, env(map[string]string{"CORP_SECRET": "s"}), g.config, g.log, g.hup,
			func(p, a string) { addrs <- [2]string{p, a} }, nil)
	}()
	select {
	case a := <-addrs:
		g.public, g.admin = a[0], a[1]
	case err := <-g.done:
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := <-g.done; err != nil {
			t.Error(err)
		}
	})
	return g
}

// cookie seals the session secret with key, as a gateway holding it first
// would have.
func cookie(t testing.TB, key, secret string) string {
	b, _ := hex.DecodeString(key)
	kr, err := seal.New([][]byte{b})
	if err != nil {
		t.Fatal(err)
	}
	return "__Host-wicket=" + kr.Seal("session", []byte(secret))
}

// auth asks the gateway whether the cookie may reach host.
func (g *fileGateway) auth(client *http.Client, host, cookie string) (int, error) {
	req, _ := http.NewRequest("GET", "http://"+g.public+"/auth", nil)
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Uri", "/")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
}

func (g *fileGateway) status(host, cookie string) int {
	g.t.Helper()
	code, err := g.auth(http.DefaultClient, host, cookie)
	if err != nil {
		g.t.Fatal(err)
	}
	return code
}

func (g *fileGateway) waitStatus(host, cookie string, want int) {
	g.t.Helper()
	start := time.Now()
	waitFor(g.t, func() bool { return g.status(host, cookie) == want })
	if d := time.Since(start); d > 5*time.Second {
		g.t.Fatalf("change took %v", d)
	}
}

func (g *fileGateway) count(msg string) int {
	return strings.Count(g.log.String(), `"msg":"`+msg+`"`)
}

// Cookie keys, apps and the log level change while the gateway runs from a
// platform file, an invalid change is refused with the running
// configuration kept, and members that need a restart are logged as such.
func TestFileReload(t *testing.T) {
	keyA, keyB := cookieKey, hex.EncodeToString(seal.RandomKey())
	g := startFileGateway(t, keyA)
	withA, withB := cookie(t, keyA, g.secret), cookie(t, keyB, g.secret)
	if c := g.status("app.example.com", withA); c != 200 {
		t.Fatalf("signed in with the first key: %d\n%s", c, g.log.String())
	}
	if c := g.status("app.example.com", withB); c != 401 {
		t.Fatalf("a key the gateway does not hold: %d", c)
	}
	if !strings.Contains(g.log.String(), `"msg":"configuration loaded"`) {
		t.Fatalf("start not logged:\n%s", g.log.String())
	}

	// Rotation: the new key first, the old one still opening.
	replaceFile(t, g.keyFile, keyB+","+keyA)
	g.waitStatus("app.example.com", withB, 200)
	if c := g.status("app.example.com", withA); c != 200 {
		t.Fatalf("old key during the overlap: %d", c)
	}
	// Then the old key is dropped.
	replaceFile(t, g.keyFile, keyB)
	g.waitStatus("app.example.com", withA, 401)

	// An app gains a host: the runtime is rebuilt from the section.
	if c := g.status("new.example.com", withB); c != 403 {
		t.Fatalf("unknown host: %d", c)
	}
	loads := strings.Count(g.log.String(), `"event":"config_loaded"`)
	g.write(gatewayDoc{extraHosts: []string{"new.example.com"}})
	g.waitStatus("new.example.com", withB, 200)
	waitFor(t, func() bool { return strings.Count(g.log.String(), `"event":"config_loaded"`) == loads+1 })
	if !strings.Contains(g.log.String(), `"applied":["apps"],"on_restart":null`) {
		t.Fatalf("app change not described:\n%s", g.log.String())
	}

	// An invalid change is refused and the running configuration kept: a
	// broken key file, then a broken document.
	refused := g.count("configuration change refused; keeping the running configuration")
	replaceFile(t, g.keyFile, "not-a-key")
	waitFor(t, func() bool {
		return g.count("configuration change refused; keeping the running configuration") == refused+1
	})
	replaceFile(t, g.config, `{"version": 1, "gateway": {`)
	waitFor(t, func() bool {
		return g.count("configuration change refused; keeping the running configuration") == refused+2
	})
	if c := g.status("new.example.com", withB); c != 200 {
		t.Fatalf("after refused changes: %d", c)
	}
	// So is a file with no gateway section.
	replaceFile(t, g.config, `{"version": 1, "serve": {}}`)
	waitFor(t, func() bool {
		return g.count("configuration change refused; keeping the running configuration") == refused+3
	})
	if !strings.Contains(g.log.String(), "no gateway section") {
		t.Fatalf("no section not explained:\n%s", g.log.String())
	}
	if c := g.status("new.example.com", withB); c != 200 {
		t.Fatalf("after the section went: %d", c)
	}

	// Fixed again, with debug logging and a new login rate, which waits for
	// a restart.
	replaceFile(t, g.keyFile, keyB)
	g.write(gatewayDoc{logLevel: "debug", loginRate: 60, extraHosts: []string{"new.example.com"}})
	waitFor(t, func() bool { return g.count("configuration changes apply when authz gateway restarts") == 1 })
	if !strings.Contains(g.log.String(), `"applied":["log_level"],"on_restart":["login_rate"]`) {
		t.Fatalf("reload not described:\n%s", g.log.String())
	}
	if !strings.Contains(g.log.String(), `"level":"DEBUG"`) {
		// The server logs requests at debug level once it is set.
		g.status("app.example.com", withB)
		waitFor(t, func() bool { return strings.Contains(g.log.String(), `"level":"DEBUG"`) })
	}
}

// SIGHUP and POST /admin/reload read the file at once instead of waiting
// for the next poll, and the change is built once.
func TestFileReloadOnSignal(t *testing.T) {
	g := startFileGateway(t, cookieKey)
	withA := cookie(t, cookieKey, g.secret)
	loads := strings.Count(g.log.String(), `"event":"config_loaded"`)

	g.write(gatewayDoc{extraHosts: []string{"hup.example.com"}})
	g.hup <- syscall.SIGHUP
	g.waitStatus("hup.example.com", withA, 200)

	g.write(gatewayDoc{extraHosts: []string{"hup.example.com", "admin.example.com"}})
	resp, err := http.Post("http://"+g.admin+"/admin/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin reload: %d", resp.StatusCode)
	}
	if c := g.status("admin.example.com", withA); c != 200 {
		t.Fatalf("after the admin reload: %d", c)
	}
	// Two changes, two rebuilds: the watcher's own poll finds them already
	// in place.
	time.Sleep(2 * time.Second)
	if n := strings.Count(g.log.String(), `"event":"config_loaded"`) - loads; n != 2 {
		t.Fatalf("%d rebuilds for two changes:\n%s", n, g.log.String())
	}

	// An admin reload of a broken file fails and keeps the configuration.
	replaceFile(t, g.config, `{"version": 1, "gateway": {"cookie_keys": {"env": "NOT_SET"}}}`)
	resp, err = http.Post("http://"+g.admin+"/admin/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatal("admin reload of a broken file succeeded")
	}
	if c := g.status("admin.example.com", withA); c != 200 {
		t.Fatalf("after a refused admin reload: %d", c)
	}
}

// Under load, with every request carrying a cookie sealed with a key that
// every version of the key file lists, no request fails while the keys
// rotate, the apps change and broken versions are refused.
func TestFileReloadUnderLoad(t *testing.T) {
	shared, other := cookieKey, hex.EncodeToString(seal.RandomKey())
	g := startFileGateway(t, shared)
	withShared := cookie(t, shared, g.secret)
	var (
		stop     atomic.Bool
		requests atomic.Int64
		failures atomic.Int64
		first    atomic.Value
		wg       sync.WaitGroup
	)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 1}}
			for !stop.Load() {
				code, err := g.auth(client, "app.example.com", withShared)
				requests.Add(1)
				if err != nil || code != 200 {
					failures.Add(1)
					first.CompareAndSwap(nil, fmt.Sprintf("%d %v", code, err))
				}
			}
		}()
	}
	steps := []func(){
		func() { replaceFile(t, g.keyFile, other+","+shared) },
		func() { g.write(gatewayDoc{extraHosts: []string{"a.example.com"}}) },
		func() { replaceFile(t, g.keyFile, "broken") },
		func() { replaceFile(t, g.keyFile, shared+","+other) },
		func() { replaceFile(t, g.config, "{") },
		func() { g.write(gatewayDoc{logLevel: "warn"}) },
		func() { replaceFile(t, g.keyFile, shared) },
	}
	for _, step := range steps {
		step()
		time.Sleep(1200 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d of %d requests failed, first: %v", n, requests.Load(), first.Load())
	}
	if requests.Load() < 100 {
		t.Fatalf("only %d requests", requests.Load())
	}
	t.Logf("%d requests across %d changes, none failed", requests.Load(), len(steps))
}

// With a file, the WICKET_ variables are ignored, and the log says which.
func TestFileIgnoresWicketVariables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authz.json")
	os.WriteFile(path, []byte(`{"version": 1, "gateway": {"addr": "127.0.0.1:0", "admin_addr": "127.0.0.1:0", `+wicketDoc+`}}`), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	logs := &syncBuf{}
	e := env(map[string]string{"CORP_SECRET": "s", "AUTHZ_GATEWAY_COOKIE_KEYS": cookieKey,
		"WICKET_ADDR": "256.0.0.1:0", "WICKET_COOKIE_KEYS": "nope", "WICKET_CONFIG": "/missing.json"})
	if err := serveFrom(ctx, e, path, logs, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), `"ignored":["WICKET_ADDR","WICKET_CONFIG","WICKET_COOKIE_KEYS"]`) {
		t.Fatalf("ignored variables not logged:\n%s", logs.String())
	}
}

// Each member that waits for a restart is named when it changes.
func TestRestartOnly(t *testing.T) {
	base := settings{addr: ":1", adminAddr: ":2", loginRate: 30}
	if got := restartOnly(base, base); got != nil {
		t.Fatalf("no change: %v", got)
	}
	for want, change := range map[string]func(*settings){
		"addr":            func(s *settings) { s.addr = ":3" },
		"admin_addr":      func(s *settings) { s.adminAddr = ":4" },
		"admin_token":     func(s *settings) { s.adminToken = "admin-token-0123456789" },
		"session_file":    func(s *settings) { s.sessionFile = "/s.log" },
		"signing_keys":    func(s *settings) { s.signingKeys = []string{"/k.pem"} },
		"trusted_proxies": func(s *settings) { s.trusted = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} },
		"login_rate":      func(s *settings) { s.loginRate = 60 },
		"audit_log":       func(s *settings) { s.auditLog = "/a.log" },
		"tls":             func(s *settings) { s.http.TLS = &httpserver.TLSFiles{CertFile: "c", KeyFile: "k"} },
		"drain":           func(s *settings) { s.http.DrainDelay = time.Second },
	} {
		s := base
		change(&s)
		if got := restartOnly(base, s); !reflect.DeepEqual(got, []string{want}) {
			t.Errorf("%s: %v", want, got)
		}
	}
}
