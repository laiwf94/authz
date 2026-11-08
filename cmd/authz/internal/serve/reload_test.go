package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/httpserver"
	"github.com/laiwf94/authz/internal/platform/httpserver/httpservertest"
)

const (
	fileKeyA = "file-key-a-0123456789"
	fileKeyB = "file-key-b-0123456789"
	fileKeyC = "file-key-c-0123456789"
)

// syncBuffer collects the server's log while the test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// logged returns the log records with message msg.
func (s *syncBuffer) logged(msg string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(s.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// replace writes path atomically, as editors and Kubernetes do.
func replace(t testing.TB, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

type fileServer struct {
	t      testing.TB
	dir    string
	config string
	keys   string
	addr   string
	log    *syncBuffer
	client *http.Client
	done   chan error
}

// startFile starts "authz serve" from a configuration file whose serve
// section is doc, with the API keys in a secret file holding keys.
func startFile(t testing.TB, doc, keys string, getenv func(string) string) *fileServer {
	t.Helper()
	dir := t.TempDir()
	f := &fileServer{t: t, dir: dir, config: filepath.Join(dir, "authz.json"), keys: filepath.Join(dir, "api-keys"),
		log: &syncBuffer{}, client: &http.Client{Timeout: 5 * time.Second}, done: make(chan error, 1)}
	replace(t, f.keys, keys)
	f.writeConfig(doc)
	if getenv == nil {
		getenv = env(nil)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	go func() { f.done <- serve(ctx, getenv, f.config, f.log, func(a string) { ready <- a }) }()
	select {
	case f.addr = <-ready:
	case err := <-f.done:
		cancel()
		t.Fatalf("serve: %v\n%s", err, f.log)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("serve did not start")
	}
	t.Cleanup(func() {
		cancel()
		if err := <-f.done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return f
}

// writeConfig writes the file with doc as its serve section, %KEYS%
// standing for the API key file.
func (f *fileServer) writeConfig(doc string) {
	replace(f.t, f.config, `{"version": 1, "serve": `+strings.ReplaceAll(doc, "%KEYS%", f.keys)+`,
  "gateway": {"anything": "is the gateway's"}, "mcp": {"policy": 7}}`)
}

func (f *fileServer) status(key string) int {
	req, _ := http.NewRequest(http.MethodGet, "http://"+f.addr+"/v1/schema", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := f.client.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// waitFor polls until cond holds, and fails after the platform's 5 s.
func (f *fileServer) waitFor(what string, cond func() bool) time.Duration {
	f.t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) > 5*time.Second {
			f.t.Fatalf("%s: not within 5 s\n%s", what, f.log)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return time.Since(start)
}

const keysDoc = `{"addr": "127.0.0.1:0", "api_keys": {"file": "%KEYS%"}}`

func TestServeFromFile(t *testing.T) {
	f := startFile(t, keysDoc, fileKeyA+"\n", nil)
	if c := f.status(fileKeyA); c != http.StatusNotFound && c != http.StatusOK && c != http.StatusFailedDependency {
		t.Fatalf("key A: %d", c)
	}
	if c := f.status(fileKeyB); c != http.StatusUnauthorized {
		t.Fatalf("key B before it is configured: %d", c)
	}
	if len(f.log.logged("configuration loaded")) != 1 || len(f.log.logged("listening")) != 1 {
		t.Fatalf("start-up log:\n%s", f.log)
	}

	// Rotating the key file applies within the 5 s the platform promises.
	replace(t, f.keys, fileKeyB+","+fileKeyA)
	took := f.waitFor("key B added", func() bool { return f.status(fileKeyB) != http.StatusUnauthorized })
	t.Logf("key file change applied after %v", took)
	replace(t, f.keys, fileKeyB)
	f.waitFor("key A removed", func() bool { return f.status(fileKeyA) == http.StatusUnauthorized })
	recs := f.log.logged("configuration reloaded")
	if len(recs) != 2 || !reflect.DeepEqual(recs[0]["applied"], []any{"api_keys"}) || recs[0]["on_restart"] != nil {
		t.Fatalf("reload log: %v", recs)
	}

	// An invalid change is refused and the running keys kept: a key too
	// short, then a file that is not JSON, then one without a serve section.
	replace(t, f.keys, "short")
	f.waitFor("short key refused", func() bool {
		return len(f.log.logged("configuration change refused; keeping the running configuration")) == 1
	})
	replace(t, f.config, `{"version": 1, "serve": {`)
	f.waitFor("bad JSON refused", func() bool {
		return len(f.log.logged("configuration change refused; keeping the running configuration")) == 2
	})
	replace(t, f.config, `{"version": 1, "gateway": {}}`)
	f.waitFor("no section refused", func() bool {
		return len(f.log.logged("configuration change refused; keeping the running configuration")) == 3
	})
	refused := f.log.logged("configuration change refused; keeping the running configuration")
	for i, want := range []string{"$.serve.api_keys: key 1 is 5 characters", "invalid JSON", "the file has no serve section"} {
		if msg, _ := refused[i]["error"].(string); !strings.Contains(msg, want) {
			t.Errorf("refusal %d: %q, want %q", i, msg, want)
		}
	}
	if c := f.status(fileKeyB); c == http.StatusUnauthorized {
		t.Fatal("a refused change removed key B")
	}
	if strings.Contains(f.log.String(), fileKeyB) || strings.Contains(f.log.String(), fileKeyA) {
		t.Fatal("an API key reached the log")
	}

	// The log level applies at once: at error, requests are not logged.
	replace(t, f.keys, fileKeyB)
	reloads := len(f.log.logged("configuration reloaded"))
	f.writeConfig(`{"addr": "127.0.0.1:0", "log_level": "error", "api_keys": {"file": "%KEYS%"}}`)
	f.waitFor("log level error", func() bool { return len(f.log.logged("configuration reloaded")) > reloads })
	quiet := len(f.log.logged("request"))
	for range 3 {
		f.status(fileKeyB)
	}
	if n := len(f.log.logged("request")); n != quiet {
		t.Fatalf("%d requests logged at level error", n-quiet)
	}

	// Members that need a restart are named, and the rest applied.
	replace(t, f.keys, fileKeyC)
	f.writeConfig(`{"addr": "127.0.0.1:1", "cache_size": 5, "key_rate": 2, "log_level": "debug", "api_keys": {"file": "%KEYS%"}}`)
	f.waitFor("key C added", func() bool { return f.status(fileKeyC) != http.StatusUnauthorized })
	f.waitFor("requests logged again", func() bool { return len(f.log.logged("request")) > quiet })
	recs = f.log.logged("configuration reloaded")
	last := recs[len(recs)-1]
	if !reflect.DeepEqual(last["applied"], []any{"api_keys", "log_level"}) ||
		!reflect.DeepEqual(last["on_restart"], []any{"addr", "cache_size", "key_rate", "key_burst"}) {
		t.Fatalf("reload log: %v", last)
	}
	if len(f.log.logged("configuration changes apply when authz serve restarts")) != 1 {
		t.Fatalf("restart warning missing:\n%s", f.log)
	}
}

// Clients keep using a key that every version of the file holds while the
// file and its secret change underneath, are rewritten in place, half
// written, broken and fixed: not one request may fail.
func TestServeReloadUnderLoad(t *testing.T) {
	f := startFile(t, keysDoc, fileKeyA+","+fileKeyB, nil)
	var stop atomic.Bool
	var requests, failures atomic.Int64
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 8}}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				req, _ := http.NewRequest(http.MethodGet, "http://"+f.addr+"/v1/schema", nil)
				req.Header.Set("Authorization", "Bearer "+fileKeyA)
				resp, err := client.Do(req)
				requests.Add(1)
				if err != nil || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode >= 500 {
					failures.Add(1)
				}
				if resp != nil {
					resp.Body.Close()
				}
			}
		}()
	}
	others := []string{fileKeyB, fileKeyC}
	for i := range 6 {
		other := others[i%2]
		switch i % 3 {
		case 0:
			replace(t, f.keys, fileKeyA+","+other)
		case 1:
			// In place: a reader can see the file empty or half written.
			fh, err := os.OpenFile(f.keys, os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprint(fh, other+",")
			fh.Sync()
			fmt.Fprint(fh, fileKeyA)
			fh.Close()
		case 2:
			replace(t, f.config, `{"version": 1, "serve": {"addr": `) // broken
			time.Sleep(1200 * time.Millisecond)
			f.writeConfig(keysDoc)
			replace(t, f.keys, other+","+fileKeyA)
		}
		f.waitFor(other+" accepted", func() bool { return f.status(other) != http.StatusUnauthorized })
		f.waitFor("the other key removed", func() bool {
			return f.status(others[(i+1)%2]) == http.StatusUnauthorized
		})
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("%d requests, %d failures, %d reloads, %d refused", requests.Load(), failures.Load(),
		len(f.log.logged("configuration reloaded")), len(f.log.logged("configuration change refused; keeping the running configuration")))
	if failures.Load() != 0 {
		t.Fatalf("%d of %d requests failed", failures.Load(), requests.Load())
	}
}

func TestServeFileStartErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o600)
		return p
	}
	for name, c := range map[string]struct {
		path string
		want string
	}{
		"missing":    {filepath.Join(dir, "nope.json"), "no such file"},
		"no section": {write("empty.json", `{"version": 1, "mcp": {}}`), "the file has no serve section"},
		"problems":   {write("bad.json", `{"version": 1, "serve": {"addr": "x", "api_keys": {"env": "NOPE_KEYS"}}}`), "$.serve.addr"},
		"typo":       {write("typo.json", `{"version": 1, "serv": {}}`), `did you mean \"serve\"`},
	} {
		err := serve(context.Background(), env(nil), c.path, &bytes.Buffer{}, nil)
		if err == nil || !strings.Contains(fmt.Sprintf("%q", err.Error()), c.want) {
			t.Errorf("%s: %v, want %s", name, err, c.want)
		}
	}
}

// Run takes the file from -config or AUTHZ_CONFIG, and the file's
// AUTHZ_SERVE_ overrides apply; GRANTD_ variables are ignored with a file,
// and the log says so.
func TestRunConfigFlagAndEnv(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "authz.json")
	os.WriteFile(file, []byte(`{"version": 1, "serve": {"addr": "127.0.0.1:0"}}`), 0o600)
	vars := map[string]string{"AUTHZ_SERVE_API_KEYS": fileKeyA, "GRANTD_API_KEYS": "short", "GRANTD_ADDR": "nope"}
	for _, c := range []struct {
		args []string
		env  map[string]string
	}{
		{[]string{"-config", file}, vars},
		{nil, map[string]string{"AUTHZ_CONFIG": file, "AUTHZ_SERVE_API_KEYS": fileKeyA, "GRANTD_ADDR": "nope"}},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		var logs, errb syncBuffer
		code := Run(ctx, c.args, env(c.env), nil, &logs, &errb)
		cancel()
		if code != 0 || errb.String() != "" {
			t.Fatalf("%v: exit %d, %q\n%s", c.args, code, errb.String(), logs.String())
		}
		ign := logs.logged("GRANTD_ variables are ignored with a configuration file; use its AUTHZ_SERVE_ overrides")
		if len(ign) != 1 || !strings.Contains(fmt.Sprint(ign[0]["ignored"]), "GRANTD_ADDR") {
			t.Fatalf("%v: no warning about GRANTD_ variables:\n%s", c.args, logs.String())
		}
	}
	var errb bytes.Buffer
	if code := Run(context.Background(), []string{"-config", filepath.Join(dir, "missing.json")}, env(nil), nil, &bytes.Buffer{}, &errb); code != 1 ||
		!strings.HasPrefix(errb.String(), "authz serve: config:") {
		t.Fatalf("missing file: exit %d, %q", code, errb.String())
	}
}

// The section starts the server exactly as the GRANTD_ variables with the
// same values do.
func TestSettingsMatchGrantdVariables(t *testing.T) {
	sc := pcfg.MustSchema(Section())
	tf := httpservertest.Write(t)
	for _, c := range []struct {
		doc  string
		vars map[string]string
	}{
		{`{}`, map[string]string{}},
		{`{"addr": ":9", "data_dir": "/d", "cache_size": 0, "retention": 5, "log_level": "debug", "audit_log": "/a",
		   "key_rate": 2.5, "token_key": {"env": "TK"}}`,
			map[string]string{"GRANTD_ADDR": ":9", "GRANTD_DATA_DIR": "/d", "GRANTD_CACHE_SIZE": "0", "GRANTD_RETENTION": "5",
				"GRANTD_LOG_LEVEL": "debug", "GRANTD_AUDIT_LOG": "/a", "GRANTD_KEY_RATE": "2.5", "GRANTD_TOKEN_KEY": hexKeyB + "," + hexKeyA}},
		{`{"key_rate": 0.25, "key_burst": 9}`, map[string]string{"GRANTD_KEY_RATE": "0.25", "GRANTD_KEY_BURST": "9"}},
		{`{"drain_delay": "2s", "drain_timeout": "40s"}`, map[string]string{"GRANTD_DRAIN_DELAY": "2s", "GRANTD_DRAIN_TIMEOUT": "40s"}},
		{`{"tls_cert": "` + tf.CertFile + `", "tls_key": "` + tf.KeyFile + `", "tls_client_ca": "` + tf.CertFile + `"}`,
			map[string]string{"GRANTD_TLS_CERT": tf.CertFile, "GRANTD_TLS_KEY": tf.KeyFile, "GRANTD_TLS_CLIENT_CA": tf.CertFile}},
	} {
		r := sc.Check([]byte(`{"version": 1, "serve": `+c.doc+`}`), []string{"AUTHZ_SERVE_API_KEYS=" + sectionKey, "TK=" + hexKeyB + "," + hexKeyA})
		if err := r.Problems.Err(); err != nil {
			t.Fatalf("%s: %v", c.doc, err)
		}
		got, err := settingsConfig(pcfg.Get[Settings](r.Config, SectionName))
		if err != nil {
			t.Fatal(err)
		}
		c.vars["GRANTD_API_KEYS"] = sectionKey
		want, err := loadConfig(env(c.vars))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n file %+v\n vars %+v", c.doc, got, want)
		}
	}
}

func TestSectionKeyLimit(t *testing.T) {
	sc := pcfg.MustSchema(Section())
	for doc, want := range map[string]string{
		`{"key_rate": -1}`:                          "$.serve.key_rate: must not be negative (0 sets no limit)",
		`{"key_burst": -1}`:                         "$.serve.key_burst: must not be negative (0 means the rate rounded up)",
		`{"key_burst": 3}`:                          "$.serve.key_burst: needs key_rate",
		`{"key_rate": "fast"}`:                      "$.serve.key_rate: must be a number, not a string",
		`{"key_rate": 0.5, "key_burst": 1}`:         "",
		`{"key_rate": 1e300, "key_burst": 0}`:       "",
		`{"tls_cert": "/c"}`:                        "$.serve.tls_cert: tls_cert and tls_key must be set together",
		`{"tls_client_ca": "/c"}`:                   "$.serve.tls_client_ca: needs tls_cert and tls_key",
		`{"tls_cert": "/nope", "tls_key": "/nope"}`: "$.serve.tls_cert:",
		`{"drain_delay": "2h"}`:                     "$.serve.drain_delay: must be at most 1h",
		`{"drain_timeout": "0s"}`:                   "$.serve.drain_timeout: must be more than 0s and at most 1h",
	} {
		r := sc.Check([]byte(`{"version": 1, "serve": `+doc+`}`), []string{"AUTHZ_SERVE_API_KEYS=" + sectionKey})
		if got := fmt.Sprint(r.Problems.Err()); (want == "" && got != "<nil>") || (want != "" && !strings.HasPrefix(got, want)) {
			t.Errorf("%s: %s, want %q", doc, got, want)
		}
	}
	r := sc.Check([]byte(`{"version": 1, "serve": {"key_rate": 1e300}}`), []string{"AUTHZ_SERVE_API_KEYS=" + sectionKey})
	c, err := settingsConfig(pcfg.Get[Settings](r.Config, SectionName))
	if err != nil || c.keyLimit.Burst != 1<<31-1 {
		t.Fatalf("a huge rate: burst %d, %v", c.keyLimit.Burst, err)
	}
}

func TestRestartOnly(t *testing.T) {
	base := config{addr: ":1", dataDir: "/d", tokenKey: []byte("a"), oldTokens: [][]byte{[]byte("b")}, cacheSize: 1,
		retention: 1, auditLog: "/a"}
	base.keyLimit.Rate, base.keyLimit.Burst = 1, 1
	if got := restartOnly(base, base); got != nil {
		t.Fatalf("no change: %q", got)
	}
	other := config{addr: ":2", dataDir: "/e", tokenKey: []byte("a"), cacheSize: 2, retention: 2, auditLog: "/b",
		apiKeys: []string{"ignored"}}
	other.keyLimit.Rate, other.keyLimit.Burst = 2, 2
	other.http.TLS = &httpserver.TLSFiles{CertFile: "c", KeyFile: "k"}
	other.http.DrainDelay = time.Second
	want := []string{"addr", "data_dir", "token_key", "cache_size", "retention", "audit_log", "key_rate", "key_burst", "tls", "drain"}
	if got := restartOnly(base, other); !reflect.DeepEqual(got, want) {
		t.Fatalf("every change: %q", got)
	}
}

func TestSettingsConfigErrors(t *testing.T) {
	for _, c := range []struct {
		s    Settings
		want string
	}{
		{Settings{}, "$.serve.api_keys holds no key"},
		{Settings{APIKeys: secret(t, sectionKey), TokenKey: secret(t, "zz")}, "$.serve.token_key: entry 1 is not 64 hex characters"},
		{Settings{APIKeys: secret(t, sectionKey), LogLevel: "loud"}, "$.serve.log_level:"},
	} {
		if _, err := settingsConfig(&c.s); err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %s", c.s, err, c.want)
		}
	}
}

// secret returns a Secret holding v, as an AUTHZ_ override sets it.
func secret(t *testing.T, v string) pcfg.Secret {
	t.Helper()
	type one struct {
		S pcfg.Secret `json:"s"`
	}
	r := pcfg.MustSchema(pcfg.NewSection[one]("x", nil, nil)).Check([]byte(`{"version": 1}`), []string{"AUTHZ_X_S=" + v})
	return pcfg.Get[one](r.Config, "x").S
}
