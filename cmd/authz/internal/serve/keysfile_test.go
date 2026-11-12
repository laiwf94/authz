package serve

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/keys"
)

func TestKeysFileVariables(t *testing.T) {
	base := map[string]string{"GRANTD_API_KEYS": "k"}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	c, err := loadConfig(env(with("GRANTD_KEYS_FILE", "/k.json", "GRANTD_DATA_DIR", "/d")))
	if err != nil {
		t.Fatalf("keys file instead of a token key with a data directory: %v", err)
	}
	if c.keysFile != "/k.json" || c.tokenPolicy != DefaultTokenPolicy || c.tokenKey != nil {
		t.Fatalf("config %+v", c)
	}
	c, err = loadConfig(env(with("GRANTD_KEYS_FILE", "/k.json", "GRANTD_TOKEN_ROTATE_EVERY", "1h", "GRANTD_TOKEN_OVERLAP", "3h")))
	if err != nil || c.tokenPolicy != (keys.Policy{RotateEvery: time.Hour, Overlap: 3 * time.Hour}) {
		t.Fatalf("policy %+v %v", c.tokenPolicy, err)
	}
	if c, err = loadConfig(env(with("GRANTD_TOKEN_ROTATE_EVERY", "0s"))); err != nil || c.tokenPolicy.RotateEvery != 0 {
		t.Fatalf("no rotation: %+v %v", c.tokenPolicy, err)
	}
	for want, vars := range map[string]map[string]string{
		"set GRANTD_TOKEN_KEY or GRANTD_KEYS_FILE, not both":      with("GRANTD_KEYS_FILE", "/k", "GRANTD_TOKEN_KEY", keyA),
		`GRANTD_TOKEN_ROTATE_EVERY must be a duration such as`:    with("GRANTD_TOKEN_ROTATE_EVERY", "daily"),
		`GRANTD_TOKEN_OVERLAP must be a duration such as "24h"`:   with("GRANTD_TOKEN_OVERLAP", "-1h"),
		"GRANTD_TOKEN_ROTATE_EVERY, GRANTD_TOKEN_OVERLAP: a ring": with("GRANTD_TOKEN_OVERLAP", "0s"),
		"GRANTD_TOKEN_ROTATE_EVERY, GRANTD_TOKEN_OVERLAP: rotat":  with("GRANTD_TOKEN_ROTATE_EVERY", "10ms"),
		"GRANTD_TOKEN_KEY is required with GRANTD_DATA_DIR":       with("GRANTD_DATA_DIR", "/d"),
	} {
		if _, err := loadConfig(env(vars)); err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("%v: %v, want %q", vars, err, want)
		}
	}
	got := grantdVars(env(with("GRANTD_KEYS_FILE", "/k", "GRANTD_TOKEN_ROTATE_EVERY", "1h", "GRANTD_TOKEN_OVERLAP", "2h")))
	if !reflect.DeepEqual(got, []string{"GRANTD_API_KEYS", "GRANTD_KEYS_FILE", "GRANTD_TOKEN_OVERLAP", "GRANTD_TOKEN_ROTATE_EVERY"}) {
		t.Errorf("grantdVars %v", got)
	}
}

func TestKeysFileSection(t *testing.T) {
	dir := t.TempDir()
	wrong := filepath.Join(dir, "wrong.json")
	f, err := keys.OpenFile(wrong, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Ensure(keys.Spec{Name: keys.RingConsistency, Alg: keys.ES256}); err != nil {
		t.Fatal(err)
	}
	newFile := filepath.Join(dir, "keys.json")
	for name, c := range map[string]struct {
		doc, path, msg string
	}{
		"both":         {`{"keys_file": "` + newFile + `", "token_key": {"env": "T"}}`, "$.serve.token_key", "set token_key or keys_file, not both"},
		"no directory": {`{"keys_file": "` + dir + `/no/keys.json"}`, "$.serve.keys_file", "does not exist and can't be created"},
		"wrong ring":   {`{"keys_file": "` + wrong + `"}`, "$.serve.keys_file", "ring consistency holds ES256 keys, want HS256"},
		"no overlap":   {`{"keys_file": "` + newFile + `", "token_overlap": "0s"}`, "$.serve.token_overlap", "a ring that rotates on schedule needs an overlap"},
		"too long":     {`{"token_rotate_every": "1s", "token_overlap": "1h"}`, "$.serve.token_overlap", "overlap 1h0m0s is longer than 15 rotation periods"},
		"bad duration": {`{"token_rotate_every": "daily"}`, "$.serve.token_rotate_every", "invalid duration"},
		"data dir":     {`{"data_dir": "` + dir + `", "token_overlap": "0s"}`, "$.serve.token_key", "is required with data_dir, so tokens stay valid across restarts (or keys_file"},
	} {
		r := serveSchema(t).Check([]byte(`{"version": 1, "serve": `+c.doc+`}`), []string{"AUTHZ_SERVE_API_KEYS=" + sectionKey, "T=" + hexKeyA})
		if len(r.Problems) == 0 || r.Problems[0].Path != c.path || !strings.Contains(r.Problems[0].Message, c.msg) {
			t.Errorf("%s: %v, want %s: %s", name, r.Problems, c.path, c.msg)
		}
	}
	// A keys file replaces token_key with a data directory, and the check
	// writes nothing.
	r := serveSchema(t).Check([]byte(`{"version": 1, "serve": {"data_dir": "`+dir+`", "keys_file": "`+newFile+`", "token_rotate_every": "1h", "token_overlap": "2h"}}`),
		[]string{"AUTHZ_SERVE_API_KEYS=" + sectionKey})
	if err := r.Problems.Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(newFile); !os.IsNotExist(err) {
		t.Fatalf("the check wrote the keys file: %v", err)
	}
	c, err := settingsConfig(pcfg.Get[Settings](r.Config, SectionName))
	if err != nil || c.keysFile != newFile || c.tokenPolicy != (keys.Policy{RotateEvery: time.Hour, Overlap: 2 * time.Hour}) {
		t.Fatalf("config %+v %v", c, err)
	}

	// The section and the variables agree.
	r = pcfg.MustSchema(Section()).Check([]byte(`{"version": 1, "serve": {"keys_file": "/k.json", "token_rotate_every": "90m", "token_overlap": "10h"}}`),
		[]string{"AUTHZ_SERVE_API_KEYS=" + sectionKey})
	got, err := settingsConfig(pcfg.Get[Settings](r.Config, SectionName))
	if err != nil {
		t.Fatal(err)
	}
	want, err := loadConfig(env(map[string]string{"GRANTD_API_KEYS": sectionKey, "GRANTD_KEYS_FILE": "/k.json",
		"GRANTD_TOKEN_ROTATE_EVERY": "90m", "GRANTD_TOKEN_OVERLAP": "10h"}))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("file %+v\nvars %+v (%v)", got, want, err)
	}

	if got := restartOnly(config{keysFile: "/a", tokenPolicy: DefaultTokenPolicy}, config{keysFile: "/b"}); !reflect.DeepEqual(got, []string{"keys_file", "token_rotation"}) {
		t.Errorf("restartOnly %v", got)
	}
}

// envServer runs "authz serve" from the GRANTD_ variables.
type envServer struct {
	t    *testing.T
	addr string
	log  *syncBuffer
	stop func()
}

func startEnv(t *testing.T, vars map[string]string) *envServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &envServer{t: t, log: &syncBuffer{}}
	addrc := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- run(ctx, env(vars), s.log, func(a string) { addrc <- a }) }()
	select {
	case s.addr = <-addrc:
	case err := <-done:
		cancel()
		t.Fatalf("serve: %v\n%s", err, s.log)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("server did not start")
	}
	stopped := false
	s.stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	}
	t.Cleanup(s.stop)
	return s
}

func (s *envServer) do(method, path, body string) (int, map[string]any) {
	s.t.Helper()
	req, _ := http.NewRequest(method, "http://"+s.addr+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer integration-key-0123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

// readAt reads at least as fresh as tok and returns the status and the
// token of the read.
func (s *envServer) readAt(tok string) (int, string) {
	s.t.Helper()
	code, out := s.do("POST", "/v1/relationships/read",
		`{"filter":{"resource_type":"doc"},"consistency":{"mode":"at_least_as_fresh","token":"`+tok+`"}}`)
	read, _ := out["read_at"].(string)
	return code, read
}

func currentKid(t *testing.T, path string) string {
	t.Helper()
	s, err := keys.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return s.Ring(keys.RingConsistency).Current().ID()
}

// A process on a keys file rotates its consistency ring while it serves:
// tokens from before a rotation keep reading, across a restart too, until
// the overlap ends.
func TestServeKeysFileRotation(t *testing.T) {
	dir := t.TempDir()
	keysFile := filepath.Join(dir, "keys.json")
	vars := map[string]string{"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": "integration-key-0123",
		"GRANTD_DATA_DIR": filepath.Join(dir, "data"), "GRANTD_KEYS_FILE": keysFile,
		"GRANTD_TOKEN_ROTATE_EVERY": "1s", "GRANTD_TOKEN_OVERLAP": "5s"}
	s := startEnv(t, vars)
	fi, err := os.Stat(keysFile)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("keys file: %v %v", fi, err)
	}
	if strings.Contains(s.log.String(), "using a random key") || len(s.log.logged("consistency tokens on a key ring")) != 1 {
		t.Fatalf("start-up log:\n%s", s.log)
	}
	code, out := s.do("PUT", "/v1/schema", `{"schema":"definition user {}\ndefinition doc { relation viewer: user }"}`)
	if code != 200 {
		t.Fatalf("schema write: %d %v", code, out)
	}
	tokA, _ := out["written_at"].(string)
	kidA := currentKid(t, keysFile)
	waitUntil(t, "a rotation saved to the keys file", func() bool { return currentKid(t, keysFile) != kidA })
	if code, tokB := s.readAt(tokA); code != 200 || tokB == tokA {
		t.Fatalf("token from before the rotation: %d, new token differs: %v", code, tokB != tokA)
	}
	if len(s.log.logged("key ring rotated")) == 0 {
		t.Fatalf("rotation not logged:\n%s", s.log)
	}
	s.stop()

	// A restart inside the overlap keeps the saved keys, so tokA still
	// reads; one started after the overlap refuses it.
	s = startEnv(t, vars)
	if code, _ := s.readAt(tokA); code != 200 {
		t.Fatalf("token from before the restart: %d", code)
	}
	waitUntil(t, "the overlap of the first key to end", func() bool { code, _ := s.readAt(tokA); return code == 400 })
	_, out = s.do("POST", "/v1/relationships/read", `{"filter":{"resource_type":"doc"}}`)
	tokC, _ := out["read_at"].(string)
	if tokC == "" {
		t.Fatal("no token from a fresh read")
	}
	if code, _ := s.readAt(tokC); code != 200 {
		t.Fatalf("fresh token: %d", code)
	}
	if n := len(s.log.logged("key ring check failed; the rings keep their keys")); n != 0 {
		t.Fatalf("%d failed checks:\n%s", n, s.log)
	}
}

// A keys file another process rewrites is not overwritten; the failure is
// logged, and the running rings keep verifying.
func TestServeKeysFileConflict(t *testing.T) {
	dir := t.TempDir()
	keysFile := filepath.Join(dir, "keys.json")
	f := startFile(t, `{"addr": "127.0.0.1:0", "api_keys": {"file": "%KEYS%"}, "keys_file": "`+keysFile+`",
	  "token_rotate_every": "1s", "token_overlap": "5s"}`, fileKeyA, nil)
	if len(f.log.logged("consistency tokens on a key ring")) != 1 {
		t.Fatalf("start-up log:\n%s", f.log)
	}
	other, err := keys.OpenFile(filepath.Join(dir, "other.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Ensure(keys.Spec{Name: keys.RingAgent, Alg: keys.HS256}); err != nil {
		t.Fatal(err)
	}
	theirs, _ := os.ReadFile(filepath.Join(dir, "other.json"))
	if err := os.WriteFile(keysFile, theirs, 0o600); err != nil {
		t.Fatal(err)
	}
	f.waitFor("the conflict to be logged", func() bool {
		return len(f.log.logged("key ring check failed; the rings keep their keys")) > 0
	})
	if b, _ := os.ReadFile(keysFile); string(b) != string(theirs) {
		t.Fatal("the other writer's file was overwritten")
	}
	// No schema yet: 424 is the API answering an authenticated request.
	if code := f.status(fileKeyA); code != http.StatusFailedDependency {
		t.Fatalf("API after the conflict: %d", code)
	}
}

func TestServeKeysFileStartErrors(t *testing.T) {
	dir := t.TempDir()
	wrong := filepath.Join(dir, "wrong.json")
	f, _ := keys.OpenFile(wrong, nil)
	if _, err := f.Ensure(keys.Spec{Name: keys.RingConsistency, Alg: keys.A256GCM}); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(dir, "broken.json")
	os.WriteFile(broken, []byte("{"), 0o600)
	for path, want := range map[string]string{
		wrong:                           "keys file: keys: key does not belong to this ring",
		broken:                          "keys file: " + broken + ": keys: ring file",
		filepath.Join(dir, "no", "k.j"): "keys file: open ",
	} {
		err := run(context.Background(), env(map[string]string{"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": "integration-key-0123",
			"GRANTD_KEYS_FILE": path}), io.Discard, nil)
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("%s: %v, want %q", path, err, want)
		}
	}
}

// waitUntil polls cond for up to 10 s.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within 10 s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Clients reading at the token of their previous read while the ring
// rotates every second: no read fails.
func TestServeKeysFileRotationUnderLoad(t *testing.T) {
	dir := t.TempDir()
	keysFile := filepath.Join(dir, "keys.json")
	s := startEnv(t, map[string]string{"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": "integration-key-0123",
		"GRANTD_KEYS_FILE": keysFile, "GRANTD_TOKEN_ROTATE_EVERY": "1s", "GRANTD_TOKEN_OVERLAP": "5s"})
	if code, out := s.do("PUT", "/v1/schema", `{"schema":"definition user {}\ndefinition doc { relation viewer: user }"}`); code != 200 {
		t.Fatalf("schema write: %d %v", code, out)
	}
	kid0 := currentKid(t, keysFile)
	var (
		mu                      sync.Mutex
		reads, failures, across int
	)
	deadline := time.Now().Add(2500 * time.Millisecond)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			client := &http.Client{Timeout: 5 * time.Second}
			defer client.CloseIdleConnections()
			prev, prevKid := "", ""
			for time.Now().Before(deadline) {
				body := `{"filter":{"resource_type":"doc"}}`
				if prev != "" {
					body = `{"filter":{"resource_type":"doc"},"consistency":{"mode":"at_least_as_fresh","token":"` + prev + `"}}`
				}
				req, _ := http.NewRequest("POST", "http://"+s.addr+"/v1/relationships/read", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer integration-key-0123")
				resp, err := client.Do(req)
				var out map[string]any
				ok := err == nil && resp.StatusCode == 200
				if err == nil {
					ok = ok && json.NewDecoder(resp.Body).Decode(&out) == nil
					resp.Body.Close()
				}
				kid := currentKid(t, keysFile)
				mu.Lock()
				reads++
				if !ok {
					failures++
				}
				if prevKid != "" && kid != prevKid {
					across++
				}
				mu.Unlock()
				prev, _ = out["read_at"].(string)
				prevKid = kid
			}
		})
	}
	wg.Wait()
	if currentKid(t, keysFile) == kid0 {
		t.Fatal("the ring did not rotate during the run")
	}
	t.Logf("%d reads, %d across a rotation, %d failures", reads, across, failures)
	if failures != 0 || across == 0 {
		t.Fatalf("%d of %d reads failed, %d across a rotation", failures, reads, across)
	}
}
