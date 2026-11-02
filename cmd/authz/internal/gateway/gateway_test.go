package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const cookieKey = "0011223344556677889900112233445566778899001122334455667788990011"

func writeConfig(t *testing.T, dir string) string {
	t.Helper()
	cfg := map[string]any{
		"public_url": "https://auth.example.com",
		"providers": []any{map[string]any{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com",
			"client_id": "c", "client_secret_env": "CORP_SECRET"}},
		"apps": []any{map[string]any{"id": "app", "hosts": []string{"app.example.com"}, "providers": []string{"corp"},
			"allow": map[string]any{"any_user": true}}},
	}
	b, _ := json.Marshal(cfg)
	p := filepath.Join(dir, "wicket.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadSettings(t *testing.T) {
	ok := map[string]string{"WICKET_CONFIG": "/c.json", "WICKET_COOKIE_KEYS": cookieKey}
	s, err := loadSettings(env(ok))
	if err != nil || s.addr != ":4180" || s.adminAddr != "127.0.0.1:4181" || len(s.trusted) != 2 {
		t.Fatalf("%+v %v", s, err)
	}
	bad := []map[string]string{
		{},
		{"WICKET_CONFIG": "/c.json"},
		{"WICKET_CONFIG": "/c.json", "WICKET_COOKIE_KEYS": "short"},
		{"WICKET_CONFIG": "/c.json", "WICKET_COOKIE_KEYS": cookieKey, "WICKET_ADMIN_ADDR": ":4181"},
		{"WICKET_CONFIG": "/c.json", "WICKET_COOKIE_KEYS": cookieKey, "WICKET_ADMIN_ADDR": "0.0.0.0:4181"},
		{"WICKET_CONFIG": "/c.json", "WICKET_COOKIE_KEYS": cookieKey, "WICKET_ADMIN_TOKEN": "short"},
		{"WICKET_CONFIG": "/c.json", "WICKET_COOKIE_KEYS": cookieKey, "WICKET_TRUSTED_PROXIES": "nope"},
		{"WICKET_CONFIG": "/c.json", "WICKET_COOKIE_KEYS": cookieKey, "WICKET_LOGIN_RATE": "0"},
		{"WICKET_CONFIG": "/c.json", "WICKET_COOKIE_KEYS": cookieKey, "WICKET_LOG_LEVEL": "loud"},
	}
	for _, m := range bad {
		if _, err := loadSettings(env(m)); err == nil {
			t.Errorf("accepted %v", m)
		}
	}
	full := map[string]string{"WICKET_CONFIG": "/c.json", "WICKET_COOKIE_KEYS": cookieKey + ", " + strings.Repeat("ab", 32),
		"WICKET_ADMIN_ADDR": "0.0.0.0:4181", "WICKET_ADMIN_TOKEN": "admin-token-0123456789", "WICKET_ADDR": ":1",
		"WICKET_TRUSTED_PROXIES": "10.0.0.0/8", "WICKET_LOGIN_RATE": "5", "WICKET_LOG_LEVEL": "debug",
		"WICKET_SIGNING_KEYS": "a.pem, b.pem", "WICKET_SESSION_FILE": "/s.log"}
	s, err = loadSettings(env(full))
	if err != nil || len(s.cookieKeys) != 2 || len(s.signingKeys) != 2 || s.loginRate != 5 || s.addr != ":1" {
		t.Fatalf("%+v %v", s, err)
	}
	for addr, want := range map[string]bool{"127.0.0.1:1": true, "[::1]:1": true, "localhost:1": true, "10.0.0.1:1": false, "nope": false} {
		if isLoopback(addr) != want {
			t.Errorf("isLoopback(%s)", addr)
		}
	}
}

func TestSubcommands(t *testing.T) {
	var out bytes.Buffer
	if err := subcommand("genkey", &out); err != nil || len(strings.TrimSpace(out.String())) != 64 {
		t.Fatalf("genkey %q", out.String())
	}
	out.Reset()
	if err := subcommand("gensigningkey", &out); err != nil || !strings.Contains(out.String(), "BEGIN PRIVATE KEY") {
		t.Fatal("gensigningkey")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "k.pem")
	os.WriteFile(key, out.Bytes(), 0o600)
	if s, err := loadSigners([]string{key}); err != nil || len(s) != 1 {
		t.Fatal(err)
	}
	if err := subcommand("nope", &out); err == nil {
		t.Fatal("unknown command")
	}
	os.WriteFile(filepath.Join(dir, "bad.pem"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, "rsa.pem"), []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600)
	for _, f := range []string{"missing.pem", "bad.pem", "rsa.pem"} {
		if _, err := loadSigners([]string{filepath.Join(dir, f)}); err == nil {
			t.Errorf("%s accepted", f)
		}
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// TestRun starts the real server on ephemeral ports, calls it, reloads it
// with a signal and shuts it down.
func TestRun(t *testing.T) {
	dir := t.TempDir()
	var keyOut bytes.Buffer
	subcommand("gensigningkey", &keyOut)
	os.WriteFile(filepath.Join(dir, "sign.pem"), keyOut.Bytes(), 0o600)
	e := map[string]string{"WICKET_CONFIG": writeConfig(t, dir), "WICKET_COOKIE_KEYS": cookieKey, "CORP_SECRET": "s",
		"WICKET_ADDR": "127.0.0.1:0", "WICKET_ADMIN_ADDR": "127.0.0.1:0", "WICKET_SESSION_FILE": filepath.Join(dir, "s.log"),
		"WICKET_SIGNING_KEYS": filepath.Join(dir, "sign.pem")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hup := make(chan os.Signal, 1)
	addrs := make(chan [2]string, 1)
	logs := &syncBuf{}
	done := make(chan error, 1)
	go func() { done <- run(ctx, env(e), logs, hup, func(p, a string) { addrs <- [2]string{p, a} }) }()
	var a [2]string
	select {
	case a = <-addrs:
	case err := <-done:
		t.Fatal(err)
	}
	get := func(u string) (int, string) {
		resp, err := http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	if code, _ := get("http://" + a[0] + "/healthz"); code != 200 {
		t.Fatal("public health")
	}
	if code, body := get("http://" + a[0] + "/.well-known/jwks.json"); code != 200 || !strings.Contains(body, "ES256") {
		t.Fatal("jwks")
	}
	if code, _ := get("http://" + a[1] + "/admin/sessions"); code != 200 {
		t.Fatal("admin")
	}
	req, _ := http.NewRequest("GET", "http://"+a[0]+"/auth", nil)
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("auth: %d", resp.StatusCode)
	}
	hup <- syscall.SIGHUP
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), `"event":"config_loaded"`+"") || strings.Count(logs.String(), `"event":"config_loaded"`) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("no reload in logs:\n%s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A broken file on reload keeps the running configuration.
	os.WriteFile(e["WICKET_CONFIG"], []byte("{"), 0o600)
	hup <- syscall.SIGHUP
	for !strings.Contains(logs.String(), "reload failed") {
		if time.Now().After(deadline) {
			t.Fatal("failed reload not logged")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunFailures(t *testing.T) {
	dir := t.TempDir()
	cfg := writeConfig(t, dir)
	base := map[string]string{"WICKET_CONFIG": cfg, "WICKET_COOKIE_KEYS": cookieKey, "CORP_SECRET": "s",
		"WICKET_ADDR": "127.0.0.1:0", "WICKET_ADMIN_ADDR": "127.0.0.1:0"}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range base {
			m[a] = b
		}
		m[k] = v
		return m
	}
	for name, e := range map[string]map[string]string{
		"settings":       with("WICKET_COOKIE_KEYS", ""),
		"signing key":    with("WICKET_SIGNING_KEYS", filepath.Join(dir, "missing.pem")),
		"config":         with("WICKET_CONFIG", filepath.Join(dir, "missing.json")),
		"session file":   with("WICKET_SESSION_FILE", filepath.Join(dir, "no", "such", "dir", "s.log")),
		"secret":         with("CORP_SECRET", ""),
		"bad addr":       with("WICKET_ADDR", "256.0.0.1:0"),
		"bad admin addr": with("WICKET_ADMIN_ADDR", "127.0.0.1:99999"),
	} {
		if err := run(context.Background(), env(e), io.Discard, nil, nil); err == nil {
			t.Errorf("%s: started", name)
		}
	}
}
