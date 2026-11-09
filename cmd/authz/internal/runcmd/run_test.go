package runcmd

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/httpserver"
	"github.com/laiwf94/authz/internal/platform/httpserver/httpservertest"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// syncBuffer is a log output several parts write to at once.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

const apiKey = "runcmd-test-key-0123456"

var serveVars = map[string]string{"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": apiKey}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func TestUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		vars map[string]string
		code int
		want string
	}{
		{"help", []string{"-h"}, nil, 0, "usage: authz run"},
		{"unknown flag", []string{"-nope"}, nil, 2, "flag provided but not defined"},
		{"argument", []string{"serve"}, nil, 2, `unexpected argument "serve"`},
		{"unknown part", []string{"-parts", "serve,ctl"}, nil, 2, `unknown part "ctl"`},
		{"empty part", []string{"-parts", ""}, nil, 2, `unknown part ""`},
		{"twice", []string{"-parts", "mcp, serve,mcp"}, nil, 2, "mcp is listed twice"},
		{"own tls", nil, map[string]string{"GRANTD_TLS_CERT": "c.pem"}, 2, "GRANTD_TLS_CERT is set; the parts share one listener group, so set AUTHZ_TLS_CERT instead"},
		{"own drain", nil, map[string]string{"AUTHZ_MCP_DRAIN_DELAY": "1s"}, 2, "set AUTHZ_DRAIN_DELAY instead"},
		{"shared drain", nil, map[string]string{"AUTHZ_DRAIN_DELAY": "soon"}, 2, "AUTHZ_DRAIN_DELAY must be a duration"},
		{"shared tls", nil, map[string]string{"AUTHZ_TLS_KEY": "k.pem"}, 2, "AUTHZ_TLS_CERT and AUTHZ_TLS_KEY must be set together"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if code := Run(context.Background(), tc.args, env(tc.vars), nil, io.Discard, &stderr); code != tc.code {
				t.Fatalf("exit %d, want %d: %s", code, tc.code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr %q lacks %q", stderr.String(), tc.want)
			}
		})
	}
	parts, err := parseParts(" mcp,gateway , serve")
	if err != nil || strings.Join(parts, ",") != "serve,gateway,mcp" {
		t.Fatalf("parts join in a fixed order: %v %v", parts, err)
	}
}

// One part over the shared group's TLS: the listener serves HTTPS with
// AUTHZ_TLS_*, the readiness probe flips for AUTHZ_DRAIN_DELAY, and run
// returns nil after the drain with a stopped line.
func TestSharedTLSAndDrain(t *testing.T) {
	tf := httpservertest.Write(t)
	vars := map[string]string{"AUTHZ_TLS_CERT": tf.CertFile, "AUTHZ_TLS_KEY": tf.KeyFile, "AUTHZ_DRAIN_DELAY": "400ms"}
	opts, err := httpserver.FromEnv(env(vars), Prefix)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &syncBuffer{}
	readyc := make(chan *httpserver.Shared, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"serve"}, opts, env(serveVars), "", logs, nil, func(s *httpserver.Shared) { readyc <- s })
	}()
	var shared *httpserver.Shared
	select {
	case shared = <-readyc:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("did not start")
	}
	base := "https://" + shared.Addrs()[0]
	get := func(path string) int {
		t.Helper()
		req, _ := http.NewRequest("GET", base+path, nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := tf.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("/readyz"); code != 200 {
		t.Fatalf("readyz over TLS: %d", code)
	}
	if code := get("/metrics"); code != 200 {
		t.Fatalf("metrics: %d", code)
	}
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for get("/readyz") != 503 {
		if time.Now().After(deadline) {
			t.Fatal("readyz did not flip")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if code := get("/v1/schema"); code >= 500 { // 424 until a schema is written
		t.Fatalf("a request during the drain delay: %d", code)
	}
	if err := <-done; err != nil {
		t.Fatalf("run: %v\n%s", err, logs)
	}
	out := logs.String()
	for _, want := range []string{`"subcommand":"run"`, `"msg":"running"`, `"tls":true`, `"subcommand":"serve"`, `"msg":"stopped"`} {
		if !strings.Contains(out, want) {
			t.Errorf("logs lack %s:\n%s", want, out)
		}
	}
}

// A part that cannot start stops the others before anything is bound:
// run reports that part's error once, the other part's listener was
// never bound, and Run exits 1.
func TestPartFailsToStart(t *testing.T) {
	addr := freeAddr(t)
	vars := map[string]string{"GRANTD_ADDR": addr, "GRANTD_API_KEYS": apiKey} // mcp has no configuration
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"-parts", "serve,mcp"}, env(vars), nil, io.Discard, &stderr); code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "authz run: mcp: ") || !strings.Contains(lines[0], "is required") {
		t.Fatalf("stderr: %q, want one line about mcp", stderr.String())
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("serve's address was left bound: %v", err)
	}
	ln.Close()

	// The same through run: one error, naming the part.
	err = run(context.Background(), []string{"serve", "mcp"}, httpserver.Options{}, env(vars), "", io.Discard, nil, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "mcp: ") || strings.Contains(err.Error(), "\n") {
		t.Fatalf("run: %v", err)
	}
}

// A part's own TLS settings, which Run refuses up front, are refused by
// the shared group too, when they come another way (here run itself; a
// section's tls_cert reaches the group the same way).
func TestOwnTLSRefusedByTheGroup(t *testing.T) {
	tf := httpservertest.Write(t)
	vars := map[string]string{"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": apiKey,
		"GRANTD_TLS_CERT": tf.CertFile, "GRANTD_TLS_KEY": tf.KeyFile}
	err := run(context.Background(), []string{"serve"}, httpserver.Options{}, env(vars), "", io.Discard, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "serve: httpserver: the api listener is in a shared group") {
		t.Fatalf("run: %v", err)
	}
}

// Run with a context that has already ended starts nothing and exits 0.
func TestRunStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stderr bytes.Buffer
	if code := Run(ctx, []string{"-parts", "serve"}, env(serveVars), nil, io.Discard, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

// SIGHUP reaches the gateway, which reloads its configuration file, and a
// configuration file named by AUTHZ_CONFIG is the one the parts read.
func TestHUPReloadsTheGateway(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"public_url": "https://auth.example.com",
	  "providers": [{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "CORP_SECRET"}],
	  "apps": [{"id": "app", "hosts": ["app.example.com"], "providers": ["corp"], "allow": {"any_user": true}}]}`
	path := filepath.Join(dir, "wicket.json")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"WICKET_CONFIG": path, "WICKET_ADDR": "127.0.0.1:0", "WICKET_ADMIN_ADDR": "127.0.0.1:0",
		"WICKET_COOKIE_KEYS": strings.Repeat("ab", 32), "CORP_SECRET": "s"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &syncBuffer{}
	hup := make(chan os.Signal, 1)
	readyc := make(chan *httpserver.Shared, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"gateway"}, httpserver.Options{}, env(vars), "", logs, hup, func(s *httpserver.Shared) { readyc <- s })
	}()
	select {
	case <-readyc:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("did not start")
	}
	loaded := func() int { return strings.Count(logs.String(), `"event":"config_loaded"`) }
	before := loaded()
	hup <- syscall.SIGHUP
	deadline := time.Now().Add(5 * time.Second)
	for loaded() == before {
		if time.Now().After(deadline) {
			t.Fatalf("SIGHUP did not reload the gateway:\n%s", logs)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// With AUTHZ_CONFIG and no gateway section, the gateway refuses to
	// start: the file, not WICKET_CONFIG, is what it reads.
	file := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(file, []byte(`{"version": 1, "serve": {"addr": "127.0.0.1:0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	vars["AUTHZ_CONFIG"] = file
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"-parts", "gateway"}, env(vars), nil, io.Discard, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "authz run: gateway: ") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}
