package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const gatewayCookieKey = "0011223344556677889900112233445566778899001122334455667788990011"

// logLines collects JSON log lines from a child's pipe on a channel, so a
// test can wait for one event and then for the next.
func logLines(r io.Reader) <-chan map[string]any {
	ch := make(chan map[string]any, 64)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				ch <- m
			}
		}
	}()
	return ch
}

// waitLog returns the first line whose field key equals value.
func waitLog(t *testing.T, ch <-chan map[string]any, key, value string) map[string]any {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case m, ok := <-ch:
			if !ok {
				t.Fatalf("exited before logging %s=%s", key, value)
			}
			if m[key] == value {
				return m
			}
		case <-deadline:
			t.Fatalf("no %s=%s in the log", key, value)
		}
	}
}

// startChild runs main in a child process with argv0 as its program name
// and the args, and returns its stdout or stderr log lines.
func startChild(t *testing.T, argv0, args string, logOnStderr bool, extraEnv ...string) (*exec.Cmd, <-chan map[string]any) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), append([]string{"AUTHZ_TEST_MAIN_ARGS=" + args, "AUTHZ_TEST_MAIN_ARGV0=" + argv0}, extraEnv...)...)
	var r io.Reader
	var err error
	if logOnStderr {
		cmd.Stdout = os.Stderr
		r, err = cmd.StderrPipe()
	} else {
		cmd.Stderr = os.Stderr
		r, err = cmd.StdoutPipe()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd, logLines(r)
}

func writeGatewayConfig(t *testing.T, dir string) string {
	t.Helper()
	cfg := `{"public_url": "https://auth.example.com",
	  "providers": [{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "CORP_SECRET"}],
	  "apps": [{"id": "app", "hosts": ["app.example.com"], "providers": ["corp"], "allow": {"any_user": true}}]}`
	p := filepath.Join(dir, "wicket.json")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// An existing wicket deployment's environment starts "authz gateway" and,
// through a "wicket" symlink, the old command name, with the real signal
// wiring: forward-auth answers, SIGHUP reloads the config file, and SIGTERM
// stops cleanly with exit 0.
func TestMainGateway(t *testing.T) {
	for _, tc := range []struct{ argv0, args string }{
		{"authz", "gateway"},
		{"/usr/local/bin/wicket", ""},
	} {
		t.Run(filepath.Base(tc.argv0), func(t *testing.T) {
			dir := t.TempDir()
			env := []string{"WICKET_CONFIG=" + writeGatewayConfig(t, dir), "WICKET_COOKIE_KEYS=" + gatewayCookieKey,
				"WICKET_ADDR=127.0.0.1:0", "WICKET_ADMIN_ADDR=127.0.0.1:0", "WICKET_SESSION_FILE=" + filepath.Join(dir, "s.log"),
				"WICKET_SIGNING_KEYS=", "WICKET_ADMIN_TOKEN=", "CORP_SECRET=s"}
			if tc.args == "" {
				// An empty value would run the tests instead of main.
				tc.args = " "
			}
			cmd, logs := startChild(t, tc.argv0, tc.args, false, env...)
			waitLog(t, logs, "event", "config_loaded")
			addr := waitLog(t, logs, "msg", "listening")["addr"].(string)

			auth := func() int {
				t.Helper()
				req, _ := http.NewRequest("GET", "http://"+addr+"/auth", nil)
				req.Header.Set("X-Forwarded-Host", "app.example.com")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				return resp.StatusCode
			}
			if code := auth(); code != http.StatusUnauthorized {
				t.Fatalf("forward-auth without a session: %d, want 401", code)
			}
			if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
				t.Fatal(err)
			}
			waitLog(t, logs, "event", "config_loaded")
			if code := auth(); code != http.StatusUnauthorized {
				t.Fatalf("after SIGHUP: %d, want 401", code)
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			waitLog(t, logs, "msg", "shutting down")
			if err := waitExit(t, cmd); err != nil {
				t.Fatalf("exited with %v, want a clean exit 0", err)
			}
		})
	}
}

// The wicket name keeps wicket's helpers and their output.
func TestMainWicketName(t *testing.T) {
	dir := t.TempDir()
	cfg := writeGatewayConfig(t, dir)
	run := func(args string, extraEnv ...string) (int, string, string) {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), append([]string{"AUTHZ_TEST_MAIN_ARGS=" + args, "AUTHZ_TEST_MAIN_ARGV0=wicket"}, extraEnv...)...)
		var out, errb strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, out.String(), errb.String()
	}
	if code, out, _ := run("genkey"); code != 0 || len(strings.TrimSpace(out)) != 64 {
		t.Fatalf("wicket genkey: %d %q", code, out)
	}
	if code, out, _ := run("gensigningkey"); code != 0 || !strings.HasPrefix(out, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("wicket gensigningkey: %d %q", code, out)
	}
	if code, out, _ := run("check", "WICKET_CONFIG="+cfg, "CORP_SECRET=s"); code != 0 ||
		out != cfg+": ok, 1 provider and 1 app, 0 warnings (offline checks)\n" {
		t.Fatalf("wicket check: %d %q", code, out)
	}
	if code, _, errb := run("check -h"); code != 0 || !strings.HasPrefix(errb, "usage: wicket check ") {
		t.Fatalf("wicket check -h: %d %q", code, errb)
	}
	if code, _, errb := run("-h"); code != 0 || !strings.HasPrefix(errb, "usage: wicket\n") {
		t.Fatalf("wicket -h: %d %q", code, errb)
	}
	if code, _, errb := run("serve"); code != exitUsage || !strings.HasPrefix(errb, `wicket: unknown command "serve"`) {
		t.Fatalf("wicket serve: %d %q", code, errb)
	}
	if code, _, errb := run(" ", "WICKET_CONFIG="); code != 1 || errb != "wicket: WICKET_CONFIG is required\n" {
		t.Fatalf("wicket without config: %d %q", code, errb)
	}
}

// "authz fakeidp" writes demo certificates and serves OpenID Connect and
// SAML metadata over TLS with them until SIGTERM.
func TestMainFakeIdP(t *testing.T) {
	dir := t.TempDir()
	gencert := exec.Command(os.Args[0], "-test.run=^$")
	gencert.Env = append(os.Environ(), "AUTHZ_TEST_MAIN_ARGS=fakeidp gencert -dir "+dir+" -hosts 127.0.0.1")
	if out, err := gencert.CombinedOutput(); err != nil {
		t.Fatalf("gencert: %v %s", err, out)
	}
	cfg := filepath.Join(dir, "fakeidp.json")
	if err := os.WriteFile(cfg, []byte(`{"issuer":"https://127.0.0.1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd, logs := startChild(t, "authz", fmt.Sprintf("fakeidp -config %s -addr 127.0.0.1:0 -tls-cert %s -tls-key %s",
		cfg, filepath.Join(dir, "tls.pem"), filepath.Join(dir, "tls-key.pem")), true)
	addr := waitLog(t, logs, "msg", "fakeidp listening")["addr"].(string)
	client := tlsClient(t, filepath.Join(dir, "ca.pem"))
	resp, err := client.Get("https://" + addr + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var disc struct{ Issuer string }
	err = json.NewDecoder(resp.Body).Decode(&disc)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || disc.Issuer != "https://127.0.0.1" {
		t.Fatalf("discovery: %d %+v %v", resp.StatusCode, disc, err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitExit(t, cmd); err != nil {
		t.Fatalf("fakeidp exited with %v, want a clean exit 0", err)
	}
}
