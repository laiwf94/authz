package gateway

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Run and Wicket are the same command under two names: help, the helpers
// and check behave alike and name the program they were called as.
func TestRunNames(t *testing.T) {
	dir := t.TempDir()
	cfg := writeConfig(t, dir)
	for _, tc := range []struct {
		prog string
		run  func(context.Context, []string, func(string) string, io.Reader, io.Writer, io.Writer) int
	}{
		{"authz gateway", Run},
		{"wicket", Wicket},
	} {
		call := func(e map[string]string, args ...string) (int, string, string) {
			var out, errb bytes.Buffer
			code := tc.run(context.Background(), args, env(e), strings.NewReader(""), &out, &errb)
			return code, out.String(), errb.String()
		}
		for _, h := range []string{"-h", "-help", "--help", "help"} {
			if code, _, errb := call(nil, h); code != 0 || !strings.HasPrefix(errb, "usage: "+tc.prog+"\n") ||
				!strings.Contains(errb, "WICKET_TRUSTED_PROXIES") {
				t.Errorf("%s %s: %d %q", tc.prog, h, code, errb)
			}
		}
		if code, out, _ := call(nil, "genkey"); code != 0 || len(strings.TrimSpace(out)) != 64 {
			t.Errorf("%s genkey: %d %q", tc.prog, code, out)
		}
		if code, out, _ := call(nil, "gensigningkey"); code != 0 || !strings.Contains(out, "BEGIN PRIVATE KEY") {
			t.Errorf("%s gensigningkey: %d %q", tc.prog, code, out)
		}
		for _, bad := range []string{"nope", "-no-such-flag", "serve"} {
			want := tc.prog + `: unknown command "` + bad + `"`
			if code, _, errb := call(nil, bad); code != 2 || !strings.HasPrefix(errb, want) || !strings.Contains(errb, tc.prog+" -h") {
				t.Errorf("%s %s: %d %q", tc.prog, bad, code, errb)
			}
		}
		if code, out, _ := call(map[string]string{"CORP_SECRET": "s"}, "check", cfg); code != checkOK || !strings.Contains(out, ": ok,") {
			t.Errorf("%s check: %d %q", tc.prog, code, out)
		}
		if code, _, errb := call(nil, "check", "-h"); code != checkOK || !strings.HasPrefix(errb, "usage: "+tc.prog+" check ") {
			t.Errorf("%s check -h: %d %q", tc.prog, code, errb)
		}
		for args, want := range map[string]string{
			"":              tc.prog + " check: name a config file or set WICKET_CONFIG\n",
			"-timeout 0s x": tc.prog + " check: -timeout must be between 1ns and 5m\n",
		} {
			if code, _, errb := call(nil, append([]string{"check"}, strings.Fields(args)...)...); code != checkUsage || errb != want {
				t.Errorf("%s check %s: %d %q", tc.prog, args, code, errb)
			}
		}
		// A gateway that cannot start exits 1 with the reason.
		if code, _, errb := call(nil); code != 1 || errb != tc.prog+": WICKET_CONFIG is required\n" {
			t.Errorf("%s without config: %d %q", tc.prog, code, errb)
		}
	}
}

// With no arguments the command serves until its context ends and exits 0;
// a SIGHUP before that reloads instead of stopping it.
func TestRunServes(t *testing.T) {
	dir := t.TempDir()
	e := map[string]string{"WICKET_CONFIG": writeConfig(t, dir), "WICKET_COOKIE_KEYS": cookieKey, "CORP_SECRET": "s",
		"WICKET_ADDR": "127.0.0.1:0", "WICKET_ADMIN_ADDR": "127.0.0.1:0"}
	ctx, cancel := context.WithCancel(context.Background())
	logs := &syncBuf{}
	done := make(chan int, 1)
	hup := make(chan os.Signal, 1)
	go func() { done <- cli(ctx, "authz gateway", nil, env(e), logs, io.Discard, hup) }()
	hup <- syscall.SIGHUP
	waitFor(t, func() bool { return strings.Count(logs.String(), `"event":"config_loaded"`) >= 2 })
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d\n%s", code, logs.String())
	}

	// Run itself subscribes to SIGHUP: a stopped context still exits 0
	// after binding both listeners.
	stopped, stop := context.WithCancel(context.Background())
	stop()
	var errb bytes.Buffer
	if code := Run(stopped, nil, env(e), nil, io.Discard, &errb); code != 0 {
		t.Fatalf("Run: exit %d %q", code, errb.String())
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 500 && !cond(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met in 5s")
	}
}
