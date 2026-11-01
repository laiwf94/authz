package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
	"time"
)

type recorded struct {
	args  []string
	ctx   context.Context
	stdin io.Reader
}

func fakeCommands(rec *recorded) []command {
	r := func(code int) runFunc {
		return func(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
			rec.args, rec.ctx, rec.stdin = args, ctx, stdin
			if len(args) == 1 && args[0] == "-h" {
				io.WriteString(stderr, "fake help\n")
				return 0
			}
			io.WriteString(stdout, getenv("WHO"))
			return code
		}
	}
	return []command{
		{name: "zeta", summary: "last alphabetically", run: r(0)},
		{name: "alpha", summary: "first alphabetically", run: r(7)},
		{name: "helper", summary: "operator helper", hidden: true, run: r(0)},
		{name: "version", summary: "version", run: r(0)},
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDispatchPassesArgumentsThrough(t *testing.T) {
	var rec recorded
	cmds := fakeCommands(&rec)
	ctx := context.WithValue(context.Background(), struct{}{}, "marker")
	stdin := strings.NewReader("in")
	var out, errb bytes.Buffer
	args := []string{"alpha", "check", "-online", "--", "-x", "file with spaces", ""}
	code := dispatch(ctx, cmds, args, env(map[string]string{"WHO": "me"}), stdin, &out, &errb)
	if code != 7 {
		t.Fatalf("exit code = %d, want the subcommand's own 7", code)
	}
	if !reflect.DeepEqual(rec.args, args[1:]) {
		t.Fatalf("args = %q, want %q untouched", rec.args, args[1:])
	}
	if rec.ctx != ctx || rec.stdin != stdin || out.String() != "me" || errb.Len() != 0 {
		t.Fatalf("ctx, stdin, getenv or output not passed through: out=%q err=%q", out.String(), errb.String())
	}
	// A hidden command still runs.
	if code := dispatch(ctx, cmds, []string{"helper"}, env(nil), nil, io.Discard, io.Discard); code != 0 || len(rec.args) != 0 {
		t.Fatalf("hidden command: code %d args %q", code, rec.args)
	}
}

func TestDispatchHelpAndUsage(t *testing.T) {
	var rec recorded
	cmds := fakeCommands(&rec)
	ctx := context.Background()

	var out, errb bytes.Buffer
	if code := dispatch(ctx, cmds, nil, env(nil), nil, &out, &errb); code != exitUsage || out.Len() != 0 {
		t.Fatalf("no arguments: code %d, stdout %q", code, out.String())
	}
	noArgs := errb.String()
	if !strings.HasPrefix(noArgs, "usage: authz <command>") {
		t.Fatalf("no arguments: usage on stderr = %q", noArgs)
	}

	for _, h := range []string{"help", "-h", "-help", "--help"} {
		out.Reset()
		errb.Reset()
		if code := dispatch(ctx, cmds, []string{h}, env(nil), nil, &out, &errb); code != exitOK || errb.Len() != 0 {
			t.Fatalf("%s: code %d, stderr %q", h, code, errb.String())
		}
		if out.String() != noArgs {
			t.Fatalf("%s: help on stdout differs from the usage error:\n%s\nvs\n%s", h, out.String(), noArgs)
		}
	}
	help := out.String()
	a, z := strings.Index(help, "  alpha    first alphabetically\n"), strings.Index(help, "  zeta     last alphabetically\n")
	if a < 0 || z < 0 || a > z {
		t.Fatalf("commands not listed in aligned, sorted order:\n%s", help)
	}
	if strings.Contains(help, "helper") {
		t.Fatalf("hidden command listed:\n%s", help)
	}

	errb.Reset()
	if code := dispatch(ctx, cmds, []string{"help", "zeta"}, env(nil), nil, &out, &errb); code != 0 || errb.String() != "fake help\n" {
		t.Fatalf("help zeta: code %d, stderr %q", code, errb.String())
	}
	if !reflect.DeepEqual(rec.args, []string{"-h"}) {
		t.Fatalf("help zeta ran with %q, want -h", rec.args)
	}
}

func TestDispatchUnknown(t *testing.T) {
	var rec recorded
	cmds := fakeCommands(&rec)
	cases := map[string][]string{
		`unknown command "nope"`:      {"nope", "x"},
		`unknown command "missing"`:   {"help", "missing"},
		`flag -addr must follow a co`: {"-addr", "x", "alpha"},
	}
	for want, args := range cases {
		var errb bytes.Buffer
		if code := dispatch(context.Background(), cmds, args, env(nil), nil, io.Discard, &errb); code != exitUsage {
			t.Errorf("%q: code %d, want %d", args, code, exitUsage)
		}
		if !strings.Contains(errb.String(), want) {
			t.Errorf("%q: stderr %q, want %q", args, errb.String(), want)
		}
	}
}

func TestDispatchVersionFlag(t *testing.T) {
	var rec recorded
	cmds := fakeCommands(&rec)
	for _, f := range []string{"-version", "--version"} {
		rec.args = []string{"unset"}
		if code := dispatch(context.Background(), cmds, []string{f, "-json"}, env(nil), nil, io.Discard, io.Discard); code != 0 {
			t.Fatalf("%s: code %d", f, code)
		}
		if !reflect.DeepEqual(rec.args, []string{"-json"}) {
			t.Fatalf("%s: version ran with %q", f, rec.args)
		}
	}
}

func TestRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range commands {
		if c.name == "" || c.summary == "" || c.run == nil {
			t.Errorf("incomplete registration: %+v", c)
		}
		if seen[c.name] {
			t.Errorf("command %q registered twice", c.name)
		}
		seen[c.name] = true
		if strings.HasPrefix(c.name, "-") || c.name == "help" {
			t.Errorf("command name %q would be shadowed by the dispatcher", c.name)
		}
		// Every subcommand owns its FlagSet, so -h exits 0 with help on stderr.
		var out, errb bytes.Buffer
		if code := c.run(context.Background(), []string{"-h"}, env(nil), strings.NewReader(""), &out, &errb); code != 0 {
			t.Errorf("%s -h: exit %d", c.name, code)
		}
		if !strings.Contains(errb.String(), "usage: authz "+c.name) {
			t.Errorf("%s -h: help %q does not start with its usage line", c.name, errb.String())
		}
		// Flags the subcommand does not define are usage errors.
		errb.Reset()
		if code := c.run(context.Background(), []string{"-no-such-flag"}, env(nil), strings.NewReader(""), io.Discard, &errb); code != 2 {
			t.Errorf("%s -no-such-flag: exit %d, want 2", c.name, code)
		}
	}
	for _, want := range []string{"serve", "check", "ctl", "version"} {
		if !seen[want] {
			t.Errorf("%s is not registered", want)
		}
	}
}

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runVersion(context.Background(), nil, env(nil), nil, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), "authz ") || !strings.Contains(out.String(), " go1.") {
		t.Fatalf("version = %q", out.String())
	}
	out.Reset()
	if code := runVersion(context.Background(), []string{"-json"}, env(nil), nil, &out, &errb); code != 0 {
		t.Fatalf("-json: exit %d", code)
	}
	var b buildInfo
	if err := json.Unmarshal(out.Bytes(), &b); err != nil || b.Version == "" || b.Go == "" || b.Platform == "" {
		t.Fatalf("-json = %q (%v)", out.String(), err)
	}
	if code := runVersion(context.Background(), []string{"extra"}, env(nil), nil, io.Discard, io.Discard); code != exitUsage {
		t.Fatalf("extra argument: exit %d", code)
	}
}

func TestCurrentBuild(t *testing.T) {
	info := &debug.BuildInfo{GoVersion: "go1.99.1", Main: debug.Module{Version: "v1.2.3"}, Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: "0123456789abcdef0123"},
		{Key: "vcs.time", Value: "2026-11-02T10:00:00Z"},
		{Key: "vcs.modified", Value: "true"},
	}}
	b := currentBuild(func() (*debug.BuildInfo, bool) { return info, true }, "")
	if b.Version != "v1.2.3" || b.Go != "go1.99.1" || !b.Modified {
		t.Fatalf("from build info: %+v", b)
	}
	if s := b.String(); !strings.HasPrefix(s, "authz v1.2.3 (0123456789ab+modified, 2026-11-02T10:00:00Z) go1.99.1 ") {
		t.Fatalf("String = %q", s)
	}
	if b := currentBuild(func() (*debug.BuildInfo, bool) { return info, true }, "v9.0.0"); b.Version != "v9.0.0" {
		t.Fatalf("a stamped version must win: %+v", b)
	}
	if b := currentBuild(func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{}, true }, ""); b.Version != "(devel)" || b.Revision != "" {
		t.Fatalf("empty build info: %+v", b)
	}
	b = currentBuild(func() (*debug.BuildInfo, bool) { return nil, false }, "")
	if b.Version != "unknown" || !strings.HasPrefix(b.String(), "authz unknown go") {
		t.Fatalf("no build info: %+v %q", b, b.String())
	}
}

// The tests below run main itself in a child process (this test binary
// re-executed), so the real signal wiring is what is tested.
func TestMain(m *testing.M) {
	if args := os.Getenv("AUTHZ_TEST_MAIN_ARGS"); args != "" {
		os.Args = append([]string{"authz"}, strings.Fields(args)...)
		main()
		return
	}
	os.Exit(m.Run())
}

func startMain(t *testing.T, args string, extraEnv ...string) (*exec.Cmd, *bufio.Scanner) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), append([]string{"AUTHZ_TEST_MAIN_ARGS=" + args}, extraEnv...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd, bufio.NewScanner(stdout)
}

// waitListening reads serve's JSON log lines until it reports its address.
func waitListening(t *testing.T, sc *bufio.Scanner) {
	t.Helper()
	ok := make(chan bool, 1)
	go func() {
		for sc.Scan() {
			if strings.Contains(sc.Text(), `"msg":"listening"`) {
				ok <- true
				for sc.Scan() { // drain so the child never blocks on a full pipe
				}
				return
			}
		}
		ok <- false
	}()
	select {
	case started := <-ok:
		if !started {
			t.Fatal("serve exited before listening")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not start")
	}
}

func waitExit(t *testing.T, cmd *exec.Cmd) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("process did not exit")
		return nil
	}
}

var serveEnv = []string{"GRANTD_ADDR=127.0.0.1:0", "GRANTD_API_KEYS=main-test-key-0123456", "GRANTD_DATA_DIR=", "GRANTD_TOKEN_KEY="}

func TestMainServeStopsCleanlyOnSIGTERM(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		cmd, sc := startMain(t, "serve", serveEnv...)
		waitListening(t, sc)
		if err := cmd.Process.Signal(sig); err != nil {
			t.Fatal(err)
		}
		if err := waitExit(t, cmd); err != nil {
			t.Fatalf("%v: serve exited with %v, want a clean exit 0", sig, err)
		}
	}
}

// The dispatcher must not catch SIGHUP: subcommands that reload on it
// subscribe themselves, and one that does not keeps the default action.
func TestMainLeavesSIGHUPAlone(t *testing.T) {
	cmd, sc := startMain(t, "serve", serveEnv...)
	waitListening(t, sc)
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	err := waitExit(t, cmd)
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("serve survived SIGHUP (err %v), so something caught it", err)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGHUP {
		t.Fatalf("serve ended with %v, want death by SIGHUP", err)
	}
}

func TestMainExitCodes(t *testing.T) {
	cases := map[string]int{
		"":                exitUsage,
		"nope":            exitUsage,
		"version":         0,
		"serve":           1, // no GRANTD_API_KEYS
		"check -schema":   exitUsage,
		"ctl schema read": exitUsage, // no AUTHZ_API_KEY
	}
	for args, want := range cases {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), "AUTHZ_TEST_MAIN_ARGS="+args, "GRANTD_API_KEYS=", "AUTHZ_API_KEY=")
		if args == "" {
			// An empty value would run the tests instead of main.
			cmd.Env = append(cmd.Env, "AUTHZ_TEST_MAIN_ARGS= ")
		}
		err := cmd.Run()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if code != want {
			t.Errorf("authz %s: exit %d, want %d", args, code, want)
		}
	}
}
