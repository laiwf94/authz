package serve

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// These tests cover the "authz serve" entry point added around grantd's
// run; serve_test.go is grantd's own suite, moved unchanged.

func TestRunCommandUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"-h"}, env(nil), nil, &out, &errb); code != 0 {
		t.Fatalf("-h: exit %d", code)
	}
	for _, v := range []string{"usage: authz serve", "GRANTD_API_KEYS", "GRANTD_RETENTION", "authz check -serve"} {
		if !strings.Contains(errb.String(), v) {
			t.Errorf("help is missing %q:\n%s", v, errb.String())
		}
	}
	errb.Reset()
	if code := Run(context.Background(), []string{"-addr", ":1"}, env(nil), nil, &out, &errb); code != 2 {
		t.Fatalf("unknown flag: exit %d", code)
	}
	errb.Reset()
	if code := Run(context.Background(), []string{"extra"}, env(nil), nil, &out, &errb); code != 2 ||
		!strings.Contains(errb.String(), `unexpected argument "extra"`) {
		t.Fatalf("positional argument: exit %d, %q", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("usage errors wrote to stdout: %q", out.String())
	}
}

func TestRunCommandExitCodes(t *testing.T) {
	var errb bytes.Buffer
	if code := Run(context.Background(), nil, env(map[string]string{}), nil, &bytes.Buffer{}, &errb); code != 1 ||
		!strings.HasPrefix(errb.String(), "authz serve: GRANTD_API_KEYS is required") {
		t.Fatalf("bad env: exit %d, %q", code, errb.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var logs bytes.Buffer
	errb.Reset()
	code := Run(ctx, nil, env(map[string]string{"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": "integration-key-0123"}), nil, &logs, &errb)
	if code != 0 || errb.Len() != 0 {
		t.Fatalf("clean shutdown: exit %d, %q", code, errb.String())
	}
	// Logs go to stdout, as grantd's did.
	if !strings.Contains(logs.String(), `"msg":"listening"`) || !strings.Contains(logs.String(), `"msg":"shutting down"`) {
		t.Fatalf("logs: %s", logs.String())
	}
}

func TestCheck(t *testing.T) {
	ok := map[string]string{"GRANTD_API_KEYS": "integration-key-0123", "GRANTD_ADDR": "127.0.0.1:0"}
	if errs := Check(env(ok)); len(errs) != 0 {
		t.Fatalf("valid env: %v", errs)
	}
	// A data directory that does not exist yet is fine: the store creates it.
	if errs := Check(env(map[string]string{"GRANTD_API_KEYS": "integration-key-0123", "GRANTD_TOKEN_KEY": key,
		"GRANTD_DATA_DIR": t.TempDir() + "/new"})); len(errs) != 0 {
		t.Fatalf("new data dir: %v", errs)
	}
	file := t.TempDir() + "/f"
	os.WriteFile(file, nil, 0o600)
	errs := Check(env(map[string]string{"GRANTD_API_KEYS": "short,integration-key-0123,tiny", "GRANTD_ADDR": "nope",
		"GRANTD_TOKEN_KEY": key, "GRANTD_DATA_DIR": file}))
	var got []string
	for _, e := range errs {
		got = append(got, e.Error())
	}
	want := []string{
		"GRANTD_API_KEYS: key 1 is 5 characters; each key must be at least 16",
		"GRANTD_API_KEYS: key 3 is 4 characters; each key must be at least 16",
		"GRANTD_ADDR: address nope: missing port in address",
		"GRANTD_DATA_DIR: " + file + " exists and is not a directory",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("errors:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Every key Check accepts, run accepts too, and the reverse.
	for _, k := range []string{"0123456789abcde", "0123456789abcdef"} {
		e := env(map[string]string{"GRANTD_API_KEYS": k, "GRANTD_ADDR": "127.0.0.1:0"})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		runErr := run(ctx, e, &bytes.Buffer{}, nil)
		if (len(Check(e)) == 0) != (runErr == nil) {
			t.Errorf("key of %d characters: Check %v, run %v", len(k), Check(e), runErr)
		}
	}
}
