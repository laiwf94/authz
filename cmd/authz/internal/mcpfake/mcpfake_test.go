package mcpfake

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	env := map[string]string{"MCPFAKE_ADDR": "127.0.0.1:0", "MCPFAKE_SANDBOX": t.TempDir(), "MCPFAKE_HTTP_ALLOW": " Example.com ,", "MCPFAKE_ADMIN_TOKEN": "adm-0123456789"}
	ctx, cancel := context.WithCancel(context.Background())
	addr := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, func(k string) string { return env[k] }, io.Discard, func(a string) { addr <- a })
	}()
	var a string
	select {
	case a = <-addr:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("did not start")
	}
	resp, err := http.Get("http://" + a + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v", err)
	}
	resp.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"MCPFAKE_SANDBOX is required": {},
		"no such file":                {"MCPFAKE_SANDBOX": "/does/not/exist"},
		"listen":                      {"MCPFAKE_SANDBOX": t.TempDir(), "MCPFAKE_ADDR": "256.0.0.1:1"},
	}
	for want, env := range cases {
		err := run(context.Background(), func(k string) string { return env[k] }, io.Discard, nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
}
