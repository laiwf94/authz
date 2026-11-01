package mcpfake

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

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

func TestRunCommand(t *testing.T) {
	none := func(string) string { return "" }
	var errb bytes.Buffer
	if code := Run(context.Background(), []string{"-h"}, none, nil, io.Discard, &errb); code != 0 || !strings.HasPrefix(errb.String(), "usage: authz mcpfake") {
		t.Fatalf("-h: exit %d, %q", code, errb.String())
	}
	for _, s := range envSuffixes {
		if !strings.Contains(errb.String(), "MCPFAKE_"+s) || !strings.Contains(errb.String(), "AUTHZ_MCPFAKE_"+s) {
			t.Errorf("help does not document %s under both names", s)
		}
	}
	if code := Run(context.Background(), []string{"extra"}, none, nil, io.Discard, io.Discard); code != 2 {
		t.Fatalf("extra argument: exit %d", code)
	}
	errb.Reset()
	if code := Run(context.Background(), nil, none, nil, io.Discard, &errb); code != 1 || !strings.Contains(errb.String(), "authz mcpfake: MCPFAKE_SANDBOX is required") {
		t.Fatalf("no sandbox: exit %d, %q", code, errb.String())
	}
	conflict := map[string]string{"MCPFAKE_SANDBOX": "/a", "AUTHZ_MCPFAKE_SANDBOX": "/b"}
	errb.Reset()
	if code := Run(context.Background(), nil, func(k string) string { return conflict[k] }, nil, io.Discard, &errb); code != 2 ||
		!strings.Contains(errb.String(), "AUTHZ_MCPFAKE_SANDBOX and MCPFAKE_SANDBOX set to different values") {
		t.Fatalf("conflict: exit %d, %q", code, errb.String())
	}
}

// The AUTHZ_MCPFAKE_ names configure the server as the old ones did,
// including the token on /mcp.
func TestRunWithNewNames(t *testing.T) {
	env := map[string]string{"AUTHZ_MCPFAKE_ADDR": "127.0.0.1:0", "AUTHZ_MCPFAKE_SANDBOX": t.TempDir(),
		"MCPFAKE_TOKEN": "up-0123456789", "AUTHZ_MCPFAKE_TOKEN": "up-0123456789"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- Run(ctx, nil, func(k string) string { return env[k] }, nil, logs, logs) }()
	var addr string
	for deadline := time.Now().Add(10 * time.Second); addr == ""; time.Sleep(10 * time.Millisecond) {
		select {
		case code := <-done:
			t.Fatalf("exited %d: %s", code, logs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("did not start: %s", logs.String())
		}
		if _, rest, ok := strings.Cut(logs.String(), `"addr":"`); ok {
			addr, _, _ = strings.Cut(rest, `"`)
		}
	}
	resp, err := http.Post("http://"+addr+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/mcp without the token: %d, want 401", resp.StatusCode)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, logs.String())
	}
}
