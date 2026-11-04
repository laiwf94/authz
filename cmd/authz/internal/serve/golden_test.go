package serve

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/golden"
)

// testdata recorded from the grantd binary at 41d9bf0, the last commit
// before the move, with scripts/serve-golden.go.
var goldenDir = filepath.Join("..", "..", "..", "..", "internal", "authz", "golden", "testdata")

// TestGoldenServe plays the end-to-end scenario through serve's own startup
// path (GRANTD_* variables, a data directory, a fixed token key) and wants
// the transcript grantd produced, byte for byte, across a restart.
func TestGoldenServe(t *testing.T) {
	want, err := os.ReadFile(filepath.Join(goldenDir, "serve.golden"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := golden.Run(inProcess(t), t.TempDir(), golden.Options{})
	if err != nil {
		t.Fatalf("%v\ntranscript so far:\n%s", err, got)
	}
	if d := golden.Diff(want, got); d != "" {
		t.Fatalf("authz serve differs from grantd's recording at %s", d)
	}
}

// TestGoldenServeOnGrantdData restarts authz serve on the data directory the
// grantd binary wrote in the fresh phase, so the write-ahead log format and
// the token key carry over from grantd unchanged.
func TestGoldenServeOnGrantdData(t *testing.T) {
	full, err := os.ReadFile(filepath.Join(goldenDir, "serve.golden"))
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(full, []byte(golden.RestartMarker))
	if i < 0 {
		t.Fatal("no restart phase in serve.golden")
	}
	dir := t.TempDir()
	src := filepath.Join(goldenDir, "grantd-data", "grantd.wal")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "grantd.wal"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := golden.Restart(inProcess(t), dir)
	if err != nil {
		t.Fatalf("%v\ntranscript so far:\n%s", err, got)
	}
	if d := golden.Diff(full[i:], got); d != "" {
		t.Fatalf("authz serve on grantd's data differs at %s", d)
	}
	// The data directory is still grantd's layout: one log file.
	if _, err := os.Stat(filepath.Join(dir, "grantd.wal")); err != nil {
		t.Fatal(err)
	}
}

// inProcess starts run in this process, the way main does, with its log
// captured.
func inProcess(t *testing.T) golden.StartFunc {
	return func(vars map[string]string) (*golden.Server, error) {
		ctx, cancel := context.WithCancel(context.Background())
		logs := &lockedBuf{}
		addrs := make(chan string, 1)
		done := make(chan error, 1)
		go func() { done <- run(ctx, env(vars), logs, func(a string) { addrs <- a }) }()
		select {
		case a := <-addrs:
			return &golden.Server{URL: "http://" + a, Stop: func() ([]byte, error) {
				cancel()
				select {
				case err := <-done:
					return logs.bytes(), err
				case <-time.After(10 * time.Second):
					t.Fatal("serve did not stop")
					return nil, nil
				}
			}}, nil
		case err := <-done:
			cancel()
			return nil, err
		case <-time.After(10 * time.Second):
			cancel()
			t.Fatal("serve did not start")
			return nil, nil
		}
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return []byte(l.b.String())
}
