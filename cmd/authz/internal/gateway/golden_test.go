package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/golden/e2e"
)

// goldenDir holds the transcripts recorded from the wicket code before the
// move; the in-process replay in internal/authn/golden/e2e uses the same
// files.
var goldenDir = filepath.Join("..", "..", "..", "..", "internal", "authn", "golden", "e2e", "testdata", "golden")

// TestGoldenGateway replays the end-to-end golden suite (OpenID Connect,
// SAML with and without signed requests, the nginx, Traefik and Envoy modes,
// the forbidden page and the admin API) through `authz gateway`'s startup
// path: settings from WICKET_* variables, a wicket config file, a signing
// key file, a cookie key, a session file and the gateway's own listeners on
// plain HTTP behind a TLS-terminating client. Every transcript must match
// the recording byte for byte. Only the clock is injected, and the
// transcripts write times relative to it.
func TestGoldenGateway(t *testing.T) {
	for _, sc := range e2e.Scenarios {
		t.Run(sc.File, func(t *testing.T) {
			// The config must name the gateway's port before it opens it,
			// so another test can take the port in between: then start
			// again on another one.
			var e *e2e.Env
			var host, admin string
			for attempt := 1; ; attempt++ {
				host = freeAddr(t)
				e = e2e.NewEnv(t, host, sc.Options)
				var key bytes.Buffer
				if err := subcommand("gensigningkey", &key); err != nil {
					t.Fatal(err)
				}
				signing := filepath.Join(e.Dir, "signing.pem")
				if err := os.WriteFile(signing, key.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
				vars := map[string]string{
					"WICKET_CONFIG":       e.ConfigPath,
					"WICKET_COOKIE_KEYS":  cookieKey,
					"WICKET_ADDR":         host,
					"WICKET_ADMIN_ADDR":   "127.0.0.1:0",
					"WICKET_SESSION_FILE": filepath.Join(e.Dir, "sessions.log"),
					"WICKET_SIGNING_KEYS": signing,
					"WICKET_LOGIN_RATE":   "10000",
					"CORP_SECRET":         e2e.ClientSecret,
				}
				if sc.AdminToken {
					vars["WICKET_ADMIN_TOKEN"] = e2e.AdminToken
				}
				a, err := startGateway(t, vars, e.Clock.Now)
				if err == nil {
					admin = a
					break
				}
				if !errors.Is(err, syscall.EADDRINUSE) || attempt == maxStartAttempts {
					t.Fatalf("gateway did not start (attempt %d): %v", attempt, err)
				}
				t.Logf("%s was taken before the gateway opened it; starting again on another port", host)
			}
			g := e2e.NewRecorder(t, e, e2e.Target{Admin: "http://" + admin, Transport: e2e.PlainHTTP(host)})
			sc.Run(g)
			e2e.Check(t, filepath.Join(goldenDir, sc.File), g.Bytes(), false)
		})
	}
}

// maxStartAttempts bounds TestGoldenGateway's starts on a fresh port.
const maxStartAttempts = 5

// startGateway serves until the test ends and returns the admin address,
// or the error of a gateway that did not start, with its log.
func startGateway(t *testing.T, vars map[string]string, now func() time.Time) (string, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	logs := &syncBuf{}
	addrs := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- serve(ctx, env(vars), logs, nil, func(_, a string) { addrs <- a }, now) }()
	select {
	case a := <-addrs:
		t.Cleanup(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("shutdown: %v", err)
			}
			if t.Failed() {
				t.Logf("gateway log:\n%s", logs.String())
			}
		})
		return a, nil
	case err := <-done:
		cancel()
		return "", fmt.Errorf("%w\n%s", err, logs.String())
	}
}

// freeAddr returns a loopback address with a port that was free a moment
// ago. The config's public_url and app host must name the port before the
// gateway opens it, as they do in a deployment.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}
