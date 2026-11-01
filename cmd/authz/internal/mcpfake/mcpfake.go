// Package mcpfake implements "authz mcpfake", the small MCP server that was
// the mcpfake command: an upstream for trying authz mcp. See
// internal/agents/fakeserver for its tools.
//
// Configuration comes from the environment, under the mcpfake names or the
// AUTHZ_MCPFAKE_ ones:
//
//	MCPFAKE_ADDR         listen address (default "127.0.0.1:9000")
//	MCPFAKE_SANDBOX      directory read_file may read (required)
//	MCPFAKE_HTTP_ALLOW   comma-separated hosts http_get may fetch (default none)
//	MCPFAKE_TOKEN        bearer token required on /mcp (default none)
//	MCPFAKE_ADMIN_TOKEN  bearer token for POST /admin/rugpull and /admin/restore (default: routes off)
package mcpfake

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/agents/fakeserver"
)

// Summary is the one-line description shown in "authz help mcpfake".
const Summary = "run a small MCP server to put behind authz mcp (a test upstream)"

const usage = `usage: authz mcpfake

Runs a small MCP server over Streamable HTTP, as an upstream for trying
authz mcp. It takes no flags; configuration comes from the environment, under
the mcpfake names or the AUTHZ_MCPFAKE_ ones (both set to different values is
an error):

  MCPFAKE_ADDR         AUTHZ_MCPFAKE_ADDR         listen address (default "127.0.0.1:9000")
  MCPFAKE_SANDBOX      AUTHZ_MCPFAKE_SANDBOX      directory read_file may read (required)
  MCPFAKE_HTTP_ALLOW   AUTHZ_MCPFAKE_HTTP_ALLOW   comma-separated hosts http_get may fetch (default none)
  MCPFAKE_TOKEN        AUTHZ_MCPFAKE_TOKEN        bearer token required on /mcp (default none)
  MCPFAKE_ADMIN_TOKEN  AUTHZ_MCPFAKE_ADMIN_TOKEN  bearer token for POST /admin/rugpull and /admin/restore (default: routes off)

SIGINT or SIGTERM stops it. Exit codes: 0 after a clean stop, 1 when it
cannot start or fails, 2 for a usage error.
`

var envSuffixes = []string{"ADDR", "SANDBOX", "HTTP_ALLOW", "TOKEN", "ADMIN_TOKEN"}

// Run is the "authz mcpfake" subcommand.
func Run(ctx context.Context, args []string, getenv func(string) string, _ io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcpfake", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "authz mcpfake: unexpected argument %q; configuration comes from the environment\n", fs.Arg(0))
		return 2
	}
	env, err := compatEnv(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "authz mcpfake:", err)
		return 2
	}
	if err := run(ctx, env, stdout, nil); err != nil {
		fmt.Fprintln(stderr, "authz mcpfake:", err)
		return 1
	}
	return 0
}

// compatEnv answers MCPFAKE_<suffix> with AUTHZ_MCPFAKE_<suffix> when that
// is set, and refuses the two set to different values.
func compatEnv(getenv func(string) string) (func(string) string, error) {
	known := make(map[string]string, len(envSuffixes))
	for _, s := range envSuffixes {
		old, cur := getenv("MCPFAKE_"+s), getenv("AUTHZ_MCPFAKE_"+s)
		if old != "" && cur != "" && old != cur {
			return nil, fmt.Errorf("AUTHZ_MCPFAKE_%s and MCPFAKE_%s set to different values; unset one", s, s)
		}
		if cur != "" {
			old = cur
		}
		known["MCPFAKE_"+s] = old
	}
	return func(k string) string {
		if v, ok := known[k]; ok {
			return v
		}
		return getenv(k)
	}, nil
}

func run(ctx context.Context, getenv func(string) string, logOut io.Writer, ready func(addr string)) error {
	addr := getenv("MCPFAKE_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9000"
	}
	sandbox := getenv("MCPFAKE_SANDBOX")
	if sandbox == "" {
		return errors.New("MCPFAKE_SANDBOX is required")
	}
	var allow []string
	for _, h := range strings.Split(getenv("MCPFAKE_HTTP_ALLOW"), ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			allow = append(allow, h)
		}
	}
	log := slog.New(slog.NewJSONHandler(logOut, nil))
	srv, err := fakeserver.New(fakeserver.Config{Sandbox: sandbox, HTTPAllow: allow,
		Token: getenv("MCPFAKE_TOKEN"), AdminToken: getenv("MCPFAKE_ADMIN_TOKEN"), Log: log})
	if err != nil {
		return err
	}
	defer srv.Close()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	log.Info("listening", "addr", ln.Addr().String(), "sandbox", sandbox)
	if ready != nil {
		ready(ln.Addr().String())
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(shutdownCtx)
}
