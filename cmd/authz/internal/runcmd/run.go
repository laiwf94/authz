// Package runcmd is "authz run": authz serve, authz gateway and authz mcp
// in one process. Each part is configured exactly as its own subcommand
// is, and they share what a process has once:
//
//   - one listener group (internal/platform/httpserver.Shared): every
//     listener is bound together or not at all, and SIGTERM flips every
//     readiness probe at once and drains every listener within one bound;
//   - one metrics registry: each part's /metrics answers with the metrics
//     of all three;
//   - one log output, each line saying which part wrote it;
//   - one grantd engine: serve's, which the gateway and mcp parts get from
//     part.Host.Engine and ask in process, with the same cache, snapshots
//     and consistency tokens as serve's HTTP API.
//
// A part that cannot start stops the others before anything is bound, and
// one that fails later stops the process the same way SIGTERM does.
package runcmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/laiwf94/authz/cmd/authz/internal/gateway"
	"github.com/laiwf94/authz/cmd/authz/internal/mcp"
	"github.com/laiwf94/authz/cmd/authz/internal/part"
	"github.com/laiwf94/authz/cmd/authz/internal/serve"
	"github.com/laiwf94/authz/internal/platform/httpserver"
	"github.com/laiwf94/authz/internal/platform/keys"
	"github.com/laiwf94/authz/internal/platform/logging"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

// Summary is the line "authz help" lists the command with.
const Summary = "run serve, gateway and mcp in one process with one listener group and one /metrics"

// Prefix names the variables of the shared listener group: AUTHZ_TLS_CERT,
// AUTHZ_TLS_KEY, AUTHZ_TLS_CLIENT_CA, AUTHZ_DRAIN_DELAY and
// AUTHZ_DRAIN_TIMEOUT.
const Prefix = "AUTHZ_"

// Parts are the subcommands "authz run" can start, in the order their
// listeners join the group.
var Parts = []string{"serve", "gateway", "mcp"}

const usage = `usage: authz run [-config file] [-parts serve,gateway,mcp]

Runs authz serve, authz gateway and authz mcp serve in one process. Each part
reads the configuration its own subcommand reads: serve and gateway the
serve and gateway sections of the platform configuration file (-config, or
$AUTHZ_CONFIG) or, without one, their GRANTD_ and WICKET_ variables; mcp its
TOOLGATE_ variables or their AUTHZ_MCP_ names.

The parts share one listener group, so every listener is bound together or
not at all, and one metrics registry, so each part's /metrics shows the
metrics of all of them. Log lines are JSON on standard output with a
"subcommand" attribute naming the part.

TLS and draining are set once, for every listener:

  AUTHZ_TLS_CERT, AUTHZ_TLS_KEY   serve every listener over TLS with this certificate and key
  AUTHZ_TLS_CLIENT_CA             require client certificates signed by these CAs
  AUTHZ_DRAIN_DELAY               how long listeners keep accepting after SIGTERM (default 0)
  AUTHZ_DRAIN_TIMEOUT             how long in-flight requests may then finish (default 20s)

A part's own TLS and drain settings (GRANTD_TLS_CERT, WICKET_DRAIN_DELAY,
tls_cert in a section, and so on) are refused rather than ignored.

Flags:
  -config file   platform configuration file for serve and gateway (default $AUTHZ_CONFIG)
  -parts list    the parts to run, comma separated (default serve,gateway,mcp)

SIGHUP reloads the gateway's configuration and the MCP policy; SIGINT or
SIGTERM drains every listener and stops. Exit codes: 0 after a clean
shutdown, 1 when a part cannot start or fails, 2 for a usage error.
`

// ownVars maps the variables a part would read its own TLS and drain
// settings from to the shared variable that replaces each.
var ownVars = func() [][2]string {
	var out [][2]string
	for _, p := range []string{"GRANTD_", "WICKET_", "TOOLGATE_", "AUTHZ_MCP_"} {
		for _, s := range []string{"TLS_CERT", "TLS_KEY", "TLS_CLIENT_CA", "DRAIN_DELAY", "DRAIN_TIMEOUT"} {
			out = append(out, [2]string{p + s, Prefix + s})
		}
	}
	return out
}()

// Run is the "authz run" subcommand.
func Run(ctx context.Context, args []string, getenv func(string) string, _ io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	file := fs.String("config", "", "platform configuration file (default $AUTHZ_CONFIG)")
	list := fs.String("parts", strings.Join(Parts, ","), "the parts to run, comma separated")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "authz run: unexpected argument %q; configuration comes from -config or the environment\n", fs.Arg(0))
		return 2
	}
	parts, err := parseParts(*list)
	if err != nil {
		fmt.Fprintln(stderr, "authz run:", err)
		return 2
	}
	for _, v := range ownVars {
		if getenv(v[0]) != "" {
			fmt.Fprintf(stderr, "authz run: %s is set; the parts share one listener group, so set %s instead\n", v[0], v[1])
			return 2
		}
	}
	opts, err := httpserver.FromEnv(getenv, Prefix)
	if err != nil {
		fmt.Fprintln(stderr, "authz run:", err)
		return 2
	}
	if *file == "" {
		*file = getenv(serve.ConfigEnv)
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	if err := run(ctx, parts, opts, getenv, *file, stdout, hup, nil); err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			fmt.Fprintln(stderr, "authz run:", line)
		}
		return 1
	}
	return 0
}

func parseParts(list string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, p := range strings.Split(list, ",") {
		p = strings.TrimSpace(p)
		known := false
		for _, k := range Parts {
			known = known || p == k
		}
		switch {
		case !known:
			return nil, fmt.Errorf("-parts: unknown part %q (parts: %s)", p, strings.Join(Parts, ", "))
		case seen[p]:
			return nil, fmt.Errorf("-parts: %s is listed twice", p)
		}
		seen[p] = true
	}
	for _, k := range Parts { // listeners join in a fixed order
		if seen[k] {
			out = append(out, k)
		}
	}
	return out, nil
}

// starter runs one part until ctx ends.
type starter func(ctx context.Context, h part.Host, getenv func(string) string, path string, logOut io.Writer, hup <-chan os.Signal) error

var starters = map[string]starter{
	"serve": func(ctx context.Context, h part.Host, getenv func(string) string, path string, logOut io.Writer, _ <-chan os.Signal) error {
		return serve.Part(ctx, h, getenv, path, logOut)
	},
	"gateway": gateway.Part,
	"mcp": func(ctx context.Context, h part.Host, getenv func(string) string, _ string, logOut io.Writer, _ <-chan os.Signal) error {
		return mcp.Part(ctx, h, getenv, logOut)
	},
}

// run starts the parts and serves until ctx ends or a part fails. ready,
// when set, receives the shared group once every listener is bound.
func run(ctx context.Context, parts []string, opts httpserver.Options, getenv func(string) string, path string,
	logOut io.Writer, hup <-chan os.Signal, ready func(*httpserver.Shared)) error {
	log := logging.NewLogger(logOut, logging.Options{Subcommand: "run"})
	shared := httpserver.NewShared(opts, len(parts))
	reg := metrics.New()
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// SIGHUP goes to the gateway; mcp subscribes to it on its own.
	hups := map[string]chan os.Signal{}
	for _, p := range parts {
		hups[p] = make(chan os.Signal, 1)
	}
	go func() {
		for {
			select {
			case <-pctx.Done():
				return
			case s := <-hup:
				select {
				case hups["gateway"] <- s:
				default:
				}
			}
		}
	}()

	errs := make([]error, len(parts))
	var wg sync.WaitGroup
	keyFiles := new(keys.Files) // parts naming one keys_file share its rings
	var engines *part.Engines   // serve's engine, asked in process by the others
	if slices.Contains(parts, "serve") {
		engines = part.NewEngines()
	}
	for i, p := range parts {
		h := part.Host{Name: p, Bind: shared.Part(i), Metrics: reg, Keys: keyFiles, Engines: engines}
		wg.Go(func() {
			errs[i] = starters[p](pctx, h, getenv, path, logOut, hups[p])
			if p == "serve" {
				engines.Stop(errs[i])
			}
			// A part that returns stops the others: before binding by
			// aborting the group, after it by ending the process context.
			shared.Abort(fmt.Errorf("%s: %w", p, errOrExit(errs[i])))
			cancel()
		})
	}
	go func() {
		select {
		case <-shared.Bound():
			if shared.Err() == nil {
				log.Info("running", "parts", parts, "addrs", shared.Addrs(), "tls", opts.TLS != nil)
				if ready != nil {
					ready(shared)
				}
			}
		case <-pctx.Done():
		}
	}()
	serveErr := shared.Serve(pctx)
	wg.Wait()

	var out []error
	for i, err := range errs {
		// The parts' Servers return the group's error, reported once
		// below, and the parts stopped by another's failure return
		// ErrAborted.
		if err != nil && err != serveErr && !errors.Is(err, httpserver.ErrAborted) {
			out = append(out, fmt.Errorf("%s: %w", parts[i], err))
		}
	}
	if serveErr != nil && !errors.Is(serveErr, httpserver.ErrAborted) {
		out = append(out, serveErr)
	}
	if len(out) > 0 {
		log.Error("stopped", "error", errors.Join(out...).Error())
		return errors.Join(out...)
	}
	log.Info("stopped", "parts", parts)
	return nil
}

func errOrExit(err error) error {
	if err == nil {
		return errors.New("stopped")
	}
	return err
}
