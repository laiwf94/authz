// Package mcp implements "authz mcp", the MCP gateway that was the toolgate
// command. Its subcommands, flags, exit codes, config and policy files and
// audit format are toolgate's, unchanged:
//
//	authz mcp [serve]                          run the gateway (configured from the environment)
//	authz mcp audit verify [-head HASH] FILE   check an audit log's hash chain
//	authz mcp policy test [-v] POLICY CASES    check a policy against a file of expected decisions
//	authz mcp token new                        print a new static agent key and its SHA-256 for the config
//	authz mcp token hash < key                 print the SHA-256 of a static key read from stdin
//	authz mcp token mint -sub ID [-owner NAME] [-scope "a b"] [-ttl 15m]
//	                                           print a signed token (needs the config and signing keys)
//
// The gateway reads its configuration from the environment. Every variable
// has the toolgate name and an AUTHZ_MCP_ name; either may be used, and
// setting both to different values is an error (see env.go):
//
//	TOOLGATE_ADDR             AUTHZ_MCP_ADDR             agent listener (default "127.0.0.1:8080")
//	TOOLGATE_ADMIN_ADDR       AUTHZ_MCP_ADMIN_ADDR       admin listener (default "127.0.0.1:8081")
//	TOOLGATE_ADMIN_TOKEN      AUTHZ_MCP_ADMIN_TOKEN      bearer token for the admin API, at least 32 characters (required)
//	TOOLGATE_CONFIG           AUTHZ_MCP_CONFIG           path of the JSON config: agents, upstreams, limits (required)
//	TOOLGATE_POLICY           AUTHZ_MCP_POLICY           path of the JSON policy, reloaded when it changes (required)
//	TOOLGATE_AUDIT_LOG        AUTHZ_MCP_AUDIT_LOG        path of the append-only audit log (required)
//	TOOLGATE_AUDIT_KEY        AUTHZ_MCP_AUDIT_KEY        64 hex characters; keys the argument digests in the audit log (required)
//	TOOLGATE_STATE_DIR        AUTHZ_MCP_STATE_DIR        directory for trusted tool definitions; empty keeps them in memory only
//	TOOLGATE_SIGNING_KEYS     AUTHZ_MCP_SIGNING_KEYS     kid=<64 hex>[,kid=<64 hex>...] for signed agent tokens; the first signs new tokens
//	TOOLGATE_ALLOWED_ORIGINS  AUTHZ_MCP_ALLOWED_ORIGINS  comma-separated browser origins allowed to call /mcp (default none)
//	TOOLGATE_POLICY_POLL      AUTHZ_MCP_POLICY_POLL      how often to check the policy file (default "2s"; "0" disables; SIGHUP always reloads)
//	TOOLGATE_LOG_LEVEL        AUTHZ_MCP_LOG_LEVEL        debug, info, warn or error (default info)
//
// Upstream credentials are read from the environment variables the config
// names in credential_env, exactly as named.
//
// Toolgate is the same command under its old name, for a binary invoked as
// "toolgate" (the image links /toolgate to /authz): its usage and error
// messages say "toolgate" where they otherwise say "authz mcp".
package mcp

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/laiwf94/authz/internal/agents/audit"
	"github.com/laiwf94/authz/internal/agents/gateway"
	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/agents/metrics"
	"github.com/laiwf94/authz/internal/agents/pins"
	"github.com/laiwf94/authz/internal/agents/policy"
)

// Summary is the one-line description shown in "authz help".
const Summary = "run the MCP gateway for AI agents, verify its audit log, test policies and issue agent tokens"

const usage = `usage: authz mcp [serve]
       authz mcp audit verify [-head HASH] FILE
       authz mcp policy test [-v] POLICY CASES
       authz mcp token new | hash | mint -sub ID [-owner NAME] [-scope "a b"] [-ttl 15m]

Runs the MCP gateway (formerly toolgate) with no arguments or "serve".
Configuration comes from the environment. Each variable may be given by its
toolgate name or its AUTHZ_MCP_ name; setting both to different values is an
error:

  TOOLGATE_ADDR             AUTHZ_MCP_ADDR             agent listener (default "127.0.0.1:8080")
  TOOLGATE_ADMIN_ADDR       AUTHZ_MCP_ADMIN_ADDR       admin listener (default "127.0.0.1:8081")
  TOOLGATE_ADMIN_TOKEN      AUTHZ_MCP_ADMIN_TOKEN      admin API bearer token, at least 32 characters (required)
  TOOLGATE_CONFIG           AUTHZ_MCP_CONFIG           JSON config: agents, upstreams, limits (required)
  TOOLGATE_POLICY           AUTHZ_MCP_POLICY           JSON policy, reloaded when it changes (required)
  TOOLGATE_AUDIT_LOG        AUTHZ_MCP_AUDIT_LOG        append-only audit log (required)
  TOOLGATE_AUDIT_KEY        AUTHZ_MCP_AUDIT_KEY        64 hex characters keying argument digests (required)
  TOOLGATE_STATE_DIR        AUTHZ_MCP_STATE_DIR        trusted tool definitions; empty keeps them in memory
  TOOLGATE_SIGNING_KEYS     AUTHZ_MCP_SIGNING_KEYS     kid=<64 hex>[,...] for signed agent tokens
  TOOLGATE_ALLOWED_ORIGINS  AUTHZ_MCP_ALLOWED_ORIGINS  browser origins allowed to call /mcp (default none)
  TOOLGATE_POLICY_POLL      AUTHZ_MCP_POLICY_POLL      policy file check interval (default "2s"; "0" disables)
  TOOLGATE_LOG_LEVEL        AUTHZ_MCP_LOG_LEVEL        debug, info, warn or error (default info)

Logs are JSON lines on standard output. SIGHUP reloads the policy; SIGINT or
SIGTERM drains requests and stops. Exit codes: 0 success, 1 failure (a failed
verification or policy case, or a gateway that cannot start), 2 usage or
unreadable input for "audit verify" and "policy test".
`

// Run is the "authz mcp" subcommand. It takes toolgate's arguments after
// "mcp" and returns toolgate's exit codes, plus 0 for -h, and 2 for a flag
// before the subcommand or conflicting environment variables.
func Run(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runAs(ctx, progName, args, getenv, stdin, stdout, stderr)
}

// LegacyName is the command name toolgate deployments call the gateway by.
// A binary invoked under that name (a symlink to authz, as in the image)
// runs Toolgate.
const LegacyName = "toolgate"

// Toolgate is the gateway under its old name: "toolgate audit verify" is
// "authz mcp audit verify", with "toolgate" in usage and error messages as
// the toolgate binary printed them.
func Toolgate(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runAs(ctx, LegacyName, args, getenv, stdin, stdout, stderr)
}

// progName is the name usage and error messages give the command.
const progName = "authz mcp"

func runAs(ctx context.Context, prog string, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && isHelp(args[0]) {
		fmt.Fprint(stderr, usageFor(prog))
		return 0
	}
	if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		fmt.Fprintf(stderr, "%[1]s: flag %[2]s is not defined; flags follow the subcommand (\"%[1]s token mint -sub ID\")\n%[3]s", prog, args[0], usageFor(prog))
		return 2
	}
	env, err := compatEnv(getenv, gatewayEnv)
	if err != nil {
		fmt.Fprintln(stderr, prog+":", err)
		return 2
	}
	return cliAs(ctx, prog, args, env, stdin, stdout, stderr, nil)
}

// usageFor is the help text with the command called prog.
func usageFor(prog string) string {
	if prog == progName {
		return usage
	}
	return strings.ReplaceAll(usage, progName, prog)
}

func isHelp(a string) bool { return a == "-h" || a == "-help" || a == "--help" || a == "help" }

// cli dispatches subcommands as "authz mcp" and returns the process exit code.
func cli(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer, ready func(gw, admin string)) int {
	return cliAs(ctx, progName, args, getenv, stdin, stdout, stderr, ready)
}

// cliAs is cli with prog as the command's name in messages.
func cliAs(ctx context.Context, prog string, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer, ready func(gw, admin string)) int {
	var err error
	switch {
	case len(args) == 0 || args[0] == "serve":
		err = run(ctx, getenv, stdout, ready)
	case args[0] == "audit" && len(args) > 1 && args[1] == "verify":
		return auditVerify(prog, args[2:], stdout, stderr)
	case args[0] == "policy" && len(args) > 1 && args[1] == "test":
		return policyTest(prog, args[2:], stdout, stderr)
	case args[0] == "token" && len(args) > 1:
		err = token(prog, args[1], args[2:], getenv, stdin, stdout)
	default:
		err = errors.New("usage: " + prog + " [serve] | audit verify [-head HASH] FILE | policy test [-v] POLICY CASES | token new|hash|mint")
	}
	if err != nil {
		fmt.Fprintln(stderr, prog+":", err)
		return 1
	}
	return 0
}

type config struct {
	addr, adminAddr string
	adminToken      string
	configPath      string
	policyPath      string
	auditPath       string
	auditKey        []byte
	stateDir        string
	keys            map[string][]byte
	activeKey       string
	origins         []string
	poll            time.Duration
	logLevel        slog.Level
}

func required(getenv func(string) string, name string) (string, error) {
	v := getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is required%s", name, aliasHint(name))
	}
	return v, nil
}

func parseKeys(v string) (map[string][]byte, string, error) {
	keys := map[string][]byte{}
	active := ""
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kid, hexKey, ok := strings.Cut(part, "=")
		k, err := hex.DecodeString(hexKey)
		if !ok || err != nil || len(k) != 32 {
			return nil, "", errors.New("TOOLGATE_SIGNING_KEYS must be kid=<64 hex characters>, comma-separated")
		}
		if _, dup := keys[kid]; dup {
			return nil, "", fmt.Errorf("TOOLGATE_SIGNING_KEYS repeats key id %q", kid)
		}
		keys[kid] = k
		if active == "" {
			active = kid
		}
	}
	return keys, active, nil
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{addr: "127.0.0.1:8080", adminAddr: "127.0.0.1:8081", poll: 2 * time.Second}
	if v := getenv("TOOLGATE_ADDR"); v != "" {
		c.addr = v
	}
	if v := getenv("TOOLGATE_ADMIN_ADDR"); v != "" {
		c.adminAddr = v
	}
	var err error
	if c.adminToken, err = required(getenv, "TOOLGATE_ADMIN_TOKEN"); err != nil {
		return c, err
	}
	if len(c.adminToken) < 32 {
		return c, errors.New("TOOLGATE_ADMIN_TOKEN must be at least 32 characters")
	}
	if c.configPath, err = required(getenv, "TOOLGATE_CONFIG"); err != nil {
		return c, err
	}
	if c.policyPath, err = required(getenv, "TOOLGATE_POLICY"); err != nil {
		return c, err
	}
	if c.auditPath, err = required(getenv, "TOOLGATE_AUDIT_LOG"); err != nil {
		return c, err
	}
	ak, err := required(getenv, "TOOLGATE_AUDIT_KEY")
	if err != nil {
		return c, err
	}
	if c.auditKey, err = hex.DecodeString(ak); err != nil || len(c.auditKey) != 32 {
		return c, errors.New("TOOLGATE_AUDIT_KEY must be 64 hex characters")
	}
	c.stateDir = getenv("TOOLGATE_STATE_DIR")
	if c.keys, c.activeKey, err = parseKeys(getenv("TOOLGATE_SIGNING_KEYS")); err != nil {
		return c, err
	}
	for _, o := range strings.Split(getenv("TOOLGATE_ALLOWED_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			c.origins = append(c.origins, o)
		}
	}
	if v := getenv("TOOLGATE_POLICY_POLL"); v != "" {
		d, err := time.ParseDuration(v)
		if v == "0" {
			d, err = 0, nil
		}
		if err != nil || d < 0 {
			return c, errors.New("TOOLGATE_POLICY_POLL must be a duration such as 2s, or 0")
		}
		c.poll = d
	}
	if v := getenv("TOOLGATE_LOG_LEVEL"); v != "" {
		if err := c.logLevel.UnmarshalText([]byte(v)); err != nil {
			return c, fmt.Errorf("TOOLGATE_LOG_LEVEL: %v", err)
		}
	}
	return c, nil
}

func readGatewayConfig(path string, getenv func(string) string) (*gateway.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	src, err := io.ReadAll(io.LimitReader(f, gateway.MaxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return gateway.ParseConfig(src, getenv)
}

// run serves until ctx ends. ready, when set, receives the bound addresses.
func run(ctx context.Context, getenv func(string) string, logOut io.Writer, ready func(gw, admin string)) error {
	cfg, err := loadConfig(getenv)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: cfg.logLevel}))
	gc, err := readGatewayConfig(cfg.configPath, getenv)
	if err != nil {
		return err
	}
	auth, err := gc.NewAuthenticator(cfg.keys, cfg.activeKey)
	if err != nil {
		return err
	}
	pol, err := policy.OpenStore(cfg.policyPath, nil)
	if err != nil {
		return err
	}
	auditLog, err := audit.Open(cfg.auditPath, nil)
	if err != nil {
		return err
	}
	defer auditLog.Close()
	pinPath := ""
	if cfg.stateDir != "" {
		pinPath = filepath.Join(cfg.stateDir, "pins.json")
	} else {
		log.Warn("TOOLGATE_STATE_DIR not set; trusted tool definitions are kept in memory and reset on restart")
	}
	pinStore, err := pins.Open(pinPath, nil)
	if err != nil {
		return err
	}
	gw, err := gateway.New(gateway.Options{Config: gc, Auth: auth, Policy: pol, Audit: auditLog, Pins: pinStore,
		AuditKey: cfg.auditKey, AllowedOrigins: cfg.origins, Log: log, Metrics: metrics.New()})
	if err != nil {
		return err
	}

	servers := []*http.Server{newServer(gw.Handler()), newServer(gw.AdminHandler(cfg.adminToken))}
	listeners := make([]net.Listener, 0, 2)
	for _, addr := range []string{cfg.addr, cfg.adminAddr} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return err
		}
		listeners = append(listeners, ln)
	}
	n, head := auditLog.Head()
	log.Info("listening", "addr", listeners[0].Addr().String(), "admin_addr", listeners[1].Addr().String(),
		"policy", pol.Current().Hash, "audit_records", n, "audit_head", head, "upstreams", len(gc.Upstreams))
	if ready != nil {
		ready(listeners[0].Addr().String(), listeners[1].Addr().String())
	}

	bg, cancelBG := context.WithCancel(ctx)
	defer cancelBG()
	if cfg.poll > 0 {
		go pol.Watch(bg, cfg.poll)
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-bg.Done():
				return
			case <-hup:
				pol.Reload()
			}
		}
	}()
	go func() {
		// Notice tool definition changes even when no agent is asking.
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		gw.Refresh(bg)
		for {
			select {
			case <-bg.Done():
				return
			case <-t.C:
				gw.Refresh(bg)
			}
		}
	}()

	errc := make(chan error, len(servers))
	for i, s := range servers {
		go func() { errc <- s.Serve(listeners[i]) }()
	}
	select {
	case err = <-errc:
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, s := range servers {
		if serr := s.Shutdown(shutdownCtx); serr != nil && err == nil {
			err = serr
		}
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Longer than the worst case for one call: a tool-list refresh (120 s)
		// plus an approval wait (60 s), a slot wait (1 s) and the call itself
		// (120 s), at the configuration maximums.
		WriteTimeout:   6 * time.Minute,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
}

func auditVerify(prog string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	head := fs.String("head", "", "expected hash of the last record (from GET /admin/audit/head)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: "+prog+" audit verify [-head HASH] FILE")
		return 2
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, prog+":", err)
		return 2
	}
	defer f.Close()
	res, err := audit.Verify(f)
	if err != nil {
		fmt.Fprintf(stdout, "FAIL %s: %v\n", fs.Arg(0), err)
		return 1
	}
	if *head != "" && *head != res.Head {
		fmt.Fprintf(stdout, "FAIL %s: chain is intact but ends at %s, not the expected head %s (records were removed from the end or the last one was changed)\n",
			fs.Arg(0), res.Head, *head)
		return 1
	}
	fmt.Fprintf(stdout, "OK %s: %d records, head %s\n", fs.Arg(0), res.Records, res.Head)
	return 0
}

// policyTest runs a case file against a policy. It exits 0 when every case
// passes, 1 when any fails and 2 when either file cannot be read or parsed.
func policyTest(prog string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	verbose := fs.Bool("v", false, "also list the cases that pass")
	if err := fs.Parse(args); err != nil || fs.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: "+prog+" policy test [-v] POLICY CASES")
		return 2
	}
	src, err := readLimited(fs.Arg(0), policy.MaxBytes)
	if err != nil {
		fmt.Fprintln(stderr, prog+":", err)
		return 2
	}
	p, err := policy.Parse(src)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s: %v\n", prog, fs.Arg(0), err)
		return 2
	}
	if src, err = readLimited(fs.Arg(1), policy.MaxCaseBytes); err != nil {
		fmt.Fprintln(stderr, prog+":", err)
		return 2
	}
	cs, err := policy.ParseCases(src)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s: %v\n", prog, fs.Arg(1), err)
		return 2
	}
	rep := policy.RunCases(p, cs)
	rep.WriteText(stdout, *verbose)
	if rep.Failed > 0 {
		return 1
	}
	return 0
}

// readLimited reads a file, refusing one larger than limit bytes.
func readLimited(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	src, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(src) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return src, nil
}

func token(prog, sub string, args []string, getenv func(string) string, stdin io.Reader, stdout io.Writer) error {
	switch sub {
	case "new":
		t := identity.NewStaticToken()
		h := identity.HashToken(t)
		fmt.Fprintf(stdout, "key:          %s\ntoken_sha256: %s\n", t, hex.EncodeToString(h[:]))
		return nil
	case "hash":
		line, err := bufio.NewReader(io.LimitReader(stdin, identity.MaxTokenBytes+2)).ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		t := strings.TrimSpace(line)
		if len(t) < identity.MinStaticBytes {
			return fmt.Errorf("a static key must be at least %d characters", identity.MinStaticBytes)
		}
		h := identity.HashToken(t)
		fmt.Fprintln(stdout, hex.EncodeToString(h[:]))
		return nil
	case "mint":
		fs := flag.NewFlagSet("token mint", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		subject := fs.String("sub", "", "agent id")
		owner := fs.String("owner", "", "owner of the agent")
		scope := fs.String("scope", "", "space-separated scopes")
		ttl := fs.Duration("ttl", 15*time.Minute, "lifetime")
		if err := fs.Parse(args); err != nil {
			return err
		}
		path, err := required(getenv, "TOOLGATE_CONFIG")
		if err != nil {
			return err
		}
		keys, active, err := parseKeys(getenv("TOOLGATE_SIGNING_KEYS"))
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			return errors.New("TOOLGATE_SIGNING_KEYS is required to mint tokens")
		}
		gc, err := readGatewayConfig(path, nil) // upstream credentials are not needed to mint
		if err != nil {
			return err
		}
		auth, err := gc.NewAuthenticator(keys, active)
		if err != nil {
			return err
		}
		tok, err := auth.Mint(*subject, *owner, strings.Fields(*scope), *ttl)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, tok)
		return nil
	default:
		return errors.New("usage: " + prog + " token new | hash | mint -sub ID [-owner NAME] [-scope \"a b\"] [-ttl 15m]")
	}
}
