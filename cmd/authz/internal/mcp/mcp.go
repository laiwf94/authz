// Package mcp implements "authz mcp", the MCP gateway that was the toolgate
// command. Its subcommands, flags, exit codes, config and policy files and
// audit format are toolgate's, unchanged:
//
//	authz mcp [serve]                          run the gateway (configured from the environment)
//	authz mcp serve -config FILE               run the gateway from the mcp section of the platform file
//	authz mcp audit verify [-head HASH] FILE   check an audit log's hash chain
//	authz mcp policy test [-v] POLICY CASES    check a policy against a file of expected decisions
//	authz mcp token new                        print a new static agent key and its SHA-256 for the config
//	authz mcp token hash < key                 print the SHA-256 of a static key read from stdin
//	authz mcp token mint -sub ID [-owner NAME] [-scope "a b"] [-ttl 15m]
//	                                           print a signed token (needs the config and signing keys)
//
// "authz mcp serve -config file" (or AUTHZ_CONFIG=file) starts the gateway
// from the mcp section of the platform configuration file instead, and
// reloads the agents, signing keys, policy and log level when the file or
// the files it names change (see section.go and reload.go). Without a
// file, the gateway reads its configuration from the environment. Every
// variable has the toolgate name and an AUTHZ_MCP_ name; either may be
// used, and setting both to different values is an error (see env.go):
//
//	TOOLGATE_ADDR             AUTHZ_MCP_ADDR             agent listener (default "127.0.0.1:8080")
//	TOOLGATE_ADMIN_ADDR       AUTHZ_MCP_ADMIN_ADDR       admin listener (default "127.0.0.1:8081")
//	TOOLGATE_ADMIN_TOKEN      AUTHZ_MCP_ADMIN_TOKEN      bearer token for the admin API, at least 32 characters (required)
//	TOOLGATE_CONFIG           AUTHZ_MCP_CONFIG           path of the JSON config: agents, upstreams, limits (required)
//	TOOLGATE_POLICY           AUTHZ_MCP_POLICY           path of the JSON policy, reloaded when it changes (required)
//	TOOLGATE_AUDIT_LOG        AUTHZ_MCP_AUDIT_LOG        path of the append-only audit log (required)
//	TOOLGATE_AUDIT_KEY        AUTHZ_MCP_AUDIT_KEY        64 hex characters; keys the argument digests in the audit log (required)
//	TOOLGATE_STATE_DIR        AUTHZ_MCP_STATE_DIR        directory for trusted tool definitions and approvals; empty keeps them in memory only
//	TOOLGATE_SIGNING_KEYS     AUTHZ_MCP_SIGNING_KEYS     kid=<64 hex>[,kid=<64 hex>...] for signed agent tokens; the first signs new tokens
//	TOOLGATE_ALLOWED_ORIGINS  AUTHZ_MCP_ALLOWED_ORIGINS  comma-separated browser origins allowed to call /mcp (default none)
//	TOOLGATE_POLICY_POLL      AUTHZ_MCP_POLICY_POLL      how often to check the policy file (default "2s"; "0" disables; SIGHUP always reloads)
//	TOOLGATE_LOG_LEVEL        AUTHZ_MCP_LOG_LEVEL        debug, info, warn or error (default info)
//	TOOLGATE_TLS_CERT         AUTHZ_MCP_TLS_CERT         PEM certificate chain; with the key, both listeners serve TLS 1.2+ and pick up renewed files
//	TOOLGATE_TLS_KEY          AUTHZ_MCP_TLS_KEY          PEM private key for TOOLGATE_TLS_CERT
//	TOOLGATE_TLS_CLIENT_CA    AUTHZ_MCP_TLS_CLIENT_CA    PEM CAs; when set, clients must present a certificate one signed
//	TOOLGATE_DRAIN_DELAY      AUTHZ_MCP_DRAIN_DELAY      after SIGTERM, how long the admin /readyz answers 503 while requests are still accepted (default 0s)
//	TOOLGATE_DRAIN_TIMEOUT    AUTHZ_MCP_DRAIN_TIMEOUT    how long in-flight calls may then finish (default 20s)
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
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/laiwf94/authz/cmd/authz/internal/part"
	"github.com/laiwf94/authz/internal/agents/gateway"
	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/agents/pins"
	"github.com/laiwf94/authz/internal/agents/policy"
	"github.com/laiwf94/authz/internal/platform/audit"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/httpserver"
	"github.com/laiwf94/authz/internal/platform/logging"
)

// Summary is the one-line description shown in "authz help".
const Summary = "run the MCP gateway for AI agents, verify its audit log, test policies and issue agent tokens"

const usage = `usage: authz mcp [serve]
       authz mcp serve -config file
       authz mcp audit verify [-head HASH] FILE
       authz mcp policy test [-v] POLICY CASES
       authz mcp token new | hash | mint -sub ID [-owner NAME] [-scope "a b"] [-ttl 15m]

Runs the MCP gateway (formerly toolgate) with no arguments or "serve".

  -config file  read the mcp section of the platform configuration file
                (default: $AUTHZ_CONFIG); the serve and gateway sections are
                skipped. Every member can be overridden by its AUTHZ_MCP_
                variable, and the TOOLGATE_ variables are ignored. The file,
                the secret files it names, the agents config and the policy
                are watched: changes to the agents, token settings and limits
                in the agents config, signing_keys, the policy and log_level
                apply within seconds, an invalid change is refused and the
                running configuration kept, and the other members apply on
                restart. SIGHUP reads them at once.

Without a file, configuration comes from the environment. Each variable may
be given by its toolgate name or its AUTHZ_MCP_ name; setting both to
different values is an error:

  TOOLGATE_ADDR             AUTHZ_MCP_ADDR             agent listener (default "127.0.0.1:8080")
  TOOLGATE_ADMIN_ADDR       AUTHZ_MCP_ADMIN_ADDR       admin listener (default "127.0.0.1:8081")
  TOOLGATE_ADMIN_TOKEN      AUTHZ_MCP_ADMIN_TOKEN      admin API bearer token, at least 32 characters (required)
  TOOLGATE_CONFIG           AUTHZ_MCP_CONFIG           JSON config: agents, upstreams, limits (required)
  TOOLGATE_POLICY           AUTHZ_MCP_POLICY           JSON policy, reloaded when it changes (required)
  TOOLGATE_AUDIT_LOG        AUTHZ_MCP_AUDIT_LOG        append-only audit log (required)
  TOOLGATE_AUDIT_KEY        AUTHZ_MCP_AUDIT_KEY        64 hex characters keying argument digests (required)
  TOOLGATE_STATE_DIR        AUTHZ_MCP_STATE_DIR        tool pins and approvals; empty keeps them in memory
  TOOLGATE_SIGNING_KEYS     AUTHZ_MCP_SIGNING_KEYS     kid=<64 hex>[,...] for signed agent tokens
  TOOLGATE_ALLOWED_ORIGINS  AUTHZ_MCP_ALLOWED_ORIGINS  browser origins allowed to call /mcp (default none)
  TOOLGATE_POLICY_POLL      AUTHZ_MCP_POLICY_POLL      policy file check interval (default "2s"; "0" disables)
  TOOLGATE_LOG_LEVEL        AUTHZ_MCP_LOG_LEVEL        debug, info, warn or error (default info)
  TOOLGATE_TLS_CERT         AUTHZ_MCP_TLS_CERT         PEM certificate chain; with the key, both listeners
                                                       serve TLS 1.2+ and pick up renewed files
  TOOLGATE_TLS_KEY          AUTHZ_MCP_TLS_KEY          PEM private key for the certificate
  TOOLGATE_TLS_CLIENT_CA    AUTHZ_MCP_TLS_CLIENT_CA    PEM CAs; clients must present a certificate one signed
  TOOLGATE_DRAIN_DELAY      AUTHZ_MCP_DRAIN_DELAY      after SIGTERM, how long the admin /readyz answers 503
                                                       while requests are still accepted (default 0s)
  TOOLGATE_DRAIN_TIMEOUT    AUTHZ_MCP_DRAIN_TIMEOUT    how long in-flight calls may then finish (default 20s)

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
	if len(args) == 0 || args[0] == "serve" {
		path, code, ok := serveArgs(prog, args, getenv, stderr)
		if !ok {
			return code
		}
		if path != "" {
			// The file replaces the TOOLGATE_ variables, so they are not
			// merged with their AUTHZ_MCP_ names: those override the
			// file's members, and a TOOLGATE_ name means nothing here.
			if err := serveFile(ctx, path, getenv, stdout, nil); err != nil {
				fmt.Fprintln(stderr, prog+":", err)
				return 1
			}
			return 0
		}
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
	http            httpserver.Options // TOOLGATE_TLS_* and TOOLGATE_DRAIN_*
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
	c := config{addr: "127.0.0.1:8080", adminAddr: "127.0.0.1:8081", poll: defaultPolicyPoll}
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
	if c.http, err = httpserver.FromEnv(getenv, legacyPrefix); err != nil {
		return c, err
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

// run serves from the TOOLGATE_ variables until ctx ends. ready, when set,
// receives the bound addresses.
func run(ctx context.Context, getenv func(string) string, logOut io.Writer, ready func(gw, admin string)) error {
	return runIn(ctx, part.Host{}, getenv, logOut, ready)
}

// Part runs "authz mcp serve" as one part of a process that runs several
// subcommands ("authz run"): its listeners join the host's group, its
// metrics go to the host's registry and its log lines say "mcp". It is
// configured as Run is, by the TOOLGATE_ variables or their AUTHZ_MCP_
// names.
func Part(ctx context.Context, h part.Host, getenv func(string) string, logOut io.Writer) error {
	env, err := compatEnv(getenv, gatewayEnv)
	if err != nil {
		return err
	}
	return runIn(ctx, h, env, logOut, nil)
}

// runIn is run with the process's listeners and registry.
func runIn(ctx context.Context, h part.Host, getenv func(string) string, logOut io.Writer, ready func(gw, admin string)) error {
	cfg, err := loadConfig(getenv)
	if err != nil {
		return err
	}
	gc, err := readGatewayConfig(cfg.configPath, getenv)
	if err != nil {
		return err
	}
	auth, err := gc.NewAuthenticator(cfg.keys, cfg.activeKey)
	if err != nil {
		return err
	}
	level := new(slog.LevelVar)
	level.Set(cfg.logLevel)
	return serveGateway(ctx, h, cfg, gc, auth, level, logOut, ready, nil)
}

// fileMode is a gateway started from the platform configuration file.
type fileMode struct {
	path    string
	watcher *pcfg.Watcher
	rl      *reloader
	getenv  func(string) string
}

// serveFile serves until ctx ends, configured by the mcp section of the
// platform configuration file at path, which is watched for changes.
func serveFile(ctx context.Context, path string, getenv func(string) string, logOut io.Writer, ready func(gw, admin string)) error {
	level := new(slog.LevelVar)
	rl := &reloader{level: level}
	w, s, cfg, err := watchFile(path, getenv, rl)
	if err != nil {
		return err
	}
	level.Set(cfg.logLevel)
	return serveGateway(ctx, part.Host{}, cfg, s.agents, s.auth, level, logOut, ready, &fileMode{path: path, watcher: w, rl: rl, getenv: getenv})
}

// serveGateway runs the gateway until ctx ends. fm is nil when it was
// configured from the environment. h is the process the gateway is a part
// of; its zero value is a process of its own.
func serveGateway(ctx context.Context, h part.Host, cfg config, gc *gateway.Config, auth *identity.Authenticator, level *slog.LevelVar,
	logOut io.Writer, ready func(gw, admin string), fm *fileMode) error {
	// The platform handler: request lines carry the correlation ID their
	// audit records do, and its tap feeds the secret scan. No subcommand
	// attribute, so every other line stays byte for byte as recorded.
	log := logging.NewLogger(logOut, logging.Options{Level: level, Subcommand: h.Name})
	if fm != nil {
		if ignored := toolgateVars(fm.getenv); len(ignored) > 0 {
			log.Warn("TOOLGATE_ variables are ignored with a configuration file; use its AUTHZ_MCP_ overrides",
				"config", fm.path, "ignored", ignored)
		}
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
	pinPath, approvalPath := "", ""
	if cfg.stateDir != "" {
		pinPath = filepath.Join(cfg.stateDir, "pins.json")
		approvalPath = filepath.Join(cfg.stateDir, "approvals.wal")
	} else if fm != nil {
		log.Warn("$.mcp.state_dir not set; trusted tool definitions and approvals are kept in memory and reset on restart")
	} else {
		log.Warn("TOOLGATE_STATE_DIR not set; trusted tool definitions and approvals are kept in memory and reset on restart")
	}
	pinStore, err := pins.Open(pinPath, nil)
	if err != nil {
		return err
	}
	defer pinStore.Close()
	gw, err := gateway.New(gateway.Options{Config: gc, Auth: auth, Policy: pol, Audit: auditLog, Pins: pinStore,
		ApprovalLog: approvalPath, AuditKey: cfg.auditKey, AllowedOrigins: cfg.origins, Log: log, Metrics: h.Registry()})
	if err != nil {
		return err
	}
	defer gw.Close()

	// Longer than the worst case for one call: a tool-list refresh (120 s)
	// plus an approval wait (60 s), a slot wait (1 s) and the call itself
	// (120 s), at the configuration maximums.
	lim := httpserver.Limits{WriteTimeout: 6 * time.Minute, MaxHeaderBytes: 32 << 10}
	g, err := h.Binder()(cfg.http,
		httpserver.Spec{Name: "agent", Addr: cfg.addr, Handler: gw.Handler(), Limits: lim},
		httpserver.Spec{Name: "admin", Addr: cfg.adminAddr, Handler: gw.AdminHandler(cfg.adminToken), Limits: lim, ReadyPath: "/readyz"})
	if err != nil {
		return err
	}
	bg, cancelBG := context.WithCancel(ctx)
	defer cancelBG()
	if fm != nil {
		fm.rl.start(log, gw, pol, cfg, gc)
		go func() { _ = fm.watcher.Run(bg) }()
		log.Info("configuration loaded", "config", fm.path, "sources", len(fm.watcher.Current().Sources()))
	}
	addrs := g.Addrs()
	n, head := auditLog.Head()
	log.Info("listening", "addr", addrs[0], "admin_addr", addrs[1],
		"policy", pol.Current().Hash, "audit_records", n, "audit_head", head, "upstreams", len(gc.Upstreams))
	if ready != nil {
		ready(addrs[0], addrs[1])
	}

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
				if fm != nil {
					// The file first: a change to the agents, the keys
					// or the level applies with the policy.
					_ = fm.watcher.Poll()
				}
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

	sctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- g.Serve(sctx) }()
	select {
	case err = <-done:
		log.Info("shutting down")
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	stop()
	return <-done
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
