// Package serve implements "authz serve", the authorization service that
// was the grantd command. It keeps grantd's environment variables and
// behaviour unchanged:
//
//	GRANTD_ADDR        listen address (default ":8080")
//	GRANTD_DATA_DIR    directory for the write-ahead log; empty keeps data in memory only
//	GRANTD_API_KEYS    comma-separated bearer keys, each at least 16 characters (required)
//	GRANTD_TOKEN_KEY   64 hex characters used to sign consistency tokens; required with GRANTD_DATA_DIR.
//	                   A comma-separated list rotates: the first key signs, the rest still verify
//	GRANTD_CACHE_SIZE  check results kept across requests (default 100000; 0 disables)
//	GRANTD_RETENTION   revisions of history kept for snapshot reads and watch (default 100000)
//	GRANTD_LOG_LEVEL   debug, info, warn or error (default info)
//	GRANTD_AUDIT_LOG   the platform's hash-chained audit log for schema changes and
//	                   relationship writes; empty keeps no audit log. It may be the
//	                   same file authz gateway and authz mcp write
//	GRANTD_AUDIT_CHECKS true also records every answered check as a decision
//	                   record in GRANTD_AUDIT_LOG (default false)
//	GRANTD_KEY_RATE    requests per second allowed per API key; 0 or empty (the
//	                   default) sets no limit. Requests over it get 429 and Retry-After
//	GRANTD_KEY_BURST   requests an API key may make at once above the rate
//	                   (default: the rate rounded up, at least 1)
//	GRANTD_TLS_CERT    PEM certificate chain; with GRANTD_TLS_KEY the API serves TLS 1.2+
//	GRANTD_TLS_KEY     and picks up renewed files without a restart
//	GRANTD_TLS_CLIENT_CA PEM CAs; when set, clients must present a certificate one signed
//	GRANTD_DRAIN_DELAY after SIGTERM, how long /readyz answers 503 while requests are
//	                   still accepted (default 0s)
//	GRANTD_DRAIN_TIMEOUT how long in-flight requests may finish after that (default 20s)
package serve

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/laiwf94/authz/cmd/authz/internal/part"
	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/audit"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/httpserver"
	"github.com/laiwf94/authz/internal/platform/logging"
	"github.com/laiwf94/authz/internal/platform/ratelimit"
)

// Summary is the one-line description shown in "authz help".
const Summary = "run the authorization (relationships and checks) API"

const usage = `usage: authz serve [-config file]

Runs the authorization API: schema, relationships, checks, lookups and watch.

  -config file  read the serve section of the platform configuration file
                (default: $AUTHZ_CONFIG). Every member can be overridden by
                its AUTHZ_SERVE_ variable. The file and the secret files it
                names are watched: api_keys and log_level changes apply
                within seconds, an invalid change is refused and the running
                configuration kept, and the other members apply on restart.

Without a file, configuration comes from the environment, as grantd's did:

  GRANTD_ADDR        listen address (default ":8080")
  GRANTD_DATA_DIR    directory for the write-ahead log; empty keeps data in memory only
  GRANTD_API_KEYS    comma-separated bearer keys, each at least 16 characters (required)
  GRANTD_TOKEN_KEY   64 hex characters used to sign consistency tokens; required with GRANTD_DATA_DIR.
                     A comma-separated list rotates: the first key signs, the rest still verify
  GRANTD_CACHE_SIZE  check results kept across requests (default 100000; 0 disables)
  GRANTD_RETENTION   revisions of history kept for snapshot reads and watch (default 100000)
  GRANTD_LOG_LEVEL   debug, info, warn or error (default info)
  GRANTD_AUDIT_LOG   hash-chained audit log of schema changes and relationship writes;
                     empty keeps none. It may be the file authz gateway and authz mcp
                     write, which makes one chain
  GRANTD_AUDIT_CHECKS true also records every answered check as a decision record
                     in GRANTD_AUDIT_LOG, before the answer (default false)
  GRANTD_KEY_RATE    requests per second allowed per API key; 0 or empty (the default)
                     sets no limit. Requests over it get 429 and Retry-After
  GRANTD_KEY_BURST   requests an API key may make at once above the rate
                     (default: the rate rounded up, at least 1)
  GRANTD_TLS_CERT    PEM certificate chain; with GRANTD_TLS_KEY the API serves TLS 1.2+
  GRANTD_TLS_KEY     and picks up renewed files without a restart
  GRANTD_TLS_CLIENT_CA  PEM CAs; when set, clients must present a certificate one signed
  GRANTD_DRAIN_DELAY    after SIGTERM, how long /readyz answers 503 while requests
                        are still accepted (default 0s)
  GRANTD_DRAIN_TIMEOUT  how long in-flight requests may then finish (default 20s)

Logs are JSON lines on standard output. SIGINT or SIGTERM drains requests
and stops. "authz check -serve" validates this environment, and
"authz check -config file" the file, without starting.
`

// Run is the "authz serve" subcommand. It serves until ctx ends and returns
// the process exit code: 0 after a clean shutdown, 1 when the server cannot
// start or fails, 2 for a usage error.
func Run(ctx context.Context, args []string, getenv func(string) string, _ io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	file := fs.String("config", "", "platform configuration file (default $AUTHZ_CONFIG)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "authz serve: unexpected argument %q; configuration comes from -config or the environment\n", fs.Arg(0))
		return 2
	}
	if *file == "" {
		*file = getenv(ConfigEnv)
	}
	if err := serve(ctx, getenv, *file, stdout, nil); err != nil {
		fmt.Fprintln(stderr, "authz serve:", err)
		return 1
	}
	return 0
}

// Check validates the environment "authz serve" would start with, without
// opening the store or listening: every rule run applies before it starts
// serving, including the API key length and a data directory that exists
// but is not a directory.
func Check(getenv func(string) string) []error {
	cfg, err := loadConfig(getenv)
	if err != nil {
		return []error{err}
	}
	var errs []error
	for i, k := range cfg.apiKeys {
		if len(k) < api.MinKeyLength {
			errs = append(errs, fmt.Errorf("GRANTD_API_KEYS: key %d is %d characters; each key must be at least %d", i+1, len(k), api.MinKeyLength))
		}
	}
	if _, _, err := net.SplitHostPort(cfg.addr); err != nil {
		errs = append(errs, fmt.Errorf("GRANTD_ADDR: %v", err))
	}
	if cfg.dataDir != "" {
		if fi, err := os.Stat(cfg.dataDir); err == nil && !fi.IsDir() {
			errs = append(errs, fmt.Errorf("GRANTD_DATA_DIR: %s exists and is not a directory", cfg.dataDir))
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("GRANTD_DATA_DIR: %v", err))
		}
	}
	if cfg.http.TLS != nil {
		if err := cfg.http.TLS.Check(); err != nil {
			errs = append(errs, fmt.Errorf("GRANTD_TLS_CERT, GRANTD_TLS_KEY: %v", err))
		}
	}
	return errs
}

type config struct {
	addr      string
	dataDir   string
	apiKeys   []string
	tokenKey  []byte   // signs consistency tokens
	oldTokens [][]byte // the rest of GRANTD_TOKEN_KEY: verify only
	cacheSize int
	retention store.Revision
	logLevel  slog.Level
	auditLog  string
	auditChk  bool // GRANTD_AUDIT_CHECKS
	keyLimit  ratelimit.Limit
	http      httpserver.Options // GRANTD_TLS_* and GRANTD_DRAIN_*
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{addr: ":8080", cacheSize: 100_000, retention: store.DefaultRetention}
	if v := getenv("GRANTD_ADDR"); v != "" {
		c.addr = v
	}
	c.dataDir = getenv("GRANTD_DATA_DIR")
	c.auditLog = getenv("GRANTD_AUDIT_LOG")
	if v := getenv("GRANTD_AUDIT_CHECKS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, errors.New("GRANTD_AUDIT_CHECKS must be true or false")
		}
		if b && c.auditLog == "" {
			return c, errors.New("GRANTD_AUDIT_CHECKS needs GRANTD_AUDIT_LOG")
		}
		c.auditChk = b
	}
	for _, k := range strings.Split(getenv("GRANTD_API_KEYS"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			c.apiKeys = append(c.apiKeys, k)
		}
	}
	if len(c.apiKeys) == 0 {
		return c, errors.New("GRANTD_API_KEYS is required (comma-separated, each at least 16 characters)")
	}
	if v := getenv("GRANTD_TOKEN_KEY"); v != "" {
		ks, err := parseTokenKeys(v)
		if err != nil {
			return c, err
		}
		c.tokenKey, c.oldTokens = ks[0], ks[1:]
	} else if c.dataDir != "" {
		return c, errors.New("GRANTD_TOKEN_KEY is required with GRANTD_DATA_DIR, so tokens stay valid across restarts")
	}
	if v := getenv("GRANTD_CACHE_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return c, errors.New("GRANTD_CACHE_SIZE must be a non-negative integer")
		}
		c.cacheSize = n
	}
	if v := getenv("GRANTD_RETENTION"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n < 1 {
			return c, errors.New("GRANTD_RETENTION must be a positive integer")
		}
		c.retention = store.Revision(n)
	}
	if v := getenv("GRANTD_LOG_LEVEL"); v != "" {
		if err := c.logLevel.UnmarshalText([]byte(v)); err != nil {
			return c, fmt.Errorf("GRANTD_LOG_LEVEL: %v", err)
		}
	}
	if v := getenv("GRANTD_KEY_RATE"); v != "" {
		r, err := strconv.ParseFloat(v, 64)
		if err != nil || r < 0 || math.IsInf(r, 0) || math.IsNaN(r) {
			return c, errors.New("GRANTD_KEY_RATE must be a non-negative number of requests per second")
		}
		c.keyLimit = ratelimit.Limit{Rate: r, Burst: int(min(math.Ceil(r), math.MaxInt32))}
	}
	if v := getenv("GRANTD_KEY_BURST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return c, errors.New("GRANTD_KEY_BURST must be a positive integer")
		}
		if c.keyLimit.Unlimited() {
			return c, errors.New("GRANTD_KEY_BURST needs GRANTD_KEY_RATE")
		}
		c.keyLimit.Burst = n
	}
	var err error
	if c.http, err = httpserver.FromEnv(getenv, "GRANTD_"); err != nil {
		return c, err
	}
	return c, nil
}

// parseTokenKeys reads GRANTD_TOKEN_KEY: one key, or a comma-separated
// list newest first, each 64 hex characters. To rotate, an operator puts a
// new key first and restarts; tokens signed with the old keys keep
// verifying until those keys are removed from the list.
func parseTokenKeys(v string) ([][]byte, error) {
	var out [][]byte
	seen := map[string]bool{}
	for i, part := range strings.Split(v, ",") {
		k, err := hex.DecodeString(strings.TrimSpace(part))
		if err != nil || len(k) != token.KeySize {
			if i == 0 && !strings.Contains(v, ",") {
				return nil, errors.New("GRANTD_TOKEN_KEY must be 64 hex characters")
			}
			return nil, fmt.Errorf("GRANTD_TOKEN_KEY must be 64 hex characters, or a comma-separated list of them; entry %d is not", i+1)
		}
		if seen[string(k)] {
			return nil, fmt.Errorf("GRANTD_TOKEN_KEY: entry %d repeats an earlier key", i+1)
		}
		seen[string(k)] = true
		out = append(out, k)
	}
	return out, nil
}

// ConfigEnv names the platform configuration file when -config is not
// given.
const ConfigEnv = "AUTHZ_CONFIG"

// run serves from the GRANTD_ variables until ctx ends. ready, when set,
// receives the bound address.
func run(ctx context.Context, getenv func(string) string, logOut io.Writer, ready func(addr string)) error {
	return serve(ctx, getenv, "", logOut, ready)
}

// serve serves until ctx ends, configured by the serve section of the file
// at path, or by the GRANTD_ variables when path is empty.
func serve(ctx context.Context, getenv func(string) string, path string, logOut io.Writer, ready func(addr string)) error {
	return serveIn(ctx, part.Host{}, getenv, path, logOut, ready)
}

// Part runs authz serve as one part of a process that runs several
// subcommands ("authz run"): its listener joins the host's group, its
// metrics go to the host's registry and its log lines say "serve". It is
// configured as Run is, by the serve section of the file at path, or by
// the GRANTD_ variables when path is empty.
func Part(ctx context.Context, h part.Host, getenv func(string) string, path string, logOut io.Writer) error {
	return serveIn(ctx, h, getenv, path, logOut, nil)
}

// serveIn is serve with the process's listeners and registry.
func serveIn(ctx context.Context, h part.Host, getenv func(string) string, path string, logOut io.Writer, ready func(addr string)) error {
	var (
		cfg     config
		err     error
		watcher *pcfg.Watcher
		rl      *reloader
	)
	level := new(slog.LevelVar)
	if path == "" {
		cfg, err = loadConfig(getenv)
	} else {
		rl = &reloader{level: level}
		watcher, cfg, err = watchFile(path, getenv, rl)
	}
	if err != nil {
		return err
	}
	loaded := cfg // before a random token key is filled in
	level.Set(cfg.logLevel)
	// The platform handler: request lines carry the correlation ID their
	// audit records do, and its tap feeds the secret scan. No subcommand
	// attribute, so every other line stays byte for byte as recorded.
	log := logging.NewLogger(logOut, logging.Options{Level: level, Subcommand: h.Name})
	if watcher != nil {
		if ignored := grantdVars(getenv); len(ignored) > 0 {
			log.Warn("GRANTD_ variables are ignored with a configuration file; use its AUTHZ_SERVE_ overrides",
				"config", path, "ignored", ignored)
		}
	}
	if cfg.tokenKey == nil {
		log.Warn("GRANTD_TOKEN_KEY not set; using a random key, so consistency tokens end with this process")
		if cfg.tokenKey, err = token.RandomKey(); err != nil {
			return err
		}
	}
	tokens, err := token.NewIssuerKeys(cfg.tokenKey, cfg.oldTokens...)
	if err != nil {
		return err
	}
	st, err := store.Open(store.Options{Dir: cfg.dataDir, Retention: cfg.retention})
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer st.Close()
	var auditLog *audit.Log
	if cfg.auditLog != "" {
		if auditLog, err = audit.OpenWith(cfg.auditLog, audit.Options{Schemas: audit.Default()}); err != nil {
			return fmt.Errorf("GRANTD_AUDIT_LOG: %w", err)
		}
		defer auditLog.Close()
	}

	srv, err := api.New(api.Config{Store: st, Tokens: tokens, APIKeys: cfg.apiKeys, Logger: log,
		Metrics: h.Registry(), CacheSize: cfg.cacheSize, Audit: auditLog, AuditChecks: cfg.auditChk, KeyLimit: cfg.keyLimit})
	if err != nil {
		return err
	}
	g, err := h.Binder()(cfg.http, httpserver.Spec{
		Name:    "api",
		Addr:    cfg.addr,
		Handler: srv,
		// Long enough for the longest watch poll.
		Limits: httpserver.Limits{WriteTimeout: api.MaxWatchWait + 15*time.Second},
		// The API answers /readyz itself (with the log's health) until
		// SIGTERM; from then on the group answers 503.
		ReadyPath: "/readyz",
		Ready:     srv,
	})
	if err != nil {
		return err
	}
	if watcher != nil {
		rl.start(log, srv, loaded)
		wctx, stop := context.WithCancel(ctx)
		defer stop()
		go func() { _ = watcher.Run(wctx) }()
		log.Info("configuration loaded", "config", path, "sources", len(watcher.Current().Sources()))
	}
	addr := g.Addrs()[0]
	log.Info("listening", "addr", addr, "persistent", cfg.dataDir != "", "revision", uint64(st.Head()))
	if ready != nil {
		ready(addr)
	}
	sctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- g.Serve(sctx) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	stop()
	return <-done
}
