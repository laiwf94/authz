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
//	                   relationship writes; empty keeps no audit log
//	GRANTD_KEY_RATE    requests per second allowed per API key; 0 or empty (the
//	                   default) sets no limit. Requests over it get 429 and Retry-After
//	GRANTD_KEY_BURST   requests an API key may make at once above the rate
//	                   (default: the rate rounded up, at least 1)
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
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/metrics"
	"github.com/laiwf94/authz/internal/platform/ratelimit"
)

// Summary is the one-line description shown in "authz help".
const Summary = "run the authorization (relationships and checks) API"

const usage = `usage: authz serve

Runs the authorization API: schema, relationships, checks, lookups and watch.
It takes no flags; configuration comes from the environment, as grantd's did:

  GRANTD_ADDR        listen address (default ":8080")
  GRANTD_DATA_DIR    directory for the write-ahead log; empty keeps data in memory only
  GRANTD_API_KEYS    comma-separated bearer keys, each at least 16 characters (required)
  GRANTD_TOKEN_KEY   64 hex characters used to sign consistency tokens; required with GRANTD_DATA_DIR.
                     A comma-separated list rotates: the first key signs, the rest still verify
  GRANTD_CACHE_SIZE  check results kept across requests (default 100000; 0 disables)
  GRANTD_RETENTION   revisions of history kept for snapshot reads and watch (default 100000)
  GRANTD_LOG_LEVEL   debug, info, warn or error (default info)
  GRANTD_AUDIT_LOG   hash-chained audit log of schema changes and relationship writes;
                     empty keeps none
  GRANTD_KEY_RATE    requests per second allowed per API key; 0 or empty (the default)
                     sets no limit. Requests over it get 429 and Retry-After
  GRANTD_KEY_BURST   requests an API key may make at once above the rate
                     (default: the rate rounded up, at least 1)

Logs are JSON lines on standard output. SIGINT or SIGTERM drains requests
and stops. "authz check -serve" validates this environment without starting.
`

// Run is the "authz serve" subcommand. It serves until ctx ends and returns
// the process exit code: 0 after a clean shutdown, 1 when the server cannot
// start or fails, 2 for a usage error.
func Run(ctx context.Context, args []string, getenv func(string) string, _ io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "authz serve: unexpected argument %q; configuration comes from the environment\n", fs.Arg(0))
		return 2
	}
	if err := run(ctx, getenv, stdout, nil); err != nil {
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
	keyLimit  ratelimit.Limit
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{addr: ":8080", cacheSize: 100_000, retention: store.DefaultRetention}
	if v := getenv("GRANTD_ADDR"); v != "" {
		c.addr = v
	}
	c.dataDir = getenv("GRANTD_DATA_DIR")
	c.auditLog = getenv("GRANTD_AUDIT_LOG")
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

// run serves until ctx ends. ready, when set, receives the bound address.
func run(ctx context.Context, getenv func(string) string, logOut io.Writer, ready func(addr string)) error {
	cfg, err := loadConfig(getenv)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: cfg.logLevel}))
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
		Metrics: metrics.New(), CacheSize: cfg.cacheSize, Audit: auditLog, KeyLimit: cfg.keyLimit})
	if err != nil {
		return err
	}
	hs := &http.Server{
		Addr:              cfg.addr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      api.MaxWatchWait + 15*time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ln, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		return err
	}
	log.Info("listening", "addr", ln.Addr().String(), "persistent", cfg.dataDir != "", "revision", uint64(st.Head()))
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
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return hs.Shutdown(shutdownCtx)
}
