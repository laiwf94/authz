// Command grantd runs the authorization service.
//
// Configuration comes from the environment:
//
//	GRANTD_ADDR        listen address (default ":8080")
//	GRANTD_DATA_DIR    directory for the write-ahead log; empty keeps data in memory only
//	GRANTD_API_KEYS    comma-separated bearer keys, each at least 16 characters (required)
//	GRANTD_TOKEN_KEY   64 hex characters used to sign consistency tokens; required with GRANTD_DATA_DIR
//	GRANTD_CACHE_SIZE  check results kept across requests (default 100000; 0 disables)
//	GRANTD_RETENTION   revisions of history kept for snapshot reads and watch (default 100000)
//	GRANTD_LOG_LEVEL   debug, info, warn or error (default info)
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/metrics"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv, os.Stdout, nil); err != nil {
		fmt.Fprintln(os.Stderr, "grantd:", err)
		os.Exit(1)
	}
}

type config struct {
	addr      string
	dataDir   string
	apiKeys   []string
	tokenKey  []byte
	cacheSize int
	retention store.Revision
	logLevel  slog.Level
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{addr: ":8080", cacheSize: 100_000, retention: store.DefaultRetention}
	if v := getenv("GRANTD_ADDR"); v != "" {
		c.addr = v
	}
	c.dataDir = getenv("GRANTD_DATA_DIR")
	for _, k := range strings.Split(getenv("GRANTD_API_KEYS"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			c.apiKeys = append(c.apiKeys, k)
		}
	}
	if len(c.apiKeys) == 0 {
		return c, errors.New("GRANTD_API_KEYS is required (comma-separated, each at least 16 characters)")
	}
	if v := getenv("GRANTD_TOKEN_KEY"); v != "" {
		k, err := hex.DecodeString(v)
		if err != nil || len(k) != token.KeySize {
			return c, errors.New("GRANTD_TOKEN_KEY must be 64 hex characters")
		}
		c.tokenKey = k
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
	return c, nil
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
	tokens, err := token.NewIssuer(cfg.tokenKey)
	if err != nil {
		return err
	}
	st, err := store.Open(store.Options{Dir: cfg.dataDir, Retention: cfg.retention})
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer st.Close()

	srv, err := api.New(api.Config{Store: st, Tokens: tokens, APIKeys: cfg.apiKeys, Logger: log,
		Metrics: metrics.New(), CacheSize: cfg.cacheSize})
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
