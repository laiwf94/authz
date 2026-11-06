// Package gateway implements "authz gateway", the single sign-on gateway
// that was the wicket command. Its subcommands, environment variables,
// config file, endpoints, cookies and exit codes are wicket's, unchanged:
//
//	authz gateway                          run the gateway (configured from the environment)
//	authz gateway check [-online] [file]   validate a configuration without starting the gateway
//	authz gateway genkey                   print a new cookie key
//	authz gateway gensigningkey            print a new P-256 signing key in PEM
//
// Identity providers and apps are described in a JSON file (see
// docs/DESIGN.md and examples/wicket.json). Everything else comes from the
// environment:
//
//	WICKET_CONFIG           path of the JSON configuration file (required)
//	WICKET_COOKIE_KEYS      comma-separated 64-hex-character keys; the first seals cookies,
//	                        all open them, so a new key goes first during rotation (required)
//	WICKET_ADDR             public listen address for forward-auth, login and logout (default ":4180")
//	WICKET_ADMIN_ADDR       admin API and metrics listen address (default "127.0.0.1:4181");
//	                        must be a loopback address unless WICKET_ADMIN_TOKEN is set
//	WICKET_ADMIN_TOKEN      bearer token for the admin API, at least 16 characters
//	WICKET_SESSION_FILE     append-only session log; empty keeps sessions in memory only
//	WICKET_SIGNING_KEYS     comma-separated PEM files with P-256 keys for upstream tokens; the
//	                        first signs, all are published; empty generates a key per process
//	WICKET_TRUSTED_PROXIES  CIDRs whose X-Forwarded-For is believed (default loopback)
//	WICKET_LOGIN_RATE       login requests per minute per client address (default 30)
//	WICKET_LOG_LEVEL        debug, info, warn or error (default info)
//	WICKET_AUDIT_LOG        the platform's hash-chained audit log; empty writes audit
//	                        events to the JSON log only
//
// The configuration is reloaded on SIGHUP or POST /admin/reload.
package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/laiwf94/authz/internal/authn/config"
	"github.com/laiwf94/authz/internal/authn/metrics"
	"github.com/laiwf94/authz/internal/authn/server"
	"github.com/laiwf94/authz/internal/authn/session"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/jose"
	"github.com/laiwf94/authz/internal/platform/seal"
)

// Summary is the one-line description shown in "authz help".
const Summary = "run the single sign-on gateway (formerly wicket), check its configuration and make keys"

// LegacyName is the command name wicket deployments call the gateway by.
// A binary invoked under that name runs Wicket.
const LegacyName = "wicket"

const usageText = `usage: %[1]s
       %[1]s check [-online] [-timeout 10s] [config.json]
       %[1]s genkey | gensigningkey

Runs the single sign-on gateway (formerly wicket) with no arguments. "check"
validates a configuration without starting it, "genkey" prints a new cookie
key and "gensigningkey" a new P-256 signing key in PEM. Apps and identity
providers are described in the JSON file named by WICKET_CONFIG; everything
else comes from the environment:

  WICKET_CONFIG           JSON configuration file (required)
  WICKET_COOKIE_KEYS      comma-separated 64-hex-character keys; the first seals cookies (required)
  WICKET_ADDR             public listener for forward-auth, login and logout (default ":4180")
  WICKET_ADMIN_ADDR       admin API and metrics listener (default "127.0.0.1:4181");
                          must be loopback unless WICKET_ADMIN_TOKEN is set
  WICKET_ADMIN_TOKEN      admin API bearer token, at least 16 characters
  WICKET_SESSION_FILE     append-only session log; empty keeps sessions in memory only
  WICKET_SIGNING_KEYS     comma-separated PEM files with P-256 keys for upstream tokens
  WICKET_TRUSTED_PROXIES  CIDRs whose X-Forwarded-For is believed (default loopback)
  WICKET_LOGIN_RATE       login requests per minute per client address (default 30)
  WICKET_LOG_LEVEL        debug, info, warn or error (default info)
  WICKET_AUDIT_LOG        hash-chained audit log file; empty writes audit events to the log only

Logs are JSON lines on standard output. SIGHUP or POST /admin/reload reloads
the configuration; SIGINT or SIGTERM drains requests and stops. Exit codes:
0 success, 1 a gateway that cannot start or fails, or problems found by
check, 2 a usage error.
`

// Run is the "authz gateway" subcommand. It takes wicket's arguments after
// "gateway" and returns wicket's exit codes, plus 0 for -h.
func Run(ctx context.Context, args []string, getenv func(string) string, _ io.Reader, stdout, stderr io.Writer) int {
	return cli(ctx, "authz gateway", args, getenv, stdout, stderr, nil)
}

// Wicket is the gateway under its old name, for a binary invoked as
// "wicket": the same as Run, with "wicket" in help and error messages.
func Wicket(ctx context.Context, args []string, getenv func(string) string, _ io.Reader, stdout, stderr io.Writer) int {
	return cli(ctx, LegacyName, args, getenv, stdout, stderr, nil)
}

// cli dispatches wicket's subcommands under the program name prog and
// returns the process exit code. hup, when set, replaces the SIGHUP
// subscription (for tests).
func cli(ctx context.Context, prog string, args []string, getenv func(string) string, stdout, stderr io.Writer, hup <-chan os.Signal) int {
	if len(args) == 0 {
		if hup == nil {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGHUP)
			defer signal.Stop(c)
			hup = c
		}
		if err := run(ctx, getenv, stdout, hup, nil); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", prog, err)
			return 1
		}
		return 0
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		fmt.Fprintf(stderr, usageText, prog)
		return 0
	case "check":
		return checkCmd(ctx, prog, args[1:], getenv, stdout, stderr)
	}
	if err := subcommand(args[0], stdout); err != nil {
		fmt.Fprintf(stderr, "%s: %v; run \"%s -h\" for help\n", prog, err, prog)
		return 2
	}
	return 0
}

func subcommand(name string, out io.Writer) error {
	switch name {
	case "genkey":
		_, err := fmt.Fprintln(out, hex.EncodeToString(seal.RandomKey()))
		return err
	case "gensigningkey":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return err
		}
		return pem.Encode(out, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	return fmt.Errorf("unknown command %q (commands: check, genkey, gensigningkey)", name)
}

type settings struct {
	configPath  string
	addr        string
	adminAddr   string
	adminToken  string
	cookieKeys  [][]byte
	sessionFile string
	auditLog    string
	signingKeys []string
	trusted     []netip.Prefix
	loginRate   int
	logLevel    slog.Level
}

func loadSettings(getenv func(string) string) (settings, error) {
	s := settings{addr: ":4180", adminAddr: "127.0.0.1:4181"}
	if s.configPath = getenv("WICKET_CONFIG"); s.configPath == "" {
		return s, errors.New("WICKET_CONFIG is required")
	}
	if v := getenv("WICKET_ADDR"); v != "" {
		s.addr = v
	}
	if v := getenv("WICKET_ADMIN_ADDR"); v != "" {
		s.adminAddr = v
	}
	s.adminToken = getenv("WICKET_ADMIN_TOKEN")
	if s.adminToken != "" && len(s.adminToken) < 16 {
		return s, errors.New("WICKET_ADMIN_TOKEN must be at least 16 characters")
	}
	if s.adminToken == "" && !isLoopback(s.adminAddr) {
		return s, fmt.Errorf("WICKET_ADMIN_ADDR %q is not a loopback address; set WICKET_ADMIN_TOKEN to expose the admin API", s.adminAddr)
	}
	for _, k := range strings.Split(getenv("WICKET_COOKIE_KEYS"), ",") {
		if k = strings.TrimSpace(k); k == "" {
			continue
		}
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != seal.KeySize {
			return s, errors.New("WICKET_COOKIE_KEYS entries must be 64 hex characters (run: authz gateway genkey)")
		}
		s.cookieKeys = append(s.cookieKeys, b)
	}
	if len(s.cookieKeys) == 0 {
		return s, errors.New("WICKET_COOKIE_KEYS is required (run: authz gateway genkey)")
	}
	s.sessionFile = getenv("WICKET_SESSION_FILE")
	s.auditLog = getenv("WICKET_AUDIT_LOG")
	for _, f := range strings.Split(getenv("WICKET_SIGNING_KEYS"), ",") {
		if f = strings.TrimSpace(f); f != "" {
			s.signingKeys = append(s.signingKeys, f)
		}
	}
	proxies := getenv("WICKET_TRUSTED_PROXIES")
	if proxies == "" {
		proxies = "127.0.0.0/8,::1/128"
	}
	for _, p := range strings.Split(proxies, ",") {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(p))
		if err != nil {
			return s, fmt.Errorf("WICKET_TRUSTED_PROXIES: %q is not a CIDR", p)
		}
		s.trusted = append(s.trusted, pfx)
	}
	if v := getenv("WICKET_LOGIN_RATE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100_000 {
			return s, errors.New("WICKET_LOGIN_RATE must be 1-100000")
		}
		s.loginRate = n
	}
	if v := getenv("WICKET_LOG_LEVEL"); v != "" {
		if err := s.logLevel.UnmarshalText([]byte(v)); err != nil {
			return s, fmt.Errorf("WICKET_LOG_LEVEL: %v", err)
		}
	}
	return s, nil
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func loadSigners(files []string) ([]*jose.Signer, error) {
	var out []*jose.Signer
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("signing key: %w", err)
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("signing key %s: no PEM block", f)
		}
		var key *ecdsa.PrivateKey
		if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
			key, _ = k.(*ecdsa.PrivateKey)
		} else if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
			key = k
		}
		if key == nil {
			return nil, fmt.Errorf("signing key %s: not an ECDSA private key", f)
		}
		sg, err := jose.NewSigner(key)
		if err != nil {
			return nil, fmt.Errorf("signing key %s: %w", f, err)
		}
		out = append(out, sg)
	}
	return out, nil
}

// run serves until ctx ends. ready, when set, receives the public and admin
// addresses once both listeners are bound.
func run(ctx context.Context, getenv func(string) string, logOut io.Writer, hup <-chan os.Signal, ready func(public, admin string)) error {
	return serve(ctx, getenv, logOut, hup, ready, nil)
}

// serve is run with the clock the sessions and handlers read; nil is the
// wall clock. Only the golden replay sets it, so the times in its tokens and
// cookies are fixed offsets and the transcripts compare byte for byte.
func serve(ctx context.Context, getenv func(string) string, logOut io.Writer, hup <-chan os.Signal, ready func(public, admin string), now func() time.Time) error {
	st, err := loadSettings(getenv)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: st.logLevel}))
	signers, err := loadSigners(st.signingKeys)
	if err != nil {
		return err
	}
	if len(signers) == 0 {
		log.Warn("WICKET_SIGNING_KEYS not set; using a key generated for this process, so upstream tokens can't be verified across replicas or restarts")
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sg, _ := jose.NewSigner(k)
		signers = []*jose.Signer{sg}
	}
	keys, err := seal.New(st.cookieKeys)
	if err != nil {
		return err
	}
	cfg, err := config.Load(st.configPath, getenv)
	if err != nil {
		return err
	}
	sessions, err := session.Open(session.Options{Path: st.sessionFile, IdleTimeout: time.Duration(cfg.Session.IdleTimeout),
		AbsoluteTimeout: time.Duration(cfg.Session.AbsoluteTimeout), Now: now})
	if err != nil {
		return err
	}
	defer sessions.Close()
	var auditLog *audit.Log
	if st.auditLog != "" {
		if auditLog, err = audit.OpenWith(st.auditLog, audit.Options{Now: now, Schemas: audit.Default()}); err != nil {
			return fmt.Errorf("WICKET_AUDIT_LOG: %w", err)
		}
		defer auditLog.Close()
	}

	first := true
	srv, err := server.New(server.Options{
		Load: func() (*config.Config, error) {
			if first {
				first = false
				return cfg, nil
			}
			return config.Load(st.configPath, getenv)
		},
		Sessions: sessions, Keys: keys, Signers: signers, Logger: log, Metrics: metrics.New(),
		AdminToken: st.adminToken, TrustedProxies: st.trusted, LoginRate: st.loginRate, Now: now,
		Audit: auditLog,
	})
	if err != nil {
		return err
	}

	pub := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 45 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	adm := &http.Server{Handler: srv.AdminHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10}
	pln, err := net.Listen("tcp", st.addr)
	if err != nil {
		return err
	}
	aln, err := net.Listen("tcp", st.adminAddr)
	if err != nil {
		pln.Close()
		return err
	}
	log.Info("listening", "addr", pln.Addr().String(), "admin_addr", aln.Addr().String(),
		"persistent_sessions", st.sessionFile != "", "sessions", sessions.Len())
	if ready != nil {
		ready(pln.Addr().String(), aln.Addr().String())
	}
	errc := make(chan error, 2)
	go func() { errc <- pub.Serve(pln) }()
	go func() { errc <- adm.Serve(aln) }()
	sweep := time.NewTicker(time.Minute)
	defer sweep.Stop()
	for {
		select {
		case err := <-errc:
			pub.Close()
			adm.Close()
			return err
		case <-hup:
			if err := srv.Reload(ctx); err != nil {
				log.Error("reload failed; keeping the running configuration", "error", err.Error())
			}
		case <-sweep.C:
			srv.Sweep()
		case <-ctx.Done():
			log.Info("shutting down")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			err1 := pub.Shutdown(shutdownCtx)
			err2 := adm.Shutdown(shutdownCtx)
			return errors.Join(err1, err2)
		}
	}
}
