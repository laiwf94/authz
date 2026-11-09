package serve

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/httpserver"
	"github.com/laiwf94/authz/internal/platform/ratelimit"
)

// SectionName is the name of the serve section of the platform
// configuration file: $.serve.
const SectionName = "serve"

// Settings is the serve section. Each member is one of the GRANTD_
// variables, under the name the platform's AUTHZ_SERVE_ variable gives it:
//
//	{"serve": {"addr": ":8080", "data_dir": "/var/lib/authz",
//	           "api_keys": {"file": "/run/secrets/api-keys"},
//	           "token_key": {"file": "/run/secrets/token-key"}}}
type Settings struct {
	// Addr is GRANTD_ADDR.
	Addr string `json:"addr"`
	// DataDir is GRANTD_DATA_DIR; empty keeps data in memory only.
	DataDir string `json:"data_dir"`
	// APIKeys is GRANTD_API_KEYS: comma-separated bearer keys.
	APIKeys pcfg.Secret `json:"api_keys"`
	// TokenKey is GRANTD_TOKEN_KEY: 64 hex characters, or a comma-separated
	// list newest first.
	TokenKey pcfg.Secret `json:"token_key"`
	// CacheSize is GRANTD_CACHE_SIZE; 0 disables the cache.
	CacheSize int `json:"cache_size"`
	// Retention is GRANTD_RETENTION.
	Retention int64 `json:"retention"`
	// LogLevel is GRANTD_LOG_LEVEL.
	LogLevel string `json:"log_level"`
	// AuditLog is GRANTD_AUDIT_LOG.
	AuditLog string `json:"audit_log"`
	// AuditChecks is GRANTD_AUDIT_CHECKS.
	AuditChecks bool `json:"audit_checks"`
	// KeyRate is GRANTD_KEY_RATE: requests per second per API key; 0 sets
	// no limit.
	KeyRate float64 `json:"key_rate"`
	// KeyBurst is GRANTD_KEY_BURST; 0 means the rate rounded up, at least 1.
	KeyBurst int `json:"key_burst"`
	// TLSCert and TLSKey are GRANTD_TLS_CERT and GRANTD_TLS_KEY: PEM files
	// the API serves TLS with. Empty serves plain HTTP.
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	// TLSClientCA is GRANTD_TLS_CLIENT_CA: CAs client certificates must
	// chain to.
	TLSClientCA string `json:"tls_client_ca"`
	// DrainDelay is GRANTD_DRAIN_DELAY.
	DrainDelay pcfg.Duration `json:"drain_delay"`
	// DrainTimeout is GRANTD_DRAIN_TIMEOUT.
	DrainTimeout pcfg.Duration `json:"drain_timeout"`
}

// OtherSections are the sections of the platform file that belong to the
// other long-running subcommands. "authz serve -config" reads past them, so
// one file can configure every subcommand and a problem in another's
// section does not stop this one.
var OtherSections = []string{"gateway", "mcp"}

// Schema is what "authz serve -config" reads: its own section, with the
// others skipped.
func Schema() *pcfg.Schema {
	secs := []pcfg.Section{Section()}
	for _, name := range OtherSections {
		secs = append(secs, pcfg.Skip(name))
	}
	return pcfg.MustSchema(secs...)
}

// Section describes the serve section, with grantd's defaults and the
// rules "authz serve" applies before it starts.
func Section() pcfg.Section {
	return pcfg.NewSection(SectionName, defaultSettings, checkSettings)
}

func defaultSettings(s *Settings) {
	s.Addr = ":8080"
	s.CacheSize = 100_000
	s.Retention = store.DefaultRetention
	s.LogLevel = "info"
	s.DrainTimeout = pcfg.Duration(httpserver.DefaultDrainTimeout)
}

func checkSettings(s *Settings, c *pcfg.Checker) {
	if _, _, err := net.SplitHostPort(s.Addr); err != nil {
		c.Errorf(c.Field("addr"), "%v", err)
	}
	if s.DataDir != "" {
		if fi, err := os.Stat(s.DataDir); err == nil && !fi.IsDir() {
			c.Errorf(c.Field("data_dir"), "%s exists and is not a directory", s.DataDir)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			c.Errorf(c.Field("data_dir"), "%v", err)
		}
	}
	switch keys := splitList(s.APIKeys.Value()); {
	case !s.APIKeys.IsSet():
		c.Errorf(c.Field("api_keys"), "is required (comma-separated bearer keys, each at least %d characters)", api.MinKeyLength)
	case len(keys) == 0:
		// The loader reports an empty file or variable reference itself;
		// a list of commas, or a blank override, is left to report here.
		if s.APIKeys.Value() != "" || blank(s.APIKeys) {
			c.Errorf(c.Field("api_keys"), "holds no key")
		}
	default:
		for i, k := range keys {
			if len(k) < api.MinKeyLength {
				c.Errorf(c.Field("api_keys"), "key %d is %d characters; each key must be at least %d", i+1, len(k), api.MinKeyLength)
			}
		}
	}
	switch {
	case s.TokenKey.IsSet():
		if v := s.TokenKey.Value(); v != "" || blank(s.TokenKey) {
			if _, err := tokenKeys(v); err != nil {
				c.Errorf(c.Field("token_key"), "%v", err)
			}
		}
	case s.DataDir != "":
		c.Errorf(c.Field("token_key"), "is required with data_dir, so tokens stay valid across restarts")
	}
	if s.CacheSize < 0 {
		c.Errorf(c.Field("cache_size"), "must not be negative (0 disables the cache)")
	}
	if s.Retention < 1 {
		c.Errorf(c.Field("retention"), "must be at least 1")
	}
	if err := new(slog.Level).UnmarshalText([]byte(s.LogLevel)); err != nil {
		c.Errorf(c.Field("log_level"), "%q is not debug, info, warn or error", s.LogLevel)
	}
	if s.AuditChecks && s.AuditLog == "" {
		c.Errorf(c.Field("audit_checks"), "needs audit_log")
	}
	if s.KeyRate < 0 {
		c.Errorf(c.Field("key_rate"), "must not be negative (0 sets no limit)")
	}
	switch {
	case s.KeyBurst < 0:
		c.Errorf(c.Field("key_burst"), "must not be negative (0 means the rate rounded up)")
	case s.KeyBurst > 0 && !(s.KeyRate > 0):
		c.Errorf(c.Field("key_burst"), "needs key_rate")
	}
	checkHTTP(s, c)
}

// checkHTTP applies the rules httpserver.FromEnv and httpserver.Listen
// apply to the TLS and drain settings, loading the TLS files.
func checkHTTP(s *Settings, c *pcfg.Checker) {
	switch {
	case s.TLSCert != "" && s.TLSKey != "":
		if err := s.tlsFiles().Check(); err != nil {
			c.Errorf(c.Field("tls_cert"), "%s", strings.TrimPrefix(err.Error(), "httpserver: "))
		}
	case s.TLSCert != "" || s.TLSKey != "":
		c.Errorf(c.Field("tls_cert"), "tls_cert and tls_key must be set together")
	case s.TLSClientCA != "":
		c.Errorf(c.Field("tls_client_ca"), "needs tls_cert and tls_key")
	}
	if time.Duration(s.DrainDelay) > time.Hour {
		c.Errorf(c.Field("drain_delay"), "must be at most 1h")
	}
	if d := time.Duration(s.DrainTimeout); d == 0 || d > time.Hour {
		c.Errorf(c.Field("drain_timeout"), "must be more than 0s and at most 1h")
	}
}

func (s *Settings) tlsFiles() *httpserver.TLSFiles {
	if s.TLSCert == "" || s.TLSKey == "" {
		return nil
	}
	return &httpserver.TLSFiles{CertFile: s.TLSCert, KeyFile: s.TLSKey, ClientCAFile: s.TLSClientCA}
}

// settingsConfig is the configuration a checked section starts the server
// with, the same one loadConfig builds from the GRANTD_ variables.
func settingsConfig(s *Settings) (config, error) {
	c := config{addr: s.Addr, dataDir: s.DataDir, auditLog: s.AuditLog, auditChk: s.AuditChecks, cacheSize: s.CacheSize,
		retention: store.Revision(s.Retention), apiKeys: splitList(s.APIKeys.Value())}
	if len(c.apiKeys) == 0 {
		return c, errors.New("$.serve.api_keys holds no key")
	}
	if s.TokenKey.IsSet() {
		ks, err := tokenKeys(s.TokenKey.Value())
		if err != nil {
			return c, fmt.Errorf("$.serve.token_key: %v", err)
		}
		c.tokenKey, c.oldTokens = ks[0], ks[1:]
	}
	if err := c.logLevel.UnmarshalText([]byte(s.LogLevel)); err != nil {
		return c, fmt.Errorf("$.serve.log_level: %v", err)
	}
	c.http = httpserver.Options{TLS: s.tlsFiles(), DrainDelay: time.Duration(s.DrainDelay), DrainTimeout: time.Duration(s.DrainTimeout)}
	if s.KeyRate > 0 {
		c.keyLimit = ratelimit.Limit{Rate: s.KeyRate, Burst: int(min(math.Ceil(s.KeyRate), math.MaxInt32))}
		if s.KeyBurst > 0 {
			c.keyLimit.Burst = s.KeyBurst
		}
	}
	return c, nil
}

// tokenKeys reads a token key list: one key, or a comma-separated list
// newest first, each 64 hex characters and none repeated.
func tokenKeys(v string) ([][]byte, error) {
	var out [][]byte
	seen := map[string]bool{}
	for i, part := range strings.Split(v, ",") {
		k, err := hex.DecodeString(strings.TrimSpace(part))
		if err != nil || len(k) != token.KeySize {
			return nil, fmt.Errorf("entry %d is not 64 hex characters", i+1)
		}
		if seen[string(k)] {
			return nil, fmt.Errorf("entry %d repeats an earlier key", i+1)
		}
		seen[string(k)] = true
		out = append(out, k)
	}
	return out, nil
}

func splitList(v string) []string {
	var out []string
	for _, e := range strings.Split(v, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// blank reports a secret set directly, by an environment override, to
// nothing but white space. An empty file or variable reference is reported
// by the loader instead.
func blank(s pcfg.Secret) bool {
	return s.IsSet() && s.Value() == "" && s.File == "" && s.Env == ""
}
