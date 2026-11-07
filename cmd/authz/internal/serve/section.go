package serve

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
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
