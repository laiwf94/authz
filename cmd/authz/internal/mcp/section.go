package mcp

import (
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/agents/gateway"
	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/agents/policy"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/httpserver"
)

// SectionName is the name of the mcp section of the platform configuration
// file: $.mcp.
const SectionName = "mcp"

// Settings is the mcp section. Each member is one of the TOOLGATE_
// variables under its AUTHZ_MCP_ name in lower case, so AUTHZ_MCP_ADDR
// overrides $.mcp.addr exactly as it stands in for TOOLGATE_ADDR today:
//
//	{"mcp": {"admin_token": {"file": "/run/secrets/mcp-admin-token"},
//	         "config": "/etc/authz/agents.json", "policy": "/etc/authz/policy.json",
//	         "audit_log": "/var/lib/authz/mcp-audit.log",
//	         "audit_key": {"file": "/run/secrets/mcp-audit-key"}}}
type Settings struct {
	// Addr is TOOLGATE_ADDR.
	Addr string `json:"addr"`
	// AdminAddr is TOOLGATE_ADMIN_ADDR.
	AdminAddr string `json:"admin_addr"`
	// AdminToken is TOOLGATE_ADMIN_TOKEN.
	AdminToken pcfg.Secret `json:"admin_token"`
	// Config is TOOLGATE_CONFIG: agents, upstreams and limits.
	Config string `json:"config"`
	// Policy is TOOLGATE_POLICY.
	Policy string `json:"policy"`
	// AuditLog is TOOLGATE_AUDIT_LOG.
	AuditLog string `json:"audit_log"`
	// AuditKey is TOOLGATE_AUDIT_KEY.
	AuditKey pcfg.Secret `json:"audit_key"`
	// StateDir is TOOLGATE_STATE_DIR.
	StateDir string `json:"state_dir"`
	// SigningKeys is TOOLGATE_SIGNING_KEYS: kid=<64 hex>[,kid=<64 hex>...].
	SigningKeys pcfg.Secret `json:"signing_keys"`
	// AllowedOrigins is TOOLGATE_ALLOWED_ORIGINS.
	AllowedOrigins []string `json:"allowed_origins"`
	// PolicyPoll is TOOLGATE_POLICY_POLL; 0 disables polling.
	PolicyPoll pcfg.Duration `json:"policy_poll"`
	// LogLevel is TOOLGATE_LOG_LEVEL.
	LogLevel string `json:"log_level"`
	// TLSCert and TLSKey are TOOLGATE_TLS_CERT and TOOLGATE_TLS_KEY: PEM
	// files both listeners serve TLS with. Empty serves plain HTTP.
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	// TLSClientCA is TOOLGATE_TLS_CLIENT_CA: CAs client certificates must
	// chain to.
	TLSClientCA string `json:"tls_client_ca"`
	// DrainDelay is TOOLGATE_DRAIN_DELAY.
	DrainDelay pcfg.Duration `json:"drain_delay"`
	// DrainTimeout is TOOLGATE_DRAIN_TIMEOUT.
	DrainTimeout pcfg.Duration `json:"drain_timeout"`

	// What the check built from the files the section names, so the
	// gateway starts, and reloads, from exactly what was checked.
	agents *gateway.Config
	auth   *identity.Authenticator
}

// Section describes the mcp section with toolgate's defaults and the rules
// "authz mcp" applies before it starts, including reading the agents
// config and the policy. getenv resolves the upstream credentials the
// agents config names in credential_env; nil skips them.
func Section(getenv func(string) string) pcfg.Section {
	return pcfg.NewSection(SectionName, defaultSettings, func(s *Settings, c *pcfg.Checker) {
		checkSettings(getenv, s, c)
	})
}

func defaultSettings(s *Settings) {
	s.Addr = "127.0.0.1:8080"
	s.AdminAddr = "127.0.0.1:8081"
	s.PolicyPoll = pcfg.Duration(defaultPolicyPoll)
	s.LogLevel = "info"
	s.DrainTimeout = pcfg.Duration(httpserver.DefaultDrainTimeout)
}

func checkSettings(getenv func(string) string, s *Settings, c *pcfg.Checker) {
	if _, _, err := net.SplitHostPort(s.Addr); err != nil {
		c.Errorf(c.Field("addr"), "%v", err)
	}
	if _, _, err := net.SplitHostPort(s.AdminAddr); err != nil {
		c.Errorf(c.Field("admin_addr"), "%v", err)
	}
	if !s.AdminToken.IsSet() {
		c.Errorf(c.Field("admin_token"), "is required")
	} else if v := s.AdminToken.Value(); (v != "" || blankSecret(s.AdminToken)) && len(v) < 32 {
		c.Errorf(c.Field("admin_token"), "must be at least 32 characters")
	}

	var gc *gateway.Config
	if s.Config == "" {
		c.Errorf(c.Field("config"), "is required")
	} else if src, err := c.ReadFile(s.Config, gateway.MaxConfigBytes); err != nil {
		c.Errorf(c.Field("config"), "%v", err)
	} else if gc, err = gateway.ParseConfig(src, getenv); err != nil {
		c.Errorf(c.Field("config"), "%s: %s", s.Config, strings.TrimPrefix(err.Error(), "config: "))
	}
	if s.Policy == "" {
		c.Errorf(c.Field("policy"), "is required")
	} else if src, err := c.ReadFile(s.Policy, policy.MaxBytes); err != nil {
		c.Errorf(c.Field("policy"), "%v", err)
	} else if _, err := policy.Parse(src); err != nil {
		c.Errorf(c.Field("policy"), "%s: %s", s.Policy, strings.TrimPrefix(err.Error(), "policy: "))
	}
	if s.AuditLog == "" {
		c.Errorf(c.Field("audit_log"), "is required")
	}
	if !s.AuditKey.IsSet() {
		c.Errorf(c.Field("audit_key"), "is required")
	} else if v := s.AuditKey.Value(); v != "" || blankSecret(s.AuditKey) {
		if k, err := hex.DecodeString(v); err != nil || len(k) != 32 {
			c.Errorf(c.Field("audit_key"), "must be 64 hex characters")
		}
	}
	if s.StateDir != "" {
		if fi, err := os.Stat(s.StateDir); err == nil && !fi.IsDir() {
			c.Errorf(c.Field("state_dir"), "%s exists and is not a directory", s.StateDir)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			c.Errorf(c.Field("state_dir"), "%v", err)
		}
	}
	var keys map[string][]byte
	var active string
	keysOK := true
	if v := s.SigningKeys.Value(); v != "" || blankSecret(s.SigningKeys) {
		var err error
		keys, active, err = parseKeys(v)
		switch {
		case err != nil:
			keysOK = false
			c.Errorf(c.Field("signing_keys"), "%s", strings.TrimPrefix(err.Error(), legacyPrefix+"SIGNING_KEYS "))
		case len(keys) == 0:
			keysOK = false
			c.Errorf(c.Field("signing_keys"), "holds no key")
		}
	}
	if gc != nil && keysOK {
		// The agents config and the signing keys must make an
		// authenticator, as they must when the gateway starts.
		auth, err := gc.NewAuthenticator(keys, active)
		if err != nil {
			path := c.Field("config")
			if len(keys) > 0 {
				path = c.Field("signing_keys")
			}
			c.Errorf(path, "%v", err)
		} else {
			s.agents, s.auth = gc, auth
		}
	}
	if err := new(slog.Level).UnmarshalText([]byte(s.LogLevel)); err != nil {
		c.Errorf(c.Field("log_level"), "%q is not debug, info, warn or error", s.LogLevel)
	}
	checkHTTP(s, c)
}

// checkHTTP applies the rules httpserver.FromEnv and httpserver.Listen
// apply to the TLS and drain settings, loading the TLS files.
func checkHTTP(s *Settings, c *pcfg.Checker) {
	switch {
	case s.TLSCert != "" && s.TLSKey != "":
		f := httpserver.TLSFiles{CertFile: s.TLSCert, KeyFile: s.TLSKey, ClientCAFile: s.TLSClientCA}
		if err := f.Check(); err != nil {
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

// defaultPolicyPoll is how often the policy file is checked by default.
const defaultPolicyPoll = 2 * time.Second

// blankSecret reports a secret set directly, by an environment override,
// to nothing but white space. An empty file or variable reference is
// reported by the loader instead.
func blankSecret(s pcfg.Secret) bool {
	return s.IsSet() && s.Value() == "" && s.File == "" && s.Env == ""
}
