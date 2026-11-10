package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/laiwf94/authz/cmd/authz/internal/part"
	"github.com/laiwf94/authz/internal/authn/check"
	"github.com/laiwf94/authz/internal/authn/config"
	"github.com/laiwf94/authz/internal/authn/server"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/httpserver"
	"github.com/laiwf94/authz/internal/platform/seal"
)

// SectionName is the name of the gateway section of the platform
// configuration file: $.gateway.
const SectionName = "gateway"

// Settings is the gateway section. It holds what wicket read from its
// WICKET_ variables and, inline, the members of wicket's JSON file
// (public_url, session, providers, apps and the rest), so a wicket file
// moves into the section unchanged:
//
//	{"gateway": {"cookie_keys": {"file": "/run/secrets/cookie-keys"},
//	             "public_url": "https://auth.example.com",
//	             "providers": [...], "apps": [...]}}
type Settings struct {
	// Addr is WICKET_ADDR.
	Addr string `json:"addr"`
	// AdminAddr is WICKET_ADMIN_ADDR.
	AdminAddr string `json:"admin_addr"`
	// AdminToken is WICKET_ADMIN_TOKEN.
	AdminToken pcfg.Secret `json:"admin_token"`
	// CookieKeys is WICKET_COOKIE_KEYS: comma-separated 64-hex-character
	// keys, the first sealing.
	CookieKeys pcfg.Secret `json:"cookie_keys"`
	// SessionFile is WICKET_SESSION_FILE.
	SessionFile string `json:"session_file"`
	// SigningKeys is WICKET_SIGNING_KEYS: PEM files with P-256 keys.
	SigningKeys []string `json:"signing_keys"`
	// TrustedProxies is WICKET_TRUSTED_PROXIES.
	TrustedProxies []string `json:"trusted_proxies"`
	// LoginRate is WICKET_LOGIN_RATE.
	LoginRate int `json:"login_rate"`
	// LogLevel is WICKET_LOG_LEVEL.
	LogLevel string `json:"log_level"`
	// AuditLog is WICKET_AUDIT_LOG.
	AuditLog string `json:"audit_log"`
	// AuditRotateBytes is WICKET_AUDIT_ROTATE_BYTES; 0 sets no size limit.
	AuditRotateBytes int64 `json:"audit_rotate_bytes"`
	// AuditRotateAge is WICKET_AUDIT_ROTATE_AGE; 0 sets no age limit.
	AuditRotateAge pcfg.Duration `json:"audit_rotate_age"`
	// TLSCert and TLSKey are WICKET_TLS_CERT and WICKET_TLS_KEY: PEM files
	// both listeners serve TLS with. Empty serves plain HTTP.
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	// TLSClientCA is WICKET_TLS_CLIENT_CA: PEM CAs client certificates must
	// chain to.
	TLSClientCA string `json:"tls_client_ca"`
	// DrainDelay is WICKET_DRAIN_DELAY.
	DrainDelay pcfg.Duration `json:"drain_delay"`
	// DrainTimeout is WICKET_DRAIN_TIMEOUT.
	DrainTimeout pcfg.Duration `json:"drain_timeout"`

	// The members of wicket's file (WICKET_CONFIG), checked by wicket's
	// own rules.
	PublicURL        string            `json:"public_url"`
	CookieDomain     string            `json:"cookie_domain"`
	Session          SessionTimeouts   `json:"session"`
	ClockSkew        pcfg.Duration     `json:"clock_skew"`
	RedirectHosts    []string          `json:"redirect_hosts"`
	UpstreamTokenTTL pcfg.Duration     `json:"upstream_token_ttl"`
	Providers        []config.Provider `json:"providers"`
	Apps             []config.App      `json:"apps"`
}

// SessionTimeouts is wicket's "session" member.
type SessionTimeouts struct {
	IdleTimeout     pcfg.Duration `json:"idle_timeout"`
	AbsoluteTimeout pcfg.Duration `json:"absolute_timeout"`
}

// File returns the wicket configuration document the section holds, as
// wicket's config.Parse reads it. Zero durations are written as "0s",
// which wicket reads as its default.
func (s *Settings) File() []byte {
	b, err := json.Marshal(wicketFile{
		PublicURL: s.PublicURL, CookieDomain: s.CookieDomain,
		Session:   s.Session,
		ClockSkew: s.ClockSkew, RedirectHosts: s.RedirectHosts, UpstreamTokenTTL: s.UpstreamTokenTTL,
		Providers: s.Providers, Apps: s.Apps,
	})
	if err != nil {
		panic("gateway: encoding the wicket document: " + err.Error())
	}
	return b
}

// wicketFile is config.Config's wire form.
type wicketFile struct {
	PublicURL        string            `json:"public_url"`
	CookieDomain     string            `json:"cookie_domain,omitempty"`
	Session          SessionTimeouts   `json:"session"`
	ClockSkew        pcfg.Duration     `json:"clock_skew"`
	RedirectHosts    []string          `json:"redirect_hosts,omitempty"`
	UpstreamTokenTTL pcfg.Duration     `json:"upstream_token_ttl"`
	Providers        []config.Provider `json:"providers,omitempty"`
	Apps             []config.App      `json:"apps,omitempty"`
}

// SectionOptions configure the gateway section's checks.
type SectionOptions struct {
	// Check is passed to wicket's checks: Getenv resolves
	// client_secret_env, and Online also fetches provider metadata, as
	// "authz gateway check -online" does.
	Check check.Options
	// Context bounds the online checks; nil is context.Background().
	Context context.Context
}

// Section describes the gateway section with wicket's defaults and every
// rule "authz gateway" and "authz gateway check" apply.
func Section(o SectionOptions) pcfg.Section {
	if o.Context == nil {
		o.Context = context.Background()
	}
	return pcfg.NewSection(SectionName, defaultSettings, func(s *Settings, c *pcfg.Checker) {
		checkSettings(o, s, c)
	})
}

func defaultSettings(s *Settings) {
	s.Addr = ":4180"
	s.AdminAddr = "127.0.0.1:4181"
	s.TrustedProxies = []string{"127.0.0.0/8", "::1/128"}
	s.LoginRate = server.DefaultLoginRate
	s.LogLevel = "info"
	s.DrainTimeout = pcfg.Duration(httpserver.DefaultDrainTimeout)
}

func checkSettings(o SectionOptions, s *Settings, c *pcfg.Checker) {
	if _, _, err := net.SplitHostPort(s.Addr); err != nil {
		c.Errorf(c.Field("addr"), "%v", err)
	}
	_, _, adminErr := net.SplitHostPort(s.AdminAddr)
	if adminErr != nil {
		c.Errorf(c.Field("admin_addr"), "%v", adminErr)
	}
	tok := s.AdminToken.Value()
	switch {
	case s.AdminToken.IsSet() && len(tok) < 16 && (tok != "" || blankSecret(s.AdminToken)):
		c.Errorf(c.Field("admin_token"), "must be at least 16 characters")
	case !s.AdminToken.IsSet() && adminErr == nil && !isLoopback(s.AdminAddr):
		c.Errorf(c.Field("admin_addr"), "%q is not a loopback address; set admin_token to expose the admin API", s.AdminAddr)
	}

	if !s.CookieKeys.IsSet() {
		c.Errorf(c.Field("cookie_keys"), "is required (run: authz gateway genkey)")
	} else if v := s.CookieKeys.Value(); v != "" || blankSecret(s.CookieKeys) {
		n := 0
		for i, k := range strings.Split(v, ",") {
			if k = strings.TrimSpace(k); k == "" {
				continue
			}
			n++
			if b, err := hex.DecodeString(k); err != nil || len(b) != seal.KeySize {
				c.Errorf(c.Field("cookie_keys"), "entry %d is not 64 hex characters (run: authz gateway genkey)", i+1)
			}
		}
		if n == 0 {
			c.Errorf(c.Field("cookie_keys"), "holds no key (run: authz gateway genkey)")
		}
	}

	for i, f := range s.SigningKeys {
		if _, err := loadSigners([]string{f}); err != nil {
			c.Errorf(pcfg.IndexPath(c.Field("signing_keys"), i), "%v", err)
		}
	}
	for i, p := range s.TrustedProxies {
		if _, err := netip.ParsePrefix(strings.TrimSpace(p)); err != nil {
			c.Errorf(pcfg.IndexPath(c.Field("trusted_proxies"), i), "%q is not a CIDR", p)
		}
	}
	if s.LoginRate < 1 || s.LoginRate > 100_000 {
		c.Errorf(c.Field("login_rate"), "must be 1-100000")
	}
	if err := new(slog.Level).UnmarshalText([]byte(s.LogLevel)); err != nil {
		c.Errorf(c.Field("log_level"), "%q is not debug, info, warn or error", s.LogLevel)
	}
	part.CheckAuditRotation(c, s.AuditLog, s.AuditRotateBytes, s.AuditRotateAge)

	checkHTTP(s, c)

	// Wicket's own checks, offline or online, with their paths moved under
	// the section: $.providers[0].issuer is $.gateway.providers[0].issuer.
	r := check.Bytes(o.Context, s.File(), o.Check)
	for _, p := range r.Problems {
		path := c.Path + strings.TrimPrefix(p.Path, "$")
		if p.Severity == config.SeverityWarning {
			c.Warnf(path, "%s", p.Message)
		} else {
			c.Errorf(path, "%s", p.Message)
		}
	}
}

// checkHTTP applies the rules httpserver.FromEnv and httpserver.Listen
// apply to the WICKET_TLS_* and WICKET_DRAIN_* settings, loading the TLS
// files.
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

// blankSecret reports a secret set directly, by an environment override,
// to nothing but white space. An empty file or variable reference is
// reported by the loader instead.
func blankSecret(s pcfg.Secret) bool {
	return s.IsSet() && s.Value() == "" && s.File == "" && s.Env == ""
}
