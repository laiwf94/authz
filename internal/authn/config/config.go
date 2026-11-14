// Package config loads and validates the gateway's JSON configuration file:
// identity providers, apps and their access policies. Secrets are never
// written in the file; it names environment variables or files that hold
// them.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/authn/redirect"
	"github.com/laiwf94/authz/internal/platform/jose"
)

// Limits and defaults.
const (
	MaxFileBytes      = 1 << 20
	maxProviders      = 64
	maxApps           = 1024
	maxListEntries    = 10_000
	DefaultSkew       = 2 * time.Minute
	MaxSkew           = 10 * time.Minute
	DefaultTokenTTL   = 2 * time.Minute
	MaxTokenTTL       = 15 * time.Minute
	DefaultIdle       = 8 * time.Hour
	DefaultAbsolute   = 24 * time.Hour
	MaxAbsolute       = 30 * 24 * time.Hour
	ProviderOIDC      = "oidc"
	ProviderSAML      = "saml"
	maxDisplayNameLen = 64
	// Revalidation bounds: often enough to matter, rarely enough not to
	// hammer the provider, and a grace that can't outlive a working day.
	MinRevalidateInterval = 30 * time.Second
	MaxRevalidateInterval = 24 * time.Hour
	MaxRevalidateGrace    = 24 * time.Hour
	RevalidateEnd         = "end"
	RevalidateGrace       = "grace"
)

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Duration is a time.Duration written as a Go duration string ("8h").
type Duration time.Duration

// UnmarshalJSON parses "90s", "8h" and so on.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`durations are strings like "90s" or "8h"`)
	}
	v, err := time.ParseDuration(s)
	if err != nil || v < 0 {
		return fmt.Errorf("invalid duration %q", s)
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON writes the duration as UnmarshalJSON reads it ("5m0s"), so a
// document that embeds a provider (the gateway section of the one
// configuration file) round-trips.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Config is the whole file.
type Config struct {
	PublicURL        string     `json:"public_url"`
	CookieDomain     string     `json:"cookie_domain"`
	Session          Session    `json:"session"`
	ClockSkew        Duration   `json:"clock_skew"`
	RedirectHosts    []string   `json:"redirect_hosts"`
	UpstreamTokenTTL Duration   `json:"upstream_token_ttl"`
	Providers        []Provider `json:"providers"`
	Apps             []App      `json:"apps"`

	// Filled in by Load.
	Public *url.URL `json:"-"`
}

// Session timeouts.
type Session struct {
	IdleTimeout     Duration `json:"idle_timeout"`
	AbsoluteTimeout Duration `json:"absolute_timeout"`
}

// Provider is one identity provider.
type Provider struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`

	// OpenID Connect.
	Issuer                string     `json:"issuer"`
	ClientID              string     `json:"client_id"`
	ClientSecretEnv       string     `json:"client_secret_env"`
	ClientSecretFile      string     `json:"client_secret_file"`
	ClientAuth            string     `json:"client_auth"`
	Scopes                []string   `json:"scopes"`
	Algorithms            []string   `json:"algorithms"`
	EmailClaim            string     `json:"email_claim"`
	NameClaim             string     `json:"name_claim"`
	GroupsClaim           string     `json:"groups_claim"`
	Userinfo              bool       `json:"userinfo"`
	TrustedAudiences      []string   `json:"trusted_audiences"`
	CAFile                string     `json:"ca_file"`
	PostLogoutRedirectURL string     `json:"post_logout_redirect_url"`
	Revalidate            Revalidate `json:"revalidate"`

	// SAML 2.0.
	IdPMetadataFile string `json:"idp_metadata_file"`
	IdPMetadataURL  string `json:"idp_metadata_url"`
	EntityID        string `json:"entity_id"`
	SPKeyFile       string `json:"sp_key_file"`
	SPCertFile      string `json:"sp_cert_file"`
	SignRequests    bool   `json:"sign_requests"`
	NameIDFormat    string `json:"name_id_format"`
	EmailAttribute  string `json:"email_attribute"`
	NameAttribute   string `json:"name_attribute"`
	GroupsAttribute string `json:"groups_attribute"`

	// Filled in by Load.
	ClientSecret string `json:"-"`
}

// Revalidate asks an OpenID provider, with the session's refresh token,
// whether each session still stands. A refusal (invalid_grant) always ends
// the session; OnFailure says what happens when the provider can't be asked.
type Revalidate struct {
	// Interval between confirmations of one session; 0 turns revalidation
	// off.
	Interval Duration `json:"interval"`
	// OnFailure is "end" (the default: a session the provider can't vouch
	// for ends at once) or "grace" (it lives on for Grace past its due
	// time, then ends unless the provider confirms it).
	OnFailure string   `json:"on_failure"`
	Grace     Duration `json:"grace"`
}

// Enabled says revalidation is on.
func (r Revalidate) Enabled() bool { return r.Interval > 0 }

// App is one protected application.
type App struct {
	ID         string   `json:"id"`
	Hosts      []string `json:"hosts"`
	Providers  []string `json:"providers"`
	Allow      Allow    `json:"allow"`
	DefaultURL string   `json:"default_url"`
}

// Allow is an app's access rule. Nothing is allowed by default.
type Allow struct {
	AnyUser      bool     `json:"any_user"`
	Emails       []string `json:"emails"`
	EmailDomains []string `json:"email_domains"`
	Groups       []string `json:"groups"`
}

// ReadFile reads a configuration file, refusing anything larger than
// MaxFileBytes.
func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("%s: file larger than %d bytes", path, MaxFileBytes)
	}
	return b, nil
}

// Load reads and validates the file at path. getenv resolves
// client_secret_env.
func Load(path string, getenv func(string) string) (*Config, error) {
	b, err := ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return Parse(b, getenv)
}

// Parse validates a configuration document. The error, if any, is a
// Problems listing every error in the document; warnings are dropped (use
// Check to see them).
func Parse(b []byte, getenv func(string) string) (*Config, error) {
	r := Check(b, getenv)
	if err := r.Problems.Err(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return r.Config, nil
}

func (c *Config) validate(getenv func(string) string, pc *Result) {
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		pc.Errorf("$.public_url", "must be an absolute https URL without query or fragment (cookies are Secure)")
	} else {
		u.Path = strings.TrimSuffix(u.Path, "/")
		c.Public = u
		c.PublicURL = u.String()
	}
	if c.CookieDomain != "" && c.Public != nil {
		d := strings.TrimPrefix(strings.ToLower(c.CookieDomain), ".")
		host := strings.ToLower(c.Public.Hostname())
		if net.ParseIP(d) != nil || !strings.Contains(d, ".") || (host != d && !strings.HasSuffix(host, "."+d)) {
			pc.Errorf("$.cookie_domain", "%q must be a parent domain of the public_url host %q", c.CookieDomain, host)
		}
		c.CookieDomain = d
	}
	if c.Session.IdleTimeout == 0 {
		c.Session.IdleTimeout = Duration(DefaultIdle)
	}
	if c.Session.AbsoluteTimeout == 0 {
		c.Session.AbsoluteTimeout = Duration(DefaultAbsolute)
	}
	if c.Session.AbsoluteTimeout > Duration(MaxAbsolute) {
		pc.Errorf("$.session.absolute_timeout", "must be at most %s", MaxAbsolute)
	}
	if c.Session.IdleTimeout < Duration(time.Minute) {
		pc.Errorf("$.session.idle_timeout", "must be at least 1m")
	} else if c.Session.IdleTimeout > c.Session.AbsoluteTimeout {
		pc.Errorf("$.session.idle_timeout", "must not be longer than absolute_timeout (%s)", time.Duration(c.Session.AbsoluteTimeout))
	}
	if c.ClockSkew == 0 {
		c.ClockSkew = Duration(DefaultSkew)
	}
	if c.ClockSkew > Duration(MaxSkew) {
		pc.Errorf("$.clock_skew", "must be at most %s", MaxSkew)
	}
	if c.UpstreamTokenTTL == 0 {
		c.UpstreamTokenTTL = Duration(DefaultTokenTTL)
	}
	if c.UpstreamTokenTTL < Duration(10*time.Second) || c.UpstreamTokenTTL > Duration(MaxTokenTTL) {
		pc.Errorf("$.upstream_token_ttl", "must be between 10s and %s", MaxTokenTTL)
	}
	if len(c.RedirectHosts) > maxListEntries {
		pc.Errorf("$.redirect_hosts", "more than %d entries", maxListEntries)
	}
	hostsOK := true
	for i, h := range c.RedirectHosts {
		if err := redirect.CheckHost(h, true); err != nil {
			pc.Errorf(indexPath("$.redirect_hosts", i), "%v", err)
			hostsOK = false
		}
	}

	providers := c.validateProviders(getenv, pc)
	used, appHostsOK := c.validateApps(providers, pc)
	for i, p := range c.Providers {
		if providers[p.ID] == i && !used[p.ID] {
			pc.Warnf(indexPath("$.providers", i), "provider %s is not used by any app", p.ID)
		}
	}

	// Every app's default_url must pass the same return-URL check as a
	// login's rd parameter, or the login would end on an error page.
	if c.Public == nil || !hostsOK || !appHostsOK {
		return
	}
	var all []string
	for _, a := range c.Apps {
		all = append(all, a.Hosts...)
	}
	v, err := redirect.New(append(all, c.RedirectHosts...), c.Public)
	if err != nil {
		pc.Errorf("$.redirect_hosts", "%v", err)
		return
	}
	for i, a := range c.Apps {
		if a.DefaultURL == "" {
			continue
		}
		if _, err := v.Validate(a.DefaultURL); err != nil {
			pc.Errorf(indexPath("$.apps", i)+".default_url", "%q is not on an app host or a redirect_hosts entry", a.DefaultURL)
		}
	}
}

// validateProviders returns the index of the first provider with each id.
func (c *Config) validateProviders(getenv func(string) string, pc *Result) map[string]int {
	if len(c.Providers) == 0 || len(c.Providers) > maxProviders {
		pc.Errorf("$.providers", "need 1 to %d providers", maxProviders)
	}
	providers := map[string]int{}
	for i := range c.Providers {
		p := &c.Providers[i]
		path := indexPath("$.providers", i)
		if !idRe.MatchString(p.ID) {
			pc.Errorf(path+".id", "provider id %q must be 1-32 lower-case letters, digits or '-'", p.ID)
		} else if j, dup := providers[p.ID]; dup {
			pc.Errorf(path+".id", "duplicate provider id %q (also $.providers[%d])", p.ID, j)
		} else {
			providers[p.ID] = i
		}
		if p.DisplayName == "" {
			p.DisplayName = p.ID
		}
		if len(p.DisplayName) > maxDisplayNameLen {
			pc.Errorf(path+".display_name", "longer than %d characters", maxDisplayNameLen)
		}
		switch p.Type {
		case ProviderOIDC:
			p.validateOIDC(path, getenv, pc)
			p.Revalidate.validate(path+".revalidate", time.Duration(c.Session.AbsoluteTimeout), pc)
		case ProviderSAML:
			p.validateSAML(path, pc)
		default:
			pc.Errorf(path+".type", "must be %q or %q", ProviderOIDC, ProviderSAML)
		}
	}
	return providers
}

// validateApps returns the providers some app uses, and whether every app
// host is well-formed.
func (c *Config) validateApps(providers map[string]int, pc *Result) (map[string]bool, bool) {
	if len(c.Apps) == 0 || len(c.Apps) > maxApps {
		pc.Errorf("$.apps", "need 1 to %d apps", maxApps)
	}
	used := map[string]bool{}
	hostsOK := true
	apps := map[string]int{}
	hosts := map[string]string{} // canonical host:port -> path of its first use
	for i := range c.Apps {
		a := &c.Apps[i]
		path := indexPath("$.apps", i)
		if !idRe.MatchString(a.ID) {
			pc.Errorf(path+".id", "app id %q must be 1-32 lower-case letters, digits or '-'", a.ID)
		} else if j, dup := apps[a.ID]; dup {
			pc.Errorf(path+".id", "duplicate app id %q (also $.apps[%d])", a.ID, j)
		} else {
			apps[a.ID] = i
		}
		if len(a.Hosts) == 0 {
			pc.Errorf(path+".hosts", "at least one host is required")
			hostsOK = false
		}
		for j, h := range a.Hosts {
			h = strings.ToLower(h)
			a.Hosts[j] = h
			hp := indexPath(path+".hosts", j)
			if err := redirect.CheckHost(h, false); err != nil {
				pc.Errorf(hp, "%v", err)
				hostsOK = false
				continue
			}
			// "host" and "host:443" are the same https origin, and
			// forward-auth treats them as one.
			canon := redirect.Canonical(h)
			if other, dup := hosts[canon]; dup {
				if strings.HasPrefix(other, path+".") {
					pc.Warnf(hp, "host %q is listed twice in this app (also %s)", h, other)
				} else {
					pc.Errorf(hp, "host %q overlaps %s: each host belongs to one app", h, other)
				}
				continue
			}
			hosts[canon] = hp
		}
		if len(a.Providers) == 0 {
			pc.Errorf(path+".providers", "list the identity providers this app accepts")
		}
		seen := map[string]bool{}
		for j, pid := range a.Providers {
			pp := indexPath(path+".providers", j)
			if _, ok := providers[pid]; !ok {
				pc.Errorf(pp, "unknown provider %q", pid)
			} else if seen[pid] {
				pc.Warnf(pp, "provider %q is listed twice", pid)
			}
			seen[pid] = true
			used[pid] = true
		}
		al := a.Allow
		if n := len(al.Emails) + len(al.EmailDomains) + len(al.Groups); n > maxListEntries {
			pc.Errorf(path+".allow", "allow lists have more than %d entries", maxListEntries)
		} else if n == 0 && !al.AnyUser {
			pc.Warnf(path+".allow", "nobody is allowed: set any_user or list emails, email_domains or groups")
		} else if n > 0 && al.AnyUser {
			pc.Warnf(path+".allow", "any_user allows everyone from the app's providers; the other lists have no effect")
		}
		for j, d := range al.EmailDomains {
			if d == "" || strings.ContainsAny(d, "@ ") || strings.HasPrefix(d, ".") {
				pc.Errorf(indexPath(path+".allow.email_domains", j), "email domain %q should look like example.com", d)
			}
		}
		for j, e := range al.Emails {
			if strings.Count(e, "@") != 1 {
				pc.Errorf(indexPath(path+".allow.emails", j), "%q is not an email address", e)
			}
		}
		if a.DefaultURL == "" && len(a.Hosts) > 0 {
			a.DefaultURL = "https://" + a.Hosts[0] + "/"
		} else if du, err := url.Parse(a.DefaultURL); a.DefaultURL != "" && (err != nil || du.Scheme != "https" || du.Host == "") {
			pc.Errorf(path+".default_url", "must be an absolute https URL")
			a.DefaultURL = ""
		}
	}
	return used, hostsOK
}

func requireHTTPS(pc *Result, path, u string) bool {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Host == "" || p.User != nil || p.Fragment != "" {
		pc.Errorf(path, "%q must be an absolute https URL without user info or fragment", u)
		return false
	}
	return true
}

func (p *Provider) validateOIDC(path string, getenv func(string) string, pc *Result) {
	for name, set := range map[string]bool{"idp_metadata_file": p.IdPMetadataFile != "", "idp_metadata_url": p.IdPMetadataURL != "",
		"sp_key_file": p.SPKeyFile != "", "sp_cert_file": p.SPCertFile != "", "entity_id": p.EntityID != "",
		"sign_requests": p.SignRequests, "name_id_format": p.NameIDFormat != "", "email_attribute": p.EmailAttribute != "",
		"name_attribute": p.NameAttribute != "", "groups_attribute": p.GroupsAttribute != ""} {
		if set {
			pc.Errorf(path+"."+name, "SAML setting on an oidc provider")
		}
	}
	if p.Issuer == "" {
		pc.Errorf(path, "issuer is required")
	} else {
		requireHTTPS(pc, path+".issuer", p.Issuer)
	}
	if p.ClientID == "" {
		pc.Errorf(path, "client_id is required")
	}
	switch {
	case p.ClientSecretEnv != "" && p.ClientSecretFile != "":
		pc.Errorf(path+".client_secret_file", "set client_secret_env or client_secret_file, not both")
	case p.ClientSecretEnv != "":
		p.ClientSecret = getenv(p.ClientSecretEnv)
		if p.ClientSecret == "" {
			pc.Errorf(path+".client_secret_env", "environment variable %s is empty", p.ClientSecretEnv)
		}
	case p.ClientSecretFile != "":
		b, err := os.ReadFile(p.ClientSecretFile)
		if err != nil {
			pc.Errorf(path+".client_secret_file", "%v", err)
		} else if p.ClientSecret = strings.TrimSpace(string(b)); p.ClientSecret == "" {
			pc.Errorf(path+".client_secret_file", "%s is empty", p.ClientSecretFile)
		}
	}
	secretSet := p.ClientSecretEnv != "" || p.ClientSecretFile != ""
	switch p.ClientAuth {
	case "", "client_secret_basic", "client_secret_post":
		if !secretSet {
			pc.Errorf(path, "a client secret is required (set client_secret_env or client_secret_file, or client_auth \"none\" for a public client)")
		}
	case "none":
		if secretSet {
			pc.Warnf(path+".client_auth", "the client secret is never sent with client_auth \"none\"")
		}
	default:
		pc.Errorf(path+".client_auth", "%q is not one of client_secret_basic, client_secret_post, none", p.ClientAuth)
	}
	if len(p.Scopes) > 0 {
		hasOpenID := false
		for j, s := range p.Scopes {
			hasOpenID = hasOpenID || s == "openid"
			if s == "" || strings.ContainsAny(s, " \"\\") {
				pc.Errorf(indexPath(path+".scopes", j), "invalid scope %q", s)
			}
		}
		if !hasOpenID {
			pc.Errorf(path+".scopes", `must include "openid"`)
		}
	}
	for j, a := range p.Algorithms {
		if !jose.IsSupported(a) {
			pc.Errorf(indexPath(path+".algorithms", j), "algorithm %q is not allowed (use one of %s)", a, strings.Join(jose.SupportedAlgorithms, ", "))
		}
	}
	if p.PostLogoutRedirectURL != "" {
		if u, err := url.Parse(p.PostLogoutRedirectURL); err != nil || u.Scheme != "https" || u.Host == "" {
			pc.Errorf(path+".post_logout_redirect_url", "must be an absolute https URL")
		}
	}
}

func (p *Provider) validateSAML(path string, pc *Result) {
	for name, set := range map[string]bool{"issuer": p.Issuer != "", "client_id": p.ClientID != "",
		"client_secret_env": p.ClientSecretEnv != "", "client_secret_file": p.ClientSecretFile != "",
		"client_auth": p.ClientAuth != "", "scopes": len(p.Scopes) > 0, "algorithms": len(p.Algorithms) > 0,
		"email_claim": p.EmailClaim != "", "name_claim": p.NameClaim != "", "groups_claim": p.GroupsClaim != "",
		"userinfo": p.Userinfo, "trusted_audiences": len(p.TrustedAudiences) > 0,
		"post_logout_redirect_url": p.PostLogoutRedirectURL != "", "revalidate": p.Revalidate != (Revalidate{})} {
		if set {
			pc.Errorf(path+"."+name, "OpenID Connect setting on a saml provider")
		}
	}
	switch {
	case p.IdPMetadataFile != "" && p.IdPMetadataURL != "":
		pc.Errorf(path+".idp_metadata_url", "set exactly one of idp_metadata_file and idp_metadata_url")
	case p.IdPMetadataFile == "" && p.IdPMetadataURL == "":
		pc.Errorf(path, "set idp_metadata_file or idp_metadata_url")
	case p.IdPMetadataURL != "":
		if u, err := url.Parse(p.IdPMetadataURL); err != nil || u.Scheme != "https" || u.Host == "" {
			pc.Errorf(path+".idp_metadata_url", "must be an absolute https URL")
		}
	}
	switch {
	case p.SPKeyFile != "" && p.SPCertFile == "":
		pc.Errorf(path+".sp_key_file", "sp_key_file and sp_cert_file go together")
	case p.SPKeyFile == "" && p.SPCertFile != "":
		pc.Errorf(path+".sp_cert_file", "sp_key_file and sp_cert_file go together")
	case p.SignRequests && p.SPKeyFile == "":
		pc.Errorf(path+".sign_requests", "sign_requests needs sp_key_file and sp_cert_file")
	}
}

func (r *Revalidate) validate(path string, absolute time.Duration, pc *Result) {
	if !r.Enabled() {
		if r.OnFailure != "" || r.Grace != 0 {
			pc.Errorf(path+".interval", "set an interval to turn revalidation on")
		}
		return
	}
	iv := time.Duration(r.Interval)
	if iv < MinRevalidateInterval || iv > MaxRevalidateInterval {
		pc.Errorf(path+".interval", "must be between %s and %s", MinRevalidateInterval, MaxRevalidateInterval)
	} else if absolute > 0 && iv >= absolute {
		pc.Warnf(path+".interval", "sessions end (absolute_timeout %s) before they are first revalidated", absolute)
	}
	switch r.OnFailure {
	case "":
		r.OnFailure = RevalidateEnd
		fallthrough
	case RevalidateEnd:
		if r.Grace != 0 {
			pc.Errorf(path+".grace", "grace needs on_failure %q", RevalidateGrace)
		}
	case RevalidateGrace:
		if time.Duration(r.Grace) < time.Second || time.Duration(r.Grace) > MaxRevalidateGrace {
			pc.Errorf(path+".grace", "on_failure %q needs a grace between 1s and %s", RevalidateGrace, MaxRevalidateGrace)
		}
	default:
		pc.Errorf(path+".on_failure", "%q is not %q or %q", r.OnFailure, RevalidateEnd, RevalidateGrace)
	}
}
