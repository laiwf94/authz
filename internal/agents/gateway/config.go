package gateway

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/agents/jsonrpc"
	"github.com/laiwf94/authz/internal/agents/mcp"
	"github.com/laiwf94/authz/internal/agents/policy"
	"github.com/laiwf94/authz/internal/agents/ratelimit"
	"github.com/laiwf94/authz/internal/platform/keys"
)

// MaxConfigBytes bounds the configuration file.
const MaxConfigBytes = 1 << 20

// Limits are per-agent admission limits. Zero rates are unlimited.
type Limits struct {
	AgentRPS   float64 `json:"agent_rps"`   // requests per second, any method
	AgentBurst int     `json:"agent_burst"` // bucket size for AgentRPS
	ToolRPS    float64 `json:"tool_rps"`    // calls per second to one tool
	ToolBurst  int     `json:"tool_burst"`
	DailyQuota int     `json:"daily_quota"` // tool calls per UTC day
}

func (l Limits) agent() ratelimit.Limit {
	return ratelimit.Limit{Rate: l.AgentRPS, Burst: l.AgentBurst}
}
func (l Limits) tool() ratelimit.Limit { return ratelimit.Limit{Rate: l.ToolRPS, Burst: l.ToolBurst} }

func (l Limits) validate() error {
	if l.AgentRPS < 0 || l.ToolRPS < 0 || l.AgentBurst < 0 || l.ToolBurst < 0 || l.DailyQuota < 0 {
		return errors.New("limits must not be negative")
	}
	if l.AgentRPS > 1e6 || l.ToolRPS > 1e6 || l.AgentBurst > 1e6 || l.ToolBurst > 1e6 {
		return errors.New("limits must be at most 1000000")
	}
	return nil
}

// AgentConfig is one statically configured agent.
type AgentConfig struct {
	ID          string   `json:"id"`
	Owner       string   `json:"owner"`
	Scopes      []string `json:"scopes"`
	TokenSHA256 string   `json:"token_sha256"` // hex SHA-256 of the agent's static key
	Limits      *Limits  `json:"limits"`       // overrides the defaults when set
}

// UpstreamConfig is one upstream MCP server.
type UpstreamConfig struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	// CredentialEnv names the environment variable holding the upstream's
	// secret. It is sent as "Authorization: Bearer <secret>", or as the raw
	// value of CredentialHeader when that is set. Agents never see it.
	CredentialEnv    string `json:"credential_env"`
	CredentialHeader string `json:"credential_header"`
	TimeoutMS        int    `json:"timeout_ms"`
	MaxResponseBytes int64  `json:"max_response_bytes"`
	MaxConcurrency   int    `json:"max_concurrency"`
	ToolsTTLSeconds  int    `json:"tools_ttl_seconds"`

	credential string
}

// Timeout returns the call timeout.
func (u UpstreamConfig) Timeout() time.Duration { return time.Duration(u.TimeoutMS) * time.Millisecond }

// TokenConfig configures signed agent tokens.
type TokenConfig struct {
	Issuer        string `json:"issuer"`
	Audience      string `json:"audience"`
	MaxTTLSeconds int    `json:"max_ttl_seconds"`
}

// ApprovalConfig configures human approval.
type ApprovalConfig struct {
	WaitSeconds        int `json:"wait_seconds"`          // how long a call waits for a decision before returning "pending"
	PendingTTLSeconds  int `json:"pending_ttl_seconds"`   // how long a request stays open
	MaxGrantTTLSeconds int `json:"max_grant_ttl_seconds"` // longest an approval stays usable
}

// Config is the gateway configuration file.
type Config struct {
	Tokens    *TokenConfig     `json:"tokens"`
	Agents    []AgentConfig    `json:"agents"`
	Upstreams []UpstreamConfig `json:"upstreams"`
	Limits    Limits           `json:"limits"`
	Approvals ApprovalConfig   `json:"approvals"`
	// Issuers are the external issuers whose signed tokens agents may
	// present, each with keys from its pinned jwks_uri.
	Issuers []IssuerConfig `json:"issuers"`
	// Resource makes the gateway an OAuth protected resource (RFC 9728):
	// it publishes metadata, challenges point at it, and every signed
	// token's audience must be its URL.
	Resource *ResourceConfig `json:"resource"`
}

// ResourceConfig is the gateway's protected resource identity.
//
//	{"url": "https://mcp.example.com/mcp",
//	 "authorization_servers": ["https://idp.example.com"],
//	 "scopes_supported": ["tools.read"], "name": "Example tools"}
type ResourceConfig struct {
	// URL is the resource identifier (RFC 8707): the canonical https URL
	// agents reach the MCP endpoint at. Tokens must carry it as audience.
	URL string `json:"url"`
	// AuthorizationServers are the issuer identifiers published in the
	// metadata; empty publishes the configured issuers.
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
	Name                 string   `json:"name"`
	Documentation        string   `json:"documentation"`
}

// NewResource returns the protected resource c describes, with
// authorization_servers defaulting to its issuers; nil without a resource
// section.
func (c *Config) NewResource() (*mcp.Resource, error) {
	if c.Resource == nil {
		return nil, nil
	}
	r := c.Resource
	as := r.AuthorizationServers
	if len(as) == 0 {
		for _, ic := range c.Issuers {
			if !slices.Contains(as, ic.Issuer) {
				as = append(as, ic.Issuer)
			}
		}
		if len(as) > mcp.MaxAuthorizationServers {
			as = as[:mcp.MaxAuthorizationServers]
		}
	}
	res, err := mcp.NewResource(mcp.ResourceMetadata{Resource: r.URL, AuthorizationServers: as,
		ScopesSupported: r.ScopesSupported, Name: r.Name, Documentation: r.Documentation})
	if err != nil {
		return nil, fmt.Errorf("resource: %w", err)
	}
	return res, nil
}

// checkAudiences binds every signed token to the resource: with a
// resource section, tokens.audience and each issuer's audience must be its
// URL, so a token minted for another resource is refused (RFC 8707).
func (c *Config) checkAudiences() error {
	if c.Resource == nil {
		return nil
	}
	want := c.Resource.URL
	if c.Tokens != nil && c.Tokens.Audience != want {
		return fmt.Errorf("tokens.audience %q is not the resource %q", c.Tokens.Audience, want)
	}
	for i, ic := range c.Issuers {
		if ic.Audience != want {
			return fmt.Errorf("issuers[%d]: audience %q is not the resource %q", i, ic.Audience, want)
		}
	}
	return nil
}

// ParseConfig validates a configuration document. getenv resolves upstream
// credentials; nil skips them, for commands that only need agents and
// token settings (such as minting a token).
func ParseConfig(src []byte, getenv func(string) string) (*Config, error) {
	if len(src) > MaxConfigBytes {
		return nil, fmt.Errorf("config: larger than %d bytes", MaxConfigBytes)
	}
	if err := jsonrpc.CheckStructure(src); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := c.Limits.validate(); err != nil {
		return nil, fmt.Errorf("config: limits: %w", err)
	}
	for _, a := range c.Agents {
		if a.Limits != nil {
			if err := a.Limits.validate(); err != nil {
				return nil, fmt.Errorf("config: agent %q: %w", a.ID, err)
			}
		}
		if h, err := hex.DecodeString(a.TokenSHA256); err != nil || len(h) != 32 {
			return nil, fmt.Errorf("config: agent %q: token_sha256 must be 64 hex characters", a.ID)
		}
	}
	if c.Tokens != nil {
		if c.Tokens.Issuer == "" || c.Tokens.Audience == "" {
			return nil, errors.New("config: tokens needs issuer and audience")
		}
		if c.Tokens.MaxTTLSeconds < 0 || c.Tokens.MaxTTLSeconds > 86400 {
			return nil, errors.New("config: tokens.max_ttl_seconds must be from 0 to 86400")
		}
	}
	if err := CheckIssuers(c.Issuers); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if c.Resource != nil {
		if _, err := c.NewResource(); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}
	if err := c.checkAudiences(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	a := &c.Approvals
	if a.WaitSeconds < 0 || a.WaitSeconds > 60 {
		return nil, errors.New("config: approvals.wait_seconds must be from 0 to 60")
	}
	if a.PendingTTLSeconds < 0 || a.PendingTTLSeconds > 86400 || a.MaxGrantTTLSeconds < 0 || a.MaxGrantTTLSeconds > 86400 {
		return nil, errors.New("config: approval TTLs must be from 0 to 86400 seconds")
	}
	if len(c.Upstreams) == 0 {
		return nil, errors.New("config: at least one upstream is required")
	}
	seen := map[string]bool{}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if err := u.validate(getenv); err != nil {
			return nil, fmt.Errorf("config: upstream %q: %w", u.Name, err)
		}
		if seen[u.Name] {
			return nil, fmt.Errorf("config: upstream %q is configured twice", u.Name)
		}
		seen[u.Name] = true
	}
	return &c, nil
}

func (u *UpstreamConfig) validate(getenv func(string) string) error {
	if !policy.ValidUpstream(u.Name) {
		return errors.New("name must be 1 to 32 lower-case letters, digits, '_' or '-', starting with a letter")
	}
	p, err := url.Parse(u.URL)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" || p.User != nil || p.Fragment != "" {
		return errors.New("url must be an absolute http(s) URL without credentials or fragment")
	}
	if u.TimeoutMS == 0 {
		u.TimeoutMS = 10_000
	}
	if u.TimeoutMS < 100 || u.TimeoutMS > 120_000 {
		return errors.New("timeout_ms must be from 100 to 120000")
	}
	if u.MaxResponseBytes == 0 {
		u.MaxResponseBytes = 1 << 20
	}
	if u.MaxResponseBytes < 1024 || u.MaxResponseBytes > 16<<20 {
		return errors.New("max_response_bytes must be from 1024 to 16777216")
	}
	if u.MaxConcurrency == 0 {
		u.MaxConcurrency = 16
	}
	if u.MaxConcurrency < 1 || u.MaxConcurrency > 1024 {
		return errors.New("max_concurrency must be from 1 to 1024")
	}
	if u.ToolsTTLSeconds == 0 {
		u.ToolsTTLSeconds = 30
	}
	if u.ToolsTTLSeconds < 1 || u.ToolsTTLSeconds > 3600 {
		return errors.New("tools_ttl_seconds must be from 1 to 3600")
	}
	if u.CredentialHeader != "" && u.CredentialEnv == "" {
		return errors.New("credential_header needs credential_env")
	}
	if strings.ContainsAny(u.CredentialHeader, " :\r\n") {
		return errors.New("credential_header must be a header name")
	}
	switch h := strings.ToLower(u.CredentialHeader); {
	case strings.HasPrefix(h, "mcp-"), h == "host", h == "content-type", h == "content-length", h == "accept", h == "transfer-encoding":
		return errors.New("credential_header must not be a protocol header")
	}
	if u.CredentialEnv != "" && getenv != nil {
		u.credential = getenv(u.CredentialEnv)
		if u.credential == "" {
			return fmt.Errorf("environment variable %s is empty", u.CredentialEnv)
		}
		if strings.ContainsAny(u.credential, "\r\n") {
			return fmt.Errorf("environment variable %s contains a line break", u.CredentialEnv)
		}
	}
	return nil
}

// identityAgents converts the configured agents for the authenticator.
func (c *Config) identityAgents() []identity.Agent {
	out := make([]identity.Agent, 0, len(c.Agents))
	for _, a := range c.Agents {
		var h [32]byte
		b, _ := hex.DecodeString(a.TokenSHA256)
		copy(h[:], b)
		out = append(out, identity.Agent{ID: a.ID, Owner: a.Owner, Scopes: a.Scopes, TokenSHA256: h})
	}
	return out
}

// NewAuthenticator builds the authenticator for this configuration.
func (c *Config) NewAuthenticator(keys map[string][]byte, activeKey string) (*identity.Authenticator, error) {
	cfg := identity.Config{Agents: c.identityAgents()}
	if len(keys) > 0 {
		if c.Tokens == nil {
			return nil, errors.New("config: signing keys are set but the config has no tokens section")
		}
		cfg.Keys, cfg.ActiveKey = keys, activeKey
		cfg.Issuer, cfg.Audience = c.Tokens.Issuer, c.Tokens.Audience
		cfg.MaxTTL = time.Duration(c.Tokens.MaxTTLSeconds) * time.Second
	}
	if err := c.addIssuers(&cfg, nil); err != nil {
		return nil, err
	}
	return identity.New(cfg)
}

// NewRingAuthenticator builds the authenticator for this configuration
// with signed tokens on an HS256 key ring (internal/platform/keys): its
// current key signs, and every key it accepts verifies, so the ring may
// rotate under the authenticator. A nil ring accepts static keys only,
// and the configured issuers' tokens with keys from LazyIssuerKeys.
func (c *Config) NewRingAuthenticator(ring *keys.Ring) (*identity.Authenticator, error) {
	return c.NewIssuerAuthenticator(ring, nil)
}

func (c *Config) ringConfig(ring *keys.Ring) (identity.Config, error) {
	cfg := identity.Config{Agents: c.identityAgents()}
	if ring != nil {
		if c.Tokens == nil {
			return cfg, errors.New("config: signing keys are set but the config has no tokens section")
		}
		cfg.Ring = ring
		cfg.Issuer, cfg.Audience = c.Tokens.Issuer, c.Tokens.Audience
		cfg.MaxTTL = time.Duration(c.Tokens.MaxTTLSeconds) * time.Second
	}
	return cfg, nil
}

// MaxTokenTTL is the longest lifetime a signed token may have under this
// configuration: tokens.max_ttl_seconds, or identity.DefaultMaxTTL.
func (c *Config) MaxTokenTTL() time.Duration {
	if c.Tokens == nil || c.Tokens.MaxTTLSeconds == 0 {
		return identity.DefaultMaxTTL
	}
	return time.Duration(c.Tokens.MaxTTLSeconds) * time.Second
}
