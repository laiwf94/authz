// Package oidc is an OpenID Connect relying party for the authorization code
// flow with PKCE (OpenID Connect Core 1.0, Discovery 1.0, RFC 6749, RFC 7636),
// following the OAuth 2.0 Security Best Current Practice (RFC 9700).
package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/authn/policy"
	"github.com/laiwf94/authz/internal/platform/jose"
)

// Defaults.
const (
	DefaultSkew       = 2 * time.Minute
	discoveryTTL      = time.Hour
	discoveryRetry    = 30 * time.Second
	idTokenMaxAge     = 10 * time.Minute
	maxSubjectLength  = 255
	maxClaimLength    = 512
	MaxGroups         = 256
	maxGroupLength    = 256
	ClientSecretBasic = "client_secret_basic"
	ClientSecretPost  = "client_secret_post"
	ClientAuthNone    = "none"
)

// DefaultAlgorithms are accepted for ID tokens unless configured otherwise.
var DefaultAlgorithms = []string{"RS256", "PS256", "ES256"}

// Config describes one OpenID provider.
type Config struct {
	ID               string
	Issuer           string
	ClientID         string
	ClientSecret     string
	ClientAuth       string // client_secret_basic (default), client_secret_post or none
	RedirectURL      string
	Scopes           []string
	Algorithms       []string
	EmailClaim       string
	NameClaim        string
	GroupsClaim      string
	UseUserinfo      bool
	TrustedAudiences []string
	Skew             time.Duration
	HTTPClient       *http.Client
	Now              func() time.Time
}

// Metadata is the subset of the discovery document this relying party uses.
type Metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	ResponseTypes         []string `json:"response_types_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

// Provider talks to one OpenID provider. It is safe for concurrent use.
type Provider struct {
	cfg  Config
	keys *keyCache

	mu          sync.Mutex
	meta        *Metadata
	metaExpires time.Time
	metaErrAt   time.Time
	metaErr     error
}

// New validates cfg. It does no network I/O: discovery happens on first use,
// so the gateway starts even while a provider is down.
func New(cfg Config) (*Provider, error) {
	if err := requireHTTPS("issuer", cfg.Issuer); err != nil {
		return nil, err
	}
	if cfg.ClientID == "" {
		return nil, errors.New("client_id is required")
	}
	switch cfg.ClientAuth {
	case "":
		cfg.ClientAuth = ClientSecretBasic
	case ClientSecretBasic, ClientSecretPost, ClientAuthNone:
	default:
		return nil, fmt.Errorf("client_auth %q is not one of client_secret_basic, client_secret_post, none", cfg.ClientAuth)
	}
	if cfg.ClientAuth != ClientAuthNone && cfg.ClientSecret == "" {
		return nil, fmt.Errorf("a client secret is required for %s", cfg.ClientAuth)
	}
	if err := requireHTTPS("redirect URL", cfg.RedirectURL); err != nil {
		return nil, err
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	hasOpenID := false
	for _, s := range cfg.Scopes {
		if s == "openid" {
			hasOpenID = true
		}
		if s == "" || strings.ContainsAny(s, " \"\\") {
			return nil, fmt.Errorf("invalid scope %q", s)
		}
	}
	if !hasOpenID {
		return nil, errors.New(`scopes must include "openid"`)
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = DefaultAlgorithms
	}
	for _, a := range cfg.Algorithms {
		if !jose.IsSupported(a) {
			return nil, fmt.Errorf("algorithm %q is not allowed (use one of %v)", a, jose.SupportedAlgorithms)
		}
	}
	if cfg.EmailClaim == "" {
		cfg.EmailClaim = "email"
	}
	if cfg.NameClaim == "" {
		cfg.NameClaim = "name"
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.Skew <= 0 {
		cfg.Skew = DefaultSkew
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = NewHTTPClient(nil)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	p := &Provider{cfg: cfg}
	p.keys = &keyCache{now: cfg.Now, fetch: func(ctx context.Context) ([]byte, time.Duration, error) {
		m, err := p.Discover(ctx)
		if err != nil {
			return nil, -1, err
		}
		return get(ctx, p.cfg.HTTPClient, m.JWKSURI, "")
	}}
	return p, nil
}

// ID returns the provider id from the configuration.
func (p *Provider) ID() string { return p.cfg.ID }

// Discover returns the provider metadata, fetched from
// {issuer}/.well-known/openid-configuration and cached for an hour. A failed
// fetch is remembered for 30 seconds so an outage is not amplified.
func (p *Provider) Discover(ctx context.Context) (*Metadata, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.cfg.Now()
	if p.meta != nil && now.Before(p.metaExpires) {
		return p.meta, nil
	}
	if p.metaErr != nil && now.Sub(p.metaErrAt) < discoveryRetry {
		if p.meta != nil {
			return p.meta, nil
		}
		return nil, p.metaErr
	}
	m, err := p.fetchMetadata(ctx)
	if err != nil {
		p.metaErr, p.metaErrAt = err, now
		if p.meta != nil {
			return p.meta, nil
		}
		return nil, err
	}
	p.meta, p.metaExpires, p.metaErr = m, now.Add(discoveryTTL), nil
	return m, nil
}

func (p *Provider) fetchMetadata(ctx context.Context) (*Metadata, error) {
	u := strings.TrimSuffix(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	body, _, err := get(ctx, p.cfg.HTTPClient, u, "")
	if err != nil {
		return nil, fail(ReasonDiscovery, "%v", err)
	}
	var m Metadata
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fail(ReasonDiscovery, "decoding metadata: %v", err)
	}
	// Discovery section 4.3: the issuer in the document must be exactly the
	// one we asked, or a provider could claim another's identity.
	if m.Issuer != p.cfg.Issuer {
		return nil, fail(ReasonDiscovery, "metadata issuer %q does not match configured issuer %q", m.Issuer, p.cfg.Issuer)
	}
	for field, v := range map[string]string{"authorization_endpoint": m.AuthorizationEndpoint,
		"token_endpoint": m.TokenEndpoint, "jwks_uri": m.JWKSURI} {
		if err := requireHTTPS(field, v); err != nil {
			return nil, fail(ReasonDiscovery, "%v", err)
		}
	}
	for field, v := range map[string]string{"userinfo_endpoint": m.UserinfoEndpoint, "end_session_endpoint": m.EndSessionEndpoint} {
		if v != "" {
			if err := requireHTTPS(field, v); err != nil {
				return nil, fail(ReasonDiscovery, "%v", err)
			}
		}
	}
	if len(m.ResponseTypes) > 0 && !contains(m.ResponseTypes, "code") {
		return nil, fail(ReasonDiscovery, "provider does not support the code flow")
	}
	if len(m.CodeChallengeMethods) > 0 && !contains(m.CodeChallengeMethods, "S256") {
		return nil, fail(ReasonDiscovery, "provider does not support PKCE with S256")
	}
	if p.cfg.UseUserinfo && m.UserinfoEndpoint == "" {
		return nil, fail(ReasonDiscovery, "userinfo is enabled but the provider has no userinfo_endpoint")
	}
	return &m, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// RandomToken returns 32 random bytes, base64url encoded (43 characters).
// Used for state, nonce and the PKCE code verifier (RFC 7636 section 4.1).
func RandomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Challenge is the S256 PKCE challenge for a verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthURL returns the authorization request URL.
func (p *Provider) AuthURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	m, err := p.Discover(ctx)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(m.AuthorizationEndpoint)
	if err != nil {
		return "", fail(ReasonDiscovery, "authorization_endpoint: %v", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", strings.Join(p.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", Challenge(verifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Result is a completed login.
type Result struct {
	Identity policy.Identity
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// Exchange redeems an authorization code, validates the ID token against
// the nonce from the login request, and maps the claims to an identity.
func (p *Provider) Exchange(ctx context.Context, code, verifier, nonce string) (*Result, error) {
	if code == "" || len(code) > 4096 {
		return nil, fail(ReasonTokenExchange, "missing or oversized code")
	}
	m, err := p.Discover(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"code_verifier": {verifier},
	}
	switch p.cfg.ClientAuth {
	case ClientSecretPost:
		form.Set("client_id", p.cfg.ClientID)
		form.Set("client_secret", p.cfg.ClientSecret)
	case ClientAuthNone:
		form.Set("client_id", p.cfg.ClientID)
	}
	tctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(tctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fail(ReasonTokenExchange, "%v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.cfg.ClientAuth == ClientSecretBasic {
		// RFC 6749 section 2.3.1: form-encode both parts before Basic.
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}
	body, status, _, err := do(p.cfg.HTTPClient, req)
	if err != nil {
		return nil, fail(ReasonTokenExchange, "%v", err)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fail(ReasonTokenExchange, "status %d, undecodable body", status)
	}
	if status != http.StatusOK {
		return nil, fail(ReasonTokenExchange, "status %d, error %q", status, printable(tr.Error, 64))
	}
	if tr.IDToken == "" {
		return nil, fail(ReasonTokenExchange, "no id_token in the token response")
	}
	if tr.AccessToken != "" && !strings.EqualFold(tr.TokenType, "Bearer") {
		return nil, fail(ReasonTokenExchange, "token_type %q is not Bearer", printable(tr.TokenType, 32))
	}
	claims, err := p.VerifyIDToken(ctx, tr.IDToken, nonce, tr.AccessToken)
	if err != nil {
		return nil, err
	}
	if p.cfg.UseUserinfo && tr.AccessToken != "" {
		if err := p.mergeUserinfo(ctx, m, tr.AccessToken, claims); err != nil {
			return nil, err
		}
	}
	id, err := p.identity(claims)
	if err != nil {
		return nil, err
	}
	return &Result{Identity: id}, nil
}

// VerifyIDToken applies OpenID Connect Core section 3.1.3.7.
func (p *Provider) VerifyIDToken(ctx context.Context, raw, nonce, accessToken string) (*jose.Claims, error) {
	tok, err := jose.Parse(raw)
	if err != nil {
		return nil, fail(ReasonIDToken, "%v", err)
	}
	// An access token in JWT form ("at+jwt") must not pass as an ID token
	// (RFC 8725 section 3.11).
	if t := strings.ToLower(tok.Header.Typ); t != "" && t != "jwt" {
		return nil, fail(ReasonIDToken, "unexpected typ %q", printable(tok.Header.Typ, 32))
	}
	if !contains(p.cfg.Algorithms, tok.Header.Alg) {
		return nil, fail(ReasonIDToken, "algorithm %q not allowed", printable(tok.Header.Alg, 16))
	}
	key, err := p.keys.key(ctx, tok.Header.Kid, tok.Header.Alg)
	if err != nil {
		return nil, err
	}
	if err := tok.Verify(key, p.cfg.Algorithms); err != nil {
		return nil, fail(ReasonIDToken, "%v", err)
	}
	claims, err := jose.ParseClaims(tok.Payload)
	if err != nil {
		return nil, fail(ReasonClaims, "%v", err)
	}
	err = claims.Validate(jose.Expect{Issuer: p.cfg.Issuer, Audience: p.cfg.ClientID, Now: p.cfg.Now(),
		Skew: p.cfg.Skew, MaxAge: idTokenMaxAge, TrustedAudiences: p.cfg.TrustedAudiences})
	if err != nil {
		var ce *jose.ClaimError
		if errors.As(err, &ce) {
			return nil, &Error{Reason: "id_token_" + ce.Reason, Err: err}
		}
		return nil, fail(ReasonClaims, "%v", err)
	}
	if claims.Nonce == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return nil, fail(ReasonNonce, "nonce does not match the login request")
	}
	if claims.Subject == "" || len(claims.Subject) > maxSubjectLength || !isPrintableASCII(claims.Subject) {
		return nil, fail(ReasonClaims, "sub must be 1-%d printable ASCII characters", maxSubjectLength)
	}
	if claims.AccessTokenHash != "" && accessToken != "" {
		if want := AccessTokenHash(tok.Header.Alg, accessToken); subtle.ConstantTimeCompare([]byte(want), []byte(claims.AccessTokenHash)) != 1 {
			return nil, fail(ReasonIDToken, "at_hash does not match the access token")
		}
	}
	return claims, nil
}

// AccessTokenHash computes at_hash (Core section 3.1.3.6): the left half of
// the hash of the access token, with the hash of the ID token's algorithm.
func AccessTokenHash(alg, accessToken string) string {
	h := crypto.SHA256
	switch {
	case alg == "EdDSA":
		h = crypto.SHA512
	case strings.HasSuffix(alg, "384"):
		h = crypto.SHA384
	case strings.HasSuffix(alg, "512"):
		h = crypto.SHA512
	}
	d := h.New()
	d.Write([]byte(accessToken))
	sum := d.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func (p *Provider) mergeUserinfo(ctx context.Context, m *Metadata, accessToken string, claims *jose.Claims) error {
	body, _, err := get(ctx, p.cfg.HTTPClient, m.UserinfoEndpoint, accessToken)
	if err != nil {
		return fail(ReasonUserinfo, "%v", err)
	}
	var info map[string]json.RawMessage
	if err := json.Unmarshal(body, &info); err != nil {
		return fail(ReasonUserinfo, "userinfo is not a JSON object (signed userinfo is not supported)")
	}
	var sub string
	_ = json.Unmarshal(info["sub"], &sub)
	// Core section 5.3.2: the userinfo sub must match the ID token's, or the
	// response may belong to someone else.
	if sub != claims.Subject {
		return fail(ReasonUserinfo, "userinfo sub does not match the ID token")
	}
	for _, name := range []string{p.cfg.EmailClaim, "email_verified", p.cfg.NameClaim, p.cfg.GroupsClaim} {
		if _, have := claims.Raw[name]; !have {
			if v, ok := info[name]; ok {
				claims.Raw[name] = v
			}
		}
	}
	return nil
}

func (p *Provider) identity(c *jose.Claims) (policy.Identity, error) {
	id := policy.Identity{Provider: p.cfg.ID, Subject: c.Subject}
	// An address the provider says is unverified is not used for policy.
	if verified, ok := c.Bool("email_verified"); !ok || verified {
		id.Email = NormalizeEmail(c.String(p.cfg.EmailClaim))
	}
	id.Name = printable(c.String(p.cfg.NameClaim), maxClaimLength)
	groups, err := c.Strings(p.cfg.GroupsClaim)
	if err != nil {
		return id, fail(ReasonClaims, "%v", err)
	}
	if id.Groups, err = CleanGroups(groups); err != nil {
		return id, fail(ReasonClaims, "%v", err)
	}
	return id, nil
}

// NormalizeEmail returns a lower-cased address, or "" if it doesn't look
// like exactly one local part and one domain.
func NormalizeEmail(s string) string {
	if len(s) > 254 || !isPrintableASCII(s) || strings.Count(s, "@") != 1 {
		return ""
	}
	at := strings.IndexByte(s, '@')
	if at == 0 || at == len(s)-1 || strings.ContainsAny(s, " ,;<>\"") {
		return ""
	}
	return strings.ToLower(s)
}

// CleanGroups validates group names: at most MaxGroups, each 1-256
// printable characters. Duplicates are removed.
func CleanGroups(groups []string) ([]string, error) {
	if len(groups) > MaxGroups {
		return nil, fmt.Errorf("more than %d groups", MaxGroups)
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range groups {
		if g == "" || len(g) > maxGroupLength || printable(g, maxGroupLength) != g {
			return nil, fmt.Errorf("invalid group name %q", printable(g, 64))
		}
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out, nil
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// printable truncates s to n bytes and drops control characters, for values
// that end up in headers or logs.
func printable(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == '�' {
			continue
		}
		if b.Len()+len(string(r)) > n {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// EndSessionURL returns the RP-initiated logout URL (OpenID Connect
// RP-Initiated Logout 1.0), or "" if the provider has none.
func (p *Provider) EndSessionURL(ctx context.Context, postLogoutRedirect string) string {
	m, err := p.Discover(ctx)
	if err != nil || m.EndSessionEndpoint == "" {
		return ""
	}
	u, err := url.Parse(m.EndSessionEndpoint)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("client_id", p.cfg.ClientID)
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// KeyFetches reports how many times the JWKS was fetched (for tests and
// metrics).
func (p *Provider) KeyFetches() int {
	p.keys.mu.Lock()
	defer p.keys.mu.Unlock()
	return p.keys.fetches
}
