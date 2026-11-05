// Package identity authenticates agents.
//
// Two credential kinds are accepted as bearer tokens:
//
//   - Static keys: long random strings. The gateway stores only their SHA-256
//     and compares digests in constant time, so the configuration file holds
//     no secret.
//   - Signed tokens: a compact HS256 JWS (RFC 7515) with JWT claims (RFC 7519)
//     iss, aud, sub, owner, scope, iat, nbf, exp. Keys are named by "kid" so
//     they can rotate: verify with every configured key, sign with the newest.
//     Only HS256 is accepted; the header cannot choose a weaker algorithm.
//     Tokens are parsed, signed and verified by the platform JOSE library
//     (internal/platform/jose), which the sign-on gateway uses too.
package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/agents/policy"
	"github.com/laiwf94/authz/internal/platform/jose"
)

// Limits and defaults.
const (
	MaxTokenBytes  = 4096
	MinStaticBytes = 32
	MinKeyBytes    = 32
	MaxScopes      = 64
	DefaultLeeway  = 30 * time.Second
	DefaultMaxTTL  = time.Hour
)

// ErrUnauthenticated is returned for any credential that is not accepted.
// The wrapped detail is for server logs, not for the caller.
var ErrUnauthenticated = errors.New("invalid or expired credential")

// Identity is an authenticated agent.
type Identity struct {
	AgentID   string
	Owner     string
	Scopes    []string
	Method    string    // "static" or "signed"
	KeyID     string    // signed tokens: the key that verified it
	ExpiresAt time.Time // signed tokens only
}

// Agent is a statically configured agent.
type Agent struct {
	ID          string
	Owner       string
	Scopes      []string
	TokenSHA256 [sha256.Size]byte
}

// Config configures an Authenticator.
type Config struct {
	Agents []Agent
	// Keys maps key ids to HMAC keys. ActiveKey names the one Mint signs with.
	Keys      map[string][]byte
	ActiveKey string
	Issuer    string
	Audience  string
	MaxTTL    time.Duration // longest accepted exp - iat; default DefaultMaxTTL
	Leeway    time.Duration // clock skew allowed; default DefaultLeeway
	Now       func() time.Time
}

// Authenticator verifies credentials. It is safe for concurrent use.
type Authenticator struct {
	agents []Agent
	cfg    Config
}

var keyIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// New validates the configuration.
func New(cfg Config) (*Authenticator, error) {
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = DefaultMaxTTL
	}
	if cfg.Leeway <= 0 {
		cfg.Leeway = DefaultLeeway
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	seenID := map[string]bool{}
	seenHash := map[[sha256.Size]byte]bool{}
	for _, a := range cfg.Agents {
		if !policy.ValidAgentID(a.ID) {
			return nil, fmt.Errorf("identity: agent id %q is not valid", a.ID)
		}
		if seenID[a.ID] {
			return nil, fmt.Errorf("identity: agent %q is configured twice", a.ID)
		}
		if seenHash[a.TokenSHA256] {
			return nil, fmt.Errorf("identity: agent %q shares a token with another agent", a.ID)
		}
		if a.TokenSHA256 == ([sha256.Size]byte{}) {
			return nil, fmt.Errorf("identity: agent %q has no token hash", a.ID)
		}
		if err := checkScopes(a.Scopes); err != nil {
			return nil, fmt.Errorf("identity: agent %q: %w", a.ID, err)
		}
		if len(a.Owner) > 128 {
			return nil, fmt.Errorf("identity: agent %q: owner is longer than 128 bytes", a.ID)
		}
		seenID[a.ID], seenHash[a.TokenSHA256] = true, true
	}
	for kid, k := range cfg.Keys {
		if !keyIDRe.MatchString(kid) {
			return nil, fmt.Errorf("identity: key id %q must be 1 to 32 letters, digits, '_' or '-'", kid)
		}
		if len(k) < MinKeyBytes {
			return nil, fmt.Errorf("identity: key %q must be at least %d bytes", kid, MinKeyBytes)
		}
	}
	if len(cfg.Keys) > 0 {
		if _, ok := cfg.Keys[cfg.ActiveKey]; !ok {
			return nil, errors.New("identity: the active key id is not among the keys")
		}
		if cfg.Issuer == "" || cfg.Audience == "" {
			return nil, errors.New("identity: signed tokens need an issuer and an audience")
		}
	}
	return &Authenticator{agents: cfg.Agents, cfg: cfg}, nil
}

func checkScopes(scopes []string) error {
	if len(scopes) > MaxScopes {
		return fmt.Errorf("at most %d scopes", MaxScopes)
	}
	for _, s := range scopes {
		if !policy.ValidScope(s) {
			return fmt.Errorf("scope %q is not valid", s)
		}
	}
	return nil
}

// HashToken returns the SHA-256 of a static key, as stored in configuration.
func HashToken(token string) [sha256.Size]byte { return sha256.Sum256([]byte(token)) }

// NewStaticToken returns a fresh random static key.
func NewStaticToken() string {
	return "tgk_" + rand.Text() + rand.Text()
}

func unauthenticated(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnauthenticated, fmt.Sprintf(format, args...))
}

// Authenticate checks a bearer token.
func (a *Authenticator) Authenticate(token string) (Identity, error) {
	if token == "" || len(token) > MaxTokenBytes {
		return Identity{}, unauthenticated("missing or oversized token")
	}
	if strings.Count(token, ".") == 2 {
		return a.verifySigned(token)
	}
	if len(token) < MinStaticBytes {
		return Identity{}, unauthenticated("static key is too short")
	}
	sum := HashToken(token)
	found := -1
	for i := range a.agents {
		eq := subtle.ConstantTimeCompare(sum[:], a.agents[i].TokenSHA256[:])
		found = subtle.ConstantTimeSelect(eq, i, found)
	}
	if found < 0 {
		return Identity{}, unauthenticated("unknown static key")
	}
	ag := a.agents[found]
	return Identity{AgentID: ag.ID, Owner: ag.Owner, Scopes: ag.Scopes, Method: "static"}, nil
}

// Claims are the claims of a signed token.
type Claims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
	Owner     string `json:"owner,omitempty"`
	Scope     string `json:"scope,omitempty"` // space separated, as in RFC 8693
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	ExpiresAt int64  `json:"exp"`
	ID        string `json:"jti,omitempty"`
}

// b64 is the strict unpadded base64url of every token part (RFC 7515
// section 2), as jose decodes it; the tests build tokens with it.
var b64 = base64.RawURLEncoding.Strict()

func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func (a *Authenticator) verifySigned(token string) (Identity, error) {
	t, err := jose.Parse(token)
	if err != nil {
		return Identity{}, unauthenticated("%v", err)
	}
	if err := t.StrictHeader(); err != nil {
		return Identity{}, unauthenticated("bad header: %v", err)
	}
	h := t.Header
	if h.Alg != jose.HS256 || h.Typ != "" && h.Typ != "JWT" {
		return Identity{}, unauthenticated("unsupported algorithm %q", h.Alg)
	}
	key, ok := a.cfg.Keys[h.Kid]
	if !ok {
		return Identity{}, unauthenticated("unknown key id")
	}
	if err := t.VerifyHMAC(key); err != nil {
		return Identity{}, unauthenticated("bad signature")
	}
	var c Claims
	if err := strictJSON(t.Payload, &c); err != nil {
		return Identity{}, unauthenticated("bad claims: %v", err)
	}
	now := a.cfg.Now()
	lw := int64(a.cfg.Leeway / time.Second)
	switch {
	case c.Issuer != a.cfg.Issuer:
		return Identity{}, unauthenticated("wrong issuer")
	case c.Audience != a.cfg.Audience:
		return Identity{}, unauthenticated("wrong audience")
	case !policy.ValidAgentID(c.Subject):
		return Identity{}, unauthenticated("bad subject")
	case c.ExpiresAt == 0 || c.IssuedAt == 0 || c.NotBefore == 0:
		return Identity{}, unauthenticated("iat, nbf and exp are required")
	case now.Unix() >= c.ExpiresAt+lw:
		return Identity{}, unauthenticated("token expired")
	case now.Unix()+lw < c.NotBefore:
		return Identity{}, unauthenticated("token not yet valid")
	case now.Unix()+lw < c.IssuedAt:
		return Identity{}, unauthenticated("token issued in the future")
	case c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > int64(a.cfg.MaxTTL/time.Second):
		return Identity{}, unauthenticated("token lifetime exceeds the maximum")
	case len(c.Owner) > 128:
		return Identity{}, unauthenticated("owner too long")
	}
	scopes := strings.Fields(c.Scope)
	if err := checkScopes(scopes); err != nil {
		return Identity{}, unauthenticated("%v", err)
	}
	return Identity{AgentID: c.Subject, Owner: c.Owner, Scopes: scopes, Method: "signed",
		KeyID: h.Kid, ExpiresAt: time.Unix(c.ExpiresAt, 0)}, nil
}

// Mint signs a token for subject with the active key.
func (a *Authenticator) Mint(subject, owner string, scopes []string, ttl time.Duration) (string, error) {
	key, ok := a.cfg.Keys[a.cfg.ActiveKey]
	if !ok {
		return "", errors.New("identity: no signing key configured")
	}
	if !policy.ValidAgentID(subject) {
		return "", fmt.Errorf("identity: subject %q is not a valid agent id", subject)
	}
	if err := checkScopes(scopes); err != nil {
		return "", fmt.Errorf("identity: %w", err)
	}
	if ttl < time.Second || ttl > a.cfg.MaxTTL {
		return "", fmt.Errorf("identity: ttl must be from 1s to %s", a.cfg.MaxTTL)
	}
	if len(owner) > 128 {
		return "", errors.New("identity: owner is longer than 128 bytes")
	}
	now := a.cfg.Now().Unix()
	var jti [12]byte
	_, _ = rand.Read(jti[:])
	c := Claims{Issuer: a.cfg.Issuer, Audience: a.cfg.Audience, Subject: subject, Owner: owner,
		Scope: strings.Join(scopes, " "), IssuedAt: now, NotBefore: now,
		ExpiresAt: now + int64(ttl/time.Second), ID: hex.EncodeToString(jti[:])}
	return jose.SignHMAC(a.cfg.ActiveKey, key, c)
}
