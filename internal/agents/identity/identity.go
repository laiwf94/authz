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
//     The keys are a configured list (Config.Keys) or an HS256 ring of
//     internal/platform/keys (Config.Ring): the ring's current key signs,
//     and its next key and retired keys inside their overlap verify, so a
//     ring rotating on schedule never refuses a token its old key signed
//     until the overlap ends.
//     Tokens are parsed, signed and verified by the platform JOSE library
//     (internal/platform/jose), which the sign-on gateway uses too.
//   - Asymmetrically signed tokens: the same claims in a compact JWS signed
//     with EdDSA (Ed25519), ES256 (P-256) or RS256 (RSA, 2048 bits or more)
//     by an issuer holding the private key. The public keys come from a
//     KeySource (Config.PublicKeys), never from the token, and each key
//     verifies only the algorithm of its key type (and its JWK "alg", when
//     set); Config.Algorithms narrows the accepted algorithms. HS256 tokens
//     are checked only against the shared secrets and asymmetric ones only
//     against the public keys, so neither can stand in for the other.
//     The KeySource is a fixed KeySet, or a JWKS client (NewJWKS) that
//     fetches a pinned issuer's jwks_uri through the egress guard
//     (internal/agents/egress), at most 64 KiB, without redirects, with
//     ETag revalidation, a scheduled refresh and at most one fetch a
//     minute for kids it doesn't hold.
//   - Tokens of other issuers (Config.Issuers): an authorization server or
//     identity provider pinned by its iss, with its own KeySource,
//     audience (aud may be a string or an array holding it), algorithms,
//     longest lifetime and claim mapping, which names the claims holding
//     the agent id, its owner and its scopes (a space-separated string or
//     an array). A token's unverified iss picks the issuer, and only that
//     issuer's keys may verify it; claims are read only after that, and a
//     claims set with a member name twice is refused. Config.PublicKeys is
//     one such issuer under Config.Issuer with the default claims.
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
	"slices"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/agents/policy"
	"github.com/laiwf94/authz/internal/platform/jose"
	"github.com/laiwf94/authz/internal/platform/keys"
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
	Issuer    string    // signed tokens: the iss claim
	KeyID     string    // signed tokens: the key that verified it; static keys: an issued key's id
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
	// Ring, instead of Keys and ActiveKey, is an HS256 key ring: its
	// current key signs, and every key it accepts at Now verifies.
	Ring *keys.Ring
	// PublicKeys verifies tokens signed with an algorithm of Algorithms
	// (default AsymmetricAlgorithms).
	PublicKeys KeySource
	Algorithms []string
	// Issuers are more issuers of asymmetrically signed tokens, each with
	// its own keys, audience, algorithms, claim mapping and lifetime.
	Issuers  []Issuer
	Issuer   string
	Audience string
	MaxTTL   time.Duration // longest accepted exp - iat; default DefaultMaxTTL
	Leeway   time.Duration // clock skew allowed; default DefaultLeeway
	Now      func() time.Time
	// Static, when set, is the persisted static key set (a
	// keys.StaticStore at the gateway's clock): configured keys it revoked
	// are refused, and the keys it issued authenticate as their agent,
	// which Agents must list.
	Static StaticSource
}

// StaticSource holds the static keys issued and revoked while the gateway
// runs, read at the source's own clock: the one the keys' overlaps were
// set by.
type StaticSource interface {
	// Issued returns the agent and key id of the issued key with digest
	// sum, if it verifies now.
	Issued(sum [sha256.Size]byte) (agent, id string, ok bool)
	// ConfigActive reports whether the configured key with digest sum
	// still verifies now.
	ConfigActive(sum [sha256.Size]byte) bool
}

// Authenticator verifies credentials. It is safe for concurrent use.
type Authenticator struct {
	agents  []Agent
	cfg     Config
	issuers map[string]*trustedIssuer // by iss; read-only after New
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
	if cfg.Ring != nil {
		if len(cfg.Keys) > 0 || cfg.ActiveKey != "" {
			return nil, errors.New("identity: configure signing keys or a key ring, not both")
		}
		if cfg.Ring.Alg() != keys.HS256 {
			return nil, fmt.Errorf("identity: key ring holds %s keys, want %s", cfg.Ring.Alg(), keys.HS256)
		}
	}
	if len(cfg.Keys) > 0 {
		if _, ok := cfg.Keys[cfg.ActiveKey]; !ok {
			return nil, errors.New("identity: the active key id is not among the keys")
		}
	}
	if cfg.PublicKeys == nil && len(cfg.Algorithms) > 0 {
		return nil, errors.New("identity: algorithms are set but there are no public keys")
	}
	if len(cfg.Keys) > 0 || cfg.Ring != nil || cfg.PublicKeys != nil {
		if cfg.Issuer == "" || cfg.Audience == "" {
			return nil, errors.New("identity: signed tokens need an issuer and an audience")
		}
	}
	issuers, err := newIssuers(cfg)
	if err != nil {
		return nil, err
	}
	cfg.Issuers = slices.Clone(cfg.Issuers)
	return &Authenticator{agents: cfg.Agents, cfg: cfg, issuers: issuers}, nil
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
	if a.cfg.Static == nil {
		if found < 0 {
			return Identity{}, unauthenticated("unknown static key")
		}
		ag := a.agents[found]
		return Identity{AgentID: ag.ID, Owner: ag.Owner, Scopes: ag.Scopes, Method: "static"}, nil
	}
	if found >= 0 {
		if !a.cfg.Static.ConfigActive(sum) {
			return Identity{}, unauthenticated("revoked static key")
		}
		ag := a.agents[found]
		return Identity{AgentID: ag.ID, Owner: ag.Owner, Scopes: ag.Scopes, Method: "static"}, nil
	}
	// Issued keys are found by their digest. A map lookup on the SHA-256
	// of a random key reveals nothing an attacker can steer towards it.
	agent, kid, ok := a.cfg.Static.Issued(sum)
	if !ok {
		return Identity{}, unauthenticated("unknown static key")
	}
	i := slices.IndexFunc(a.agents, func(ag Agent) bool { return ag.ID == agent })
	if i < 0 {
		return Identity{}, unauthenticated("static key of agent %q, which the configuration no longer lists", agent)
	}
	ag := a.agents[i]
	return Identity{AgentID: ag.ID, Owner: ag.Owner, Scopes: ag.Scopes, Method: "static", KeyID: kid}, nil
}

// WithStatic returns a copy of a that also checks static keys against src
// (see Config.Static); nil checks only the configured digests.
func (a *Authenticator) WithStatic(src StaticSource) *Authenticator {
	b := *a
	b.cfg.Static = src
	return &b
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
	if t.Header.Alg != jose.HS256 {
		return a.verifyIssued(t)
	}
	if err := a.verifyHMAC(t); err != nil {
		return Identity{}, err
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
		Issuer: c.Issuer, KeyID: t.Header.Kid, ExpiresAt: time.Unix(c.ExpiresAt, 0)}, nil
}

// verifyHMAC checks an HS256 token against the shared secrets. Its header
// must be exactly what Mint writes.
func (a *Authenticator) verifyHMAC(t *jose.Token) error {
	if err := t.StrictHeader(); err != nil {
		return unauthenticated("bad header: %v", err)
	}
	if h := t.Header; h.Typ != "" && h.Typ != "JWT" {
		return unauthenticated("unsupported token type %q", h.Typ)
	}
	key, ok := a.verifyKey(t.Header.Kid)
	if !ok {
		return unauthenticated("unknown key id")
	}
	if err := t.VerifyHMAC(key); err != nil {
		return unauthenticated("bad signature")
	}
	return nil
}

// verifyKey returns the secret of the key kid names, if it verifies now.
func (a *Authenticator) verifyKey(kid string) ([]byte, bool) {
	if a.cfg.Ring == nil {
		key, ok := a.cfg.Keys[kid]
		return key, ok
	}
	k := a.cfg.Ring.Lookup(kid, a.cfg.Now())
	if k == nil {
		return nil, false
	}
	return k.Secret(), true
}

// Mint signs a token for subject with the active key, or the ring's
// current key.
func (a *Authenticator) Mint(subject, owner string, scopes []string, ttl time.Duration) (string, error) {
	kid, key := a.cfg.ActiveKey, a.cfg.Keys[a.cfg.ActiveKey]
	if a.cfg.Ring != nil {
		k := a.cfg.Ring.Current()
		kid, key = k.ID(), k.Secret()
	}
	if key == nil {
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
	return jose.SignHMAC(kid, key, c)
}
