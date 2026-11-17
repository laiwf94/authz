package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/laiwf94/authz/internal/agents/jsonrpc"
	"github.com/laiwf94/authz/internal/agents/policy"
	"github.com/laiwf94/authz/internal/platform/jose"
)

// Limits on issuers and the tokens they sign.
const (
	MaxIssuers     = 32
	MaxIssuerBytes = 1024 // an iss or aud value
	MaxClaimName   = 128
	MaxAudiences   = 16 // entries of an aud array
	MaxIssuerTTL   = 24 * time.Hour
	MaxOwnerBytes  = 128
)

// Issuer is one issuer of asymmetrically signed agent tokens: an
// authorization server or identity provider whose public keys are pinned
// in configuration. A token is matched to its issuer by its iss claim,
// and only that issuer's keys, algorithms, audience, claim mapping and
// lifetime apply to it. Config.PublicKeys, when set, is one more issuer
// with Config's Issuer, Audience, Algorithms and MaxTTL and the default
// claim mapping.
type Issuer struct {
	Issuer   string // the iss claim, exactly
	Audience string // the gateway's resource indicator; aud must hold it
	Keys     KeySource
	// Algorithms narrows the accepted algorithms; default
	// AsymmetricAlgorithms.
	Algorithms []string
	Claims     ClaimMap
	// MaxTTL is the longest accepted exp - iat; default Config.MaxTTL, at
	// most MaxIssuerTTL.
	MaxTTL time.Duration
}

// ClaimMap names the top-level claims an issuer's tokens carry the agent
// in. Names are used as they are, so a namespaced claim such as
// "https://example.com/owner" works; there is no nesting.
//
// The subject claim must be a string that is a valid agent id. The owner
// claim, when present, is a string of at most MaxOwnerBytes. The scopes
// claim, when present, is a space-separated string (RFC 8693 "scope") or
// an array of strings (as some issuers' "scp"), of at most MaxScopes
// valid scopes. Other claims are ignored, apart from the registered ones
// every issuer's tokens are checked for: iss, aud, exp, iat and nbf.
type ClaimMap struct {
	Subject string // default "sub"
	Owner   string // default "owner"
	Scopes  string // default "scope"
}

// registeredClaims may not be mapped: they have their own checks.
var registeredClaims = []string{"iss", "aud", "exp", "iat", "nbf", "jti"}

// issuer is a validated Issuer.
type trustedIssuer struct {
	Issuer
	maxTTL int64 // seconds
}

func (m ClaimMap) withDefaults() ClaimMap {
	if m.Subject == "" {
		m.Subject = "sub"
	}
	if m.Owner == "" {
		m.Owner = "owner"
	}
	if m.Scopes == "" {
		m.Scopes = "scope"
	}
	return m
}

func checkClaimName(name string) error {
	if len(name) > MaxClaimName || !utf8.ValidString(name) {
		return fmt.Errorf("claim name %q must be valid UTF-8 of at most %d bytes", name, MaxClaimName)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("claim name %q contains a control character", name)
		}
	}
	if slices.Contains(registeredClaims, name) {
		return fmt.Errorf("claim %q is checked on its own and cannot be mapped", name)
	}
	return nil
}

func checkIssuerString(what, s string) error {
	if s == "" {
		return fmt.Errorf("%s is required", what)
	}
	if len(s) > MaxIssuerBytes || !utf8.ValidString(s) {
		return fmt.Errorf("%s must be valid UTF-8 of at most %d bytes", what, MaxIssuerBytes)
	}
	return nil
}

// checkIssuer validates one issuer; defaultTTL is Config.MaxTTL.
func checkIssuer(is Issuer, defaultTTL time.Duration) (*trustedIssuer, error) {
	if err := checkIssuerString("issuer", is.Issuer); err != nil {
		return nil, err
	}
	if err := checkIssuerString("audience", is.Audience); err != nil {
		return nil, err
	}
	if is.Keys == nil {
		return nil, errors.New("no keys")
	}
	algs, err := checkAlgorithms(is.Algorithms)
	if err != nil {
		return nil, err
	}
	is.Algorithms = algs
	is.Claims = is.Claims.withDefaults()
	m := is.Claims
	for _, n := range []string{m.Subject, m.Owner, m.Scopes} {
		if err := checkClaimName(n); err != nil {
			return nil, err
		}
	}
	if m.Subject == m.Owner || m.Subject == m.Scopes || m.Owner == m.Scopes {
		return nil, errors.New("the subject, owner and scopes claims must differ")
	}
	if is.MaxTTL < 0 {
		return nil, errors.New("max TTL must not be negative")
	}
	if is.MaxTTL == 0 {
		is.MaxTTL = defaultTTL
	}
	if is.MaxTTL < time.Second || is.MaxTTL > MaxIssuerTTL {
		return nil, fmt.Errorf("max TTL must be from 1s to %s", MaxIssuerTTL)
	}
	return &trustedIssuer{Issuer: is, maxTTL: int64(is.MaxTTL / time.Second)}, nil
}

// noKeys stands in for an issuer's keys while CheckIssuer checks the rest.
type noKeys struct{}

func (noKeys) Lookup(string, string) (jose.Key, bool) { return jose.Key{}, false }

// CheckIssuer reports whether New would accept is, apart from its Keys,
// with defaultTTL as Config.MaxTTL (DefaultMaxTTL when 0). Configuration
// readers use it to check an issuer before its keys exist.
func CheckIssuer(is Issuer, defaultTTL time.Duration) error {
	if defaultTTL <= 0 {
		defaultTTL = DefaultMaxTTL
	}
	if is.Keys == nil {
		is.Keys = noKeys{}
	}
	_, err := checkIssuer(is, defaultTTL)
	return err
}

// CheckJWKSURL reports whether NewJWKS would accept u as a jwks_uri.
func CheckJWKSURL(u string) error {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Host == "" || p.User != nil || p.Fragment != "" || p.Opaque != "" {
		return fmt.Errorf("identity: JWKS URL %q must be an absolute https URL without user info or fragment", u)
	}
	return nil
}

// newIssuers validates the issuers of cfg, Config.PublicKeys first.
func newIssuers(cfg Config) (map[string]*trustedIssuer, error) {
	list := cfg.Issuers
	if cfg.PublicKeys != nil {
		list = append([]Issuer{{Issuer: cfg.Issuer, Audience: cfg.Audience, Keys: cfg.PublicKeys,
			Algorithms: cfg.Algorithms, MaxTTL: cfg.MaxTTL}}, list...)
	}
	if len(list) > MaxIssuers {
		return nil, fmt.Errorf("identity: at most %d issuers", MaxIssuers)
	}
	out := make(map[string]*trustedIssuer, len(list))
	for i, is := range list {
		v, err := checkIssuer(is, cfg.MaxTTL)
		if err != nil {
			return nil, fmt.Errorf("identity: issuer %d (%q): %w", i, is.Issuer, err)
		}
		if _, dup := out[v.Issuer.Issuer]; dup {
			return nil, fmt.Errorf("identity: issuer %q is configured twice", v.Issuer.Issuer)
		}
		out[v.Issuer.Issuer] = v
	}
	return out, nil
}

// verifyIssued verifies a token whose header names an asymmetric
// algorithm. Its unverified iss selects the issuer; the signature must
// then verify with that issuer's keys before any other claim is read.
func (a *Authenticator) verifyIssued(t *jose.Token) (Identity, error) {
	h := t.Header
	if len(a.issuers) == 0 {
		return Identity{}, unauthenticated("no public keys for %q", h.Alg)
	}
	claims, err := parseClaims(t.Payload)
	if err != nil {
		return Identity{}, unauthenticated("bad claims: %v", err)
	}
	iss, err := stringClaim(claims, "iss")
	if err != nil {
		return Identity{}, unauthenticated("%v", err)
	}
	is, ok := a.issuers[iss]
	if !ok {
		return Identity{}, unauthenticated("unknown issuer")
	}
	if !slices.Contains(is.Algorithms, h.Alg) {
		return Identity{}, unauthenticated("unsupported algorithm %q", h.Alg)
	}
	// RFC 9068 access tokens say at+jwt; other issuers JWT or nothing.
	if h.Typ != "" && h.Typ != "JWT" && h.Typ != "at+jwt" && h.Typ != "application/at+jwt" {
		return Identity{}, unauthenticated("unsupported token type %q", h.Typ)
	}
	key, ok := is.Keys.Lookup(h.Kid, h.Alg)
	if !ok {
		return Identity{}, unauthenticated("no key %q for %s", h.Kid, h.Alg)
	}
	if err := t.Verify(key, is.Algorithms); err != nil {
		return Identity{}, unauthenticated("bad signature: %v", err)
	}
	id, err := a.checkIssued(is, claims)
	if err != nil {
		return Identity{}, err
	}
	id.KeyID = key.ID
	return id, nil
}

// checkIssued checks the verified claims of a token of issuer is.
func (a *Authenticator) checkIssued(is *trustedIssuer, claims map[string]json.RawMessage) (Identity, error) {
	if err := checkAudience(claims["aud"], is.Audience); err != nil {
		return Identity{}, unauthenticated("%v", err)
	}
	sub, err := stringClaim(claims, is.Claims.Subject)
	if err != nil {
		return Identity{}, unauthenticated("%v", err)
	}
	if !policy.ValidAgentID(sub) {
		return Identity{}, unauthenticated("bad subject")
	}
	owner, err := optionalStringClaim(claims, is.Claims.Owner)
	if err != nil {
		return Identity{}, unauthenticated("%v", err)
	}
	if len(owner) > MaxOwnerBytes {
		return Identity{}, unauthenticated("owner too long")
	}
	scopes, err := scopesClaim(claims[is.Claims.Scopes])
	if err != nil {
		return Identity{}, unauthenticated("scopes: %v", err)
	}
	if err := checkScopes(scopes); err != nil {
		return Identity{}, unauthenticated("%v", err)
	}
	exp, err := dateClaim(claims, "exp", math.Floor)
	if err != nil {
		return Identity{}, unauthenticated("%v", err)
	}
	iat, err := dateClaim(claims, "iat", math.Ceil)
	if err != nil {
		return Identity{}, unauthenticated("%v", err)
	}
	nbf := iat
	if _, ok := claims["nbf"]; ok {
		if nbf, err = dateClaim(claims, "nbf", math.Ceil); err != nil {
			return Identity{}, unauthenticated("%v", err)
		}
	}
	now := a.cfg.Now().Unix()
	lw := int64(a.cfg.Leeway / time.Second)
	switch {
	case now >= exp+lw:
		return Identity{}, unauthenticated("token expired")
	case now+lw < nbf:
		return Identity{}, unauthenticated("token not yet valid")
	case now+lw < iat:
		return Identity{}, unauthenticated("token issued in the future")
	case exp <= iat || exp-iat > is.maxTTL:
		return Identity{}, unauthenticated("token lifetime exceeds the maximum")
	}
	return Identity{AgentID: sub, Owner: owner, Scopes: scopes, Method: "signed",
		Issuer: is.Issuer.Issuer, ExpiresAt: time.Unix(exp, 0)}, nil
}

// parseClaims decodes a JWT claims set: one JSON object whose member
// names are unique at every level (RFC 7519 section 4 lets a parser
// refuse duplicates; taking the last, as encoding/json does, would let
// two parsers read one token differently).
func parseClaims(payload []byte) (map[string]json.RawMessage, error) {
	if err := jsonrpc.CheckStructure(payload); err != nil {
		return nil, err
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("the claims set is not a JSON object")
	}
	if claims == nil {
		return nil, errors.New("the claims set is null")
	}
	return claims, nil
}

func stringClaim(claims map[string]json.RawMessage, name string) (string, error) {
	raw, ok := claims[name]
	if !ok {
		return "", fmt.Errorf("claim %q is missing", name)
	}
	var s string
	if raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", fmt.Errorf("claim %q is not a string", name)
	}
	return s, nil
}

// optionalStringClaim is stringClaim with an absent or null claim read
// as "".
func optionalStringClaim(claims map[string]json.RawMessage, name string) (string, error) {
	if raw, ok := claims[name]; !ok || string(raw) == "null" {
		return "", nil
	}
	return stringClaim(claims, name)
}

// checkAudience accepts an aud that is aud, or an array of at most
// MaxAudiences strings holding it (RFC 7519 section 4.1.3).
func checkAudience(raw json.RawMessage, aud string) error {
	if raw == nil {
		return errors.New("aud is missing")
	}
	var list []string
	switch raw[0] {
	case '"':
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return errors.New("aud is not a string")
		}
		list = []string{s}
	case '[':
		if json.Unmarshal(raw, &list) != nil {
			return errors.New("aud is not an array of strings")
		}
		if len(list) > MaxAudiences {
			return fmt.Errorf("aud has more than %d entries", MaxAudiences)
		}
	default:
		return errors.New("aud is not a string or an array of strings")
	}
	if !slices.Contains(list, aud) {
		return errors.New("wrong audience")
	}
	return nil
}

// scopesClaim reads a scopes claim: absent or null, a space-separated
// string, or an array of strings.
func scopesClaim(raw json.RawMessage) ([]string, error) {
	if raw == nil || string(raw) == "null" {
		return nil, nil
	}
	switch raw[0] {
	case '"':
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil, errors.New("not a string")
		}
		return strings.Fields(s), nil
	case '[':
		dec := json.NewDecoder(bytes.NewReader(raw))
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		var out []string
		for dec.More() {
			if len(out) == MaxScopes {
				return nil, fmt.Errorf("at most %d scopes", MaxScopes)
			}
			var s string
			if err := dec.Decode(&s); err != nil {
				return nil, errors.New("not an array of strings")
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, errors.New("not a string or an array of strings")
}

// maxNumericDate bounds dates: the year 5138, far past any token's life
// and far below int64 seconds.
const maxNumericDate = 1e11

// dateClaim reads a NumericDate (RFC 7519 section 2): a JSON number of
// seconds, which may have a fraction; round makes it whole, down for
// exp and up for nbf and iat, so the window is never wider than written.
func dateClaim(claims map[string]json.RawMessage, name string, round func(float64) float64) (int64, error) {
	raw, ok := claims[name]
	if !ok {
		return 0, fmt.Errorf("claim %q is missing", name)
	}
	if c := raw[0]; c != '-' && (c < '0' || c > '9') {
		return 0, fmt.Errorf("claim %q is not a number", name)
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("claim %q is not a number", name)
	}
	f = round(f)
	if f < 1 || f > maxNumericDate {
		return 0, fmt.Errorf("claim %q is out of range", name)
	}
	return int64(f), nil
}
