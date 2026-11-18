package gateway

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/agents/egress"
	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/platform/keys"
)

// Limits on the issuers section.
const (
	// MaxPrivateNetworks bounds an issuer's private_networks.
	MaxPrivateNetworks = 16
	// MaxCAFileBytes bounds an issuer's ca_file.
	MaxCAFileBytes = 1 << 20
)

// ClaimsConfig names the claims an issuer's tokens carry the agent in;
// empty members take identity.ClaimMap's defaults (sub, owner, scope).
type ClaimsConfig struct {
	Subject string `json:"subject"`
	Owner   string `json:"owner"`
	Scopes  string `json:"scopes"`
}

// IssuerConfig is one external issuer of asymmetrically signed agent
// tokens: an authorization server or identity provider whose keys are
// fetched from its pinned jwks_uri.
//
//	{"issuer": "https://idp.example.com", "audience": "https://mcp.example.com",
//	 "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
//	 "algorithms": ["ES256"], "claims": {"subject": "azp", "scopes": "scp"},
//	 "max_ttl_seconds": 900}
type IssuerConfig struct {
	Issuer   string `json:"issuer"`   // the iss claim, exactly
	Audience string `json:"audience"` // the gateway's resource indicator
	JWKSURI  string `json:"jwks_uri"` // absolute https URL
	// Algorithms narrows EdDSA, ES256 and RS256; empty accepts all three.
	Algorithms []string     `json:"algorithms"`
	Claims     ClaimsConfig `json:"claims"`
	// MaxTTLSeconds is the longest accepted token lifetime, exp - iat;
	// 0 is identity.DefaultMaxTTL.
	MaxTTLSeconds int `json:"max_ttl_seconds"`
	// PrivateNetworks are the addresses or CIDR ranges outside the public
	// internet the JWKS fetch may connect to, for an issuer on the
	// private network. Every other non-public address is refused.
	PrivateNetworks []string `json:"private_networks"`
	// CAFile is a PEM bundle that replaces the system's trusted CAs for
	// the JWKS fetch.
	CAFile string `json:"ca_file"`
}

// identityIssuer is ic for the authenticator, with its keys from ks.
func (ic IssuerConfig) identityIssuer(ks identity.KeySource) identity.Issuer {
	return identity.Issuer{Issuer: ic.Issuer, Audience: ic.Audience, Keys: ks,
		Algorithms: ic.Algorithms, MaxTTL: time.Duration(ic.MaxTTLSeconds) * time.Second,
		Claims: identity.ClaimMap{Subject: ic.Claims.Subject, Owner: ic.Claims.Owner, Scopes: ic.Claims.Scopes}}
}

// Check validates ic without reading its CA file.
func (ic IssuerConfig) Check() error {
	if ic.MaxTTLSeconds < 0 || ic.MaxTTLSeconds > int(identity.MaxIssuerTTL/time.Second) {
		return fmt.Errorf("max_ttl_seconds must be from 0 to %d", int(identity.MaxIssuerTTL/time.Second))
	}
	if err := identity.CheckIssuer(ic.identityIssuer(nil), 0); err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "identity: "))
	}
	if ic.JWKSURI == "" {
		return errors.New("jwks_uri is required")
	}
	if identity.CheckJWKSURL(ic.JWKSURI) != nil {
		return fmt.Errorf("jwks_uri %q must be an absolute https URL without user info or fragment", ic.JWKSURI)
	}
	if len(ic.PrivateNetworks) > MaxPrivateNetworks {
		return fmt.Errorf("private_networks has more than %d entries", MaxPrivateNetworks)
	}
	if _, err := egress.ParseAllow(ic.PrivateNetworks); err != nil {
		return fmt.Errorf("private_networks: %s", strings.TrimPrefix(err.Error(), "egress: "))
	}
	return nil
}

// CheckIssuers validates an issuers list: each issuer, at most
// identity.MaxIssuers of them, and no iss twice. Errors name the
// issuer's index.
func CheckIssuers(list []IssuerConfig) error {
	if len(list) > identity.MaxIssuers {
		return fmt.Errorf("at most %d issuers", identity.MaxIssuers)
	}
	seen := map[string]bool{}
	for i, ic := range list {
		if err := ic.Check(); err != nil {
			return fmt.Errorf("issuers[%d]: %w", i, err)
		}
		if seen[ic.Issuer] {
			return fmt.Errorf("issuers[%d]: issuer %q is configured twice", i, ic.Issuer)
		}
		seen[ic.Issuer] = true
	}
	return nil
}

// WithIssuers returns a copy of c with more issuers after its own, as
// the platform file's mcp section adds them to the agents config's. The
// combined list is checked as one.
func (c *Config) WithIssuers(more []IssuerConfig) (*Config, error) {
	if len(more) == 0 {
		return c, nil
	}
	out := *c
	out.Issuers = append(slices.Clip(c.Issuers), more...)
	if err := CheckIssuers(out.Issuers); err != nil {
		return nil, err
	}
	if err := out.checkAudiences(); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReadCA reads and parses ic's CA file; nil without one.
func (ic IssuerConfig) ReadCA() (*x509.CertPool, []byte, error) {
	if ic.CAFile == "" {
		return nil, nil, nil
	}
	pem, err := readCapped(ic.CAFile, MaxCAFileBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ca_file: %w", err)
	}
	pool, err := ParseCA(pem)
	if err != nil {
		return nil, nil, fmt.Errorf("ca_file %s: %w", ic.CAFile, err)
	}
	return pool, pem, nil
}

// ParseCA parses a PEM bundle of CA certificates.
func ParseCA(pem []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("holds no PEM certificate")
	}
	return pool, nil
}

func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	b := make([]byte, fi.Size())
	if _, err := f.ReadAt(b, 0); err != nil && fi.Size() > 0 {
		return nil, err
	}
	return b, nil
}

// JWKSKey identifies the JWKS client ic's keys come from: its jwks_uri,
// private networks and CA certificates (ca, as ReadCA returns them).
// Issuers with one key share a client, and a reload keeps a client while
// its key is unchanged.
func (ic IssuerConfig) JWKSKey(ca []byte) string {
	nets := slices.Clone(ic.PrivateNetworks)
	slices.Sort(nets)
	h := sha256.Sum256(ca)
	return ic.JWKSURI + "\x00" + strings.Join(nets, ",") + "\x00" + hex.EncodeToString(h[:])
}

// NewJWKS builds the JWKS client for ic, with ca the CA pool from
// ReadCA. It does not fetch; run it to refresh on schedule.
func (ic IssuerConfig) NewJWKS(ca *x509.CertPool, log *slog.Logger) (*identity.JWKS, error) {
	allow, err := egress.ParseAllow(ic.PrivateNetworks)
	if err != nil {
		return nil, err
	}
	return identity.NewJWKS(identity.JWKSConfig{URL: ic.JWKSURI, Guard: egress.New(allow...), RootCAs: ca, Logger: log})
}

// IssuerKeys gives the key source for an issuer.
type IssuerKeys func(IssuerConfig) (identity.KeySource, error)

// LazyIssuerKeys gives each issuer a JWKS client of its own that is not
// run: it fetches the key set on the first token it sees, and again for a
// kid it does not hold. A server shares and runs its clients instead.
func LazyIssuerKeys(ic IssuerConfig) (identity.KeySource, error) {
	ca, _, err := ic.ReadCA()
	if err != nil {
		return nil, err
	}
	return ic.NewJWKS(ca, nil)
}

// NewIssuerAuthenticator builds the authenticator for this configuration
// as NewRingAuthenticator does, with the configured issuers' keys from
// issuerKeys (LazyIssuerKeys when nil).
func (c *Config) NewIssuerAuthenticator(ring *keys.Ring, issuerKeys IssuerKeys) (*identity.Authenticator, error) {
	cfg, err := c.ringConfig(ring)
	if err != nil {
		return nil, err
	}
	if err := c.addIssuers(&cfg, issuerKeys); err != nil {
		return nil, err
	}
	return identity.New(cfg)
}

// addIssuers adds the configured issuers to cfg.
func (c *Config) addIssuers(cfg *identity.Config, issuerKeys IssuerKeys) error {
	if issuerKeys == nil {
		issuerKeys = LazyIssuerKeys
	}
	for i, ic := range c.Issuers {
		ks, err := issuerKeys(ic)
		if err != nil {
			return fmt.Errorf("config: issuers[%d] (%q): %w", i, ic.Issuer, err)
		}
		cfg.Issuers = append(cfg.Issuers, ic.identityIssuer(ks))
	}
	return nil
}
