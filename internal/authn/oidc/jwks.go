package oidc

import (
	"context"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/platform/jose"
)

// JWKS cache timing.
const (
	jwksDefaultTTL = time.Hour
	jwksMinTTL     = 5 * time.Minute
	jwksMaxTTL     = 24 * time.Hour
	// jwksMinRefresh bounds re-fetches triggered by an unknown kid, so a
	// stream of tokens with random kids can't make us hammer the provider.
	jwksMinRefresh = time.Minute
)

// keyCache holds a provider's signing keys. A token with an unknown kid
// triggers one re-fetch (the provider may have rotated keys), at most once
// per jwksMinRefresh.
type keyCache struct {
	fetch func(ctx context.Context) ([]byte, time.Duration, error)
	now   func() time.Time

	mu          sync.Mutex
	set         *jose.KeySet
	expires     time.Time
	lastAttempt time.Time
	fetches     int
}

func (c *keyCache) refresh(ctx context.Context) error {
	c.lastAttempt = c.now()
	c.fetches++
	body, maxAge, err := c.fetch(ctx)
	if err != nil {
		return fail(ReasonJWKS, "%v", err)
	}
	set, err := jose.ParseKeySet(body)
	if err != nil {
		return fail(ReasonJWKS, "%v", err)
	}
	ttl := jwksDefaultTTL
	if maxAge >= 0 {
		ttl = min(max(maxAge, jwksMinTTL), jwksMaxTTL)
	}
	c.set, c.expires = set, c.now().Add(ttl)
	return nil
}

// key returns the key for kid that can verify alg.
func (c *keyCache) key(ctx context.Context, kid, alg string) (jose.Key, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	canRefresh := now.Sub(c.lastAttempt) >= jwksMinRefresh || c.lastAttempt.IsZero()
	if c.set == nil || !now.Before(c.expires) {
		if err := c.refresh(ctx); err != nil && c.set == nil {
			return jose.Key{}, err
		}
		// On a failed refresh keep serving the previous keys: a provider
		// outage should not log everyone out of new logins at once.
		canRefresh = false
	}
	if k, ok := find(c.set, kid, alg); ok {
		return k, nil
	}
	if canRefresh {
		if err := c.refresh(ctx); err != nil {
			return jose.Key{}, err
		}
		if k, ok := find(c.set, kid, alg); ok {
			return k, nil
		}
	}
	return jose.Key{}, fail(ReasonUnknownKey, "no key with kid %q for %s", kid, alg)
}

// find picks the key by kid. Without a kid, it is accepted only if exactly
// one key could verify alg.
func find(set *jose.KeySet, kid, alg string) (jose.Key, bool) {
	var match []jose.Key
	for _, k := range set.Keys {
		if kid != "" && k.ID != kid {
			continue
		}
		if !k.Fits(alg) {
			continue
		}
		match = append(match, k)
	}
	if len(match) != 1 {
		return jose.Key{}, false
	}
	return match[0], true
}

// Probe fetches the discovery document and the signing keys now, instead
// of on first use, so a configuration check can tell whether the provider
// is reachable and usable. It fails when no published key can verify any
// of the configured algorithms.
func (p *Provider) Probe(ctx context.Context) (*Metadata, error) {
	m, err := p.Discover(ctx)
	if err != nil {
		return nil, err
	}
	c := p.keys
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	for _, k := range c.set.Keys {
		for _, alg := range p.cfg.Algorithms {
			if k.Fits(alg) {
				return m, nil
			}
		}
	}
	return nil, fail(ReasonJWKS, "no key in %s can verify %v", redact(m.JWKSURI), p.cfg.Algorithms)
}
