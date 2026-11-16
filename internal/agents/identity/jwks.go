package identity

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laiwf94/authz/internal/agents/egress"
	"github.com/laiwf94/authz/internal/platform/clock"
	"github.com/laiwf94/authz/internal/platform/jose"
)

// JWKS client limits and defaults.
const (
	// MaxJWKSBytes caps a key set document. A set of a hundred 4096-bit
	// RSA keys is about 75 KiB; real issuers publish two to five keys.
	MaxJWKSBytes = 64 << 10
	// DefaultJWKSInterval is the refresh interval when the issuer's
	// response gives no Cache-Control max-age.
	DefaultJWKSInterval = time.Hour
	// MinJWKSInterval and MaxJWKSInterval clamp the issuer's max-age, so
	// an issuer can neither make the gateway poll it constantly nor keep
	// a revoked key alive for days.
	MinJWKSInterval = 5 * time.Minute
	MaxJWKSInterval = 24 * time.Hour
	// UnknownKidInterval is the least time between two fetches caused by
	// a token whose kid isn't in the set: an issuer that rotated its key
	// is picked up at once, and a stream of tokens with made-up kids costs
	// the issuer at most one request a minute.
	UnknownKidInterval = time.Minute
	// DefaultJWKSMaxStale is how long keys keep verifying after the last
	// successful fetch, while every refresh fails.
	DefaultJWKSMaxStale = 24 * time.Hour
	// DefaultJWKSTimeout bounds one fetch, connection included.
	DefaultJWKSTimeout = 10 * time.Second
	// jwksRetryMin is the first wait after a failed scheduled refresh; it
	// doubles on each further failure, up to the refresh interval.
	jwksRetryMin = 30 * time.Second
)

// ErrJWKS wraps every failed key set fetch.
var ErrJWKS = errors.New("identity: JWKS fetch failed")

// JWKSConfig configures a JWKS client for one pinned issuer.
type JWKSConfig struct {
	// URL is the issuer's jwks_uri: an absolute https URL from
	// configuration. Keys are fetched only from it, never from a URL a
	// token names.
	URL string
	// Guard checks every connection's address; default egress.New(),
	// which allows public addresses only.
	Guard *egress.Guard
	// RootCAs, when set, replaces the system's trusted CAs.
	RootCAs *x509.CertPool
	// Interval is the refresh interval when the response has no max-age;
	// default DefaultJWKSInterval. It is clamped like max-age.
	Interval time.Duration
	// MaxStale is how long keys keep verifying after the last successful
	// fetch; default DefaultJWKSMaxStale. After it Lookup finds no key.
	MaxStale time.Duration
	// Timeout bounds one fetch; default DefaultJWKSTimeout.
	Timeout time.Duration
	Clock   clock.Clock
	Logger  *slog.Logger
}

// JWKS is a KeySource that fetches a pinned issuer's key set.
//
// Lookup reads the current set without locking. A kid the set doesn't
// hold starts one fetch, at most once per UnknownKidInterval, and lookups
// for unknown kids made while it runs wait for it; lookups for known kids
// never wait. Run refreshes the set on schedule. A fetch that fails, or
// returns a set with no usable key, leaves the current set in place; keys
// the issuer stops publishing stop verifying at the next successful fetch.
// Fetches send If-None-Match with the last ETag, and a 304 keeps the set.
type JWKS struct {
	cfg    JWKSConfig
	url    string
	client *http.Client
	clk    clock.Clock
	log    *slog.Logger

	cur atomic.Pointer[jwksState]

	fetchMu sync.Mutex // one fetch at a time

	unknownMu   sync.Mutex
	lastUnknown time.Time     // start of the last fetch an unknown kid caused
	inflight    chan struct{} // closed when the running unknown-kid fetch ends

	fetches, notModified, failures, unknownKid atomic.Uint64
}

// jwksState is one fetched key set. It is never modified once published.
type jwksState struct {
	set      *KeySet
	kids     []string
	etag     string
	verified time.Time     // last 200 or 304
	maxAge   time.Duration // from the last response; -1 when absent
}

// JWKSStats counts a client's fetches.
type JWKSStats struct {
	Fetches     uint64 // requests sent
	NotModified uint64 // 304 answers
	Failures    uint64 // fetches that left the set unchanged by error
	UnknownKid  uint64 // fetches caused by an unknown kid
	Keys        []string
	LastSuccess time.Time
}

// NewJWKS validates cfg. It does not fetch: call Refresh to fail fast on
// a bad issuer, or let the first Lookup fetch.
func NewJWKS(cfg JWKSConfig) (*JWKS, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("identity: JWKS URL %q must be an absolute https URL without user info or fragment", cfg.URL)
	}
	if cfg.Interval < 0 || cfg.MaxStale < 0 || cfg.Timeout < 0 {
		return nil, errors.New("identity: JWKS durations must not be negative")
	}
	if cfg.Interval == 0 {
		cfg.Interval = DefaultJWKSInterval
	}
	cfg.Interval = clampInterval(cfg.Interval)
	if cfg.MaxStale == 0 {
		cfg.MaxStale = DefaultJWKSMaxStale
	}
	if cfg.MaxStale < cfg.Interval {
		return nil, fmt.Errorf("identity: JWKS max stale %v is shorter than the refresh interval %v", cfg.MaxStale, cfg.Interval)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultJWKSTimeout
	}
	if cfg.Guard == nil {
		cfg.Guard = egress.New()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	j := &JWKS{
		cfg: cfg,
		url: u.String(),
		client: &http.Client{
			Transport: cfg.Guard.Transport(cfg.RootCAs),
			Timeout:   cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirects are not followed")
			},
		},
		clk: clock.Or(cfg.Clock),
		log: cfg.Logger,
	}
	return j, nil
}

func clampInterval(d time.Duration) time.Duration {
	return min(max(d, MinJWKSInterval), MaxJWKSInterval)
}

// Lookup implements KeySource.
func (j *JWKS) Lookup(kid, alg string) (jose.Key, bool) {
	// No document could serve another algorithm, so it is no reason to
	// fetch one.
	if !slices.Contains(AsymmetricAlgorithms, alg) {
		return jose.Key{}, false
	}
	if st := j.fresh(); st != nil {
		if k, ok := st.set.Lookup(kid, alg); ok {
			return k, true
		}
	}
	if !j.fetchForUnknownKid() {
		return jose.Key{}, false
	}
	if st := j.fresh(); st != nil {
		return st.set.Lookup(kid, alg)
	}
	return jose.Key{}, false
}

// fresh returns the current state, or nil when there is none or it is
// older than MaxStale.
func (j *JWKS) fresh() *jwksState {
	st := j.cur.Load()
	if st == nil || j.clk.Since(st.verified) > j.cfg.MaxStale {
		return nil
	}
	return st
}

// fetchForUnknownKid runs, or waits for, the fetch an unknown kid causes.
// It reports whether one ran or was waited for, so the caller looks again.
func (j *JWKS) fetchForUnknownKid() bool {
	j.unknownMu.Lock()
	if ch := j.inflight; ch != nil {
		j.unknownMu.Unlock()
		<-ch
		return true
	}
	now := j.clk.Now()
	if !j.lastUnknown.IsZero() && now.Sub(j.lastUnknown) < UnknownKidInterval {
		j.unknownMu.Unlock()
		return false
	}
	ch := make(chan struct{})
	j.inflight, j.lastUnknown = ch, now
	j.unknownMu.Unlock()
	defer func() {
		j.unknownMu.Lock()
		j.inflight = nil
		j.unknownMu.Unlock()
		close(ch)
	}()
	j.unknownKid.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), j.cfg.Timeout)
	defer cancel()
	if err := j.Refresh(ctx); err != nil {
		j.log.Warn("jwks refresh for unknown kid failed", "url", j.url, "error", err)
	}
	return true
}

// Refresh fetches the key set now. On error the current set stays.
func (j *JWKS) Refresh(ctx context.Context) error {
	j.fetchMu.Lock()
	defer j.fetchMu.Unlock()
	if err := j.fetch(ctx); err != nil {
		j.failures.Add(1)
		return err
	}
	return nil
}

func (j *JWKS) fetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, j.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJWKS, err)
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	prev := j.cur.Load()
	if prev != nil && prev.etag != "" {
		req.Header.Set("If-None-Match", prev.etag)
	}
	j.fetches.Add(1)
	resp, err := j.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJWKS, err)
	}
	defer resp.Body.Close()
	maxAge := cacheMaxAge(resp.Header.Get("Cache-Control"))
	switch {
	case resp.StatusCode == http.StatusNotModified && prev != nil:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxJWKSBytes))
		next := *prev
		next.verified, next.maxAge = j.clk.Now(), maxAge
		if et := resp.Header.Get("ETag"); et != "" {
			next.etag = et
		}
		j.cur.Store(&next)
		j.notModified.Add(1)
		return nil
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("%w: GET %s: status %d", ErrJWKS, j.url, resp.StatusCode)
	}
	if resp.ContentLength > MaxJWKSBytes {
		return fmt.Errorf("%w: key set of %d bytes is larger than %d", ErrJWKS, resp.ContentLength, MaxJWKSBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil {
		return fmt.Errorf("%w: reading body: %w", ErrJWKS, err)
	}
	// A body that arrives after the deadline is no answer.
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("%w: %w", ErrJWKS, cerr)
	}
	if len(body) > MaxJWKSBytes {
		return fmt.Errorf("%w: key set larger than %d bytes", ErrJWKS, MaxJWKSBytes)
	}
	set, kids, err := ParseJWKS(body)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJWKS, err)
	}
	st := &jwksState{set: set, kids: kids, etag: resp.Header.Get("ETag"), verified: j.clk.Now(), maxAge: maxAge}
	j.cur.Store(st)
	if prev == nil || !slices.Equal(prev.kids, kids) {
		j.log.Info("jwks keys loaded", "url", j.url, "kids", kids)
	}
	return nil
}

// ParseJWKS parses a JWK Set document into a KeySet of the keys agent
// tokens may be verified with. Keys of other types, curves or algorithms,
// and encryption keys, are skipped, as RFC 7517 section 5 asks; so are
// keys without a kid in a set of more than one usable key, since no token
// could select them. A malformed key, a private key, a duplicate kid or a
// set with no usable key fails the whole document. kids lists the kept
// keys' ids in document order.
func ParseJWKS(b []byte) (set *KeySet, kids []string, err error) {
	if len(b) > MaxJWKSBytes {
		return nil, nil, fmt.Errorf("key set larger than %d bytes", MaxJWKSBytes)
	}
	raw, err := jose.ParseKeySet(b)
	if err != nil {
		return nil, nil, err
	}
	var usable []jose.Key
	for _, k := range raw.Keys {
		if checkPublicKey(k) == nil {
			usable = append(usable, k)
		}
	}
	if len(usable) > 1 {
		usable = slices.DeleteFunc(usable, func(k jose.Key) bool { return k.ID == "" })
	}
	if len(usable) == 0 {
		return nil, nil, fmt.Errorf("no key in the set can verify %v", AsymmetricAlgorithms)
	}
	set, err = NewKeySet(usable...)
	if err != nil {
		return nil, nil, err
	}
	for _, k := range usable {
		kids = append(kids, k.ID)
	}
	return set, kids, nil
}

// Run refreshes the key set until ctx ends: at once when there is no set
// yet, then every max-age the issuer sends (clamped to MinJWKSInterval
// and MaxJWKSInterval) or Interval, and after a failure in 30 seconds,
// doubling on each further failure up to the interval.
func (j *JWKS) Run(ctx context.Context) {
	wait := time.Duration(0)
	if st := j.cur.Load(); st != nil {
		wait = j.interval(st) - j.clk.Since(st.verified)
	}
	retry := jwksRetryMin
	t := j.clk.NewTimer(max(wait, 0))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
		}
		if err := j.Refresh(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			j.log.Warn("jwks refresh failed", "url", j.url, "error", err, "retry_in", retry)
			wait = retry
			if st := j.cur.Load(); st != nil {
				wait = min(retry, j.interval(st))
			}
			retry = min(retry*2, j.cfg.Interval)
		} else {
			retry = jwksRetryMin
			wait = j.interval(j.cur.Load())
		}
		t.Reset(wait)
	}
}

func (j *JWKS) interval(st *jwksState) time.Duration {
	if st.maxAge >= 0 {
		return clampInterval(st.maxAge)
	}
	return j.cfg.Interval
}

// Stats returns the client's counters and current key ids.
func (j *JWKS) Stats() JWKSStats {
	s := JWKSStats{
		Fetches:     j.fetches.Load(),
		NotModified: j.notModified.Load(),
		Failures:    j.failures.Load(),
		UnknownKid:  j.unknownKid.Load(),
	}
	if st := j.cur.Load(); st != nil {
		s.Keys = slices.Clone(st.kids)
		s.LastSuccess = st.verified
	}
	return s
}

// cacheMaxAge returns the max-age of a Cache-Control header, or -1. A
// no-store or no-cache response asks to be fetched again at the shortest
// interval.
func cacheMaxAge(h string) time.Duration {
	age := time.Duration(-1)
	for _, d := range strings.Split(h, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "no-store" || d == "no-cache" {
			return 0
		}
		if v, ok := strings.CutPrefix(d, "max-age="); ok {
			if n, err := strconv.ParseInt(strings.Trim(v, `"`), 10, 64); err == nil && n >= 0 {
				age = time.Duration(min(n, int64(MaxJWKSInterval/time.Second))) * time.Second
			}
		}
	}
	return age
}
