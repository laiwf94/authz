package server

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/platform/ratelimit"
)

// maxBuckets bounds the limiter's memory. When full, buckets that have
// refilled are dropped; if that is not enough, the half closest to full goes.
const maxBuckets = 100_000

// rateLimiter is a token bucket per client address: rate requests per
// minute, bursting up to rate. The buckets are the platform's GCRA limiter
// (internal/platform/ratelimit).
type rateLimiter struct {
	limit ratelimit.Limit
	burst float64
	lim   *ratelimit.Limiter
}

func newRateLimiter(perMinute int, now func() time.Time) *rateLimiter {
	return &rateLimiter{limit: ratelimit.PerMinute(perMinute), burst: float64(perMinute),
		lim: ratelimit.New(ratelimit.Options{Now: now, MaxKeys: maxBuckets})}
}

// allow takes one token for key. When none is left it returns how long
// until the next one.
func (l *rateLimiter) allow(key string) (time.Duration, bool) {
	ok, wait := l.lim.Take(key, l.limit)
	return wait, ok
}

// sweep drops buckets that have refilled completely; they hold no state.
func (l *rateLimiter) sweep() { l.lim.Sweep() }

// clientIP returns the client address. X-Forwarded-For is read right to
// left and believed only while the hop that added an entry is a trusted
// proxy, so a client can't pick its own rate-limit key.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	if !isTrusted(addr, trusted) {
		return addr.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		addr = a.Unmap()
		if !isTrusted(addr, trusted) {
			break
		}
	}
	return addr.String()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
