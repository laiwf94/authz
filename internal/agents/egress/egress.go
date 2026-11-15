// Package egress guards the gateway's own outbound connections: JWKS
// fetches now, and upstream calls as they move onto it.
//
// The check runs at connect time, on the address the dialer is about to
// connect to, after name resolution. A name-based allow-list can't do
// this: a public name can resolve to a private address, or resolve to a
// public one when it is checked and a private one when it is used (DNS
// rebinding). The Guard refuses every address that is not public unicast
// unless an operator allowed its range, so a URL from configuration or
// from an issuer can't be turned against the loopback interface, the
// cloud metadata address or the private network.
package egress

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// DefaultDialTimeout bounds each connection attempt.
const DefaultDialTimeout = 5 * time.Second

// ErrBlocked is wrapped by every refused connection.
var ErrBlocked = errors.New("egress: address not allowed")

// BlockedError is a connection the guard refused.
type BlockedError struct {
	Addr netip.Addr
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("egress: connection to %s refused: not a public address", e.Addr)
}

func (e *BlockedError) Unwrap() error { return ErrBlocked }

// Ranges that are not public unicast but that netip's predicates don't
// cover: shared address space, benchmarking, documentation, reserved and
// broadcast addresses, and IPv6 prefixes that carry an IPv4 address
// (NAT64, 6to4, Teredo) and so could reach a private one through a
// translator.
var special = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",         // "this network"
		"100.64.0.0/10",     // shared address space (RFC 6598)
		"192.0.0.0/24",      // IETF protocol assignments
		"192.0.2.0/24",      // TEST-NET-1
		"192.88.99.0/24",    // 6to4 relay anycast
		"198.18.0.0/15",     // benchmarking
		"198.51.100.0/24",   // TEST-NET-2
		"203.0.113.0/24",    // TEST-NET-3
		"240.0.0.0/4",       // reserved, and broadcast
		"::/96",             // IPv4-compatible (deprecated)
		"64:ff9b::/96",      // NAT64
		"64:ff9b:1::/48",    // local-use NAT64
		"100::/64",          // discard-only
		"2001::/23",         // IETF protocol assignments: Teredo, ORCHID, AS112
		"2001:db8::/32",     // documentation
		"2002::/16",         // 6to4
		"3fff::/20",         // documentation
		"5f00::/16",         // segment routing SIDs
		"fec0::/10",         // deprecated site-local
		"::ffff:0:0:0/96",   // IPv4-translated
		"2620:4f:8000::/48", // AS112-v6 direct delegation
		"192.31.196.0/24",   // AS112-v4
		"192.175.48.0/24",   // AS112 direct delegation
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Guard decides which addresses outbound connections may reach. The zero
// value is not usable; call New.
type Guard struct {
	allow []netip.Prefix
}

// New returns a guard that permits public unicast addresses and those in
// allow. An allowed range wins over every built-in refusal, so an operator
// can let the gateway reach an issuer on the private network by naming
// its range.
func New(allow ...netip.Prefix) *Guard {
	g := &Guard{}
	for _, p := range allow {
		g.allow = append(g.allow, p.Masked())
	}
	return g
}

// ParseAllow parses a list of CIDR ranges or single addresses for New.
func ParseAllow(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("egress: %q is neither an address nor a CIDR range", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Permitted reports whether a connection to ip may be made.
func (g *Guard) Permitted(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.WithZone("")
	for _, p := range g.allow {
		if p.Contains(ip) || (ip.Is4In6() && p.Contains(ip.Unmap())) {
			return true
		}
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range special {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// Control is a net.Dialer Control function: it runs after the address is
// resolved and before the connection is made, and refuses addresses the
// guard does not permit.
func (g *Guard) Control(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparsable address %q", ErrBlocked, address)
	}
	if !g.Permitted(ap.Addr()) {
		return &BlockedError{Addr: ap.Addr()}
	}
	return nil
}

// Transport returns an HTTP transport whose every connection passes the
// guard. It never uses a proxy, since the guard would then see the
// proxy's address instead of the destination's. roots, when not nil,
// replaces the system's trusted certificate authorities.
func (g *Guard) Transport(roots *x509.CertPool) *http.Transport {
	d := &net.Dialer{Timeout: DefaultDialTimeout, KeepAlive: 30 * time.Second, Control: g.Control}
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		TLSClientConfig:        &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    DefaultDialTimeout,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        90 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
	}
}
