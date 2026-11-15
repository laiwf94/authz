package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestPermitted(t *testing.T) {
	g := New()
	for _, s := range []string{
		"8.8.8.8", "1.1.1.1", "93.184.215.14", "2606:4700:4700::1111",
		"2001:4860:4860::8888", "::ffff:8.8.8.8", "100.63.255.255", "100.128.0.0",
		"172.32.0.1", "192.169.0.1", "198.20.0.1",
	} {
		if !g.Permitted(netip.MustParseAddr(s)) {
			t.Errorf("%s refused", s)
		}
	}
	for _, s := range []string{
		"127.0.0.1", "127.255.255.254", "::1", "0.0.0.0", "::", "0.1.2.3",
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fc00::1", "fd12:3456::1",
		"169.254.169.254", "169.254.0.1", "fe80::1", "fe80::1%eth0",
		"224.0.0.1", "239.255.255.250", "ff02::1", "255.255.255.255", "240.0.0.1",
		"100.64.0.1", "100.127.255.255", "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.19.255.255",
		"198.51.100.7", "203.0.113.9", "192.88.99.1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b:1::1", "2002:7f00:1::1", "2001::1", "2001:db8::1",
		"3fff::1", "fec0::1", "100::1", "::ffff:0:7f00:1", "5f00::1",
		"::127.0.0.1",
	} {
		if g.Permitted(netip.MustParseAddr(s)) {
			t.Errorf("%s permitted", s)
		}
	}
	if g.Permitted(netip.Addr{}) {
		t.Error("invalid address permitted")
	}
}

func TestAllow(t *testing.T) {
	allow, err := ParseAllow([]string{"10.1.0.0/16", "127.0.0.1", "fd00::5", "169.254.169.254/32"})
	if err != nil {
		t.Fatal(err)
	}
	g := New(allow...)
	for _, s := range []string{"10.1.2.3", "127.0.0.1", "::ffff:127.0.0.1", "fd00::5", "169.254.169.254", "8.8.8.8"} {
		if !g.Permitted(netip.MustParseAddr(s)) {
			t.Errorf("%s refused", s)
		}
	}
	for _, s := range []string{"10.2.0.1", "127.0.0.2", "fd00::6", "169.254.169.253"} {
		if g.Permitted(netip.MustParseAddr(s)) {
			t.Errorf("%s permitted", s)
		}
	}
	// Prefixes are masked: 10.1.2.3/16 means 10.1.0.0/16.
	g = New(netip.MustParsePrefix("10.1.2.3/16"))
	if !g.Permitted(netip.MustParseAddr("10.1.200.1")) {
		t.Error("unmasked prefix")
	}
	for _, bad := range []string{"", "10.0.0.0/33", "host.example", "10.0.0.1/x"} {
		if _, err := ParseAllow([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestControl(t *testing.T) {
	g := New()
	err := g.Control("tcp4", "127.0.0.1:443", nil)
	var be *BlockedError
	if !errors.As(err, &be) || be.Addr != netip.MustParseAddr("127.0.0.1") || !errors.Is(err, ErrBlocked) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("message %q", err)
	}
	if err := g.Control("tcp6", "[2606:4700:4700::1111]:443", nil); err != nil {
		t.Fatal(err)
	}
	if err := g.Control("tcp", "nonsense", nil); !errors.Is(err, ErrBlocked) {
		t.Fatalf("unparsable: %v", err)
	}
}

// TestTransport dials a loopback server through the transport: refused
// by default, reached when allowed. Names are checked on the address they
// resolve to, so "localhost" is refused too.
func TestTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	get := func(g *Guard, u string) error {
		c := &http.Client{Transport: g.Transport(nil)}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}
	if err := get(New(), srv.URL); !errors.Is(err, ErrBlocked) {
		t.Fatalf("loopback by default: %v", err)
	}
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	if err := get(New(), "http://localhost:"+port); !errors.Is(err, ErrBlocked) {
		t.Fatalf("localhost by default: %v", err)
	}
	if err := get(New(netip.MustParsePrefix("127.0.0.0/8")), srv.URL); err != nil {
		t.Fatalf("allowed loopback: %v", err)
	}
	// The transport ignores proxy settings.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	if New().Transport(nil).Proxy != nil {
		t.Fatal("transport uses a proxy")
	}
}
