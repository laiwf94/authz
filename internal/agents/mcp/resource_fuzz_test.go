package mcp

import (
	"net/url"
	"strings"
	"testing"
)

// FuzzCanonicalResource checks that whatever CanonicalResource accepts is
// a fixed point that NewResource takes as it is, with the URL parts the
// specification forbids absent, and that the challenge built from it is
// a valid header value whatever the description says.
func FuzzCanonicalResource(f *testing.F) {
	for _, s := range []string{"https://mcp.example.com/mcp", "HTTPS://MCP.example.com:443/a/b/", "http://[::1]:80/x",
		"https://mcp.example.com/a%2e/b", "https://u@h/p", "https://h/p?q#f", "http://10.0.0.1/", "https://h:/p",
		"https://[fe80::1%25eth0]/mcp", "https://h/%zz", "https://h/a b"} {
		f.Add(s, "expired \"token\"\r\n")
	}
	f.Fuzz(func(t *testing.T, raw, desc string) {
		c, err := CanonicalResource(raw)
		if err != nil {
			return
		}
		if again, err := CanonicalResource(c); err != nil || again != c {
			t.Fatalf("%q -> %q -> %q, %v", raw, c, again, err)
		}
		p, err := url.Parse(c)
		if err != nil || p.User != nil || p.RawQuery != "" || p.ForceQuery || p.Fragment != "" || strings.HasSuffix(c, "/") ||
			(p.Scheme != "https" && p.Scheme != "http") || p.Host != strings.ToLower(p.Host) {
			t.Fatalf("%q -> %q: %+v %v", raw, c, p, err)
		}
		if p.Scheme == "http" && !isLoopback(p.Hostname()) {
			t.Fatalf("%q -> %q: http on a non-loopback host", raw, c)
		}
		r, err := NewResource(ResourceMetadata{Resource: c})
		if err != nil {
			t.Fatalf("NewResource(%q): %v", c, err)
		}
		mu, err := url.Parse(r.MetadataURL())
		if err != nil || !strings.HasPrefix(mu.EscapedPath(), MetadataWellKnown) || mu.Host != p.Host ||
			mu.EscapedPath() != MetadataWellKnown+p.EscapedPath() {
			t.Fatalf("metadata URL %q for %q: %v", r.MetadataURL(), c, err)
		}
		h := r.WWWAuthenticate("toolgate", &Challenge{Error: ChallengeInvalidToken, Description: desc, Scope: []string{desc}})
		for i := 0; i < len(h); i++ {
			if h[i] < 0x20 || h[i] > 0x7e {
				t.Fatalf("challenge %q has byte %#x", h, h[i])
			}
		}
	})
}
