package mcp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/laiwf94/authz/internal/agents/jsonrpc"
)

// The MCP authorization specification (2025-06-18 and later, both eras)
// makes the server an OAuth 2.0 protected resource: it publishes RFC 9728
// metadata naming its resource identifier and the authorization servers
// that issue tokens for it, and its 401 and 403 responses carry a Bearer
// challenge (RFC 6750) whose resource_metadata parameter points at that
// document. Clients ask the authorization server for a token bound to the
// resource with the RFC 8707 resource parameter, and the server refuses
// tokens whose audience is not its own resource identifier.

// MetadataWellKnown is the RFC 9728 well-known path segment.
const MetadataWellKnown = "/.well-known/oauth-protected-resource"

// Limits on protected resource metadata.
const (
	MaxResourceURLBytes     = 2048
	MaxAuthorizationServers = 32
	MaxScopesSupported      = 64
	MaxScopeBytes           = 128
	MaxResourceNameBytes    = 128
)

// Bearer challenge error codes (RFC 6750 §3.1).
const (
	ChallengeInvalidRequest    = "invalid_request"
	ChallengeInvalidToken      = "invalid_token"
	ChallengeInsufficientScope = "insufficient_scope"
)

// Challenge is the Bearer challenge an *Error with status 401 or 403
// carries in WWW-Authenticate. A 401 without a Challenge, or with an
// empty Error, asks for credentials without an error code, which is what
// RFC 6750 §3.1 prescribes when the request carried none.
type Challenge struct {
	Error       string   // "", invalid_request, invalid_token or insufficient_scope
	Description string   // error_description; plain text for a developer
	Scope       []string // the scopes needed; nil sends the resource's scopes_supported
}

// ResourceMetadata is the configuration of a protected resource.
type ResourceMetadata struct {
	// Resource is the resource identifier: the canonical https URL of the
	// MCP endpoint, as CanonicalResource returns it.
	Resource string
	// AuthorizationServers are the issuer identifiers of the authorization
	// servers whose tokens the resource accepts.
	AuthorizationServers []string
	ScopesSupported      []string
	Name                 string // resource_name, for people
	Documentation        string // resource_documentation, an https URL
}

// Resource is a validated protected resource: its metadata document,
// prepared once, and the challenges that point at it. It is immutable.
type Resource struct {
	meta     ResourceMetadata
	doc      []byte // the RFC 9728 document
	url      string // where the document is served
	path     string // the path of url
	scopeStr string // scopes_supported joined by spaces
}

// CanonicalResource returns the canonical form of a resource identifier,
// as the MCP specification defines it for RFC 8707: an absolute https
// URL (http only for a loopback host) without user info, query or
// fragment; the scheme and host in lower case, a default port dropped,
// and no trailing slash. Paths with dot segments or empty segments are
// refused rather than rewritten.
func CanonicalResource(raw string) (string, error) {
	bad := func(why string) (string, error) {
		return "", fmt.Errorf("resource %q %s", raw, why)
	}
	if raw == "" {
		return "", errors.New("resource is required")
	}
	if len(raw) > MaxResourceURLBytes {
		return bad(fmt.Sprintf("is longer than %d bytes", MaxResourceURLBytes))
	}
	p, err := url.Parse(raw)
	if err != nil || p.Opaque != "" || p.Host == "" {
		return bad("must be an absolute URL")
	}
	if p.User != nil {
		return bad("must not carry user info")
	}
	if p.RawQuery != "" || p.ForceQuery {
		return bad("must not have a query")
	}
	if p.Fragment != "" || strings.Contains(raw, "#") {
		return bad("must not have a fragment")
	}
	scheme := strings.ToLower(p.Scheme)
	host := strings.ToLower(p.Hostname())
	switch {
	case scheme == "https":
	case scheme == "http" && isLoopback(host):
	default:
		return bad("must be an https URL (http only for a loopback host)")
	}
	if host == "" {
		return bad("must name a host")
	}
	if strings.Contains(host, "%") {
		return bad("must not have an IPv6 zone")
	}
	if !validHost(host) {
		return bad("must name its host in ASCII: a DNS name (an IDN as punycode) or an IP address")
	}
	port := p.Port()
	if port == "" && strings.HasSuffix(p.Host, ":") {
		return bad("has an empty port")
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" {
		authority = net.JoinHostPort(host, port)
	}
	path := p.EscapedPath()
	if path != "" {
		segs := strings.Split(strings.TrimSuffix(path, "/"), "/")[1:]
		for _, s := range segs {
			if s == "" || s == "." || s == ".." || strings.EqualFold(s, "%2e") || strings.EqualFold(s, "%2e%2e") ||
				strings.EqualFold(s, ".%2e") || strings.EqualFold(s, "%2e.") {
				return bad("must not have empty or dot path segments")
			}
		}
		path = strings.TrimSuffix(path, "/")
	}
	out := scheme + "://" + authority + path
	if len(out) > MaxResourceURLBytes {
		return bad(fmt.Sprintf("is longer than %d bytes once its path is escaped", MaxResourceURLBytes))
	}
	return out, nil
}

// validHost reports whether host is a DNS name of letters, digits, '-'
// and '.', or an IP address. Anything else, from sub-delimiters to bytes
// outside ASCII, could be written more than one way.
func validHost(host string) bool {
	if strings.Contains(host, ":") {
		return net.ParseIP(host) != nil
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// MetadataURL returns where RFC 9728 §3.1 puts the metadata of a
// canonical resource identifier: the well-known segment inserted between
// the host and the path.
func MetadataURL(resource string) string {
	i := strings.Index(resource, "://")
	rest := resource[i+3:]
	j := strings.IndexByte(rest, '/')
	if j < 0 {
		return resource + MetadataWellKnown
	}
	return resource[:i+3] + rest[:j] + MetadataWellKnown + rest[j:]
}

// validScope reports whether s is an RFC 6749 scope-token.
func validScope(s string) bool {
	if s == "" || len(s) > MaxScopeBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// validIssuerID reports whether s is usable as an RFC 8414 issuer
// identifier: https (http only for loopback), no query or fragment.
func validIssuerID(s string) bool {
	if len(s) > MaxResourceURLBytes {
		return false
	}
	p, err := url.Parse(s)
	if err != nil || p.Opaque != "" || p.Host == "" || p.User != nil || p.RawQuery != "" || p.ForceQuery ||
		p.Fragment != "" || strings.Contains(s, "#") {
		return false
	}
	return p.Scheme == "https" || p.Scheme == "http" && isLoopback(strings.ToLower(p.Hostname()))
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == ' ' || r == ' ' || r == '�' {
			return false
		}
	}
	return true
}

// NewResource validates m and prepares its document. Resource must
// already be canonical: a configuration that names another form would
// publish one identifier and bind tokens to another.
func NewResource(m ResourceMetadata) (*Resource, error) {
	canon, err := CanonicalResource(m.Resource)
	if err != nil {
		return nil, err
	}
	if canon != m.Resource {
		return nil, fmt.Errorf("resource %q is not canonical; write %q", m.Resource, canon)
	}
	if len(m.AuthorizationServers) > MaxAuthorizationServers {
		return nil, fmt.Errorf("at most %d authorization servers", MaxAuthorizationServers)
	}
	seen := map[string]bool{}
	for i, as := range m.AuthorizationServers {
		if !validIssuerID(as) {
			return nil, fmt.Errorf("authorization_servers[%d] %q must be an https issuer URL without user info, query or fragment", i, as)
		}
		if seen[as] {
			return nil, fmt.Errorf("authorization_servers[%d] %q is listed twice", i, as)
		}
		seen[as] = true
	}
	if len(m.ScopesSupported) > MaxScopesSupported {
		return nil, fmt.Errorf("at most %d scopes_supported", MaxScopesSupported)
	}
	seen = map[string]bool{}
	for i, sc := range m.ScopesSupported {
		if !validScope(sc) {
			return nil, fmt.Errorf("scopes_supported[%d] %q is not a scope token", i, sc)
		}
		if seen[sc] {
			return nil, fmt.Errorf("scopes_supported[%d] %q is listed twice", i, sc)
		}
		seen[sc] = true
	}
	if len(m.Name) > MaxResourceNameBytes || !printable(m.Name) {
		return nil, fmt.Errorf("name must be at most %d bytes of printable text", MaxResourceNameBytes)
	}
	if m.Documentation != "" {
		if p, err := url.Parse(m.Documentation); err != nil || p.Scheme != "https" || p.Host == "" || p.User != nil ||
			len(m.Documentation) > MaxResourceURLBytes {
			return nil, fmt.Errorf("documentation %q must be an https URL", m.Documentation)
		}
	}
	m.AuthorizationServers = append([]string(nil), m.AuthorizationServers...)
	m.ScopesSupported = append([]string(nil), m.ScopesSupported...)
	doc := map[string]any{
		"resource":                 m.Resource,
		"bearer_methods_supported": []string{"header"},
	}
	if len(m.AuthorizationServers) > 0 {
		doc["authorization_servers"] = m.AuthorizationServers
	}
	if len(m.ScopesSupported) > 0 {
		doc["scopes_supported"] = m.ScopesSupported
	}
	if m.Name != "" {
		doc["resource_name"] = m.Name
	}
	if m.Documentation != "" {
		doc["resource_documentation"] = m.Documentation
	}
	b, err := jsonrpc.Marshal(doc)
	if err != nil {
		return nil, err
	}
	mu := MetadataURL(m.Resource)
	pu, _ := url.Parse(mu)
	return &Resource{meta: m, doc: append(b, '\n'), url: mu, path: pu.EscapedPath(),
		scopeStr: strings.Join(m.ScopesSupported, " ")}, nil
}

// Metadata returns the configuration r was built from.
func (r *Resource) Metadata() ResourceMetadata {
	m := r.meta
	m.AuthorizationServers = append([]string(nil), m.AuthorizationServers...)
	m.ScopesSupported = append([]string(nil), m.ScopesSupported...)
	return m
}

// ID returns the resource identifier: the audience tokens must carry.
func (r *Resource) ID() string { return r.meta.Resource }

// MetadataURL returns the URL of the metadata document.
func (r *Resource) MetadataURL() string { return r.url }

// MetadataPath returns the path of the metadata document.
func (r *Resource) MetadataPath() string { return r.path }

// Document returns the metadata document.
func (r *Resource) Document() []byte { return append([]byte(nil), r.doc...) }

// quote returns s as an RFC 9110 quoted-string. Control characters are
// dropped, since a header value may not carry them.
func quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
		case r >= 0x80:
			b.WriteByte('?') // header values are ASCII here
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// WWWAuthenticate returns the Bearer challenge for c under realm, with
// resource_metadata when r is not nil. Its parameters come in a fixed
// order: realm, resource_metadata, scope, error, error_description.
func (r *Resource) WWWAuthenticate(realm string, c *Challenge) string {
	var b strings.Builder
	b.WriteString("Bearer realm=")
	b.WriteString(quote(realm))
	if r != nil {
		b.WriteString(", resource_metadata=")
		b.WriteString(quote(r.url))
	}
	scope := ""
	if c != nil && c.Scope != nil {
		parts := make([]string, 0, len(c.Scope))
		for _, s := range c.Scope {
			if validScope(s) {
				parts = append(parts, s)
			}
		}
		scope = strings.Join(parts, " ")
	} else if r != nil {
		scope = r.scopeStr
	}
	if scope != "" {
		b.WriteString(", scope=")
		b.WriteString(quote(scope))
	}
	if c != nil && c.Error != "" {
		b.WriteString(", error=")
		b.WriteString(quote(c.Error))
		if c.Description != "" {
			b.WriteString(", error_description=")
			b.WriteString(quote(c.Description))
		}
	}
	return b.String()
}

// ServeHTTP serves the metadata document at its path and at the root
// well-known path, which clients of the 2025-06-18 revision and clients
// that cannot derive the inserted path ask for. Anything else is 404.
// The document is public, so any origin may read it.
func (r *Resource) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r == nil || (req.URL.EscapedPath() != r.path && req.URL.EscapedPath() != MetadataWellKnown) {
		writeMetaError(w, http.StatusNotFound, "no protected resource metadata here")
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	switch req.Method {
	case http.MethodGet, http.MethodHead:
	case http.MethodOptions:
		h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Accept, "+HeaderProtocolVersion)
		h.Set("Access-Control-Max-Age", "86400")
		h.Set("Allow", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		h.Set("Allow", "GET, HEAD, OPTIONS")
		writeMetaError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("X-Content-Type-Options", "nosniff")
	if req.Method == http.MethodHead {
		h.Set("Content-Length", fmt.Sprint(len(r.doc)))
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(r.doc)
}

func writeMetaError(w http.ResponseWriter, status int, msg string) {
	code := "not_found"
	if status == http.StatusMethodNotAllowed {
		code = "method_not_allowed"
	}
	b, _ := jsonrpc.Marshal(map[string]string{"error": code, "message": msg})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
