package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/mcp"
)

const resourceURL = "https://mcp.example.com/mcp"

func parseResource(t *testing.T, resource string, tokensAud string, issuers ...map[string]any) (*Config, error) {
	t.Helper()
	is, _ := json.Marshal(issuers)
	tokens := ""
	if tokensAud != "" {
		tokens = fmt.Sprintf(`"tokens":{"issuer":"toolgate","audience":%q},`, tokensAud)
	}
	src := fmt.Sprintf(`{%s"agents":[],"upstreams":[{"name":"fake","url":"http://127.0.0.1:1/mcp"}],"issuers":%s,"resource":%s}`,
		tokens, is, resource)
	return ParseConfig([]byte(src), nil)
}

func TestParseConfigResource(t *testing.T) {
	second := map[string]any{"issuer": "https://other.example.com", "audience": resourceURL, "jwks_uri": "https://other.example.com/k"}
	_, err := parseResource(t, `{"url":"https://mcp.example.com/mcp"}`, resourceURL, goodIssuer(), second)
	if err == nil {
		t.Fatal("goodIssuer's audience is not the resource but was accepted")
	}
	good := with(goodIssuer(), "audience", resourceURL)
	c, err := parseResource(t, `{"url":"https://mcp.example.com/mcp","scopes_supported":["files:read"],"name":"Tools",
	  "documentation":"https://docs.example.com"}`, resourceURL, good, second)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.NewResource()
	if err != nil {
		t.Fatal(err)
	}
	m := res.Metadata()
	if m.Resource != resourceURL || strings.Join(m.AuthorizationServers, " ") != "https://idp.example.com https://other.example.com" ||
		strings.Join(m.ScopesSupported, " ") != "files:read" || m.Name != "Tools" || m.Documentation != "https://docs.example.com" {
		t.Fatalf("metadata %+v", m)
	}
	// Named authorization servers replace the issuers.
	c, err = parseResource(t, `{"url":"https://mcp.example.com/mcp","authorization_servers":["https://as.example.com"]}`, "", good)
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := c.NewResource(); strings.Join(res.Metadata().AuthorizationServers, " ") != "https://as.example.com" {
		t.Fatalf("authorization servers %v", res.Metadata().AuthorizationServers)
	}
	// With no issuers there are no authorization servers.
	c, err = parseResource(t, `{"url":"https://mcp.example.com"}`, "")
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := c.NewResource(); res.Metadata().AuthorizationServers != nil || res.ID() != "https://mcp.example.com" {
		t.Fatalf("no issuers: %+v", res.Metadata())
	}
	// Without the section there is no resource and no binding.
	if c, err := parseIssuers(t, goodIssuer()); err != nil || c.Resource != nil {
		t.Fatalf("no resource: %v", err)
	} else if res, err := c.NewResource(); res != nil || err != nil {
		t.Fatalf("no resource: %v %v", res, err)
	}

	for name, tc := range map[string]struct {
		resource, tokensAud string
		issuers             []map[string]any
		why                 string
	}{
		"not canonical":      {`{"url":"https://MCP.example.com/mcp/"}`, "", nil, `config: resource: resource "https://MCP.example.com/mcp/" is not canonical; write "https://mcp.example.com/mcp"`},
		"http":               {`{"url":"http://mcp.example.com/mcp"}`, "", nil, "https"},
		"no url":             {`{}`, "", nil, "resource is required"},
		"unknown member":     {`{"url":"https://mcp.example.com/mcp","scopes":["a"]}`, "", nil, "unknown field"},
		"bad scope":          {`{"url":"https://mcp.example.com/mcp","scopes_supported":["a b"]}`, "", nil, "scopes_supported[0]"},
		"bad as":             {`{"url":"https://mcp.example.com/mcp","authorization_servers":["http://as.example.com"]}`, "", nil, "authorization_servers[0]"},
		"bad documentation":  {`{"url":"https://mcp.example.com/mcp","documentation":"ftp://d"}`, "", nil, "documentation"},
		"tokens audience":    {`{"url":"https://mcp.example.com/mcp"}`, "toolgate-test", nil, `config: tokens.audience "toolgate-test" is not the resource "https://mcp.example.com/mcp"`},
		"tokens audience /":  {`{"url":"https://mcp.example.com/mcp"}`, resourceURL + "/", nil, "tokens.audience"},
		"issuer audience":    {`{"url":"https://mcp.example.com/mcp"}`, "", []map[string]any{good, with(second, "audience", "https://mcp.example.com")}, `config: issuers[1]: audience "https://mcp.example.com" is not the resource`},
		"issuer case":        {`{"url":"https://mcp.example.com/mcp"}`, "", []map[string]any{with(good, "audience", "https://MCP.example.com/mcp")}, "issuers[0]: audience"},
		"issuer other path":  {`{"url":"https://mcp.example.com/mcp"}`, "", []map[string]any{with(good, "audience", "https://mcp.example.com/other")}, "issuers[0]: audience"},
		"issuer other port":  {`{"url":"https://mcp.example.com/mcp"}`, "", []map[string]any{with(good, "audience", "https://mcp.example.com:8443/mcp")}, "issuers[0]: audience"},
		"resource not a obj": {`"https://mcp.example.com/mcp"`, "", nil, "cannot unmarshal"},
	} {
		if _, err := parseResource(t, tc.resource, tc.tokensAud, tc.issuers...); err == nil || !strings.Contains(err.Error(), tc.why) {
			t.Errorf("%s: %v, want %s", name, err, tc.why)
		}
	}

	// The mcp section's issuers are bound too.
	c, err = parseResource(t, `{"url":"https://mcp.example.com/mcp"}`, "", good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WithIssuers([]IssuerConfig{{Issuer: "https://s.example.com", Audience: "https://mcp.example.com", JWKSURI: "https://s.example.com/k"}}); err == nil ||
		err.Error() != `issuers[1]: audience "https://mcp.example.com" is not the resource "https://mcp.example.com/mcp"` {
		t.Fatalf("section issuer: %v", err)
	}
	all, err := c.WithIssuers([]IssuerConfig{{Issuer: "https://s.example.com", Audience: resourceURL, JWKSURI: "https://s.example.com/k"}})
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := all.NewResource(); strings.Join(res.Metadata().AuthorizationServers, " ") != "https://idp.example.com https://s.example.com" {
		t.Fatalf("section issuers published as %v", res.Metadata().AuthorizationServers)
	}
}

func TestResourceAuthorizationServersCap(t *testing.T) {
	c := &Config{Resource: &ResourceConfig{URL: resourceURL}}
	for i := 0; i < 40; i++ {
		c.Issuers = append(c.Issuers, IssuerConfig{Issuer: fmt.Sprintf("https://idp%d.example.com", i)})
	}
	res, err := c.NewResource()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Metadata().AuthorizationServers); n != mcp.MaxAuthorizationServers {
		t.Fatalf("%d authorization servers", n)
	}
}

func withResource(c *Config) {
	c.Tokens.Audience = resourceURL
	c.Resource = &ResourceConfig{URL: resourceURL, ScopesSupported: []string{"files:read"}}
}

func (e *env) get(path string, h map[string]string) reply {
	req, _ := http.NewRequest("GET", strings.TrimSuffix(e.gwURL, "/mcp")+path, nil)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	return e.do(req)
}

func TestGatewayProtectedResource(t *testing.T) {
	e := newEnv(t, withResource)
	metaURL := "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
	want := `{"bearer_methods_supported":["header"],"resource":"https://mcp.example.com/mcp","scopes_supported":["files:read"]}` + "\n"
	for _, p := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"} {
		r := e.get(p, map[string]string{"Origin": "https://anywhere.example"})
		if r.status != 200 || r.raw != want || r.header.Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("GET %s: %d %q", p, r.status, r.raw)
		}
	}
	if r := e.get("/.well-known/oauth-protected-resource/other", nil); r.status != 404 {
		t.Fatalf("other path: %d", r.status)
	}

	list := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}`)
	base := `Bearer realm="toolgate", resource_metadata="` + metaURL + `", scope="files:read"`
	other, _ := e.replaced(t, func(c *Config) {
		c.Tokens = &TokenConfig{Issuer: "toolgate", Audience: "https://elsewhere.example.com/mcp"}
	})
	otherAuth, err := other.NewAuthenticator(map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := otherAuth.Mint("ci-agent", "carol", nil, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	own, err := e.auth.Mint("ci-agent", "carol", nil, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		h    map[string]string
		want string
	}{
		"no credential":  {nil, base},
		"basic":          {map[string]string{"Authorization": "Basic YTpi"}, base + `, error="invalid_request", error_description="send the access token as Authorization: Bearer"`},
		"empty bearer":   {map[string]string{"Authorization": "Bearer "}, base + `, error="invalid_request", error_description="send the access token as Authorization: Bearer"`},
		"wrong key":      {map[string]string{"Authorization": "Bearer wrong-key-0123456789abcdefghijklmn"}, base + `, error="invalid_token", error_description="the access token is malformed, expired, revoked or not for this resource"`},
		"other audience": {map[string]string{"Authorization": "Bearer " + foreign}, base + `, error="invalid_token", error_description="the access token is malformed, expired, revoked or not for this resource"`},
	} {
		r := e.post(e.gwURL, "", list, tc.h)
		if r.status != 401 || r.header.Get("WWW-Authenticate") != tc.want || r.errCode() != mcp.CodeUnauthenticated {
			t.Errorf("%s: %d\n got %s\nwant %s", name, r.status, r.header.Get("WWW-Authenticate"), tc.want)
		}
	}
	// A token for this resource works, in both eras.
	if names := toolNames(e.rpc(own, "tools/list", nil, nil)); len(names) == 0 {
		t.Fatal("own token refused")
	}
	if r := e.post(e.gwURL, own, list, nil); r.status != 200 || r.header.Get(mcp.HeaderSessionID) == "" {
		t.Fatalf("legacy initialize: %d %s", r.status, r.raw)
	}

	// A reload moves the resource with the agents; one that fails keeps it.
	moved, auth := e.replaced(t, func(c *Config) {
		c.Tokens = &TokenConfig{Issuer: "toolgate", Audience: "https://tools.example.com"}
		c.Resource = &ResourceConfig{URL: "https://tools.example.com", Name: "Moved"}
	})
	if err := e.gw.SetAgents(moved, auth); err != nil {
		t.Fatal(err)
	}
	if r := e.get("/.well-known/oauth-protected-resource", nil); r.status != 200 || !strings.Contains(r.raw, `"resource":"https://tools.example.com"`) ||
		!strings.Contains(r.raw, `"resource_name":"Moved"`) {
		t.Fatalf("after the move: %d %s", r.status, r.raw)
	}
	if r := e.get("/.well-known/oauth-protected-resource/mcp", nil); r.status != 404 {
		t.Fatalf("old path after the move: %d", r.status)
	}
	if r := e.post(e.gwURL, "", list, nil); r.header.Get("WWW-Authenticate") != `Bearer realm="toolgate", resource_metadata="https://tools.example.com/.well-known/oauth-protected-resource"` {
		t.Fatalf("challenge after the move: %s", r.header.Get("WWW-Authenticate"))
	}
	broken, bauth := e.replaced(t, func(c *Config) { c.Resource = &ResourceConfig{URL: "http://tools.example.com"} })
	if err := e.gw.SetAgents(broken, bauth); err == nil || !strings.Contains(err.Error(), "resource:") {
		t.Fatalf("broken resource: %v", err)
	}
	if r := e.get("/.well-known/oauth-protected-resource", nil); !strings.Contains(r.raw, "https://tools.example.com") {
		t.Fatalf("after a refused change: %s", r.raw)
	}
	// Removing the section stops serving metadata.
	plain, pauth := e.replaced(t, func(c *Config) { c.Resource = nil })
	if err := e.gw.SetAgents(plain, pauth); err != nil {
		t.Fatal(err)
	}
	if r := e.get("/.well-known/oauth-protected-resource", nil); r.status != 404 {
		t.Fatalf("without a resource: %d", r.status)
	}
	if r := e.post(e.gwURL, "", list, nil); r.header.Get("WWW-Authenticate") != `Bearer realm="toolgate"` {
		t.Fatalf("challenge without a resource: %s", r.header.Get("WWW-Authenticate"))
	}
}

func TestGatewayBadResource(t *testing.T) {
	e := newEnv(t)
	c := *e.gw.cfg
	c.Resource = &ResourceConfig{URL: "not a url"}
	if _, err := New(Options{Config: &c, Auth: e.auth, Policy: e.gw.opt.Policy, Audit: e.auditLog, Pins: e.gw.opt.Pins,
		AuditKey: bytes.Repeat([]byte{9}, 32)}); err == nil || !strings.Contains(err.Error(), "resource") {
		t.Fatalf("New with a bad resource: %v", err)
	}
	// Without a resource section the metadata is not found.
	if r := e.get("/.well-known/oauth-protected-resource", nil); r.status != 404 {
		t.Fatalf("metadata without a resource: %d", r.status)
	}
}
