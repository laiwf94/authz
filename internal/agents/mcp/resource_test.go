package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestCanonicalResource(t *testing.T) {
	ok := map[string]string{
		"https://mcp.example.com/mcp":          "https://mcp.example.com/mcp",
		"https://MCP.Example.COM/mcp":          "https://mcp.example.com/mcp",
		"HTTPS://mcp.example.com/mcp":          "https://mcp.example.com/mcp",
		"https://mcp.example.com/mcp/":         "https://mcp.example.com/mcp",
		"https://mcp.example.com/":             "https://mcp.example.com",
		"https://mcp.example.com":              "https://mcp.example.com",
		"https://mcp.example.com:443/mcp":      "https://mcp.example.com/mcp",
		"https://mcp.example.com:8443/mcp":     "https://mcp.example.com:8443/mcp",
		"https://mcp.example.com/a/b/MCP":      "https://mcp.example.com/a/b/MCP", // paths keep their case
		"https://mcp.example.com/a%20b":        "https://mcp.example.com/a%20b",
		"https://[2001:DB8::1]/mcp":            "https://[2001:db8::1]/mcp",
		"https://[2001:db8::1]:443/mcp":        "https://[2001:db8::1]/mcp",
		"https://[2001:db8::1]:9443/mcp":       "https://[2001:db8::1]:9443/mcp",
		"http://localhost:8080/mcp":            "http://localhost:8080/mcp",
		"http://127.0.0.1/mcp":                 "http://127.0.0.1/mcp",
		"http://127.0.0.1:80/mcp":              "http://127.0.0.1/mcp",
		"http://[::1]:7000/mcp":                "http://[::1]:7000/mcp",
		"https://xn--bcher-kva.example/tools/": "https://xn--bcher-kva.example/tools",
	}
	for in, want := range ok {
		got, err := CanonicalResource(in)
		if err != nil || got != want {
			t.Errorf("CanonicalResource(%q) = %q, %v; want %q", in, got, err, want)
		}
		// The canonical form is a fixed point.
		if again, err := CanonicalResource(got); err != nil || again != got {
			t.Errorf("CanonicalResource(%q) = %q, %v; not a fixed point", got, again, err)
		}
	}
	bad := map[string]string{
		"":                                      "required",
		"mcp.example.com/mcp":                   "absolute",
		"/mcp":                                  "absolute",
		"mailto:a@example.com":                  "absolute",
		"http://mcp.example.com/mcp":            "https",
		"http://10.0.0.1/mcp":                   "https",
		"ftp://mcp.example.com/mcp":             "https",
		"https://user@mcp.example.com/mcp":      "user info",
		"https://u:p@mcp.example.com/mcp":       "user info",
		"https://mcp.example.com/mcp?x=1":       "query",
		"https://mcp.example.com/mcp?":          "query",
		"https://mcp.example.com/mcp#frag":      "fragment",
		"https://mcp.example.com/mcp#":          "fragment",
		"https://mcp.example.com//mcp":          "segments",
		"https://mcp.example.com/a//b":          "segments",
		"https://mcp.example.com/a/./b":         "segments",
		"https://mcp.example.com/a/../b":        "segments",
		"https://mcp.example.com/a/%2e%2E":      "segments",
		"https://mcp.example.com/a/%2E/b":       "segments",
		"https://mcp.example.com/.%2e/b":        "segments",
		"https://mcp.example.com/%2e./b":        "segments",
		"https://mcp.example.com/mcp//":         "segments",
		"https://mcp.example.com:/mcp":          "empty port",
		"https://:443/mcp":                      "host",
		"https://mcp.example.com/\x7f":          "absolute",
		"https://" + strings.Repeat("a", 2100):  "longer",
		"https://h/" + strings.Repeat("é", 400): "once its path is escaped",
	}
	for in, why := range bad {
		if got, err := CanonicalResource(in); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("CanonicalResource(%q) = %q, %v; want an error about %s", in, got, err, why)
		}
	}
}

func TestMetadataURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://mcp.example.com/mcp":       "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
		"https://mcp.example.com/a/b":       "https://mcp.example.com/.well-known/oauth-protected-resource/a/b",
		"https://mcp.example.com":           "https://mcp.example.com/.well-known/oauth-protected-resource",
		"https://mcp.example.com:8443/mcp":  "https://mcp.example.com:8443/.well-known/oauth-protected-resource/mcp",
		"http://[::1]:7000/mcp":             "http://[::1]:7000/.well-known/oauth-protected-resource/mcp",
		"https://mcp.example.com/a%20b/mcp": "https://mcp.example.com/.well-known/oauth-protected-resource/a%20b/mcp",
	} {
		if got := MetadataURL(in); got != want {
			t.Errorf("MetadataURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func testResource(t *testing.T) *Resource {
	t.Helper()
	r, err := NewResource(ResourceMetadata{Resource: "https://mcp.example.com/mcp",
		AuthorizationServers: []string{"https://idp.example.com", "https://idp2.example.com/tenant"},
		ScopesSupported:      []string{"tools.read", "tools:write"}, Name: "Example tools",
		Documentation: "https://docs.example.com/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNewResource(t *testing.T) {
	r := testResource(t)
	if r.ID() != "https://mcp.example.com/mcp" || r.MetadataURL() != "https://mcp.example.com/.well-known/oauth-protected-resource/mcp" ||
		r.MetadataPath() != "/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("resource %q at %q path %q", r.ID(), r.MetadataURL(), r.MetadataPath())
	}
	var doc map[string]any
	if err := json.Unmarshal(r.Document(), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"resource":                 "https://mcp.example.com/mcp",
		"authorization_servers":    []any{"https://idp.example.com", "https://idp2.example.com/tenant"},
		"scopes_supported":         []any{"tools.read", "tools:write"},
		"bearer_methods_supported": []any{"header"},
		"resource_name":            "Example tools",
		"resource_documentation":   "https://docs.example.com/mcp",
	}
	if !reflect.DeepEqual(doc, want) {
		t.Fatalf("document %s", r.Document())
	}
	// Document and Metadata return copies.
	r.Document()[0] = 'x'
	md := r.Metadata()
	md.ScopesSupported[0], md.AuthorizationServers[0] = "x", "x"
	if r.Document()[0] != '{' || r.Metadata().ScopesSupported[0] != "tools.read" || r.Metadata().AuthorizationServers[0] != "https://idp.example.com" {
		t.Fatal("resource was changed through a returned value")
	}

	// The smallest document has the resource and the bearer method only.
	min, err := NewResource(ResourceMetadata{Resource: "https://mcp.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(min.Document()); got != `{"bearer_methods_supported":["header"],"resource":"https://mcp.example.com"}`+"\n" {
		t.Fatalf("minimal document %s", got)
	}
	if min.MetadataPath() != MetadataWellKnown {
		t.Fatalf("path %q", min.MetadataPath())
	}

	many := func(n int, f func(int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	base := ResourceMetadata{Resource: "https://mcp.example.com/mcp"}
	for name, tc := range map[string]struct {
		mod func(*ResourceMetadata)
		why string
	}{
		"not canonical":  {func(m *ResourceMetadata) { m.Resource = "https://MCP.example.com/mcp/" }, `write "https://mcp.example.com/mcp"`},
		"bad resource":   {func(m *ResourceMetadata) { m.Resource = "http://mcp.example.com/mcp" }, "https"},
		"no resource":    {func(m *ResourceMetadata) { m.Resource = "" }, "required"},
		"as http":        {func(m *ResourceMetadata) { m.AuthorizationServers = []string{"http://idp.example.com"} }, "authorization_servers[0]"},
		"as query":       {func(m *ResourceMetadata) { m.AuthorizationServers = []string{"https://idp.example.com?x"} }, "authorization_servers[0]"},
		"as empty query": {func(m *ResourceMetadata) { m.AuthorizationServers = []string{"https://idp.example.com?"} }, "authorization_servers[0]"},
		"as fragment":    {func(m *ResourceMetadata) { m.AuthorizationServers = []string{"https://idp.example.com#"} }, "authorization_servers[0]"},
		"as user":        {func(m *ResourceMetadata) { m.AuthorizationServers = []string{"https://a@idp.example.com"} }, "authorization_servers[0]"},
		"as relative":    {func(m *ResourceMetadata) { m.AuthorizationServers = []string{"idp.example.com"} }, "authorization_servers[0]"},
		"as long": {func(m *ResourceMetadata) {
			m.AuthorizationServers = []string{"https://idp.example.com/" + strings.Repeat("a", 2048)}
		}, "authorization_servers[0]"},
		"as twice": {func(m *ResourceMetadata) {
			m.AuthorizationServers = []string{"https://idp.example.com", "https://idp.example.com"}
		}, "authorization_servers[1]"},
		"too many as": {func(m *ResourceMetadata) {
			m.AuthorizationServers = many(33, func(i int) string {
				return "https://idp" + string(rune('a'+i%26)) + strings.Repeat("x", i) + ".example.com"
			})
		}, "at most 32"},
		"bad scope":   {func(m *ResourceMetadata) { m.ScopesSupported = []string{"a b"} }, "scopes_supported[0]"},
		"quote scope": {func(m *ResourceMetadata) { m.ScopesSupported = []string{"ok", `a"b`} }, "scopes_supported[1]"},
		"slash scope": {func(m *ResourceMetadata) { m.ScopesSupported = []string{`a\b`} }, "scopes_supported[0]"},
		"empty scope": {func(m *ResourceMetadata) { m.ScopesSupported = []string{""} }, "scopes_supported[0]"},
		"utf8 scope":  {func(m *ResourceMetadata) { m.ScopesSupported = []string{"é"} }, "scopes_supported[0]"},
		"long scope":  {func(m *ResourceMetadata) { m.ScopesSupported = []string{strings.Repeat("a", 129)} }, "scopes_supported[0]"},
		"scope twice": {func(m *ResourceMetadata) { m.ScopesSupported = []string{"a", "a"} }, "scopes_supported[1]"},
		"too many scopes": {func(m *ResourceMetadata) {
			m.ScopesSupported = many(65, func(i int) string { return "s" + strings.Repeat("x", i) })
		}, "at most 64"},
		"long name":    {func(m *ResourceMetadata) { m.Name = strings.Repeat("n", 129) }, "name"},
		"control name": {func(m *ResourceMetadata) { m.Name = "a\nb" }, "name"},
		"bad utf8":     {func(m *ResourceMetadata) { m.Name = "a\xffb" }, "name"},
		"doc http":     {func(m *ResourceMetadata) { m.Documentation = "http://docs.example.com" }, "documentation"},
		"doc relative": {func(m *ResourceMetadata) { m.Documentation = "/docs" }, "documentation"},
		"doc user":     {func(m *ResourceMetadata) { m.Documentation = "https://u@docs.example.com" }, "documentation"},
	} {
		m := base
		tc.mod(&m)
		if _, err := NewResource(m); err == nil || !strings.Contains(err.Error(), tc.why) {
			t.Errorf("%s: %v, want an error about %s", name, err, tc.why)
		}
	}
	// The limits themselves are accepted.
	m := base
	m.ScopesSupported = many(64, func(i int) string { return "s" + strings.Repeat("x", i) })
	m.AuthorizationServers = many(32, func(i int) string { return "https://idp" + strings.Repeat("x", i) + ".example.com" })
	m.Name = strings.Repeat("n", 128)
	m.AuthorizationServers[0] = "http://127.0.0.1:9000"
	if _, err := NewResource(m); err != nil {
		t.Fatal(err)
	}
}

func TestWWWAuthenticate(t *testing.T) {
	r := testResource(t)
	const rm = `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`
	for name, tc := range map[string]struct {
		r    *Resource
		c    *Challenge
		want string
	}{
		"no resource":   {nil, nil, `Bearer realm="gw"`},
		"no resource 2": {nil, &Challenge{Error: ChallengeInvalidToken}, `Bearer realm="gw", error="invalid_token"`},
		"no credential": {r, nil, `Bearer realm="gw", ` + rm + `, scope="tools.read tools:write"`},
		"empty":         {r, &Challenge{}, `Bearer realm="gw", ` + rm + `, scope="tools.read tools:write"`},
		"invalid": {r, &Challenge{Error: ChallengeInvalidToken, Description: "expired"},
			`Bearer realm="gw", ` + rm + `, scope="tools.read tools:write", error="invalid_token", error_description="expired"`},
		"step up": {r, &Challenge{Error: ChallengeInsufficientScope, Scope: []string{"tools:write", "bad scope", "admin"}},
			`Bearer realm="gw", ` + rm + `, scope="tools:write admin", error="insufficient_scope"`},
		"no scope": {r, &Challenge{Error: ChallengeInvalidRequest, Scope: []string{}},
			`Bearer realm="gw", ` + rm + `, error="invalid_request"`},
		"quoting": {r, &Challenge{Error: ChallengeInvalidToken, Description: "a \"q\" \\ b\r\nc\x7fé"},
			`Bearer realm="gw", ` + rm + `, scope="tools.read tools:write", error="invalid_token", error_description="a \"q\" \\ bc?"`},
		"description without error": {r, &Challenge{Description: "ignored"}, `Bearer realm="gw", ` + rm + `, scope="tools.read tools:write"`},
	} {
		if got := tc.r.WWWAuthenticate("gw", tc.c); got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, tc.want)
		}
	}
	if got := r.WWWAuthenticate(`a"b`, nil); !strings.HasPrefix(got, `Bearer realm="a\"b", `) {
		t.Fatalf("realm %s", got)
	}
}

func TestResourceServeHTTP(t *testing.T) {
	r := testResource(t)
	do := func(h http.Handler, method, path string) *http.Response {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "https://mcp.example.com"+path, nil))
		return rec.Result()
	}
	for _, path := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"} {
		res := do(r, "GET", path)
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 || string(body) != string(r.Document()) || res.Header.Get("Content-Type") != "application/json" ||
			res.Header.Get("Cache-Control") != "public, max-age=300" || res.Header.Get("Access-Control-Allow-Origin") != "*" ||
			res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("GET %s: %d %v %s", path, res.StatusCode, res.Header, body)
		}
		res = do(r, "HEAD", path)
		body, _ = io.ReadAll(res.Body)
		if res.StatusCode != 200 || len(body) != 0 || res.Header.Get("Content-Length") != itoa(len(r.Document())) {
			t.Fatalf("HEAD %s: %d %v", path, res.StatusCode, res.Header)
		}
		res = do(r, "OPTIONS", path)
		if res.StatusCode != 204 || res.Header.Get("Access-Control-Allow-Methods") != "GET, HEAD, OPTIONS" ||
			!strings.Contains(res.Header.Get("Access-Control-Allow-Headers"), HeaderProtocolVersion) {
			t.Fatalf("OPTIONS %s: %d %v", path, res.StatusCode, res.Header)
		}
		for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
			res = do(r, m, path)
			if res.StatusCode != 405 || res.Header.Get("Allow") != "GET, HEAD, OPTIONS" {
				t.Fatalf("%s %s: %d", m, path, res.StatusCode)
			}
		}
	}
	for _, path := range []string{"/.well-known/oauth-protected-resource/other", "/.well-known/oauth-protected-resource/mcp/",
		"/.well-known/oauth-protected-resource/MCP", "/mcp", "/"} {
		res := do(r, "GET", path)
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != 404 || !strings.Contains(string(body), "not_found") {
			t.Fatalf("GET %s: %d %s", path, res.StatusCode, body)
		}
	}
	var none *Resource
	if res := do(none, "GET", MetadataWellKnown); res.StatusCode != 404 {
		t.Fatalf("nil resource: %d", res.StatusCode)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// newResourceHarness is the harness with r as its resource.
func newResourceHarness(t *testing.T, r *Resource) *harness {
	h := &testHandler{}
	srv := NewServer(ServerConfig{Info: Implementation{Name: "gw", Version: "1"}, Handler: h, Resource: r})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &harness{t: t, srv: srv, h: h, ts: ts}
}

func TestServerChallenges(t *testing.T) {
	r := testResource(t)
	hs := newResourceHarness(t, r)
	want := `Bearer realm="toolgate", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="tools.read tools:write"`

	// Both eras get a 401 with the challenge: a modern request and a
	// legacy initialize, and a request inside a legacy session.
	r1 := hs.do("POST", map[string]string{"Authorization": "", HeaderProtocolVersion: VersionModern, HeaderMethod: MethodToolsList},
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+meta+`}}`)
	if r1.status != 401 || r1.header.Get("WWW-Authenticate") != want || errCode(r1) != CodeUnauthenticated {
		t.Fatalf("modern: %d %q %s", r1.status, r1.header.Get("WWW-Authenticate"), r1.raw)
	}
	for _, v := range LegacyVersions {
		r2 := hs.do("POST", map[string]string{"Authorization": ""},
			`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"`+v+`","capabilities":{}}}`)
		if r2.status != 401 || r2.header.Get("WWW-Authenticate") != want {
			t.Fatalf("legacy %s initialize: %d %q", v, r2.status, r2.header.Get("WWW-Authenticate"))
		}
	}
	sid := legacyInit(t, hs, "alice", Version250618)
	r3 := hs.do("POST", map[string]string{"Authorization": "Bearer nobody", HeaderSessionID: sid},
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if r3.status != 401 || r3.header.Get("WWW-Authenticate") != want {
		t.Fatalf("legacy session: %d %q", r3.status, r3.header.Get("WWW-Authenticate"))
	}

	// A handler's challenge is sent as it is, with its status, in both
	// eras: a 403 step-up keeps 403 in a legacy session too.
	stepUp := &Error{RPC: NewError(0, CodeUnauthenticated, "needs tools:write").RPC, Status: http.StatusForbidden,
		Challenge: &Challenge{Error: ChallengeInsufficientScope, Scope: []string{"tools:write"}, Description: "needs tools:write"}}
	hs.h.callErr = stepUp
	wantStep := `Bearer realm="toolgate", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="tools:write", error="insufficient_scope", error_description="needs tools:write"`
	h := modernHeaders(MethodToolsCall)
	h[HeaderName] = "echo"
	r4 := hs.do("POST", h, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo",`+meta+`}}`)
	if r4.status != 403 || r4.header.Get("WWW-Authenticate") != wantStep {
		t.Fatalf("modern step-up: %d %q", r4.status, r4.header.Get("WWW-Authenticate"))
	}
	r5 := hs.do("POST", map[string]string{HeaderSessionID: sid}, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo"}}`)
	if r5.status != 403 || r5.header.Get("WWW-Authenticate") != wantStep {
		t.Fatalf("legacy step-up: %d %q", r5.status, r5.header.Get("WWW-Authenticate"))
	}
	// A 403 without a challenge is still a 200 in a legacy session and
	// carries no WWW-Authenticate.
	hs.h.callErr = NewError(http.StatusForbidden, CodeUnauthenticated, "denied")
	r6 := hs.do("POST", map[string]string{HeaderSessionID: sid}, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo"}}`)
	if r6.status != 200 || r6.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("legacy 403 without challenge: %d %q", r6.status, r6.header.Get("WWW-Authenticate"))
	}
	r7 := hs.do("POST", h, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"echo",`+meta+`}}`)
	if r7.status != 403 || r7.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("modern 403 without challenge: %d %q", r7.status, r7.header.Get("WWW-Authenticate"))
	}
	// A challenge on another status is not sent.
	hs.h.callErr = &Error{RPC: NewError(0, CodeRateLimited, "slow down").RPC, Status: http.StatusTooManyRequests, Challenge: &Challenge{Error: ChallengeInvalidToken}}
	r8 := hs.do("POST", h, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo",`+meta+`}}`)
	if r8.status != 429 || r8.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("429: %d %q", r8.status, r8.header.Get("WWW-Authenticate"))
	}
	r9 := hs.do("POST", map[string]string{HeaderSessionID: sid}, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"echo"}}`)
	if r9.status != 200 {
		t.Fatalf("legacy 429 with a challenge: %d", r9.status)
	}
}

func TestServerSetResource(t *testing.T) {
	hs := newResourceHarness(t, nil)
	meta := hs.srv.MetadataHandler()
	get := func() int {
		rec := httptest.NewRecorder()
		meta(rec, httptest.NewRequest("GET", "http://x"+MetadataWellKnown+"/mcp", nil))
		return rec.Code
	}
	noAuth := map[string]string{"Authorization": "", HeaderProtocolVersion: VersionModern, HeaderMethod: MethodToolsList}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + `"_meta":{}` + `}}`
	if r := hs.do("POST", noAuth, body); r.header.Get("WWW-Authenticate") != `Bearer realm="toolgate"` || get() != 404 || hs.srv.Resource() != nil {
		t.Fatalf("without a resource: %q %d", r.header.Get("WWW-Authenticate"), get())
	}
	r := testResource(t)
	hs.srv.SetResource(r)
	if got := hs.do("POST", noAuth, body).header.Get("WWW-Authenticate"); !strings.Contains(got, `resource_metadata="`+r.MetadataURL()+`"`) || get() != 200 || hs.srv.Resource() != r {
		t.Fatalf("with a resource: %q %d", got, get())
	}
	other, err := NewResource(ResourceMetadata{Resource: "https://other.example.com/tools"})
	if err != nil {
		t.Fatal(err)
	}
	hs.srv.SetResource(other)
	if got := hs.do("POST", noAuth, body).header.Get("WWW-Authenticate"); got != `Bearer realm="toolgate", resource_metadata="https://other.example.com/.well-known/oauth-protected-resource/tools"` || get() != 404 {
		t.Fatalf("after the change: %q %d", got, get())
	}
	hs.srv.SetResource(nil)
	if get() != 404 {
		t.Fatal("metadata after the resource was removed")
	}
}
