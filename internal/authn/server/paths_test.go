package server

import (
	"net/http"
	"strings"
	"testing"
)

// pathRules gives the whoami app public paths and per-path, per-method
// rules: the wiki is public to read, its admin area needs the admins group
// (alice has it, bob does not), and nobody may delete the audit log.
func pathRules(cfg map[string]any) {
	app := cfg["apps"].([]any)[0].(map[string]any)
	app["allow"] = map[string]any{"any_user": true}
	app["public"] = []string{"/static"}
	app["paths"] = []any{
		map[string]any{"path": "/wiki", "methods": []string{"GET"}, "public": true},
		map[string]any{"path": "/admin", "allow": map[string]any{"groups": []string{"admins"}}},
		map[string]any{"path": "/admin/audit", "methods": []string{"DELETE"}, "deny": true},
	}
}

func authMethod(b *browser, method, path string) *http.Response {
	b.h.t.Helper()
	return b.auth(path, http.Header{"X-Forwarded-Method": {method}})
}

func TestForwardAuthPathRules(t *testing.T) {
	h := newHarness(t, harnessOpts{cfgMutate: pathRules})
	anon := h.browser()

	// Public paths need no session and carry no identity.
	for _, c := range []struct{ method, path string }{{"GET", "/wiki/home"}, {"HEAD", "/wiki"}, {"POST", "/static/x.css"}} {
		resp := authMethod(anon, c.method, c.path)
		if resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderUser) != "" || resp.Header.Get(HeaderToken) != "" {
			t.Fatalf("anonymous %s %s: %d %v", c.method, c.path, resp.StatusCode, resp.Header)
		}
	}
	// Writing the wiki is not public: the every-method app rule applies.
	if resp := authMethod(anon, "POST", "/wiki/home"); resp.StatusCode != http.StatusUnauthorized || resp.Header.Get(HeaderRedirect) == "" {
		t.Fatalf("anonymous POST /wiki/home: %d", resp.StatusCode)
	}
	// Traversal out of a public prefix is resolved first.
	if resp := anon.auth("/static/../admin", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous /static/../admin: %d", resp.StatusCode)
	}

	bob := h.browser()
	bob.loginOIDC("bob", "bob-pass", "")
	if resp := authMethod(bob, "POST", "/wiki/home"); resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderUser) != "bob" {
		t.Fatalf("bob POST /wiki/home: %d", resp.StatusCode)
	}
	// A signed-in user on a public path is still named upstream.
	if resp := bob.auth("/wiki/home", nil); resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderUser) != "bob" || resp.Header.Get(HeaderToken) == "" {
		t.Fatalf("bob GET /wiki/home: %d %v", resp.StatusCode, resp.Header)
	}
	if resp := bob.auth("/admin/users", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bob /admin/users: %d", resp.StatusCode)
	}
	h.expectAudit("access_denied", "no_rule_matched")
	if !strings.Contains(h.logs.String(), `"rule":"paths[1]"`) {
		t.Fatalf("the denial does not name the rule:\n%s", h.logs.String())
	}

	alice := h.browser()
	alice.loginOIDC("alice", "alice-pass", "")
	if resp := alice.auth("/admin/users", nil); resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderUser) != "alice" {
		t.Fatalf("alice /admin/users: %d", resp.StatusCode)
	}
	if resp := authMethod(alice, "GET", "/admin/audit"); resp.StatusCode != http.StatusOK {
		t.Fatalf("alice GET /admin/audit: %d", resp.StatusCode)
	}
	if resp := authMethod(alice, "DELETE", "/admin/audit"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alice DELETE /admin/audit: %d", resp.StatusCode)
	}
	// nginx can pass the method as X-Original-Method.
	if resp := alice.auth("/admin/audit", http.Header{"X-Original-Method": {"DELETE"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alice X-Original-Method DELETE /admin/audit: %d", resp.StatusCode)
	}
	h.expectAudit("access_denied", "denied_by_rule")

	// A path two servers could read differently is refused for everyone,
	// signed in or not, and is not sent to the login page.
	for _, b := range []*browser{anon, alice} {
		for _, p := range []string{"/static%2F..%2Fadmin", "/static/..;/admin", "/admin%zz"} {
			resp := b.auth(p, nil)
			if resp.StatusCode != http.StatusForbidden || resp.Header.Get(HeaderRedirect) != "" {
				t.Fatalf("%s: %d %v", p, resp.StatusCode, resp.Header)
			}
		}
	}
	h.expectAudit("access_denied", "bad_path")

	// Envoy sends the original method and path on the auth request itself.
	req, _ := http.NewRequest(http.MethodDelete, h.public+"/auth/envoy/admin/audit", nil)
	req.Host = h.host
	if resp := alice.do(req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("envoy DELETE /admin/audit: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, h.public+"/auth/envoy/wiki/x", nil)
	req.Host = h.host
	if resp := anon.do(req); resp.StatusCode != http.StatusOK {
		t.Fatalf("envoy anonymous GET /wiki/x: %d", resp.StatusCode)
	}
	// The same ambiguous paths are refused on the Envoy endpoint, which must
	// not decode them before the rules run.
	for _, b := range []*browser{anon, alice} {
		for _, p := range []string{"/admin%2F..%2Fwiki", "/admin%5C..%5Cwiki", "/wiki%2Fx"} {
			req, _ = http.NewRequest(http.MethodGet, h.public+"/auth/envoy"+p, nil)
			req.Host = h.host
			resp := b.do(req)
			if resp.StatusCode != http.StatusForbidden || resp.Header.Get("Location") != "" {
				t.Fatalf("envoy %s: %d %v", p, resp.StatusCode, resp.Header)
			}
		}
	}
	// Envoy does not normalize the path unless told to, so "." and ".."
	// segments and doubled slashes arrive as the client sent them. The
	// rules resolve them; the endpoint must not answer with the mux's
	// redirect to a cleaned /auth/envoy/... URL, which Envoy would hand to
	// the client.
	envoy := func(b *browser, method, p string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, h.public+"/auth/envoy"+p, nil)
		req.Host = h.host
		req.Header.Set("Accept", "text/html")
		return b.do(req)
	}
	for _, p := range []string{"/wiki//x", "/./wiki/x", "/admin/../wiki/x", "//wiki/x"} {
		if resp := envoy(anon, "GET", p); resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderUser) != "" {
			t.Fatalf("envoy anonymous GET %s: %d %v", p, resp.StatusCode, resp.Header)
		}
	}
	for _, p := range []string{"/static/../admin/users", "/wiki/./../admin/users", "/static//../admin/users"} {
		resp := envoy(anon, "GET", p)
		loc := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusFound || !strings.Contains(loc, "/login?") || strings.Contains(loc, "/auth/envoy") {
			t.Fatalf("envoy anonymous GET %s: %d to %q, want the login page", p, resp.StatusCode, loc)
		}
	}
	if resp := envoy(bob, "GET", "/wiki/../admin/users"); resp.StatusCode != http.StatusForbidden || resp.Header.Get("Location") != "" {
		t.Fatalf("envoy bob GET /wiki/../admin/users: %d %v", resp.StatusCode, resp.Header)
	}
	if resp := envoy(alice, "GET", "/static/../admin//users"); resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderUser) != "alice" {
		t.Fatalf("envoy alice GET /static/../admin//users: %d %v", resp.StatusCode, resp.Header)
	}
	if resp := envoy(alice, "DELETE", "/admin/./audit"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("envoy alice DELETE /admin/./audit: %d", resp.StatusCode)
	}
}

// TestPublicPathOtherProvider: a session from a provider an app does not
// accept may open that app's public paths, but its identity is not passed
// on, and it gets no further.
func TestPublicPathOtherProvider(t *testing.T) {
	h := newHarness(t, harnessOpts{cfgMutate: func(cfg map[string]any) {
		open := cfg["apps"].([]any)[1].(map[string]any)
		open["public"] = []string{"/news"}
	}})
	b := h.browser()
	if resp := b.loginSAML("carol", "carol-pass"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("acs: %d\n%s", resp.StatusCode, h.logs.String())
	}
	openApp := func(path string) *http.Response {
		return b.auth(path, http.Header{"X-Forwarded-Host": {"open.example.com"}})
	}
	resp := openApp("/news/today")
	if resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderUser) != "" || resp.Header.Get(HeaderToken) != "" {
		t.Fatalf("carol on a public path: %d %v", resp.StatusCode, resp.Header)
	}
	if resp := openApp("/"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("carol /: %d", resp.StatusCode)
	}
	h.expectAudit("access_denied", "provider_not_accepted")
	// On the app that accepts her provider, she is named on its paths.
	if resp := b.auth("/", nil); resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderUser) != "carol@partner.example" {
		t.Fatalf("carol on whoami: %d %v", resp.StatusCode, resp.Header)
	}
}
