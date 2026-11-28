package gateway

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authn/server"
)

// TestProxiesDocCoversMigration keeps the "Moving from wicket" note in
// docs/proxies.md in step with the gateway: every WICKET_ variable that
// "authz gateway -h" documents is named there, and so is every command the
// note tells an operator to run.
func TestProxiesDocCoversMigration(t *testing.T) {
	doc, err := os.ReadFile("../../../../docs/proxies.md")
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"-h"}, func(string) string { return "" }, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("authz gateway -h: exit %d: %s", code, stderr.String())
	}
	vars := regexp.MustCompile(`\bWICKET_[A-Z_]+\b`).FindAllString(stderr.String(), -1)
	if len(vars) < 5 {
		t.Fatalf("authz gateway -h documents only %v", vars)
	}
	for _, v := range vars {
		if !bytes.Contains(doc, []byte(v)) {
			t.Errorf("docs/proxies.md does not mention %s, which authz gateway -h documents", v)
		}
	}
	for _, want := range []string{
		"authz gateway genkey",
		"authz gateway gensigningkey",
		"authz gateway check",
		"authz fakeidp",
		"/wicket -> /authz",
		"scripts/image-check.sh",
	} {
		if !bytes.Contains(doc, []byte(want)) {
			t.Errorf("docs/proxies.md does not mention %q", want)
		}
	}
	// Every gateway subcommand the doc runs must be one the usage lists.
	usage := stderr.String()
	for _, m := range regexp.MustCompile("authz gateway ([a-z]+)").FindAllStringSubmatch(string(doc), -1) {
		if !regexp.MustCompile(`(?m)^\s*(usage: )?authz gateway .*\b` + m[1] + `\b`).MatchString(usage) {
			t.Errorf("docs/proxies.md runs authz gateway %s, which authz gateway -h does not list", m[1])
		}
	}
}

// identityHeaders are the headers forward-auth hands the proxy to copy
// upstream, which a client must never be able to set itself.
var identityHeaders = []string{server.HeaderUser, server.HeaderEmail, server.HeaderGroups, server.HeaderProvider, server.HeaderToken}

// TestProxySnippetsStripIdentity holds every proxy configuration in
// docs/proxies.md, the demo's and the ones wicket/examples/proxies.sh runs
// to the two rules that keep identity headers honest: each header the
// gateway sends is removed from (or overwritten on) the client's request,
// and is copied from the gateway's answer to the app.
func TestProxySnippetsStripIdentity(t *testing.T) {
	doc, err := os.ReadFile("../../../../docs/proxies.md")
	if err != nil {
		t.Fatal(err)
	}
	type snippet struct{ from, text string }
	var all []snippet
	for i, m := range regexp.MustCompile("(?s)```[a-z]*\n(.*?)```").FindAllStringSubmatch(string(doc), -1) {
		all = append(all, snippet{fmt.Sprintf("docs/proxies.md, code block %d", i+1), m[1]})
	}
	for _, f := range []string{"wicket/examples/nginx.conf", "wicket/examples/proxies/nginx.conf",
		"wicket/examples/proxies/traefik-dynamic.yml", "wicket/examples/proxies/envoy.yaml"} {
		b, err := os.ReadFile("../../../../" + f)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, snippet{f, string(b)})
	}
	has := func(s snippet, pattern string) bool {
		return regexp.MustCompile(pattern).MatchString(s.text)
	}
	kinds := map[string]int{}
	for _, s := range all {
		var rules []string
		switch {
		case strings.Contains(s.text, "auth_request "):
			kinds["nginx"]++
			for _, h := range identityHeaders {
				v := strings.ReplaceAll(strings.ToLower(h), "-", "_")
				rules = append(rules,
					`auth_request_set\s+\$(\w+)\s+\$upstream_http_`+v+`;`,
					`proxy_set_header\s+`+regexp.QuoteMeta(h)+`\s+\$\w+;`)
			}
			rules = append(rules, `proxy_set_header\s+X-Forwarded-Uri\s+\$request_uri;`,
				`proxy_set_header\s+X-Forwarded-Method\s+\$request_method;`)
		case strings.Contains(s.text, "forwardAuth:"):
			kinds["traefik"]++
			for _, h := range identityHeaders {
				rules = append(rules, `(?m)^\s+`+regexp.QuoteMeta(h)+`: ""$`,
					`authResponseHeaders: \[[^\]]*"`+regexp.QuoteMeta(h)+`"`)
			}
			rules = append(rules, `trustForwardHeader: false`)
		case strings.Contains(s.text, "envoy.filters.http.ext_authz"):
			kinds["envoy"]++
			for _, h := range identityHeaders {
				rules = append(rules, `(?m)^\s+- remove: `+strings.ToLower(h)+`$`)
			}
			rules = append(rules, `allowed_upstream_headers:\s+patterns: \[\{prefix: x-auth-\}\]`,
				`path_prefix: /auth/envoy\n`, `normalize_path: true`, `merge_slashes: true`)
			// The stripping must run before ext_authz adds the gateway's headers.
			if strings.Index(s.text, "header_mutation") > strings.Index(s.text, "envoy.filters.http.ext_authz") {
				t.Errorf("%s: the header mutation filter runs after ext_authz", s.from)
			}
		default:
			continue
		}
		for _, r := range rules {
			if !has(s, r) {
				t.Errorf("%s: no line matching %s", s.from, r)
			}
		}
	}
	for _, k := range []string{"nginx", "traefik", "envoy"} {
		if kinds[k] < 2 {
			t.Errorf("found %d %s configurations, want the doc's and at least one file's", kinds[k], k)
		}
	}
}
