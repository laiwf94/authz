package checkcmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/cmd/authz/internal/gateway"
	"github.com/laiwf94/authz/cmd/authz/internal/mcp"
	"github.com/laiwf94/authz/cmd/authz/internal/serve"
	"github.com/laiwf94/authz/internal/authn/check"
	authnconfig "github.com/laiwf94/authz/internal/authn/config"
	"github.com/laiwf94/authz/internal/authn/fakeidp"
)

const (
	cookieKeyHex = "0011223344556677889900112233445566778899001122334455667788990011"
	auditKeyHex  = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	mcpToken     = "check-config-admin-token-0123456789"
)

// platformDoc is a configuration file with all three sections, the
// secrets given by environment references.
func platformDoc(t *testing.T, issuer string) string {
	t.Helper()
	m := map[string]any{
		"version": 1,
		"serve":   map[string]any{"addr": ":8080", "api_keys": map[string]string{"env": "API_KEYS"}},
		"gateway": map[string]any{
			"cookie_keys": map[string]string{"env": "COOKIE_KEYS"},
			"public_url":  "https://auth.example.com",
			"providers": []any{map[string]any{"id": "corp", "type": "oidc", "issuer": issuer,
				"client_id": "c", "client_secret_env": "CORP_SECRET"}},
			"apps": []any{map[string]any{"id": "app", "hosts": []string{"app.example.com"}, "providers": []string{"corp"},
				"allow": map[string]any{"any_user": true}}},
		},
		"mcp": map[string]any{
			"admin_token": map[string]string{"env": "MCP_TOKEN"},
			"config":      "../../../../toolgate/examples/config.json",
			"policy":      "../../../../toolgate/examples/policy.json",
			"audit_log":   filepath.Join(t.TempDir(), "audit.log"),
			"audit_key":   map[string]string{"env": "MCP_AUDIT_KEY"},
		},
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return write(t, "authz.json", string(b))
}

// runProcess runs the command as the process does, with os.Getenv, after
// setting e in the process environment for the rest of the test. Secrets
// the file references by {"env": ...} are read from the variables the
// process has, so a map-backed getenv cannot stand in for them.
func runProcess(t *testing.T, e map[string]string, args ...string) (int, string) {
	t.Helper()
	for k, v := range e {
		t.Setenv(k, v)
	}
	var out, errb strings.Builder
	code := Run(context.Background(), args, os.Getenv, strings.NewReader(""), &out, &errb)
	return code, out.String()
}

func goodEnv() map[string]string {
	return map[string]string{
		"API_KEYS": "check-test-key-0123456", "COOKIE_KEYS": cookieKeyHex, "CORP_SECRET": "s",
		"MCP_TOKEN": mcpToken, "MCP_AUDIT_KEY": auditKeyHex, "FAKE_UPSTREAM_TOKEN": "t",
	}
}

func TestConfigFile(t *testing.T) {
	file := platformDoc(t, "https://idp.example.com")
	t.Run("valid", func(t *testing.T) {
		code, out := runProcess(t, goodEnv(), "-config", file)
		want := file + ": config is valid: 3 sections (serve, gateway, mcp), 0 warnings (offline checks)\n"
		if code != OK || out != want {
			t.Fatalf("code %d, out %q, want %q", code, out, want)
		}
	})

	t.Run("every problem", func(t *testing.T) {
		// Every problem in every section, each with its place and JSON path.
		e := goodEnv()
		delete(e, "COOKIE_KEYS")
		e["API_KEYS"] = "short"
		e["MCP_AUDIT_KEY"] = "abc"
		e["AUTHZ_GATEWAY_LOGIN_RATE"] = "0"
		e["AUTHZ_SERVE_ADRR"] = ":1"
		code, out := runProcess(t, e, "-config", file)
		for _, w := range []string{
			file + ":17:20: error: $.gateway.cookie_keys: environment variable COOKIE_KEYS is empty or unset\n",
			file + ":35:18: error: $.mcp.audit_key: must be 64 hex characters\n",
			file + ":44:17: error: $.serve.api_keys: key 1 is 5 characters; each key must be at least 16\n",
			"AUTHZ_GATEWAY_LOGIN_RATE: error: $.gateway.login_rate: must be 1-100000\n",
			`AUTHZ_SERVE_ADRR: warning: $.serve: unknown variable (did you mean "AUTHZ_SERVE_ADDR"?)` + "\n",
		} {
			if !strings.Contains(out, w) {
				t.Errorf("missing %q in:\n%s", w, out)
			}
		}
		if code != Problems || !strings.HasSuffix(out, "\n4 problems\n") {
			t.Fatalf("code %d, out:\n%s", code, out)
		}
	})

	t.Run("warnings pass", func(t *testing.T) {
		e := goodEnv()
		e["AUTHZ_MCP_ADRR"] = "x"
		code, out := runProcess(t, e, "-config", file)
		if code != OK || !strings.HasSuffix(out, "3 sections (serve, gateway, mcp), 1 warning (offline checks)\n") {
			t.Fatalf("code %d, out %q", code, out)
		}
	})
}

func TestConfigFileOnline(t *testing.T) {
	// Nothing listens on port 1, so discovery fails without leaving the
	// machine.
	file := platformDoc(t, "https://127.0.0.1:1")
	code, out := runProcess(t, goodEnv(), "-config", file, "-online", "-timeout", "5s")
	if code != Problems || !strings.Contains(out, file+":25:19: error: $.gateway.providers[0].issuer: ") || !strings.HasSuffix(out, "\n1 problem\n") {
		t.Fatalf("code %d, out %q", code, out)
	}
	code, out = runProcess(t, nil, "-config", file)
	if code != OK || !strings.HasSuffix(out, "(offline checks)\n") {
		t.Fatalf("offline: code %d, out %q", code, out)
	}
	// A provider that answers passes, and the summary names the mode.
	srv := httptest.NewUnstartedServer(nil)
	issuer := "https://" + srv.Listener.Addr().String()
	idp, err := fakeidp.New(fakeidp.Config{Issuer: issuer})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = idp
	srv.StartTLS()
	defer srv.Close()
	var b strings.Builder
	r := &report{out: &b}
	checkConfig(context.Background(), r, platformDoc(t, issuer), os.Getenv, check.Options{
		Getenv: os.Getenv, Online: true, Timeout: 5 * time.Second,
		Client: func(*authnconfig.Provider, *x509.CertPool) *http.Client { return srv.Client() },
	})
	if r.problems != 0 || !strings.HasSuffix(b.String(), "3 sections (serve, gateway, mcp), 0 warnings (online checks)\n") {
		t.Fatalf("%q", b.String())
	}
}

func TestConfigFileUnreadable(t *testing.T) {
	cases := map[string]struct{ content, want string }{
		"not json":   {"{", ":1:2: error: $: invalid JSON: unexpected end of file"},
		"no version": {`{"serve": {}}`, `:1:1: error: $: "version" is required`},
		"unknown":    {`{"version": 1, "sevre": {}}`, `:1:16: error: $.sevre: unknown member (did you mean "serve"?)`},
	}
	for name, c := range cases {
		file := write(t, "c.json", c.content)
		code, out, _ := run(t, nil, "", "-config", file)
		if code != Problems || !strings.Contains(out, file+c.want) {
			t.Errorf("%s: code %d, out %q, want %q", name, code, out, c.want)
		}
	}
	missing := filepath.Join(t.TempDir(), "missing.json")
	code, out, _ := run(t, nil, "", "-config", missing)
	if code != Problems || !strings.HasPrefix(out, missing+": error: open "+missing+": no such file") {
		t.Fatalf("missing: code %d, out %q", code, out)
	}
	empty := write(t, "empty.json", `{"version": 1}`)
	code, out, _ = run(t, nil, "", "-config", empty)
	if code != OK || out != empty+": config is valid: no sections, 0 warnings (offline checks)\n" {
		t.Fatalf("empty: code %d, out %q", code, out)
	}
	// A section given only by the environment is checked, with the
	// variables named.
	code, out, _ = run(t, map[string]string{"AUTHZ_SERVE_ADDR": "nope"}, "", "-config", empty)
	if code != Problems || !strings.Contains(out, empty+": error: $.serve.api_keys: is required") ||
		!strings.Contains(out, "AUTHZ_SERVE_ADDR: error: $.serve.addr: address nope: missing port in address") {
		t.Fatalf("env only: code %d, out %q", code, out)
	}
}

func TestConfigUsage(t *testing.T) {
	cases := map[string][]string{
		"-online and -timeout apply to -config": {"-serve", "-online"},
		"-timeout must be between":              {"-config", "f", "-timeout", "0s"},
	}
	for want, args := range cases {
		code, _, errb := run(t, nil, "", args...)
		if code != Usage || !strings.Contains(errb, want) {
			t.Errorf("%q: code %d, stderr %q, want %q", args, code, errb, want)
		}
	}
	code, _, errb := run(t, nil, "", "-h")
	if code != OK || !strings.Contains(errb, "-config file") {
		t.Fatalf("-h: code %d, stderr %q", code, errb)
	}
}

func TestEnvironIncludesProcessAndSchema(t *testing.T) {
	t.Setenv("AUTHZ_GATEWAY_FROM_PROCESS", "1")
	sc := Schema(context.Background(), check.Options{})
	got := sc.Environ(func(k string) string {
		return map[string]string{"AUTHZ_SERVE_ADDR": ":1", "AUTHZ_GATEWAY_FROM_PROCESS": "x", "UNRELATED": "y"}[k]
	})
	if strings.Join(got, " ") != "AUTHZ_GATEWAY_FROM_PROCESS=x AUTHZ_SERVE_ADDR=:1" {
		t.Fatalf("%v", got)
	}
}

// Each subcommand that reads the platform file skips the sections of the
// others: the serve schema reads the whole file, whatever the other
// sections hold, and knows every section the full schema has.
func TestServeSchemaSkipsTheOthers(t *testing.T) {
	file := platformDoc(t, "https://idp.example.com")
	for k, v := range goodEnv() {
		t.Setenv(k, v)
	}
	sc := serve.Schema()
	res, err := sc.LoadResult(file, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("serve schema on the full file: %v", res.Problems)
	}
	b, _ := os.ReadFile(file)
	broken := strings.Replace(string(b), `"public_url": "https://auth.example.com"`, `"public_url": 7`, 1)
	if r := sc.Check([]byte(broken), os.Environ()); len(r.Problems) != 0 {
		t.Fatalf("a gateway problem stopped serve: %v", r.Problems)
	}
	if r := Schema(context.Background(), check.Options{}).Check([]byte(broken), os.Environ()); r.Problems.Err() == nil {
		t.Fatal("the full schema missed the gateway problem")
	}
	if want := []string{gateway.SectionName, mcp.SectionName}; strings.Join(serve.OtherSections, ",") != strings.Join(want, ",") {
		t.Fatalf("serve.OtherSections = %q, want %q", serve.OtherSections, want)
	}
}
