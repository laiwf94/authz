package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pcfg "github.com/laiwf94/authz/internal/platform/config"
)

const (
	exampleConfig     = "../../../../toolgate/examples/config.json"
	examplePolicy     = "../../../../toolgate/examples/policy.json"
	sectionAdminToken = "mcp-section-admin-token-0123456789"
	auditKeyHex       = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)

func mcpSchema(t *testing.T, getenv func(string) string) *pcfg.Schema {
	t.Helper()
	sc, err := pcfg.NewSchema(Section(getenv))
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func upstreamEnv(k string) string {
	if k == "FAKE_UPSTREAM_TOKEN" {
		return "upstream-secret"
	}
	return ""
}

// goodSection is a valid mcp section with the members in extra merged in.
func goodSection(t *testing.T, extra map[string]any) []byte {
	t.Helper()
	m := map[string]any{
		"admin_token": map[string]string{"env": "AT"},
		"config":      exampleConfig,
		"policy":      examplePolicy,
		"audit_log":   filepath.Join(t.TempDir(), "audit.log"),
		"audit_key":   map[string]string{"env": "AK"},
	}
	for k, v := range extra {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, err := json.Marshal(map[string]any{"version": 1, "mcp": m})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var goodEnviron = []string{"AT=" + sectionAdminToken, "AK=" + auditKeyHex}

func TestSectionGood(t *testing.T) {
	doc := goodSection(t, map[string]any{"addr": "127.0.0.1:9100", "state_dir": t.TempDir(),
		"allowed_origins": []string{"https://app.example.com"}, "policy_poll": "0", "log_level": "debug"})
	r := mcpSchema(t, upstreamEnv).Check(doc, append(goodEnviron, "AUTHZ_MCP_SIGNING_KEYS=k1="+auditKeyHex))
	if len(r.Problems) != 0 {
		t.Fatal(r.Problems)
	}
	s := pcfg.Get[Settings](r.Config, SectionName)
	if s.Addr != "127.0.0.1:9100" || s.PolicyPoll != 0 || s.AdminToken.Value() != sectionAdminToken ||
		s.SigningKeys.Value() != "k1="+auditKeyHex || len(s.AllowedOrigins) != 1 {
		t.Fatalf("%+v", s)
	}
}

// TestSectionDefaults: the defaults are toolgate's, and the AUTHZ_MCP_
// variables the gateway already reads are the section's overrides.
func TestSectionDefaults(t *testing.T) {
	r := mcpSchema(t, upstreamEnv).Check(goodSection(t, nil), goodEnviron)
	if len(r.Problems) != 0 {
		t.Fatal(r.Problems)
	}
	s := pcfg.Get[Settings](r.Config, SectionName)
	want, err := loadConfig(func(k string) string {
		return map[string]string{"TOOLGATE_ADMIN_TOKEN": sectionAdminToken, "TOOLGATE_CONFIG": "c", "TOOLGATE_POLICY": "p",
			"TOOLGATE_AUDIT_LOG": "a", "TOOLGATE_AUDIT_KEY": auditKeyHex}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Addr != want.addr || s.AdminAddr != want.adminAddr || time.Duration(s.PolicyPoll) != want.poll ||
		!strings.EqualFold(s.LogLevel, want.logLevel.String()) {
		t.Fatalf("defaults %+v differ from toolgate's %+v", s, want)
	}

	sc := mcpSchema(t, upstreamEnv)
	for _, name := range gatewayEnv {
		v := newPrefix + name
		found := false
		for _, n := range sc.EnvNames(SectionName) {
			found = found || n == v
		}
		if !found {
			t.Errorf("%s does not override a member of the mcp section", v)
		}
	}
}

func TestSectionProblems(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	os.WriteFile(file, []byte("{"), 0o600)
	badPolicy := filepath.Join(dir, "policy.json")
	os.WriteFile(badPolicy, []byte(`{"rules": 1}`), 0o600)
	huge := filepath.Join(dir, "huge.json")
	os.WriteFile(huge, make([]byte, 2<<20), 0o600)
	noTokens := filepath.Join(dir, "no-tokens.json")
	src, _ := os.ReadFile(exampleConfig)
	var cfg map[string]any
	json.Unmarshal(src, &cfg)
	delete(cfg, "tokens")
	b, _ := json.Marshal(cfg)
	os.WriteFile(noTokens, b, 0o600)

	cases := map[string]struct {
		extra   map[string]any
		environ []string
		getenv  func(string) string
		path    string
		msg     string
	}{
		"bad addr":         {map[string]any{"addr": "x"}, goodEnviron, upstreamEnv, "$.mcp.addr", "missing port"},
		"bad admin addr":   {map[string]any{"admin_addr": "x"}, goodEnviron, upstreamEnv, "$.mcp.admin_addr", "missing port"},
		"no admin token":   {map[string]any{"admin_token": nil}, goodEnviron, upstreamEnv, "$.mcp.admin_token", "is required"},
		"short token":      {nil, []string{"AT=short", "AK=" + auditKeyHex}, upstreamEnv, "$.mcp.admin_token", "at least 32 characters"},
		"blank token":      {map[string]any{"admin_token": nil}, []string{"AUTHZ_MCP_ADMIN_TOKEN= ", "AK=" + auditKeyHex}, upstreamEnv, "$.mcp.admin_token", "at least 32 characters"},
		"no config":        {map[string]any{"config": nil}, goodEnviron, upstreamEnv, "$.mcp.config", "is required"},
		"missing config":   {map[string]any{"config": filepath.Join(dir, "none")}, goodEnviron, upstreamEnv, "$.mcp.config", "no such file"},
		"huge config":      {map[string]any{"config": huge}, goodEnviron, upstreamEnv, "$.mcp.config", "larger than"},
		"broken config":    {map[string]any{"config": file}, goodEnviron, upstreamEnv, "$.mcp.config", file + ": "},
		"no credential":    {nil, goodEnviron, func(string) string { return "" }, "$.mcp.config", `upstream "fake"`},
		"no policy":        {map[string]any{"policy": nil}, goodEnviron, upstreamEnv, "$.mcp.policy", "is required"},
		"missing policy":   {map[string]any{"policy": filepath.Join(dir, "none")}, goodEnviron, upstreamEnv, "$.mcp.policy", "no such file"},
		"bad policy":       {map[string]any{"policy": badPolicy}, goodEnviron, upstreamEnv, "$.mcp.policy", badPolicy + ": "},
		"no audit log":     {map[string]any{"audit_log": nil}, goodEnviron, upstreamEnv, "$.mcp.audit_log", "is required"},
		"no audit key":     {map[string]any{"audit_key": nil}, goodEnviron, upstreamEnv, "$.mcp.audit_key", "is required"},
		"bad audit key":    {nil, []string{"AT=" + sectionAdminToken, "AK=abc"}, upstreamEnv, "$.mcp.audit_key", "64 hex characters"},
		"state dir file":   {map[string]any{"state_dir": file}, goodEnviron, upstreamEnv, "$.mcp.state_dir", "exists and is not a directory"},
		"state dir stat":   {map[string]any{"state_dir": file + "/sub"}, goodEnviron, upstreamEnv, "$.mcp.state_dir", "not a directory"},
		"bad signing key":  {nil, append(goodEnviron, "AUTHZ_MCP_SIGNING_KEYS=k1=abc"), upstreamEnv, "$.mcp.signing_keys", "must be kid=<64 hex characters>, comma-separated"},
		"repeated kid":     {nil, append(goodEnviron, "AUTHZ_MCP_SIGNING_KEYS=k="+auditKeyHex+",k="+auditKeyHex), upstreamEnv, "$.mcp.signing_keys", `repeats key id "k"`},
		"commas only":      {nil, append(goodEnviron, "AUTHZ_MCP_SIGNING_KEYS=,"), upstreamEnv, "$.mcp.signing_keys", "holds no key"},
		"keys, no tokens":  {map[string]any{"config": noTokens}, append(goodEnviron, "AUTHZ_MCP_SIGNING_KEYS=k="+auditKeyHex), upstreamEnv, "$.mcp.signing_keys", "no tokens section"},
		"bad log level":    {map[string]any{"log_level": "loud"}, goodEnviron, upstreamEnv, "$.mcp.log_level", `"loud" is not debug`},
		"bad policy poll":  {nil, append(goodEnviron, "AUTHZ_MCP_POLICY_POLL=soon"), upstreamEnv, "$.mcp.policy_poll", "invalid duration"},
		"policy poll file": {map[string]any{"policy_poll": "-1s"}, goodEnviron, upstreamEnv, "$.mcp.policy_poll", "invalid duration"},
	}
	for name, c := range cases {
		r := mcpSchema(t, c.getenv).Check(goodSection(t, c.extra), c.environ)
		if r.Problems.Count(pcfg.SeverityError) != 1 || r.Problems[0].Path != c.path || !strings.Contains(r.Problems[0].Message, c.msg) {
			t.Errorf("%s: %v, want %s: %s", name, r.Problems, c.path, c.msg)
		}
	}
}

// TestSectionAuthenticator: an agents config that cannot make an
// authenticator is reported at $.mcp.config when no signing keys are set.
func TestSectionAuthenticator(t *testing.T) {
	dir := t.TempDir()
	src, _ := os.ReadFile(exampleConfig)
	var cfg map[string]any
	json.Unmarshal(src, &cfg)
	agents := cfg["agents"].([]any)
	cfg["agents"] = append(agents, agents[0]) // the same agent twice
	b, _ := json.Marshal(cfg)
	dup := filepath.Join(dir, "dup.json")
	os.WriteFile(dup, b, 0o600)
	r := mcpSchema(t, upstreamEnv).Check(goodSection(t, map[string]any{"config": dup}), goodEnviron)
	if r.Problems.Err() == nil || r.Problems[0].Path != "$.mcp.config" {
		t.Fatalf("%v", r.Problems)
	}
}
