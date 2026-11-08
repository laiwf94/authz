package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type upstream struct {
	URL        string `json:"url"`
	Credential Secret `json:"credential"`
}

type limits struct {
	Burst  int      `json:"burst"`
	Window Duration `json:"window"`
}

type serveSection struct {
	Addr      string              `json:"addr"`
	APIKeys   Secret              `json:"api_keys"`
	CacheSize int                 `json:"cache_size"`
	Retention int64               `json:"retention"`
	Shards    int32               `json:"shards"`
	Debug     bool                `json:"debug"`
	Timeout   Duration            `json:"timeout"`
	Hosts     []string            `json:"hosts"`
	Limits    limits              `json:"limits"`
	Upstreams map[string]upstream `json:"upstreams"`
	Tokens    []Secret            `json:"tokens"`
	Labels    map[string]string   `json:"labels"`
}

type gatewaySection struct {
	PublicURL string `json:"public_url"`
}

func serveDefaults(s *serveSection) {
	s.Addr = ":8080"
	s.CacheSize = 100_000
	s.Timeout = Duration(30 * time.Second)
}

func checkServe(s *serveSection, c *Checker) {
	if !s.APIKeys.IsSet() {
		c.Errorf(c.Path, "api_keys is required")
	}
	if s.CacheSize < 0 {
		c.Errorf(c.Field("cache_size"), "must not be negative")
	}
	if s.Debug {
		c.Warnf(c.Field("debug"), "debug logging shows request bodies")
	}
}

func checkGateway(g *gatewaySection, c *Checker) {
	if !strings.HasPrefix(g.PublicURL, "https://") {
		c.Errorf(c.Field("public_url"), "must be an https URL")
	}
}

func testSchema(t testing.TB) *Schema {
	t.Helper()
	sc, err := NewSchema(
		NewSection("serve", serveDefaults, checkServe),
		NewSection("gateway", nil, checkGateway),
	)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func writeFile(t testing.TB, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// lines renders problems as "line:col severity path (env): message".
func lines(ps Problems) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = fmt.Sprintf("%d:%d %s %s", p.Line, p.Column, p.Severity, p)
	}
	return out
}

func TestLoadFull(t *testing.T) {
	dir := t.TempDir()
	keys := writeFile(t, dir, "keys", "  key-one,key-two\n")
	cred := writeFile(t, dir, "cred", "upstream-secret\n")
	tok := writeFile(t, dir, "tok", "tok-1")
	doc := fmt.Sprintf(`{
  "version": 1,
  "serve": {
    "addr": ":9090",
    "api_keys": {"file": %q},
    "retention": 9000000000,
    "shards": 16,
    "timeout": "2m",
    "hosts": ["a.example", "b.example"],
    "limits": {"burst": 5, "window": "1s"},
    "upstreams": {"github": {"url": "https://api.github.com", "credential": {"file": %q}},
                  "jira": {"url": "https://jira.example", "credential": {"env": "JIRA_TOKEN"}}},
    "tokens": [{"file": %q}, {"env": "TOKEN_TWO"}],
    "labels": {"team": "identity", "odd key": "x"},
    "cache_size": null
  },
  "gateway": {"public_url": "https://login.example"}
}`, keys, cred, tok)
	path := writeFile(t, dir, "authz.json", doc)
	env := []string{"JIRA_TOKEN= jira-secret ", "TOKEN_TWO=tok-2", "UNRELATED=1", "NOEQUALS"}
	cfg, err := testSchema(t).Load(path, env)
	if err != nil {
		t.Fatal(err)
	}
	s := Get[serveSection](cfg, "serve")
	if s == nil {
		t.Fatal("serve section missing")
	}
	if s.Addr != ":9090" || s.CacheSize != 100_000 || s.Retention != 9_000_000_000 || s.Shards != 16 ||
		time.Duration(s.Timeout) != 2*time.Minute || s.Limits.Burst != 5 || time.Duration(s.Limits.Window) != time.Second {
		t.Errorf("serve = %+v", *s)
	}
	if !reflect.DeepEqual(s.Hosts, []string{"a.example", "b.example"}) {
		t.Errorf("hosts = %q", s.Hosts)
	}
	if got := s.APIKeys.Value(); got != "key-one,key-two" {
		t.Errorf("api_keys = %q", got)
	}
	if got := s.Upstreams["github"].Credential.Value(); got != "upstream-secret" {
		t.Errorf("github credential = %q", got)
	}
	if got := s.Upstreams["jira"].Credential.Value(); got != "jira-secret" {
		t.Errorf("jira credential = %q", got)
	}
	if s.Tokens[0].Value() != "tok-1" || s.Tokens[1].Value() != "tok-2" {
		t.Errorf("tokens = %q %q", s.Tokens[0].Value(), s.Tokens[1].Value())
	}
	if s.Labels["odd key"] != "x" {
		t.Errorf("labels = %v", s.Labels)
	}
	if g := Get[gatewaySection](cfg, "gateway"); g == nil || g.PublicURL != "https://login.example" {
		t.Errorf("gateway = %+v", g)
	}
	if cfg.Version != Version || !cfg.Has("serve") || !cfg.Has("gateway") || cfg.Has("mcp") {
		t.Errorf("version %d, has serve %v gateway %v mcp %v", cfg.Version, cfg.Has("serve"), cfg.Has("gateway"), cfg.Has("mcp"))
	}
	if Get[gatewaySection](cfg, "serve") != nil || Get[serveSection](nil, "serve") != nil {
		t.Error("Get returned a section of the wrong type")
	}
	var read []string
	for _, src := range cfg.Sources() {
		if src.Err != "" {
			t.Errorf("source %s: %s", src.Path, src.Err)
		}
		read = append(read, filepath.Base(src.Path))
	}
	// The file, then secrets in member order: api_keys, tokens, upstreams.
	if want := []string{"authz.json", "keys", "tok", "cred"}; !reflect.DeepEqual(read, want) {
		t.Errorf("sources = %q, want %q", read, want)
	}
}

func TestAbsentSection(t *testing.T) {
	r := testSchema(t).Check([]byte(`{"version": 1, "gateway": {"public_url": "https://x"}}`), nil)
	if err := r.Problems.Err(); err != nil {
		t.Fatal(err)
	}
	if r.Config.Has("serve") || Get[serveSection](r.Config, "serve") != nil {
		t.Error("an absent section is present")
	}
}

func TestProblems(t *testing.T) {
	dir := t.TempDir()
	empty := writeFile(t, dir, "empty", " \n")
	missing := filepath.Join(dir, "missing")
	big := writeFile(t, dir, "big", strings.Repeat("x", MaxSecretBytes+1))
	cases := []struct {
		name string
		doc  string
		env  []string
		want []string
	}{
		{"not JSON", `{"version": 1,`, nil, []string{"1:15 error $: invalid JSON: unexpected end of file"}},
		{"bad token", `{"version": 1 x}`, nil, []string{`1:15 error $: invalid JSON: invalid character 'x' after object key:value pair`}},
		{"empty", ``, nil, []string{"1:1 error $: invalid JSON: unexpected end of file"}},
		{"trailing", `{"version": 1} {}`, nil, []string{"1:16 error $: trailing data after the JSON object"}},
		{"not an object", `[1]`, nil, []string{
			"1:1 error $: must be an object, not an array",
			`1:1 error $: "version" is required; this build reads version 1`,
		}},
		{"null", `null`, nil, []string{
			"1:1 error $: must be an object, not null",
			`1:1 error $: "version" is required; this build reads version 1`,
		}},
		{"no version", `{}`, nil, []string{`1:1 error $: "version" is required; this build reads version 1`}},
		{"newer", `{"version": 2}`, nil, []string{"1:13 error $.version: version 2 was written for a newer authz; this build reads version 1"}},
		{"zero", `{"version": 0}`, nil, []string{"1:13 error $.version: version 0 does not exist; this build reads version 1"}},
		{"version string", `{"version": "1"}`, nil, []string{"1:13 error $.version: must be a whole number, not a string"}},
		{"version fraction", `{"version": 1.5}`, nil, []string{"1:13 error $.version: 1.5 is not a whole number between -9223372036854775808 and 9223372036854775807"}},
		{"unknown section", `{"version": 1, "serv": {}}`, nil, []string{`1:16 error $.serv: unknown member (did you mean "serve"?)`}},
		{"unknown member", "{\"version\": 1,\n \"gateway\": {\"public_url\": \"https://x\", \"publicurl\": 1}}", nil,
			[]string{`2:41 error $.gateway.publicurl: unknown member (did you mean "public_url"?)`}},
		{"unknown odd member", `{"version": 1, "gateway": {"public_url": "https://x", "a b": {"c": [1]}}}`, nil,
			[]string{`1:55 error $.gateway["a b"]: unknown member`}},
		{"duplicate", `{"version": 1, "version": 1}`, nil, []string{`1:16 error $.version: duplicate member "version"`}},
		{"types", `{"version": 1, "serve": {"api_keys": {"env": "K"}, "addr": 8080, "debug": "yes", "hosts": "a", "limits": [], "cache_size": "1", "upstreams": [], "tokens": {}}}`,
			[]string{"K=k"}, []string{
				"1:60 error $.serve.addr: must be a string, not a number",
				"1:75 error $.serve.debug: must be true or false, not a string",
				"1:91 error $.serve.hosts: must be an array, not a string",
				"1:106 error $.serve.limits: must be an object, not an array",
				"1:124 error $.serve.cache_size: must be a whole number, not a string",
				"1:142 error $.serve.upstreams: must be an object, not an array",
				"1:156 error $.serve.tokens: must be an array, not an object",
			}},
		{"bool for object", `{"version": 1, "gateway": true}`, nil, []string{"1:27 error $.gateway: must be an object, not a boolean"}},
		{"range", `{"version": 1, "serve": {"api_keys": {"env": "K"}, "shards": 3000000000}}`, []string{"K=k"},
			[]string{"1:62 error $.serve.shards: 3000000000 is not a whole number between -2147483648 and 2147483647"}},
		{"durations", `{"version": 1, "serve": {"api_keys": {"env": "K"}, "timeout": "-1s", "limits": {"window": 5}}}`, []string{"K=k"}, []string{
			`1:63 error $.serve.timeout: invalid duration "-1s" (use a string like "90s" or "8h")`,
			`1:91 error $.serve.limits.window: must be a duration string like "90s" or "8h", not a number`,
		}},
		{"literal secret", `{"version": 1, "serve": {"api_keys": "hunter2hunter2"}}`, nil, []string{
			"1:25 error $.serve: api_keys is required",
			`1:38 error $.serve.api_keys: secrets are not written in the file: use {"file": "/path"} or {"env": "NAME"}`,
		}},
		{"secret shapes", `{"version": 1, "serve": {"api_keys": {}, "tokens": [{"file": "a", "env": "B"}, {"path": "x"}, 7]}}`, nil, []string{
			"1:25 error $.serve: api_keys is required",
			`1:38 error $.serve.api_keys: set "file" to a path or "env" to a variable name`,
			`1:53 error $.serve.tokens[0]: set "file" or "env", not both`,
			`1:80 error $.serve.tokens[1]: set "file" to a path or "env" to a variable name`,
			`1:81 error $.serve.tokens[1].path: unknown member`,
			`1:95 error $.serve.tokens[2]: must be {"file": "/path"} or {"env": "NAME"}, not a number`,
		}},
		{"secret reads", fmt.Sprintf(`{"version": 1, "serve": {"api_keys": {"file": %q}, "tokens": [{"file": %q}, {"env": "UNSET"}, {"file": %q}]}}`, empty, missing, big), nil, []string{
			fmt.Sprintf("1:38 error $.serve.api_keys: %s is empty", empty),
			fmt.Sprintf("%d:%d error $.serve.tokens[0]: open %s: no such file or directory", 1, 63+len(empty), missing),
			fmt.Sprintf("%d:%d error $.serve.tokens[1]: environment variable UNSET is empty or unset", 1, 77+len(empty)+len(missing)),
			fmt.Sprintf("%d:%d error $.serve.tokens[2]: %s: file larger than %d bytes", 1, 95+len(empty)+len(missing), big, MaxSecretBytes),
		}},
		{"section checks", `{"version": 1, "serve": {"api_keys": {"env": "K"}, "cache_size": -1, "debug": true}, "gateway": {}}`, []string{"K=k"}, []string{
			"1:66 error $.serve.cache_size: must not be negative",
			"1:79 warning $.serve.debug: debug logging shows request bodies",
			"1:97 error $.gateway.public_url: must be an https URL",
		}},
		{"null keeps default", `{"version": 1, "serve": {"api_keys": {"env": "K"}, "addr": null, "cache_size": -5}}`, []string{"K=k"}, []string{
			"1:80 error $.serve.cache_size: must not be negative",
		}},
	}
	sc := testSchema(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := sc.Check([]byte(tc.doc), tc.env)
			if got := lines(r.Problems); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("problems:\n got %q\nwant %q", got, tc.want)
			}
			if r.Config == nil && !strings.HasPrefix(tc.name, "not JSON") && tc.name != "bad token" && tc.name != "empty" {
				t.Error("Config is nil for a JSON document")
			}
		})
	}
}

func TestProblemsErr(t *testing.T) {
	ps := Problems{
		{Path: "$.a", Severity: SeverityWarning, Message: "w"},
		{Path: "$.b", Env: "AUTHZ_X_B", Message: "e"},
	}
	if ps.Count(SeverityWarning) != 1 || ps.Count(SeverityError) != 1 {
		t.Errorf("counts %d %d", ps.Count(SeverityWarning), ps.Count(SeverityError))
	}
	err := ps.Err()
	var got Problems
	if !errors.As(err, &got) || len(got) != 1 || err.Error() != "$.b (AUTHZ_X_B): e" {
		t.Errorf("Err() = %v", err)
	}
	if ps[:1].Err() != nil {
		t.Error("warnings failed a load")
	}
	if ps.Error() != "$.a: w; $.b (AUTHZ_X_B): e" {
		t.Errorf("Error() = %q", ps.Error())
	}
	if SeverityError.String() != "error" || SeverityWarning.String() != "warning" {
		t.Error("severity names")
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	sc := testSchema(t)
	if _, err := sc.Load(filepath.Join(dir, "nope.json"), nil); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("missing file: %v", err)
	}
	big := writeFile(t, dir, "big.json", `{"version": 1}`+strings.Repeat(" ", MaxFileBytes))
	if _, err := sc.Load(big, nil); err == nil || !strings.Contains(err.Error(), "file larger than") {
		t.Errorf("big file: %v", err)
	}
	bad := writeFile(t, dir, "bad.json", `{"version": 1, "gateway": {}}`)
	_, err := sc.Load(bad, nil)
	var ps Problems
	if !errors.As(err, &ps) || len(ps) != 1 || ps[0].Path != "$.gateway.public_url" {
		t.Errorf("invalid file: %v", err)
	}
	warn := writeFile(t, dir, "warn.json", `{"version": 1, "serve": {"api_keys": {"env": "K"}, "debug": true}}`)
	r, err := sc.LoadResult(warn, []string{"K=k"})
	if err != nil || r.Problems.Count(SeverityWarning) != 1 || r.Problems.Err() != nil {
		t.Errorf("warnings: %v %v", err, r.Problems)
	}
	if _, err := sc.Load(warn, []string{"K=k"}); err != nil {
		t.Errorf("warnings fail Load: %v", err)
	}
}

func TestEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	keyFile := writeFile(t, dir, "keys", "from-file\n")
	sc := testSchema(t)
	doc := []byte(`{"version": 1, "serve": {"addr": ":1", "api_keys": {"env": "K"}, "hosts": ["file.example"]}}`)
	r := sc.Check(doc, []string{
		"K=k",
		"AUTHZ_SERVE_ADDR=:2",
		"AUTHZ_SERVE_CACHE_SIZE= 7 ",
		"AUTHZ_SERVE_DEBUG=false",
		"AUTHZ_SERVE_TIMEOUT=5s",
		"AUTHZ_SERVE_HOSTS=a.example, b.example,,",
		"AUTHZ_SERVE_LIMITS_BURST=9",
		"AUTHZ_SERVE_RETENTION=",
		"AUTHZ_SERVE_API_KEYS_FILE=" + keyFile,
	})
	if err := r.Problems.Err(); err != nil {
		t.Fatal(err)
	}
	s := Get[serveSection](r.Config, "serve")
	if s.Addr != ":2" || s.CacheSize != 7 || s.Debug || time.Duration(s.Timeout) != 5*time.Second || s.Limits.Burst != 9 || s.Retention != 0 {
		t.Errorf("serve = %+v", *s)
	}
	if !reflect.DeepEqual(s.Hosts, []string{"a.example", "b.example"}) {
		t.Errorf("hosts = %q", s.Hosts)
	}
	if s.APIKeys.Value() != "from-file" {
		t.Errorf("api_keys = %q", s.APIKeys.Value())
	}

	// A section can be given by the environment alone, and a secret set
	// directly.
	r = sc.Check([]byte(`{"version": 1}`), []string{"AUTHZ_SERVE_API_KEYS= direct-key "})
	if err := r.Problems.Err(); err != nil {
		t.Fatal(err)
	}
	s = Get[serveSection](r.Config, "serve")
	if s == nil || s.APIKeys.Value() != "direct-key" || s.Addr != ":8080" {
		t.Fatalf("env-only serve = %+v", s)
	}

	// Problems from the environment name the variable and have no position;
	// they follow the problems in the file.
	r = sc.Check([]byte(`{"version": 1, "gateway": {"public_url": "https://x", "bogus": 1}}`), []string{
		"AUTHZ_SERVE_API_KEYS=a",
		"AUTHZ_SERVE_API_KEYS_FILE=/b",
		"AUTHZ_SERVE_DEBUG=maybe",
		"AUTHZ_SERVE_CACHE_SIZE=-3",
		"AUTHZ_SERVE_SHARDS=99999999999",
		"AUTHZ_SERVE_TIMEOUT=soon",
		"AUTHZ_SERVE_ADRR=:1",
		"AUTHZ_GATEWAY_PUBLIC_URL=http://x",
		"AUTHZ_OTHER_THING=1",
	})
	want := []string{
		"1:55 error $.gateway.bogus: unknown member",
		"0:0 error $.gateway.public_url (AUTHZ_GATEWAY_PUBLIC_URL): must be an https URL",
		"0:0 error $.serve.api_keys (AUTHZ_SERVE_API_KEYS): set by both AUTHZ_SERVE_API_KEYS and AUTHZ_SERVE_API_KEYS_FILE; unset one",
		`0:0 error $.serve.debug (AUTHZ_SERVE_DEBUG): "maybe" is not true or false`,
		`0:0 error $.serve.shards (AUTHZ_SERVE_SHARDS): "99999999999" is not a whole number between -2147483648 and 2147483647`,
		`0:0 error $.serve.timeout (AUTHZ_SERVE_TIMEOUT): invalid duration "soon" (use a string like "90s" or "8h")`,
		`0:0 warning $.serve (AUTHZ_SERVE_ADRR): unknown variable (did you mean "AUTHZ_SERVE_ADDR"?)`,
		// Both spellings of api_keys were refused, so it is missing; the
		// section came from the environment alone and has no position.
		"0:0 error $.serve: api_keys is required",
		"0:0 error $.serve.cache_size (AUTHZ_SERVE_CACHE_SIZE): must not be negative",
	}
	if got := lines(r.Problems); !reflect.DeepEqual(got, want) {
		t.Errorf("problems:\n got %q\nwant %q", got, want)
	}
}

func TestEnvNames(t *testing.T) {
	sc := testSchema(t)
	want := []string{
		"AUTHZ_SERVE_ADDR", "AUTHZ_SERVE_API_KEYS", "AUTHZ_SERVE_API_KEYS_FILE", "AUTHZ_SERVE_CACHE_SIZE",
		"AUTHZ_SERVE_DEBUG", "AUTHZ_SERVE_HOSTS", "AUTHZ_SERVE_LIMITS_BURST", "AUTHZ_SERVE_LIMITS_WINDOW",
		"AUTHZ_SERVE_RETENTION", "AUTHZ_SERVE_SHARDS", "AUTHZ_SERVE_TIMEOUT",
	}
	if got := sc.EnvNames("serve"); !reflect.DeepEqual(got, want) {
		t.Errorf("EnvNames(serve) =\n %q\nwant %q", got, want)
	}
	if got := sc.EnvNames("nope"); got != nil {
		t.Errorf("EnvNames(nope) = %q", got)
	}
}

func TestNewSchemaErrors(t *testing.T) {
	type noTag struct{ A string }
	type badName struct {
		A string `json:"A"`
	}
	type float struct {
		F float32 `json:"f"`
	}
	type ptr struct {
		P *string `json:"p"`
	}
	type intMap struct {
		M map[int]string `json:"m"`
	}
	type inner struct {
		B string `json:"b"`
	}
	type collide struct {
		AB string `json:"a_b"`
		A  inner  `json:"a"`
	}
	type secretCollide struct {
		K     Secret `json:"k"`
		KFile string `json:"k_file"`
	}
	type ok struct {
		A      string `json:"a"`
		hidden int
		Skip   chan int `json:"-"`
	}
	cases := []struct {
		name     string
		sections []Section
		want     string
	}{
		{"zero", []Section{{}}, "zero Section"},
		{"name", []Section{NewSection[ok]("Serve", nil, nil)}, `section name "Serve"`},
		{"version", []Section{NewSection[ok]("version", nil, nil)}, `section name "version"`},
		{"underscore", []Section{NewSection[ok]("my_app", nil, nil)}, `section name "my_app"`},
		{"dup", []Section{NewSection[ok]("a", nil, nil), NewSection[ok]("a", nil, nil)}, `two sections are named "a"`},
		{"not struct", []Section{NewSection[string]("a", nil, nil)}, "string is not a struct"},
		{"no tag", []Section{NewSection[noTag]("a", nil, nil)}, "a.A has no json name"},
		{"bad tag", []Section{NewSection[badName]("a", nil, nil)}, `json name "A"`},
		{"float", []Section{NewSection[float]("a", nil, nil)}, "a.f: no rule for float32"},
		{"pointer", []Section{NewSection[ptr]("a", nil, nil)}, "a.p: no rule for *string"},
		{"int map", []Section{NewSection[intMap]("a", nil, nil)}, "a.m: map keys must be strings"},
		{"env collision", []Section{NewSection[collide]("a", nil, nil)}, "AUTHZ_A_A_B would set both"},
		{"secret file collision", []Section{NewSection[secretCollide]("a", nil, nil)}, "AUTHZ_A_K_FILE would set both"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSchema(tc.sections...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
	// Two members with one json name; go vet refuses to let a declared
	// struct say so.
	dup := reflect.StructOf([]reflect.StructField{
		{Name: "A", Type: reflect.TypeFor[string](), Tag: `json:"a"`},
		{Name: "B", Type: reflect.TypeFor[string](), Tag: `json:"a"`},
	})
	if err := checkType(dup, "s"); err == nil || !strings.Contains(err.Error(), `two fields are named "a"`) {
		t.Errorf("duplicate json name: %v", err)
	}
	// Unexported and "-" members are not part of the document.
	okSchema, err := NewSchema(NewSection("a", func(o *ok) { o.hidden = 7 }, func(o *ok, c *Checker) {
		if o.hidden != 7 {
			c.Errorf(c.Path, "defaults lost")
		}
	}))
	if err != nil {
		t.Fatalf("unexported and skipped members: %v", err)
	}
	if r := okSchema.Check([]byte(`{"version": 1, "a": {"a": "x"}}`), nil); r.Problems != nil {
		t.Errorf("problems: %v", r.Problems)
	}
	if r := okSchema.Check([]byte(`{"version": 1, "a": {"hidden": 1}}`), nil); len(r.Problems) != 1 || r.Problems[0].Message != `unknown member` {
		t.Errorf("an unexported member was accepted: %v", r.Problems)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("MustSchema did not panic")
			}
		}()
		MustSchema(NewSection[float]("a", nil, nil))
	}()
	if MustSchema(NewSection[ok]("a", nil, nil)) == nil {
		t.Error("MustSchema returned nil")
	}
}

func TestSecretNeverPrinted(t *testing.T) {
	r := testSchema(t).Check([]byte(`{"version": 1, "serve": {"api_keys": {"env": "K"}, "tokens": [{"env": "K"}]}}`), []string{"K=s3cr3t-value"})
	s := Get[serveSection](r.Config, "serve")
	if s.APIKeys.Value() != "s3cr3t-value" {
		t.Fatalf("value = %q", s.APIKeys.Value())
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(f, *s); strings.Contains(out, "s3cr3t") {
			t.Errorf("%s prints the secret: %s", f, out)
		}
	}
	for _, c := range []struct {
		s    Secret
		want string
	}{
		{Secret{File: "/f"}, "secret(file /f)"},
		{Secret{Env: "E"}, "secret(env E)"},
		{Secret{value: "x", direct: true}, "secret(set)"},
		{Secret{}, "secret(unset)"},
	} {
		if got := c.s.String(); got != c.want {
			t.Errorf("String() = %q, want %q", got, c.want)
		}
		if c.s.IsSet() != (c.want != "secret(unset)") {
			t.Errorf("%s: IsSet = %v", c.want, c.s.IsSet())
		}
	}
}

func TestDurationJSON(t *testing.T) {
	d := Duration(90 * time.Second)
	b, err := d.MarshalJSON()
	if err != nil || string(b) != `"1m30s"` {
		t.Fatalf("MarshalJSON = %s, %v", b, err)
	}
	var back Duration
	if err := back.UnmarshalJSON(b); err != nil || back != d {
		t.Errorf("round trip = %v, %v", back, err)
	}
	if err := back.UnmarshalJSON([]byte(`90`)); err == nil {
		t.Error("a number was accepted")
	}
	if err := back.UnmarshalJSON([]byte(`"-1s"`)); err == nil {
		t.Error("a negative duration was accepted")
	}
}

func TestPaths(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"$.a[0].b", "$.a[0]"},
		{"$.a[0]", "$.a"},
		{"$.a", "$"},
		{"$", ""},
		{"", ""},
		{`$.a["x.y[1]"]`, "$.a"},
		{`$["k"]`, "$"},
	} {
		if got := parentPath(c.in); got != c.want {
			t.Errorf("parentPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := KeyPath("$", "a.b"); got != `$["a.b"]` {
		t.Errorf("KeyPath = %q", got)
	}
	if got := IndexPath("$.a", 3); got != "$.a[3]" {
		t.Errorf("IndexPath = %q", got)
	}
}
