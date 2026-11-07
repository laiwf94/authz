package serve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	pcfg "github.com/laiwf94/authz/internal/platform/config"
)

const (
	sectionKey = "section-test-key-0123456"
	hexKeyA    = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	hexKeyB    = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
)

func serveSchema(t *testing.T) *pcfg.Schema {
	t.Helper()
	sc, err := pcfg.NewSchema(Section())
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func TestSectionGood(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "api-keys")
	os.WriteFile(keys, []byte(sectionKey+","+sectionKey+"-2\n"), 0o600)
	doc := `{"version": 1, "serve": {"addr": "127.0.0.1:9000", "data_dir": "` + dir + `/data",
  "api_keys": {"file": "` + keys + `"}, "token_key": {"env": "TK"},
  "cache_size": 0, "retention": 5, "log_level": "warn", "audit_log": "` + dir + `/audit"}}`
	r := serveSchema(t).Check([]byte(doc), []string{"TK=" + hexKeyB + "," + hexKeyA})
	if len(r.Problems) != 0 {
		t.Fatal(r.Problems)
	}
	s := pcfg.Get[Settings](r.Config, SectionName)
	if s.Addr != "127.0.0.1:9000" || s.CacheSize != 0 || s.Retention != 5 || s.LogLevel != "warn" ||
		s.APIKeys.Value() != sectionKey+","+sectionKey+"-2" {
		t.Fatalf("%+v", s)
	}
	ks, err := tokenKeys(s.TokenKey.Value())
	if err != nil || len(ks) != 2 {
		t.Fatal(ks, err)
	}
}

// TestSectionDefaults: an empty section, given its keys by the environment,
// starts as an unconfigured grantd would.
func TestSectionDefaults(t *testing.T) {
	r := serveSchema(t).Check([]byte(`{"version": 1}`), []string{"AUTHZ_SERVE_API_KEYS=" + sectionKey})
	if len(r.Problems) != 0 {
		t.Fatal(r.Problems)
	}
	s := pcfg.Get[Settings](r.Config, SectionName)
	want, err := loadConfig(func(k string) string { return map[string]string{"GRANTD_API_KEYS": sectionKey}[k] })
	if err != nil {
		t.Fatal(err)
	}
	if s.Addr != want.addr || s.CacheSize != want.cacheSize || s.Retention != int64(want.retention) ||
		!strings.EqualFold(s.LogLevel, want.logLevel.String()) || s.DataDir != "" || s.AuditLog != "" {
		t.Fatalf("defaults %+v differ from grantd's %+v", s, want)
	}
}

func TestSectionProblems(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o600)
	cases := map[string]struct {
		doc     string
		environ []string
		path    string
		msg     string
	}{
		"no api keys":    {`{}`, nil, "$.serve.api_keys", "is required"},
		"short key":      {`{"api_keys": {"env": "K"}}`, []string{"K=" + sectionKey + ",short"}, "$.serve.api_keys", "key 2 is 5 characters; each key must be at least 16"},
		"only commas":    {`{}`, []string{"AUTHZ_SERVE_API_KEYS=,,"}, "$.serve.api_keys", "holds no key"},
		"blank override": {`{}`, []string{"AUTHZ_SERVE_API_KEYS= "}, "$.serve.api_keys", "holds no key"},
		"bad addr":       {`{"addr": "localhost", "api_keys": {"env": "K"}}`, []string{"K=" + sectionKey}, "$.serve.addr", "missing port"},
		"data dir file":  {`{"data_dir": "` + file + `", "api_keys": {"env": "K"}, "token_key": {"env": "T"}}`, []string{"K=" + sectionKey, "T=" + hexKeyA}, "$.serve.data_dir", "exists and is not a directory"},
		"data dir stat":  {`{"data_dir": "` + file + `/sub", "api_keys": {"env": "K"}, "token_key": {"env": "T"}}`, []string{"K=" + sectionKey, "T=" + hexKeyA}, "$.serve.data_dir", "not a directory"},
		"token required": {`{"data_dir": "/var/lib/authz", "api_keys": {"env": "K"}}`, []string{"K=" + sectionKey}, "$.serve.token_key", "is required with data_dir"},
		"bad token":      {`{"api_keys": {"env": "K"}, "token_key": {"env": "T"}}`, []string{"K=" + sectionKey, "T=" + hexKeyA + ",abc"}, "$.serve.token_key", "entry 2 is not 64 hex characters"},
		"repeated token": {`{"api_keys": {"env": "K"}}`, []string{"K=" + sectionKey, "AUTHZ_SERVE_TOKEN_KEY=" + hexKeyA + "," + hexKeyA}, "$.serve.token_key", "entry 2 repeats an earlier key"},
		"blank token":    {`{"api_keys": {"env": "K"}}`, []string{"K=" + sectionKey, "AUTHZ_SERVE_TOKEN_KEY= "}, "$.serve.token_key", "entry 1 is not 64 hex characters"},
		"cache size":     {`{"api_keys": {"env": "K"}, "cache_size": -1}`, []string{"K=" + sectionKey}, "$.serve.cache_size", "must not be negative"},
		"retention":      {`{"api_keys": {"env": "K"}, "retention": 0}`, []string{"K=" + sectionKey}, "$.serve.retention", "must be at least 1"},
		"log level":      {`{"api_keys": {"env": "K"}}`, []string{"K=" + sectionKey, "AUTHZ_SERVE_LOG_LEVEL=loud"}, "$.serve.log_level", `"loud" is not debug, info, warn or error`},
	}
	for name, c := range cases {
		r := serveSchema(t).Check([]byte(`{"version": 1, "serve": `+c.doc+`}`), c.environ)
		if len(r.Problems) != 1 || r.Problems[0].Path != c.path || !strings.Contains(r.Problems[0].Message, c.msg) {
			t.Errorf("%s: %v, want %s: %s", name, r.Problems, c.path, c.msg)
		}
	}

	// Every problem at once, each at its line.
	doc := `{"version": 1, "serve": {
  "addr": "nope",
  "api_keys": {"env": "K"},
  "cache_size": -5,
  "retention": -1,
  "log_level": "chatty"
}}`
	r := serveSchema(t).Check([]byte(doc), []string{"K=a,b"})
	lines := map[string]int{}
	for _, p := range r.Problems {
		lines[p.Path+": "+p.Message] = p.Line
	}
	for msg, line := range map[string]int{
		"$.serve.addr: address nope: missing port in address":                   2,
		"$.serve.api_keys: key 1 is 1 characters; each key must be at least 16": 3,
		"$.serve.api_keys: key 2 is 1 characters; each key must be at least 16": 3,
		"$.serve.cache_size: must not be negative (0 disables the cache)":       4,
		"$.serve.retention: must be at least 1":                                 5,
		`$.serve.log_level: "chatty" is not debug, info, warn or error`:         6,
	} {
		if got, ok := lines[msg]; !ok || got != line {
			t.Errorf("%q at line %d, want %d", msg, got, line)
		}
	}
	if len(r.Problems) != 6 {
		t.Errorf("%d problems: %v", len(r.Problems), r.Problems)
	}
}
