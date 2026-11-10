package gateway

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/check"
	"github.com/laiwf94/authz/internal/authn/config"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
)

// wicketDoc is a wicket file that "authz gateway check" passes.
const wicketDoc = `"public_url": "https://auth.example.com",
    "session": {"idle_timeout": "1h", "absolute_timeout": "8h"},
    "clock_skew": "1m",
    "redirect_hosts": ["docs.example.com"],
    "upstream_token_ttl": "1m",
    "providers": [{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com",
      "client_id": "c", "client_secret_env": "CORP_SECRET", "scopes": ["openid", "email"]}],
    "apps": [{"id": "app", "hosts": ["app.example.com"], "providers": ["corp"],
      "allow": {"groups": ["eng"]}, "default_url": "https://app.example.com/home"}]`

func gatewaySchema(t *testing.T, o check.Options) *pcfg.Schema {
	t.Helper()
	sc, err := pcfg.NewSchema(Section(SectionOptions{Check: o}))
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

// TestSectionHoldsWicketFile keeps the section in step with wicket's file:
// every member of config.Config, at every level, is a member of Settings
// with the same JSON name and the same type, apart from the durations,
// which are the platform's.
func TestSectionHoldsWicketFile(t *testing.T) {
	members := func(t reflect.Type) map[string]reflect.Type {
		out := map[string]reflect.Type{}
		for i := range t.NumField() {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
			if name != "" && name != "-" {
				out[name] = t.Field(i).Type
			}
		}
		return out
	}
	ours := members(reflect.TypeFor[Settings]())
	durations := map[reflect.Type]reflect.Type{reflect.TypeFor[config.Duration](): reflect.TypeFor[pcfg.Duration]()}
	for name, typ := range members(reflect.TypeFor[config.Config]()) {
		got, ok := ours[name]
		switch {
		case !ok:
			t.Errorf("wicket's %q is not in the gateway section", name)
		case name == "session":
			sm := members(got)
			for n, st := range members(typ) {
				if sm[n] != durations[st] {
					t.Errorf("session.%s: %v, want %v", n, sm[n], durations[st])
				}
			}
			if len(sm) != len(members(typ)) {
				t.Errorf("session members %v, want those of %v", sm, typ)
			}
		case durations[typ] != nil:
			if got != durations[typ] {
				t.Errorf("%s: %v, want %v", name, got, durations[typ])
			}
		case got != typ:
			t.Errorf("%s: %v, want %v", name, got, typ)
		}
	}
	// The section's other members are the WICKET_ variables.
	if n := len(ours) - len(members(reflect.TypeFor[config.Config]())); n != 17 {
		t.Errorf("%d members besides wicket's file, want the 17 WICKET_ settings", n)
	}
}

func TestSectionGood(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "signing.pem")
	var pemOut bytes.Buffer
	if err := subcommand("gensigningkey", &pemOut); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(keyFile, pemOut.Bytes(), 0o600)
	os.WriteFile(filepath.Join(dir, "cookie-keys"), []byte(cookieKey+"\n"), 0o600)
	keyJSON, _ := json.Marshal(keyFile)
	cookieJSON, _ := json.Marshal(filepath.Join(dir, "cookie-keys"))
	doc := `{"version": 1, "gateway": {
    "addr": ":8443", "admin_addr": "0.0.0.0:9443", "admin_token": {"env": "ADMIN"},
    "cookie_keys": {"file": ` + string(cookieJSON) + `},
    "signing_keys": [` + string(keyJSON) + `], "trusted_proxies": ["10.0.0.0/8"],
    "login_rate": 60, "log_level": "debug", "session_file": "/var/lib/sessions", "audit_log": "/var/log/audit",
    ` + wicketDoc + `}}`
	getenv := env(map[string]string{"CORP_SECRET": "s"})
	r := gatewaySchema(t, check.Options{Getenv: getenv}).Check([]byte(doc), []string{"ADMIN=admin-token-0123456789"})
	if len(r.Problems) != 0 {
		t.Fatalf("problems: %v", r.Problems)
	}
	s := pcfg.Get[Settings](r.Config, SectionName)
	if s.Addr != ":8443" || s.AdminToken.Value() != "admin-token-0123456789" || s.CookieKeys.Value() != cookieKey ||
		s.LoginRate != 60 || len(s.Providers) != 1 || s.Providers[0].Scopes[1] != "email" {
		t.Fatalf("settings: %+v", s)
	}

	// The section's wicket members make the same configuration as the
	// same members in a wicket file.
	fromSection, err := config.Parse(s.File(), getenv)
	if err != nil {
		t.Fatal(err)
	}
	fromFile, err := config.Parse([]byte("{"+wicketDoc+"}"), getenv)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromSection, fromFile) {
		t.Fatalf("section:\n%+v\nfile:\n%+v", fromSection, fromFile)
	}
}

func TestSectionDefaults(t *testing.T) {
	doc := `{"version": 1, "gateway": {"cookie_keys": {"env": "CK"}, ` + wicketDoc + `}}`
	r := gatewaySchema(t, check.Options{Getenv: env(map[string]string{"CORP_SECRET": "s"})}).
		Check([]byte(doc), []string{"CK=" + cookieKey})
	if len(r.Problems) != 0 {
		t.Fatalf("problems: %v", r.Problems)
	}
	s := pcfg.Get[Settings](r.Config, SectionName)
	want, _ := loadSettings(env(map[string]string{"WICKET_CONFIG": "c", "WICKET_COOKIE_KEYS": cookieKey}))
	if s.Addr != want.addr || s.AdminAddr != want.adminAddr || s.LogLevel != "info" || s.LoginRate != 30 ||
		len(s.TrustedProxies) != len(want.trusted) || s.TrustedProxies[0] != want.trusted[0].String() {
		t.Fatalf("defaults %+v differ from wicket's %+v", s, want)
	}
}

func TestSectionProblems(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not.pem")
	os.WriteFile(notPEM, []byte("not a key"), 0o600)
	pemJSON, _ := json.Marshal(notPEM)
	doc := `{"version": 1, "gateway": {
  "addr": "nope",
  "admin_addr": "0.0.0.0:4181",
  "cookie_keys": {"env": "CK"},
  "signing_keys": [` + string(pemJSON) + `, "/does/not/exist.pem"],
  "trusted_proxies": ["10.0.0.0/8", "everyone"],
  "login_rate": 0,
  "log_level": "loud",
  "public_url": "http://auth.example.com",
  "session": {"idle_timeout": "10s"},
  "providers": [{"id": "Corp", "type": "ldap"}],
  "apps": [{"id": "app", "hosts": ["app.example.com"], "providers": ["corp"], "allow": {"any_user": true}}]
}}`
	r := gatewaySchema(t, check.Options{}).Check([]byte(doc), []string{"CK=00,zz"})
	type want struct {
		line int
		path string
		msg  string
	}
	wants := []want{
		{2, "$.gateway.addr", "missing port in address"},
		{3, "$.gateway.admin_addr", `"0.0.0.0:4181" is not a loopback address; set admin_token`},
		{5, "$.gateway.signing_keys[0]", "no PEM block"},
		{5, "$.gateway.signing_keys[1]", "no such file"},
		{6, "$.gateway.trusted_proxies[1]", `"everyone" is not a CIDR`},
		{7, "$.gateway.login_rate", "must be 1-100000"},
		{8, "$.gateway.log_level", `"loud" is not debug, info, warn or error`},
		{9, "$.gateway.public_url", "must be an absolute https URL"},
		{10, "$.gateway.session.idle_timeout", "must be at least 1m"},
		{11, "$.gateway.providers[0].id", `provider id "Corp"`},
		{11, "$.gateway.providers[0].type", `must be "oidc" or "saml"`},
		{12, "$.gateway.apps[0].providers[0]", "corp"},
		{4, "$.gateway.cookie_keys", "entry 1 is not 64 hex characters"},
		{4, "$.gateway.cookie_keys", "entry 2 is not 64 hex characters"},
	}
	errs := r.Problems.Count(pcfg.SeverityError)
	for _, w := range wants {
		found := false
		for _, p := range r.Problems {
			if p.Path == w.path && p.Line == w.line && strings.Contains(p.Message, w.msg) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing %+v", w)
		}
	}
	if errs != len(wants) {
		t.Errorf("%d errors, want %d:\n%v", errs, len(wants), r.Problems)
	}
	for _, p := range r.Problems {
		if p.Line == 0 && p.Env == "" {
			t.Errorf("problem without a place: %+v", p)
		}
	}
}

func TestSectionSecrets(t *testing.T) {
	sc := gatewaySchema(t, check.Options{Getenv: env(map[string]string{"CORP_SECRET": "s"})})
	doc := []byte(`{"version": 1, "gateway": {` + wicketDoc + `}}`)
	cases := map[string]struct {
		environ []string
		path    string
		msg     string
	}{
		"no cookie keys":  {nil, "$.gateway.cookie_keys", "is required (run: authz gateway genkey)"},
		"only commas":     {[]string{"AUTHZ_GATEWAY_COOKIE_KEYS=,,"}, "$.gateway.cookie_keys", "holds no key"},
		"blank override":  {[]string{"AUTHZ_GATEWAY_COOKIE_KEYS= "}, "$.gateway.cookie_keys", "holds no key"},
		"short token":     {[]string{"AUTHZ_GATEWAY_COOKIE_KEYS=" + cookieKey, "AUTHZ_GATEWAY_ADMIN_TOKEN=short"}, "$.gateway.admin_token", "at least 16"},
		"blank token":     {[]string{"AUTHZ_GATEWAY_COOKIE_KEYS=" + cookieKey, "AUTHZ_GATEWAY_ADMIN_TOKEN= "}, "$.gateway.admin_token", "at least 16"},
		"env idle":        {[]string{"AUTHZ_GATEWAY_COOKIE_KEYS=" + cookieKey, "AUTHZ_GATEWAY_SESSION_IDLE_TIMEOUT=9h"}, "$.gateway.session.idle_timeout", "must not be longer than absolute_timeout"},
		"env login rate":  {[]string{"AUTHZ_GATEWAY_COOKIE_KEYS=" + cookieKey, "AUTHZ_GATEWAY_LOGIN_RATE=200000"}, "$.gateway.login_rate", "must be 1-100000"},
		"env proxy list":  {[]string{"AUTHZ_GATEWAY_COOKIE_KEYS=" + cookieKey, "AUTHZ_GATEWAY_TRUSTED_PROXIES=10.0.0.0/8, nope"}, "$.gateway.trusted_proxies[1]", `"nope" is not a CIDR`},
		"env admin addr":  {[]string{"AUTHZ_GATEWAY_COOKIE_KEYS=" + cookieKey, "AUTHZ_GATEWAY_ADMIN_ADDR=localhost"}, "$.gateway.admin_addr", "missing port"},
		"env public addr": {[]string{"AUTHZ_GATEWAY_COOKIE_KEYS=" + cookieKey, "AUTHZ_GATEWAY_ADDR=localhost"}, "$.gateway.addr", "missing port"},
	}
	for name, c := range cases {
		r := sc.Check(doc, c.environ)
		errs := r.Problems.Count(pcfg.SeverityError)
		if errs != 1 {
			t.Errorf("%s: %d errors, want 1: %v", name, errs, r.Problems)
			continue
		}
		for _, p := range r.Problems {
			if p.Severity == pcfg.SeverityError && (p.Path != c.path || !strings.Contains(p.Message, c.msg)) {
				t.Errorf("%s: %+v, want %s: %s", name, p, c.path, c.msg)
			}
		}
	}
	// A loopback admin address needs no token; "localhost" counts.
	r := sc.Check(doc, []string{"AUTHZ_GATEWAY_COOKIE_KEYS=" + cookieKey, "AUTHZ_GATEWAY_ADMIN_ADDR=localhost:4181"})
	if len(r.Problems) != 0 {
		t.Fatal(r.Problems)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestSectionOnline runs wicket's online checks and reports what they find
// under the section.
func TestSectionOnline(t *testing.T) {
	var asked []string
	client := func(*config.Provider, *x509.CertPool) *http.Client {
		return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			asked = append(asked, r.URL.String())
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")),
				Header: http.Header{}, Request: r}, nil
		})}
	}
	doc := []byte(`{"version": 1, "gateway": {"cookie_keys": {"env": "CK"},
    ` + wicketDoc + `}}`)
	o := check.Options{Getenv: env(map[string]string{"CORP_SECRET": "s"}), Online: true, Timeout: time.Second, Client: client}
	r := gatewaySchema(t, o).Check(doc, []string{"CK=" + cookieKey})
	if len(r.Problems) != 1 || r.Problems[0].Path != "$.gateway.providers[0].issuer" || r.Problems[0].Line != 7 {
		t.Fatalf("problems: %v", r.Problems)
	}
	if len(asked) == 0 || !strings.HasPrefix(asked[0], "https://idp.example.com/.well-known/openid-configuration") {
		t.Fatalf("asked %v", asked)
	}

	// Offline, nothing is fetched.
	asked = nil
	o.Online = false
	if r := gatewaySchema(t, o).Check(doc, []string{"CK=" + cookieKey}); len(r.Problems) != 0 || len(asked) != 0 {
		t.Fatalf("offline: %v, asked %v", r.Problems, asked)
	}

	// A cancelled context stops the online checks.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o.Online = true
	sc, _ := pcfg.NewSchema(Section(SectionOptions{Check: o, Context: ctx}))
	if r := sc.Check(doc, []string{"CK=" + cookieKey}); r.Problems.Count(pcfg.SeverityError) != 1 {
		t.Fatalf("cancelled: %v", r.Problems)
	}
}

// TestSectionWarnings: wicket's warnings stay warnings.
func TestSectionWarnings(t *testing.T) {
	doc := []byte(`{"version": 1, "gateway": {"cookie_keys": {"env": "CK"},
    "public_url": "https://auth.example.com",
    "providers": [{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "S"},
                  {"id": "spare", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "S"}],
    "apps": [{"id": "app", "hosts": ["app.example.com"], "providers": ["corp"], "allow": {"any_user": true}}]}}`)
	r := gatewaySchema(t, check.Options{Getenv: env(map[string]string{"S": "s"})}).Check(doc, []string{"CK=" + cookieKey})
	if r.Problems.Err() != nil || len(r.Problems) != 1 || r.Problems[0].Severity != pcfg.SeverityWarning ||
		r.Problems[0].Path != "$.gateway.providers[1]" || r.Problems[0].Line != 4 {
		t.Fatalf("problems: %v", r.Problems)
	}
}
