package logging

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// Credential-shaped values are built at run time, so no file in the
// repository looks like it holds one.
func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

var (
	testJWT = b64(`{"alg":"ES256","kid":"k1"}`) + "." + b64(`{"sub":"agent:build","exp":1893456000}`) + "." + b64(strings.Repeat("s", 64))
	testJWE = b64(`{"alg":"dir","enc":"A256GCM"}`) + ".." + b64("iv-iv-iv-iv-") + "." + b64(strings.Repeat("c", 40)) + "." + b64("tag-tag-tag-tag-")
	ghKey   = "gh" + "p_" + strings.Repeat("a1B2", 9)
	pemHead = "-----BEGIN " + "EC PRIVATE KEY-----"
)

func rules(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

func TestScanFinds(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		rule string
	}{
		"jws":                  {`{"msg":"verify","raw":"` + testJWT + `"}`, RuleJWT},
		"jwe":                  {"token " + testJWE + " refused", RuleJWT},
		"unsigned jwt":         {b64(`{"alg":"none"}`) + "." + b64(`{"sub":"x"}`) + ".", RuleJWT},
		"pem private key":      {pemHead + "\nMHcCAQEE\n", RulePrivateKey},
		"pkcs8 private key":    {"-----BEGIN " + "PRIVATE KEY-----", RulePrivateKey},
		"openssh private key":  {"-----BEGIN " + "OPENSSH PRIVATE KEY-----", RulePrivateKey},
		"jwk d":                {`{"kty":"EC","crv":"P-256","x":"abc","d":"` + strings.Repeat("Qz", 16) + `"}`, RuleJWKPrivate},
		"jwk oct k":            {`{"kty":"oct","k":"` + strings.Repeat("Qz", 16) + `"}`, RuleJWKPrivate},
		"bearer with digit":    {`"authorization":["Bearer abcdef0123456789"]`, RuleAuthHeader},
		"bearer long":          {"Authorization: bearer " + strings.Repeat("abcd", 6), RuleAuthHeader},
		"basic":                {"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wonderland")), RuleAuthHeader},
		"query password":       {"GET /login?user=alice&password=hunter22 200", RuleCredentialParam},
		"form client secret":   {"grant_type=code&client_secret=s3cr3t-value&code=x", RuleCredentialParam},
		"logfmt access token":  {`level=info access_token=abc.def.ghi`, RuleCredentialParam},
		"json secret key":      {`{"msg":"m","upstream_token":"s3cr3t-value"}`, RuleCredentialField},
		"json nested":          {`{"req":{"Cookie":"session=abc"}}`, RuleCredentialField},
		"json escaped value":   {`{"password":"a\"b\\c"}`, RuleCredentialField},
		"url password":         {"dial postgres://app:s3cr3t@db:5432/x failed", RuleURLPassword},
		"provider key":         {"key " + ghKey, RuleProviderKey},
		"provider key json":    {`{"k":"` + ghKey + `"}`, RuleProviderKey},
		"credential at start":  {"password=hunter22", RuleCredentialParam},
		"secret key in custom": {`{"vendor_api_key":"abcdefgh"}`, RuleCredentialField},
	} {
		t.Run(name, func(t *testing.T) {
			fs := Scan([]byte(tc.in))
			found := false
			for _, f := range fs {
				found = found || f.Rule == tc.rule
			}
			if !found {
				t.Fatalf("Scan(%q) = %v, want %s", tc.in, fs, tc.rule)
			}
		})
	}
}

func TestScanLeavesAlone(t *testing.T) {
	for _, in := range []string{
		`{"time":"2026-11-08T00:00:00Z","level":"INFO","msg":"listening","addr":"127.0.0.1:8080"}`,
		`{"password":"[REDACTED]","token":"","cookie":"***","api_key":"xxxx"}`,
		`{"token_ttl":"5m","key_id":"api_key:0a1b2c3d","kid":"k1","revision":"GhUKEzE3"}`,
		"password=&client_secret=[REDACTED]&access_token=" + url.QueryEscape(Redacted),
		"--- PASS: TestAttacks/bearer_confirmation_with_NotBefore (0.00s)",
		"SAML bearer confirmation required; bearer assertion expired",
		"Authorization: Bearer [REDACTED]",
		"Authorization: Basic notbase64!",
		"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon-here")),
		"eyJub3Rqc29u.payload.sig is not a token: its header is not JSON",
		b64(`{"typ":"x"}`) + "." + b64("p") + ".s has no alg",
		`{"d":"` + strings.Repeat("Qz", 16) + `","note":"no kty"}`,
		"https://example.com:8443/path@v1",
		"https://user:" + Redacted + "@db/x",
		"gh" + "p_short",
		"ok  \tgithub.com/laiwf94/authz/internal/authz/token\t0.012s",
		`{"password":12345678,"token":null,"secret":{"a":1}}`,
		`{"password":"unterminated`,
		`{"password":"split` + "\n" + `line"}`,
		`"password" : x`,
		`: "value"`,
		`{"":"x"}`,
		`{"` + strings.Repeat("k", 70) + `_token":"abcdefgh"}`,
		"a_very_long_name_password=abcdefgh",
		"=abcdefgh",
		"xpassword=abcdefgh",
	} {
		if fs := Scan([]byte(in)); len(fs) != 0 {
			t.Errorf("Scan(%q) = %v, want nothing", in, fs)
		}
	}
}

func TestScanFindingFields(t *testing.T) {
	in := "first line\n{\"msg\":\"m\",\"token\":\"abcdefghijklmnop\"}\nthird " + ghKey
	fs := Scan([]byte(in))
	if got := strings.Join(rules(fs), ","); got != RuleCredentialField+","+RuleProviderKey {
		t.Fatalf("rules %s: %v", got, fs)
	}
	if fs[0].Line != 2 || fs[1].Line != 3 {
		t.Errorf("lines %d %d", fs[0].Line, fs[1].Line)
	}
	if want := strings.Index(in, "abcdefghijklmnop"); fs[0].Offset != want {
		t.Errorf("offset %d, want %d", fs[0].Offset, want)
	}
	if fs[0].Excerpt != "abcd…[16 bytes]" {
		t.Errorf("excerpt %q", fs[0].Excerpt)
	}
	if s := fs[1].String(); s != "line 3: provider_key: ghp_…[40 bytes]" {
		t.Errorf("String %q", s)
	}
	// A short secret shows nothing but its length.
	if fs := Scan([]byte(`{"password":"hunter2"}`)); len(fs) != 1 || fs[0].Excerpt != "[7 bytes]" {
		t.Errorf("short secret: %v", fs)
	}
	// Control characters in the first bytes are not copied out.
	if fs := Scan([]byte(`{"password":"\u0001\u0002abcdefghijkl"}`)); len(fs) != 1 || strings.ContainsAny(fs[0].Excerpt, "\x00\x01\x02") {
		t.Errorf("control characters: %q", fs)
	}
}

// No report ever carries the secret it found.
func TestScanNeverRepeatsSecret(t *testing.T) {
	secret := "zq9-unique-credential-value"
	s := NewScanner()
	if err := s.Known(secret); err != nil {
		t.Fatal(err)
	}
	in := fmt.Sprintf(`{"password":%q} Bearer %s %s password=%s https://u:%s@h`,
		secret, secret, base64.StdEncoding.EncodeToString([]byte(secret)), secret, secret)
	fs := s.Scan([]byte(in))
	if len(fs) < 5 {
		t.Fatalf("findings %v", fs)
	}
	for _, f := range fs {
		if strings.Contains(f.String(), secret[4:]) || strings.Contains(f.String(), "unique") {
			t.Errorf("report carries the secret: %s", f)
		}
	}
}

func TestScanKnown(t *testing.T) {
	secret := "cookie-key\x00\xff/+?&= value"
	s := NewScanner()
	if err := s.Known(secret, secret); err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(secret)
	for enc, form := range map[string]string{
		"raw":          secret,
		"base64":       base64.StdEncoding.EncodeToString([]byte(secret)),
		"base64 nopad": base64.RawStdEncoding.EncodeToString([]byte(secret)),
		"base64url":    base64.URLEncoding.EncodeToString([]byte(secret)),
		"hex":          hex.EncodeToString([]byte(secret)),
		"HEX":          strings.ToUpper(hex.EncodeToString([]byte(secret))),
		"query":        url.QueryEscape(secret),
		"path":         url.PathEscape(secret),
		"json":         string(j[1 : len(j)-1]),
	} {
		fs := s.Scan([]byte("x " + form + " y"))
		if len(fs) != 1 || fs[0].Rule != RuleKnown || fs[0].Offset != 2 {
			t.Errorf("%s: %v", enc, fs)
		}
		if strings.Contains(fs[0].Excerpt, form[:4]) {
			t.Errorf("%s: a known value's excerpt shows its bytes: %q", enc, fs[0].Excerpt)
		}
	}
	// Every occurrence is reported.
	if fs := s.Scan([]byte(secret + secret + "/" + secret)); len(fs) != 3 {
		t.Errorf("repeated: %v", fs)
	}
	if err := s.Known("short", "long enough value"); err == nil {
		t.Error("a 5-byte known value accepted")
	}
	if fs := s.Scan([]byte("long enough value")); len(fs) != 0 {
		t.Errorf("a failed Known registered values: %v", fs)
	}
	// Other scanners do not see it.
	if fs := Scan([]byte(secret)); len(fs) != 0 {
		t.Errorf("default scanner: %v", fs)
	}
}

func TestScanAllow(t *testing.T) {
	s := NewScanner()
	in := []byte(`{"password":"hunter22"} ` + testJWT)
	if got := rules(s.Scan(in)); len(got) != 2 {
		t.Fatalf("before Allow: %v", got)
	}
	if err := s.Allow(RuleJWT); err != nil {
		t.Fatal(err)
	}
	if got := rules(s.Scan(in)); len(got) != 1 || got[0] != RuleCredentialField {
		t.Errorf("after Allow: %v", got)
	}
	if err := s.Allow("nope", RuleCredentialField); err == nil {
		t.Error("unknown rule accepted")
	}
	if got := rules(s.Scan(in)); len(got) != 1 {
		t.Errorf("a failed Allow turned rules off: %v", got)
	}
	_ = s.Known("hunter22-hunter22")
	_ = s.Allow(RuleKnown)
	if fs := s.Scan([]byte("hunter22-hunter22")); len(fs) != 0 {
		t.Errorf("known allowed: %v", fs)
	}
	for _, r := range Rules() {
		if err := NewScanner().Allow(r); err != nil {
			t.Errorf("Allow(%s): %v", r, err)
		}
	}
}

func TestScannerSecretKeys(t *testing.T) {
	in := []byte(`{"vault_lease":"abcdefgh"}`)
	if fs := Scan(in); len(fs) != 0 {
		t.Fatalf("default: %v", fs)
	}
	if fs := NewScanner("Vault-Lease").Scan(in); len(fs) != 1 {
		t.Errorf("custom key: %v", fs)
	}
}

// What the Handler redacts, the scanner finds in a plain JSON handler's
// output, and nothing in the Handler's: the two agree on what a secret is.
func TestScanAgreesWithRedaction(t *testing.T) {
	type creds struct {
		User string `json:"user"`
		Pass string `json:"pass" log:"secret"`
	}
	args := []any{
		"password", "hunter22", "upstream_token", "abcdefghijk", "Set-Cookie", "sid=abc",
		"key", Secret("a-secret-value"), "creds", creds{"alice", "pw-in-a-struct"},
		slog.Group("req", "authorization", "Bearer abcdef0123456789"),
	}
	s := NewScanner()
	if err := s.Known("a-secret-value", "pw-in-a-struct"); err != nil {
		t.Fatal(err)
	}
	var plainOut, ours bytes.Buffer
	slog.New(slog.NewJSONHandler(&plainOut, nil)).Info("m", args...)
	NewLogger(&ours, Options{}).Info("m", args...)
	if fs := s.Scan(plainOut.Bytes()); len(fs) < 5 {
		t.Errorf("plain handler output: %v\n%s", fs, plainOut.String())
	}
	if fs := s.Scan(ours.Bytes()); len(fs) != 0 {
		t.Errorf("Handler output: %v\n%s", fs, ours.String())
	}
}

func TestWatch(t *testing.T) {
	before := watcherCount()
	var mu sync.Mutex
	var got []string
	remove := Watch(func(source string, p []byte) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, source+" "+string(p))
	})
	if n := watcherCount(); n != before+1 {
		t.Errorf("%d watchers registered, want %d", n, before+1)
	}
	var buf bytes.Buffer
	log := NewLogger(&buf, Options{Subcommand: "mcp"})
	log.Info("one", "password", "hunter22")
	Observe(SourceAudit, []byte("rec"))
	second := 0
	remove2 := Watch(func(string, []byte) { second++ })
	log.Info("two")
	remove()
	remove() // a second call does nothing
	log.Info("three")
	remove2()
	log.Info("four")
	if len(got) != 3 || got[0] != SourceLog+" "+strings.Split(buf.String(), "\n")[0]+"\n" ||
		got[1] != "audit rec" || !strings.Contains(got[2], `"msg":"two"`) {
		t.Errorf("watched %q", got)
	}
	if strings.Contains(got[0], "hunter22") {
		t.Error("a watcher saw an unredacted record")
	}
	if second != 2 {
		t.Errorf("second watcher saw %d records, want 2", second)
	}
	if n := watcherCount(); n != before {
		t.Errorf("%d watchers registered, want %d", n, before)
	}
}

// watcherCount is 0 in a normal build and 1 in the secretscan build.
func watcherCount() int {
	if ws := watchers.Load(); ws != nil {
		return len(*ws)
	}
	return 0
}

type shortWriter struct{ n int }

func (s *shortWriter) Write(p []byte) (int, error) { return s.n, fmt.Errorf("short") }

func TestWatchSeesOnlyWrittenBytes(t *testing.T) {
	var seen [][]byte
	defer Watch(func(_ string, p []byte) { seen = append(seen, append([]byte(nil), p...)) })()
	NewLogger(&shortWriter{n: 5}, Options{}).Info("m")
	NewLogger(&shortWriter{n: 0}, Options{}).Info("m")
	if len(seen) != 1 || string(seen[0]) != `{"tim` {
		t.Errorf("seen %q", seen)
	}
}

func TestWatchConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				rm := Watch(func(string, []byte) { mu.Lock(); n++; mu.Unlock() })
				Observe(SourceLog, []byte("x"))
				rm()
			}
		}()
	}
	wg.Wait()
	if n < 800 {
		t.Errorf("observed %d, want at least 800", n)
	}
}

// Scan never panics, and every finding lies inside its input and never
// repeats more than the four bytes an excerpt may show.
func FuzzScan(f *testing.F) {
	for _, s := range []string{
		`{"password":"hunter22","a":"b"}`, testJWT, testJWE, "Bearer abcdef0123456789",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("a:b")), "x://u:p@h", "password=x&secret=y",
		`{"kty":"oct","k":"` + strings.Repeat("Q", 20) + `"}`, pemHead, ghKey, `{"k\"ey":"v\\"}`, "",
	} {
		f.Add([]byte(s))
	}
	s := NewScanner()
	if err := s.Known("known-secret-value"); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, fd := range s.Scan(b) {
			if fd.Offset < 0 || fd.Offset > len(b) || fd.Line < 1 || fd.Line > bytes.Count(b, []byte("\n"))+1 {
				t.Fatalf("finding out of range: %+v in %d bytes", fd, len(b))
			}
			if !validRule(fd.Rule) {
				t.Fatalf("unknown rule %q", fd.Rule)
			}
			if fd.Rule == RuleKnown && strings.Contains(fd.Excerpt, "know") {
				t.Fatalf("known value shown: %q", fd.Excerpt)
			}
		}
	})
}

func BenchmarkObserveNoWatcher(b *testing.B) {
	p := []byte(`{"msg":"m"}`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Observe(SourceLog, p)
	}
}

func BenchmarkScanRecord(b *testing.B) {
	p := []byte(`{"time":"2026-11-08T10:00:00.123Z","level":"INFO","msg":"request","method":"POST","path":"/v1/check","status":200,"duration":0.0012,"request_id":"4bf92f3577b34da6a3ce929d0e0e4736","key_id":"api_key:0a1b2c3d"}` + "\n")
	b.ReportAllocs()
	b.SetBytes(int64(len(p)))
	for i := 0; i < b.N; i++ {
		Scan(p)
	}
}
