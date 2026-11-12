package logging

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ScanMarker starts every line the secretscan build writes about a finding
// (see secretscan.go), so scripts/secret-scan.go can tell them from test
// output.
const ScanMarker = "SECRET-SCAN:"

// Scan rule names, as Finding.Rule reports them and Allow takes them.
const (
	RuleJWT             = "jwt"              // a compact JWS or JWE
	RulePrivateKey      = "private_key"      // a PEM private key block
	RuleJWKPrivate      = "jwk_private"      // a JWK's private "d" member
	RuleAuthHeader      = "auth_header"      // Bearer or Basic credentials
	RuleCredentialParam = "credential_param" // password=..., access_token=... in a query, form or logfmt line
	RuleCredentialField = "credential_field" // a JSON member whose key names a secret
	RuleURLPassword     = "url_password"     // scheme://user:password@host
	RuleProviderKey     = "provider_key"     // a well-known provider key format
	RuleKnown           = "known"            // a value registered with Known, in any of its encodings
)

// Finding is one secret a Scanner found. It never holds the secret itself:
// Excerpt shows its first characters and its length.
type Finding struct {
	Rule    string
	Line    int // 1-based line of the scanned bytes
	Offset  int // byte offset of the match in the scanned bytes
	Excerpt string
}

func (f Finding) String() string {
	return fmt.Sprintf("line %d: %s: %s", f.Line, f.Rule, f.Excerpt)
}

// Scanner finds keys, tokens and passwords in log and audit output: the
// patterns credentials have in the wild and values registered with Known.
// It is safe for concurrent use. The zero value is not usable; call
// NewScanner.
type Scanner struct {
	mu    sync.RWMutex
	known []knownForm
	allow map[string]bool
	red   *redactor
}

type knownForm struct {
	form []byte
	enc  string // "raw", "base64", "hex", ...
}

// MinKnownBytes is the shortest value Known accepts: anything shorter
// would match ordinary text.
const MinKnownBytes = 8

// NewScanner returns a Scanner with every rule on and no known values. Keys
// in secretKeys count as secret for RuleCredentialField in addition to
// DefaultSecretKeys, as Options.SecretKeys does for a Handler.
func NewScanner(secretKeys ...string) *Scanner {
	return &Scanner{allow: map[string]bool{}, red: newRedactor(secretKeys)}
}

// Scan reports the secrets in b found by a NewScanner().
func Scan(b []byte) []Finding { return defaultScanner.Scan(b) }

var defaultScanner = NewScanner()

// Known registers values that must never appear, such as the keys and
// passwords a test configures. Each is also looked for base64 (standard and
// URL alphabets, padded or not), hex, URL-query and JSON-string encoded. It
// returns an error, and registers none of them, if one is shorter than
// MinKnownBytes.
func (s *Scanner) Known(values ...string) error {
	var add []knownForm
	for _, v := range values {
		if len(v) < MinKnownBytes {
			return fmt.Errorf("logging: a known secret must be at least %d bytes, got %d", MinKnownBytes, len(v))
		}
		add = append(add, encodings(v)...)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range add {
		dup := false
		for _, o := range s.known {
			if bytes.Equal(o.form, k.form) {
				dup = true
				break
			}
		}
		if !dup {
			s.known = append(s.known, k)
		}
	}
	sort.SliceStable(s.known, func(i, j int) bool { return len(s.known[i].form) > len(s.known[j].form) })
	return nil
}

func encodings(v string) []knownForm {
	b := []byte(v)
	forms := []knownForm{
		{[]byte(v), "raw"},
		{[]byte(base64.StdEncoding.EncodeToString(b)), "base64"},
		{[]byte(base64.RawStdEncoding.EncodeToString(b)), "base64"},
		{[]byte(base64.URLEncoding.EncodeToString(b)), "base64url"},
		{[]byte(base64.RawURLEncoding.EncodeToString(b)), "base64url"},
		{[]byte(hex.EncodeToString(b)), "hex"},
		{[]byte(strings.ToUpper(hex.EncodeToString(b))), "hex"},
		{[]byte(url.QueryEscape(v)), "query"},
		{[]byte(url.PathEscape(v)), "path"},
	}
	if j, err := json.Marshal(v); err == nil {
		forms = append(forms, knownForm{j[1 : len(j)-1], "json"})
	}
	out := forms[:0]
	seen := map[string]bool{}
	for _, f := range forms {
		if !seen[string(f.form)] {
			seen[string(f.form)] = true
			out = append(out, f)
		}
	}
	return out
}

// Allow turns rules off, for output whose job is to carry such a value (a
// test of the scanner, a fixture). Unknown names are an error.
func (s *Scanner) Allow(rules ...string) error {
	for _, r := range rules {
		if !validRule(r) {
			return fmt.Errorf("logging: unknown scan rule %q", r)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range rules {
		s.allow[r] = true
	}
	return nil
}

// Rules lists every rule name.
func Rules() []string {
	return []string{RuleJWT, RulePrivateKey, RuleJWKPrivate, RuleAuthHeader, RuleCredentialParam,
		RuleCredentialField, RuleURLPassword, RuleProviderKey, RuleKnown}
}

func validRule(r string) bool {
	for _, x := range Rules() {
		if x == r {
			return true
		}
	}
	return false
}

// A pattern finds candidates, with re or with find when a regular
// expression would be slow, after hint (when set) says b can hold one;
// check, when set, confirms a candidate from its submatch indexes and
// returns the span to report as the secret.
type pattern struct {
	rule  string
	re    *regexp.Regexp
	find  func(b []byte) [][]int
	hint  func(b []byte) bool
	check func(b []byte, m []int, s *Scanner) (start, end int, ok bool)
}

func (p *pattern) matches(b []byte) [][]int {
	if p.hint != nil && !p.hint(b) {
		return nil
	}
	if p.find != nil {
		return p.find(b)
	}
	return p.re.FindAllSubmatchIndex(b, -1)
}

func contains(subs ...string) func([]byte) bool {
	return func(b []byte) bool {
		for _, s := range subs {
			if bytes.Contains(b, []byte(s)) {
				return true
			}
		}
		return false
	}
}

func containsFold(words ...string) func([]byte) bool {
	return func(b []byte) bool {
		for _, w := range words {
			if indexFold(b, w) >= 0 {
				return true
			}
		}
		return false
	}
}

// indexFold is bytes.Index ignoring ASCII case; w is lower case.
func indexFold(b []byte, w string) int {
	for i := 0; i+len(w) <= len(b); i++ {
		j := 0
		for ; j < len(w); j++ {
			c := b[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != w[j] {
				break
			}
		}
		if j == len(w) {
			return i
		}
	}
	return -1
}

var patterns = []pattern{
	{rule: RuleJWT, re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)?`),
		hint: contains("eyJ"), check: checkJWT},
	// A PEM private key, or a signed-note signing key (the audit log's
	// AUTHZ_AUDIT_SIGNING_KEY): PRIVATE+KEY+<name>+<hash>+<key>.
	{rule: RulePrivateKey, re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----|PRIVATE\+KEY\+[^\s+]+\+[0-9a-f]{8}\+[A-Za-z0-9+/]{40,}=*`),
		hint: contains("PRIVATE KEY", "PRIVATE+KEY+")},
	{rule: RuleJWKPrivate, re: regexp.MustCompile(`"(?:d|p|q|dp|dq|qi|k)"\s*:\s*"([A-Za-z0-9_-]{16,})"`),
		hint: contains(`"kty"`), check: checkJWK},
	{rule: RuleAuthHeader, re: regexp.MustCompile(`(?i)\b(bearer|basic)[ \t]+([A-Za-z0-9._~+/-]+=*)`),
		hint: containsFold("bearer", "basic"), check: checkAuthHeader},
	{rule: RuleCredentialParam, find: findParams, hint: contains("="), check: checkValue(4)},
	{rule: RuleCredentialField, find: findMembers, hint: contains(`"`), check: checkField},
	{rule: RuleURLPassword, re: regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@"'<>]+:([^\s/@"'<>]+)@`),
		hint: contains("://"), check: checkValue(2)},
	{rule: RuleProviderKey, re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35})`),
		hint: contains("gh", "sk-", "sk_live_", "xox", "AIza")},
}

// credentialParams are the names findParams reports, compared in lower case.
var credentialParams = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "client_secret": true, "access_token": true,
	"refresh_token": true, "id_token": true, "code_verifier": true, "api_key": true, "apikey": true,
	"private_key": true, "secret": true, "samlresponse": true,
}

func wordByte(c byte) bool {
	return c == '_' || ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

// findParams finds name=value pairs whose name is a credential parameter, as
// in a query string, a form body or a logfmt line. Each match is {start,
// end, name start, name end, value start, value end}.
func findParams(b []byte) [][]int {
	var out [][]int
	for i := 0; i < len(b); i++ {
		if b[i] != '=' {
			continue
		}
		ks := i
		for ks > 0 && wordByte(b[ks-1]) {
			ks--
		}
		if ks == i || i-ks > 16 || !credentialParams[strings.ToLower(string(b[ks:i]))] {
			continue
		}
		ve := i + 1
		for ve < len(b) && !strings.ContainsRune("&\"'<>;, \t\r\n", rune(b[ve])) {
			ve++
		}
		out = append(out, []int{ks, ve, ks, i, i + 1, ve})
	}
	return out
}

// findMembers finds JSON string members, "key":"value", with a key of up to
// 64 bytes of [A-Za-z0-9_.-]. Each match is {start, end, key start, key end,
// value start, value end}, the value still escaped.
func findMembers(b []byte) [][]int {
	var out [][]int
	for i := 0; i < len(b); i++ {
		if b[i] != ':' {
			continue
		}
		// Back over spaces to the key's closing quote, then over the key.
		k := i - 1
		for k >= 0 && (b[k] == ' ' || b[k] == '\t') {
			k--
		}
		if k < 1 || b[k] != '"' {
			continue
		}
		ks := k
		for ks > 0 && k-ks <= 64 && keyByte(b[ks-1]) {
			ks--
		}
		if ks == k || ks == 0 || b[ks-1] != '"' || k-ks > 64 {
			continue
		}
		// Forward over spaces to the value's opening quote, then to its
		// closing one.
		v := i + 1
		for v < len(b) && (b[v] == ' ' || b[v] == '\t') {
			v++
		}
		if v >= len(b) || b[v] != '"' {
			continue
		}
		e := v + 1
		for e < len(b) && b[e] != '"' && b[e] != '\n' {
			if b[e] == '\\' {
				e++
			}
			e++
		}
		if e >= len(b) || b[e] != '"' {
			continue
		}
		out = append(out, []int{ks - 1, e + 1, ks, k, v + 1, e})
		i = e
	}
	return out
}

func keyByte(c byte) bool { return wordByte(c) || c == '.' || c == '-' }

// placeholder reports values that say a secret was left out.
func placeholder(v []byte) bool {
	s := string(v)
	if s == "" || s == Redacted || s == "REDACTED" || s == url.QueryEscape(Redacted) || s == url.PathEscape(Redacted) {
		return true
	}
	return strings.Trim(s, "*xX.…-") == ""
}

// checkValue confirms a match whose value is submatch group g/2 (indexes
// m[g], m[g+1]) and is not empty or a placeholder.
func checkValue(g int) func([]byte, []int, *Scanner) (int, int, bool) {
	return func(b []byte, m []int, _ *Scanner) (int, int, bool) {
		if m[g] < 0 || placeholder(b[m[g]:m[g+1]]) {
			return 0, 0, false
		}
		return m[g], m[g+1], true
	}
}

// checkJWT wants a header that decodes to a JSON object naming an alg or
// enc, so dotted base64 that happens to start with eyJ is not reported.
func checkJWT(b []byte, m []int, _ *Scanner) (int, int, bool) {
	tok := b[m[0]:m[1]]
	head, _, _ := bytes.Cut(tok, []byte("."))
	h, err := base64.RawURLEncoding.DecodeString(string(head))
	if err != nil {
		return 0, 0, false
	}
	var hdr map[string]any
	if json.Unmarshal(h, &hdr) != nil {
		return 0, 0, false
	}
	if _, ok := hdr["alg"]; !ok {
		if _, ok := hdr["enc"]; !ok {
			return 0, 0, false
		}
	}
	return m[0], m[1], true
}

// checkJWK wants a "kty" on the same line, so only key material is
// reported.
func checkJWK(b []byte, m []int, _ *Scanner) (int, int, bool) {
	ls, le := lineBounds(b, m[0])
	if !bytes.Contains(b[ls:le], []byte(`"kty"`)) {
		return 0, 0, false
	}
	return m[2], m[3], true
}

// checkAuthHeader wants Bearer credentials that look like a token (16
// bytes or more with a digit, or 24 or more), not prose such as "bearer
// confirmation", and Basic credentials that decode to user:password.
func checkAuthHeader(b []byte, m []int, _ *Scanner) (int, int, bool) {
	scheme := strings.ToLower(string(b[m[2]:m[3]]))
	cred := b[m[4]:m[5]]
	if scheme == "basic" {
		d, err := base64.StdEncoding.DecodeString(string(cred))
		if err != nil {
			return 0, 0, false
		}
		user, pass, ok := bytes.Cut(d, []byte(":"))
		if !ok || len(pass) == 0 || !printable(user) || !printable(pass) {
			return 0, 0, false
		}
		return m[4], m[5], true
	}
	digit := bytes.ContainsAny(cred, "0123456789")
	if len(cred) >= 24 || (len(cred) >= 16 && digit) {
		return m[4], m[5], true
	}
	return 0, 0, false
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// checkField reports a JSON string member whose key names a secret, as the
// Handler's redaction decides, unless its value is empty or a placeholder.
func checkField(b []byte, m []int, s *Scanner) (int, int, bool) {
	if !s.red.secretKey(string(b[m[2]:m[3]])) || placeholder(b[m[4]:m[5]]) {
		return 0, 0, false
	}
	return m[4], m[5], true
}

func lineBounds(b []byte, i int) (int, int) {
	s := bytes.LastIndexByte(b[:i], '\n') + 1
	e := bytes.IndexByte(b[i:], '\n')
	if e < 0 {
		return s, len(b)
	}
	return s, i + e
}

// Scan reports the secrets in b, at most one per rule and position, in
// order of offset.
func (s *Scanner) Scan(b []byte) []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Finding
	add := func(rule string, start, end int) {
		out = append(out, Finding{
			Rule:    rule,
			Line:    bytes.Count(b[:start], []byte("\n")) + 1,
			Offset:  start,
			Excerpt: mask(b[start:end]),
		})
	}
	for _, p := range patterns {
		if s.allow[p.rule] {
			continue
		}
		for _, m := range p.matches(b) {
			start, end := m[0], m[1]
			if p.check != nil {
				var ok bool
				if start, end, ok = p.check(b, m, s); !ok {
					continue
				}
			}
			add(p.rule, start, end)
		}
	}
	if !s.allow[RuleKnown] {
		// Longest forms first (s.known is kept that way), and a match
		// inside one already reported is the same occurrence: an unpadded
		// base64 form is a prefix of the padded one.
		var spans [][2]int
		for _, k := range s.known {
			for i := 0; ; {
				j := bytes.Index(b[i:], k.form)
				if j < 0 {
					break
				}
				start, end := i+j, i+j+len(k.form)
				i = end
				inside := false
				for _, sp := range spans {
					inside = inside || (start >= sp[0] && end <= sp[1])
				}
				if inside {
					continue
				}
				spans = append(spans, [2]int{start, end})
				add(RuleKnown, start, end)
				// A registered value is shown by length only.
				out[len(out)-1].Excerpt = fmt.Sprintf("[%d bytes] (%s)", len(k.form), k.enc)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}

// mask shows the first four bytes of a secret of 12 bytes or more, none of
// a shorter one, and its length, so a report never carries the value.
func mask(v []byte) string {
	n := len(v)
	if n < 12 {
		return fmt.Sprintf("[%d bytes]", n)
	}
	head := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, string(v[:4]))
	return fmt.Sprintf("%s…[%d bytes]", head, n)
}
