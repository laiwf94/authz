// Package golden records HTTP exchanges as a normalised text transcript and
// compares it byte for byte with a file checked into testdata.
//
// A transcript keeps everything a client of the gateway can observe: the
// status line, every response header except Date and Content-Length, and the
// body. Values that are random by construction (listener ports, sealed
// cookies, OAuth state and nonce, CSRF tokens, signatures, session IDs) or
// tied to the wall clock are replaced by placeholders. Placeholders are
// numbered by first appearance and the same value always gets the same
// placeholder, so a transcript still proves that, for example, the session ID
// in a token is the one the admin API lists. Anything not named by a rule is
// compared exactly.
//
// Content-Length is left out because it follows from the body, which is
// compared in full once normalised, and would otherwise change with the
// number of digits in a port.
package golden

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Normalizer rewrites the volatile parts of strings into stable
// placeholders. It is not safe for concurrent use.
type Normalizer struct {
	literals [][2]string // value, name; longest value first
	rules    []rule
	values   map[string]string // volatile value -> placeholder
	counts   map[string]int
	repl     *strings.Replacer
	base     time.Time
	hasBase  bool
}

type rule struct {
	kind string
	re   *regexp.Regexp
}

// NewNormalizer returns a Normalizer with no rules.
func NewNormalizer() *Normalizer {
	return &Normalizer{values: map[string]string{}, counts: map[string]int{}}
}

// Literal replaces every occurrence of value, and its URL-query-escaped,
// path-escaped and HTML-escaped forms, with {{name}}. Use it for listener
// addresses and other values known up front.
func (n *Normalizer) Literal(value, name string) {
	if value == "" {
		return
	}
	ph := "{{" + name + "}}"
	for _, v := range []string{value, url.QueryEscape(value), url.PathEscape(value), html.EscapeString(value)} {
		if !slices.ContainsFunc(n.literals, func(l [2]string) bool { return l[0] == v }) {
			n.literals = append(n.literals, [2]string{v, ph})
		}
	}
	slices.SortStableFunc(n.literals, func(a, b [2]string) int { return len(b[0]) - len(a[0]) })
}

// Volatile marks every match of re as a random value of the given kind. When
// re has a capturing group, only the first group is the value. Each distinct
// value becomes <kind#k>, numbered by first appearance across the whole
// transcript, and later occurrences anywhere (escaped or not) get the same
// placeholder.
func (n *Normalizer) Volatile(kind string, re *regexp.Regexp) {
	n.rules = append(n.rules, rule{kind: kind, re: re})
}

// Value registers v as a volatile value of the given kind and returns its
// placeholder.
func (n *Normalizer) Value(kind, v string) string {
	if ph, ok := n.values[v]; ok {
		return ph
	}
	n.counts[kind]++
	ph := "<" + kind + "#" + strconv.Itoa(n.counts[kind]) + ">"
	n.values[v] = ph
	for _, e := range []string{url.QueryEscape(v), html.EscapeString(v)} {
		if _, ok := n.values[e]; !ok && e != v {
			n.values[e] = ph
		}
	}
	n.repl = nil
	return ph
}

// Clock makes times relative to base: Unix seconds in JWT time claims,
// RFC 3339 timestamps and HTTP dates are written as <T+duration>. base
// should be the server's clock at the start of the transcript.
func (n *Normalizer) Clock(base time.Time) {
	n.base, n.hasBase = base, true
}

var (
	jwtRe      = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+`)
	rfc3339Re  = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)
	httpDateRe = regexp.MustCompile(`(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT`)
	timeClaim  = regexp.MustCompile(`"(iat|nbf|exp|auth_time)":(\d+)`)
)

// String returns s with literals, registered values, JWTs and times
// normalised.
func (n *Normalizer) String(s string) string {
	for _, l := range n.literals {
		s = strings.ReplaceAll(s, l[0], l[1])
	}
	s = jwtRe.ReplaceAllStringFunc(s, n.jwt)
	if n.hasBase {
		s = rfc3339Re.ReplaceAllStringFunc(s, func(m string) string {
			t, err := time.Parse(time.RFC3339Nano, m)
			if err != nil {
				return m
			}
			return n.rel(t, false)
		})
		s = httpDateRe.ReplaceAllStringFunc(s, func(m string) string {
			t, err := http.ParseTime(m)
			if err != nil {
				return m
			}
			return n.rel(t, true)
		})
	}
	for _, r := range n.rules {
		for _, m := range r.re.FindAllStringSubmatch(s, -1) {
			v := m[0]
			if len(m) > 1 {
				v = m[1]
			}
			if v != "" && !strings.HasPrefix(v, "<") {
				n.Value(r.kind, v)
			}
		}
	}
	return n.replacer().Replace(s)
}

func (n *Normalizer) replacer() *strings.Replacer {
	if n.repl != nil {
		return n.repl
	}
	keys := make([]string, 0, len(n.values))
	for k := range n.values {
		keys = append(keys, k)
	}
	// Longest first, so a value is never cut by a shorter one inside it.
	slices.SortFunc(keys, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
	args := make([]string, 0, 2*len(keys))
	for _, k := range keys {
		args = append(args, k, n.values[k])
	}
	n.repl = strings.NewReplacer(args...)
	return n.repl
}

// rel writes t relative to the base clock. Second-precision formats compare
// against the base truncated to the second.
func (n *Normalizer) rel(t time.Time, seconds bool) string {
	base := n.base
	if seconds {
		base = base.Truncate(time.Second)
	}
	d := t.Sub(base)
	if d >= 0 {
		return "<T+" + d.String() + ">"
	}
	return "<T-" + (-d).String() + ">"
}

// jwt replaces a compact JWS with its decoded, normalised header and claims.
// The signature is dropped: ECDSA signatures are random even for the same
// input, and the keys are generated per run.
func (n *Normalizer) jwt(tok string) string {
	parts := strings.Split(tok, ".")
	hdr, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	claims, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil || !json.Valid(hdr) || !json.Valid(claims) {
		return tok
	}
	c := string(claims)
	if n.hasBase {
		c = timeClaim.ReplaceAllStringFunc(c, func(m string) string {
			sm := timeClaim.FindStringSubmatch(m)
			sec, err := strconv.ParseInt(sm[2], 10, 64)
			if err != nil {
				return m
			}
			return `"` + sm[1] + `":"` + n.rel(time.Unix(sec, 0), true) + `"`
		})
	}
	// The decoded parts go through the rules too (kid, sid, nonce...), but
	// not through the JWT rule again.
	return "jwt{" + n.String(string(hdr)) + "." + n.String(c) + "}"
}

// Transcript is an ordered record of HTTP exchanges.
type Transcript struct {
	n   *Normalizer
	buf bytes.Buffer
	// RequestHeaders lists the request headers worth recording, in the
	// canonical form. Cookie is always recorded.
	RequestHeaders []string
}

// New returns a transcript that normalises with n.
func New(n *Normalizer) *Transcript {
	return &Transcript{n: n}
}

// Normalizer returns the transcript's normalizer.
func (t *Transcript) Normalizer() *Normalizer { return t.n }

// Step starts a named section.
func (t *Transcript) Step(name string) {
	if t.buf.Len() > 0 {
		t.buf.WriteByte('\n')
	}
	fmt.Fprintf(&t.buf, "=== %s\n", name)
}

// Note records a line of free text, normalised.
func (t *Transcript) Note(s string) {
	fmt.Fprintf(&t.buf, "# %s\n", t.n.String(s))
}

// Exchange records a request and its response. reqBody is the body that was
// sent (nil for none); the response body is read in full, recorded, and
// returned, and resp.Body is closed.
func (t *Transcript) Exchange(req *http.Request, reqBody []byte, resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	n := t.n
	fmt.Fprintf(&t.buf, "> %s %s\n", req.Method, n.String(req.URL.String()))
	if req.Host != "" && req.Host != req.URL.Host {
		fmt.Fprintf(&t.buf, "> Host: %s\n", n.String(req.Host))
	}
	for _, k := range t.RequestHeaders {
		for _, v := range req.Header.Values(k) {
			fmt.Fprintf(&t.buf, "> %s: %s\n", k, n.String(v))
		}
	}
	for _, c := range req.Cookies() {
		fmt.Fprintf(&t.buf, "> Cookie: %s\n", t.cookie(c.Name+"="+c.Value))
	}
	if len(reqBody) > 0 {
		fmt.Fprintf(&t.buf, "> \n> %s\n", n.String(string(reqBody)))
	}
	fmt.Fprintf(&t.buf, "< %s %s\n", resp.Proto, resp.Status)
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		if k != "Date" && k != "Content-Length" {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			if k == "Set-Cookie" {
				v = t.cookie(v)
			} else {
				v = n.String(v)
			}
			fmt.Fprintf(&t.buf, "< %s: %s\n", k, v)
		}
	}
	if len(body) > 0 {
		t.buf.WriteString("<\n")
		b := n.String(string(body))
		t.buf.WriteString(b)
		if !strings.HasSuffix(b, "\n") {
			t.buf.WriteString("\n<no newline at end of body>\n")
		}
	}
	return body, nil
}

// cookie normalises "name=value[; attributes]". A non-empty value is always
// volatile: every cookie the gateway sets is sealed with a random nonce.
func (t *Transcript) cookie(s string) string {
	pair, attrs, _ := strings.Cut(s, ";")
	name, value, ok := strings.Cut(pair, "=")
	if !ok {
		return t.n.String(s)
	}
	name = t.n.String(name)
	if value != "" {
		value = t.n.Value("cookie", value)
	}
	out := name + "=" + value
	if attrs != "" {
		out += ";" + t.n.String(attrs)
	}
	return out
}

// Bytes returns the transcript so far.
func (t *Transcript) Bytes() []byte { return t.buf.Bytes() }

// Check compares got with the file at path. With update set it writes got
// to path instead (creating directories) and reports no error.
func Check(path string, got []byte, update bool) error {
	if update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, got, 0o644)
	}
	want, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s does not exist; run the test with -update to create it", path)
	}
	if err != nil {
		return err
	}
	if bytes.Equal(got, want) {
		return nil
	}
	return fmt.Errorf("%s differs from the recorded responses:\n%s", path, Diff(want, got))
}

// Diff describes the first difference between want and got as numbered
// lines with three lines of context, and counts the differing lines.
func Diff(want, got []byte) string {
	w := strings.Split(string(want), "\n")
	g := strings.Split(string(got), "\n")
	first := -1
	differ := 0
	for i := 0; i < max(len(w), len(g)); i++ {
		var a, b string
		okA, okB := i < len(w), i < len(g)
		if okA {
			a = w[i]
		}
		if okB {
			b = g[i]
		}
		if okA != okB || a != b {
			differ++
			if first < 0 {
				first = i
			}
		}
	}
	if first < 0 {
		return "(no differences)"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d differing lines (want %d lines, got %d); first at line %d:\n", differ, len(w), len(g), first+1)
	for i := max(0, first-3); i < first; i++ {
		fmt.Fprintf(&sb, "  %5d   %s\n", i+1, w[i])
	}
	for i := first; i < min(first+4, len(w)); i++ {
		fmt.Fprintf(&sb, "- %5d   %s\n", i+1, w[i])
	}
	for i := first; i < min(first+4, len(g)); i++ {
		fmt.Fprintf(&sb, "+ %5d   %s\n", i+1, g[i])
	}
	return sb.String()
}
