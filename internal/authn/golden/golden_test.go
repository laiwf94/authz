package golden

import (
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestLiteralForms(t *testing.T) {
	n := NewNormalizer()
	n.Literal("https://127.0.0.1:4321", "public")
	n.Literal("127.0.0.1:4321", "host")
	got := n.String(`https://127.0.0.1:4321/x?rd=https%3A%2F%2F127.0.0.1%3A4321%2Fy host=127.0.0.1:4321 &amp;`)
	want := `{{public}}/x?rd={{public}}%2Fy host={{host}} &amp;`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if n.String("") != "" {
		t.Fatal("empty string changed")
	}
	n.Literal("", "ignored")
}

func TestVolatileValuesAreStableAndNumbered(t *testing.T) {
	n := NewNormalizer()
	n.Volatile("state", regexp.MustCompile(`state=([A-Za-z0-9+/=]+)`))
	n.Volatile("word", regexp.MustCompile(`\bzz[a-z]+\b`))
	a := n.String("a?state=AAAA&b=1 state=BB/+= zzfoo")
	b := n.String("again AAAA then " + "BB%2F%2B%3D" + " zzfoo zzbar")
	if a != "a?state=<state#1>&b=1 state=<state#2> <word#1>" {
		t.Fatalf("first: %s", a)
	}
	// Known values are replaced wherever they appear, escaped or not.
	if b != "again <state#1> then <state#2> <word#1> <word#2>" {
		t.Fatalf("second: %s", b)
	}
	if ph := n.Value("state", "AAAA"); ph != "<state#1>" {
		t.Fatalf("Value of a known value: %s", ph)
	}
	if ph := n.Value("other", "CCCC"); ph != "<other#1>" {
		t.Fatalf("Value: %s", ph)
	}
}

func TestLongerValuesWin(t *testing.T) {
	n := NewNormalizer()
	n.Value("a", "abc")
	n.Value("b", "abcdef")
	if got := n.String("abcdef abc"); got != "<b#1> <a#1>" {
		t.Fatal(got)
	}
}

func TestClock(t *testing.T) {
	base := time.Date(2026, 11, 1, 10, 0, 0, 500_000_000, time.UTC)
	n := NewNormalizer()
	if got := n.String("2026-11-01T10:00:00Z"); got != "2026-11-01T10:00:00Z" {
		t.Fatalf("without a clock times are kept: %s", got)
	}
	n.Clock(base)
	got := n.String(`"2026-11-01T10:00:00.5Z" "2026-11-01T11:00:00.5+01:00" Expires=Sun, 01 Nov 2026 10:05:00 GMT "2026-11-01T09:59:59.5Z"`)
	want := `"<T+0s>" "<T+0s>" Expires=<T+5m0s> "<T-1s>"`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func jws(header, claims string) string {
	e := base64.RawURLEncoding
	return e.EncodeToString([]byte(header)) + "." + e.EncodeToString([]byte(claims)) + ".c2lnbmF0dXJl"
}

func TestJWT(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	n := NewNormalizer()
	n.Clock(base)
	n.Literal("https://gw.test:1234", "public")
	n.Volatile("key", regexp.MustCompile(`"kid":"([^"]+)"`))
	tok := jws(`{"alg":"ES256","kid":"k-123"}`, `{"iss":"https://gw.test:1234","iat":1800000000,"exp":1800000120,"sub":"alice"}`)
	got := n.String("X-Auth-Token: " + tok)
	want := `X-Auth-Token: jwt{{"alg":"ES256","kid":"<key#1>"}.{"iss":"{{public}}","iat":"<T+0s>","exp":"<T+2m0s>","sub":"alice"}}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	// Not JSON inside: left alone.
	bad := "eyJhbGciOi.eyJzdWIi.c2ln"
	if got := n.String(bad); got != bad {
		t.Fatalf("invalid token changed: %s", got)
	}
}

func TestTranscript(t *testing.T) {
	n := NewNormalizer()
	n.Literal("https://gw.test:1234", "public")
	n.Clock(time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC))
	tr := New(n)
	tr.RequestHeaders = []string{"Accept", "X-Missing"}
	if tr.Normalizer() != n {
		t.Fatal("Normalizer")
	}
	req, _ := http.NewRequest(http.MethodPost, "https://gw.test:1234/login?x=1", strings.NewReader("a=b"))
	req.Host = "other.test"
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Not-Recorded", "1")
	req.AddCookie(&http.Cookie{Name: "sid", Value: "sealed-1"})
	resp := &http.Response{Proto: "HTTP/1.1", Status: "302 Found", Header: http.Header{
		"Date":           {"Sun, 01 Nov 2026 10:00:00 GMT"},
		"Content-Length": {"9"},
		"Location":       {"https://gw.test:1234/next"},
		"Set-Cookie":     {"sid=sealed-2; Path=/; Expires=Sun, 01 Nov 2026 11:00:00 GMT; HttpOnly", "old=; Max-Age=0", "odd"},
	}, Body: io.NopCloser(strings.NewReader("moved to https://gw.test:1234/next; old cookie sealed-1"))}
	tr.Step("first")
	tr.Note("seen at https://gw.test:1234")
	body, err := tr.Exchange(req, []byte("a=b"), resp)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "moved to https://gw.test:1234/next; old cookie sealed-1" {
		t.Fatalf("body returned: %q", body)
	}
	tr.Step("second")
	empty := &http.Response{Proto: "HTTP/1.1", Status: "204 No Content", Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok\n"))}
	req2, _ := http.NewRequest(http.MethodGet, "https://gw.test:1234/", nil)
	if _, err := tr.Exchange(req2, nil, empty); err != nil {
		t.Fatal(err)
	}
	want := `=== first
# seen at {{public}}
> POST {{public}}/login?x=1
> Host: other.test
> Accept: text/html
> Cookie: sid=<cookie#1>
> 
> a=b
< HTTP/1.1 302 Found
< Location: {{public}}/next
< Set-Cookie: sid=<cookie#2>; Path=/; Expires=<T+1h0m0s>; HttpOnly
< Set-Cookie: old=; Max-Age=0
< Set-Cookie: odd
<
moved to {{public}}/next; old cookie <cookie#1>
<no newline at end of body>

=== second
> GET {{public}}/
< HTTP/1.1 204 No Content
<
ok
`
	if got := string(tr.Bytes()); got != want {
		t.Fatalf("transcript:\n%s\nwant:\n%s\n%s", got, want, Diff([]byte(want), []byte(got)))
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, os.ErrClosed }

func TestExchangeReadError(t *testing.T) {
	tr := New(NewNormalizer())
	req, _ := http.NewRequest(http.MethodGet, "http://x.test/", nil)
	if _, err := tr.Exchange(req, nil, &http.Response{Body: io.NopCloser(failingReader{})}); err == nil {
		t.Fatal("read error not reported")
	}
}

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "x.txt")
	if err := Check(path, []byte("a\n"), false); err == nil || !strings.Contains(err.Error(), "-update") {
		t.Fatalf("missing file: %v", err)
	}
	if err := Check(path, []byte("a\nb\n"), true); err != nil {
		t.Fatal(err)
	}
	if err := Check(path, []byte("a\nb\n"), false); err != nil {
		t.Fatalf("same bytes: %v", err)
	}
	err := Check(path, []byte("a\nc\n"), false)
	if err == nil || !strings.Contains(err.Error(), "-     2   b") || !strings.Contains(err.Error(), "+     2   c") {
		t.Fatalf("diff: %v", err)
	}
	if err := Check(dir, []byte("x"), false); err == nil {
		t.Fatal("reading a directory should fail")
	}
	if err := Check(filepath.Join(path, "below-a-file"), []byte("x"), true); err == nil {
		t.Fatal("writing below a file should fail")
	}
}

func TestDiff(t *testing.T) {
	if got := Diff([]byte("a\nb"), []byte("a\nb")); got != "(no differences)" {
		t.Fatal(got)
	}
	got := Diff([]byte("1\n2\n3\n4\n5"), []byte("1\n2\n3\n4\n5\n6"))
	if !strings.HasPrefix(got, "1 differing lines (want 5 lines, got 6); first at line 6:") || !strings.Contains(got, "+     6   6") {
		t.Fatal(got)
	}
	got = Diff([]byte("x\ny"), []byte("x"))
	if !strings.Contains(got, "-     2   y") {
		t.Fatal(got)
	}
}
