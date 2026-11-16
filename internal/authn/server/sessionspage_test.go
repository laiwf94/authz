package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authn/session"
)

func TestDeviceLabel(t *testing.T) {
	for _, c := range []struct{ ua, want string }{
		{"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0", "Firefox on Linux"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15", "Safari on macOS"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1", "Safari on iOS"},
		{"Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0 Mobile/15E148 Safari/604.1", "Chrome on iPadOS"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "Chrome on Windows"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0", "Edge on Windows"},
		{"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36", "Chrome on Android"},
		{"Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36", "Samsung Internet on Android"},
		{"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "Chrome on ChromeOS"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/114.0.0.0", "Opera on macOS"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/132.0 Mobile/15E148 Safari/605.1.15", "Firefox on iOS"},
		{"curl/8.10.1", "curl"},
		{"Mozilla/5.0 (X11; Linux x86_64) SomethingNew/1.0", "Browser on Linux"},
		{"Go-http-client/1.1", "Unknown device"},
		{"", "Unknown device"},
		{"<script>alert(1)</script> Firefox/1", "Firefox"},
	} {
		got := deviceLabel(c.ua)
		if got != c.want {
			t.Errorf("%q: got %q, want %q", c.ua, got, c.want)
		}
		if len(got) > session.MaxDeviceBytes {
			t.Errorf("%q: label too long", c.ua)
		}
	}
}

func TestCanonicalIP(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.1": "192.0.2.1", "::ffff:192.0.2.1": "192.0.2.1",
		"2001:DB8::1": "2001:db8::1", "fe80::1%eth0": "", "pipe": "", "": ""} {
		if got := canonicalIP(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// uaTransport sends every request with one User-Agent, as a browser does.
type uaTransport struct {
	base http.RoundTripper
	ua   string
}

func (u uaTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("User-Agent", u.ua)
	return u.base.RoundTrip(r)
}

func (h *harness) browserUA(ua string) *browser {
	b := h.browser()
	b.c.Transport = uaTransport{base: b.c.Transport, ua: ua}
	return b
}

const (
	uaFirefoxLinux = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
	uaSafariIOS    = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
	uaEdgeWindows  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
)

var (
	sessionsFormRe = regexp.MustCompile(`(?s)<form[^>]*method="post" action="([^"]+)">(.*?)</form>`)
	sessionItemRe  = regexp.MustCompile(`(?s)<li>(.*?)</li>`)
)

// sessionsForms returns the page's forms: the end-session form of each
// listed session by id, and the "end all others" form under "others".
func sessionsForms(t *testing.T, page string) (action string, forms map[string]url.Values) {
	t.Helper()
	forms = map[string]url.Values{}
	for _, m := range sessionsFormRe.FindAllStringSubmatch(page, -1) {
		action = m[1]
		_, f := formFields(m[2])
		switch {
		case f.Get("id") != "":
			forms[f.Get("id")] = f
		case f.Get("all") == "others":
			forms["others"] = f
		default:
			t.Fatalf("unexpected form: %s", m[0])
		}
	}
	return action, forms
}

func (b *browser) sessionsPage() (string, map[string]url.Values, string) {
	b.h.t.Helper()
	resp, page := b.get(b.h.public + "/sessions")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" ||
		resp.Header.Get("Content-Security-Policy") != sessionsPolicy || !strings.Contains(sessionsPolicy, styleHash(sessionsCSS)) ||
		!strings.Contains(sessionsPolicy, styleHash(pageCSS)) {
		b.h.t.Fatalf("sessions page: %d %s", resp.StatusCode, page)
	}
	action, forms := sessionsForms(b.h.t.(*testing.T), page)
	return action, forms, page
}

func (b *browser) currentID() string {
	b.h.t.Helper()
	sess, err := b.h.srv.currentSession(b.cookieRequest(), b.h.srv.rt.Load())
	if err != nil {
		b.h.t.Fatalf("no current session: %v", err)
	}
	return sess.ID
}

func (b *browser) cookieRequest() *http.Request {
	r, _ := http.NewRequest(http.MethodGet, b.h.public+"/", nil)
	u, _ := url.Parse(b.h.public)
	for _, c := range b.jar.Cookies(u) {
		r.AddCookie(c)
	}
	return r
}

func TestSessionsPage(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	// Not signed in: no list, no forms.
	anon := h.browser()
	if resp, body := anon.get(h.public + "/sessions"); resp.StatusCode != 401 || strings.Contains(body, "<form") {
		t.Fatalf("anonymous: %d %s", resp.StatusCode, body)
	}

	ff := h.browserUA(uaFirefoxLinux)
	ff.loginOIDC("alice", "alice-pass", "")
	h.clk.Advance(5 * 60e9)
	phone := h.browserUA(uaSafariIOS)
	phone.loginOIDC("alice", "alice-pass", "")
	bob := h.browserUA(uaEdgeWindows)
	bob.loginOIDC("bob", "bob-pass", "")
	ffID, phoneID, bobID := ff.currentID(), phone.currentID(), bob.currentID()
	h.clk.Advance(60e9)

	action, forms, page := ff.sessionsPage()
	if action != h.public+"/sessions/end" || !strings.Contains(page, "<style>"+sessionsCSS+"</style>") {
		t.Fatalf("action %q", action)
	}
	items := sessionItemRe.FindAllStringSubmatch(page, -1)
	if len(items) != 2 || len(forms) != 3 || forms[ffID] == nil || forms[phoneID] == nil || forms["others"] == nil || forms[bobID] != nil {
		t.Fatalf("listed %d sessions, forms %v:\n%s", len(items), forms, page)
	}
	// Most recently used first: the Firefox browser just loaded the page.
	first, second := items[0][1], items[1][1]
	for _, want := range []string{"Firefox on Linux", "This browser", "Address 127.0.0.1", "last used", "End this session and sign out"} {
		if !strings.Contains(first, want) {
			t.Errorf("first row lacks %q:\n%s", want, first)
		}
	}
	for _, want := range []string{"Safari on iOS", "Address 127.0.0.1", ">End session<"} {
		if !strings.Contains(second, want) {
			t.Errorf("second row lacks %q:\n%s", want, second)
		}
	}
	if strings.Contains(second, "This browser") || strings.Contains(page, "bob") || !strings.Contains(page, "alice@example.org") {
		t.Errorf("page:\n%s", page)
	}

	// Refused: cross-origin, wrong content type, forged or foreign tokens,
	// the logout page's token, a malformed request, someone else's session.
	tok := forms[phoneID]
	req, _ := http.NewRequest(http.MethodPost, action, strings.NewReader(tok.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	if resp := ff.do(req); resp.StatusCode != 403 {
		t.Fatalf("cross-origin: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, action, strings.NewReader(`{"id":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	if resp := ff.do(req); resp.StatusCode != 415 {
		t.Fatalf("JSON: %d", resp.StatusCode)
	}
	_, phoneForms, _ := phone.sessionsPage()
	_, logoutPage := ff.get(h.public + "/logout")
	_, logoutForm := formFields(logoutPage)
	for name, csrf := range map[string]string{"forged": "forged", "missing": "",
		"another browser's": phoneForms[phoneID].Get("csrf"), "logout": logoutForm.Get("csrf")} {
		if resp, _ := ff.post(action, url.Values{"csrf": {csrf}, "id": {phoneID}}); resp.StatusCode != 403 {
			t.Fatalf("%s token: %d", name, resp.StatusCode)
		}
	}
	h.expectAudit("logout_rejected", "csrf_token_invalid")
	csrf := tok.Get("csrf")
	for _, f := range []url.Values{{"csrf": {csrf}}, {"csrf": {csrf}, "id": {"NOTHEX"}}, {"csrf": {csrf}, "all": {"everyone"}},
		{"csrf": {csrf}, "id": {phoneID}, "all": {"others"}}} {
		if resp, _ := ff.post(action, f); resp.StatusCode != 400 {
			t.Fatalf("%v: %d", f, resp.StatusCode)
		}
	}
	if resp, _ := ff.post(action, url.Values{"csrf": {csrf}, "id": {bobID}}); resp.StatusCode != 404 {
		t.Fatalf("bob's session: %d", resp.StatusCode)
	}
	if resp, _ := anon.post(action, url.Values{"csrf": {csrf}, "id": {phoneID}}); resp.StatusCode != 401 {
		t.Fatalf("anonymous: %d", resp.StatusCode)
	}
	for name, b := range map[string]*browser{"phone": phone, "firefox": ff} {
		if resp := b.auth("/", nil); resp.StatusCode != 200 {
			t.Fatalf("a refused request ended %s's session: %d", name, resp.StatusCode)
		}
	}
	if l := h.sessions.UserSessions("corp", "bob"); len(l) != 1 || l[0].ID != bobID {
		t.Fatalf("bob's session ended: %+v", l)
	}

	// End the phone's session from Firefox.
	resp, _ := ff.post(action, tok)
	if resp.StatusCode != 303 || resp.Header.Get("Location") != h.public+"/sessions" {
		t.Fatalf("end: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	h.expectAudit("session_revoked", "")
	if !strings.Contains(h.logs.String(), `"by":"user"`) {
		t.Fatal("no audit record by the user")
	}
	if resp := phone.auth("/", nil); resp.StatusCode == 200 {
		t.Fatal("the ended session still works")
	}
	if resp := ff.auth("/", nil); resp.StatusCode != 200 {
		t.Fatalf("firefox signed out: %d", resp.StatusCode)
	}
	if resp, _ := ff.post(action, tok); resp.StatusCode != 404 {
		t.Fatalf("ended twice: %d", resp.StatusCode)
	}
	_, forms, _ = ff.sessionsPage()
	if len(forms) != 1 || forms[ffID] == nil {
		t.Fatalf("after ending: %v", forms)
	}
}

func TestSessionsPageEndOthersAndSelf(t *testing.T) {
	h := newHarness(t, harnessOpts{sessionFile: true})
	var bs []*browser
	for _, ua := range []string{uaFirefoxLinux, uaSafariIOS, uaEdgeWindows} {
		b := h.browserUA(ua)
		b.loginOIDC("alice", "alice-pass", "")
		bs = append(bs, b)
	}
	bob := h.browser()
	bob.loginOIDC("bob", "bob-pass", "")
	action, forms, _ := bs[0].sessionsPage()
	if len(forms) != 4 {
		t.Fatalf("forms %v", forms)
	}
	if resp, _ := bs[0].post(action, forms["others"]); resp.StatusCode != 303 || resp.Header.Get("Location") != h.public+"/sessions" {
		t.Fatalf("end others: %d", resp.StatusCode)
	}
	for i, b := range bs {
		if got, want := b.auth("/", nil).StatusCode == 200, i == 0; got != want {
			t.Fatalf("browser %d signed in: %v", i, got)
		}
	}
	if l := h.sessions.UserSessions("corp", "bob"); len(l) != 1 || l[0].ID != bob.currentID() {
		t.Fatalf("bob's session ended: %+v", l)
	}
	if n := len(h.sessions.UserSessions("corp", "alice")); n != 1 {
		t.Fatalf("alice has %d sessions", n)
	}
	// With no other session, there's no "end all others" form; ending this
	// one signs the browser out.
	action, forms, page := bs[0].sessionsPage()
	if forms["others"] != nil || strings.Contains(page, "End all other sessions") {
		t.Fatalf("others form with one session: %v", forms)
	}
	id := bs[0].currentID()
	resp, _ := bs[0].post(action, forms[id])
	if resp.StatusCode != 303 || resp.Header.Get("Location") != h.public+"/logged-out" {
		t.Fatalf("end self: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if c := resp.Header.Get("Set-Cookie"); !strings.Contains(c, "__Host-wicket=;") || !strings.Contains(c, "Max-Age=0") {
		t.Fatalf("cookie not cleared: %q", c)
	}
	if bs[0].auth("/", nil).StatusCode == 200 {
		t.Fatal("still signed in")
	}
	if resp, _ := bs[0].get(h.public + "/sessions"); resp.StatusCode != 401 {
		t.Fatalf("page after sign-out: %d", resp.StatusCode)
	}
}

// What a session records about the browser comes from the request that
// completed the login, through the trusted-proxy rules.
func TestLoginRecordsDevice(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.browserUA(uaSafariIOS)
	b.loginOIDC("alice", "alice-pass", "")
	l := h.sessions.UserSessions("corp", "alice")
	if len(l) != 1 || l[0].Device() != "Safari on iOS" || l[0].IP() != "127.0.0.1" {
		t.Fatalf("%+v %q %q", l, l[0].Device(), l[0].IP())
	}
}
