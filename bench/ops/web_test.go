package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/laiwf94/authz/internal/agents/fakeserver"
)

func TestForwardAuth(t *testing.T) {
	var seen sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth" || r.Header.Get("X-Forwarded-Host") != "app.example.com" ||
			r.Header.Get("X-Forwarded-Method") != "GET" || r.Header.Get("X-Forwarded-Proto") != "https" {
			http.Error(w, "bad forward-auth request", http.StatusBadRequest)
			return
		}
		seen.Store(r.Header.Get("X-Forwarded-Uri"), true)
		c, err := r.Cookie("sess")
		if err != nil || !strings.HasPrefix(c.Value, "ok") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Auth-User", c.Value)
	}))
	defer srv.Close()
	ctx := context.Background()
	f := &ForwardAuth{Client: srv.Client(), URL: srv.URL + "/auth", Host: "app.example.com", Paths: []string{"/a", "/b?x=1"},
		Sessions: []*http.Cookie{{Name: "sess", Value: "ok1"}, {Name: "sess", Value: "ok2"}}}
	r := rng()
	for range 50 {
		if err := f.Do(ctx, 0, r); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range f.Paths {
		if _, ok := seen.Load(p); !ok {
			t.Fatalf("path %s never asked about", p)
		}
	}
	// Without a session the gateway answers 401: a failure, unless the run
	// measures the 401 path.
	anon := &ForwardAuth{Client: srv.Client(), URL: srv.URL + "/auth", Host: "app.example.com"}
	var se *StatusError
	if err := anon.Do(ctx, 0, r); !errors.As(err, &se) || se.Status != 401 {
		t.Fatalf("anonymous: %v", err)
	}
	if _, ok := seen.Load("/"); !ok {
		t.Fatal("no paths should ask about /")
	}
	anon.Expect = http.StatusUnauthorized
	if err := anon.Do(ctx, 0, r); err != nil {
		t.Fatalf("expected 401: %v", err)
	}
	bad := &ForwardAuth{Client: srv.Client(), URL: "::", Host: "h"}
	if err := bad.Do(ctx, 0, r); err == nil {
		t.Fatal("bad URL accepted")
	}
	closed := &ForwardAuth{Client: srv.Client(), URL: "http://127.0.0.1:1/auth", Host: "h"}
	if err := closed.Do(ctx, 0, r); err == nil {
		t.Fatal("closed port answered")
	}
	if f.Name() != "forward_auth" {
		t.Fatal(f.Name())
	}
}

// fakeSSO is a relying party (the gateway) and an identity provider on
// two servers, with the redirects, state cookie, hidden form fields and
// CSRF token of a real code flow.
type fakeSSO struct {
	rp, idp *httptest.Server
	logins  atomic.Int64
	// formMethod is the IdP form's method attribute.
	formMethod string
	// noSession makes the callback forget to set the session cookie.
	noSession bool
	// loop makes the callback redirect to itself forever.
	loop bool
}

func newFakeSSO(t *testing.T) *fakeSSO {
	f := &fakeSSO{formMethod: "post"}
	f.idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			if r.Method == http.MethodGet && r.URL.Query().Get("username") == "" {
				http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "c-123"})
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<html><body>
<form action="/search"><input name="q"><input type="password" name="other"></form>
<form method='%s' action="/authorize?client=rp&amp;x=1">
  <input type="hidden" name="state" value="%s">
  <input type=hidden name=csrf value=c-123>
  <input type="checkbox" name="remember" checked>
  <input type="checkbox" name="marketing" value="yes">
  <input type="text" name="username" value="">
  <input type="password" name="password">
  <input type="submit" name="go" value="Sign in">
  <input value="unnamed">
</form></body></html>`, f.formMethod, r.URL.Query().Get("state"))
				return
			}
			r.ParseForm()
			c, err := r.Cookie("csrf")
			if err != nil || r.Form.Get("csrf") != c.Value || r.Method == http.MethodPost && r.Form.Get("client") != "rp" ||
				r.Form.Get("go") != "" || r.Form.Get("remember") != "on" || r.Form.Has("marketing") {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("password") != r.Form.Get("username")+"-pass" {
				// Wrong password: the form again.
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<form method="post" action="/authorize"><input name="username"><input type="password" name="password"></form>`)
				return
			}
			http.Redirect(w, r, f.rp.URL+"/callback?code=xyz&state="+url.QueryEscape(r.Form.Get("state")), http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	f.rp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "rp-state", Value: "s-1"})
			http.SetCookie(w, &http.Cookie{Name: "old", Value: "", MaxAge: -1})
			http.Redirect(w, r, f.idp.URL+"/authorize?state=s-1", http.StatusFound)
		case "/callback":
			c, err := r.Cookie("rp-state")
			if err != nil || c.Value != r.URL.Query().Get("state") {
				http.Error(w, "state mismatch", http.StatusBadRequest)
				return
			}
			if f.loop {
				http.Redirect(w, r, r.URL.String(), http.StatusFound)
				return
			}
			if !f.noSession {
				f.logins.Add(1)
				http.SetCookie(w, &http.Cookie{Name: "__Host-wicket", Value: fmt.Sprintf("session-%d", f.logins.Load()), Secure: true})
			}
			http.Redirect(w, r, "/home", http.StatusFound)
		case "/home":
			fmt.Fprint(w, "welcome")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.rp.Close)
	t.Cleanup(f.idp.Close)
	return f
}

func TestLogin(t *testing.T) {
	sso := newFakeSSO(t)
	c, _ := NewClient(2, "")
	l := &Login{Client: c, Start: sso.rp.URL + "/login", SessionCookie: "__Host-wicket",
		Credentials: []Credential{{"alice", "alice-pass"}, {"bob", "bob-pass"}}}
	ctx := context.Background()
	r := rng()
	for range 10 {
		if err := l.Do(ctx, 0, r); err != nil {
			t.Fatal(err)
		}
	}
	s, err := l.Session(ctx, r)
	if err != nil || s.Name != "__Host-wicket" || s.Value != "session-11" {
		t.Fatalf("session %v %v", s, err)
	}
	if l.Name() != "oidc_login" {
		t.Fatal(l.Name())
	}

	// A form submitted with GET.
	sso.formMethod = "get"
	if _, err := l.Session(ctx, r); err != nil {
		t.Fatalf("GET form: %v", err)
	}
	sso.formMethod = "post"

	wrong := *l
	wrong.Credentials = []Credential{{"alice", "nope"}}
	if _, err := wrong.Session(ctx, r); err == nil || !strings.Contains(err.Error(), "alice was refused") {
		t.Fatalf("wrong password: %v", err)
	}
	fields := *l
	fields.UserField, fields.PasswordField = "login", "secret"
	if _, err := fields.Session(ctx, r); err == nil || !strings.Contains(err.Error(), `no form with a "secret" field`) {
		t.Fatalf("other field names: %v", err)
	}
	if _, err := (&Login{Client: c, Start: sso.rp.URL + "/login"}).Session(ctx, r); err == nil {
		t.Fatal("login without credentials")
	}
	sso.noSession = true
	if _, err := l.Session(ctx, r); err == nil || !strings.Contains(err.Error(), "did not sign in") {
		t.Fatalf("no session cookie: %v", err)
	}
	sso.noSession = false
	sso.loop = true
	if _, err := l.Session(ctx, r); err == nil || !strings.Contains(err.Error(), "no session after 20 requests") {
		t.Fatalf("redirect loop: %v", err)
	}
	sso.loop = false
	missing := *l
	missing.Start = sso.rp.URL + "/missing"
	if _, err := missing.Session(ctx, r); err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("404 start: %v", err)
	}
	for _, start := range []string{"::", "http://127.0.0.1:1/login"} {
		bad := *l
		bad.Start = start
		if _, err := bad.Session(ctx, r); err == nil {
			t.Fatalf("start %q accepted", start)
		}
	}
}

// A sign-in that lands on an error page after the session was set still
// counts: the session is what the benchmark needs.
func TestLoginSessionBeforeErrorPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "v"})
			http.Redirect(w, r, "/gone", http.StatusSeeOther)
		case "/bad-redirect":
			w.Header().Set("Location", "http://[::1")
			w.WriteHeader(http.StatusFound)
		case "/bad-action":
			fmt.Fprint(w, `<form method="post" action="http://[::1"><input name="password"></form>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, _ := NewClient(1, "")
	l := &Login{Client: c, Start: srv.URL + "/login", SessionCookie: "sid", Credentials: []Credential{{"u", "p"}}}
	if s, err := l.Session(context.Background(), rng()); err != nil || s.Value != "v" {
		t.Fatalf("%v %v", s, err)
	}
	l.Start = srv.URL + "/bad-redirect"
	if _, err := l.Session(context.Background(), rng()); err == nil || !strings.Contains(err.Error(), "Location") {
		t.Fatalf("bad redirect: %v", err)
	}
	l.Start = srv.URL + "/bad-action"
	if _, err := l.Session(context.Background(), rng()); err == nil || !strings.Contains(err.Error(), "bad form action") {
		t.Fatalf("bad action: %v", err)
	}
	l.Start = srv.URL + "/login"
	l.MaxSteps = 1
	if _, err := l.Session(context.Background(), rng()); err != nil {
		t.Fatalf("session within one step: %v", err)
	}
}

func newMCP(t *testing.T) *httptest.Server {
	t.Helper()
	fs, err := fakeserver.New(fakeserver.Config{Sandbox: t.TempDir(), Token: "agent-key-0123456789"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fs.Close() })
	srv := httptest.NewServer(fs)
	t.Cleanup(srv.Close)
	return srv
}

// tools/call against a real MCP server, in both protocol revisions, from
// several workers at once.
func TestMCPCall(t *testing.T) {
	srv := newMCP(t)
	ctx := context.Background()
	for _, proto := range []string{"", MCPStateless, MCPSession} {
		m := &MCPCall{Client: srv.Client(), URL: srv.URL + "/mcp", Key: "agent-key-0123456789", Protocol: proto,
			Tools: []Tool{{Name: "echo", Arguments: map[string]any{"text": "hi"}}, {Name: "translate", Arguments: map[string]any{"text": "x", "language": "de"}}}}
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for w := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := rng()
				for range 25 {
					if err := m.Do(ctx, w, r); err != nil {
						errs <- err
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("protocol %q: %v", proto, err)
		}
		if proto == MCPSession && len(m.sessions) != 4 {
			t.Fatalf("%d sessions for 4 workers", len(m.sessions))
		}
	}
	if (&MCPCall{}).Name() != "mcp_call" {
		t.Fatal("name")
	}
}

func TestMCPCallFailures(t *testing.T) {
	srv := newMCP(t)
	ctx := context.Background()
	call := func(m *MCPCall) error { return m.Do(ctx, 0, rng()) }
	base := func() *MCPCall {
		return &MCPCall{Client: srv.Client(), URL: srv.URL + "/mcp", Key: "agent-key-0123456789"}
	}
	m := base()
	if err := call(m); err == nil || !strings.Contains(err.Error(), "no tools") {
		t.Fatalf("no tools: %v", err)
	}
	m.Tools = []Tool{{Name: "echo"}} // no text: the tool reports an error
	if err := call(m); err == nil || !strings.Contains(err.Error(), "the tool reported an error") {
		t.Fatalf("isError: %v", err)
	}
	m.Tools = []Tool{{Name: "nope"}}
	if err := call(m); err == nil || !strings.Contains(err.Error(), "-32602") {
		t.Fatalf("unknown tool: %v", err)
	}
	m.Key = "wrong"
	m.Tools = []Tool{{Name: "echo", Arguments: map[string]any{"text": "x"}}}
	var se *StatusError
	if err := call(m); !errors.As(err, &se) || se.Status != 401 {
		t.Fatalf("wrong key: %v", err)
	}
	m.Protocol = MCPSession
	if err := call(m); err == nil || !strings.Contains(err.Error(), "initialize") {
		t.Fatalf("session with a wrong key: %v", err)
	}
	m = base()
	m.URL = "::"
	m.Tools = []Tool{{Name: "echo", Arguments: map[string]any{"text": "x"}}}
	if err := call(m); err == nil {
		t.Fatal("bad URL")
	}
}

// Event-stream answers, a forgotten session and malformed answers.
func TestMCPCallAnswers(t *testing.T) {
	var answer func(w http.ResponseWriter, r *http.Request, id string)
	var inits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		if err := jsonDecode(r, &body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		switch body.Method {
		case "initialize":
			inits.Add(1)
			w.Header().Set("Mcp-Session-Id", fmt.Sprintf("s%d", inits.Load()))
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{}}`, body.ID)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			answer(w, r, fmt.Sprint(body.ID))
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	tools := []Tool{{Name: "t"}}
	for _, tc := range []struct {
		name   string
		answer func(w http.ResponseWriter, r *http.Request, id string)
		want   string // "" for success
	}{
		{"sse", func(w http.ResponseWriter, r *http.Request, id string) {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\r\n\r\n"+
				"data: {\"jsonrpc\":\"2.0\",\r\ndata: \"id\":%s,\"result\":{}}\r\n", id)
		}, ""},
		{"sse ending in a blank line", func(w http.ResponseWriter, r *http.Request, id string) {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{}}\n\n: comment\n", id)
		}, ""},
		{"empty sse", func(w http.ResponseWriter, r *http.Request, id string) {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, ": nothing\n\n")
		}, "no data"},
		{"not json", func(w http.ResponseWriter, r *http.Request, id string) { fmt.Fprint(w, "<html>") }, "not JSON-RPC"},
		{"wrong id", func(w http.ResponseWriter, r *http.Request, id string) {
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":999999,"result":{}}`)
		}, "answer id 999999"},
		{"no result", func(w http.ResponseWriter, r *http.Request, id string) {
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s}`, id)
		}, "no result"},
		{"session forgotten", func(w http.ResponseWriter, r *http.Request, id string) {
			http.Error(w, "unknown session", http.StatusNotFound)
		}, "status 404"},
	} {
		answer = tc.answer
		for _, proto := range []string{MCPStateless, MCPSession} {
			m := &MCPCall{Client: srv.Client(), URL: srv.URL, Tools: tools, Protocol: proto}
			err := m.Do(ctx, 0, rng())
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Errorf("%s (%s): %v, want %q", tc.name, proto, err, tc.want)
			}
			if proto == MCPSession && tc.name == "session forgotten" {
				if _, ok := m.sessions[0]; ok {
					t.Error("a forgotten session was kept")
				}
				before := inits.Load()
				m.Do(ctx, 0, rng())
				if inits.Load() != before+1 {
					t.Error("no new session after the server forgot the old one")
				}
			}
		}
	}
	// A notification answered with something other than 202.
	answer = nil
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		jsonDecode(r, &body)
		if body.Method == "initialize" {
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{}}`, body.ID)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer bad.Close()
	m := &MCPCall{Client: bad.Client(), URL: bad.URL, Tools: tools, Protocol: MCPSession}
	if err := m.Do(ctx, 0, rng()); err == nil || !strings.Contains(err.Error(), "notifications/initialized") {
		t.Fatalf("notification refused: %v", err)
	}
	if _, _, err := m.rpc(ctx, "", 1, "x", map[string]any{"f": func() {}}); err == nil {
		t.Fatal("marshalled a function")
	}
}

func jsonDecode(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }

// twoPageIdP is a provider that asks for the name on one page and the
// password on the next, as Zitadel's login does, checks the Origin and
// Referer of each submitted form, and ends at a redirect URI nothing
// answers at.
func twoPageIdP(t *testing.T) (*httptest.Server, *atomic.Int64) {
	var origins atomic.Int64
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := func(body string) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, body)
		}
		sameSite := func(from string) bool {
			if r.Header.Get("Origin") != srv.URL || r.Header.Get("Referer") != srv.URL+from {
				http.Error(w, "cross-site form", http.StatusForbidden)
				return false
			}
			origins.Add(1)
			return true
		}
		switch r.URL.Path {
		case "/authorize":
			http.SetCookie(w, &http.Cookie{Name: "agent", Value: "a-1"})
			http.Redirect(w, r, "/ui/login/login?authRequestID=r1", http.StatusFound)
		case "/ui/login/login":
			page(`<form action="/ui/login/loginname" method="POST"><input type="hidden" name="authRequestID" value="r1">
<input type="text" name="loginName"><button name="register" value="true">Register</button></form>`)
		case "/ui/login/loginname":
			r.ParseForm()
			if !sameSite("/ui/login/login?authRequestID=r1") {
				return
			}
			if r.Form.Get("loginName") == "nobody" {
				page(`<form action="/ui/login/loginname" method="POST"><input type="text" name="loginName"></form>`)
				return
			}
			page(`<form action="/ui/login/password" method="POST"><input type="hidden" name="authRequestID" value="r1">
<input type="text" name="loginName" value="` + r.Form.Get("loginName") + `" class="hidden"><input type="password" name="password"></form>`)
		case "/ui/login/password":
			r.ParseForm()
			if !sameSite("/ui/login/loginname") {
				return
			}
			if c, err := r.Cookie("agent"); err != nil || c.Value != "a-1" || r.Form.Get("password") != r.Form.Get("loginName")+"-pass" {
				page(`<form action="/ui/login/password" method="POST"><input type="password" name="password"></form>`)
				return
			}
			http.Redirect(w, r, "/oauth/v2/authorize/callback?id=r1", http.StatusFound)
		case "/oauth/v2/authorize/callback":
			if r.Header.Get("Referer") != "" {
				http.Error(w, "a redirect carries no referer here", http.StatusBadRequest)
				return
			}
			q := "code=c-1&state=s"
			if r.URL.Query().Get("deny") != "" {
				q = "error=access_denied&error_description=no+grant"
			}
			http.Redirect(w, r, "http://127.0.0.1:1/callback?"+q, http.StatusFound)
		case "/no-code":
			http.Redirect(w, r, "http://127.0.0.1:1/callback?state=s", http.StatusFound)
		case "/early":
			http.Redirect(w, r, "http://127.0.0.1:1/callback?code=c-0", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &origins
}

func TestLoginTwoPages(t *testing.T) {
	srv, origins := twoPageIdP(t)
	c, _ := NewClient(2, "")
	ctx, r := context.Background(), rng()
	l := &Login{Client: c, Start: srv.URL + "/authorize", UserField: "loginName", DoneURL: "http://127.0.0.1:1/callback",
		Credentials: []Credential{{"u1", "u1-pass"}, {"u2", "u2-pass"}}}
	for range 5 {
		if err := l.Do(ctx, 0, r); err != nil {
			t.Fatal(err)
		}
	}
	res, err := l.SignIn(ctx, Credential{"u3", "u3-pass"})
	if err != nil || res.Done == nil || res.Done.Query().Get("code") != "c-1" || res.Session != nil {
		t.Fatalf("SignIn: %+v %v", res, err)
	}
	if got := origins.Load(); got != 12 {
		t.Errorf("%d forms came with the page's Origin and Referer, want 12", got)
	}
	// Session needs a cookie, which a sign-in ending at DoneURL has not set.
	if _, err := l.Session(ctx, r); err == nil || !strings.Contains(err.Error(), "cookie was set") {
		t.Errorf("session without a cookie: %v", err)
	}
	withCookie := *l
	withCookie.SessionCookie = "agent"
	if s, err := withCookie.Session(ctx, r); err != nil || s.Value != "a-1" {
		t.Errorf("session cookie set before DoneURL: %v %v", s, err)
	}

	for _, tc := range []struct {
		start, user, pass, want string
	}{
		{"/authorize", "u1", "wrong", "u1 was refused"},
		{"/authorize", "nobody", "x", "nobody was refused"},
		{"/oauth/v2/authorize/callback?deny=1", "u1", "u1-pass", "answered access_denied: no grant"},
		{"/no-code", "u1", "u1-pass", "without a code"},
		{"/early", "u1", "u1-pass", "before a password was asked for"},
	} {
		bad := *l
		bad.Start = srv.URL + tc.start
		bad.Credentials = []Credential{{tc.user, tc.pass}}
		if err := bad.Do(ctx, 0, r); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s as %s: %v, want %q", tc.start, tc.user, err, tc.want)
		}
	}
	// A bad action on the name page is reported as one.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<form method="post" action="http://[::1"><input name="loginName"></form>`)
	}))
	defer bad.Close()
	l.Start = bad.URL
	if err := l.Do(ctx, 0, r); err == nil || !strings.Contains(err.Error(), "bad form action") {
		t.Errorf("bad action: %v", err)
	}
}
