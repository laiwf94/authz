package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// ForwardAuth is the decision a reverse proxy asks for before passing a
// request on: GET URL (for authz gateway, http://host:4180/auth) with the
// forwarded host, method and path headers nginx and Traefik send and one of
// Sessions as the cookie. The answer must have status Expect (0 means 200).
// oauth2-proxy's /oauth2/auth and other forward-auth endpoints take the
// same request.
type ForwardAuth struct {
	Client *http.Client
	URL    string
	// Host is X-Forwarded-Host; Paths are drawn for X-Forwarded-Uri, "/"
	// when empty.
	Host     string
	Paths    []string
	Sessions []*http.Cookie
	Expect   int
}

// Name implements load.Op.
func (*ForwardAuth) Name() string { return "forward_auth" }

// Do implements load.Op.
func (f *ForwardAuth) Do(ctx context.Context, _ int, rng *rand.Rand) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return err
	}
	path := "/"
	if len(f.Paths) > 0 {
		path = f.Paths[rng.IntN(len(f.Paths))]
	}
	req.Header.Set("X-Forwarded-Host", f.Host)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Method", http.MethodGet)
	req.Header.Set("X-Forwarded-Uri", path)
	if len(f.Sessions) > 0 {
		req.AddCookie(f.Sessions[rng.IntN(len(f.Sessions))])
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return err
	}
	want := f.Expect
	if want == 0 {
		want = http.StatusOK
	}
	_, err = readAnswer(resp, want)
	return err
}

// Credential is a user name and password an identity provider accepts.
type Credential struct{ User, Password string }

// Login is a whole OpenID Connect (or SAML) sign-in as a browser does it:
// GET Start, follow redirects, fill the first form with a password field
// with a drawn credential and submit it, and follow redirects again until a
// page that is not a redirect. It succeeds when the answers on the way set
// a non-empty SessionCookie: for authz gateway, Start is
// /login?app=APP&provider=PROVIDER and the cookie is __Host-wicket.
// Keycloak's login works the same way with its own field names.
//
// A provider that asks for the user name and the password on two pages
// (Zitadel's) is signed in to the same way: while no page has had the
// password, a form with the user field and no password field is filled
// with the user name and submitted. A form is submitted with the Origin
// and Referer a browser sends, so a provider's CSRF checks of them pass.
//
// When DoneURL is set, a redirect to an address that starts with it ends
// the login without being followed: one whose query carries an
// authorization code after the password was submitted succeeds, any other
// fails. That measures a sign-in at a provider on its own, with a redirect
// URI nothing has to answer at, and needs no SessionCookie.
type Login struct {
	Client      *http.Client
	Start       string
	Credentials []Credential
	// UserField and PasswordField are the form's input names; empty means
	// "username" and "password".
	UserField, PasswordField string
	SessionCookie            string
	DoneURL                  string
	// MaxSteps bounds the requests in one login; 0 means 20.
	MaxSteps int
}

// Name implements load.Op.
func (*Login) Name() string { return "oidc_login" }

// Do implements load.Op.
func (l *Login) Do(ctx context.Context, _ int, rng *rand.Rand) error {
	_, err := l.draw(ctx, rng)
	return err
}

// Session signs in once and returns the session cookie it set.
func (l *Login) Session(ctx context.Context, rng *rand.Rand) (*http.Cookie, error) {
	res, err := l.draw(ctx, rng)
	if err == nil && res.Session == nil {
		// Only a sign-in that ended at DoneURL gets here.
		return nil, fmt.Errorf("login: no %q cookie was set", l.SessionCookie)
	}
	return res.Session, err
}

func (l *Login) draw(ctx context.Context, rng *rand.Rand) (LoginResult, error) {
	if len(l.Credentials) == 0 {
		return LoginResult{}, errors.New("login: no credentials")
	}
	return l.SignIn(ctx, l.Credentials[rng.IntN(len(l.Credentials))])
}

// LoginResult is how a sign-in ended: the session cookie it set, if any,
// and, when it ended at DoneURL, the address it was redirected to (which
// carries the authorization code).
type LoginResult struct {
	Session *http.Cookie
	Done    *url.URL
}

// Browser returns a function that signs a user in from a start address
// with a Login of client and userField, ended by the redirect to done; it
// is a products.Browser.
func Browser(client *http.Client, userField string) func(ctx context.Context, start, done, user, password string) (*url.URL, error) {
	return func(ctx context.Context, start, done, user, password string) (*url.URL, error) {
		l := &Login{Client: client, Start: start, UserField: userField, DoneURL: done}
		// With no session cookie to look for, a sign-in succeeds only at
		// the redirect to done.
		res, err := l.SignIn(ctx, Credential{User: user, Password: password})
		return res.Done, err
	}
}

// SignIn signs cred in once, ignoring Credentials.
func (l *Login) SignIn(ctx context.Context, cred Credential) (LoginResult, error) {
	s, done, err := l.signIn(ctx, cred)
	return LoginResult{Session: s, Done: done}, err
}

// signIn signs in once. The cookie it returns is nil when the sign-in
// ended at DoneURL before a session cookie was set.
func (l *Login) signIn(ctx context.Context, cred Credential) (*http.Cookie, *url.URL, error) {
	userField, passField := l.UserField, l.PasswordField
	if userField == "" {
		userField = "username"
	}
	if passField == "" {
		passField = "password"
	}
	steps := l.MaxSteps
	if steps <= 0 {
		steps = 20
	}
	jar := map[string]map[string]*http.Cookie{} // host -> name -> cookie
	var session *http.Cookie
	method, target, body := http.MethodGet, l.Start, ""
	var referer *url.URL // the page a form was submitted from
	submitted, userSubmitted := false, false
	for range steps {
		u, err := url.Parse(target)
		if err != nil {
			return nil, nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if referer != nil {
			req.Header.Set("Referer", referer.String())
			if method == http.MethodPost {
				req.Header.Set("Origin", referer.Scheme+"://"+referer.Host)
			}
			referer = nil
		}
		req.Header.Set("Accept", "text/html")
		for _, c := range jar[u.Host] {
			req.AddCookie(c)
		}
		resp, err := l.Client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		for _, c := range resp.Cookies() {
			if jar[u.Host] == nil {
				jar[u.Host] = map[string]*http.Cookie{}
			}
			if c.MaxAge < 0 || c.Value == "" {
				delete(jar[u.Host], c.Name)
				continue
			}
			jar[u.Host][c.Name] = &http.Cookie{Name: c.Name, Value: c.Value}
			if c.Name == l.SessionCookie {
				session = &http.Cookie{Name: c.Name, Value: c.Value}
			}
		}
		if loc := resp.Header.Get("Location"); resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
			resp.Body.Close()
			// The client has already refused a Location that does not parse.
			next, _ := u.Parse(loc)
			if l.DoneURL != "" && strings.HasPrefix(next.String(), l.DoneURL) {
				return session, next, l.done(next, submitted, cred.User)
			}
			method, target, body = http.MethodGet, next.String(), ""
			continue
		}
		page, err := readAnswer(resp, http.StatusOK)
		if err != nil {
			if session != nil {
				// Signed in; the page the login returns to is not ours to judge.
				return session, nil, nil
			}
			return nil, nil, fmt.Errorf("login: %s %s: %w", method, u.Redacted(), err)
		}
		f, ok := findForm(page, passField)
		if !ok && !submitted && !userSubmitted {
			// The first page of a two-page sign-in asks for the name only.
			if f, ok = findForm(page, userField); ok {
				action, err := u.Parse(f.action)
				if err != nil {
					return nil, nil, fmt.Errorf("login: bad form action %q: %w", f.action, err)
				}
				f.values.Set(userField, cred.User)
				userSubmitted, referer = true, u
				method, target, body = f.submit(action)
				continue
			}
		}
		if !ok || submitted {
			if session != nil {
				return session, nil, nil
			}
			if submitted || userSubmitted {
				return nil, nil, fmt.Errorf("login: %s was refused or did not sign in", cred.User)
			}
			return nil, nil, fmt.Errorf("login: %s has no form with a %q field", u.Redacted(), passField)
		}
		action, err := u.Parse(f.action)
		if err != nil {
			return nil, nil, fmt.Errorf("login: bad form action %q: %w", f.action, err)
		}
		f.values.Set(userField, cred.User)
		f.values.Set(passField, cred.Password)
		submitted, referer = true, u
		method, target, body = f.submit(action)
	}
	if session != nil {
		return session, nil, nil
	}
	return nil, nil, fmt.Errorf("login: no session after %d requests", steps)
}

// done judges the redirect to DoneURL that ended a sign-in.
func (l *Login) done(to *url.URL, submitted bool, user string) error {
	q := to.Query()
	switch {
	case q.Get("error") != "":
		return fmt.Errorf("login: %s: the provider answered %s: %s", user, q.Get("error"), q.Get("error_description"))
	case q.Get("code") == "":
		return fmt.Errorf("login: %s: redirected to %s without a code", user, l.DoneURL)
	case !submitted:
		return fmt.Errorf("login: %s: redirected to %s before a password was asked for", user, l.DoneURL)
	}
	return nil
}

type form struct {
	method, action string
	values         url.Values
}

// submit returns the request that submits f to action, as a browser sends
// it.
func (f form) submit(action *url.URL) (method, target, body string) {
	if f.method == http.MethodGet {
		action.RawQuery = f.values.Encode()
		return http.MethodGet, action.String(), ""
	}
	return http.MethodPost, action.String(), f.values.Encode()
}

var (
	formRe  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	inputRe = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
	// checkedRe finds the checked attribute, bare or with a value.
	checkedRe = regexp.MustCompile(`(?i)(^|\s)checked(\s|=|/|$)`)
	attrRe    = regexp.MustCompile(`(?s)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
)

func attrs(s string) map[string]string {
	m := map[string]string{}
	for _, a := range attrRe.FindAllStringSubmatch(s, -1) {
		m[strings.ToLower(a[1])] = html.UnescapeString(a[2] + a[3] + a[4])
	}
	return m
}

// findForm returns the first form in page that has an input named field,
// with the values of its other inputs (hidden state, CSRF tokens).
func findForm(page []byte, field string) (form, bool) {
	for _, m := range formRe.FindAllSubmatch(page, -1) {
		fa := attrs(string(m[1]))
		f := form{method: strings.ToUpper(fa["method"]), action: fa["action"], values: url.Values{}}
		if f.method != http.MethodGet {
			f.method = http.MethodPost
		}
		found := false
		for _, in := range inputRe.FindAllSubmatch(m[2], -1) {
			a := attrs(string(in[1]))
			name := a["name"]
			if name == "" {
				continue
			}
			if name == field {
				found = true
			}
			a["type"] = strings.ToLower(a["type"])
			switch a["type"] {
			case "submit", "button", "image", "reset":
				continue
			case "checkbox", "radio":
				if !checkedRe.Match(in[1]) {
					continue
				}
			}
			v, hasValue := a["value"]
			if !hasValue && (a["type"] == "checkbox" || a["type"] == "radio") {
				v = "on" // what browsers send for a checked box without a value
			}
			f.values.Set(name, v)
		}
		if found {
			return f, true
		}
	}
	return form{}, false
}

// Tool is an MCP tool a call may name, with its arguments.
type Tool struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// MCP protocol revisions MCPCall speaks.
const (
	// MCPStateless is the 2026-07-28 revision: each request carries its
	// protocol version and client information, with no session.
	MCPStateless = "2026-07-28"
	// MCPSession is the 2025-06-18 revision: a session per worker, opened
	// with initialize and named by Mcp-Session-Id. Gateways that do not
	// speak the newer revision are measured this way.
	MCPSession = "2025-06-18"
)

// MCPCall is POST URL of a JSON-RPC tools/call naming a drawn tool, with
// Authorization: Bearer Key. The answer, JSON or a server-sent event
// stream, must be a result for the request's id without isError.
type MCPCall struct {
	Client *http.Client
	URL    string
	Key    string
	Tools  []Tool
	// Protocol is MCPStateless (the default) or MCPSession.
	Protocol string

	ids      atomic.Int64
	mu       sync.Mutex
	sessions map[int]string // worker -> Mcp-Session-Id
}

// Name implements load.Op.
func (*MCPCall) Name() string { return "mcp_call" }

type rpcAnswer struct {
	ID     json.RawMessage `json:"id"`
	Result *struct {
		IsError bool `json:"isError"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// rpc sends one JSON-RPC message and returns the answer and its headers; a
// notification (id 0) expects 202 and no answer.
func (m *MCPCall) rpc(ctx context.Context, session string, id int64, method string, params map[string]any) (*rpcAnswer, http.Header, error) {
	msg := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		msg["params"] = params
	}
	if id != 0 {
		msg["id"] = id
	}
	buf, err := json.Marshal(msg)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.URL, bytes.NewReader(buf))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if m.Key != "" {
		req.Header.Set("Authorization", "Bearer "+m.Key)
	}
	proto := m.protocol()
	if method != "initialize" {
		req.Header.Set("MCP-Protocol-Version", proto)
	}
	if proto == MCPStateless {
		req.Header.Set("Mcp-Method", method)
		if n, ok := params["name"].(string); ok {
			req.Header.Set("Mcp-Name", n)
		}
	}
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if id == 0 {
		_, err := readAnswer(resp, http.StatusAccepted)
		return nil, resp.Header, err
	}
	ct := resp.Header.Get("Content-Type")
	b, err := readAnswer(resp, http.StatusOK)
	if err != nil {
		return nil, nil, err
	}
	if strings.HasPrefix(ct, "text/event-stream") {
		b, err = lastEvent(b)
		if err != nil {
			return nil, nil, err
		}
	}
	var a rpcAnswer
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, nil, fmt.Errorf("answer is not JSON-RPC: %w", err)
	}
	if string(a.ID) != fmt.Sprint(id) {
		return nil, nil, fmt.Errorf("answer id %s, want %d", a.ID, id)
	}
	if a.Error != nil {
		return nil, nil, fmt.Errorf("%s: error %d: %s", method, a.Error.Code, a.Error.Message)
	}
	if a.Result == nil {
		return nil, nil, fmt.Errorf("%s: answer has no result", method)
	}
	return &a, resp.Header, nil
}

// lastEvent returns the data of the last event in a server-sent event
// stream that carries any.
func lastEvent(b []byte) ([]byte, error) {
	var last, cur []byte
	for _, line := range bytes.Split(b, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		switch {
		case len(line) == 0:
			if cur != nil {
				last, cur = cur, nil
			}
		case bytes.HasPrefix(line, []byte("data:")):
			d := bytes.TrimPrefix(bytes.TrimPrefix(line, []byte("data:")), []byte(" "))
			if cur != nil {
				cur = append(cur, '\n')
			}
			cur = append(cur, d...)
		}
	}
	if cur != nil {
		last = cur
	}
	if last == nil {
		return nil, errors.New("event stream has no data")
	}
	return last, nil
}

func (m *MCPCall) protocol() string {
	if m.Protocol == "" {
		return MCPStateless
	}
	return m.Protocol
}

var clientInfo = map[string]any{"name": "authzbench", "version": "1"}

// session returns worker's session, opening one if it has none.
func (m *MCPCall) session(ctx context.Context, worker int) (string, error) {
	m.mu.Lock()
	s, ok := m.sessions[worker]
	m.mu.Unlock()
	if ok {
		return s, nil
	}
	_, hdr, err := m.rpc(ctx, "", m.ids.Add(1), "initialize", map[string]any{
		"protocolVersion": MCPSession, "capabilities": map[string]any{}, "clientInfo": clientInfo})
	if err != nil {
		return "", fmt.Errorf("initialize: %w", err)
	}
	s = hdr.Get("Mcp-Session-Id")
	if _, _, err := m.rpc(ctx, s, 0, "notifications/initialized", nil); err != nil {
		return "", fmt.Errorf("notifications/initialized: %w", err)
	}
	m.mu.Lock()
	if m.sessions == nil {
		m.sessions = map[int]string{}
	}
	m.sessions[worker] = s
	m.mu.Unlock()
	return s, nil
}

// Do implements load.Op. In the session revision a worker's first call
// opens its session, and that call's time includes the handshake.
func (m *MCPCall) Do(ctx context.Context, worker int, rng *rand.Rand) error {
	if len(m.Tools) == 0 {
		return errors.New("mcp: no tools")
	}
	t := m.Tools[rng.IntN(len(m.Tools))]
	args := t.Arguments
	if args == nil {
		args = map[string]any{}
	}
	params := map[string]any{"name": t.Name, "arguments": args}
	session := ""
	if m.protocol() == MCPSession {
		s, err := m.session(ctx, worker)
		if err != nil {
			return err
		}
		session = s
	} else {
		params["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    MCPStateless,
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			"io.modelcontextprotocol/clientInfo":         clientInfo,
		}
	}
	a, _, err := m.rpc(ctx, session, m.ids.Add(1), "tools/call", params)
	if err != nil {
		var se *StatusError
		if session != "" && errors.As(err, &se) && se.Status == http.StatusNotFound {
			// The server forgot the session: open a new one next time.
			m.mu.Lock()
			delete(m.sessions, worker)
			m.mu.Unlock()
		}
		return err
	}
	if a.Result.IsError {
		return fmt.Errorf("tools/call %s: the tool reported an error", t.Name)
	}
	return nil
}
