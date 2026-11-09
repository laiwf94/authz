package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/laiwf94/authz/internal/agents/fakeserver"
	"github.com/laiwf94/authz/internal/authn/fakeidp"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/logging"
	"github.com/laiwf94/authz/internal/platform/logging/logtest"
)

// TestMainOneChain is the platform end to end, as three processes of the
// one binary deployed on a host with a proxy in front: a browser signs in
// through authz gateway, the app behind the proxy asks authz serve whether
// the user may view a document, and on yes calls a tool through authz mcp
// for the user's agent. serve, gateway and mcp write one audit file, so the
// sign-in, the check it led to and the tool call it allowed are records of
// one verified chain, typed by their schemas, under the one correlation ID
// the browser's traceparent started: the proxy passes it to the gateway,
// the gateway's forward-auth answer hands it back for the app, and the app
// passes it to serve and mcp, which passes it to the tool's server.
func TestMainOneChain(t *testing.T) {
	dir := t.TempDir()
	chain := filepath.Join(dir, "audit.jsonl")
	const (
		clientSecret = "one-chain-client-secret-0123456789"
		apiKey       = "one-chain-api-key-0123456789"
		agentKey     = "tgk_one_chain_0123456789abcdefghijklmnop"
		adminToken   = "admin-0123456789abcdefghijklmnopqrstuv"
		auditKey     = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	)
	// None of the secrets may reach the chain.
	logtest.Check(t).Known(clientSecret, apiKey, agentKey, adminToken, auditKey, gatewayCookieKey).File(chain)

	// The proxy's address is the gateway's public URL, so it is reserved
	// first; it starts once the gateway's own address is known.
	proxy := httptest.NewUnstartedServer(nil)
	public := "https://" + proxy.Listener.Addr().String()
	appHost := proxy.Listener.Addr().String()

	// The identity provider, over TLS with a certificate the gateway pins.
	idpSrv := httptest.NewUnstartedServer(nil)
	issuer := "https://" + idpSrv.Listener.Addr().String()
	idp, err := fakeidp.New(fakeidp.Config{Issuer: issuer,
		Clients: []fakeidp.Client{{ID: "authz", Secret: clientSecret, RedirectURIs: []string{public + "/callback/corp"}}}})
	if err != nil {
		t.Fatal(err)
	}
	idpSrv.Config.Handler = idp
	idpSrv.StartTLS()
	defer idpSrv.Close()
	caFile := filepath.Join(dir, "idp-ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idpSrv.Certificate().Raw}), 0o600)

	// The tool's server; it remembers the traceparent of each tools/call.
	box := filepath.Join(dir, "box")
	os.MkdirAll(box, 0o700)
	os.WriteFile(filepath.Join(box, "readme.txt"), []byte("the readme"), 0o600)
	fs, err := fakeserver.New(fakeserver.Config{Sandbox: box})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var upstream []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(peek(r), `"method":"tools/call"`) {
			mu.Lock()
			upstream = append(upstream, r.Header.Get("Traceparent"))
			mu.Unlock()
		}
		fs.ServeHTTP(w, r)
	}))
	defer up.Close()

	// authz serve, recording check decisions.
	serveCmd, serveCh := startChild(t, "authz", "serve", false, "GRANTD_ADDR=127.0.0.1:0", "GRANTD_API_KEYS="+apiKey,
		"GRANTD_DATA_DIR=", "GRANTD_TOKEN_KEY=", "GRANTD_AUDIT_LOG="+chain, "GRANTD_AUDIT_CHECKS=true")
	serveLogs := collect(serveCh)

	// authz mcp, for alice's agent.
	mcpCfg := fmt.Sprintf(`{"tokens":{"issuer":"authz","audience":"one-chain"},
	  "agents":[{"id":"alice-bot","owner":"alice","scopes":["files:read"],"token_sha256":%q}],
	  "upstreams":[{"name":"files","url":"%s/mcp"}]}`, sha256Hex(agentKey), up.URL)
	pol := `{"version":1,"rules":[{"id":"files-read","effect":"allow","scopes":["files:read"],"upstreams":["files"],"tools":["read_file"]}]}`
	os.WriteFile(filepath.Join(dir, "mcp.json"), []byte(mcpCfg), 0o600)
	os.WriteFile(filepath.Join(dir, "policy.json"), []byte(pol), 0o600)
	mcpCmd, mcpCh := startChild(t, "authz", "mcp serve", false, "AUTHZ_MCP_ADDR=127.0.0.1:0", "AUTHZ_MCP_ADMIN_ADDR=127.0.0.1:0",
		"AUTHZ_MCP_ADMIN_TOKEN="+adminToken, "AUTHZ_MCP_CONFIG="+filepath.Join(dir, "mcp.json"),
		"AUTHZ_MCP_POLICY="+filepath.Join(dir, "policy.json"), "AUTHZ_MCP_AUDIT_LOG="+chain,
		"AUTHZ_MCP_AUDIT_KEY="+auditKey, "AUTHZ_MCP_POLICY_POLL=0")
	mcpLogs := collect(mcpCh)

	// authz gateway, signing in through the identity provider.
	gwCfg := fmt.Sprintf(`{"public_url": %q,
	  "providers": [{"id": "corp", "type": "oidc", "issuer": %q, "ca_file": %q, "client_id": "authz", "client_secret_env": "CORP_SECRET"}],
	  "apps": [{"id": "docs", "hosts": [%q], "providers": ["corp"], "allow": {"any_user": true}}]}`, public, issuer, caFile, appHost)
	os.WriteFile(filepath.Join(dir, "gateway.json"), []byte(gwCfg), 0o600)
	gwCmd, gwCh := startChild(t, "authz", "gateway", false, "WICKET_CONFIG="+filepath.Join(dir, "gateway.json"),
		"WICKET_COOKIE_KEYS="+gatewayCookieKey, "WICKET_ADDR=127.0.0.1:0", "WICKET_ADMIN_ADDR=127.0.0.1:0",
		"WICKET_SESSION_FILE="+filepath.Join(dir, "sessions.log"), "WICKET_SIGNING_KEYS=", "WICKET_ADMIN_TOKEN=",
		"CORP_SECRET="+clientSecret, "WICKET_AUDIT_LOG="+chain)
	gwLogs := collect(gwCh)

	serveAddr, mcpAddr, gwAddr := waitAddr(t, serveLogs), waitAddr(t, mcpLogs), waitAddr(t, gwLogs)

	// The document's relationships, written by an operator outside the trace.
	api := func(path, body, traceparent string) map[string]any {
		t.Helper()
		req, _ := http.NewRequest("POST", "http://"+serveAddr+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Content-Type", "application/json")
		if traceparent != "" {
			req.Header.Set("Traceparent", traceparent)
		}
		if path == "/v1/schema" {
			req.Method = "PUT"
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %v", path, resp.StatusCode, out)
		}
		return out
	}
	api("/v1/schema", `{"schema":"definition user {}\ndefinition doc { relation viewer: user\n permission view = viewer }"}`, "")
	api("/v1/relationships/write", `{"updates":[{"op":"touch","relationship":"doc:readme#viewer@user:alice"}]}`, "")

	// The app: it trusts the identity headers the proxy sets, asks serve
	// whether the user may view the document and, if so, has the user's
	// agent read it through mcp. Both calls carry the trace on.
	var appCalls atomic.Int32
	app := func(w http.ResponseWriter, r *http.Request) {
		appCalls.Add(1)
		trace, ok := logging.ParseTraceparent(r.Header.Get("Traceparent"))
		if !ok {
			http.Error(w, "no traceparent from the proxy", http.StatusInternalServerError)
			return
		}
		user := r.Header.Get("X-Auth-User")
		chk := api("/v1/check", fmt.Sprintf(`{"resource":"doc:readme","permission":"view","subject":"user:%s"}`, user),
			logging.Traceparent(trace))
		if chk["allowed"] != true {
			http.Error(w, "not allowed", http.StatusForbidden)
			return
		}
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"files.read_file","arguments":{"path":"readme.txt"},` +
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
		req, _ := http.NewRequest("POST", "http://"+mcpAddr+"/mcp", strings.NewReader(body))
		for k, v := range map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
			"Authorization": "Bearer " + agentKey, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call",
			"Mcp-Name": "files.read_file", "Traceparent": logging.Traceparent(trace)} {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}

	// The proxy, as nginx with auth_request is set up in docs/proxies.md:
	// the gateway's own paths go to the gateway, everything else is
	// authorized by a forward-auth subrequest carrying the client's
	// traceparent, and on 200 the identity headers and the traceparent the
	// gateway answered with go to the app.
	gw, _ := url.Parse("http://" + gwAddr)
	toGateway := httputil.NewSingleHostReverseProxy(gw)
	proxy.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range []string{"/login", "/callback/", "/logout", "/logged-out"} {
			if strings.HasPrefix(r.URL.Path, p) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", r.Host)
				toGateway.ServeHTTP(w, r)
				return
			}
		}
		sub, _ := http.NewRequest("GET", "http://"+gwAddr+"/auth", nil)
		for _, h := range []string{"Cookie", "Traceparent", "Accept"} {
			sub.Header[h] = r.Header[h]
		}
		sub.Header.Set("X-Forwarded-Proto", "https")
		sub.Header.Set("X-Forwarded-Host", r.Host)
		sub.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
		sub.Header.Set("X-Forwarded-Method", r.Method)
		resp, err := http.DefaultClient.Do(sub)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case 200:
		case 401:
			http.Redirect(w, r, resp.Header.Get("X-Auth-Redirect"), http.StatusFound)
			return
		default:
			http.Error(w, "forbidden", resp.StatusCode)
			return
		}
		for _, h := range []string{"X-Auth-User", "X-Auth-Email", "X-Auth-Groups", "Traceparent"} {
			r.Header.Del(h)
			if v := resp.Header.Get(h); v != "" {
				r.Header.Set(h, v)
			}
		}
		app(w, r)
	})
	proxy.StartTLS()
	defer proxy.Close()

	// The browser, traced: every request it makes carries corrTP, the way
	// a traced client starts one trace for a user's action.
	roots := x509.NewCertPool()
	roots.AddCert(proxy.Certificate())
	roots.AddCert(idpSrv.Certificate())
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Transport: &tracing{&http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}}
	get := func(u string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Accept", "text/html")
		resp, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}

	// Not signed in: the proxy sends the browser to sign in, and the
	// redirects end on the identity provider's form.
	resp, page := get(public + "/docs/readme")
	if resp.StatusCode != 200 || !strings.Contains(page, `name="username"`) || appCalls.Load() != 0 {
		t.Fatalf("sign-in page: %d %s", resp.StatusCode, page)
	}
	action, form := loginForm(t, page)
	form.Set("username", "alice")
	form.Set("password", "alice-pass")
	req, _ := http.NewRequest("POST", action, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	resp, err = browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// Back through the callback to the document, which the app served
	// with the agent's tool call.
	if resp.StatusCode != 200 || resp.Request.URL.String() != public+"/docs/readme" || !strings.Contains(string(body), "the readme") {
		t.Fatalf("after sign-in: %d at %s: %s", resp.StatusCode, resp.Request.URL, body)
	}

	stop(t, gwCmd)
	stop(t, mcpCmd)
	stop(t, serveCmd)

	// One chain from three writers, every record typed by its schema.
	raw, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	res, err := audit.VerifyWith(bytes.NewReader(raw), audit.Default())
	if err != nil {
		t.Fatalf("the shared chain does not verify: %v\n%s", err, raw)
	}
	var recs []audit.Record
	tracks := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var r audit.Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
		switch {
		case strings.HasPrefix(r.Event, "authz."):
			tracks["serve"] = true
		case strings.HasPrefix(r.Event, "authn."):
			tracks["gateway"] = true
		default:
			tracks["mcp"] = true
		}
	}
	if uint64(len(recs)) != res.Records || len(tracks) != 3 {
		t.Fatalf("%d records from %v, want records from all three", len(recs), tracks)
	}

	// Under the browser's trace, in order: the sign-in, the check it led to
	// and the tool call that check allowed (its decision and its outcome).
	var traced []audit.Record
	for _, r := range recs {
		if r.CorrelationID == corrTrace {
			traced = append(traced, r)
		}
	}
	type want struct {
		event, actor, subject, action string
		decision                      audit.Decision
	}
	wants := []want{
		{audit.EventLoginSucceeded, "alice", "app:docs", "login", audit.Allow},
		{audit.EventCheckDecided, "", "doc:readme", "view", audit.Allow},
		{"tool_call", "", "", "", ""},
		{"tool_call", "", "", "", ""},
	}
	if len(traced) != len(wants) {
		t.Fatalf("%d records under the trace, want %d:\n%s", len(traced), len(wants), raw)
	}
	for i, w := range wants {
		r := traced[i]
		if r.Event != w.event || (w.actor != "" && r.Actor != w.actor) || r.Subject != w.subject || r.Action != w.action || r.Decision != w.decision {
			t.Errorf("traced record %d: %s %+v, want %+v", i, r.Event, r.Envelope, w)
		}
	}
	var login audit.LoginSucceeded
	var check audit.CheckDecided
	var decided, done audit.ToolCall
	for i, v := range []any{&login, &check, &decided, &done} {
		if err := json.Unmarshal(traced[i].Data, v); err != nil {
			t.Fatal(err)
		}
	}
	if login.Provider != "corp" || login.App != "docs" || login.Session == "" {
		t.Errorf("sign-in: %+v", login)
	}
	if check.Principal != "user:alice" || check.Revision == "" || traced[1].Actor == "" {
		t.Errorf("check: %+v by %q", check, traced[1].Actor)
	}
	if decided.Agent != "alice-bot" || decided.Owner != "alice" || decided.Tool != "read_file" || decided.Decision != "allow" ||
		decided.RuleID != "files-read" || done.Stage == decided.Stage || done.Outcome == "" {
		t.Errorf("tool call: %+v then %+v", decided, done)
	}

	// The same ID is on each process's request line, and reached the tool's
	// server under mcp's own parent ID.
	for name, l := range map[string]*lineLog{"gateway": gwLogs, "serve": serveLogs, "mcp": mcpLogs} {
		if !l.has("request", corrTrace) {
			t.Errorf("%s logged no request line under the trace", name)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(upstream) != 1 {
		t.Fatalf("the tool's server saw %d calls: %q", len(upstream), upstream)
	}
	if id, ok := logging.ParseTraceparent(upstream[0]); !ok || id != corrTrace || upstream[0] == corrTP {
		t.Errorf("upstream traceparent %q, want trace ID %s under a new parent", upstream[0], corrTrace)
	}
}

// tracing sets corrTP on every request, redirects included.
type tracing struct{ next http.RoundTripper }

func (tr *tracing) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Traceparent", corrTP)
	return tr.next.RoundTrip(r)
}

var (
	formAction = regexp.MustCompile(`<form method="post" action="([^"]+)"`)
	formHidden = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)
)

// loginForm returns the identity provider's form action and hidden fields.
func loginForm(t *testing.T, page string) (string, url.Values) {
	t.Helper()
	m := formAction.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no form in %s", page)
	}
	v := url.Values{}
	for _, h := range formHidden.FindAllStringSubmatch(page, -1) {
		v.Set(html.UnescapeString(h[1]), html.UnescapeString(h[2]))
	}
	return html.UnescapeString(m[1]), v
}

// has reports whether a line with message msg carries correlation ID id.
func (l *lineLog) has(msg, id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.lines {
		if m["msg"] == msg && m["correlation_id"] == id {
			return true
		}
	}
	return false
}
