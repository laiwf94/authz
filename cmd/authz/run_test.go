package main

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/fakeserver"
	"github.com/laiwf94/authz/internal/authn/fakeidp"
)

// platform is the fixture of the "authz run" tests: the environment for
// all three parts (serve with a data directory, the gateway with a session
// file and a SAML provider, mcp with a state directory, an approval rule and
// a fake upstream), and clients for each part.
type platform struct {
	t      *testing.T
	env    []string
	dir    string
	idp    *httptest.Server
	client *http.Client
}

const (
	runAPIKey     = "run-test-api-key-0123456789"
	runAdminToken = "run-admin-0123456789abcdefghijklmnop"
	runMCPAdmin   = "run-mcp-admin-0123456789abcdefghijklm"
	runAgents     = 4 // agents bot0 to bot3; each round asks as its own, under the open-request limit per agent
	runUpToken    = "up-run-0123456789"
	runPublicURL  = "https://auth.example.com"
	runAppHost    = "app.example.com"
)

func newPlatform(t *testing.T) *platform {
	t.Helper()
	dir := t.TempDir()
	mk := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	data, state, box := mk("data"), mk("state"), mk("box")

	// The gateway signs people in with SAML: the IdP's metadata is a
	// file, so the gateway never calls the IdP and the test's browser
	// carries every message.
	spKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spCert, err := fakeidp.SelfSignedCert(spKey, "sp", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(spKey)
	idpSrv := httptest.NewUnstartedServer(nil)
	idp, err := fakeidp.New(fakeidp.Config{Issuer: "https://" + idpSrv.Listener.Addr().String(),
		ServiceProviders: []fakeidp.ServiceProvider{{EntityID: runPublicURL + "/saml/partner/metadata",
			ACSURL: runPublicURL + "/saml/partner/acs", SignAssertion: true, SignResponse: true}}})
	if err != nil {
		t.Fatal(err)
	}
	idpSrv.Config.Handler = idp
	idpSrv.StartTLS()
	t.Cleanup(idpSrv.Close)
	gwCfg, _ := json.Marshal(map[string]any{
		"public_url": runPublicURL,
		"providers": []any{map[string]any{"id": "partner", "type": "saml", "display_name": "Partner",
			"idp_metadata_file": write("idp.xml", idp.Metadata()),
			"sp_key_file":       write("sp-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
			"sp_cert_file":      write("sp.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: spCert.Raw})),
			"email_attribute":   "email", "name_attribute": "displayName", "groups_attribute": "groups"}},
		"apps": []any{map[string]any{"id": "app", "hosts": []string{runAppHost}, "providers": []string{"partner"},
			"allow": map[string]any{"any_user": true}}},
	})

	fake, err := fakeserver.New(fakeserver.Config{Sandbox: box, Token: runUpToken})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Close() })
	up := httptest.NewServer(fake)
	t.Cleanup(up.Close)
	var agents []string
	for i := range runAgents {
		agents = append(agents, fmt.Sprintf(`{"id":"bot%d","owner":"alice","scopes":["s"],"token_sha256":%q}`, i, sha256Hex(agentKey(i))))
	}
	mcpCfg := fmt.Sprintf(`{"tokens":{"issuer":"authz","audience":"run-test"},
	  "agents":[%s],
	  "upstreams":[{"name":"up","url":"%s/mcp","credential_env":"UP_TOKEN","max_concurrency":32,"tools_ttl_seconds":3600}],
	  "limits":{"agent_rps":100000,"agent_burst":100000,"tool_rps":100000,"tool_burst":100000,"daily_quota":10000000},
	  "approvals":{"wait_seconds":0,"pending_ttl_seconds":600,"max_grant_ttl_seconds":600}}`, strings.Join(agents, ","), up.URL)
	pol := `{"version":1,"rules":[{"id":"echo","effect":"allow","scopes":["s"],"upstreams":["up"],"tools":["echo"],"requires_approval":true}]}`

	env := []string{
		"AUTHZ_CONFIG=",
		"GRANTD_ADDR=127.0.0.1:0", "GRANTD_API_KEYS=" + runAPIKey, "GRANTD_DATA_DIR=" + data, "GRANTD_TOKEN_KEY=" + strings.Repeat("ab", 32),
		"GRANTD_AUDIT_LOG=",
		"WICKET_CONFIG=" + write("wicket.json", gwCfg), "WICKET_COOKIE_KEYS=" + gatewayCookieKey,
		"WICKET_ADDR=127.0.0.1:0", "WICKET_ADMIN_ADDR=127.0.0.1:0", "WICKET_ADMIN_TOKEN=" + runAdminToken,
		"WICKET_SESSION_FILE=" + filepath.Join(dir, "sessions.log"), "WICKET_SIGNING_KEYS=", "WICKET_AUDIT_LOG=",
		"WICKET_LOGIN_RATE=100000",
		"AUTHZ_MCP_ADDR=127.0.0.1:0", "AUTHZ_MCP_ADMIN_ADDR=127.0.0.1:0", "AUTHZ_MCP_ADMIN_TOKEN=" + runMCPAdmin,
		"AUTHZ_MCP_CONFIG=" + write("mcp.json", []byte(mcpCfg)), "AUTHZ_MCP_POLICY=" + write("policy.json", []byte(pol)),
		"AUTHZ_MCP_AUDIT_LOG=" + filepath.Join(dir, "mcp-audit.jsonl"), "AUTHZ_MCP_AUDIT_KEY=" + strings.Repeat("cd", 32),
		"AUTHZ_MCP_STATE_DIR=" + state, "AUTHZ_MCP_POLICY_POLL=0", "UP_TOKEN=" + runUpToken,
	}
	for _, k := range []string{"ADDR", "ADMIN_ADDR", "ADMIN_TOKEN", "CONFIG", "POLICY", "AUDIT_LOG", "AUDIT_KEY", "STATE_DIR", "POLICY_POLL", "LOG_LEVEL"} {
		env = append(env, "TOOLGATE_"+k+"=")
	}
	for _, p := range []string{"GRANTD_", "WICKET_", "TOOLGATE_", "AUTHZ_MCP_", "AUTHZ_"} {
		for _, s := range []string{"TLS_CERT", "TLS_KEY", "TLS_CLIENT_CA", "DRAIN_DELAY", "DRAIN_TIMEOUT"} {
			env = append(env, p+s+"=")
		}
	}
	return &platform{t: t, env: env, dir: dir, idp: idpSrv,
		client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// running is one "authz run" process and its five listeners.
type running struct {
	cmd                                   *exec.Cmd
	api, public, gwAdmin, agent, mcpAdmin string
	lines                                 *lineLog
}

// start runs "authz run" in a child process and waits for its "running"
// line.
func (p *platform) start() *running {
	t := p.t
	t.Helper()
	cmd, sc := startMain(t, "run", p.env...)
	ch := make(chan map[string]any, 1024)
	go func() {
		defer close(ch)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				ch <- m
			}
		}
	}()
	logs := collect(ch)
	addrs := waitRunning(t, logs)
	if len(addrs) != 5 {
		t.Fatalf("running line has %d addresses, want 5: %v", len(addrs), addrs)
	}
	return &running{cmd: cmd, api: addrs[0], public: addrs[1], gwAdmin: addrs[2], agent: addrs[3], mcpAdmin: addrs[4], lines: logs}
}

func waitRunning(t *testing.T, l *lineLog) []string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		for _, m := range l.lines {
			if m["msg"] == "running" && m["subcommand"] == "run" {
				l.mu.Unlock()
				var out []string
				for _, a := range m["addrs"].([]any) {
					out = append(out, a.(string))
				}
				return out
			}
		}
		l.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("authz run did not start")
	return nil
}

func (r *running) kill(t *testing.T) {
	t.Helper()
	if err := r.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitExit(t, r.cmd)
}

// do sends one request and returns the status and body, or ok false when
// no answer came (the process was killed).
func (p *platform) do(method, u, token, contentType, body string, hdr map[string]string) (int, []byte, http.Header, bool) {
	req, err := http.NewRequest(method, u, strings.NewReader(body))
	if err != nil {
		p.t.Error(err)
		return 0, nil, nil, false
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, nil, false
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, false
	}
	return resp.StatusCode, b, resp.Header, true
}

func (p *platform) mustDo(method, u, token, contentType, body string) (int, []byte) {
	p.t.Helper()
	code, b, _, ok := p.do(method, u, token, contentType, body, nil)
	if !ok {
		p.t.Fatalf("%s %s: no answer", method, u)
	}
	return code, b
}

var (
	runHiddenRe = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)
	runActionRe = regexp.MustCompile(`<form method="post" action="([^"]+)">`)
)

func runForm(body string) (string, url.Values) {
	f := url.Values{}
	for _, m := range runHiddenRe.FindAllStringSubmatch(body, -1) {
		f.Set(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	action := ""
	if m := runActionRe.FindStringSubmatch(body); m != nil {
		action = html.UnescapeString(m[1])
	}
	return action, f
}

func cookieHeader(cs []*http.Cookie) string {
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = c.Name + "=" + c.Value
	}
	return strings.Join(parts, "; ")
}

// login signs alice in at the gateway with SAML, as a browser would, and
// returns her session cookie. ok is false when the gateway did not answer
// (it was killed); the login is acknowledged only once the gateway has
// answered the assertion with its session cookie.
func (p *platform) login(public string) (string, bool) {
	t := p.t
	code, _, hdr, ok := p.do("GET", "http://"+public+"/login?app=app&provider=partner", "", "", "", map[string]string{"Accept": "text/html"})
	if !ok {
		return "", false
	}
	if code != http.StatusFound {
		t.Errorf("login: %d", code)
		return "", false
	}
	state := (&http.Response{Header: hdr}).Cookies()
	idp := p.idp.Client()
	resp, err := idp.Get(hdr.Get("Location"))
	if err != nil {
		t.Error(err)
		return "", false
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	action, fields := runForm(string(body))
	fields.Set("username", "alice")
	fields.Set("password", "alice-pass")
	resp, err = idp.PostForm(action, fields)
	if err != nil {
		t.Error(err)
		return "", false
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	acs, post := runForm(string(body))
	if acs != runPublicURL+"/saml/partner/acs" || post.Get("SAMLResponse") == "" {
		t.Errorf("IdP answered %d without a SAML post form: %.200s", resp.StatusCode, body)
		return "", false
	}
	code, _, hdr, ok = p.do("POST", "http://"+public+"/saml/partner/acs", "", "application/x-www-form-urlencoded", post.Encode(),
		map[string]string{"Cookie": cookieHeader(state)})
	if !ok {
		return "", false
	}
	if code != http.StatusSeeOther {
		t.Errorf("ACS: %d", code)
		return "", false
	}
	for _, c := range (&http.Response{Header: hdr}).Cookies() {
		if strings.Contains(c.Name, "wicket") && c.Value != "" && c.MaxAge >= 0 {
			return c.Name + "=" + c.Value, true
		}
	}
	t.Errorf("ACS set no session cookie: %v", hdr["Set-Cookie"])
	return "", false
}

// forwardAuth asks the gateway, as nginx does, whether the session cookie
// lets its holder into the app.
func (p *platform) forwardAuth(public, cookie string) int {
	p.t.Helper()
	code, _, _, ok := p.do("GET", "http://"+public+"/auth", "", "", "", map[string]string{
		"X-Forwarded-Proto": "https", "X-Forwarded-Host": runAppHost, "X-Forwarded-Uri": "/", "Cookie": cookie})
	if !ok {
		p.t.Fatal("forward-auth: no answer")
	}
	return code
}

// callEcho calls up.echo through mcp and returns the approval the call is
// waiting for, or ran true when it ran.
func (p *platform) callEcho(agent string, bot int, text string) (approval string, ran bool) {
	p.t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"up.echo","arguments":{"text":%q},`+
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`, text)
	code, b, _, ok := p.do("POST", "http://"+agent+"/mcp", agentKey(bot), "application/json", body, map[string]string{
		"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "up.echo"})
	if !ok || code != 200 {
		p.t.Fatalf("tools/call %q: %d %v %s", text, code, ok, b)
	}
	var out struct {
		Result *struct{ Content []struct{ Text string } }
		Error  *struct {
			Code int
			Data struct {
				ApprovalID string `json:"approval_id"`
			}
		}
	}
	if err := json.Unmarshal(b, &out); err != nil {
		p.t.Fatalf("tools/call %q: %v: %s", text, err, b)
	}
	if out.Error != nil {
		if out.Error.Code != -31004 || out.Error.Data.ApprovalID == "" {
			p.t.Fatalf("tools/call %q: %s", text, b)
		}
		return out.Error.Data.ApprovalID, false
	}
	return "", out.Result != nil && len(out.Result.Content) == 1 && out.Result.Content[0].Text == text
}

func (p *platform) approval(admin, id string) string {
	p.t.Helper()
	code, b := p.mustDo("GET", "http://"+admin+"/admin/approvals/"+id, runMCPAdmin, "", "")
	var out struct{ Status string }
	if code != 200 || json.Unmarshal(b, &out) != nil {
		p.t.Fatalf("approval %s: %d %s", id, code, b)
	}
	return out.Status
}

// agentKey is the static key of agent bot<i>.
func agentKey(i int) string { return fmt.Sprintf("tgk_run_test_agent%d_0123456789abcdefghijklm", i) }

const runSchema = "definition user {}\n\ndefinition doc {\n  relation viewer: user\n  permission view = viewer\n}\n"

func (p *platform) writeSchema(api string) {
	p.t.Helper()
	b, _ := json.Marshal(map[string]string{"schema": runSchema})
	if code, body := p.mustDo("PUT", "http://"+api+"/v1/schema", runAPIKey, "application/json", string(b)); code != 200 {
		p.t.Fatalf("schema: %d %s", code, body)
	}
}

// checkAll checks, fully consistent, that every relationship lets its
// subject view its doc.
func (p *platform) checkAll(api string, rels []string) {
	t := p.t
	t.Helper()
	for chunk := range slices.Chunk(rels, 100) {
		var items []map[string]string
		for _, r := range chunk {
			res, subj, _ := strings.Cut(r, "#viewer@")
			items = append(items, map[string]string{"resource": res, "permission": "view", "subject": subj})
		}
		b, _ := json.Marshal(map[string]any{"items": items, "consistency": map[string]string{"mode": "fully_consistent"}})
		code, body := p.mustDo("POST", "http://"+api+"/v1/check/bulk", runAPIKey, "application/json", string(b))
		var out struct{ Results []struct{ Allowed bool } }
		if code != 200 || json.Unmarshal(body, &out) != nil || len(out.Results) != len(chunk) {
			t.Fatalf("bulk check: %d %s", code, body)
		}
		for i, r := range out.Results {
			if !r.Allowed {
				t.Errorf("acknowledged relationship %s was lost", chunk[i])
			}
		}
	}
}

// familySet returns the metric families a /metrics exposition declares.
func familySet(t *testing.T, body []byte) []string {
	t.Helper()
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 4 && f[0] == "#" && f[1] == "TYPE" {
			out = append(out, f[2])
		}
	}
	slices.Sort(out)
	return out
}

// TestRunOneProcess: "authz run" starts serve, gateway and mcp in one
// process. Each part answers on its own listeners, every /metrics is the
// one registry with the metrics of all three, each log line names its
// part, and SIGTERM flips every readiness probe and drains every listener
// before a clean exit 0.
func TestRunOneProcess(t *testing.T) {
	p := newPlatform(t)
	r := p.start()
	p.writeSchema(r.api)
	if cookie, ok := p.login(r.public); !ok || p.forwardAuth(r.public, cookie) != 200 {
		t.Fatalf("sign-in through the gateway: %v", ok)
	}
	if id, _ := p.callEcho(r.agent, 0, "hello"); id == "" {
		t.Fatal("no approval asked for")
	}
	scrape := func() [][]string {
		var sets [][]string
		for _, ep := range []struct{ url, token string }{
			{"http://" + r.api + "/metrics", runAPIKey},
			{"http://" + r.gwAdmin + "/metrics", runAdminToken},
			{"http://" + r.mcpAdmin + "/metrics", runMCPAdmin},
		} {
			code, body := p.mustDo("GET", ep.url, ep.token, "", "")
			if code != 200 {
				t.Fatalf("%s: %d", ep.url, code)
			}
			sets = append(sets, familySet(t, body))
		}
		return sets
	}
	scrape() // every /metrics route has a series from here on
	sets := scrape()
	for i, s := range sets {
		for _, want := range []string{"grantd_http_requests_total", "grantd_head_revision", "wicket_logins_total",
			"wicket_sessions", "toolgate_http_requests_total", "toolgate_approvals_pending"} {
			if !slices.Contains(s, want) {
				t.Errorf("/metrics %d lacks %s: %v", i, want, s)
			}
		}
		if !slices.Equal(s, sets[0]) {
			t.Errorf("/metrics %d declares other families than /metrics 0:\n%v\n%v", i, s, sets[0])
		}
	}

	parts := map[string]bool{}
	r.lines.mu.Lock()
	for _, m := range r.lines.lines {
		sub, _ := m["subcommand"].(string)
		if sub == "" {
			t.Errorf("a line without a subcommand: %v", m)
		}
		if m["msg"] == "listening" {
			parts[sub] = true
		}
	}
	r.lines.mu.Unlock()
	if len(parts) != 3 || !parts["serve"] || !parts["gateway"] || !parts["mcp"] {
		t.Errorf("listening lines from %v, want serve, gateway and mcp", parts)
	}

	if err := r.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitExit(t, r.cmd); err != nil {
		t.Fatalf("exit after SIGTERM: %v", err)
	}
	stopped := waitField(t, r.lines, "stopped", "subcommand")
	if stopped != "run" {
		t.Fatalf("stopped line from %q", stopped)
	}
}

// TestRunSurvivesSIGKILLMidWrite: "authz run" is killed with SIGKILL while
// all three parts are writing (relationships to serve's log, sign-ins to
// the gateway's session log, approval decisions to mcp's approval log) and
// restarted on the same files, round after round. Every write acknowledged
// before a kill is there after every later restart:
//
//   - each relationship serve answered 200 for is checked allowed, fully
//     consistent;
//   - each session cookie the gateway set still passes forward-auth;
//   - each approval mcp answered 200 for is still approved, and pending
//     requests are still pending.
//
// Writes the kill interrupted were never acknowledged and are not
// checked. The kill comes only once every part has acknowledged writes in
// that round, so it always lands mid-write.
func TestRunSurvivesSIGKILLMidWrite(t *testing.T) {
	const rounds = runAgents
	p := newPlatform(t)
	r := p.start()
	p.writeSchema(r.api)

	var (
		rels     []string // acknowledged relationships
		cookies  []string // acknowledged sessions
		approved []string // acknowledged approvals
		pending  []string // requests the kill left undecided, until denied
		denied   []string // acknowledged denials
	)
	rng := rand.New(rand.NewPCG(7, uint64(time.Now().UnixNano())))
	for round := range rounds {
		// Requests to decide during the round, opened before it.
		var open []string
		for i := range 12 { // under mcp's limit of open requests per agent
			id, _ := p.callEcho(r.agent, round, fmt.Sprintf("r%d-%d", round, i))
			open = append(open, id)
		}

		var (
			mu                     sync.Mutex
			nRel, nSess, nApproval atomic.Int64
			stop                   atomic.Bool
			wg                     sync.WaitGroup
			decided                = map[string]bool{}
		)
		for w := range 4 {
			wg.Go(func() {
				for k := 0; !stop.Load(); k++ {
					rel := fmt.Sprintf("doc:r%dw%dn%d#viewer@user:u%d", round, w, k, k%7)
					body := fmt.Sprintf(`{"updates":[{"op":"touch","relationship":%q}]}`, rel)
					code, _, _, ok := p.do("POST", "http://"+r.api+"/v1/relationships/write", runAPIKey, "application/json", body, nil)
					if !ok {
						return
					}
					if code != 200 {
						t.Errorf("write %s: %d", rel, code)
						return
					}
					mu.Lock()
					rels = append(rels, rel)
					mu.Unlock()
					nRel.Add(1)
				}
			})
		}
		for range 2 {
			wg.Go(func() {
				for !stop.Load() {
					c, ok := p.login(r.public)
					if !ok {
						return
					}
					mu.Lock()
					cookies = append(cookies, c)
					mu.Unlock()
					nSess.Add(1)
				}
			})
		}
		ids := make(chan string, len(open))
		for _, id := range open {
			ids <- id
		}
		close(ids)
		for range 2 {
			wg.Go(func() {
				for id := range ids {
					if stop.Load() {
						return
					}
					code, body, _, ok := p.do("POST", "http://"+r.mcpAdmin+"/admin/approvals/"+id+"/approve", runMCPAdmin,
						"application/json", `{"ttl_seconds":600}`, nil)
					if !ok {
						return
					}
					if code != 200 {
						t.Errorf("approve %s: %d %s", id, code, body)
						return
					}
					mu.Lock()
					approved = append(approved, id)
					decided[id] = true
					mu.Unlock()
					nApproval.Add(1)
					time.Sleep(10 * time.Millisecond) // spread the decisions over the round
				}
			})
		}
		deadline := time.Now().Add(20 * time.Second)
		for nRel.Load() < 20 || nSess.Load() < 2 || nApproval.Load() < 2 {
			if time.Now().After(deadline) {
				t.Fatalf("round %d: too few writes acknowledged: %d relationships, %d sessions, %d approvals",
					round, nRel.Load(), nSess.Load(), nApproval.Load())
			}
			time.Sleep(time.Millisecond)
		}
		time.Sleep(time.Duration(rng.IntN(20)) * time.Millisecond)
		r.kill(t)
		stop.Store(true)
		wg.Wait()
		mu.Lock()
		for _, id := range open {
			if !decided[id] {
				pending = append(pending, id)
			}
		}
		mu.Unlock()
		t.Logf("round %d: killed after %d relationships, %d sessions and %d approvals acknowledged",
			round, nRel.Load(), nSess.Load(), nApproval.Load())

		r = p.start()
		p.checkAll(r.api, rels)
		for _, c := range cookies {
			if code := p.forwardAuth(r.public, c); code != 200 {
				t.Errorf("acknowledged session lost: forward-auth %d", code)
			}
		}
		for _, id := range approved {
			if st := p.approval(r.mcpAdmin, id); st != "approved" {
				t.Errorf("acknowledged approval %s is %q after the restart", id, st)
			}
		}
		for _, id := range denied {
			if st := p.approval(r.mcpAdmin, id); st != "denied" {
				t.Errorf("acknowledged denial %s is %q after the restart", id, st)
			}
		}
		// An approval the kill interrupted may or may not have been
		// written; every other request is still pending. Deny those, so
		// the open requests stay under the limit, and check the denials
		// after the next kill.
		for _, id := range pending {
			switch st := p.approval(r.mcpAdmin, id); st {
			case "approved":
			case "pending":
				if code, body := p.mustDo("POST", "http://"+r.mcpAdmin+"/admin/approvals/"+id+"/deny", runMCPAdmin,
					"application/json", `{"note":"left over"}`); code != 200 {
					t.Fatalf("deny %s: %d %s", id, code, body)
				}
				denied = append(denied, id)
			default:
				t.Errorf("request %s is %q after the restart, want pending", id, st)
			}
		}
		pending = nil
		if t.Failed() {
			t.FailNow()
		}
	}

	// The gateway counts the sessions it brought back.
	code, body := p.mustDo("GET", "http://"+r.gwAdmin+"/admin/sessions?limit=1000", runAdminToken, "", "")
	var list struct{ Sessions []json.RawMessage }
	if code != 200 || json.Unmarshal(body, &list) != nil || len(list.Sessions) < len(cookies) {
		t.Fatalf("admin sessions: %d, %d listed for %d acknowledged", code, len(list.Sessions), len(cookies))
	}
	if err := r.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitExit(t, r.cmd); err != nil {
		t.Fatalf("exit after SIGTERM: %v", err)
	}
	if code, out := runMain(t, "mcp audit verify "+filepath.Join(p.dir, "mcp-audit.jsonl"), p.env...); code != 0 {
		t.Fatalf("the MCP audit chain does not verify after %d kills: %s", rounds, out)
	}
}
