package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/fakeserver"
	"github.com/laiwf94/authz/internal/platform/jose"
)

// e2eIssuer is a local OAuth authorization server for agents on
// 127.0.0.1 over TLS: RFC 8414 metadata, a client_credentials token
// endpoint that mints ES256 access tokens for the RFC 8707 resource the
// client names, and the JWKS it publishes. Its signing key and its
// published keys change separately, as an issuer rotating a key does.
type e2eIssuer struct {
	*httptest.Server
	caFile  string
	clients map[string]string // client_id -> client_secret

	mu        sync.Mutex
	signer    *jose.Signer
	published []*jose.Signer
	fetches   int
}

func newE2EIssuer(t *testing.T, clients map[string]string) *e2eIssuer {
	t.Helper()
	is := &e2eIssuer{clients: clients}
	is.signer = newES256Signer(t)
	is.published = []*jose.Signer{is.signer}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": is.URL, "jwks_uri": is.URL + "/jwks", "token_endpoint": is.URL + "/token",
			"grant_types_supported":                 []string{"client_credentials"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
			"response_types_supported":              []string{"token"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		is.mu.Lock()
		is.fetches++
		first := is.fetches == 1
		keys := make([]map[string]string, 0, len(is.published))
		for _, s := range is.published {
			keys = append(keys, jose.PublicJWK(s.Public(), s.KeyID()))
		}
		is.mu.Unlock()
		if first {
			// A slow first answer, so a gateway that serves before it
			// holds keys is seen to.
			time.Sleep(300 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300")
		json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		oauthErr := func(code int, e string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			fmt.Fprintf(w, `{"error":%q}`, e)
		}
		if r.ParseForm() != nil || r.PostForm.Get("grant_type") != "client_credentials" {
			oauthErr(400, "unsupported_grant_type")
			return
		}
		id := r.PostForm.Get("client_id")
		if secret, ok := is.clients[id]; !ok || secret != r.PostForm.Get("client_secret") {
			oauthErr(401, "invalid_client")
			return
		}
		// RFC 8707: the token is for exactly the one resource asked for.
		res := r.PostForm["resource"]
		if len(res) != 1 {
			oauthErr(400, "invalid_target")
			return
		}
		is.mu.Lock()
		s := is.signer
		is.mu.Unlock()
		now := time.Now().Unix()
		tok, err := s.Sign(map[string]any{"iss": is.URL, "aud": res[0], "sub": id, "scope": r.PostForm.Get("scope"),
			"iat": now, "exp": now + 120, "jti": rand.Text()})
		if err != nil {
			oauthErr(500, "server_error")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 120})
	})
	is.Server = httptest.NewTLSServer(mux)
	t.Cleanup(is.Close)
	is.caFile = filepath.Join(t.TempDir(), "issuer-ca.pem")
	if err := os.WriteFile(is.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: is.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return is
}

func newES256Signer(t *testing.T) *jose.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jose.NewSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// publish sets the keys the JWKS serves; sign sets the key new tokens
// are signed with.
func (is *e2eIssuer) publish(keys ...*jose.Signer) {
	is.mu.Lock()
	is.published = keys
	is.mu.Unlock()
}

func (is *e2eIssuer) sign(s *jose.Signer) {
	is.mu.Lock()
	is.signer = s
	is.mu.Unlock()
}

func (is *e2eIssuer) jwksFetches() int {
	is.mu.Lock()
	defer is.mu.Unlock()
	return is.fetches
}

// freeLoopbackAddr returns a 127.0.0.1 address nothing listens on, for a
// server whose resource identifier must name its port before it starts.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// parseChallenge reads the auth-params of a Bearer challenge (RFC 9110
// §11.2: token or quoted-string values).
func parseChallenge(t *testing.T, h string) map[string]string {
	t.Helper()
	rest, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		t.Fatalf("challenge %q is not Bearer", h)
	}
	out := map[string]string{}
	for rest != "" {
		name, after, ok := strings.Cut(rest, "=")
		if !ok {
			t.Fatalf("challenge %q: no value after %q", h, rest)
		}
		name = strings.TrimSpace(name)
		var val strings.Builder
		if strings.HasPrefix(after, `"`) {
			i := 1
			for ; i < len(after) && after[i] != '"'; i++ {
				if after[i] == '\\' {
					i++
				}
				val.WriteByte(after[i])
			}
			if i >= len(after) {
				t.Fatalf("challenge %q: unterminated quoted string", h)
			}
			after = after[i+1:]
		} else {
			end := strings.IndexByte(after, ',')
			if end < 0 {
				end = len(after)
			}
			val.WriteString(after[:end])
			after = after[end:]
		}
		out[name] = val.String()
		rest = strings.TrimLeft(after, ", ")
	}
	return out
}

// The agent token path end to end, through the built `authz mcp serve`
// and a local authorization server on loopback TLS:
//
//   - an MCP client with only the gateway's URL and its client
//     credentials discovers the authorization server from the 401's
//     resource_metadata (RFC 9728), reads the server's metadata (RFC
//     8414), gets a token for the gateway's resource (RFC 8707) and calls
//     a tool with it; a token the same server minted for another
//     resource is refused;
//   - four agents keep calling while the issuer rotates its signing key:
//     the new key is published next to the old, then tokens are signed
//     with it. No call fails, every agent is served under both keys, and
//     the gateway fetches the key set once for the new kid however many
//     agents present it at once;
//   - a static key the admin API issued while the gateway runs is revoked
//     while its agent keeps calling: every call before the revocation was
//     answered succeeds, and every call after it is refused with an
//     invalid_token challenge; a configured key is revoked the same way,
//     and the issuer's agents carry on;
//   - the audit log the run wrote verifies and records the key changes.
func TestMCPIssuerEndToEnd(t *testing.T) {
	const (
		upToken    = "up-issuer-e2e-0123456789"
		adminToken = "admin-issuer-e2e-0123456789abcdefghijkl"
		staticKey  = "tgk_issuer_e2e_static_key_0123456789abcdefgh"
		scope      = "tools:echo"
		agents     = 4
	)
	clients := map[string]string{}
	for i := 1; i <= agents; i++ {
		clients[fmt.Sprintf("agent-%d", i)] = fmt.Sprintf("secret-%d-%s", i, strings.Repeat("x", 24))
	}
	is := newE2EIssuer(t, clients)

	dir := t.TempDir()
	box, state := filepath.Join(dir, "box"), filepath.Join(dir, "state")
	for _, d := range []string{box, state} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fake, err := fakeserver.New(fakeserver.Config{Sandbox: box, Token: upToken})
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	up := httptest.NewServer(fake)
	defer up.Close()

	addr := freeLoopbackAddr(t)
	resource := "http://" + addr
	cfg := map[string]any{
		"agents": []any{map[string]any{"id": "bot", "owner": "alice", "scopes": []string{scope}, "token_sha256": sha256Hex(staticKey)}},
		"upstreams": []any{map[string]any{"name": "up", "url": up.URL + "/mcp", "credential_env": "UP_TOKEN",
			"tools_ttl_seconds": 3600}},
		"limits": map[string]any{"agent_rps": 100000, "agent_burst": 100000},
		"issuers": []any{map[string]any{"issuer": is.URL, "audience": resource, "jwks_uri": is.URL + "/jwks",
			"algorithms": []string{"ES256"}, "max_ttl_seconds": 600, "private_networks": []string{"127.0.0.1/32"},
			"ca_file": is.caFile}},
		"resource": map[string]any{"url": resource, "scopes_supported": []string{scope}, "name": "End-to-end tools"},
	}
	cfgJSON, _ := json.Marshal(cfg)
	pol := `{"version":1,"rules":[{"id":"echo","effect":"allow","scopes":["` + scope + `"],"upstreams":["up"],"tools":["echo"]}]}`
	for name, body := range map[string]string{"config.json": string(cfgJSON), "policy.json": pol} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	env := []string{
		"AUTHZ_MCP_ADDR=" + addr, "AUTHZ_MCP_ADMIN_ADDR=127.0.0.1:0", "AUTHZ_MCP_ADMIN_TOKEN=" + adminToken,
		"AUTHZ_MCP_CONFIG=" + filepath.Join(dir, "config.json"), "AUTHZ_MCP_POLICY=" + filepath.Join(dir, "policy.json"),
		"AUTHZ_MCP_AUDIT_LOG=" + logPath, "AUTHZ_MCP_AUDIT_KEY=" + strings.Repeat("cd", 32),
		"AUTHZ_MCP_STATE_DIR=" + state, "AUTHZ_MCP_POLICY_POLL=0", "UP_TOKEN=" + upToken,
	}
	for _, k := range []string{"ADDR", "ADMIN_ADDR", "ADMIN_TOKEN", "CONFIG", "POLICY", "AUDIT_LOG", "AUDIT_KEY", "STATE_DIR", "POLICY_POLL", "LOG_LEVEL"} {
		env = append(env, "TOOLGATE_"+k+"=")
	}
	gw, sc := startMain(t, "mcp serve", env...)
	logs, adminAddr := gatewayLogs(t, sc)
	if !strings.Contains(logs.String(), `"listening","addr":"`+addr+`"`) {
		t.Fatalf("not listening on %s: %s", addr, logs.String())
	}
	// The server listens before its JWKS client's first fetch returns; a
	// token that came first would cause a fetch of its own for the kid,
	// which the fetch counts below don't expect.
	eventually(t, "issuer keys loaded at start", func() bool {
		return strings.Contains(logs.String(), `"msg":"jwks keys loaded"`)
	})

	client := &http.Client{Timeout: 10 * time.Second}
	// mcp posts a tools/call of echo with text and returns the HTTP
	// status, the WWW-Authenticate header and whether the tool echoed.
	mcp := func(token, text string) (int, string, bool) {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"up.echo","arguments":{"text":%q},`+
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`, text)
		req, _ := http.NewRequest("POST", resource+"/mcp", strings.NewReader(body))
		for k, v := range map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
			"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "up.echo"} {
			req.Header.Set(k, v)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("tools/call: %v", err)
			return 0, "", false
		}
		defer resp.Body.Close()
		var out struct {
			Result struct{ Content []struct{ Text string } }
		}
		json.NewDecoder(resp.Body).Decode(&out)
		echoed := len(out.Result.Content) == 1 && out.Result.Content[0].Text == text
		return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), echoed
	}
	getJSON := func(c *http.Client, u string, v any) {
		t.Helper()
		resp, err := c.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("GET %s: %d %s", u, resp.StatusCode, b)
		}
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
	}
	idp := is.Client()
	idp.Timeout = 10 * time.Second
	// token asks the token endpoint for a token for res.
	token := func(endpoint, id, res, scope string) string {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {clients[id]},
			"resource": {res}, "scope": {scope}}
		resp, err := idp.PostForm(endpoint, form)
		if err != nil {
			t.Errorf("token: %v", err)
			return ""
		}
		defer resp.Body.Close()
		var out struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
		}
		if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&out) != nil || out.TokenType != "Bearer" {
			t.Errorf("token: status %d", resp.StatusCode)
		}
		return out.AccessToken
	}

	// 1. Discovery from the 401. The client knows the gateway's URL and
	// its client credentials, nothing else.
	code, challenge, _ := mcp("", "hello")
	if code != 401 {
		t.Fatalf("no credentials: %d", code)
	}
	params := parseChallenge(t, challenge)
	if params["resource_metadata"] != resource+"/.well-known/oauth-protected-resource" || params["scope"] != scope ||
		params["error"] != "" {
		t.Fatalf("challenge %q", challenge)
	}
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	getJSON(client, params["resource_metadata"], &prm)
	// RFC 9728 §3.3: the document is for the resource the client called.
	if prm.Resource != resource || len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != is.URL {
		t.Fatalf("protected resource metadata %+v", prm)
	}
	var asm struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
		JWKSURI       string `json:"jwks_uri"`
	}
	// RFC 8414 §3: the well-known segment goes between host and path.
	getJSON(idp, prm.AuthorizationServers[0]+"/.well-known/oauth-authorization-server", &asm)
	if asm.Issuer != prm.AuthorizationServers[0] || asm.TokenEndpoint == "" {
		t.Fatalf("authorization server metadata %+v", asm)
	}
	first := token(asm.TokenEndpoint, "agent-1", prm.Resource, params["scope"])
	if code, _, echoed := mcp(first, "discovered"); code != 200 || !echoed {
		t.Fatalf("call with the discovered token: %d %v", code, echoed)
	}
	// RFC 8707: the same issuer's token for another resource is refused,
	// with the challenge a malformed token gets, so it says nothing about
	// why.
	other := token(asm.TokenEndpoint, "agent-1", "https://other.example", scope)
	code, challenge, _ = mcp(other, "elsewhere")
	_, garbage, _ := mcp("not-a-token", "garbage")
	if code != 401 || parseChallenge(t, challenge)["error"] != "invalid_token" || challenge != garbage {
		t.Fatalf("token for another resource: %d %q, a malformed token gets %q", code, challenge, garbage)
	}
	if n := is.jwksFetches(); n != 1 {
		t.Fatalf("%d JWKS fetches before the rotation, want the one at start", n)
	}

	// 2. Rotation under load.
	k1 := is.signer
	k2 := newES256Signer(t)
	var (
		stop     atomic.Bool
		failures atomic.Int64
		mu       sync.Mutex
		served   = map[string]map[string]int{} // agent -> kid -> calls served
	)
	kidOf := func(tok string) string {
		h, _, _ := strings.Cut(tok, ".")
		b, _ := base64.RawURLEncoding.DecodeString(h)
		var hdr struct{ Kid string }
		json.Unmarshal(b, &hdr)
		return hdr.Kid
	}
	servedUnder := func(kid string, min int) bool {
		mu.Lock()
		defer mu.Unlock()
		for id := range clients {
			if served[id][kid] < min {
				return false
			}
		}
		return true
	}
	var wg sync.WaitGroup
	for id := range clients {
		served[id] = map[string]int{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; !stop.Load(); n++ {
				// A fresh token every third call, so tokens under the old
				// key are still in use after the switch.
				tok := token(asm.TokenEndpoint, id, resource, scope)
				for j := 0; j < 3 && !stop.Load(); j++ {
					code, ch, echoed := mcp(tok, fmt.Sprintf("%s-%d-%d", id, n, j))
					if code != 200 || !echoed {
						failures.Add(1)
						t.Errorf("%s under %s: %d %q", id, kidOf(tok), code, ch)
						continue
					}
					mu.Lock()
					served[id][kidOf(tok)]++
					mu.Unlock()
				}
			}
		}()
	}
	eventually(t, "every agent served under the first key", func() bool { return servedUnder(k1.KeyID(), 5) })
	is.publish(k1, k2)
	eventually(t, "more calls with both keys published", func() bool { return servedUnder(k1.KeyID(), 10) })
	is.sign(k2)
	eventually(t, "every agent served under the new key", func() bool { return servedUnder(k2.KeyID(), 10) })
	stop.Store(true)
	wg.Wait()
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d calls failed during the rotation", n)
	}
	if n := is.jwksFetches(); n != 2 {
		t.Fatalf("%d JWKS fetches, want 2: at start and once for the new kid", n)
	}
	eventually(t, "new key set logged", func() bool {
		return strings.Contains(logs.String(), `"msg":"jwks keys loaded"`) && strings.Contains(logs.String(), k2.KeyID())
	})
	mu.Lock()
	t.Logf("calls served per agent and kid: %v", served)
	mu.Unlock()

	// 3. A static key issued live, then revoked while its agent calls.
	admin := func(method, path, body string, want int) map[string]any {
		t.Helper()
		req, _ := http.NewRequest(method, "http://"+adminAddr+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d %v, want %d", method, path, resp.StatusCode, out, want)
		}
		return out
	}
	version := func() int { return int(admin("GET", "/admin/keys", "", 200)["version"].(float64)) }
	issued := admin("POST", "/admin/keys", fmt.Sprintf(`{"agent":"bot","version":%d}`, version()), 201)["secret"].(string)
	if code, _, echoed := mcp(issued, "issued"); code != 200 || !echoed {
		t.Fatalf("issued key: %d", code)
	}
	var revoked atomic.Bool
	type outcome struct {
		afterRevoke bool // the call started after the revocation was answered
		code        int
		challenge   string
		echoed      bool
	}
	results := make(chan outcome, 10000)
	stop.Store(false)
	go func() {
		defer close(results)
		for n := 0; !stop.Load(); n++ {
			after := revoked.Load()
			code, ch, echoed := mcp(issued, fmt.Sprintf("live-%d", n))
			results <- outcome{after, code, ch, echoed}
			if after && code == 401 && n%8 == 7 {
				stop.Store(true)
			}
		}
	}()
	time.Sleep(200 * time.Millisecond)
	admin("POST", "/admin/keys/"+sha256Hex(issued)[:16]+"/revoke", fmt.Sprintf(`{"version":%d}`, version()), 200)
	revoked.Store(true)
	var before, after int
	for r := range results {
		switch {
		case r.afterRevoke:
			after++
			if r.code != 401 || parseChallenge(t, r.challenge)["error"] != "invalid_token" {
				t.Errorf("a call after the revocation: %d %q", r.code, r.challenge)
			}
		case r.code == 200 && r.echoed:
			before++
		case r.code != 401:
			// Calls in flight while the revocation is applied may go either
			// way; any answer but those two is wrong.
			t.Errorf("a call during the revocation: %d", r.code)
		}
	}
	if before == 0 || after == 0 {
		t.Fatalf("%d calls before and %d after the revocation", before, after)
	}
	t.Logf("issued key: %d calls served before the revocation, %d refused after", before, after)

	// The configured key is revoked the same way; the issuer's agents
	// carry on.
	if code, _, echoed := mcp(staticKey, "configured"); code != 200 || !echoed {
		t.Fatalf("configured key: %d", code)
	}
	admin("POST", "/admin/keys/"+sha256Hex(staticKey)[:16]+"/revoke", fmt.Sprintf(`{"version":%d}`, version()), 200)
	if code, _, _ := mcp(staticKey, "configured"); code != 401 {
		t.Fatalf("revoked configured key: %d", code)
	}
	if code, _, echoed := mcp(token(asm.TokenEndpoint, "agent-2", resource, scope), "still"); code != 200 || !echoed {
		t.Fatalf("issuer token after the revocations: %d", code)
	}

	// 4. A clean stop, and the log the run wrote.
	if err := gw.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitExit(t, gw); err != nil {
		t.Fatalf("gateway exit: %v", err)
	}
	if code, out := runMain(t, "mcp audit verify "+logPath, env...); code != 0 {
		t.Fatalf("authz mcp audit verify exited %d: %s", code, out)
	}
	audit, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"static_key_created"`, `"static_key_revoked"`} {
		if !strings.Contains(string(audit), want) {
			t.Errorf("audit log has no %s record", want)
		}
	}
}

// gatewayLogs keeps every log line of `authz mcp serve` and returns them
// with the admin address once the server listens.
func gatewayLogs(t *testing.T, sc *bufio.Scanner) (*lockedLog, string) {
	t.Helper()
	l := &lockedLog{}
	admin := make(chan string, 1)
	go func() {
		sent := false
		for sc.Scan() {
			l.add(sc.Text())
			var line struct {
				Msg       string
				AdminAddr string `json:"admin_addr"`
			}
			if !sent && json.Unmarshal(sc.Bytes(), &line) == nil && line.Msg == "listening" {
				admin <- line.AdminAddr
				sent = true
			}
		}
		if !sent {
			admin <- ""
		}
	}()
	select {
	case a := <-admin:
		if a == "" {
			t.Fatalf("exited before listening: %s", l.String())
		}
		return l, a
	case <-time.After(10 * time.Second):
		t.Fatalf("did not start: %s", l.String())
		return nil, ""
	}
}

type lockedLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedLog) add(line string) {
	l.mu.Lock()
	l.b.WriteString(line)
	l.b.WriteByte('\n')
	l.mu.Unlock()
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// eventually waits up to 30 s for ok, which polls the running gateway.
func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within 30s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
