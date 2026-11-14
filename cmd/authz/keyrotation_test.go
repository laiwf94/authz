//go:build unix

package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/jose"
	"github.com/laiwf94/authz/internal/platform/keys"
)

// rotationFixture is what TestRunRotatesEveryKey shares between its
// clients: the running process, the keys file, the failures seen and how
// much each kind of credential was used across a rotation.
type rotationFixture struct {
	p        *platform
	r        *running
	keysFile string

	mu     sync.Mutex
	failed []string
	fails  atomic.Int64
	// requests and crossed count, per kind, the requests made and those
	// made with a credential issued more than a rotation period earlier.
	requests, crossed map[string]*atomic.Int64
}

// The rotation policy of every ring in the test: a new key each second,
// and a retired key verifies for four more.
const (
	rotEvery   = time.Second
	rotOverlap = 4 * time.Second
	// rotReuse is how long a client keeps using one credential: past two
	// rotations, well inside the overlap.
	rotReuse = 2500 * time.Millisecond
)

func (f *rotationFixture) fail(format string, a ...any) {
	f.fails.Add(1)
	f.mu.Lock()
	if len(f.failed) < 20 {
		f.failed = append(f.failed, fmt.Sprintf(format, a...))
	}
	f.mu.Unlock()
}

func (f *rotationFixture) count(kind string, issued time.Time) {
	f.requests[kind].Add(1)
	if time.Since(issued) > rotEvery {
		f.crossed[kind].Add(1)
	}
}

// currentKids reads the keys file and returns the current key of each ring.
func (f *rotationFixture) currentKids() (map[string]string, error) {
	s, err := keys.Load(f.keysFile)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, name := range []string{keys.RingConsistency, keys.RingSession, keys.RingUpstream, keys.RingAgent} {
		if r := s.Ring(name); r != nil {
			out[name] = r.Current().ID()
		}
	}
	return out, nil
}

// logins signs people in through the gateway's SAML flow, whose state
// cookie is sealed on the session ring at /login and opened at the ACS,
// and asks forward-auth with each session cookie for up to rotReuse. Every
// answer must be 200 with an upstream token that verifies against a JWKS
// fetched at most a rotation period earlier.
func (f *rotationFixture) logins(stop *atomic.Bool) {
	var (
		ks      *jose.KeySet
		fetched time.Time
		cookie  string
		sealed  time.Time
	)
	for !stop.Load() {
		if time.Since(fetched) > rotEvery {
			code, b, _, ok := f.p.do("GET", "http://"+f.r.public+"/.well-known/jwks.json", "", "", "", nil)
			set, err := jose.ParseKeySet(b)
			if !ok || code != 200 || err != nil {
				f.fail("jwks: %d %v %v", code, ok, err)
				return
			}
			ks, fetched = set, time.Now()
		}
		if time.Since(sealed) > rotReuse {
			c, ok := f.p.login(f.r.public)
			f.count("login", time.Now())
			if !ok {
				f.fail("login failed")
				return
			}
			cookie, sealed = c, time.Now()
		}
		code, _, hdr, ok := f.p.do("GET", "http://"+f.r.public+"/auth", "", "", "", map[string]string{
			"X-Forwarded-Proto": "https", "X-Forwarded-Host": runAppHost, "X-Forwarded-Uri": "/", "Cookie": cookie})
		f.count("forward-auth", sealed)
		tok := ""
		if hdr != nil {
			tok = hdr.Get("X-Auth-Token")
		}
		switch {
		case !ok:
			f.fail("forward-auth: no answer")
			return
		case code != 200:
			f.fail("forward-auth with a cookie sealed %v earlier: %d", time.Since(sealed), code)
		case !upstreamVerifies(ks, tok):
			f.fail("upstream token %.40s… not in a JWKS fetched %v earlier", tok, time.Since(fetched))
		}
	}
}

func upstreamVerifies(ks *jose.KeySet, tok string) bool {
	pt, err := jose.Parse(tok)
	if err != nil || ks == nil {
		return false
	}
	for _, k := range ks.Keys {
		if k.ID == pt.Header.Kid {
			return pt.Verify(k, []string{"ES256"}) == nil
		}
	}
	return false
}

// checks writes relationships and checks each one with the consistency
// token its write returned, kept for up to rotReuse, so most checks read a
// token sealed by a key that has since stopped signing.
func (f *rotationFixture) checks(w int, stop *atomic.Bool) {
	type written struct {
		rel, token string
		at         time.Time
	}
	var held []written
	for k := 0; !stop.Load(); k++ {
		if len(held) == 0 || time.Since(held[len(held)-1].at) > 200*time.Millisecond {
			rel := fmt.Sprintf("doc:w%dn%d#viewer@user:u%d", w, k, k%5)
			code, b, _, ok := f.p.do("POST", "http://"+f.r.api+"/v1/relationships/write", runAPIKey, "application/json",
				fmt.Sprintf(`{"updates":[{"op":"touch","relationship":%q}]}`, rel), nil)
			var out struct {
				WrittenAt string `json:"written_at"`
			}
			if !ok || code != 200 || json.Unmarshal(b, &out) != nil || out.WrittenAt == "" {
				f.fail("write %s: %d %v %s", rel, code, ok, b)
				return
			}
			held = append(held, written{rel, out.WrittenAt, time.Now()})
		}
		for len(held) > 1 && time.Since(held[0].at) > rotReuse {
			held = held[1:]
		}
		c := held[k%len(held)]
		res, subj, _ := strings.Cut(c.rel, "#viewer@")
		body, _ := json.Marshal(map[string]any{"resource": res, "permission": "view", "subject": subj,
			"consistency": map[string]string{"mode": "at_least_as_fresh", "token": c.token}})
		code, b, _, ok := f.p.do("POST", "http://"+f.r.api+"/v1/check", runAPIKey, "application/json", string(body), nil)
		f.count("check", c.at)
		var out struct {
			Allowed   bool   `json:"allowed"`
			CheckedAt string `json:"checked_at"`
		}
		if !ok || code != 200 || json.Unmarshal(b, &out) != nil || !out.Allowed || out.CheckedAt == "" {
			f.fail("check %s with a token from %v earlier: %d %v %s", c.rel, time.Since(c.at), code, ok, b)
		}
	}
}

// agentToken is a signed agent token and when it was minted.
type agentToken struct {
	tok string
	at  time.Time
}

// mints mints agent tokens with "authz mcp token mint", which signs with
// the current key of the agent ring in the keys file, and publishes them
// to the MCP clients.
func (f *rotationFixture) mints(t *testing.T, latest *atomic.Pointer[agentToken], stop *atomic.Bool) {
	for !stop.Load() {
		code, out, errOut := runToEnd(t, "mcp token mint -sub ci-bot -scope s -ttl 1m", f.p.env...)
		tok := strings.TrimSpace(out)
		if code != 0 || strings.Count(tok, ".") != 2 {
			f.fail("token mint: exit %d: %s", code, errOut)
			return
		}
		latest.Store(&agentToken{tok, time.Now()})
		time.Sleep(150 * time.Millisecond)
	}
}

// mcpCalls lists the tools through mcp with a signed agent token, keeping
// each token for up to rotReuse.
func (f *rotationFixture) mcpCalls(latest *atomic.Pointer[agentToken], stop *atomic.Bool) {
	var cur *agentToken
	for !stop.Load() {
		if l := latest.Load(); cur == nil || time.Since(cur.at) > rotReuse {
			cur = l
		}
		code, b, _, ok := f.p.do("POST", "http://"+f.r.agent+"/mcp", cur.tok, "application/json",
			`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			map[string]string{"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"})
		f.count("mcp", cur.at)
		var out struct {
			Result *struct {
				Tools []struct{ Name string } `json:"tools"`
			} `json:"result"`
		}
		if !ok || code != 200 || json.Unmarshal(b, &out) != nil || out.Result == nil || len(out.Result.Tools) == 0 {
			f.fail("tools/list with a token minted %v earlier: %d %v %s", time.Since(cur.at), code, ok, b)
		}
	}
}

// TestRunRotatesEveryKey: "authz run" with serve, the gateway and mcp on
// one keys file rotates every key it holds, each ring every second with a
// four-second overlap, while clients sign people in, check relationships
// and call tools, and nothing fails:
//
//   - consistency ring: every check with a token a write returned up to
//     2.5 s earlier is answered, allowed;
//   - session ring: every SAML sign-in completes (its state cookie sealed
//     at /login and opened at the ACS), and every forward-auth with a
//     session cookie sealed up to 2.5 s earlier passes;
//   - upstream ring: every upstream token forward-auth returns verifies
//     against a JWKS fetched at most a rotation period earlier;
//   - agent ring: every tools/list with an agent token minted from the
//     file up to 2.5 s earlier is answered.
//
// Each ring's current key changes at least twice during the run (a ring
// rotates on the first one-second check after its key is due),
// every kind of credential is used across a rotation, the keys file is
// never refused a write, and SIGTERM still stops the process cleanly.
func TestRunRotatesEveryKey(t *testing.T) {
	if testing.Short() {
		t.Skip("rotates for several seconds")
	}
	p := newPlatform(t)
	kf := filepath.Join(p.dir, "keys.json")
	every, overlap := rotEvery.String(), rotOverlap.String()
	p.env = append(p.env,
		"GRANTD_TOKEN_KEY=", "GRANTD_KEYS_FILE="+kf, "GRANTD_TOKEN_ROTATE_EVERY="+every, "GRANTD_TOKEN_OVERLAP="+overlap,
		"WICKET_KEYS_FILE="+kf, "WICKET_COOKIE_ROTATE_EVERY="+every, "WICKET_COOKIE_OVERLAP="+overlap,
		"WICKET_SIGNING_ROTATE_EVERY="+every, "WICKET_SIGNING_OVERLAP="+overlap,
		"TOOLGATE_SIGNING_KEYS=", "TOOLGATE_KEYS_FILE=", "TOOLGATE_SIGNING_ROTATE_EVERY=", "TOOLGATE_SIGNING_OVERLAP=",
		"AUTHZ_MCP_KEYS_FILE="+kf, "AUTHZ_MCP_SIGNING_ROTATE_EVERY="+every, "AUTHZ_MCP_SIGNING_OVERLAP="+overlap,
		"GRANTD_LOG_LEVEL=info", "WICKET_LOG_LEVEL=info", "AUTHZ_MCP_LOG_LEVEL=info")
	f := &rotationFixture{p: p, keysFile: kf, requests: map[string]*atomic.Int64{}, crossed: map[string]*atomic.Int64{}}
	for _, k := range []string{"login", "forward-auth", "check", "mcp"} {
		f.requests[k], f.crossed[k] = new(atomic.Int64), new(atomic.Int64)
	}
	f.r = p.start()
	p.writeSchema(f.r.api)

	start, err := f.currentKids()
	if err != nil {
		t.Fatal(err)
	}
	if len(start) != 4 {
		t.Fatalf("keys file holds rings %v, want consistency, session, upstream and agent", start)
	}

	var (
		stop   atomic.Bool
		latest atomic.Pointer[agentToken]
		wg     sync.WaitGroup
	)
	code, out, errOut := runToEnd(t, "mcp token mint -sub ci-bot -scope s -ttl 1m", p.env...)
	if code != 0 {
		t.Fatalf("token mint: exit %d: %s", code, errOut)
	}
	latest.Store(&agentToken{strings.TrimSpace(out), time.Now()})

	for range 2 {
		wg.Go(func() { f.logins(&stop) })
	}
	for w := range 3 {
		wg.Go(func() { f.checks(w, &stop) })
	}
	wg.Go(func() { f.mints(t, &latest, &stop) })
	for range 3 {
		wg.Go(func() { f.mcpCalls(&latest, &stop) })
	}

	// Sample the keys file while the load runs: every ring must move on.
	seen := map[string]map[string]bool{}
	for name, kid := range start {
		seen[name] = map[string]bool{kid: true}
	}
	for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline) && f.fails.Load() == 0; {
		time.Sleep(100 * time.Millisecond)
		cur, err := f.currentKids()
		if err != nil {
			f.fail("reading the keys file: %v", err)
			break
		}
		for name, kid := range cur {
			seen[name][kid] = true
		}
	}
	stop.Store(true)
	wg.Wait()

	var summary []string
	for _, k := range []string{"login", "forward-auth", "check", "mcp"} {
		summary = append(summary, fmt.Sprintf("%s %d (%d across a rotation)", k, f.requests[k].Load(), f.crossed[k].Load()))
	}
	t.Logf("requests: %s; current keys seen: consistency %d, session %d, upstream %d, agent %d",
		strings.Join(summary, ", "), len(seen[keys.RingConsistency]), len(seen[keys.RingSession]),
		len(seen[keys.RingUpstream]), len(seen[keys.RingAgent]))
	if n := f.fails.Load(); n > 0 {
		t.Fatalf("%d failures while every key rotated: %s", n, strings.Join(f.failed, "\n"))
	}
	for name, kids := range seen {
		if len(kids) < 3 {
			t.Errorf("ring %s had %d current keys in 6 s of 1 s rotations, want at least 3", name, len(kids))
		}
	}
	for _, k := range []string{"forward-auth", "check", "mcp"} {
		if f.crossed[k].Load() == 0 {
			t.Errorf("no %s request used a credential issued before a rotation", k)
		}
	}
	if f.requests["login"].Load() < 4 {
		t.Errorf("only %d sign-ins", f.requests["login"].Load())
	}

	// Rotations were logged for every ring, and no save of the keys file
	// was refused.
	rotated := map[string]bool{}
	f.r.lines.mu.Lock()
	for _, m := range f.r.lines.lines {
		switch m["msg"] {
		case "key ring rotated":
			if ring, _ := m["ring"].(string); ring != "" {
				rotated[ring] = true
			}
		case "key ring check failed; the rings keep their keys":
			t.Errorf("keys file check failed: %v", m)
		}
	}
	f.r.lines.mu.Unlock()
	for _, name := range []string{keys.RingConsistency, keys.RingSession, keys.RingUpstream, keys.RingAgent} {
		if !rotated[name] {
			t.Errorf("no rotation of the %s ring logged", name)
		}
	}

	if err := f.r.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitExit(t, f.r.cmd); err != nil {
		t.Fatalf("exit after SIGTERM: %v", err)
	}
	if _, err := f.currentKids(); err != nil {
		t.Fatalf("keys file after the stop: %v", err)
	}
}
