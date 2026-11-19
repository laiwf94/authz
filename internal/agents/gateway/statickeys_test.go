package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/keys"
)

func keyID(token string) string { return keys.StaticKeyID(identity.HashToken(token)) }

// keySet reads GET /admin/keys: the version and, per key id, its view.
func (e *env) keySet() (uint64, map[string]map[string]any) {
	e.t.Helper()
	r := e.admin("GET", "/admin/keys", "")
	if r.status != 200 {
		e.t.Fatalf("GET /admin/keys: %s", r.raw)
	}
	v := uint64(r.body["version"].(float64))
	if r.header.Get("ETag") != fmt.Sprintf(`"%d"`, v) || r.header.Get("Cache-Control") != "no-store" {
		e.t.Fatalf("GET /admin/keys headers: %v", r.header)
	}
	out := map[string]map[string]any{}
	for _, k := range r.body["keys"].([]any) {
		m := k.(map[string]any)
		out[m["id"].(string)] = m
	}
	return v, out
}

func (e *env) agentStatus(token string) int {
	e.t.Helper()
	return e.rpc(token, "tools/list", nil, nil).status
}

func TestStaticKeysAdminAPI(t *testing.T) {
	e := newEnv(t)
	path := filepath.Join(e.dir, "static-keys.json")
	st, err := keys.OpenStatic(path)
	if err != nil {
		t.Fatal(err)
	}
	e.gw.static = st
	if err := e.gw.SetAgents(e.gw.cfg, e.auth); err != nil {
		t.Fatal(err)
	}

	v, set := e.keySet()
	if v != 0 || len(set) != 3 || set[keyID(aliceKey)]["source"] != "config" || set[keyID(aliceKey)]["agent"] != "alice-bot" {
		t.Fatalf("initial key set: %d %v", v, set)
	}

	// Bodies that are refused before anything changes.
	for _, tc := range []struct{ path, body, code string }{
		{"/admin/keys", `{"agent":"alice-bot"}`, "invalid_argument"},
		{"/admin/keys", `{"agent":"nobody","version":0}`, "invalid_argument"},
		{"/admin/keys", `{"agent":"alice-bot","version":0,"overlap_seconds":5}`, "invalid_argument"},
		{"/admin/keys", `{"agent":"alice-bot","version":0,"extra":1}`, "invalid_argument"},
		{"/admin/keys/" + keyID(aliceKey) + "/rotate", `{"version":0,"overlap_seconds":-1}`, "invalid_argument"},
		{"/admin/keys/" + keyID(aliceKey) + "/rotate", `{"version":0,"overlap_seconds":604801}`, "invalid_argument"},
		{"/admin/keys/" + keyID(aliceKey) + "/rotate", `{"version":0,"agent":"bob-bot"}`, "invalid_argument"},
		{"/admin/keys/" + keyID(aliceKey) + "/revoke", `{"version":0,"overlap_seconds":5}`, "invalid_argument"},
		{"/admin/keys/" + keyID(aliceKey) + "/revoke", `{}`, "invalid_argument"},
		{"/admin/keys/0123456789abcdef/revoke", `{"version":0}`, "not_found"},
		{"/admin/keys/" + keyID(aliceKey) + "/revoke", `{"version":7}`, "version_conflict"},
	} {
		r := e.admin("POST", tc.path, tc.body)
		if code, _ := r.body["error"].(map[string]any)["code"].(string); code != tc.code {
			t.Errorf("POST %s %s: %d %s, want %s", tc.path, tc.body, r.status, r.raw, tc.code)
		}
	}
	if r := e.admin("POST", "/admin/keys/x/revoke", `{"version":9}`); r.status != 409 || r.header.Get("ETag") != `"0"` {
		t.Fatalf("conflict answer: %d %v", r.status, r.header)
	}
	if e.gw.static.Version() != 0 {
		t.Fatal("a refused change moved the version")
	}

	// Issue a second key for alice.
	r := e.admin("POST", "/admin/keys", `{"agent":"alice-bot","version":0}`)
	if r.status != 201 || r.body["version"] != 1.0 || r.header.Get("ETag") != `"1"` {
		t.Fatalf("create: %s", r.raw)
	}
	alice2 := r.body["secret"].(string)
	k := r.body["key"].(map[string]any)
	if !strings.HasPrefix(alice2, "tgk_") || k["id"] != keyID(alice2) || k["source"] != "issued" || k["agent"] != "alice-bot" || k["created"] == "" {
		t.Fatalf("created key: %s", r.raw)
	}
	if s := e.agentStatus(alice2); s != 200 {
		t.Fatalf("issued key: %d", s)
	}
	if s := e.agentStatus(aliceKey); s != 200 {
		t.Fatalf("configured key after another was issued: %d", s)
	}
	if c := e.call(alice2, "fake.echo", map[string]any{"text": "hi"}); c.status != 200 || c.text() != "hi" {
		t.Fatalf("call with the issued key: %s", c.raw)
	}
	// A second change against version 0 is refused.
	if r := e.admin("POST", "/admin/keys", `{"agent":"bob-bot","version":0}`); r.status != 409 {
		t.Fatalf("stale create: %s", r.raw)
	}

	// Rotate alice's configured key with a minute of overlap.
	r = e.admin("POST", "/admin/keys/"+keyID(aliceKey)+"/rotate", `{"version":1,"overlap_seconds":60}`)
	if r.status != 200 || r.body["version"] != 2.0 {
		t.Fatalf("rotate: %s", r.raw)
	}
	alice3 := r.body["secret"].(string)
	old := r.body["old"].(map[string]any)
	if old["id"] != keyID(aliceKey) || old["until"] != e.clk.now().Add(time.Minute).UTC().Format(time.RFC3339) {
		t.Fatalf("rotated key: %s", r.raw)
	}
	for _, tok := range []string{aliceKey, alice2, alice3} {
		if s := e.agentStatus(tok); s != 200 {
			t.Fatalf("inside the overlap: %d", s)
		}
	}
	e.clk.add(61 * time.Second)
	if s := e.agentStatus(aliceKey); s != 401 {
		t.Fatalf("the rotated configured key after its overlap: %d", s)
	}
	if s := e.agentStatus(alice3); s != 200 {
		t.Fatalf("the rotated-in key: %d", s)
	}

	// Revoke bob's configured key and alice's first issued key.
	if r := e.admin("POST", "/admin/keys/"+keyID(bobKey)+"/revoke", `{"version":2}`); r.status != 200 || r.body["key"].(map[string]any)["source"] != "config" {
		t.Fatalf("revoke bob: %s", r.raw)
	}
	if s := e.agentStatus(bobKey); s != 401 {
		t.Fatalf("revoked configured key: %d", s)
	}
	if r := e.admin("POST", "/admin/keys/"+keyID(alice2)+"/revoke", `{"version":3}`); r.status != 200 {
		t.Fatalf("revoke issued key: %s", r.raw)
	}
	if s := e.agentStatus(alice2); s != 401 {
		t.Fatalf("revoked issued key: %d", s)
	}
	v, set = e.keySet()
	if v != 4 || len(set) != 2 || set[keyID(alice3)] == nil || set[keyID(quotaKey)] == nil {
		t.Fatalf("key set after the changes: %d %v", v, set)
	}

	// A reload that drops alice stops her issued key; one that brings her
	// back starts it again. Bob's revocation holds across reloads.
	c, auth := e.replaced(t, func(c *Config) { c.Agents = c.Agents[1:] })
	if err := e.gw.SetAgents(c, auth); err != nil {
		t.Fatal(err)
	}
	if s := e.agentStatus(alice3); s != 401 {
		t.Fatalf("issued key of an agent the config dropped: %d", s)
	}
	if r := e.admin("POST", "/admin/keys", `{"agent":"alice-bot","version":4}`); r.status != 400 {
		t.Fatalf("issuing for a dropped agent: %s", r.raw)
	}
	c, auth = e.replaced(t, func(c *Config) {})
	if err := e.gw.SetAgents(c, auth); err != nil {
		t.Fatal(err)
	}
	if e.agentStatus(alice3) != 200 || e.agentStatus(bobKey) != 401 {
		t.Fatal("after the agent came back")
	}

	// A restart reads the same key set from the file.
	st2, err := keys.OpenStatic(path)
	if err != nil {
		t.Fatal(err)
	}
	e.gw.static = st2
	if err := e.gw.SetAgents(c, auth); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.keySet(); v != 4 || e.agentStatus(alice3) != 200 || e.agentStatus(bobKey) != 401 || e.agentStatus(alice2) != 401 || e.agentStatus(aliceKey) != 401 {
		t.Fatalf("after a restart: version %d", v)
	}

	// Audited without secrets, and the records match the schemas.
	seen := map[string]int{}
	for _, rec := range e.auditRecords() {
		seen[rec.Event]++
	}
	if seen[audit.EventStaticKeyCreated] != 1 || seen[audit.EventStaticKeyRotated] != 1 || seen[audit.EventStaticKeyRevoked] != 2 {
		t.Fatalf("audit records: %v", seen)
	}
	raw, _ := os.ReadFile(e.auditPath)
	for _, secret := range []string{alice2, alice3} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("a static key is in the audit log")
		}
	}
	if !strings.Contains(string(raw), `"key_id":"`+keyID(alice2)+`"`) {
		t.Fatal("the call with an issued key does not name it")
	}
	f, _ := os.Open(e.auditPath)
	defer f.Close()
	if _, err := audit.VerifyWith(f, audit.Default()); err != nil {
		t.Fatalf("static key records do not match the schemas: %v", err)
	}
	fb, _ := os.ReadFile(path)
	for _, secret := range []string{alice2, alice3} {
		if strings.Contains(string(fb), secret) {
			t.Fatal("a static key is in the static key file")
		}
	}
}

// Concurrent changes against one version: exactly one wins.
func TestStaticKeysCompareAndSet(t *testing.T) {
	e := newEnv(t)
	const n = 16
	var wg sync.WaitGroup
	status := make([]int, n)
	for i := range n {
		wg.Go(func() {
			status[i] = e.admin("POST", "/admin/keys", `{"agent":"bob-bot","version":0}`).status
		})
	}
	wg.Wait()
	created := 0
	for _, s := range status {
		switch s {
		case 201:
			created++
		case 409:
		default:
			t.Fatalf("status %d", s)
		}
	}
	if created != 1 {
		t.Fatalf("%d creations against one version succeeded", created)
	}
	if v, set := e.keySet(); v != 1 || len(set) != 4 {
		t.Fatalf("key set: %d %v", v, set)
	}
	// Without a key file the key set lives in memory.
	if e.gw.StaticKeys().Path() != "" {
		t.Fatal("the default store has a path")
	}
}

// A store whose file another process replaced refuses the change.
func TestStaticKeysFileConflict(t *testing.T) {
	e := newEnv(t)
	path := filepath.Join(e.dir, "static-keys.json")
	st, _ := keys.OpenStatic(path)
	e.gw.static = st
	if err := e.gw.SetAgents(e.gw.cfg, e.auth); err != nil {
		t.Fatal(err)
	}
	other, _ := keys.OpenStatic(path)
	if _, _, err := other.Create(0, nil, "x", identity.HashToken("other-process"), time.Now()); err != nil {
		t.Fatal(err)
	}
	r := e.admin("POST", "/admin/keys", `{"agent":"bob-bot","version":0}`)
	if r.status != 409 || !strings.Contains(r.raw, "another process") {
		t.Fatalf("change over another process's file: %s", r.raw)
	}
	// A full agent answers resource_exhausted.
	e2 := newEnv(t)
	v := uint64(0)
	for range keys.MaxStaticKeysPerAgent {
		r := e2.admin("POST", "/admin/keys", fmt.Sprintf(`{"agent":"bob-bot","version":%d}`, v))
		if r.status != 201 {
			t.Fatal(r.raw)
		}
		v++
	}
	if r := e2.admin("POST", "/admin/keys", fmt.Sprintf(`{"agent":"bob-bot","version":%d}`, v)); r.status != 409 || !strings.Contains(r.raw, "resource_exhausted") {
		t.Fatalf("one key too many: %s", r.raw)
	}
}
