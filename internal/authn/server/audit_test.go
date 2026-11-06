package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/platform/audit"
)

// withAudit gives h's server a hash-chained audit log in h.dir.
func withAudit(t *testing.T, h *harness) (path string, l *audit.Log) {
	t.Helper()
	path = filepath.Join(h.dir, "audit.log")
	l, err := audit.OpenWith(path, audit.Options{Now: h.clk.Now, Schemas: audit.Default()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	h.srv.auditLog.Store(l)
	return path, l
}

// readAudit verifies the log against the platform schemas and returns its
// records.
func readAudit(t *testing.T, path string) []audit.Record {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.VerifyWith(bytes.NewReader(raw), audit.Default()); err != nil {
		t.Fatalf("audit log does not verify: %v\n%s", err, raw)
	}
	var out []audit.Record
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var r audit.Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func byEvent(recs []audit.Record, event string) []audit.Record {
	var out []audit.Record
	for _, r := range recs {
		if r.Event == event {
			out = append(out, r)
		}
	}
	return out
}

// TestAuditChain drives every audit event the gateway emits and requires
// each one in the hash chain as its typed authn event, with the envelope
// filled in, the request ID as the correlation ID, and no cookie, secret or
// key in the file.
func TestAuditChain(t *testing.T) {
	var cfg map[string]any
	h := newHarness(t, harnessOpts{cfgMutate: func(c map[string]any) { cfg = c }})
	path, _ := withAudit(t, h)

	// A sign-in under a request ID the proxy chose.
	alice := h.browser()
	req, _ := http.NewRequest(http.MethodGet, h.public+"/login?app=whoami&provider=corp", nil)
	resp := alice.do(req)
	resp.Body.Close()
	resp, body := alice.get(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize: %d", resp.StatusCode)
	}
	action, fields := formFields(body)
	fields.Set("username", "alice")
	fields.Set("password", "alice-pass")
	resp, _ = alice.post(action, fields)
	cb, _ := http.NewRequest(http.MethodGet, resp.Header.Get("Location"), nil)
	cb.Header.Set("X-Request-Id", "trace-4bf92f3577b34da6")
	if resp := alice.do(cb); resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d\n%s", resp.StatusCode, h.logs.String())
	}
	if alice.auth("/", nil).StatusCode != 200 {
		t.Fatal("alice is signed in")
	}

	// A login refused before the provider, and one the callback breaks.
	other := h.browser()
	if resp, _ := other.get(h.public + "/login?app=whoami&provider=corp&rd=" + url.QueryEscape("https://evil.example/")); resp.StatusCode != 400 {
		t.Fatalf("bad return URL: %d", resp.StatusCode)
	}
	if resp, _ := other.get(h.public + "/callback/corp?state=forged&code=x"); resp.StatusCode < 400 {
		t.Fatalf("forged callback: %d", resp.StatusCode)
	}

	// Denied by the app's policy, and a host no app serves.
	bob := h.browser()
	bob.loginOIDC("bob", "bob-pass", "")
	if bob.auth("/", nil).StatusCode != 403 {
		t.Fatal("bob has no access")
	}
	if bob.auth("/", http.Header{"X-Forwarded-Host": {"nowhere.example"}}).StatusCode != 403 {
		t.Fatal("unknown host")
	}

	// A forged logout, then a real one.
	carol := h.browser()
	carol.loginSAML("carol", "carol-pass")
	_, page := carol.get(h.public + "/logout")
	action, form := formFields(page)
	if resp, _ := carol.post(action, url.Values{"csrf": {"forged"}}); resp.StatusCode != 403 {
		t.Fatal("forged logout")
	}
	req, _ = http.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", h.public)
	if resp := carol.do(req); resp.StatusCode != 303 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}

	// Administrator revocations: by subject, then by session ID. Bob's
	// subject is the actor of his sign-in record.
	logins := byEvent(readAudit(t, path), audit.EventLoginSucceeded)
	if len(logins) != 3 {
		t.Fatalf("%d sign-ins recorded, want 3", len(logins))
	}
	bobSub := logins[1].Actor
	rb, _ := json.Marshal(map[string]string{"subject": bobSub, "provider": "corp"})
	resp2, out := h.adminDo("POST", "/admin/sessions/revoke", "", string(rb))
	if resp2.StatusCode != 200 {
		t.Fatalf("revoke subject: %d %v", resp2.StatusCode, out)
	}
	_, list := h.adminDo("GET", "/admin/sessions", "", "")
	var aliceSession string
	for _, s := range list["sessions"].([]any) {
		aliceSession = s.(map[string]any)["id"].(string)
	}
	if resp, _ := h.adminDo("DELETE", "/admin/sessions/"+aliceSession, "", ""); resp.StatusCode != 204 {
		t.Fatalf("revoke session: %d", resp.StatusCode)
	}

	// A reload, and a broken one.
	h.writeConfig(cfg)
	if resp, _ := h.adminDo("POST", "/admin/reload", "", ""); resp.StatusCode != 200 {
		t.Fatal("reload")
	}
	os.WriteFile(h.cfgPath, []byte(`{"public_url":"http://x"}`), 0o600)
	if resp, _ := h.adminDo("POST", "/admin/reload", "", ""); resp.StatusCode != 400 {
		t.Fatal("bad reload accepted")
	}

	recs := readAudit(t, path)
	for _, ev := range []string{audit.EventLoginSucceeded, audit.EventLoginFailed, audit.EventLoginRejected,
		audit.EventLogout, audit.EventLogoutRejected, audit.EventSessionRevoked, audit.EventAccessDenied,
		audit.EventConfigLoaded, audit.EventConfigLoadFailed} {
		if len(byEvent(recs, ev)) == 0 {
			t.Errorf("no %s record", ev)
		}
	}
	// Every record has a correlation ID: the one the proxy sent, or the one
	// the gateway generated and logged.
	for _, r := range recs {
		if r.CorrelationID == "" {
			t.Errorf("seq %d %s: no correlation ID", r.Seq, r.Event)
		} else if !strings.Contains(h.logs.String(), `"request_id":"`+r.CorrelationID+`"`) {
			t.Errorf("seq %d %s: correlation ID %q is not a logged request ID", r.Seq, r.Event, r.CorrelationID)
		}
	}

	ok := byEvent(recs, audit.EventLoginSucceeded)
	if len(ok) != 3 {
		t.Fatalf("%d login_succeeded records, want 3", len(ok))
	}
	first := ok[0]
	var p audit.LoginSucceeded
	if err := json.Unmarshal(first.Data, &p); err != nil {
		t.Fatal(err)
	}
	if first.CorrelationID != "trace-4bf92f3577b34da6" || first.Action != "login" || first.Decision != audit.Allow ||
		first.Subject != "app:whoami" || first.Actor == "" || p.Provider != "corp" || p.Email != "alice@example.org" ||
		len(p.Session) != 32 || p.ClientIP == "" {
		t.Errorf("login_succeeded: %+v %+v", first.Envelope, p)
	}

	for _, r := range byEvent(recs, audit.EventAccessDenied) {
		var p audit.AccessDenied
		json.Unmarshal(r.Data, &p)
		switch r.Subject {
		case "app:whoami":
			if r.Actor == "" || p.Reason == "" || p.Session == "" || r.Decision != audit.Deny {
				t.Errorf("policy denial: %+v %+v", r.Envelope, p)
			}
		case "host:nowhere.example":
			if p.Reason != "unknown_app" || p.Host != "nowhere.example" {
				t.Errorf("unknown host: %+v", p)
			}
		default:
			t.Errorf("access_denied subject %q", r.Subject)
		}
	}
	revoked := byEvent(recs, audit.EventSessionRevoked)
	if len(revoked) != 2 || revoked[0].Subject != bobSub || revoked[1].Subject != "session:"+aliceSession {
		t.Fatalf("session_revoked: %+v", revoked)
	}
	for _, r := range revoked {
		if r.Actor != "admin" || r.Action != "session.revoke" {
			t.Errorf("session_revoked envelope: %+v", r.Envelope)
		}
	}
	if lr := byEvent(recs, audit.EventLogoutRejected); lr[0].Decision != audit.Deny || !strings.HasPrefix(lr[0].Subject, "session:") {
		t.Errorf("logout_rejected: %+v", lr[0].Envelope)
	}

	// The audit log holds no cookie, client secret or cookie key.
	raw, _ := os.ReadFile(path)
	u, _ := url.Parse(h.public)
	for _, b := range []*browser{alice, bob, carol, other} {
		for _, c := range b.jar.Cookies(u) {
			if len(c.Value) >= 16 && bytes.Contains(raw, []byte(c.Value)) {
				t.Errorf("audit log contains cookie %s", c.Name)
			}
		}
	}
	if bytes.Contains(raw, []byte(clientSecret)) {
		t.Error("audit log contains the client secret")
	}
	if bytes.Contains(raw, []byte(hex.EncodeToString(h.cookieKey))) || bytes.Contains(raw, h.cookieKey) {
		t.Error("audit log contains the cookie key")
	}

	// The log line wicket wrote is still there, unchanged in shape.
	h.expectAudit("login_succeeded", "")
	if !strings.Contains(h.metrics(), `wicket_audit_records_total{event="login_succeeded"} 3`) {
		t.Errorf("metrics:\n%s", h.metrics())
	}
}

// TestAuditWriteFailure: once the audit log can't be written the request
// still completes, the failure is counted and logged, and /healthz reports
// the log unavailable.
func TestAuditWriteFailure(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	_, l := withAudit(t, h)
	if resp, _ := h.adminDo("GET", "/healthz", "", ""); resp.StatusCode != 200 {
		t.Fatal("healthy at start")
	}
	l.Close() // the next write fails and marks the log broken
	b := h.browser()
	b.loginOIDC("alice", "alice-pass", "")
	if b.auth("/", nil).StatusCode != 200 {
		t.Fatal("the sign-in must complete without the audit log")
	}
	if !strings.Contains(h.logs.String(), `"msg":"audit write failed"`) {
		t.Fatalf("no failure logged:\n%s", h.logs.String())
	}
	if !strings.Contains(h.metrics(), "wicket_audit_failures_total 1") {
		t.Errorf("metrics:\n%s", h.metrics())
	}
	resp, out := h.adminDo("GET", "/healthz", "", "")
	if resp.StatusCode != 503 || out["status"] != "audit log unavailable" {
		t.Fatalf("healthz with a broken audit log: %d %v", resp.StatusCode, out)
	}
	if resp, _ := b.get(h.public + "/healthz"); resp.StatusCode != 503 {
		t.Fatalf("public healthz with a broken audit log: %d", resp.StatusCode)
	}
}

// TestAuditWithoutLog: with no audit log the gateway logs as before and
// /healthz is unaffected.
func TestAuditWithoutLog(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	h.browser().loginOIDC("alice", "alice-pass", "")
	h.expectAudit("login_succeeded", "")
	if strings.Contains(h.metrics(), "wicket_audit_") {
		t.Error("audit metrics without an audit log")
	}
	if resp, _ := h.adminDo("GET", "/healthz", "", ""); resp.StatusCode != 200 {
		t.Fatal("healthz")
	}
}

func (h *harness) metrics() string {
	h.t.Helper()
	resp, err := http.Get(h.admin.URL + "/metrics")
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
