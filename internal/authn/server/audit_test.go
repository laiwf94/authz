package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/logging"
	"github.com/laiwf94/authz/internal/platform/logging/logtest"
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
	// The platform handler, as authz gateway logs, so request lines carry
	// the correlation ID their audit records do.
	h.srv.log = logging.NewLogger(h.logs, logging.Options{Level: slog.LevelDebug})
	return path, l
}

// tracedCallback is the traceparent the proxy sends with alice's callback.
const tracedCallback = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

// loggedCorrelations returns the correlation_id of every request line in
// logs, keyed by its request_id.
func loggedCorrelations(t *testing.T, logs string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(logs), "\n") {
		var m struct {
			Msg           string `json:"msg"`
			RequestID     string `json:"request_id"`
			CorrelationID string `json:"correlation_id"`
		}
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line %q: %v", l, err)
		}
		if m.Msg == "request" {
			out[m.RequestID] = m.CorrelationID
		}
	}
	return out
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
// filled in, the request's correlation ID (its traceparent's trace ID, or a
// generated one that its log lines also carry), and no cookie, secret or key
// in the file.
func TestAuditChain(t *testing.T) {
	var cfg map[string]any
	h := newHarness(t, harnessOpts{cfgMutate: func(c map[string]any) { cfg = c }})
	path, _ := withAudit(t, h)
	scan := logtest.Check(t).Known(clientSecret, string(h.cookieKey))
	scan.File(path)

	// A sign-in under a request ID and a traceparent the proxy chose.
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
	cb.Header.Set("Traceparent", tracedCallback)
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
	// Every record has a correlation ID in trace ID form, and it is the one
	// on the request line of the request that wrote it: the record's audit
	// log line names the request ID.
	corr := loggedCorrelations(t, h.logs.String())
	seen := map[string]bool{}
	for _, r := range recs {
		if logging.Traceparent(r.CorrelationID) == "" {
			t.Errorf("seq %d %s: correlation ID %q is not a trace ID", r.Seq, r.Event, r.CorrelationID)
			continue
		}
		var rid string
		for id, c := range corr {
			if c == r.CorrelationID {
				rid = id
			}
		}
		if rid == "" {
			t.Errorf("seq %d %s: correlation ID %q is on no request line", r.Seq, r.Event, r.CorrelationID)
		} else if !strings.Contains(h.logs.String(), `"msg":"audit","correlation_id":"`+r.CorrelationID+`"`) {
			t.Errorf("seq %d %s: no audit line carries correlation ID %q", r.Seq, r.Event, r.CorrelationID)
		}
		seen[r.CorrelationID] = true
	}
	// Two revocations, two reloads and the sign-ins are separate requests.
	if len(seen) < 10 {
		t.Errorf("%d distinct correlation IDs over %d records", len(seen), len(recs))
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
	if first.CorrelationID != "4bf92f3577b34da6a3ce929d0e0e4736" || first.Action != "login" || first.Decision != audit.Allow ||
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

	// The audit log holds no cookie, client secret or cookie key, and
	// neither does the gateway's log (logtest checks both when the test
	// ends, and the audit log once more below).
	raw, _ := os.ReadFile(path)
	u, _ := url.Parse(h.public)
	for _, b := range []*browser{alice, bob, carol, other} {
		for _, c := range b.jar.Cookies(u) {
			if len(c.Value) >= logging.MinKnownBytes {
				scan.Known(c.Value)
			}
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
	scan.Bytes("gateway log", []byte(h.logs.String()))

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

// TestForwardAuthTraceparent: a proxy that sends a traceparent gets one back
// on an allowed forward-auth answer, to copy upstream: the same trace ID
// under the gateway's own parent ID, which is also the request's logged
// correlation ID. Without one the answer has none, as wicket's had.
func TestForwardAuthTraceparent(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	withAudit(t, h)
	alice := h.browser()
	alice.loginOIDC("alice", "alice-pass", "")

	resp := alice.auth("/", http.Header{"Traceparent": {tracedCallback}, "X-Request-Id": {"fwd-1"}})
	tp := resp.Header.Get("Traceparent")
	id, ok := logging.ParseTraceparent(tp)
	if resp.StatusCode != 200 || !ok || id != "4bf92f3577b34da6a3ce929d0e0e4736" || tp == tracedCallback {
		t.Fatalf("traced forward-auth: %d traceparent %q", resp.StatusCode, tp)
	}
	if got := loggedCorrelations(t, h.logs.String())["fwd-1"]; got != id {
		t.Errorf("request line correlation ID %q, want %q", got, id)
	}

	for _, hdr := range []http.Header{{"X-Request-Id": {"fwd-2"}}, {"Traceparent": {"garbage"}, "X-Request-Id": {"fwd-3"}}} {
		resp := alice.auth("/", hdr)
		if resp.StatusCode != 200 || resp.Header.Values("Traceparent") != nil {
			t.Errorf("untraced forward-auth: %d traceparent %q", resp.StatusCode, resp.Header.Values("Traceparent"))
		}
	}
	corr := loggedCorrelations(t, h.logs.String())
	if c2, c3 := corr["fwd-2"], corr["fwd-3"]; logging.Traceparent(c2) == "" || logging.Traceparent(c3) == "" || c2 == c3 || c2 == id {
		t.Errorf("generated correlation IDs %q %q", c2, c3)
	}

	// A denied answer carries no traceparent: the proxy sends nothing on.
	bob := h.browser()
	bob.loginOIDC("bob", "bob-pass", "")
	if resp := bob.auth("/", http.Header{"Traceparent": {tracedCallback}}); resp.StatusCode != 403 || resp.Header.Get("Traceparent") != "" {
		t.Errorf("denied: %d traceparent %q", resp.StatusCode, resp.Header.Get("Traceparent"))
	}
}
