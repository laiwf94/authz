package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/enginetest"
)

// explainRules is stepUpRules plus a public static area, documents read
// through the engine and an audit log nobody may delete.
func explainRules(cfg map[string]any) {
	stepUpRules(cfg)
	app := cfg["apps"].([]any)[0].(map[string]any)
	app["public"] = []string{"/wiki", "/static"}
	app["paths"] = append(app["paths"].([]any),
		map[string]any{"path": "/docs/{id}", "methods": []string{"GET"},
			"check": map[string]any{"resource": "doc:{path.id}", "permission": "view"}},
		map[string]any{"path": "/admin/audit", "methods": []string{"DELETE"}, "deny": true},
	)
}

func explainHarness(t *testing.T) (*harness, *engine.Local) {
	t.Helper()
	h := newHarness(t, harnessOpts{cfgMutate: explainRules, adminToken: strings.Repeat("t", 32)})
	eng := enginetest.NewLocal(t, docsSchema, engine.Options{}, "doc:plan#viewer@user:alice", "doc:spec#editor@user:bob")
	h.srv.opts.Engine = func(context.Context) (engine.Engine, error) { return eng, nil }
	return h, eng
}

// explainCall posts body to /admin/explain and decodes the answer.
func (h *harness) explainCall(body string) (int, explainResponse, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.admin.URL+"/admin/explain", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	var out explainResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
			h.t.Fatalf("%s: %v", buf.String(), err)
		}
	}
	return resp.StatusCode, out, buf.String()
}

func (h *harness) explainFor(method, path, who string) explainResponse {
	h.t.Helper()
	body := fmt.Sprintf(`{"url":%q,"method":%q%s}`, "https://"+h.host+path, method, who)
	code, out, raw := h.explainCall(body)
	if code != http.StatusOK {
		h.t.Fatalf("explain %s: %d %s", body, code, raw)
	}
	return out
}

func rulesChain(out explainResponse) string {
	var parts []string
	for _, c := range out.Rules {
		s := c.Rule
		switch {
		case c.Selected:
			s += "*"
		case !c.MethodMatches:
			s += "-"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func TestAdminExplain(t *testing.T) {
	h, _ := explainHarness(t)
	h.clk.Advance(time.Hour)
	recent := h.clk.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339)
	old := h.clk.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	alice := `,"identity":{"provider":"corp","sub":"alice","groups":["eng","admins"]}`
	bob := `,"identity":{"provider":"corp","sub":"bob","groups":["sales"]}`
	cases := []struct {
		name, method, path, who string
		status                  int
		decision, reason, rule  string
		chain                   string
	}{
		{"public", "GET", "/static/app.css", "", 200, "public", "public_path", "public[1]", "public[1]* allow"},
		{"anonymous", "GET", "/docs/plan", "", 401, "unauthenticated", "no_subject", "paths[3]", "paths[3]* paths[2]- allow"},
		{"check allows", "GET", "/docs/plan", alice, 200, "allowed", "allowed", "paths[3]", "paths[3]* paths[2]- allow"},
		{"check denies", "GET", "/docs/plan", bob, 403, "forbidden", "check_denied", "paths[3]", "paths[3]* paths[2]- allow"},
		{"bad check input", "GET", "/docs/a%20b", bob, 403, "forbidden", "check_bad_input", "paths[3]", "paths[3]* paths[2]- allow"},
		{"group rule", "GET", "/admin/users", bob, 403, "forbidden", "no_rule_matched", "paths[0]", "paths[0]* allow"},
		{"deny rule", "DELETE", "/admin/audit", alice, 403, "forbidden", "denied_by_rule", "paths[4]", "paths[4]* paths[0] allow"},
		{"deny passed over", "GET", "/admin/audit", alice + `,"auth":{"time":"` + recent + `"}`, 200, "allowed", "allowed", "paths[0]", "paths[4]- paths[0]* allow"},
		{"step-up age", "GET", "/admin", alice + `,"auth":{"time":"` + old + `"}`, 401, "step_up", "step_up_max_age", "paths[0]", "paths[0]* allow"},
		{"step-up unknown age", "GET", "/admin", alice, 401, "step_up", "step_up_max_age", "paths[0]", "paths[0]* allow"},
		{"step-up acr", "GET", "/billing/x", bob + `,"auth":{"acr":"urn:other"}`, 401, "step_up", "step_up_acr", "paths[1]", "paths[1]* allow"},
		{"step-up acr met", "GET", "/billing/x", bob + `,"auth":{"acr":"urn:fakeidp:acr:mfa"}`, 200, "allowed", "allowed", "paths[1]", "paths[1]* allow"},
		{"step-up before check", "PUT", "/docs/spec", bob, 401, "step_up", "step_up_max_age", "paths[2]", "paths[3]- paths[2]* allow"},
		{"step-up then check", "PUT", "/docs/spec", bob + `,"auth":{"time":"` + recent + `"}`, 200, "allowed", "allowed", "paths[2]", "paths[3]- paths[2]* allow"},
		{"app-wide", "POST", "/elsewhere", bob, 200, "allowed", "allowed", "allow", "allow*"},
		{"provider", "GET", "/elsewhere", `,"identity":{"provider":"elsewhere","sub":"bob"}`, 403, "forbidden", "provider_not_accepted", "allow", "allow*"},
		{"bad path", "GET", "/docs/a%2Fb", bob, 403, "forbidden", "bad_path", "", ""},
	}
	for _, c := range cases {
		out := h.explainFor(c.method, c.path, c.who)
		if out.Status != c.status || out.Decision != c.decision || out.Reason != c.reason || out.Rule != c.rule ||
			rulesChain(out) != c.chain || out.App != "whoami" || out.Method != c.method {
			t.Errorf("%s: %d %s %s %s chain %q, want %d %s %s %s %q", c.name, out.Status, out.Decision, out.Reason, out.Rule,
				rulesChain(out), c.status, c.decision, c.reason, c.rule, c.chain)
		}
	}

	// A relationship rule's answer carries the check and the engine's
	// trace.
	out := h.explainFor("GET", "/docs/plan", alice)
	c := out.Check
	if c == nil || c.Resource != "doc:plan" || c.Permission != "view" || c.Subject != "user:alice" || c.Result != "allowed" ||
		c.Consistency != "minimize_latency" || c.Revision == 0 || c.Trace == nil || c.Trace.Root == nil ||
		c.Trace.Root.Role != "grant" || c.Trace.Root.Object != "doc:plan" || c.Trace.Nodes == 0 {
		t.Fatalf("allowed check: %+v", c)
	}
	if p := out.Rules[0].Params; p["id"] != "plan" || out.Rules[0].Kind != "check" || out.Path != "/docs/plan" {
		t.Fatalf("rule: %+v, path %q", out.Rules[0], out.Path)
	}
	out = h.explainFor("GET", "/docs/plan", bob)
	if c := out.Check; c == nil || c.Result != "denied" || c.Trace == nil || c.Trace.Root.Role != "deny" || c.Trace.Root.Result {
		t.Fatalf("denied check: %+v", c)
	}
	out = h.explainFor("GET", "/docs/plan", bob+`,"trace_nodes":1`)
	if c := out.Check; c.Trace.Nodes != 1 || !c.Trace.Truncated {
		t.Fatalf("one trace node: %+v", c.Trace)
	}
	out = h.explainFor("GET", "/docs/a%20b", bob)
	if c := out.Check; c == nil || c.Error == "" || c.Result != "" || c.Trace != nil || out.Path != "/docs/a b" {
		t.Fatalf("bad input check: %+v", c)
	}
	// The step-up requirement and how the sign-in compares.
	out = h.explainFor("GET", "/admin", alice+`,"auth":{"time":"`+old+`","acr":"urn:x"}`)
	if su := out.StepUp; su == nil || su.MaxAge != 600 || su.Satisfied || su.ACR != "urn:x" || su.AuthTime == nil ||
		su.AuthTime.Format(time.RFC3339) != old {
		t.Fatalf("step-up: %+v", out.StepUp)
	}
	lu, _ := url.Parse(out.LoginURL)
	if q := lu.Query(); q.Get("step_up") != "paths[0]" || q.Get("provider") != "corp" || q.Get("rd") != "https://"+h.host+"/admin" {
		t.Fatalf("step-up login URL %s", out.LoginURL)
	}
	out = h.explainFor("GET", "/billing", bob+`,"auth":{"acr":"urn:fakeidp:acr:mfa"}`)
	if su := out.StepUp; su == nil || !su.Satisfied || su.MaxAge != 0 || len(su.ACRValues) != 1 {
		t.Fatalf("met step-up: %+v", su)
	}
	// Signed out, a step-up path asks for its requirement in the first
	// login.
	out = h.explainFor("GET", "/admin?tab=keys", "")
	lu, _ = url.Parse(out.LoginURL)
	if q := lu.Query(); q.Get("step_up") != "paths[0]" || q.Get("provider") != "" || q.Get("rd") != "https://"+h.host+"/admin?tab=keys" ||
		out.StepUp == nil || out.StepUp.Satisfied || out.Identity != nil {
		t.Fatalf("anonymous step-up: %+v, %s", out.StepUp, out.LoginURL)
	}

	// The app comes from the host, or from app.
	code, out, raw := h.explainCall(`{"url":"https://nowhere.example.com/","method":"GET"}`)
	if code != 200 || out.Status != 403 || out.Reason != "unknown_app" || out.App != "" || len(out.Rules) != 0 || !strings.Contains(raw, `"rules":[]`) {
		t.Fatalf("unknown host: %d %s", code, raw)
	}
	code, out, raw = h.explainCall(`{"app":"open","url":"https://nowhere.example.com/x","identity":{"provider":"corp","sub":"bob"}}`)
	if code != 200 || out.App != "open" || out.Status != 200 || out.Method != "GET" {
		t.Fatalf("app by name: %d %s", code, raw)
	}

	// Without an engine, a relationship rule is an outage.
	h.srv.opts.Engine = nil
	out = h.explainFor("GET", "/docs/plan", alice)
	if out.Status != 503 || out.Decision != "unavailable" || out.Reason != "check_unavailable" || out.Check == nil ||
		!strings.Contains(out.Check.Error, "no authorization engine") {
		t.Fatalf("no engine: %+v %+v", out, out.Check)
	}
}

func TestAdminExplainRefusesBadInput(t *testing.T) {
	h, _ := explainHarness(t)
	u := `"url":"https://` + h.host + `/x"`
	for _, c := range []struct {
		body string
		code int
		want string
	}{
		{`{}`, 400, "url is required"},
		{`{"url":"/x"}`, 400, "absolute"},
		{`{"url":"ftp://h/x"}`, 400, "absolute"},
		{`{"url":"https://h/` + strings.Repeat("a", 4100) + `"}`, 400, "url is required"},
		{`{` + u + `,"method":"get"}`, 400, "method"},
		{`{` + u + `,"method":"VERYLONGMETHODNAME"}`, 400, "method"},
		{`{` + u + `,"session":"00000000000000000000000000000000","identity":{"provider":"corp","sub":"a"}}`, 400, "not both"},
		{`{` + u + `,"auth":{"acr":"x"}}`, 400, "auth describes"},
		{`{` + u + `,"session":"nope"}`, 400, "32 hex"},
		{`{` + u + `,"session":"00000000000000000000000000000000"}`, 404, "no such live session"},
		{`{` + u + `,"identity":{"provider":"corp"}}`, 400, "provider and a sub"},
		{`{` + u + `,"identity":{"provider":"corp","sub":"` + strings.Repeat("a", 600) + `"}}`, 400, "too large"},
		{`{` + u + `,"identity":{"provider":"corp","sub":"a"},"auth":{"acr":"has space"}}`, 400, "auth.acr"},
		{`{` + u + `,"trace_nodes":10001}`, 400, "trace_nodes"},
		{`{` + u + `,"trace_nodes":-1}`, 400, "trace_nodes"},
		{`{` + u + `,"identity":{"provider":"corp","sub":"a","role":"admin"}}`, 400, "unknown field"},
		{`{` + u + `,"app":"` + strings.Repeat("a", 129) + `"}`, 400, "app is too long"},
	} {
		code, _, raw := h.explainCall(c.body)
		if code != c.code || !strings.Contains(raw, c.want) {
			t.Errorf("%.80s: %d %s, want %d %q", c.body, code, raw, c.code, c.want)
		}
	}
	// The admin token is required.
	if resp, _ := h.adminDo(http.MethodPost, "/admin/explain", "", `{`+u+`}`); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without the admin token: %d", resp.StatusCode)
	}
	if resp, _ := h.adminDo(http.MethodGet, "/admin/explain", strings.Repeat("t", 32), ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
}

// TestExplainAgreesWithForwardAuth: for real sessions, explaining a
// request by session gives the status forward-auth answers, and changes
// nothing: the session's idle timer and consistency token, the metrics and
// the audit log stay as they were.
func TestExplainAgreesWithForwardAuth(t *testing.T) {
	h, _ := explainHarness(t)
	alice, bob, anon := h.browser(), h.browser(), h.browser()
	alice.loginOIDC("alice", "alice-pass", "")
	bob.loginOIDC("bob", "bob-pass", "")
	sessionOf := func(sub string) string { return h.sessions.UserSessions("corp", sub)[0].ID }
	type req struct{ method, path string }
	reqs := []req{
		{"GET", "/static/a.css"}, {"GET", "/wiki/home"}, {"GET", "/docs/plan"}, {"GET", "/docs/spec"},
		{"PUT", "/docs/spec"}, {"PUT", "/docs/plan"}, {"GET", "/docs/a%20b"}, {"GET", "/admin"},
		{"DELETE", "/admin/audit"}, {"GET", "/billing"}, {"POST", "/elsewhere"}, {"GET", "/docs/a%2Fb"},
		{"HEAD", "/docs/plan"}, {"GET", "/docs/./plan"},
	}
	seen := map[string]int{}
	// Twelve minutes on, alice's sign-in is too old for /admin and
	// /docs PUT, so step-ups are compared too.
	for _, step := range []time.Duration{0, 12 * time.Minute} {
		h.clk.Advance(step)
		for _, b := range []struct {
			name string
			br   *browser
		}{{"alice", alice}, {"bob", bob}, {"anonymous", anon}} {
			who := ""
			if b.br != anon {
				who = `,"session":"` + sessionOf(b.name) + `"`
			}
			for _, r := range reqs {
				var before []byte
				if b.br != anon {
					s, _ := h.sessions.Get(sessionOf(b.name))
					before, _ = json.Marshal(struct {
						Seen time.Time
						Tok  string
					}{s.LastSeen, s.ConsistencyToken()})
				}
				metricsBefore := decisionMetrics(h)
				logsBefore := len(h.logs.String())

				out := h.explainFor(r.method, r.path, who)

				// Only the admin request's own log line is written.
				logged := h.logs.String()[logsBefore:]
				if decisionMetrics(h) != metricsBefore || strings.Count(logged, "\n") != 1 || !strings.Contains(logged, `"route":"/admin/explain"`) {
					t.Fatalf("%s %s %s: explaining changed the metrics or logged:\n%s", b.name, r.method, r.path, logged)
				}
				if b.br != anon {
					s, _ := h.sessions.Get(sessionOf(b.name))
					after, _ := json.Marshal(struct {
						Seen time.Time
						Tok  string
					}{s.LastSeen, s.ConsistencyToken()})
					if !bytes.Equal(before, after) {
						t.Fatalf("%s %s %s: explaining changed the session: %s -> %s", b.name, r.method, r.path, before, after)
					}
					if out.Session != sessionOf(b.name) || out.Identity == nil || out.Identity.Subject != b.name {
						t.Fatalf("%s: explained as %+v", b.name, out.Identity)
					}
				}
				resp := b.br.auth(r.path, http.Header{"X-Forwarded-Method": {r.method}})
				seen[out.Decision+" "+out.Reason]++
				if resp.StatusCode != out.Status {
					t.Errorf("+%s %s %s %s: forward-auth %d, explain %d (%s %s)", step, b.name, r.method, r.path,
						resp.StatusCode, out.Status, out.Decision, out.Reason)
				}
				if out.Status == http.StatusUnauthorized && resp.Header.Get(HeaderRedirect) != out.LoginURL {
					t.Errorf("%s %s %s: login %s, explain %s", b.name, r.method, r.path, resp.Header.Get(HeaderRedirect), out.LoginURL)
				}
			}
		}
	}
	// Every kind of answer was compared.
	for _, want := range []string{"public public_path", "unauthenticated no_subject", "allowed allowed", "forbidden check_denied",
		"forbidden check_bad_input", "forbidden no_rule_matched", "forbidden denied_by_rule", "forbidden bad_path",
		"step_up step_up_max_age", "step_up step_up_acr"} {
		if seen[want] == 0 {
			t.Errorf("no request was answered %q: %v", want, seen)
		}
	}
	// A session's consistency token is used: after bob's check, his next
	// explanation reads at least as fresh.
	out := h.explainFor("GET", "/docs/spec", `,"session":"`+sessionOf("bob")+`"`)
	if c := out.Check; c == nil || c.Consistency != string(engine.AtLeastAsFresh) || c.Result != "allowed" {
		t.Fatalf("bob's check: %+v", out.Check)
	}
	// A session that ended cannot be explained.
	id := sessionOf("bob")
	if _, err := h.sessions.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if code, _, raw := h.explainCall(`{"url":"https://` + h.host + `/","session":"` + id + `"}`); code != http.StatusNotFound {
		t.Fatalf("revoked session: %d %s", code, raw)
	}
}

// decisionMetrics is the metrics forward-auth decisions count.
func decisionMetrics(h *harness) string {
	var buf bytes.Buffer
	if err := h.srv.m.Write(&buf); err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(l, "wicket_auth_decisions_total") || strings.HasPrefix(l, "wicket_relationship_checks_total") ||
			strings.HasPrefix(l, "wicket_step_ups_total") || strings.HasPrefix(l, "grantd_check_") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
