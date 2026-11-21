package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/agents/mcp"
	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/enginetest"
	"github.com/laiwf94/authz/internal/platform/audit"
)

const checkTestSchema = `definition user {}

definition project {
  relation editor: user
  permission edit = editor
}
`

// checkTestPolicy lets an agent echo a project's name only when the user
// behind it can edit the project.
const checkTestPolicy = `{"version":1,"rules":[
 {"id":"echo-projects","effect":"allow","agents":["*"],"upstreams":["fake"],"tools":["echo"],
  "check":{"resource":"project:{args.text}","permission":"edit"}}
]}`

func newCheckEnv(t *testing.T, getEngine func(context.Context) (engine.Engine, error)) *env {
	t.Helper()
	e := newEnv(t)
	e.gw.opt.Engine = getEngine
	writePolicy(t, e, checkTestPolicy)
	return e
}

func recordData(t *testing.T, rec audit.Record) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestToolRulesAskTheEngine(t *testing.T) {
	f, err := enginetest.NewFake(checkTestSchema, "project:p1#editor@user:alice", "project:p2#editor@user:bob")
	if err != nil {
		t.Fatal(err)
	}
	gets := 0
	e := newCheckEnv(t, func(context.Context) (engine.Engine, error) { gets++; return f, nil })

	if r := e.call(aliceKey, "fake.echo", map[string]any{"text": "p1"}); r.text() != "p1" {
		t.Fatalf("alice on her project: %s", r.raw)
	}
	r := e.call(aliceKey, "fake.echo", map[string]any{"text": "p2"})
	if r.status != http.StatusOK || r.errCode() != mcp.CodePolicyDenied || r.errData()["rule_id"] != "default-deny" ||
		!strings.Contains(r.raw, "relationship check of rule echo-projects is denied: project:p2#edit@user:alice") {
		t.Fatalf("alice on bob's project: %d %s", r.status, r.raw)
	}
	if r := e.call(bobKey, "fake.echo", map[string]any{"text": "p2"}); r.text() != "p2" {
		t.Fatalf("bob on his project: %s", r.raw)
	}
	// An argument that is not an object ID is not asked about.
	if r := e.call(bobKey, "fake.echo", map[string]any{"text": "two words"}); r.errCode() != mcp.CodePolicyDenied ||
		!strings.Contains(r.raw, "is not a valid object id") {
		t.Fatalf("invalid id: %s", r.raw)
	}
	if gets != 3 {
		t.Errorf("engine fetched %d times, want once per call that asked (3)", gets)
	}
	// tools/list does not ask: the tool is listed, calls decide.
	if names := toolNames(e.rpc(aliceKey, "tools/list", nil, nil)); !slices.Contains(names, "fake.echo") {
		t.Errorf("alice sees %v", names)
	}

	var checks [][]any
	var outcomes []string
	for _, rec := range e.auditRecords() {
		data := recordData(t, rec)
		if rec.Event != "tool_call" || data["tool"] != "echo" || data["stage"] == "started" {
			continue
		}
		c, _ := data["checks"].([]any)
		checks = append(checks, c)
		outcomes = append(outcomes, data["outcome"].(string))
	}
	want := []string{
		"project:p1#edit@user:alice: allowed",
		"project:p2#edit@user:alice: denied",
		"project:p2#edit@user:bob: allowed",
		"project:two words#edit@user:bob: bad_input",
	}
	if len(checks) != 4 || strings.Join(outcomes, ",") != "ok,denied,ok,denied" {
		t.Fatalf("records %v %v", checks, outcomes)
	}
	for i, w := range want {
		if len(checks[i]) != 1 || checks[i][0] != w {
			t.Errorf("record %d checks %v, want %q", i, checks[i], w)
		}
	}
	m := e.admin("GET", "/metrics", "").raw
	for _, line := range []string{
		`toolgate_relationship_checks_total{result="allowed"} 2`,
		`toolgate_relationship_checks_total{result="denied"} 1`,
		`toolgate_relationship_checks_total{result="bad_input"} 1`,
	} {
		if !strings.Contains(m, line) {
			t.Errorf("metrics lack %s", line)
		}
	}
}

func TestToolRulesWithoutEngineAreAnOutage(t *testing.T) {
	for _, c := range []struct {
		name string
		get  func(context.Context) (engine.Engine, error)
		why  string
	}{
		{"no engine option", nil, "run authz run with its serve part"},
		{"engine stopped", func(context.Context) (engine.Engine, error) { return nil, errors.New("the in-process engine stopped") }, "stopped"},
		{"engine fails", func(context.Context) (engine.Engine, error) {
			f, err := enginetest.NewFake(checkTestSchema)
			if err != nil {
				return nil, err
			}
			f.Fail(errors.New("disk on fire"))
			return f, nil
		}, "disk on fire"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newCheckEnv(t, c.get)
			r := e.call(aliceKey, "fake.echo", map[string]any{"text": "p1"})
			if r.status != http.StatusServiceUnavailable || r.errCode() != mcp.CodeCheckUnavailable ||
				r.errData()["rule_id"] != "echo-projects" || strings.Contains(r.raw, c.why) {
				// The engine's error stays in the audit log and the
				// server log; the agent learns only to retry.
				t.Fatalf("modern: %d %s", r.status, r.raw)
			}
			// A 2025-11-25 session gets the same error with HTTP 200.
			init := e.post(e.gwURL, aliceKey, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"old","version":"1"}}}`), nil)
			h := map[string]string{mcp.HeaderSessionID: init.header.Get(mcp.HeaderSessionID), mcp.HeaderProtocolVersion: mcp.Version251125}
			e.post(e.gwURL, aliceKey, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), h)
			r = e.post(e.gwURL, aliceKey, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fake.echo","arguments":{"text":"p1"}}}`), h)
			if r.status != http.StatusOK || r.errCode() != mcp.CodeCheckUnavailable {
				t.Fatalf("legacy: %d %s", r.status, r.raw)
			}
			n := 0
			for _, rec := range e.auditRecords() {
				data := recordData(t, rec)
				if rec.Event == "tool_call" && data["outcome"] == "check_unavailable" {
					n++
					if !strings.Contains(data["reason"].(string), c.why) || data["constraint_rule_id"] != "echo-projects" {
						t.Errorf("record %v", data)
					}
				}
			}
			if n != 2 {
				t.Errorf("%d check_unavailable records, want 2", n)
			}
			if m := e.admin("GET", "/metrics", "").raw; !strings.Contains(m, `toolgate_relationship_checks_total{result="unavailable"} 2`) {
				t.Errorf("metrics: %s", m)
			}
		})
	}
}
