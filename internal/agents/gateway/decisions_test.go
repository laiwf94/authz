package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/mcp"
)

// auditLine builds one audit line with the given run-specific values.
func auditLine(seq int, ts, prev, event, data string) string {
	return fmt.Sprintf(`{"seq":%d,"time":%q,"prev":%q,"event":%q,"data":%s}`, seq, ts, prev, event, data)
}

func record(t *testing.T, log string) string {
	t.Helper()
	var out bytes.Buffer
	if err := RecordDecisions(strings.NewReader(log), &out); err != nil {
		t.Fatalf("RecordDecisions: %v", err)
	}
	return out.String()
}

// runLog is a small log in the shape the gateway writes; the run-specific
// values come from v so two runs can differ only in them.
func runLog(v [6]string) string {
	return strings.Join([]string{
		auditLine(1, v[0], strings.Repeat("0", 64), "tool_call",
			`{"agent":"a","args_hmac":"`+v[1]+`","decision":"allow","request_id":"`+v[2]+`","stage":"started","rule_id":"r","n":1.50}`),
		auditLine(2, v[0], v[5], "tool_call",
			`{"agent":"a","args_hmac":"`+v[1]+`","decision":"allow","latency_ms":`+v[4]+`,"outcome":"ok","request_id":"`+v[2]+`","stage":"completed","rule_id":"r"}`),
		auditLine(3, v[0], v[5], "approval_requested",
			`{"agent":"a","approval_id":"`+v[3]+`","args_hmac":"`+v[2]+`x","request_id":"`+v[2]+`y"}`),
		auditLine(4, v[0], v[5], "approval_decided",
			`{"approval_id":"`+v[3]+`","decision":"approved","expires_at":"`+v[0]+`","note":"<b>ok</b>"}`),
		auditLine(5, v[0], v[5], "policy_applied", `null`),
	}, "\n") + "\n"
}

func TestRecordDecisionsNormalisesRunSpecificValues(t *testing.T) {
	a := record(t, runLog([6]string{"2026-11-01T00:00:00.1Z", "aaaa", "req1", "apr_ONE", "3", strings.Repeat("1", 64)}))
	b := record(t, runLog([6]string{"2031-02-03T04:05:06Z", "bbbb", "req9", "apr_TWO", "1200", strings.Repeat("2", 64)}))
	if a != b {
		t.Fatalf("two runs that differ only in run-specific values recorded differently:\n%s\n%s", a, b)
	}
	want := `{"seq":1,"event":"tool_call","data":{"agent":"a","args_hmac":"<args_hmac>#1","decision":"allow","n":1.50,"request_id":"<request_id>#1","rule_id":"r","stage":"started"}}
{"seq":2,"event":"tool_call","data":{"agent":"a","args_hmac":"<args_hmac>#1","decision":"allow","latency_ms":"<latency_ms>","outcome":"ok","request_id":"<request_id>#1","rule_id":"r","stage":"completed"}}
{"seq":3,"event":"approval_requested","data":{"agent":"a","approval_id":"<approval_id>#1","args_hmac":"<args_hmac>#2","request_id":"<request_id>#2"}}
{"seq":4,"event":"approval_decided","data":{"approval_id":"<approval_id>#1","decision":"approved","expires_at":"<expires_at>","note":"<b>ok</b>"}}
{"seq":5,"event":"policy_applied","data":null}
`
	if a != want {
		t.Fatalf("recording:\n%s\nwant:\n%s", a, want)
	}
}

func TestRecordDecisionsKeepsDecisionsExactly(t *testing.T) {
	base := `{"agent":"a","decision":"deny","reason":"rule x forbids this call","rule_id":"x","args_preview":"{\"p\":1}","redactions":2,"policy":"abc"}`
	a := record(t, auditLine(1, "t", "p", "tool_call", base)+"\n")
	for _, change := range [][2]string{
		{`"decision":"deny"`, `"decision":"allow"`},
		{`"rule_id":"x"`, `"rule_id":"y"`},
		{`forbids`, `allows`},
		{`"redactions":2`, `"redactions":1`},
		{`"policy":"abc"`, `"policy":"abd"`},
		{`{\"p\":1}`, `{\"p\":2}`},
	} {
		b := record(t, auditLine(1, "t", "p", "tool_call", strings.Replace(base, change[0], change[1], 1))+"\n")
		if a == b {
			t.Errorf("changing %s to %s left the recording unchanged", change[0], change[1])
		}
	}
	if b := record(t, auditLine(1, "t", "p", "tool_denied", base)+"\n"); a == b {
		t.Error("changing the event left the recording unchanged")
	}
	// Distinct identifiers stay distinct and equal ones stay equal.
	two := record(t, auditLine(1, "t", "p", "e", `{"request_id":"x"}`)+"\n"+auditLine(2, "t", "p", "e", `{"request_id":"y"}`)+"\n")
	same := record(t, auditLine(1, "t", "p", "e", `{"request_id":"x"}`)+"\n"+auditLine(2, "t", "p", "e", `{"request_id":"x"}`)+"\n")
	if two == same || !strings.Contains(two, "#2") || strings.Contains(same, "#2") {
		t.Errorf("identifier numbering lost which records share a value:\n%s\n%s", two, same)
	}
}

func TestRecordDecisionsRejectsBadLogs(t *testing.T) {
	ok := auditLine(1, "t", "p", "e", `{}`)
	for name, log := range map[string]string{
		"seq gap":        ok + "\n" + auditLine(3, "t", "p", "e", `{}`) + "\n",
		"seq not from 1": auditLine(2, "t", "p", "e", `{}`) + "\n",
		"not json":       ok + "\n{\n",
		"empty line":     ok + "\n\n",
		"no event":       auditLine(1, "t", "p", "", `{}`) + "\n",
		"data array":     auditLine(1, "t", "p", "e", `[1]`) + "\n",
		"id not string":  auditLine(1, "t", "p", "e", `{"request_id":7}`) + "\n",
		"long line":      auditLine(1, "t", "p", "e", `{"x":"`+strings.Repeat("a", 1<<20)+`"}`) + "\n",
	} {
		if err := RecordDecisions(strings.NewReader(log), &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var out bytes.Buffer
	if err := RecordDecisions(strings.NewReader(""), &out); err != nil || out.Len() != 0 {
		t.Errorf("empty log: %v %q", err, out.String())
	}
}

func TestDiffDecisions(t *testing.T) {
	a := []byte("x\ny\n")
	if d := DiffDecisions(a, []byte("x\ny\n")); d != "" {
		t.Errorf("equal: %s", d)
	}
	if d := DiffDecisions(a, []byte("x\nz\n")); !strings.Contains(d, "line 2 differs") || !strings.Contains(d, "recorded: y") || !strings.Contains(d, "now:      z") {
		t.Errorf("changed: %s", d)
	}
	if d := DiffDecisions(a, []byte("x\ny\nw\n")); !strings.Contains(d, "line 3: extra record w") {
		t.Errorf("extra: %s", d)
	}
	if d := DiffDecisions(a, []byte("x\n")); !strings.Contains(d, "line 2: missing record y") {
		t.Errorf("missing: %s", d)
	}
	if d := DiffDecisions(nil, nil); d != "" {
		t.Errorf("both empty: %s", d)
	}
}

// scenario drives a gateway through the demo's kinds of decision: an allowed
// call, a constraint denial, a deny rule, a rate limit, and an approval that
// is requested, granted, used and then needed again.
func scenario(t *testing.T, e *env) string {
	t.Helper()
	e.call(aliceKey, "fake.read_file", map[string]any{"path": "reports/q1.txt"})
	e.call(aliceKey, "fake.read_file", map[string]any{"path": "../secret.txt"})
	e.call(aliceKey, "fake.read_file", map[string]any{"path": "reports/.env"})
	e.call(aliceKey, "fake.read_file", map[string]any{"path": "reports/creds.txt"})
	for range 4 {
		e.call(aliceKey, "fake.echo", map[string]any{"text": "ping"})
	}
	e.clk.add(time.Minute)
	args := map[string]any{"text": "hello", "language": "de"}
	r := e.call(aliceKey, "fake.translate", args, lang("de"))
	if r.errCode() != mcp.CodeApprovalPending {
		t.Fatalf("want pending: %s", r.raw)
	}
	id := r.errData()["approval_id"].(string)
	if r := e.admin("POST", "/admin/approvals/"+id+"/approve", `{"ttl_seconds":120,"note":"ok"}`); r.status != 200 {
		t.Fatalf("approve: %s", r.raw)
	}
	e.clk.add(3 * time.Second)
	e.call(aliceKey, "fake.translate", args, lang("de"))
	e.call(aliceKey, "fake.translate", args, lang("de"))
	data, err := os.ReadFile(e.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := RecordDecisions(bytes.NewReader(data), &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestRecordedDecisionsMatchAcrossRuns(t *testing.T) {
	first := newEnv(t)
	second := newEnv(t)
	second.clk.add(400 * 24 * time.Hour) // another day, so every timestamp differs
	a, b := scenario(t, first), scenario(t, second)
	if d := DiffDecisions([]byte(a), []byte(b)); d != "" {
		t.Fatalf("the same scenario recorded differently on two gateways: %s", d)
	}
	for _, want := range []string{`"decision":"allow"`, `"decision":"deny"`, `"rule_id":"no-env"`,
		`"outcome":"rate_limited"`, `"outcome":"approval_pending"`, `"event":"approval_decided"`,
		`"<approval_id>#2"`, `"redactions":1`} {
		if !strings.Contains(a, want) {
			t.Errorf("recording has no %s:\n%s", want, a)
		}
	}
	for _, leak := range []string{`"time"`, `"prev"`, "apr_", first.clk.now().Format("2006-01-02")} {
		if strings.Contains(a, leak) {
			t.Errorf("recording still holds run-specific %s:\n%s", leak, a)
		}
	}
}

// The demo's recording is checked in; make sure it stays in normal form, so a
// hand edit cannot slip a timestamp or a raw identifier into it.
func TestDemoRecordingIsNormalised(t *testing.T) {
	data, err := os.ReadFile("../../../toolgate/examples/demo_decisions.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(data)
	if len(lines) == 0 {
		t.Fatal("empty recording")
	}
	for i, l := range lines {
		var r struct {
			Seq   int            `json:"seq"`
			Event string         `json:"event"`
			Data  map[string]any `json:"data"`
		}
		dec := json.NewDecoder(bytes.NewReader(l))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		if r.Seq != i+1 || r.Event == "" {
			t.Fatalf("line %d: seq %d event %q", i+1, r.Seq, r.Event)
		}
		for _, f := range numberedFields {
			if v, ok := r.Data[f]; ok && !strings.HasPrefix(fmt.Sprint(v), "<"+f+">#") {
				t.Errorf("line %d: %s is %v", i+1, f, v)
			}
		}
		for _, f := range clockFields {
			if v, ok := r.Data[f]; ok && v != "<"+f+">" {
				t.Errorf("line %d: %s is %v", i+1, f, v)
			}
		}
	}
}
