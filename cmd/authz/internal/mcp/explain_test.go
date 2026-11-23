package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/agents/policy"
)

func TestPolicyExplainCommand(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	run := func(prog string, args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := cliAs(context.Background(), prog, append([]string{"policy", "explain"}, args...), nil, nil, &out, &errOut, nil)
		return code, out.String(), errOut.String()
	}
	pol := filepath.Join(examplesDir, "policy.json")
	call := write("call.json", `{"subject": {"agent": "alice-bot", "scopes": ["files:read"]},
	  "call": {"tool": "fake.read_file", "arguments": {"path": "../etc/passwd"}}}`)
	code, out, errOut := run(progName, pol, call)
	if code != 0 || errOut != "" {
		t.Fatalf("explain: %d %q", code, errOut)
	}
	for _, want := range []string{"fake.read_file: deny by default-deny\n", "  constraint rule: read-workspace\n",
		"  ! allow read-workspace           arguments_not_matched: $.path: path must not contain \"..\" segments\n",
		"    deny  no-dotenv                arguments_not_matched: "} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
	// A denial still exits 0: the explanation is the answer.
	code, out, _ = run(progName, "-json", pol, write("ok.json", `{"subject": {"agent": "alice-bot", "scopes": ["files:read"]},
	  "call": {"tool": "fake.read_file", "arguments": {"path": "reports/q1.txt"}}}`))
	var ex struct {
		Decision, Rule string
		Rules          []struct{ Rule, Result string }
	}
	if err := json.Unmarshal([]byte(out), &ex); code != 0 || err != nil || ex.Decision != "allow" || ex.Rule != "read-workspace" ||
		len(ex.Rules) == 0 || ex.Rules[0].Result != "arguments_not_matched" {
		t.Fatalf("json: %d %v %s", code, err, out)
	}

	for _, prog := range []string{progName, LegacyName} {
		if code, _, errOut := run(prog, pol); code != 2 || errOut != "usage: "+prog+" policy explain [-json] POLICY CALL\n" {
			t.Errorf("usage: %d %q", code, errOut)
		}
	}
	if code, _, errOut := run(progName, filepath.Join(dir, "missing"), call); code != 2 || !strings.Contains(errOut, "missing") {
		t.Errorf("missing policy: %d %s", code, errOut)
	}
	if code, _, _ := run(progName, pol, filepath.Join(dir, "missing")); code != 2 {
		t.Error("missing call")
	}
	if code, _, errOut := run(progName, write("bad.json", `{"version":1,"rules":[{"id":"x"}]}`), call); code != 2 || !strings.Contains(errOut, "bad.json") {
		t.Errorf("invalid policy: %d %s", code, errOut)
	}
	if code, _, errOut := run(progName, pol, write("badcall.json", `{"subject":{"agent":"a"},"call":{"tool":"x"}}`)); code != 2 ||
		!strings.Contains(errOut, "badcall.json: call: tool \"x\" must be written as upstream.tool") {
		t.Errorf("invalid call: %d %s", code, errOut)
	}
	if code, _, errOut := run(progName, pol, write("big.json", strings.Repeat(" ", policy.MaxCallBytes+1))); code != 2 || !strings.Contains(errOut, "larger than") {
		t.Errorf("large call: %d %s", code, errOut)
	}
	var help bytes.Buffer
	Run(context.Background(), []string{"-h"}, func(string) string { return "" }, nil, io.Discard, &help)
	if !strings.Contains(help.String(), "authz mcp policy explain [-json] POLICY CALL\n") {
		t.Errorf("help:\n%s", help.String())
	}
}
