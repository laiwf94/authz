package mcp

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const examplesDir = "../../../../toolgate/examples"

// Under its old name the gateway prints its usage and errors as the toolgate
// binary did, with "toolgate" where "authz mcp" is otherwise; under
// "authz mcp" nothing says toolgate except the variable names.
func TestToolgateNameMessages(t *testing.T) {
	noEnv := func(string) string { return "" }
	missing := filepath.Join(t.TempDir(), "missing.json")
	for _, tc := range []struct {
		name   string
		args   []string
		exit   int
		stderr string // exact for "toolgate"; "authz mcp" is checked by substitution
	}{
		// These four are what the toolgate binary at dec2e96 printed.
		{"unknown subcommand", []string{"bogus"}, 1,
			"toolgate: usage: toolgate [serve] | audit verify [-head HASH] FILE | policy test [-v] POLICY CASES | token new|hash|mint\n"},
		{"audit verify without a file", []string{"audit", "verify"}, 2,
			"usage: toolgate audit verify [-head HASH] FILE\n"},
		{"policy test with one file", []string{"policy", "test", "p.json"}, 2,
			"usage: toolgate policy test [-v] POLICY CASES\n"},
		{"unknown token subcommand", []string{"token", "bogus"}, 1,
			"toolgate: usage: toolgate token new | hash | mint -sub ID [-owner NAME] [-scope \"a b\"] [-ttl 15m]\n"},
		{"unreadable policy", []string{"policy", "test", missing, missing}, 2,
			"toolgate: open " + missing + ": no such file or directory\n"},
		{"missing admin token", nil, 1,
			"toolgate: TOOLGATE_ADMIN_TOKEN is required (or AUTHZ_MCP_ADMIN_TOKEN)\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, prog := range []string{LegacyName, progName} {
				run := Toolgate
				if prog == progName {
					run = Run
				}
				var errOut bytes.Buffer
				code := run(context.Background(), tc.args, noEnv, nil, io.Discard, &errOut)
				want := strings.ReplaceAll(tc.stderr, "toolgate:", prog+":")
				want = strings.ReplaceAll(want, "toolgate [", prog+" [")
				want = strings.ReplaceAll(want, "usage: toolgate ", "usage: "+prog+" ")
				if code != tc.exit || errOut.String() != want {
					t.Errorf("%s %s:\n got exit %d: %q\nwant exit %d: %q", prog, strings.Join(tc.args, " "), code, errOut.String(), tc.exit, want)
				}
			}
		})
	}
}

func TestToolgateNameHelp(t *testing.T) {
	for _, tc := range []struct {
		run       func(context.Context, []string, func(string) string, io.Reader, io.Writer, io.Writer) int
		prog, not string
	}{
		{Toolgate, "toolgate", "authz mcp"},
		{Run, "authz mcp", "usage: toolgate"},
	} {
		var errOut bytes.Buffer
		if code := tc.run(context.Background(), []string{"-h"}, func(string) string { return "" }, nil, io.Discard, &errOut); code != 0 {
			t.Fatalf("%s -h: exit %d", tc.prog, code)
		}
		help := errOut.String()
		for _, sub := range []string{" [serve]\n", " audit verify [-head HASH] FILE\n", " policy test [-v] POLICY CASES\n", " token new | hash | mint"} {
			if !strings.Contains(help, tc.prog+sub) {
				t.Errorf("%s -h does not show %q:\n%s", tc.prog, tc.prog+sub, help)
			}
		}
		if strings.Contains(help, tc.not) {
			t.Errorf("%s -h mentions %q:\n%s", tc.prog, tc.not, help)
		}
		if !strings.Contains(help, "TOOLGATE_ADMIN_TOKEN      AUTHZ_MCP_ADMIN_TOKEN") {
			t.Errorf("%s -h lost the variable table:\n%s", tc.prog, help)
		}

		errOut.Reset()
		code := tc.run(context.Background(), []string{"-v", "policy", "test"}, func(string) string { return "" }, nil, io.Discard, &errOut)
		if code != 2 || !strings.HasPrefix(errOut.String(), tc.prog+": flag -v is not defined; flags follow the subcommand (\""+tc.prog+" token mint -sub ID\")\nusage: "+tc.prog+" [serve]\n") {
			t.Errorf("%s -v policy test: exit %d: %q", tc.prog, code, errOut.String())
		}
	}
}

// The old name runs the same commands with the same output: the example
// case file and the old binary's audit log give identical results under
// both names, and an environment that sets the two spellings of a variable
// differently is refused under both.
func TestToolgateNameSameResults(t *testing.T) {
	type result struct {
		code           int
		stdout, stderr string
	}
	both := func(args []string, getenv func(string) string) (result, result) {
		t.Helper()
		var rs [2]result
		for i, run := range []func(context.Context, []string, func(string) string, io.Reader, io.Writer, io.Writer) int{Toolgate, Run} {
			var out, errOut bytes.Buffer
			rs[i].code = run(context.Background(), args, getenv, nil, &out, &errOut)
			rs[i].stdout, rs[i].stderr = out.String(), errOut.String()
		}
		return rs[0], rs[1]
	}
	noEnv := func(string) string { return "" }

	old, cur := both([]string{"policy", "test", "-v", filepath.Join(examplesDir, "policy.json"), filepath.Join(examplesDir, "policy_cases.json")}, noEnv)
	if old != cur || old.code != 0 || !strings.Contains(old.stdout, "PASS 17 cases") {
		t.Fatalf("policy test:\ntoolgate:  %+v\nauthz mcp: %+v", old, cur)
	}

	data, err := os.ReadFile(filepath.Join(oldChainDir, "toolgate-demo.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(log, data, 0o600); err != nil {
		t.Fatal(err)
	}
	old, cur = both([]string{"audit", "verify", log}, noEnv)
	if old != cur || old.code != 0 || !strings.HasPrefix(old.stdout, "OK "+log+": 23 records, head ") {
		t.Fatalf("audit verify:\ntoolgate:  %+v\nauthz mcp: %+v", old, cur)
	}

	conflict := map[string]string{"TOOLGATE_ADDR": "127.0.0.1:1", "AUTHZ_MCP_ADDR": "127.0.0.1:2"}
	old, cur = both(nil, func(k string) string { return conflict[k] })
	if old.code != 2 || cur.code != 2 ||
		old.stderr != "toolgate: AUTHZ_MCP_ADDR and TOOLGATE_ADDR set to different values; unset one name of each pair\n" ||
		cur.stderr != "authz mcp: AUTHZ_MCP_ADDR and TOOLGATE_ADDR set to different values; unset one name of each pair\n" {
		t.Fatalf("conflicting variables:\ntoolgate:  %+v\nauthz mcp: %+v", old, cur)
	}
}
