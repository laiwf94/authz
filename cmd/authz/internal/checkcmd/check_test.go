package checkcmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const docsSchema = `definition user {}

definition group {
  relation member: user | group#member
}

definition doc {
  relation owner: user
  relation viewer: user | group#member
  permission view = viewer + owner
}
`

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func run(t *testing.T, e map[string]string, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, env(e), strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestServeEnvironment(t *testing.T) {
	good := map[string]string{"GRANTD_API_KEYS": "check-test-key-0123456"}
	code, out, _ := run(t, good, "", "-serve")
	if code != OK || out != "env: serve environment is valid\n" {
		t.Fatalf("valid env: code %d, out %q", code, out)
	}

	file := write(t, "f", "")
	cases := map[string]map[string]string{
		"env: error: GRANTD_API_KEYS is required":                     {},
		"env: error: GRANTD_API_KEYS: key 2 is 5 characters":          {"GRANTD_API_KEYS": "check-test-key-0123456,short"},
		"env: error: GRANTD_ADDR: address localhost: missing port":    {"GRANTD_API_KEYS": "check-test-key-0123456", "GRANTD_ADDR": "localhost"},
		"env: error: GRANTD_DATA_DIR: " + file + " exists and is not": {"GRANTD_API_KEYS": "check-test-key-0123456", "GRANTD_DATA_DIR": file, "GRANTD_TOKEN_KEY": strings.Repeat("ab", 32)},
		"env: error: GRANTD_DATA_DIR: stat " + file + "/sub":          {"GRANTD_API_KEYS": "check-test-key-0123456", "GRANTD_DATA_DIR": file + "/sub", "GRANTD_TOKEN_KEY": strings.Repeat("ab", 32)},
		"env: error: GRANTD_TOKEN_KEY is required with":               {"GRANTD_API_KEYS": "check-test-key-0123456", "GRANTD_DATA_DIR": t.TempDir()},
	}
	for want, e := range cases {
		code, out, _ := run(t, e, "", "-serve")
		if code != Problems || !strings.Contains(out, want) {
			t.Errorf("env %v: code %d, out %q, want %q", e, code, out, want)
		}
	}
	// Every problem is reported, not just the first.
	code, out, _ = run(t, map[string]string{"GRANTD_API_KEYS": "a,b", "GRANTD_ADDR": "nope"}, "", "-serve")
	if code != Problems || strings.Count(out, "env: error:") != 3 || !strings.HasSuffix(out, "3 problems\n") {
		t.Fatalf("several problems: code %d, out %q", code, out)
	}
}

func TestSchemaFile(t *testing.T) {
	code, out, _ := run(t, nil, "", "-schema", write(t, "ok.schema", docsSchema))
	if code != OK || !strings.HasSuffix(out, "ok.schema: schema is valid: 3 definitions\n") {
		t.Fatalf("valid schema: code %d, out %q", code, out)
	}
	code, out, _ = run(t, nil, docsSchema, "-schema", "-")
	if code != OK || out != "-: schema is valid: 3 definitions\n" {
		t.Fatalf("schema on stdin: code %d, out %q", code, out)
	}

	bad := write(t, "bad.schema", "definition user {}\n\ndefinition doc {\n  relation owner: usr\n}\n")
	code, out, _ = run(t, nil, "", "-schema", bad)
	if code != Problems || !strings.Contains(out, bad+": error: ") || !strings.HasSuffix(out, "1 problem\n") {
		t.Fatalf("unknown type: code %d, out %q", code, out)
	}
	syntax := write(t, "syntax.schema", "definition user {}\ndefinition doc {\n  relation owner user\n}\n")
	code, out, _ = run(t, nil, "", "-schema", syntax)
	if code != Problems || !strings.HasPrefix(out, syntax+":3:") {
		t.Fatalf("syntax error should carry line and column: code %d, out %q", code, out)
	}
	huge := write(t, "huge.schema", "definition user {}\n"+strings.Repeat("// padding\n", 30000))
	code, out, _ = run(t, nil, "", "-schema", huge)
	if code != Problems || !strings.Contains(out, "larger than") {
		t.Fatalf("oversized schema: code %d, out %q", code, out)
	}
	code, out, _ = run(t, nil, "", "-schema", filepath.Join(t.TempDir(), "missing"))
	if code != Problems || !strings.Contains(out, "no such file") {
		t.Fatalf("missing file: code %d, out %q", code, out)
	}
}

func TestRelationshipsFile(t *testing.T) {
	sc := write(t, "docs.schema", docsSchema)
	rels := write(t, "rels.txt", `// people
group:eng#member@user:alice

doc:plan#viewer@group:eng#member
  doc:plan#owner@user:bob
`)
	code, out, _ := run(t, nil, "", "-schema", sc, "-relationships", rels)
	if code != OK || !strings.HasSuffix(out, "rels.txt: 3 relationships, valid against the schema\n") {
		t.Fatalf("valid relationships: code %d, out %q", code, out)
	}
	code, out, _ = run(t, nil, "doc:plan#viewer@user:carol", "-relationships", "-")
	if code != OK || out != "-: 1 relationship, syntax is valid\n" {
		t.Fatalf("syntax only from stdin, no trailing newline: code %d, out %q", code, out)
	}

	bad := write(t, "bad.txt", strings.Join([]string{
		"group:eng#member@user:alice",
		"doc:plan#view@user:alice",                             // a permission
		"doc:plan#owner@group:eng#member",                      // not allowed on owner
		"folder:root#parent@folder:x",                          // unknown type
		"doc:plan#viewer",                                      // syntax
		"doc:plan#viewer@user:" + strings.Repeat("a", maxLine), // too long
		"doc:plan#viewer@user:dave",
	}, "\n")+"\n")
	code, out, _ = run(t, nil, "", "-schema", sc, "-relationships", bad)
	for _, want := range []string{
		bad + ":2: error: doc#view is a permission",
		bad + ":3: error: doc#owner does not allow group#member (allowed: user)",
		bad + `:4: error: type "folder" is not defined`,
		bad + `:5: error: relationship "doc:plan#viewer" has no '@'`,
		bad + ":6: error: line is longer than",
		"5 problems\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code != Problems || strings.Contains(out, ":1:") || strings.Contains(out, ":7:") {
		t.Fatalf("code %d, out:\n%s", code, out)
	}

	// Syntax only, because the schema itself is broken.
	broken := write(t, "broken.schema", "definition {")
	code, out, _ = run(t, nil, "", "-schema", broken, "-relationships", rels)
	if code != Problems || !strings.Contains(out, rels+": schema is invalid; checking syntax only") ||
		!strings.Contains(out, "3 relationships, syntax is valid") || !strings.HasSuffix(out, "1 problem\n") {
		t.Fatalf("broken schema: code %d, out %q", code, out)
	}
}

func TestUsage(t *testing.T) {
	cases := map[string][]string{
		"nothing to check":        {},
		"unexpected argument":     {"-serve", "extra"},
		"only one of -schema and": {"-schema", "-", "-relationships", "-"},
		"flag provided but not":   {"-nope"},
	}
	for want, args := range cases {
		code, _, errb := run(t, nil, "", args...)
		if code != Usage || !strings.Contains(errb, want) {
			t.Errorf("%q: code %d, stderr %q, want %q", args, code, errb, want)
		}
	}
	code, _, errb := run(t, nil, "", "-h")
	if code != OK || !strings.HasPrefix(errb, "usage: authz check") {
		t.Fatalf("-h: code %d, stderr %q", code, errb)
	}
}
