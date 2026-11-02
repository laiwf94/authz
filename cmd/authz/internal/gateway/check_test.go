package gateway

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCheckCommand(t *testing.T) {
	dir := t.TempDir()
	good := writeConfig(t, dir)
	getenv := env(map[string]string{"CORP_SECRET": "s"})
	runIt := func(getenv func(string) string, args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := runCheck(context.Background(), args, getenv, &out, &errOut)
		return code, out.String(), errOut.String()
	}

	code, out, _ := runIt(getenv, good)
	if code != checkOK || out != good+": ok, 1 provider and 1 app, 0 warnings (offline checks)\n" {
		t.Fatalf("%d %q", code, out)
	}
	// WICKET_CONFIG is the default file.
	code, out, _ = runIt(env(map[string]string{"CORP_SECRET": "s", "WICKET_CONFIG": good}))
	if code != checkOK || !strings.Contains(out, ": ok,") {
		t.Fatalf("%d %q", code, out)
	}

	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{
  "public_url": "https://auth.example.com",
  "providers": [{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c",
    "client_secret_env": "CORP_SECRET", "colour": "blue"}],
  "apps": [{"id": "app", "hosts": ["app.example.com"], "providers": ["corp", "nope"], "allow": {}}]
}`), 0o600)
	code, out, _ = runIt(getenv, bad)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != checkProblems || len(lines) != 4 {
		t.Fatalf("%d\n%s", code, out)
	}
	for i, re := range []string{
		`^.*bad\.json:4:41: error: \$\.providers\[0\]\.colour: unknown field$`,
		`^.*bad\.json:5:78: error: \$\.apps\[0\]\.providers\[1\]: unknown provider "nope"$`,
		`^.*bad\.json:5:96: warning: \$\.apps\[0\]\.allow: nobody is allowed`,
		`^.*bad\.json: 2 errors, 1 warning \(offline checks\)$`,
	} {
		if !regexp.MustCompile(re).MatchString(lines[i]) {
			t.Errorf("line %d = %q, want %s", i, lines[i], re)
		}
	}

	// The online flag is accepted and reported; the provider is a closed
	// local port, so it fails quickly with a located error.
	b, _ := os.ReadFile(good)
	closed := filepath.Join(dir, "closed.json")
	os.WriteFile(closed, bytes.Replace(b, []byte("https://idp.example.com"), []byte("https://127.0.0.1:1"), 1), 0o600)
	code, out, _ = runIt(getenv, "-online", "-timeout", "2s", closed)
	if code != checkProblems || !strings.Contains(out, "$.providers[0].issuer:") || !strings.HasSuffix(out, "(online checks)\n") {
		t.Fatalf("%d %q", code, out)
	}

	missing := filepath.Join(dir, "missing.json")
	if code, out, _ = runIt(getenv, missing); code != checkProblems || !strings.HasPrefix(out, missing+": error: $: open ") {
		t.Fatalf("%d %q", code, out)
	}
	for _, args := range [][]string{{}, {"a.json", "b.json"}, {"-bogus"}, {"-timeout", "0s", good}} {
		if code, _, _ := runIt(env(nil), args...); code != checkUsage {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
	if code, _, errOut := runIt(env(nil), "-h"); code != checkOK || !strings.Contains(errOut, "usage: wicket check") {
		t.Errorf("-h: %d %q", code, errOut)
	}
	if plural(1, "app") != "1 app" || plural(0, "app") != "0 apps" {
		t.Error("plural")
	}
}
