package gateway

import (
	"bytes"
	"context"
	"os"
	"regexp"
	"testing"
)

// TestProxiesDocCoversMigration keeps the "Moving from wicket" note in
// docs/proxies.md in step with the gateway: every WICKET_ variable that
// "authz gateway -h" documents is named there, and so is every command the
// note tells an operator to run.
func TestProxiesDocCoversMigration(t *testing.T) {
	doc, err := os.ReadFile("../../../../docs/proxies.md")
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"-h"}, func(string) string { return "" }, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("authz gateway -h: exit %d: %s", code, stderr.String())
	}
	vars := regexp.MustCompile(`\bWICKET_[A-Z_]+\b`).FindAllString(stderr.String(), -1)
	if len(vars) < 5 {
		t.Fatalf("authz gateway -h documents only %v", vars)
	}
	for _, v := range vars {
		if !bytes.Contains(doc, []byte(v)) {
			t.Errorf("docs/proxies.md does not mention %s, which authz gateway -h documents", v)
		}
	}
	for _, want := range []string{
		"authz gateway genkey",
		"authz gateway gensigningkey",
		"authz gateway check",
		"authz fakeidp",
		"/wicket -> /authz",
		"scripts/image-check.sh",
	} {
		if !bytes.Contains(doc, []byte(want)) {
			t.Errorf("docs/proxies.md does not mention %q", want)
		}
	}
	// Every gateway subcommand the doc runs must be one the usage lists.
	usage := stderr.String()
	for _, m := range regexp.MustCompile("authz gateway ([a-z]+)").FindAllStringSubmatch(string(doc), -1) {
		if !regexp.MustCompile(`(?m)^\s*(usage: )?authz gateway .*\b` + m[1] + `\b`).MatchString(usage) {
			t.Errorf("docs/proxies.md runs authz gateway %s, which authz gateway -h does not list", m[1])
		}
	}
}
