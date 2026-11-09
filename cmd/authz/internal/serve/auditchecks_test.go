package serve

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	pcfg "github.com/laiwf94/authz/internal/platform/config"
)

// GRANTD_AUDIT_CHECKS and the section's audit_checks: a boolean that needs
// the audit log, applied on the next start.
func TestAuditChecksSetting(t *testing.T) {
	base := map[string]string{"GRANTD_API_KEYS": "integration-key-0123", "GRANTD_AUDIT_LOG": "/a"}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range base {
			m[a] = b
		}
		m[k] = v
		return m
	}
	for v, want := range map[string]bool{"": false, "true": true, "1": true, "false": false} {
		c, err := loadConfig(env(with("GRANTD_AUDIT_CHECKS", v)))
		if err != nil || c.auditChk != want {
			t.Errorf("GRANTD_AUDIT_CHECKS=%q: %v %v", v, c.auditChk, err)
		}
	}
	if _, err := loadConfig(env(with("GRANTD_AUDIT_CHECKS", "yes please"))); err == nil || err.Error() != "GRANTD_AUDIT_CHECKS must be true or false" {
		t.Errorf("bad value: %v", err)
	}
	noLog := with("GRANTD_AUDIT_CHECKS", "true")
	delete(noLog, "GRANTD_AUDIT_LOG")
	if _, err := loadConfig(env(noLog)); err == nil || err.Error() != "GRANTD_AUDIT_CHECKS needs GRANTD_AUDIT_LOG" {
		t.Errorf("without a log: %v", err)
	}

	sc := pcfg.MustSchema(Section())
	for doc, want := range map[string]string{
		`{"audit_checks": true}`:                    "$.serve.audit_checks: needs audit_log",
		`{"audit_checks": "on"}`:                    "$.serve.audit_checks: must be",
		`{"audit_checks": true, "audit_log": "/a"}`: "",
		`{"audit_checks": false}`:                   "",
	} {
		r := sc.Check([]byte(`{"version": 1, "serve": `+doc+`}`), []string{"AUTHZ_SERVE_API_KEYS=" + sectionKey})
		if got := fmt.Sprint(r.Problems.Err()); (want == "" && got != "<nil>") || (want != "" && !strings.HasPrefix(got, want)) {
			t.Errorf("%s: %s, want %q", doc, got, want)
			continue
		}
		if want == "" {
			c, err := settingsConfig(pcfg.Get[Settings](r.Config, SectionName))
			if err != nil || c.auditChk != strings.Contains(doc, "true") {
				t.Errorf("%s: config %v %v", doc, c.auditChk, err)
			}
		}
	}
	// The environment variable spelling of the section works too.
	r := sc.Check([]byte(`{"version": 1, "serve": {"audit_log": "/a"}}`), []string{"AUTHZ_SERVE_API_KEYS=" + sectionKey, "AUTHZ_SERVE_AUDIT_CHECKS=true"})
	if err := r.Problems.Err(); err != nil || !pcfg.Get[Settings](r.Config, SectionName).AuditChecks {
		t.Errorf("AUTHZ_SERVE_AUDIT_CHECKS: %v", err)
	}

	a := config{auditLog: "/a"}
	b := a
	b.auditChk = true
	if got := restartOnly(a, b); !slices.Equal(got, []string{"audit_checks"}) {
		t.Errorf("restartOnly: %q", got)
	}
	t.Setenv("GRANTD_AUDIT_CHECKS", "true")
	if got := grantdVars(env(map[string]string{"GRANTD_AUDIT_CHECKS": "true"})); !slices.Contains(got, "GRANTD_AUDIT_CHECKS") {
		t.Errorf("grantdVars: %q", got)
	}
}
