package serve

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
)

// GRANTD_AUDIT_ROTATE_BYTES and _AGE, and their section members, rotate
// the audit log; malformed limits, limits under the minimum and limits
// without a log are refused.
func TestAuditRotationSettings(t *testing.T) {
	with := func(kv ...string) map[string]string {
		m := map[string]string{"GRANTD_API_KEYS": sectionKey, "GRANTD_AUDIT_LOG": "/a"}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	c, err := loadConfig(env(with("GRANTD_AUDIT_ROTATE_BYTES", "1048576", "GRANTD_AUDIT_ROTATE_AGE", "24h")))
	if err != nil || c.auditRot != (audit.Rotation{MaxBytes: 1 << 20, MaxAge: 24 * time.Hour}) {
		t.Fatalf("%+v %v", c.auditRot, err)
	}
	if c, err := loadConfig(env(with())); err != nil || c.auditRot.Enabled() {
		t.Fatalf("unset: %+v %v", c.auditRot, err)
	}
	for kv, want := range map[[2]string]string{
		{"GRANTD_AUDIT_ROTATE_BYTES", "1MB"}: `GRANTD_AUDIT_ROTATE_BYTES: size limit "1MB" is not a whole number of bytes`,
		{"GRANTD_AUDIT_ROTATE_BYTES", "-5"}:  "GRANTD_AUDIT_ROTATE_BYTES: must not be negative",
		{"GRANTD_AUDIT_ROTATE_BYTES", "100"}: "GRANTD_AUDIT_ROTATE_BYTES: size limit 100 is under the minimum of 4096 bytes",
		{"GRANTD_AUDIT_ROTATE_AGE", "1d"}:    `GRANTD_AUDIT_ROTATE_AGE: age limit "1d" is not a duration such as 24h`,
		{"GRANTD_AUDIT_ROTATE_AGE", "10s"}:   "GRANTD_AUDIT_ROTATE_AGE: age limit 10s is under the minimum of 1m0s",
	} {
		if _, err := loadConfig(env(with(kv[0], kv[1]))); err == nil || err.Error() != want {
			t.Errorf("%s=%s: %v, want %q", kv[0], kv[1], err, want)
		}
	}
	noLog := with("GRANTD_AUDIT_ROTATE_AGE", "1h")
	delete(noLog, "GRANTD_AUDIT_LOG")
	if _, err := loadConfig(env(noLog)); err == nil || err.Error() != "GRANTD_AUDIT_ROTATE_BYTES and GRANTD_AUDIT_ROTATE_AGE need GRANTD_AUDIT_LOG" {
		t.Errorf("without a log: %v", err)
	}
	if errs := Check(env(with("GRANTD_AUDIT_ROTATE_BYTES", "x"))); len(errs) != 1 || !strings.HasPrefix(errs[0].Error(), "GRANTD_AUDIT_ROTATE_BYTES:") {
		t.Errorf("Check: %v", errs)
	}

	sc := pcfg.MustSchema(Section())
	for doc, want := range map[string]string{
		`{"audit_log": "/a", "audit_rotate_bytes": 65536, "audit_rotate_age": "24h"}`: "",
		`{"audit_log": "/a", "audit_rotate_bytes": 0, "audit_rotate_age": "0s"}`:      "",
		`{"audit_rotate_bytes": 65536}`:                                               "$.serve.audit_rotate_bytes: needs audit_log",
		`{"audit_rotate_age": "1h"}`:                                                  "$.serve.audit_rotate_age: needs audit_log",
		`{"audit_log": "/a", "audit_rotate_bytes": 10}`:                               "$.serve.audit_rotate_bytes: size limit 10 is under the minimum",
		`{"audit_log": "/a", "audit_rotate_bytes": -1}`:                               "$.serve.audit_rotate_bytes: must not be negative",
		`{"audit_log": "/a", "audit_rotate_bytes": "64k"}`:                            "$.serve.audit_rotate_bytes: must be",
		`{"audit_log": "/a", "audit_rotate_age": "5s"}`:                               "$.serve.audit_rotate_age: age limit 5s is under the minimum",
		`{"audit_log": "/a", "audit_rotate_age": "a day"}`:                            "$.serve.audit_rotate_age:",
	} {
		r := sc.Check([]byte(`{"version": 1, "serve": `+doc+`}`), []string{"AUTHZ_SERVE_API_KEYS=" + sectionKey})
		if got := fmt.Sprint(r.Problems.Err()); (want == "" && got != "<nil>") || (want != "" && !strings.HasPrefix(got, want)) {
			t.Errorf("%s: %s, want %q", doc, got, want)
			continue
		}
		if want == "" {
			c, err := settingsConfig(pcfg.Get[Settings](r.Config, SectionName))
			wantRot := audit.Rotation{}
			if strings.Contains(doc, "65536") {
				wantRot = audit.Rotation{MaxBytes: 65536, MaxAge: 24 * time.Hour}
			}
			if err != nil || c.auditRot != wantRot {
				t.Errorf("%s: config %+v %v", doc, c.auditRot, err)
			}
		}
	}
	// The AUTHZ_SERVE_ spelling overrides the section.
	r := sc.Check([]byte(`{"version": 1, "serve": {"audit_log": "/a"}}`),
		[]string{"AUTHZ_SERVE_API_KEYS=" + sectionKey, "AUTHZ_SERVE_AUDIT_ROTATE_BYTES=8192", "AUTHZ_SERVE_AUDIT_ROTATE_AGE=2h"})
	if s := pcfg.Get[Settings](r.Config, SectionName); r.Problems.Err() != nil || s.AuditRotateBytes != 8192 || time.Duration(s.AuditRotateAge) != 2*time.Hour {
		t.Errorf("AUTHZ_SERVE_AUDIT_ROTATE_*: %v", r.Problems.Err())
	}

	a := config{auditLog: "/a"}
	b := a
	b.auditRot = audit.Rotation{MaxBytes: 8192, MaxAge: time.Hour}
	if got := restartOnly(a, b); !slices.Equal(got, []string{"audit_rotate_bytes", "audit_rotate_age"}) {
		t.Errorf("restartOnly: %q", got)
	}
	t.Setenv("GRANTD_AUDIT_ROTATE_AGE", "1h")
	if got := grantdVars(env(map[string]string{"GRANTD_AUDIT_ROTATE_AGE": "1h"})); !slices.Contains(got, "GRANTD_AUDIT_ROTATE_AGE") {
		t.Errorf("grantdVars: %q", got)
	}
}
