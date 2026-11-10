package gateway

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/check"
	"github.com/laiwf94/authz/internal/platform/audit"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
)

// WICKET_AUDIT_ROTATE_BYTES and _AGE, and their section members, rotate
// the audit log; malformed limits, limits under the minimum and limits
// without a log are refused.
func TestAuditRotationSettings(t *testing.T) {
	with := func(kv ...string) map[string]string {
		m := map[string]string{"WICKET_CONFIG": "/c.json", "WICKET_COOKIE_KEYS": cookieKey, "WICKET_AUDIT_LOG": "/a"}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	s, err := loadSettings(env(with("WICKET_AUDIT_ROTATE_BYTES", "65536", "WICKET_AUDIT_ROTATE_AGE", "168h")))
	if err != nil || s.auditRot != (audit.Rotation{MaxBytes: 65536, MaxAge: 168 * time.Hour}) {
		t.Fatalf("%+v %v", s.auditRot, err)
	}
	for kv, want := range map[[2]string]string{
		{"WICKET_AUDIT_ROTATE_BYTES", "big"}:  `WICKET_AUDIT_ROTATE_BYTES: size limit "big" is not a whole number of bytes`,
		{"WICKET_AUDIT_ROTATE_BYTES", "4095"}: "WICKET_AUDIT_ROTATE_BYTES: size limit 4095 is under the minimum of 4096 bytes",
		{"WICKET_AUDIT_ROTATE_AGE", "-1h"}:    "WICKET_AUDIT_ROTATE_AGE: must not be negative",
		{"WICKET_AUDIT_ROTATE_AGE", "30s"}:    "WICKET_AUDIT_ROTATE_AGE: age limit 30s is under the minimum of 1m0s",
	} {
		if _, err := loadSettings(env(with(kv[0], kv[1]))); err == nil || err.Error() != want {
			t.Errorf("%s=%s: %v, want %q", kv[0], kv[1], err, want)
		}
	}
	noLog := with("WICKET_AUDIT_ROTATE_BYTES", "65536")
	delete(noLog, "WICKET_AUDIT_LOG")
	if _, err := loadSettings(env(noLog)); err == nil || err.Error() != "WICKET_AUDIT_ROTATE_BYTES and WICKET_AUDIT_ROTATE_AGE need WICKET_AUDIT_LOG" {
		t.Errorf("without a log: %v", err)
	}

	sc := gatewaySchema(t, check.Options{Getenv: env(map[string]string{"CORP_SECRET": "s"})})
	for doc, want := range map[string]string{
		`"audit_log": "/a", "audit_rotate_bytes": 65536, "audit_rotate_age": "24h"`: "",
		`"audit_rotate_bytes": 65536`:                    "$.gateway.audit_rotate_bytes: needs audit_log",
		`"audit_log": "/a", "audit_rotate_age": "1s"`:    "$.gateway.audit_rotate_age: age limit 1s is under the minimum",
		`"audit_log": "/a", "audit_rotate_bytes": -4096`: "$.gateway.audit_rotate_bytes: must not be negative",
	} {
		r := sc.Check([]byte(`{"version": 1, "gateway": {"cookie_keys": {"env": "CK"}, `+doc+`, `+wicketDoc+`}}`), []string{"CK=" + cookieKey})
		if got := fmt.Sprint(r.Problems.Err()); (want == "" && got != "<nil>") || (want != "" && !strings.Contains(got, want)) {
			t.Errorf("%s: %s, want %q", doc, got, want)
			continue
		}
		if want == "" {
			st, err := sectionSettings(pcfg.Get[Settings](r.Config, SectionName))
			if err != nil || st.auditRot != (audit.Rotation{MaxBytes: 65536, MaxAge: 24 * time.Hour}) {
				t.Errorf("%s: settings %+v %v", doc, st.auditRot, err)
			}
		}
	}

	a := settings{auditLog: "/a"}
	b := a
	b.auditRot.MaxAge = time.Hour
	if got := restartOnly(a, b); !slices.Equal(got, []string{"audit_rotate_age"}) {
		t.Errorf("restartOnly: %q", got)
	}
	t.Setenv("WICKET_AUDIT_ROTATE_BYTES", "65536")
	if got := wicketVars(env(map[string]string{"WICKET_AUDIT_ROTATE_BYTES": "65536"})); !slices.Contains(got, "WICKET_AUDIT_ROTATE_BYTES") {
		t.Errorf("wicketVars: %q", got)
	}
}
