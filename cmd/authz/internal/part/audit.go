package part

import (
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
)

// The serve, gateway and mcp sections each have audit_log and the two
// rotation members beside it, audit_rotate_bytes and audit_rotate_age, with
// the same rules.

// CheckAuditRotation applies the rules on a section's audit_rotate_bytes
// and audit_rotate_age: each within audit.Rotation's limits, and only with
// audit_log.
func CheckAuditRotation(c *pcfg.Checker, auditLog string, bytes int64, age pcfg.Duration) {
	if err := (audit.Rotation{MaxBytes: bytes}).Validate(); err != nil {
		c.Errorf(c.Field("audit_rotate_bytes"), "%v", err)
	}
	if err := (audit.Rotation{MaxAge: time.Duration(age)}).Validate(); err != nil {
		c.Errorf(c.Field("audit_rotate_age"), "%v", err)
	}
	if auditLog == "" {
		if bytes != 0 {
			c.Errorf(c.Field("audit_rotate_bytes"), "needs audit_log")
		}
		if age != 0 {
			c.Errorf(c.Field("audit_rotate_age"), "needs audit_log")
		}
	}
}

// AuditRotation is the rotation a checked section's members configure.
func AuditRotation(bytes int64, age pcfg.Duration) audit.Rotation {
	return audit.Rotation{MaxBytes: bytes, MaxAge: time.Duration(age)}
}

// AuditRotationChanges names the rotation members that differ between a
// running configuration and a reloaded one; they apply on restart.
func AuditRotationChanges(a, b audit.Rotation) []string {
	var out []string
	if a.MaxBytes != b.MaxBytes {
		out = append(out, "audit_rotate_bytes")
	}
	if a.MaxAge != b.MaxAge {
		out = append(out, "audit_rotate_age")
	}
	return out
}
