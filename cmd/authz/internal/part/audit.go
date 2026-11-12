package part

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
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

// The variables that make every subcommand sign checkpoints of its audit
// log. They are the platform's, not a section's: authz serve, gateway and
// mcp writing one file sign it with one key.
const (
	// AuditSigningKeyEnv holds the Ed25519 signing key in note form,
	// PRIVATE+KEY+<name>+<hash>+<key> ("authz audit keygen" makes one);
	// AuditSigningKeyEnv+"_FILE" names a file holding it instead.
	AuditSigningKeyEnv = "AUTHZ_AUDIT_SIGNING_KEY"
	// AuditCheckpointIntervalEnv is how often the state is signed when
	// records were added, a duration of at least audit.MinCheckpointEvery
	// (default audit.DefaultCheckpointEvery).
	AuditCheckpointIntervalEnv = "AUTHZ_AUDIT_CHECKPOINT_INTERVAL"
)

// AuditSigning is the checkpoint configuration the environment gives.
// Signer is nil when no key is set.
type AuditSigning struct {
	Signer *audit.Signer
	Every  time.Duration
}

// AuditSigningFromEnv reads AUTHZ_AUDIT_SIGNING_KEY (or its _FILE
// spelling) and AUTHZ_AUDIT_CHECKPOINT_INTERVAL. A malformed key or
// interval, both spellings of the key, a key file that cannot be read, or
// an interval without a key is an error that starts with the variable's
// name and a colon; no error repeats the key.
func AuditSigningFromEnv(getenv func(string) string) (AuditSigning, error) {
	var out AuditSigning
	fileVar := AuditSigningKeyEnv + pcfg.SecretFileSuffix
	key, file := getenv(AuditSigningKeyEnv), getenv(fileVar)
	switch {
	case key != "" && file != "":
		return out, fmt.Errorf("%s: set by both %s and %s; unset one", AuditSigningKeyEnv, AuditSigningKeyEnv, fileVar)
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return out, fmt.Errorf("%s: %v", fileVar, err)
		}
		if key = strings.TrimSpace(string(b)); key == "" {
			return out, fmt.Errorf("%s: %s is empty", fileVar, file)
		}
	}
	every := getenv(AuditCheckpointIntervalEnv)
	if key == "" {
		if every != "" {
			return out, fmt.Errorf("%s: needs %s", AuditCheckpointIntervalEnv, AuditSigningKeyEnv)
		}
		return out, nil
	}
	name := AuditSigningKeyEnv
	if file != "" {
		name = fileVar
	}
	var err error
	if out.Signer, err = audit.ParseSigner(key); err != nil {
		return out, fmt.Errorf("%s: %s", name, strings.TrimPrefix(err.Error(), "audit: "))
	}
	if out.Every, err = audit.ParseCheckpointEvery(every); err != nil {
		return AuditSigning{}, fmt.Errorf("%s: %v", AuditCheckpointIntervalEnv, err)
	}
	return out, nil
}

// Options adds the signer, its interval and a reporter of failed
// checkpoints to o. The reporter logs at warning level: a checkpoint that
// could not be written does not stop the subcommand, and the next one
// tries again.
func (s AuditSigning) Options(o audit.Options, log *slog.Logger) audit.Options {
	if s.Signer == nil {
		return o
	}
	o.Signer, o.CheckpointEvery = s.Signer, s.Every
	o.OnCheckpointError = func(err error) {
		log.Warn("audit checkpoint not written; the next one tries again", "err", err.Error())
	}
	return o
}
