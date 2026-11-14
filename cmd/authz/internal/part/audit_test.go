package part

import (
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
)

func TestAuditSigningFromEnv(t *testing.T) {
	skey, vkey, err := audit.GenerateKey(rand.Reader, "audit.example")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "audit.key")
	os.WriteFile(keyFile, []byte(skey+"\n"), 0o600)
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	getenv := func(kv ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}

	s, err := AuditSigningFromEnv(getenv())
	if err != nil || s.Signer != nil {
		t.Fatalf("unset: %+v %v", s, err)
	}
	if o := s.Options(audit.Options{SameRotation: true}, slog.Default()); o.Signer != nil || !o.SameRotation {
		t.Fatalf("Options without a key changed: %+v", o)
	}
	for _, env := range []func(string) string{
		getenv("AUTHZ_AUDIT_SIGNING_KEY", skey),
		getenv("AUTHZ_AUDIT_SIGNING_KEY_FILE", keyFile),
	} {
		s, err := AuditSigningFromEnv(env)
		if err != nil || s.Signer == nil || s.Signer.Verifier().String() != vkey || s.Every != audit.DefaultCheckpointEvery {
			t.Fatalf("%+v %v", s, err)
		}
	}
	s, err = AuditSigningFromEnv(getenv("AUTHZ_AUDIT_SIGNING_KEY", skey, "AUTHZ_AUDIT_CHECKPOINT_INTERVAL", "15s"))
	if err != nil || s.Every != 15*time.Second {
		t.Fatalf("interval: %+v %v", s, err)
	}
	var reported []string
	log := slog.New(slog.NewTextHandler(writerFunc(func(b []byte) { reported = append(reported, string(b)) }), nil))
	o := s.Options(audit.Options{SameRotation: true}, log)
	if o.Signer != s.Signer || o.CheckpointEvery != 15*time.Second || !o.SameRotation || o.OnCheckpointError == nil {
		t.Fatalf("Options: %+v", o)
	}
	o.OnCheckpointError(errors.New("disk full"))
	if len(reported) != 1 || !strings.Contains(reported[0], "level=WARN") || !strings.Contains(reported[0], "disk full") {
		t.Fatalf("reported %q", reported)
	}

	s, err = AuditSigningFromEnv(getenv("AUTHZ_AUDIT_SIGNING_KEY", skey, "AUTHZ_AUDIT_RETAIN_BYTES", "1048576", "AUTHZ_AUDIT_RETAIN_AGE", "720h"))
	if err != nil || s.Retain != (audit.Retention{MaxBytes: 1 << 20, MaxAge: 720 * time.Hour}) {
		t.Fatalf("retention: %+v %v", s, err)
	}
	reported = nil
	o = s.Options(audit.Options{}, log)
	if o.Retention != s.Retain || o.OnRetainError == nil {
		t.Fatalf("Options: %+v", o)
	}
	o.OnRetainError(errors.New("segment busy"))
	if len(reported) != 1 || !strings.Contains(reported[0], "level=WARN") || !strings.Contains(reported[0], "segment busy") {
		t.Fatalf("reported %q", reported)
	}

	bad := strings.Replace(skey, "audit.example", "audit.other", 1)
	for _, tc := range []struct {
		env  func(string) string
		want string
	}{
		{getenv("AUTHZ_AUDIT_SIGNING_KEY", skey, "AUTHZ_AUDIT_SIGNING_KEY_FILE", keyFile), "AUTHZ_AUDIT_SIGNING_KEY: set by both"},
		{getenv("AUTHZ_AUDIT_SIGNING_KEY", "hunter2"), "AUTHZ_AUDIT_SIGNING_KEY: signing key must have the form PRIVATE+KEY+"},
		{getenv("AUTHZ_AUDIT_SIGNING_KEY", bad), "AUTHZ_AUDIT_SIGNING_KEY: signing key: the key hash does not match"},
		{getenv("AUTHZ_AUDIT_SIGNING_KEY", vkey), "AUTHZ_AUDIT_SIGNING_KEY: signing key must have the form"},
		{getenv("AUTHZ_AUDIT_SIGNING_KEY_FILE", filepath.Join(dir, "missing")), "AUTHZ_AUDIT_SIGNING_KEY_FILE: open "},
		{getenv("AUTHZ_AUDIT_SIGNING_KEY_FILE", empty), "AUTHZ_AUDIT_SIGNING_KEY_FILE: " + empty + " is empty"},
		{getenv("AUTHZ_AUDIT_SIGNING_KEY_FILE", filepath.Join(dir, "missing", "..", "empty", "x")), "AUTHZ_AUDIT_SIGNING_KEY_FILE:"},
		{getenv("AUTHZ_AUDIT_CHECKPOINT_INTERVAL", "1m"), "AUTHZ_AUDIT_CHECKPOINT_INTERVAL: needs AUTHZ_AUDIT_SIGNING_KEY"},
		{getenv("AUTHZ_AUDIT_SIGNING_KEY", skey, "AUTHZ_AUDIT_CHECKPOINT_INTERVAL", "100ms"), "AUTHZ_AUDIT_CHECKPOINT_INTERVAL: 100ms is shorter than the minimum of 1s"},
		{getenv("AUTHZ_AUDIT_SIGNING_KEY", skey, "AUTHZ_AUDIT_CHECKPOINT_INTERVAL", "often"), `AUTHZ_AUDIT_CHECKPOINT_INTERVAL: "often" is not a duration`},
		{getenv("AUTHZ_AUDIT_RETAIN_BYTES", "1048576"), "AUTHZ_AUDIT_RETAIN_BYTES: needs AUTHZ_AUDIT_SIGNING_KEY"},
		{getenv("AUTHZ_AUDIT_RETAIN_AGE", "720h"), "AUTHZ_AUDIT_RETAIN_AGE: needs AUTHZ_AUDIT_SIGNING_KEY"},
		{getenv("AUTHZ_AUDIT_SIGNING_KEY", skey, "AUTHZ_AUDIT_RETAIN_BYTES", "100"), "AUTHZ_AUDIT_RETAIN_BYTES: size limit 100 is under the minimum"},
		{getenv("AUTHZ_AUDIT_SIGNING_KEY", skey, "AUTHZ_AUDIT_RETAIN_BYTES", "1MB"), `AUTHZ_AUDIT_RETAIN_BYTES: size limit "1MB" is not a whole number`},
		{getenv("AUTHZ_AUDIT_SIGNING_KEY", skey, "AUTHZ_AUDIT_RETAIN_AGE", "10m"), "AUTHZ_AUDIT_RETAIN_AGE: age limit 10m0s is under the minimum"},
		{getenv("AUTHZ_AUDIT_SIGNING_KEY", skey, "AUTHZ_AUDIT_RETAIN_AGE", "-1h"), "AUTHZ_AUDIT_RETAIN_AGE: must not be negative"},
	} {
		s, err := AuditSigningFromEnv(tc.env)
		if err == nil || !strings.HasPrefix(err.Error(), tc.want) || s.Signer != nil {
			t.Errorf("%v, want %q", err, tc.want)
			continue
		}
		secret := skey[strings.LastIndexByte(skey, '+')+1:]
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("error repeats the key: %v", err)
		}
	}
}

type writerFunc func([]byte)

func (f writerFunc) Write(b []byte) (int, error) { f(b); return len(b), nil }
