//go:build unix

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
	pcfg "github.com/laiwf94/authz/internal/platform/config"
)

// AUTHZ_MCP_AUDIT_ROTATE_BYTES and _AGE, and their section members,
// rotate the audit log; malformed limits and limits under the minimum are
// refused. The settings are new, so they have no TOOLGATE_ names.
func TestAuditRotationSettings(t *testing.T) {
	s := newSetup(t)
	c, err := loadConfig(s.getenv)
	if err != nil || c.auditRot.Enabled() {
		t.Fatalf("unset: %+v %v", c.auditRot, err)
	}
	s.env["AUTHZ_MCP_AUDIT_ROTATE_BYTES"] = "16384"
	s.env["AUTHZ_MCP_AUDIT_ROTATE_AGE"] = "12h"
	if c, err = loadConfig(s.getenv); err != nil || c.auditRot != (audit.Rotation{MaxBytes: 16384, MaxAge: 12 * time.Hour}) {
		t.Fatalf("%+v %v", c.auditRot, err)
	}
	for kv, want := range map[[2]string]string{
		{"AUTHZ_MCP_AUDIT_ROTATE_BYTES", "16k"}: `AUTHZ_MCP_AUDIT_ROTATE_BYTES: size limit "16k" is not a whole number of bytes`,
		{"AUTHZ_MCP_AUDIT_ROTATE_BYTES", "1"}:   "AUTHZ_MCP_AUDIT_ROTATE_BYTES: size limit 1 is under the minimum of 4096 bytes",
		{"AUTHZ_MCP_AUDIT_ROTATE_AGE", "soon"}:  `AUTHZ_MCP_AUDIT_ROTATE_AGE: age limit "soon" is not a duration such as 24h`,
		{"AUTHZ_MCP_AUDIT_ROTATE_AGE", "59s"}:   "AUTHZ_MCP_AUDIT_ROTATE_AGE: age limit 59s is under the minimum of 1m0s",
	} {
		old := s.env[kv[0]]
		s.env[kv[0]] = kv[1]
		if _, err := loadConfig(s.getenv); err == nil || err.Error() != want {
			t.Errorf("%s=%s: %v, want %q", kv[0], kv[1], err, want)
		}
		s.env[kv[0]] = old
	}
	// A malformed limit stops the gateway before it opens anything.
	s.env["AUTHZ_MCP_AUDIT_ROTATE_BYTES"] = "-1"
	var out, errb bytes.Buffer
	if code := Run(context.Background(), nil, s.getenv, nil, &out, &errb); code != 1 || !strings.Contains(errb.String(), "AUTHZ_MCP_AUDIT_ROTATE_BYTES: must not be negative") {
		t.Fatalf("exit %d: %s", code, errb.String())
	}

	sc := mcpSchema(t, upstreamEnv)
	for extra, want := range map[string]string{
		`{"audit_rotate_bytes": 65536, "audit_rotate_age": "24h"}`: "",
		`{"audit_rotate_bytes": 100}`:                              "$.mcp.audit_rotate_bytes: size limit 100 is under the minimum",
		`{"audit_rotate_age": "-24h"}`:                             "$.mcp.audit_rotate_age: invalid duration",
		`{"audit_rotate_age": 5}`:                                  "$.mcp.audit_rotate_age:",
	} {
		var m map[string]any
		json.Unmarshal([]byte(extra), &m)
		r := sc.Check(goodSection(t, m), goodEnviron)
		if got := fmt.Sprint(r.Problems.Err()); (want == "" && got != "<nil>") || (want != "" && !strings.HasPrefix(got, want)) {
			t.Errorf("%s: %s, want %q", extra, got, want)
			continue
		}
		if want == "" {
			c, err := sectionConfig(pcfg.Get[Settings](r.Config, SectionName))
			if err != nil || c.auditRot != (audit.Rotation{MaxBytes: 65536, MaxAge: 24 * time.Hour}) {
				t.Errorf("%s: config %+v %v", extra, c.auditRot, err)
			}
		}
	}
	// AUTHZ_MCP_ overrides the section, as for every member.
	r := sc.Check(goodSection(t, nil), append(goodEnviron, "AUTHZ_MCP_AUDIT_ROTATE_BYTES=8192"))
	if s := pcfg.Get[Settings](r.Config, SectionName); r.Problems.Err() != nil || s.AuditRotateBytes != 8192 {
		t.Errorf("AUTHZ_MCP_AUDIT_ROTATE_BYTES: %v", r.Problems.Err())
	}

	a := config{auditPath: "/a"}
	b := a
	b.auditRot = audit.Rotation{MaxBytes: 8192}
	f := newFileSetup(t)
	sc2 := Schema(f.getenv)
	pc, err := sc2.Load(f.path, sc2.Environ(f.getenv))
	if err != nil {
		t.Fatal(err)
	}
	ag := pcfg.Get[Settings](pc, SectionName).agents
	if got := restartOnly(a, b, ag, ag); !slices.Equal(got, []string{"audit_rotate_bytes"}) {
		t.Errorf("restartOnly: %q", got)
	}
}

// A gateway set to rotate the shared audit log under other limits than the
// ones its active segment was cut under does not start.
func TestAuditRotationSameLimits(t *testing.T) {
	s := newSetup(t)
	path := s.env["TOOLGATE_AUDIT_LOG"]
	l, err := audit.OpenWith(path, audit.Options{Schemas: audit.Default(), Rotation: audit.Rotation{MaxBytes: audit.MinRotateBytes}})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		if err := l.Write(audit.Envelope{}, audit.ToolCall{Agent: "bot", Auth: "key", Decision: "allow", Stage: "policy", Tool: fmt.Sprint("t", i)}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	s.env["AUTHZ_MCP_AUDIT_ROTATE_BYTES"] = "8192"
	var out, errb bytes.Buffer
	code := Run(context.Background(), nil, s.getenv, nil, &out, &errb)
	want := "is rotated with max_bytes=4096, but this writer has max_bytes=8192; every process writing one audit file must set the same rotation limits"
	if code != 1 || !strings.Contains(errb.String(), want) {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
}
