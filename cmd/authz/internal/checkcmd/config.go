package checkcmd

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/laiwf94/authz/cmd/authz/internal/gateway"
	"github.com/laiwf94/authz/cmd/authz/internal/mcp"
	"github.com/laiwf94/authz/cmd/authz/internal/part"
	"github.com/laiwf94/authz/cmd/authz/internal/serve"
	"github.com/laiwf94/authz/internal/authn/check"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/config"
)

// Schema is the platform configuration file the subcommands read: the
// serve, gateway and mcp sections. o configures the gateway's checks
// (wicket's, online or not); o.Getenv also resolves the upstream
// credentials the mcp section's agents config names.
func Schema(ctx context.Context, o check.Options) *config.Schema {
	return config.MustSchema(
		serve.Section(),
		gateway.Section(gateway.SectionOptions{Check: o, Context: ctx}),
		mcp.Section(o.Getenv),
	)
}

// checkConfig validates the platform configuration file at name.
func checkConfig(ctx context.Context, r *report, name string, getenv func(string) string, o check.Options) {
	sc := Schema(ctx, o)
	res, err := sc.LoadResult(name, sc.Environ(getenv))
	if err != nil {
		r.problem(name, strings.TrimPrefix(err.Error(), "config: "))
		return
	}
	for _, p := range res.Problems {
		where := name
		switch {
		case p.Env != "":
			where = p.Env
		case p.Line > 0:
			where = fmt.Sprintf("%s:%d:%d", name, p.Line, p.Column)
		}
		msg := p.Path + ": " + p.Message
		if p.Severity == config.SeverityWarning {
			r.warning(where, msg)
		} else {
			r.problem(where, msg)
		}
	}
	if res.Problems.Err() != nil {
		return
	}
	// The checkpoint signing key is the platform's, read by every
	// subcommand from the environment.
	if _, err := part.AuditSigningFromEnv(getenv); err != nil {
		where, msg, _ := strings.Cut(err.Error(), ": ")
		r.problem(where, msg)
		return
	}
	if probs := sharedAuditLogs(res.Config); len(probs) > 0 {
		for _, p := range probs {
			r.problem(name, p)
		}
		return
	}
	var present []string
	for _, s := range []string{serve.SectionName, gateway.SectionName, mcp.SectionName} {
		if res.Config.Has(s) {
			present = append(present, s)
		}
	}
	sections := "no sections"
	if len(present) > 0 {
		sections = fmt.Sprintf("%d %s (%s)", len(present), plural(len(present), "section", "sections"), strings.Join(present, ", "))
	}
	mode := "offline"
	if o.Online {
		mode = "online"
	}
	warns := res.Problems.Count(config.SeverityWarning)
	r.ok(fmt.Sprintf("%s: config is valid: %s, %d %s (%s checks)", name, sections,
		warns, plural(warns, "warning", "warnings"), mode))
}

// sharedAuditLogs reports sections that write one audit file with
// different rotation limits. Each of serve, gateway and mcp would refuse
// to open the file once another had rotated it under other limits, so the
// file is refused here, before any of them starts.
func sharedAuditLogs(c *config.Config) []string {
	type writer struct {
		section string
		rot     audit.Rotation
	}
	byFile := map[string][]writer{}
	var order []string
	add := func(section, path string, bytes int64, age config.Duration) {
		if path == "" {
			return
		}
		key := filepath.Clean(path)
		if abs, err := filepath.Abs(key); err == nil {
			key = abs
		}
		if _, ok := byFile[key]; !ok {
			order = append(order, key)
		}
		byFile[key] = append(byFile[key], writer{section, part.AuditRotation(bytes, age)})
	}
	if s := config.Get[serve.Settings](c, serve.SectionName); s != nil {
		add(serve.SectionName, s.AuditLog, s.AuditRotateBytes, s.AuditRotateAge)
	}
	if s := config.Get[gateway.Settings](c, gateway.SectionName); s != nil {
		add(gateway.SectionName, s.AuditLog, s.AuditRotateBytes, s.AuditRotateAge)
	}
	if s := config.Get[mcp.Settings](c, mcp.SectionName); s != nil {
		add(mcp.SectionName, s.AuditLog, s.AuditRotateBytes, s.AuditRotateAge)
	}
	var out []string
	for _, f := range order {
		ws := byFile[f]
		for _, w := range ws[1:] {
			if w.rot != ws[0].rot {
				out = append(out, fmt.Sprintf("$.%s.audit_rotate_bytes, $.%s.audit_rotate_age: %s and %s write the audit log %s with different rotation limits (%s, %s); every writer of one file must set the same",
					w.section, w.section, ws[0].section, w.section, f, ws[0].rot, w.rot))
			}
		}
	}
	return out
}
