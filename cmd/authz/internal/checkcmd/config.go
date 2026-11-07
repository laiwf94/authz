package checkcmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/laiwf94/authz/cmd/authz/internal/gateway"
	"github.com/laiwf94/authz/cmd/authz/internal/mcp"
	"github.com/laiwf94/authz/cmd/authz/internal/serve"
	"github.com/laiwf94/authz/internal/authn/check"
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

// environ rebuilds an environment from getenv: every variable the process
// has and every override the schema reads, with the values getenv gives.
// A secret the file names as {"env": NAME} is found only when the process
// has NAME, as it is when the subcommand loads the file.
func environ(sc *config.Schema, getenv func(string) string) []string {
	names := map[string]bool{}
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok {
			names[k] = true
		}
	}
	for _, s := range []string{serve.SectionName, gateway.SectionName, mcp.SectionName} {
		for _, n := range sc.EnvNames(s) {
			names[n] = true
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		if v := getenv(n); v != "" {
			out = append(out, n+"="+v)
		}
	}
	sort.Strings(out)
	return out
}

// checkConfig validates the platform configuration file at name.
func checkConfig(ctx context.Context, r *report, name string, getenv func(string) string, o check.Options) {
	sc := Schema(ctx, o)
	res, err := sc.LoadResult(name, environ(sc, getenv))
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
