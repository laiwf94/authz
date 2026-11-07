package metrics

import (
	"fmt"
	"time"
)

// registerTracks registers every metric family grantd (authz serve), wicket
// (authz gateway) and toolgate (authz mcp, mcpfake) register, with the label
// sets, help texts and value shapes their call sites use, and fixed values.
// testdata/tracks.golden is its exposition, recorded from the three old
// packages before they were removed (they were byte-identical); TestTrackNames
// checks that it covers every name the tracks' sources register.
func registerTracks(r *Registry) {
	ms := time.Millisecond

	// grantd: internal/authz/api.
	r.Gauge("grantd_head_revision", "Newest committed revision.", func() float64 { return 42 })
	for i, route := range []string{"/v1/check", "/v1/relationships/write", "/metrics"} {
		r.Histogram("grantd_http_request_duration_seconds", `route="`+route+`"`, "HTTP request latency.").Observe(time.Duration(i+1) * 300 * time.Microsecond)
		r.Counter("grantd_http_requests_total", fmt.Sprintf(`route=%q,code="%d"`, route, 200), "HTTP requests.").Add(uint64(10 * (i + 1)))
	}
	r.Counter("grantd_http_requests_total", fmt.Sprintf(`route=%q,code="%d"`, "/v1/check", 400), "HTTP requests.").Inc()
	r.Counter("grantd_audit_failures_total", "", "Audit records that could not be written.").Add(0)
	r.Counter("grantd_audit_records_total", fmt.Sprintf("event=%q", "relationships.write"), "Audit records written.").Add(3)
	h := r.Histogram("grantd_check_duration_seconds", "", "Time to evaluate one check.")
	for _, d := range []time.Duration{40 * time.Microsecond, 120 * time.Microsecond, 2 * ms, 3 * time.Second} {
		h.Observe(d)
	}
	r.Counter("grantd_check_dispatches_total", "", "object#relation evaluations across all checks.").Add(17)
	r.Counter("grantd_check_cache_hits_total", "", "Check sub-results served from the cache.").Add(5)

	// wicket: internal/authn/server.
	r.Gauge("wicket_sessions", "Sessions held in memory.", func() float64 { return 7 })
	for _, route := range []string{"/auth", "/login", "/callback"} {
		r.Histogram("wicket_http_request_duration_seconds", `route="`+route+`"`, "HTTP request latency.").Observe(ms)
		r.Counter("wicket_http_requests_total", fmt.Sprintf(`route=%q,code="%d"`, route, 302), "HTTP requests.").Inc()
	}
	r.Counter("wicket_rate_limited_total", "", "Requests refused by the login rate limit.").Add(2)
	r.Counter("wicket_audit_failures_total", "", "Audit records that could not be written.")
	r.Counter("wicket_audit_records_total", `event="`+"login"+`"`, "Audit records written.").Add(4)
	for _, d := range []string{"allow", "deny", "login"} {
		r.Counter("wicket_auth_decisions_total", `decision="`+d+`"`, "Forward-auth decisions.").Inc()
	}
	r.Counter("wicket_logins_total", `result="failure",reason="`+"bad_state"+`"`, "Completed logins by result.").Inc()
	r.Counter("wicket_logins_total", `result="success",reason="ok"`, "Completed logins by result.").Add(9)

	// toolgate: internal/agents/gateway and internal/agents/httpx, whose
	// prefix is "toolgate" for the gateway and "mcpfake" for the fake server.
	r.Gauge("toolgate_approvals_pending", "Approval requests awaiting a decision.", func() float64 { return 1 })
	r.Gauge("toolgate_tools_quarantined", "Tools whose definition changed and awaits review.", func() float64 { return 0 })
	r.Gauge("toolgate_sessions_open", "Open legacy MCP sessions.", func() float64 { return 2 })
	r.Gauge("toolgate_audit_records", "Records in the audit log.", func() float64 { return 128 })
	for _, p := range []struct{ prefix, server, route string }{
		{"toolgate", "gateway", "/mcp"}, {"toolgate", "admin", "/metrics"}, {"mcpfake", "mcpfake", "/mcp"},
	} {
		r.Histogram(p.prefix+"_http_request_duration_seconds", fmt.Sprintf(`server=%q,route=%q`, p.server, p.route), "HTTP request latency.").Observe(5 * ms)
		r.Counter(p.prefix+"_http_requests_total", fmt.Sprintf(`server=%q,route=%q,code="%d"`, p.server, p.route, 200), "HTTP requests.").Inc()
	}
	r.Counter("toolgate_auth_failures_total", "", "Requests with a missing or invalid credential.").Inc()
	r.Counter("toolgate_rate_limited_total", `scope="agent"`, "Requests refused by a rate limit.").Inc()
	r.Counter("toolgate_rate_limited_total", `scope="tool"`, "Requests refused by a rate limit.").Inc()
	r.Counter("toolgate_upstream_errors_total", fmt.Sprintf(`upstream=%q,op="tools/list"`, "files"), "Failed upstream requests.").Inc()
	r.Counter("toolgate_upstream_errors_total", fmt.Sprintf(`upstream=%q,op="tools/call"`, "files"), "Failed upstream requests.").Inc()
	r.Counter("toolgate_tools_quarantined_total", "", "Tool definitions quarantined after a change.").Inc()
	r.Counter("toolgate_audit_failures_total", "", "Audit records that could not be written.")
	r.Counter("toolgate_audit_records_total", fmt.Sprintf("event=%q", "tool.call"), "Audit records written.").Add(6)
	r.Counter("toolgate_tool_calls_total", fmt.Sprintf(`upstream="",tool="",outcome=%q`, "unknown_tool"), "Tool calls by outcome.").Inc()
	r.Counter("toolgate_tool_calls_total", fmt.Sprintf(`upstream=%q,tool=%q,outcome=%q`, "files", "read", "allowed"), "Tool calls by outcome.").Add(11)
	r.Counter("toolgate_redactions_total", "", "Secrets redacted from tool results.").Add(1)
	r.Counter("toolgate_policy_reloads_total", `result="rejected"`, "Policy reload attempts.")
	r.Counter("toolgate_policy_reloads_total", `result="applied"`, "Policy reload attempts.").Inc()
}
