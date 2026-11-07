// Package gateway is the policy enforcement point between agents and the MCP
// servers they call.
//
// Every tools/call passes these checks, in order, and each outcome is
// written to the audit log:
//
//  1. authentication (static key or signed token) and the agent's request rate;
//  2. the tool exists upstream, its definition is the trusted one (not
//     quarantined), and any Mcp-Param-* headers match the arguments;
//  3. policy: default deny, explicit deny wins, argument constraints;
//  4. the agent+tool rate limit;
//  5. human approval, for rules that require it;
//  6. the agent's daily quota;
//  7. an audit record of the decision, fsynced before anything is sent (if
//     the audit log cannot be written, the call is refused);
//  8. the upstream's concurrency limit; only then is an approval used up;
//  9. the call itself with the gateway's credential, a timeout and a
//     response size limit;
//  10. output guarding (redaction, truncation) and a final audit record.
package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/laiwf94/authz/internal/agents/approval"
	"github.com/laiwf94/authz/internal/agents/guard"
	"github.com/laiwf94/authz/internal/agents/httpx"
	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/agents/jsonrpc"
	"github.com/laiwf94/authz/internal/agents/mcp"
	"github.com/laiwf94/authz/internal/agents/metrics"
	"github.com/laiwf94/authz/internal/agents/pins"
	"github.com/laiwf94/authz/internal/agents/policy"
	"github.com/laiwf94/authz/internal/agents/ratelimit"
	"github.com/laiwf94/authz/internal/platform/audit"
)

// Version is reported as serverInfo.version.
const Version = "1.0.0"

// Limits that are not configurable.
const (
	MaxBodyBytes        = 1 << 20
	MaxToolsPerUpstream = 1000
	PreviewChars        = 256
	slotWait            = time.Second
)

// Options are the gateway's dependencies.
type Options struct {
	Config *Config
	Auth   *identity.Authenticator
	Policy *policy.Store
	Audit  *audit.Log
	Pins   *pins.Store
	// ApprovalLog is the file approval requests, decisions and grant uses
	// are kept in; empty keeps them in memory, lost on restart.
	ApprovalLog    string
	AuditKey       []byte // HMAC key for argument digests in the audit log
	AllowedOrigins []string
	Log            *slog.Logger
	Metrics        *metrics.Registry
	Now            func() time.Time
	// Transport carries upstream requests; nil uses a fresh http.Transport.
	Transport http.RoundTripper
}

// Gateway serves agents over MCP and administrators over the admin API.
type Gateway struct {
	opt       Options
	cfg       *Config
	log       *slog.Logger
	m         *metrics.Registry
	now       func() time.Time
	limits    map[string]Limits
	limiter   *ratelimit.Limiter
	quota     *ratelimit.Quota
	approvals *approval.Store
	ups       map[string]*upstream
	upNames   []string
	server    *mcp.Server
}

type upstream struct {
	cfg    UpstreamConfig
	client *mcp.Client
	sem    *ratelimit.Semaphore

	refreshMu sync.Mutex // one refresh at a time
	mu        sync.Mutex // guards the fields below
	tools     map[string]*upTool
	fetched   time.Time
	failedAt  time.Time // last failed refresh
	lastErr   error
}

type upTool struct {
	def    mcp.Tool
	hash   string
	params []mcp.HeaderParam
}

// New builds a gateway.
func New(opt Options) (*Gateway, error) {
	if opt.Config == nil || opt.Auth == nil || opt.Policy == nil || opt.Audit == nil || opt.Pins == nil {
		return nil, errors.New("gateway: config, authenticator, policy, audit log and pin store are required")
	}
	if len(opt.AuditKey) < 32 {
		return nil, errors.New("gateway: the audit key must be at least 32 bytes")
	}
	if opt.Log == nil {
		opt.Log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if opt.Metrics == nil {
		opt.Metrics = metrics.New()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Transport == nil {
		opt.Transport = &http.Transport{
			Proxy:                  nil, // upstream URLs come from config; never route them via the environment
			DialContext:            (&net.Dialer{Timeout: mcp.DefaultDialTimeout, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConnsPerHost:    64,
			IdleConnTimeout:        90 * time.Second,
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  2 * time.Minute,
			MaxResponseHeaderBytes: 64 << 10,
		}
	}
	c := opt.Config
	ap := c.Approvals
	acfg := approval.Config{
		PendingTTL:  time.Duration(ap.PendingTTLSeconds) * time.Second,
		MaxGrantTTL: time.Duration(ap.MaxGrantTTLSeconds) * time.Second,
		Now:         opt.Now,
	}
	approvals := approval.New(acfg)
	if opt.ApprovalLog != "" {
		var err error
		if approvals, err = approval.Open(opt.ApprovalLog, acfg); err != nil {
			return nil, err
		}
	}
	g := &Gateway{opt: opt, cfg: c, log: opt.Log, m: opt.Metrics, now: opt.Now,
		limits:    map[string]Limits{},
		limiter:   ratelimit.NewLimiter(opt.Now),
		quota:     ratelimit.NewQuota(opt.Now),
		approvals: approvals,
		ups:       map[string]*upstream{},
	}
	for _, a := range c.Agents {
		if a.Limits != nil {
			g.limits[a.ID] = *a.Limits
		}
	}
	for _, uc := range c.Upstreams {
		h := http.Header{}
		switch {
		case uc.credential == "":
		case uc.CredentialHeader != "":
			h.Set(uc.CredentialHeader, uc.credential)
		default:
			h.Set("Authorization", "Bearer "+uc.credential)
		}
		g.ups[uc.Name] = &upstream{cfg: uc, sem: ratelimit.NewSemaphore(uc.MaxConcurrency),
			client: mcp.NewClient(mcp.ClientConfig{URL: uc.URL, Header: h, MaxResponseBytes: uc.MaxResponseBytes,
				Info: mcp.Implementation{Name: "toolgate", Version: Version},
				HTTP: &http.Client{Transport: opt.Transport, CheckRedirect: mcp.NoRedirects}})}
		g.upNames = append(g.upNames, uc.Name)
	}
	sort.Strings(g.upNames)
	g.server = mcp.NewServer(mcp.ServerConfig{
		Info:           mcp.Implementation{Name: "toolgate", Version: Version},
		Instructions:   "Tools are named <upstream>.<tool>. Calls are checked against policy, rate limited and audited.",
		Handler:        g,
		AllowedOrigins: opt.AllowedOrigins,
		MaxBodyBytes:   MaxBodyBytes,
		Log:            opt.Log,
		Now:            opt.Now,
	})
	g.m.Gauge("toolgate_approvals_pending", "Approval requests awaiting a decision.", func() float64 { return float64(g.approvals.PendingCount()) })
	g.m.Gauge("toolgate_tools_quarantined", "Tools whose definition changed and awaits review.", func() float64 { return float64(opt.Pins.QuarantinedCount()) })
	g.m.Gauge("toolgate_sessions_open", "Open legacy MCP sessions.", func() float64 { return float64(g.server.SessionCount()) })
	g.m.Gauge("toolgate_audit_records", "Records in the audit log.", func() float64 { n, _ := opt.Audit.Head(); return float64(n) })
	opt.Policy.SetOnReload(g.policyReloaded)
	return g, nil
}

// Close closes the approval log. The gateway must not serve calls after it.
func (g *Gateway) Close() error { return g.approvals.Close() }

// Handler returns the agent-facing HTTP handler (/mcp and /healthz).
func (g *Gateway) Handler() http.Handler {
	hs := &httpx.Server{Name: "gateway", Prefix: "toolgate", Log: g.log, Metrics: g.m}
	mux := http.NewServeMux()
	mux.Handle("/mcp", hs.Wrap("/mcp", g.server.ServeHTTP))
	mux.Handle("GET /healthz", hs.Wrap("/healthz", g.healthz))
	mux.Handle("/", hs.Wrap("other", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "no such endpoint")
	}))
	return mux
}

func (g *Gateway) healthz(w http.ResponseWriter, r *http.Request) {
	if !g.opt.Audit.Healthy() {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "audit log unavailable"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (g *Gateway) limitsFor(agent string) Limits {
	if l, ok := g.limits[agent]; ok {
		return l
	}
	return g.cfg.Limits
}

func (g *Gateway) count(name, labels, help string) { g.m.Counter(name, labels, help).Inc() }

// Authenticate implements mcp.Handler: it checks the credential and the
// agent's overall request rate.
func (g *Gateway) Authenticate(r *http.Request) (any, string, error) {
	id, err := g.opt.Auth.Authenticate(httpx.Bearer(r))
	if err != nil {
		g.count("toolgate_auth_failures_total", "", "Requests with a missing or invalid credential.")
		g.log.Warn("authentication failed", "request_id", httpx.RequestID(r.Context()), "reason", err.Error())
		return nil, "", mcp.NewError(http.StatusUnauthorized, mcp.CodeUnauthenticated, "missing or invalid credential")
	}
	if ok, wait := g.limiter.Take("agent\x00"+id.AgentID, g.limitsFor(id.AgentID).agent()); !ok {
		g.count("toolgate_rate_limited_total", `scope="agent"`, "Requests refused by a rate limit.")
		return nil, "", &mcp.Error{RPC: jsonrpc.NewError(mcp.CodeRateLimited, "rate limit exceeded for agent %s", id.AgentID).
			WithData(map[string]any{"scope": "agent", "retry_after_ms": wait.Milliseconds()}),
			Status: http.StatusTooManyRequests, RetryAfter: wait}
	}
	return &id, "agent:" + id.AgentID, nil
}

func subjectOf(id *identity.Identity) policy.Subject {
	return policy.Subject{AgentID: id.AgentID, Scopes: id.Scopes}
}

// refreshBackoff is how long a failed tool-list refresh is remembered before
// the upstream is asked again, so that callers do not queue up behind
// repeated timeouts.
const refreshBackoff = 5 * time.Second

// toolsOf returns an upstream's tools, refreshing them when older than the
// upstream's TTL. While a refresh is running, or shortly after one failed,
// callers get the last good list instead of waiting; only a caller with no
// list at all waits for the refresh.
func (g *Gateway) toolsOf(ctx context.Context, u *upstream) (map[string]*upTool, error) {
	ttl := time.Duration(u.cfg.ToolsTTLSeconds) * time.Second
	u.mu.Lock()
	tools, fetched := u.tools, u.fetched
	u.mu.Unlock()
	if tools != nil && g.now().Sub(fetched) < ttl {
		return tools, nil
	}
	if tools != nil {
		if !u.refreshMu.TryLock() {
			return tools, nil // another caller is refreshing
		}
	} else {
		u.refreshMu.Lock()
	}
	defer u.refreshMu.Unlock()
	u.mu.Lock()
	tools, fetched, failedAt, lastErr := u.tools, u.fetched, u.failedAt, u.lastErr
	u.mu.Unlock()
	if tools != nil && g.now().Sub(fetched) < ttl {
		return tools, nil // refreshed by another caller while we waited
	}
	if !failedAt.IsZero() && g.now().Sub(failedAt) < refreshBackoff {
		if tools != nil {
			return tools, nil
		}
		return nil, lastErr
	}
	cctx, cancel := context.WithTimeout(ctx, u.cfg.Timeout())
	defer cancel()
	defs, err := u.client.ListTools(cctx)
	if err != nil {
		g.count("toolgate_upstream_errors_total", fmt.Sprintf(`upstream=%q,op="tools/list"`, u.cfg.Name), "Failed upstream requests.")
		g.log.Error("listing upstream tools failed", "upstream", u.cfg.Name, "error", err.Error())
		u.mu.Lock()
		u.failedAt, u.lastErr = g.now(), err
		u.mu.Unlock()
		if tools != nil {
			return tools, nil
		}
		return nil, err
	}
	fresh := g.buildTools(ctx, u.cfg.Name, defs)
	u.mu.Lock()
	u.tools, u.fetched, u.failedAt, u.lastErr = fresh, g.now(), time.Time{}, nil
	u.mu.Unlock()
	return fresh, nil
}

// buildTools validates upstream definitions and records each one with the
// pin store, which quarantines changed definitions.
func (g *Gateway) buildTools(ctx context.Context, up string, defs []mcp.Tool) map[string]*upTool {
	out := map[string]*upTool{}
	dup := map[string]bool{}
	for i, d := range defs {
		if i >= MaxToolsPerUpstream {
			g.log.Warn("upstream lists too many tools; the rest are ignored", "upstream", up, "limit", MaxToolsPerUpstream)
			break
		}
		ns := up + "." + d.Name
		if !mcp.ValidToolName(d.Name) || !mcp.ValidToolName(ns) {
			g.log.Warn("ignoring tool with an invalid name", "upstream", up, "tool", fmt.Sprintf("%.80q", d.Name))
			continue
		}
		if _, seen := out[d.Name]; seen || dup[d.Name] {
			delete(out, d.Name)
			dup[d.Name] = true
			g.log.Warn("ignoring tool listed twice", "upstream", up, "tool", d.Name)
			continue
		}
		canon, err := d.Canonical()
		if err != nil {
			g.log.Warn("ignoring invalid tool definition", "upstream", up, "tool", d.Name, "error", err.Error())
			continue
		}
		params, err := mcp.HeaderParams(d.InputSchema)
		if err != nil {
			g.log.Warn("ignoring tool with invalid x-mcp-header annotations", "upstream", up, "tool", d.Name, "error", err.Error())
			continue
		}
		ut := &upTool{def: d, hash: pins.Hash(canon), params: params}
		_, newly, err := g.opt.Pins.Observe(ns, canon)
		if err != nil {
			g.log.Error("saving tool pin failed", "tool", ns, "error", err.Error())
		}
		if newly {
			p, _ := g.opt.Pins.Get(ns)
			g.log.Warn("tool definition changed; quarantined until approved", "tool", ns, "trusted_hash", p.Hash, "new_hash", p.PendingHash)
			g.count("toolgate_tools_quarantined_total", "", "Tool definitions quarantined after a change.")
			g.audit(ctx, "tool_quarantined", map[string]any{"tool": ns, "trusted_hash": p.Hash, "new_hash": p.PendingHash})
		}
		out[d.Name] = ut
	}
	return out
}

// ListTools implements mcp.Handler: the tools this agent may call, from
// every reachable upstream, namespaced and in a stable order. Quarantined
// tools and tools no policy rule could allow are left out.
func (g *Gateway) ListTools(ctx context.Context, c *mcp.Caller) ([]mcp.Tool, error) {
	id := c.Principal.(*identity.Identity)
	p := g.opt.Policy.Current()
	subj := subjectOf(id)
	// Upstreams are asked in parallel, so one slow upstream delays the list
	// by its own timeout at most, not by the sum of all of them.
	lists := make([]map[string]*upTool, len(g.upNames))
	var wg sync.WaitGroup
	for i, name := range g.upNames {
		wg.Go(func() {
			if tools, err := g.toolsOf(ctx, g.ups[name]); err == nil {
				lists[i] = tools
			}
		})
	}
	wg.Wait()
	var out []mcp.Tool
	for i, name := range g.upNames {
		tools := lists[i] // nil when the upstream is down; list the others
		names := make([]string, 0, len(tools))
		for n := range tools {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			t := tools[n]
			ns := name + "." + n
			if !g.opt.Pins.Trusted(ns, t.hash) || !p.Visible(subj, name, n) {
				continue
			}
			d := t.def
			d.Name = ns
			out = append(out, d)
		}
	}
	return out, nil
}

type callRecord map[string]any

func (g *Gateway) audit(ctx context.Context, event string, data map[string]any) error {
	if rid := httpx.RequestID(ctx); rid != "" {
		data["request_id"] = rid
	}
	err := g.opt.Audit.Append(event, data)
	if err != nil {
		g.count("toolgate_audit_failures_total", "", "Audit records that could not be written.")
		g.log.Error("audit append failed", "event", event, "error", err.Error())
	} else {
		g.count("toolgate_audit_records_total", fmt.Sprintf("event=%q", event), "Audit records written.")
	}
	return err
}

// truncate cuts s to at most n bytes on a character boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func rpcErr(status, code int, data map[string]any, format string, args ...any) *mcp.Error {
	e := jsonrpc.NewError(code, format, args...)
	if data != nil {
		e = e.WithData(data)
	}
	return &mcp.Error{RPC: e, Status: status}
}

func unknownTool(name string) *mcp.Error {
	return rpcErr(http.StatusOK, jsonrpc.CodeInvalidParams, nil, "Unknown tool: %.200s", name)
}

// CallTool implements mcp.Handler.
func (g *Gateway) CallTool(ctx context.Context, c *mcp.Caller, name string, args map[string]any) (map[string]any, error) {
	start := g.now()
	id := c.Principal.(*identity.Identity)
	// early records refusals that happen before the tool is known. The name
	// came from the agent, so it is cut short and kept out of metric labels.
	early := func(outcome string, e *mcp.Error) (map[string]any, error) {
		_ = g.audit(ctx, "tool_call", map[string]any{"agent": id.AgentID, "owner": id.Owner, "auth": id.Method,
			"requested_tool": truncate(name, 128), "decision": "deny", "stage": "refused", "outcome": outcome})
		g.count("toolgate_tool_calls_total", fmt.Sprintf(`upstream="",tool="",outcome=%q`, outcome), "Tool calls by outcome.")
		return nil, e
	}
	upName, toolName, ok := strings.Cut(name, ".")
	u := g.ups[upName]
	if !ok || u == nil {
		return early("unknown_tool", unknownTool(name))
	}
	tools, err := g.toolsOf(ctx, u)
	if err != nil {
		return early("upstream_unavailable", rpcErr(http.StatusBadGateway, mcp.CodeUpstreamError, nil, "upstream %s is unavailable", upName))
	}
	t, ok := tools[toolName]
	if !ok {
		return early("unknown_tool", unknownTool(name))
	}
	canonArgs, err := jsonrpc.Canonical(args)
	if err != nil {
		return nil, rpcErr(http.StatusBadRequest, jsonrpc.CodeInvalidParams, nil, "arguments cannot be encoded")
	}
	argsSum := sha256.Sum256(canonArgs)
	mac := hmac.New(sha256.New, g.opt.AuditKey)
	mac.Write(canonArgs)
	p := g.opt.Policy.Current()
	rec := callRecord{
		"agent": id.AgentID, "owner": id.Owner, "auth": id.Method, "upstream": upName, "tool": toolName,
		"args_hmac": hex.EncodeToString(mac.Sum(nil)), "args_preview": guard.Preview(args, PreviewChars),
		"policy": p.Hash, "protocol": c.Version,
	}
	if id.KeyID != "" {
		rec["key_id"] = id.KeyID
	}
	refuse := func(outcome string, e *mcp.Error) (map[string]any, error) {
		rec["stage"], rec["outcome"] = "refused", outcome
		_ = g.audit(ctx, "tool_call", rec)
		g.count("toolgate_tool_calls_total", fmt.Sprintf(`upstream=%q,tool=%q,outcome=%q`, upName, toolName, outcome), "Tool calls by outcome.")
		return nil, e
	}

	if !g.opt.Pins.Trusted(name, t.hash) {
		rec["decision"], rec["rule_id"] = "deny", "tool-quarantine"
		return refuse("quarantined", rpcErr(http.StatusOK, mcp.CodeToolQuarantined, map[string]any{"tool": name},
			"tool %s changed its definition and is quarantined until an administrator reviews it", name))
	}
	if !c.Legacy {
		if err := mcp.CheckParamHeaders(c.Header, t.params, args); err != nil {
			rec["decision"], rec["rule_id"] = "deny", "header-mismatch"
			return refuse("header_mismatch", rpcErr(http.StatusBadRequest, mcp.CodeHeaderMismatch, nil, "Header mismatch: %v", err))
		}
	}

	d := p.Evaluate(subjectOf(id), upName, toolName, args)
	rec["rule_id"] = d.RuleID
	if d.ConstraintRuleID != "" {
		rec["constraint_rule_id"] = d.ConstraintRuleID
	}
	if !d.Allowed {
		rec["decision"], rec["reason"] = "deny", d.Reason
		if d.RuleID == policy.DefaultDenyID && d.ConstraintRuleID == "" && !p.Visible(subjectOf(id), upName, toolName) {
			// Do not confirm that a tool the agent cannot see exists.
			return refuse("denied", unknownTool(name))
		}
		return refuse("denied", rpcErr(http.StatusOK, mcp.CodePolicyDenied,
			map[string]any{"rule_id": d.RuleID, "reason": d.Reason}, "denied by policy: %s", d.Reason))
	}
	rec["decision"] = "allow"
	lim := g.limitsFor(id.AgentID)
	headers, err := mcp.ParamHeaders(t.params, args)
	if err != nil {
		return refuse("invalid_arguments", rpcErr(http.StatusBadRequest, jsonrpc.CodeInvalidParams, nil, "%v", err))
	}

	if ok, wait := g.limiter.Take("tool\x00"+id.AgentID+"\x00"+name, lim.tool()); !ok {
		g.count("toolgate_rate_limited_total", `scope="tool"`, "Requests refused by a rate limit.")
		e := rpcErr(http.StatusTooManyRequests, mcp.CodeRateLimited, map[string]any{"scope": "tool", "retry_after_ms": wait.Milliseconds()},
			"rate limit exceeded for %s", name)
		e.RetryAfter = wait
		return refuse("rate_limited", e)
	}

	approvalID := ""
	if d.RequiresApproval {
		var e *mcp.Error
		if approvalID, e = g.approve(ctx, id, name, d.RuleID, canonArgs, hex.EncodeToString(argsSum[:]), rec); e != nil {
			return refuse(rec["outcome"].(string), e)
		}
	}

	if ok, wait := g.quota.Take(id.AgentID, lim.DailyQuota); !ok {
		e := rpcErr(http.StatusTooManyRequests, mcp.CodeQuotaExceeded, map[string]any{"limit": lim.DailyQuota},
			"daily quota of %d calls is used up", lim.DailyQuota)
		e.RetryAfter = wait
		return refuse("quota_exceeded", e)
	}

	rec["stage"] = "started"
	if err := g.audit(ctx, "tool_call", rec); err != nil {
		g.quota.Refund(id.AgentID)
		return nil, rpcErr(http.StatusServiceUnavailable, mcp.CodeAuditUnavailable, nil,
			"the audit log is unavailable, so calls are refused")
	}
	finish := func(outcome string, extra map[string]any) {
		rec["stage"], rec["outcome"] = "completed", outcome
		rec["latency_ms"] = g.now().Sub(start).Milliseconds()
		for k, v := range extra {
			rec[k] = v
		}
		_ = g.audit(ctx, "tool_call", rec)
		g.count("toolgate_tool_calls_total", fmt.Sprintf(`upstream=%q,tool=%q,outcome=%q`, upName, toolName, outcome), "Tool calls by outcome.")
	}

	if !u.sem.Acquire(ctx, slotWait) {
		g.quota.Refund(id.AgentID)
		finish("upstream_busy", nil)
		e := rpcErr(http.StatusTooManyRequests, mcp.CodeUpstreamBusy, nil, "upstream %s is at its concurrency limit", upName)
		e.RetryAfter = time.Second
		return nil, e
	}
	defer u.sem.Release()
	// Use the approval only now, when nothing but the upstream itself can stop
	// the call. Another identical call may have used it in the meantime.
	if approvalID != "" && !g.approvals.Consume(approvalID) {
		g.quota.Refund(id.AgentID)
		finish("approval_pending", nil)
		return nil, rpcErr(http.StatusOK, mcp.CodeApprovalPending, map[string]any{"approval_id": approvalID, "status": "used"},
			"the approval was used by another identical call; this call needs a new approval")
	}
	cctx, cancel := context.WithTimeout(ctx, u.cfg.Timeout())
	defer cancel()
	res, err := u.client.CallTool(cctx, toolName, args, headers)
	if err != nil {
		return nil, g.upstreamFailure(upName, err, d.Output, finish)
	}
	delete(res, "_meta")
	delete(res, "resultType")
	rep := d.Output.Apply(res)
	outcome := "ok"
	if isErr, _ := res["isError"].(bool); isErr {
		outcome = "tool_error"
	}
	finish(outcome, map[string]any{"response_bytes": rep.BytesAfter, "redactions": rep.Redactions, "truncated": rep.Truncated})
	if rep.Redactions > 0 {
		g.m.Counter("toolgate_redactions_total", "", "Secrets redacted from tool results.").Add(uint64(rep.Redactions))
	}
	return res, nil
}

// upstreamFailure maps an upstream error to what the agent sees. Upstream
// error text is passed on only in short form, through the rule's redaction
// patterns and the built-in ones.
func (g *Gateway) upstreamFailure(up string, err error, out *guard.Guard, finish func(string, map[string]any)) *mcp.Error {
	g.count("toolgate_upstream_errors_total", fmt.Sprintf(`upstream=%q,op="tools/call"`, up), "Failed upstream requests.")
	var re *mcp.RPCError
	switch {
	case mcp.IsTimeout(err):
		finish("upstream_timeout", nil)
		return rpcErr(http.StatusGatewayTimeout, mcp.CodeUpstreamTimeout, nil, "upstream %s did not answer in time", up)
	case errors.As(err, &re):
		msg := out.RedactText(truncate(re.Err.Message, 200))
		finish("upstream_error", map[string]any{"upstream_code": re.Err.Code})
		return rpcErr(http.StatusBadGateway, mcp.CodeUpstreamError, map[string]any{"upstream_code": re.Err.Code},
			"upstream %s rejected the call: %s", up, msg)
	case errors.Is(err, mcp.ErrResponseTooLarge):
		finish("upstream_error", map[string]any{"error": "response too large"})
		return rpcErr(http.StatusBadGateway, mcp.CodeUpstreamError, nil, "upstream %s sent a response larger than the limit", up)
	case errors.Is(err, mcp.ErrInputRequired):
		finish("upstream_error", map[string]any{"error": "input required"})
		return rpcErr(http.StatusBadGateway, mcp.CodeUpstreamError, nil, "upstream %s asked for interactive input, which toolgate does not relay", up)
	default:
		g.log.Error("upstream call failed", "upstream", up, "error", err.Error())
		finish("upstream_error", map[string]any{"error": "unavailable"})
		return rpcErr(http.StatusBadGateway, mcp.CodeUpstreamError, nil, "upstream %s is unavailable", up)
	}
}

// approve runs the approval step. It returns the approval to consume when
// the call may proceed, and sets rec["outcome"] otherwise.
func (g *Gateway) approve(ctx context.Context, id *identity.Identity, tool, ruleID string, canonArgs []byte, argsHash string, rec callRecord) (string, *mcp.Error) {
	b := approval.Binding{AgentID: id.AgentID, Owner: id.Owner, Tool: tool, ArgsHash: argsHash,
		Arguments: json.RawMessage(canonArgs), RuleID: ruleID}
	req, out, err := g.approvals.Begin(b)
	if err != nil && !errors.Is(err, approval.ErrTooMany) {
		g.log.Error("opening an approval request failed", "agent", id.AgentID, "tool", tool, "error", err.Error())
		rec["outcome"] = "approval_unavailable"
		e := rpcErr(http.StatusServiceUnavailable, mcp.CodeApprovalPending, map[string]any{"status": "unavailable"},
			"the approval request could not be recorded; try again later")
		e.RetryAfter = 10 * time.Second
		return "", e
	}
	if err != nil {
		rec["outcome"] = "approval_limit"
		e := rpcErr(http.StatusTooManyRequests, mcp.CodeRateLimited, map[string]any{"scope": "approvals"},
			"too many open approval requests; wait for a decision")
		e.RetryAfter = 10 * time.Second
		return "", e
	}
	rec["approval_id"] = req.ID
	if out == approval.OutcomeOpened {
		g.log.Info("approval requested", "approval_id", req.ID, "agent", id.AgentID, "tool", tool)
		_ = g.audit(ctx, "approval_requested", map[string]any{"approval_id": req.ID, "agent": id.AgentID,
			"tool": tool, "rule_id": ruleID, "args_hmac": rec["args_hmac"], "args_preview": rec["args_preview"]})
	}
	if out == approval.OutcomeOpened || out == approval.OutcomePending {
		if wait := time.Duration(g.cfg.Approvals.WaitSeconds) * time.Second; wait > 0 {
			out = g.approvals.Wait(ctx, req.ID, wait)
		}
	}
	switch out {
	case approval.OutcomeProceed:
		return req.ID, nil
	case approval.OutcomeDenied:
		rec["outcome"] = "approval_denied"
		return "", rpcErr(http.StatusOK, mcp.CodeApprovalDenied, map[string]any{"approval_id": req.ID}, "a human denied this call")
	default:
		rec["outcome"] = "approval_pending"
		return "", rpcErr(http.StatusOK, mcp.CodeApprovalPending, map[string]any{
			"approval_id": req.ID, "status": "pending", "expires_at": req.ExpiresAt.UTC().Format(time.RFC3339),
			"retry": "call the tool again with the same arguments once approved",
		}, "this call needs human approval (request %s)", req.ID)
	}
}

func (g *Gateway) policyReloaded(r policy.ReloadResult) {
	data := map[string]any{"previous": r.PrevHash, "current": r.Hash}
	if r.Err != nil {
		data["error"] = r.Err.Error()
		g.count("toolgate_policy_reloads_total", `result="rejected"`, "Policy reload attempts.")
		g.log.Error("policy reload rejected; the previous policy stays in force", "error", r.Err.Error())
		_ = g.audit(context.Background(), "policy_rejected", data)
		return
	}
	g.count("toolgate_policy_reloads_total", `result="applied"`, "Policy reload attempts.")
	g.log.Info("policy reloaded", "hash", r.Hash)
	_ = g.audit(context.Background(), "policy_applied", data)
}
