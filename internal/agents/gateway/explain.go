package gateway

import (
	"bytes"
	"io"
	"net/http"

	"github.com/laiwf94/authz/internal/agents/httpx"
	"github.com/laiwf94/authz/internal/agents/jsonrpc"
	"github.com/laiwf94/authz/internal/agents/mcp"
	"github.com/laiwf94/authz/internal/agents/policy"
)

// explainResponse is what the gateway would do with a tools/call and why:
// the policy's explanation, and the gateway steps around it.
type explainResponse struct {
	*policy.Explanation
	// Outcome is the toolgate_tool_calls_total outcome a refusal is
	// counted under ("unknown_tool", "quarantined", "denied" or
	// "check_unavailable"), or "allowed" for a call that would go on to
	// the rate limits, quotas, approval and the upstream. Code is the
	// JSON-RPC error code of a refusal and Status its HTTP status in a
	// session of the current protocol; sessions of the 2025 revisions
	// get every refusal with HTTP 200.
	Outcome string `json:"outcome"`
	Code    int    `json:"code,omitempty"`
	Status  int    `json:"status"`
	// ToolKnown says whether the upstream's last tools/list offered the
	// tool; absent when the upstream has not been listed yet. Explaining
	// never lists an upstream.
	ToolKnown *bool `json:"tool_known,omitempty"`
}

// explainCall: POST /admin/explain. The body is a call file (see
// policy.ParseCall) without "checks": relationship checks are asked of
// the engine the gateway uses, explained with its trace when the engine
// can explain. Without "now" the call is decided at the gateway's clock.
// The answer is the policy's explanation, with every rule considered and
// what it found, and what the gateway would answer. Nothing changes: no
// rate limit or quota is counted, no approval is created, nothing is
// audited, no upstream is asked and no metric is counted.
func (g *Gateway) explainCall(w http.ResponseWriter, r *http.Request) error {
	if !httpx.IsJSON(r.Header.Get("Content-Type")) {
		return &httpx.Error{Status: http.StatusUnsupportedMediaType, Code: "invalid_argument", Msg: "Content-Type must be application/json"}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, policy.MaxCallBytes))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return httpx.BadRequest("the body must be a call: {\"subject\": {...}, \"call\": {\"tool\": \"upstream.tool\", \"arguments\": {...}}}")
	}
	c, err := policy.ParseCall(body)
	if err != nil {
		return httpx.BadRequest("%v", err)
	}
	if c.Checks != nil {
		return httpx.BadRequest("checks answers relationship checks without an engine; the gateway asks its engine, so leave it out")
	}
	if c.Now.IsZero() {
		c.Now = g.now()
	}
	p := g.opt.Policy.Current()
	d, ex := p.Explain(r.Context(), c.Now, c.Subject, c.Tool.Upstream, c.Tool.Tool, c.Arguments, g.engine, c.TraceNodes)
	out := &explainResponse{Explanation: ex, Outcome: "allowed", Status: http.StatusOK}
	refuse := func(outcome string, status, code int) {
		out.Outcome, out.Status, out.Code = outcome, status, code
	}
	// The steps of CallTool before the call goes on, in its order.
	u := g.ups[c.Tool.Upstream]
	var t *upTool
	if u != nil {
		u.mu.Lock()
		tools := u.tools
		u.mu.Unlock()
		if tools != nil {
			t = tools[c.Tool.Tool]
			known := t != nil
			out.ToolKnown = &known
		}
	}
	switch {
	case u == nil || out.ToolKnown != nil && !*out.ToolKnown:
		refuse("unknown_tool", http.StatusOK, jsonrpc.CodeInvalidParams)
	case t != nil && !g.opt.Pins.Trusted(c.Tool.String(), t.hash):
		refuse("quarantined", http.StatusOK, mcp.CodeToolQuarantined)
	case d.Allowed:
	case d.Unavailable:
		refuse("check_unavailable", http.StatusServiceUnavailable, mcp.CodeCheckUnavailable)
	case ex.Hidden:
		refuse("denied", http.StatusOK, jsonrpc.CodeInvalidParams)
	default:
		refuse("denied", http.StatusOK, mcp.CodePolicyDenied)
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}
