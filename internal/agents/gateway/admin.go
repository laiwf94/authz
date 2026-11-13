package gateway

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/agents/approval"
	"github.com/laiwf94/authz/internal/agents/httpx"
	"github.com/laiwf94/authz/internal/agents/pins"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

// AdminHandler returns the administrator API. Every route except /healthz
// needs "Authorization: Bearer <admin token>"; the token is a separate
// credential from any agent's, so an agent cannot approve its own calls.
func (g *Gateway) AdminHandler(adminToken string) http.Handler {
	hs := &httpx.Server{Name: "admin", Prefix: "toolgate", Log: g.log, Metrics: g.m}
	mux := http.NewServeMux()
	route := func(pattern string, h func(http.ResponseWriter, *http.Request) error) {
		path := pattern[strings.IndexByte(pattern, ' ')+1:]
		mux.Handle(pattern, hs.Wrap(path, func(w http.ResponseWriter, r *http.Request) {
			if !httpx.TokenMatches(httpx.Bearer(r), adminToken) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="toolgate-admin"`)
				httpx.WriteError(w, r, http.StatusUnauthorized, "unauthenticated", "missing or invalid admin token")
				return
			}
			if err := h(w, r); err != nil {
				httpx.Fail(w, r, g.log, err)
			}
		}))
	}
	mux.Handle("GET /healthz", hs.Wrap("/healthz", g.healthz))
	route("GET /metrics", g.metrics)
	route("GET /admin/approvals", g.listApprovals)
	route("GET /admin/approvals/{id}", g.getApproval)
	route("POST /admin/approvals/{id}/approve", g.decide(true))
	route("POST /admin/approvals/{id}/deny", g.decide(false))
	route("GET /admin/tools", g.listTools)
	route("POST /admin/tools/{name}/approve", g.approveTool)
	route("GET /admin/policy", g.getPolicy)
	route("POST /admin/policy/reload", g.reloadPolicy)
	route("GET /admin/audit/head", g.auditHead)
	route("GET /admin/audit/checkpoint", g.auditCheckpoint)
	route("GET /admin/audit/proof", g.auditProof)
	mux.Handle("/", hs.Wrap("other", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "no such endpoint")
	}))
	return mux
}

const adminBodyLimit = 64 << 10

func (g *Gateway) metrics(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", metrics.ContentType)
	return g.m.Write(w)
}

func (g *Gateway) listApprovals(w http.ResponseWriter, r *http.Request) error {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"approvals": g.approvals.List()})
	return nil
}

func (g *Gateway) getApproval(w http.ResponseWriter, r *http.Request) error {
	req, ok := g.approvals.Get(r.PathValue("id"))
	if !ok {
		return &httpx.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such approval request"}
	}
	httpx.WriteJSON(w, http.StatusOK, req)
	return nil
}

func (g *Gateway) decide(approve bool) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		var body struct {
			TTLSeconds int    `json:"ttl_seconds"`
			Note       string `json:"note"`
		}
		if err := httpx.DecodeJSON(w, r, adminBodyLimit, &body); err != nil {
			return err
		}
		maxTTL := int(g.approvals.MaxGrantTTL() / time.Second)
		if approve && (body.TTLSeconds < 0 || body.TTLSeconds > maxTTL) {
			return httpx.BadRequest("ttl_seconds must be from 0 to %d (0 means 300)", maxTTL)
		}
		if !approve && body.TTLSeconds != 0 {
			return httpx.BadRequest("ttl_seconds applies only to approvals")
		}
		if len(body.Note) > 1024 {
			return httpx.BadRequest("note is longer than 1024 bytes")
		}
		ttl := time.Duration(body.TTLSeconds) * time.Second
		if ttl == 0 {
			ttl = 5 * time.Minute
		}
		req, err := g.approvals.Decide(r.PathValue("id"), approve, ttl, body.Note)
		switch {
		case errors.Is(err, approval.ErrNotFound):
			return &httpx.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such approval request (it may have expired)"}
		case errors.Is(err, approval.ErrNotPending):
			return &httpx.Error{Status: http.StatusConflict, Code: "failed_precondition", Msg: "the request was already decided"}
		case err != nil:
			return err
		}
		decision := "denied"
		if approve {
			decision = "approved"
		}
		if err := g.audit(r.Context(), "approval_decided", map[string]any{"approval_id": req.ID, "decision": decision,
			"agent": req.AgentID, "tool": req.Tool, "args_sha256": req.ArgsHash, "note": req.Note,
			"expires_at": req.ExpiresAt.UTC().Format(time.RFC3339)}); err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, req)
		return nil
	}
}

type toolView struct {
	pins.Pin
	Status string `json:"status"`
}

func (g *Gateway) listTools(w http.ResponseWriter, r *http.Request) error {
	list := g.opt.Pins.List()
	out := make([]toolView, len(list))
	for i, p := range list {
		out[i] = toolView{Pin: p, Status: "trusted"}
		if p.Quarantined() {
			out[i].Status = "quarantined"
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"tools": out})
	return nil
}

func (g *Gateway) approveTool(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Hash string `json:"hash"`
	}
	if err := httpx.DecodeJSON(w, r, adminBodyLimit, &body); err != nil {
		return err
	}
	if len(body.Hash) != 64 {
		return httpx.BadRequest("hash must be the 64-character pending_hash you reviewed")
	}
	name := r.PathValue("name")
	p, err := g.opt.Pins.Approve(name, body.Hash)
	switch {
	case errors.Is(err, pins.ErrNotFound):
		return &httpx.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such tool"}
	case errors.Is(err, pins.ErrNoChange):
		return &httpx.Error{Status: http.StatusConflict, Code: "failed_precondition", Msg: "the tool is not quarantined"}
	case errors.Is(err, pins.ErrHashChanged):
		return &httpx.Error{Status: http.StatusConflict, Code: "failed_precondition", Msg: err.Error()}
	case err != nil:
		return err
	}
	if err := g.audit(r.Context(), "tool_approved", map[string]any{"tool": name, "hash": p.Hash}); err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, toolView{Pin: p, Status: "trusted"})
	return nil
}

func (g *Gateway) getPolicy(w http.ResponseWriter, r *http.Request) error {
	p := g.opt.Policy.Current()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"hash": p.Hash, "rules": len(p.Rules)})
	return nil
}

func (g *Gateway) reloadPolicy(w http.ResponseWriter, r *http.Request) error {
	res := g.opt.Policy.Reload()
	if res.Err != nil {
		return &httpx.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_policy",
			Msg: "the policy file was rejected and the previous policy stays in force: " + res.Err.Error()}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"changed": res.Changed, "hash": res.Hash})
	return nil
}

func (g *Gateway) auditHead(w http.ResponseWriter, r *http.Request) error {
	n, head := g.opt.Audit.Head()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"records": n, "head": head})
	return nil
}

// auditCheckpoint serves the audit log's newest checkpoint, a signed note
// covering every record written so far (signed now if records were added
// since the last one), for an auditor to keep and later check the log
// against with only the public key: "authz audit verify -key".
func (g *Gateway) auditCheckpoint(w http.ResponseWriter, r *http.Request) error {
	msg, _, err := g.opt.Audit.Checkpoint()
	if errors.Is(err, audit.ErrNoSigner) {
		return &httpx.Error{Status: http.StatusNotFound, Code: "not_found",
			Msg: "the audit log signs no checkpoints; set AUTHZ_AUDIT_SIGNING_KEY"}
	}
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = w.Write(msg)
	return err
}

// Refresh lists every upstream's tools now, so that definition changes are
// noticed without waiting for an agent request.
func (g *Gateway) Refresh(ctx context.Context) {
	for _, name := range g.upNames {
		_, _ = g.toolsOf(ctx, g.ups[name])
	}
}

// auditProof serves an RFC 6962 proof over the audit log's records, as
// JSON (audit.Proof): with ?record=N that record N is in the log, with
// ?from=M that the log extends its first M records, an auditor's earlier
// checkpoint. Either is against the newest checkpoint, which the proof
// carries, or with &size=S against the first S records, a checkpoint the
// auditor kept. "authz audit prove -check" checks one with only the public
// key.
func (g *Gateway) auditProof(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	num := func(name string) (uint64, error) {
		v := q.Get(name)
		if v == "" {
			return 0, nil
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != v {
			return 0, httpx.BadRequest("%s must be a record count from 1", name)
		}
		return n, nil
	}
	for name := range q {
		if name != "record" && name != "from" && name != "size" || len(q[name]) != 1 {
			return httpx.BadRequest("the parameters are record or from, and size, each at most once")
		}
	}
	record, err := num("record")
	if err != nil {
		return err
	}
	from, err := num("from")
	if err != nil {
		return err
	}
	size, err := num("size")
	if err != nil {
		return err
	}
	var p audit.Proof
	switch {
	case (record == 0) == (from == 0):
		return httpx.BadRequest("give record=N for an inclusion proof or from=M for a consistency proof")
	case record != 0:
		p, err = g.opt.Audit.InclusionProof(record, size)
	default:
		p, err = g.opt.Audit.ConsistencyProof(from, size)
	}
	switch {
	case errors.Is(err, audit.ErrNoSigner):
		return &httpx.Error{Status: http.StatusNotFound, Code: "not_found",
			Msg: "the audit log signs no checkpoints, so it has no tree to prove against; set AUTHZ_AUDIT_SIGNING_KEY"}
	case errors.Is(err, audit.ErrProofRange):
		return &httpx.Error{Status: http.StatusNotFound, Code: "not_found", Msg: strings.TrimPrefix(err.Error(), "audit: ")}
	case err != nil:
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, p)
	return nil
}
