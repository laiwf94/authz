package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"github.com/laiwf94/authz/internal/platform/audit"
)

var sessionIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// handleListSessions: GET /admin/sessions[?subject=...&limit=...]
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := adminListLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > adminListLimit {
			writeError(w, r, http.StatusBadRequest, "invalid_argument", "limit must be 1-1000")
			return
		}
		limit = n
	}
	subject := q.Get("subject")
	if len(subject) > 512 {
		writeError(w, r, http.StatusBadRequest, "invalid_argument", "subject is too long")
		return
	}
	list := s.sessions.List(subject, limit)
	if list == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sessions": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

// handleRevokeSession: DELETE /admin/sessions/{id}
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !sessionIDRe.MatchString(id) {
		writeError(w, r, http.StatusBadRequest, "invalid_argument", "session id must be 32 hex characters")
		return
	}
	found, err := s.sessions.Revoke(id)
	if !found {
		writeError(w, r, http.StatusNotFound, "not_found", "no such live session")
		return
	}
	s.audit(r.Context(), audit.Envelope{Actor: "admin", Subject: "session:" + id, Action: "session.revoke"},
		audit.SessionRevoked{Session: id, Count: 1, By: "admin"},
		slog.String("session", id), slog.String("by", "admin"))
	if err != nil {
		s.log.Error("persisting revocation", "request_id", requestIDFrom(r.Context()), "error", err.Error())
		writeError(w, r, http.StatusServiceUnavailable, "unavailable", "revoked now, but not saved; it may come back after a restart")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRevokeSubject: POST /admin/sessions/revoke {"subject": "...", "provider": "..."}
func (s *Server) handleRevokeSubject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subject  string `json:"subject"`
		Provider string `json:"provider"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}
	if req.Subject == "" || len(req.Subject) > 512 || len(req.Provider) > 64 {
		writeError(w, r, http.StatusBadRequest, "invalid_argument", "subject is required (at most 512 bytes)")
		return
	}
	n, err := s.sessions.RevokeSubject(req.Provider, req.Subject)
	if n > 0 {
		s.audit(r.Context(), audit.Envelope{Actor: "admin", Subject: req.Subject, Action: "session.revoke"},
			audit.SessionRevoked{Provider: req.Provider, Count: n, By: "admin"},
			slog.String("sub", req.Subject), slog.String("provider", req.Provider),
			slog.Int("count", n), slog.String("by", "admin"))
	}
	if err != nil {
		s.log.Error("persisting revocation", "request_id", requestIDFrom(r.Context()), "error", err.Error())
		writeError(w, r, http.StatusServiceUnavailable, "unavailable", "revoked now, but not saved; it may come back after a restart")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

// handleReload: POST /admin/reload
func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if err := s.Reload(r.Context()); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_config", err.Error())
		return
	}
	rt := s.rt.Load()
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": true, "providers": len(rt.providers), "apps": len(rt.apps)})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(http.MaxBytesReader(w, r.Body, MaxJSONBody)); err != nil {
		return errors.New("request body is too large or unreadable")
	}
	dec := json.NewDecoder(&buf)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body: " + err.Error())
	}
	if dec.More() {
		return errors.New("request body must be a single JSON object")
	}
	return nil
}
