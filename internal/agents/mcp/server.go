package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laiwf94/authz/internal/agents/httpx"
	"github.com/laiwf94/authz/internal/agents/jsonrpc"
)

// Caller describes one authenticated request to a Handler.
type Caller struct {
	Principal    any         // what Handler.Authenticate returned
	PrincipalKey string      // the identity sessions are bound to
	Version      string      // protocol version of this request
	Legacy       bool        // the request belongs to a handshake-based session
	Header       http.Header // the HTTP request headers
}

// Handler implements the methods a Server dispatches.
type Handler interface {
	// Authenticate identifies the caller. Returning an *Error with status
	// 401 asks the client for credentials.
	Authenticate(r *http.Request) (principal any, key string, err error)
	// ListTools returns the tools this caller may see, in a stable order.
	ListTools(ctx context.Context, c *Caller) ([]Tool, error)
	// CallTool runs a tool and returns its result object. Errors that are
	// *Error or *jsonrpc.Error are sent to the client as they are; any other
	// error becomes an internal error.
	CallTool(ctx context.Context, c *Caller, name string, args map[string]any) (map[string]any, error)
}

// ServerConfig configures a Server.
type ServerConfig struct {
	Info         Implementation
	Instructions string
	Handler      Handler
	// AllowedOrigins lists the browser origins (scheme://host[:port]) that
	// may call the server. Requests without an Origin header are not from a
	// browser and are allowed; any other Origin is refused with 403, which is
	// the DNS-rebinding defense the transport requires.
	AllowedOrigins    []string
	MaxBodyBytes      int64
	ListTTL           time.Duration // ttlMs advertised on tools/list
	SessionIdle       time.Duration
	MaxSessions       int
	MaxSessionsPerKey int
	Log               *slog.Logger
	Now               func() time.Time
	// Realm is the realm of Bearer challenges; empty is "toolgate".
	Realm string
	// Resource makes the server a protected resource: 401 and 403
	// challenges carry resource_metadata and its scopes, and
	// MetadataHandler serves its document. SetResource replaces it.
	Resource *Resource
}

// Server serves MCP over Streamable HTTP at a single endpoint.
type Server struct {
	cfg      ServerConfig
	origins  map[string]bool
	sessions *sessionStore
	resource atomic.Pointer[Resource]
}

// NewServer applies defaults and returns a server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.ListTTL <= 0 {
		cfg.ListTTL = 30 * time.Second
	}
	if cfg.SessionIdle <= 0 {
		cfg.SessionIdle = 30 * time.Minute
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 10_000
	}
	if cfg.MaxSessionsPerKey <= 0 {
		cfg.MaxSessionsPerKey = 32
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Realm == "" {
		cfg.Realm = "toolgate"
	}
	s := &Server{cfg: cfg, origins: map[string]bool{},
		sessions: newSessionStore(cfg.SessionIdle, cfg.MaxSessions, cfg.MaxSessionsPerKey, cfg.Now)}
	s.resource.Store(cfg.Resource)
	for _, o := range cfg.AllowedOrigins {
		s.origins[strings.ToLower(o)] = true
	}
	return s
}

// SetResource puts r in force for the challenges and the metadata
// document of requests that start after it; nil stops being a protected
// resource.
func (s *Server) SetResource(r *Resource) { s.resource.Store(r) }

// Resource returns the protected resource in force, or nil.
func (s *Server) Resource() *Resource { return s.resource.Load() }

// MetadataHandler serves the protected resource metadata of the resource
// in force (see Resource.ServeHTTP), or 404 without one. Mount it at
// MetadataWellKnown and below it.
func (s *Server) MetadataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.resource.Load().ServeHTTP(w, r) }
}

// SessionCount returns the number of open legacy sessions.
func (s *Server) SessionCount() int { return s.sessions.len() }

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := jsonrpc.Marshal(v)
	if err != nil {
		b, _ = jsonrpc.Marshal(jsonrpc.ErrorResponse(nil, jsonrpc.NewError(jsonrpc.CodeInternalError, "internal error")))
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

func (s *Server) writeError(w http.ResponseWriter, status int, id json.RawMessage, e *jsonrpc.Error) {
	s.writeChallenge(w, status, id, e, nil)
}

// writeChallenge sends an error; a 401, and a 403 with a challenge, carry
// WWW-Authenticate.
func (s *Server) writeChallenge(w http.ResponseWriter, status int, id json.RawMessage, e *jsonrpc.Error, c *Challenge) {
	if status == http.StatusUnauthorized || status == http.StatusForbidden && c != nil {
		w.Header().Set("WWW-Authenticate", s.resource.Load().WWWAuthenticate(s.cfg.Realm, c))
	}
	s.writeJSON(w, status, jsonrpc.ErrorResponse(id, e))
}

// fail sends a handler error.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, id json.RawMessage, err error) {
	var me *Error
	var je *jsonrpc.Error
	switch {
	case errors.As(err, &me):
		status := me.Status
		if status == 0 {
			status = http.StatusOK
		}
		if me.RetryAfter > 0 {
			secs := int((me.RetryAfter + time.Second - 1) / time.Second)
			w.Header().Set("Retry-After", strconv.Itoa(secs))
		}
		s.writeChallenge(w, status, id, me.RPC, me.Challenge)
	case errors.As(err, &je):
		s.writeError(w, http.StatusOK, id, je)
	default:
		s.cfg.Log.Error("handler error", "request_id", httpx.RequestID(r.Context()), "error", err.Error())
		s.writeError(w, http.StatusInternalServerError, id, jsonrpc.NewError(jsonrpc.CodeInternalError, "internal error"))
	}
}

func (s *Server) originAllowed(r *http.Request) bool {
	o := r.Header.Get("Origin")
	return o == "" || s.origins[strings.ToLower(o)]
}

// acceptsJSON reports whether the Accept header allows application/json.
// A missing header accepts anything.
func acceptsJSON(values []string) bool {
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			if q, ok := params["q"]; ok {
				if f, err := strconv.ParseFloat(q, 64); err != nil || f == 0 {
					continue
				}
			}
			if mt == "application/json" || mt == "application/*" || mt == "*/*" {
				return true
			}
		}
	}
	return false
}

// ServeHTTP handles the MCP endpoint.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.originAllowed(r) {
		s.writeError(w, http.StatusForbidden, nil, jsonrpc.NewError(jsonrpc.CodeInvalidRequest, "origin not allowed"))
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "POST, DELETE")
		s.writeError(w, http.StatusMethodNotAllowed, nil, jsonrpc.NewError(jsonrpc.CodeInvalidRequest,
			"use POST; this server does not offer a standalone SSE stream"))
		return
	}
	principal, key, err := s.cfg.Handler.Authenticate(r)
	if err != nil {
		s.fail(w, r, nil, err)
		return
	}
	c := &Caller{Principal: principal, PrincipalKey: key, Header: r.Header}
	if r.Method == http.MethodDelete {
		s.deleteSession(w, r, c)
		return
	}
	if !httpx.IsJSON(r.Header.Get("Content-Type")) {
		s.writeError(w, http.StatusUnsupportedMediaType, nil, jsonrpc.NewError(jsonrpc.CodeInvalidRequest, "Content-Type must be application/json"))
		return
	}
	if !acceptsJSON(r.Header.Values("Accept")) {
		s.writeError(w, http.StatusNotAcceptable, nil, jsonrpc.NewError(jsonrpc.CodeInvalidRequest, "Accept must allow application/json"))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			s.writeError(w, http.StatusRequestEntityTooLarge, nil, jsonrpc.NewError(jsonrpc.CodeInvalidRequest,
				"body is larger than %d bytes", s.cfg.MaxBodyBytes))
			return
		}
		s.writeError(w, http.StatusBadRequest, nil, jsonrpc.NewError(jsonrpc.CodeParseError, "could not read the body"))
		return
	}
	msg, id, rpcErr := jsonrpc.Decode(body)
	if rpcErr != nil {
		s.writeError(w, http.StatusBadRequest, id, rpcErr)
		return
	}
	if msg.Kind == jsonrpc.KindResponse {
		s.writeError(w, http.StatusBadRequest, nil, jsonrpc.NewError(jsonrpc.CodeInvalidRequest,
			"this server sends no requests, so it accepts no responses"))
		return
	}
	pv := r.Header.Get(HeaderProtocolVersion)
	switch {
	case msg.Method == MethodInitialize:
		s.initialize(w, r, msg, c)
	case pv == VersionModern:
		s.modern(w, r, msg, c)
	case r.Header.Get(HeaderSessionID) != "":
		s.legacy(w, r, msg, c)
	case pv == "":
		s.writeError(w, http.StatusBadRequest, msg.ID, jsonrpc.NewError(CodeHeaderMismatch,
			"missing %s header (send %s, or initialize for an older version)", HeaderProtocolVersion, VersionModern).
			WithData(map[string]any{"supported": SupportedVersions}))
	case IsLegacy(pv):
		s.writeError(w, http.StatusBadRequest, msg.ID, jsonrpc.NewError(jsonrpc.CodeInvalidRequest,
			"protocol version %s needs a session: send initialize first", pv))
	default:
		s.writeError(w, http.StatusBadRequest, msg.ID, jsonrpc.NewError(CodeUnsupportedProtocolVersion,
			"Unsupported protocol version").WithData(map[string]any{"supported": SupportedVersions, "requested": pv}))
	}
}

func decodeParams(raw json.RawMessage) (map[string]any, error) {
	if raw == nil {
		return map[string]any{}, nil
	}
	v, err := jsonrpc.DecodeValue(raw)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("params must be an object")
	}
	return m, nil
}

func invalidParams(format string, args ...any) *Error {
	return NewError(http.StatusBadRequest, jsonrpc.CodeInvalidParams, format, args...)
}

// modern serves a stateless 2026-07-28 request.
func (s *Server) modern(w http.ResponseWriter, r *http.Request, msg *jsonrpc.Message, c *Caller) {
	c.Version = VersionModern
	if hm := r.Header.Values(HeaderMethod); len(hm) > 1 || len(hm) == 1 && hm[0] != msg.Method {
		s.writeError(w, http.StatusBadRequest, msg.ID, jsonrpc.NewError(CodeHeaderMismatch,
			"Header mismatch: %s does not match the body's method", HeaderMethod))
		return
	}
	if msg.Kind == jsonrpc.KindNotification {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if len(r.Header.Values(HeaderMethod)) == 0 {
		s.writeError(w, http.StatusBadRequest, msg.ID, jsonrpc.NewError(CodeHeaderMismatch, "missing %s header", HeaderMethod))
		return
	}
	params, err := decodeParams(msg.Params)
	if err != nil {
		s.fail(w, r, msg.ID, invalidParams("%v", err))
		return
	}
	meta, _ := params["_meta"].(map[string]any)
	pv, _ := meta[MetaProtocolVersion].(string)
	if pv == "" {
		s.fail(w, r, msg.ID, invalidParams("params._meta must carry %s", MetaProtocolVersion))
		return
	}
	if pv != VersionModern {
		s.writeError(w, http.StatusBadRequest, msg.ID, jsonrpc.NewError(CodeHeaderMismatch,
			"Header mismatch: %s header does not match params._meta", HeaderProtocolVersion))
		return
	}
	if _, ok := meta[MetaClientCapabilities].(map[string]any); !ok {
		s.fail(w, r, msg.ID, invalidParams("params._meta must carry %s as an object", MetaClientCapabilities))
		return
	}
	if ci, ok := meta[MetaClientInfo]; ok {
		if _, isObj := ci.(map[string]any); !isObj {
			s.fail(w, r, msg.ID, invalidParams("%s must be an object", MetaClientInfo))
			return
		}
	}
	switch msg.Method {
	case MethodDiscover:
		s.writeResult(w, msg.ID, map[string]any{
			"supportedVersions": SupportedVersions,
			"capabilities":      map[string]any{"tools": map[string]any{}},
			"instructions":      s.cfg.Instructions,
			"ttlMs":             s.cfg.ListTTL.Milliseconds(),
			"cacheScope":        "public",
		}, true)
	case MethodToolsList:
		s.toolsList(w, r, msg, c, params)
	case MethodToolsCall:
		name, _ := params["name"].(string)
		hn := r.Header.Values(HeaderName)
		if len(hn) != 1 {
			s.writeError(w, http.StatusBadRequest, msg.ID, jsonrpc.NewError(CodeHeaderMismatch, "%s header is required once for tools/call", HeaderName))
			return
		}
		if dec, err := DecodeHeaderValue(hn[0]); err != nil || dec != name {
			s.writeError(w, http.StatusBadRequest, msg.ID, jsonrpc.NewError(CodeHeaderMismatch,
				"Header mismatch: %s does not match params.name", HeaderName))
			return
		}
		s.toolsCall(w, r, msg, c, params)
	default:
		s.writeError(w, http.StatusNotFound, msg.ID, jsonrpc.NewError(jsonrpc.CodeMethodNotFound, "Method not found: %s", msg.Method))
	}
}

// initialize opens a legacy session.
func (s *Server) initialize(w http.ResponseWriter, r *http.Request, msg *jsonrpc.Message, c *Caller) {
	if msg.Kind != jsonrpc.KindRequest {
		s.writeError(w, http.StatusBadRequest, nil, jsonrpc.NewError(jsonrpc.CodeInvalidRequest, "initialize must be a request"))
		return
	}
	params, err := decodeParams(msg.Params)
	if err != nil {
		s.fail(w, r, msg.ID, invalidParams("%v", err))
		return
	}
	requested, _ := params["protocolVersion"].(string)
	if requested == "" {
		s.fail(w, r, msg.ID, invalidParams("initialize needs params.protocolVersion"))
		return
	}
	if _, ok := params["capabilities"].(map[string]any); !ok {
		s.fail(w, r, msg.ID, invalidParams("initialize needs params.capabilities as an object"))
		return
	}
	// Answer with the requested version when it is a supported legacy one,
	// else with the newest legacy version (the client may then disconnect).
	negotiated := Version251125
	if IsLegacy(requested) {
		negotiated = requested
	}
	id, err := s.sessions.create(c.PrincipalKey, negotiated)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, msg.ID, jsonrpc.NewError(jsonrpc.CodeInternalError, "too many open sessions; retry later"))
		return
	}
	w.Header().Set(HeaderSessionID, id)
	s.writeResult(w, msg.ID, map[string]any{
		"protocolVersion": negotiated,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      s.cfg.Info,
		"instructions":    s.cfg.Instructions,
	}, false)
}

// legacy serves a request inside a handshake-based session.
func (s *Server) legacy(w http.ResponseWriter, r *http.Request, msg *jsonrpc.Message, c *Caller) {
	sess, ok := s.sessions.get(r.Header.Get(HeaderSessionID), c.PrincipalKey)
	if !ok {
		s.writeError(w, http.StatusNotFound, msg.ID, jsonrpc.NewError(jsonrpc.CodeInvalidRequest,
			"session not found or expired; send initialize to start a new one"))
		return
	}
	if pv := r.Header.Get(HeaderProtocolVersion); pv != "" && pv != sess.version {
		s.writeError(w, http.StatusBadRequest, msg.ID, jsonrpc.NewError(jsonrpc.CodeInvalidRequest,
			"%s %q does not match the session's version %s", HeaderProtocolVersion, pv, sess.version))
		return
	}
	c.Version, c.Legacy = sess.version, true
	if msg.Kind == jsonrpc.KindNotification {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	params, err := decodeParams(msg.Params)
	if err != nil {
		s.writeError(w, http.StatusOK, msg.ID, jsonrpc.NewError(jsonrpc.CodeInvalidParams, "%v", err))
		return
	}
	switch msg.Method {
	case MethodPing:
		s.writeResult(w, msg.ID, map[string]any{}, false)
	case MethodToolsList:
		s.toolsList(w, r, msg, c, params)
	case MethodToolsCall:
		s.toolsCall(w, r, msg, c, params)
	default:
		s.writeError(w, http.StatusOK, msg.ID, jsonrpc.NewError(jsonrpc.CodeMethodNotFound, "Method not found: %s", msg.Method))
	}
}

func (s *Server) toolsList(w http.ResponseWriter, r *http.Request, msg *jsonrpc.Message, c *Caller, params map[string]any) {
	if cur, ok := params["cursor"]; ok && cur != "" {
		s.fail(w, r, msg.ID, &Error{RPC: jsonrpc.NewError(jsonrpc.CodeInvalidParams, "invalid cursor: the list is returned in one page"),
			Status: statusFor(c, http.StatusBadRequest)})
		return
	}
	tools, err := s.cfg.Handler.ListTools(r.Context(), c)
	if err != nil {
		s.fail(w, r, msg.ID, legacyStatus(c, err))
		return
	}
	if tools == nil {
		tools = []Tool{}
	}
	res := map[string]any{"tools": tools}
	if !c.Legacy {
		// The list depends on the caller's credentials, so shared caches
		// must not store it.
		res["ttlMs"] = s.cfg.ListTTL.Milliseconds()
		res["cacheScope"] = "private"
	}
	s.writeResult(w, msg.ID, res, !c.Legacy)
}

// statusFor returns status for modern requests and 200 for legacy ones:
// the 2025 revisions send JSON-RPC errors with a 200 response, and many
// clients written for them throw away the body of anything else.
func statusFor(c *Caller, status int) int {
	if c.Legacy {
		return http.StatusOK
	}
	return status
}

// legacyStatus sends a handler's error with HTTP 200 on a legacy session.
// Retry-After is kept, so a rate-limited client still learns when to retry.
// A 401 or 403 with a challenge keeps its status: clients of every
// revision start authorization, or step up their scopes, from it.
func legacyStatus(c *Caller, err error) error {
	var me *Error
	if c.Legacy && errors.As(err, &me) && me.Status != 0 && me.Status != http.StatusOK &&
		(me.Challenge == nil || me.Status != http.StatusUnauthorized && me.Status != http.StatusForbidden) {
		cp := *me
		cp.Status = http.StatusOK
		return &cp
	}
	return err
}

func (s *Server) toolsCall(w http.ResponseWriter, r *http.Request, msg *jsonrpc.Message, c *Caller, params map[string]any) {
	name, ok := params["name"].(string)
	if !ok || name == "" || len(name) > 256 {
		s.fail(w, r, msg.ID, &Error{RPC: jsonrpc.NewError(jsonrpc.CodeInvalidParams, "params.name must be a tool name"),
			Status: statusFor(c, http.StatusBadRequest)})
		return
	}
	args := map[string]any{}
	if raw, present := params["arguments"]; present && raw != nil {
		if args, ok = raw.(map[string]any); !ok {
			s.fail(w, r, msg.ID, &Error{RPC: jsonrpc.NewError(jsonrpc.CodeInvalidParams, "params.arguments must be an object"),
				Status: statusFor(c, http.StatusBadRequest)})
			return
		}
	}
	res, err := s.cfg.Handler.CallTool(r.Context(), c, name, args)
	if err != nil {
		s.fail(w, r, msg.ID, legacyStatus(c, err))
		return
	}
	s.writeResult(w, msg.ID, res, !c.Legacy)
}

// writeResult sends a result. Modern results carry resultType and the
// server's identity in _meta; legacy results carry neither.
func (s *Server) writeResult(w http.ResponseWriter, id json.RawMessage, res map[string]any, modern bool) {
	if modern {
		res["resultType"] = "complete"
		meta, _ := res["_meta"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
		}
		meta[MetaServerInfo] = s.cfg.Info
		res["_meta"] = meta
	} else {
		delete(res, "resultType")
	}
	s.writeJSON(w, http.StatusOK, jsonrpc.ResultResponse(id, res))
}

// deleteSession ends a legacy session (HTTP DELETE with Mcp-Session-Id).
func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request, c *Caller) {
	sid := r.Header.Get(HeaderSessionID)
	if sid == "" {
		w.Header().Set("Allow", "POST, DELETE")
		s.writeError(w, http.StatusBadRequest, nil, jsonrpc.NewError(jsonrpc.CodeInvalidRequest,
			"DELETE ends a session and needs the %s header", HeaderSessionID))
		return
	}
	if !s.sessions.remove(sid, c.PrincipalKey) {
		s.writeError(w, http.StatusNotFound, nil, jsonrpc.NewError(jsonrpc.CodeInvalidRequest, "session not found"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
