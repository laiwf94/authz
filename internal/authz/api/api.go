// Package api serves grantd over HTTP with JSON bodies.
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

// Request limits.
const (
	MaxBodyBytes      = 1 << 20
	MaxBulkChecks     = 100
	DefaultTimeout    = 5 * time.Second
	MaxWatchWait      = 30 * time.Second
	DefaultQuantum    = 100 * time.Millisecond
	maxWatchChanges   = 1000
	requestIDHeader   = "X-Request-Id"
	maxRequestIDBytes = 128
)

// MinKeyLength is the shortest API key New accepts.
const MinKeyLength = 16

// Config configures a Server.
type Config struct {
	Store   *store.Store
	Tokens  *token.Issuer
	APIKeys []string // bearer tokens accepted by /v1; must not be empty
	Logger  *slog.Logger
	Metrics *metrics.Registry
	// CacheSize is the number of check results kept across requests; 0 disables it.
	CacheSize int
	// Quantum is how stale "minimize_latency" reads may be. Snapshots are
	// shared for this long so the cache can serve repeated checks.
	Quantum time.Duration
	Timeout time.Duration
	// Audit, when set, receives a typed record in the platform's hash chain
	// for every schema change and relationship write, with the API key's
	// fingerprint as the actor and the request ID as the correlation ID. It
	// should be opened with audit.Default() schemas. The server does not
	// close it.
	Audit *audit.Log
}

// Server is the HTTP API.
type Server struct {
	st      *store.Store
	eng     *check.Engine
	tokens  *token.Issuer
	keys    [][sha256.Size]byte
	keyIDs  []string // fingerprints of keys, for audit actors
	audit   *audit.Log
	log     *slog.Logger
	m       *metrics.Registry
	quantum time.Duration
	timeout time.Duration
	mux     *http.ServeMux

	snapMu   sync.Mutex
	snapRev  store.Revision
	snapTime time.Time
}

// New builds a server. It returns an error for unsafe configuration.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Tokens == nil {
		return nil, errors.New("api: store and token issuer are required")
	}
	if len(cfg.APIKeys) == 0 {
		return nil, errors.New("api: at least one API key is required")
	}
	s := &Server{st: cfg.Store, tokens: cfg.Tokens, log: cfg.Logger, m: cfg.Metrics,
		quantum: cfg.Quantum, timeout: cfg.Timeout, audit: cfg.Audit}
	for _, k := range cfg.APIKeys {
		if len(k) < MinKeyLength {
			return nil, fmt.Errorf("api: API keys must be at least %d characters", MinKeyLength)
		}
		sum := sha256.Sum256([]byte(k))
		s.keys = append(s.keys, sum)
		s.keyIDs = append(s.keyIDs, KeyID(k))
	}
	if s.log == nil {
		s.log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if s.m == nil {
		s.m = metrics.New()
	}
	if s.quantum <= 0 {
		s.quantum = DefaultQuantum
	}
	if s.timeout <= 0 {
		s.timeout = DefaultTimeout
	}
	s.eng = check.New(cfg.Store, check.NewCache(cfg.CacheSize))
	s.m.Gauge("grantd_head_revision", "Newest committed revision.", func() float64 { return float64(cfg.Store.Head()) })

	s.mux = http.NewServeMux()
	s.route("GET /healthz", s.healthz, false)
	s.route("GET /readyz", s.healthz, false)
	s.route("GET /metrics", s.metricsHandler, true)
	s.route("GET /v1/schema", s.getSchema, true)
	s.route("PUT /v1/schema", s.putSchema, true)
	s.route("POST /v1/relationships/write", s.write, true)
	s.route("POST /v1/relationships/read", s.read, true)
	s.route("POST /v1/check", s.check, true)
	s.route("POST /v1/check/bulk", s.checkBulk, true)
	s.route("POST /v1/lookup/resources", s.lookup, true)
	s.route("POST /v1/watch", s.watch, true)
	s.route("/", func(http.ResponseWriter, *http.Request) error {
		return &apiError{http.StatusNotFound, "not_found", "no such endpoint"}
	}, false)
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

type handler func(w http.ResponseWriter, r *http.Request) error

type ctxKey int

const (
	requestIDKey ctxKey = iota
	actorKey
)

// KeyID is the name an API key goes by in audit records: "api_key:" and
// the first 8 hex characters of a domain-separated SHA-256 of the key. It
// tells the keys of a deployment apart without the record revealing them.
func KeyID(key string) string {
	sum := sha256.Sum256([]byte("authz api key id\x00" + key))
	return "api_key:" + hex.EncodeToString(sum[:4])
}

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func requestID(r *http.Request) string {
	if id := r.Header.Get(requestIDHeader); requestIDRe.MatchString(id) {
		return id
	}
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// statusWriter remembers the response code for logs and metrics.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (s *Server) route(pattern string, h handler, auth bool) {
	path := pattern[strings.IndexByte(pattern, ' ')+1:]
	latency := s.m.Histogram("grantd_http_request_duration_seconds", `route="`+path+`"`, "HTTP request latency.")
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := requestID(r)
		sw := &statusWriter{ResponseWriter: w}
		sw.Header().Set(requestIDHeader, id)
		sw.Header().Set("Cache-Control", "no-store")
		sw.Header().Set("X-Content-Type-Options", "nosniff")
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		r = r.WithContext(ctx)
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic", "request_id", id, "route", path, "panic", fmt.Sprint(p))
				if sw.code == 0 {
					writeError(sw, r, http.StatusInternalServerError, "internal", "internal error")
				}
			}
			code := sw.code
			if code == 0 {
				code = http.StatusOK
			}
			latency.Observe(time.Since(start))
			s.m.Counter("grantd_http_requests_total", fmt.Sprintf(`route=%q,code="%d"`, path, code), "HTTP requests.").Inc()
			lvl := slog.LevelInfo
			if code >= 500 {
				lvl = slog.LevelError
			}
			s.log.Log(ctx, lvl, "request", "request_id", id, "method", r.Method, "route", path,
				"status", code, "duration_ms", float64(time.Since(start).Microseconds())/1000)
		}()
		if auth {
			k := s.authorized(r)
			if k < 0 {
				sw.Header().Set("WWW-Authenticate", `Bearer realm="grantd"`)
				writeError(sw, r, http.StatusUnauthorized, "unauthenticated", "missing or invalid API key")
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), actorKey, s.keyIDs[k]))
		}
		if path != "/" && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				writeError(sw, r, http.StatusUnsupportedMediaType, "invalid_argument", "Content-Type must be application/json")
				return
			}
			r.Body = http.MaxBytesReader(sw, r.Body, MaxBodyBytes)
		}
		if err := h(sw, r); err != nil {
			s.fail(sw, r, err)
		}
	})
}

// authorized compares the bearer token against every key in constant time
// and returns the index of the one it matches, or -1.
func (s *Server) authorized(r *http.Request) int {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" {
		return -1
	}
	sum := sha256.Sum256([]byte(tok))
	match := -1
	for i, k := range s.keys {
		match = subtle.ConstantTimeSelect(subtle.ConstantTimeCompare(sum[:], k[:]), i, match)
	}
	return match
}

// record appends one typed audit record, when an audit log is configured.
// The write it describes has committed, so a failure is counted and logged
// rather than returned; /healthz then reports the log unavailable.
func (s *Server) record(ctx context.Context, env audit.Envelope, p audit.Payload) {
	if s.audit == nil {
		return
	}
	env.Actor, _ = ctx.Value(actorKey).(string)
	env.CorrelationID, _ = ctx.Value(requestIDKey).(string)
	if err := s.audit.Write(env, p); err != nil {
		s.m.Counter("grantd_audit_failures_total", "", "Audit records that could not be written.").Inc()
		s.log.Error("audit write failed", "event", p.AuditEvent(), "request_id", env.CorrelationID, "error", err.Error())
		return
	}
	s.m.Counter("grantd_audit_records_total", fmt.Sprintf("event=%q", p.AuditEvent()), "Audit records written.").Inc()
}

// apiError carries an HTTP status and stable code.
type apiError struct {
	status int
	code   string
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return &apiError{http.StatusBadRequest, "invalid_argument", fmt.Sprintf(format, args...)}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &ae):
		writeError(w, r, ae.status, ae.code, ae.msg)
	case errors.As(err, &mbe):
		writeError(w, r, http.StatusRequestEntityTooLarge, "invalid_argument", fmt.Sprintf("request body is larger than %d bytes", MaxBodyBytes))
	case errors.Is(err, store.ErrInvalid), errors.Is(err, check.ErrUnknownType), errors.Is(err, check.ErrUnknownName),
		errors.Is(err, token.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "invalid_argument", err.Error())
	case errors.Is(err, store.ErrNoSchema):
		writeError(w, r, http.StatusFailedDependency, "no_schema", "write a schema first (PUT /v1/schema)")
	case errors.Is(err, store.ErrConflict):
		writeError(w, r, http.StatusConflict, "already_exists", err.Error())
	case errors.Is(err, store.ErrPrecondition):
		writeError(w, r, http.StatusPreconditionFailed, "failed_precondition", err.Error())
	case errors.Is(err, store.ErrSnapshotExpired):
		writeError(w, r, http.StatusGone, "snapshot_expired", err.Error())
	case errors.Is(err, check.ErrDepthExceeded), errors.Is(err, check.ErrTooMuchWork), errors.Is(err, store.ErrTooManyCandidate):
		writeError(w, r, http.StatusUnprocessableEntity, "resource_exhausted", err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, r, http.StatusGatewayTimeout, "deadline_exceeded", "the request took too long")
	case errors.Is(err, context.Canceled):
		writeError(w, r, 499, "canceled", "the client went away")
	case errors.Is(err, store.ErrUnavailable):
		s.log.Error("store unavailable", "request_id", r.Context().Value(requestIDKey), "error", err.Error())
		writeError(w, r, http.StatusServiceUnavailable, "unavailable", "storage is unavailable; retry later")
	default:
		s.log.Error("internal error", "request_id", r.Context().Value(requestIDKey), "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, "internal", "internal error")
	}
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	id, _ := r.Context().Value(requestIDKey).(string)
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg, "request_id": id}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return err
		}
		return badRequest("invalid JSON body: %v", err)
	}
	if dec.More() {
		return badRequest("request body must be a single JSON object")
	}
	return nil
}

func (s *Server) withTimeout(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), s.timeout)
}

// Consistency picks the snapshot a read uses.
type Consistency struct {
	// "minimize_latency" (default): a recent snapshot shared for up to Quantum.
	// "at_least_as_fresh": a snapshot no older than Token.
	// "at_exact_snapshot": exactly Token's snapshot.
	// "fully_consistent": the newest committed revision.
	Mode  string `json:"mode,omitempty"`
	Token string `json:"token,omitempty"`
}

func (s *Server) quantizedHead() store.Revision {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	if time.Since(s.snapTime) >= s.quantum {
		s.snapRev, s.snapTime = s.st.Head(), time.Now()
	}
	return s.snapRev
}

func (s *Server) resolve(c Consistency) (store.Revision, error) {
	switch c.Mode {
	case "", "minimize_latency":
		if c.Token != "" {
			return 0, badRequest("consistency.token is only used with at_least_as_fresh or at_exact_snapshot")
		}
		return s.quantizedHead(), nil
	case "fully_consistent":
		if c.Token != "" {
			return 0, badRequest("consistency.token is only used with at_least_as_fresh or at_exact_snapshot")
		}
		return s.st.Head(), nil
	case "at_least_as_fresh", "at_exact_snapshot":
		if c.Token == "" {
			return 0, badRequest("consistency mode %s needs a token", c.Mode)
		}
		rev, err := s.tokens.Decode(c.Token)
		if err != nil {
			return 0, err
		}
		head := s.st.Head()
		if rev > head {
			// A valid MAC with a future revision means the key is shared with a
			// store that has more history (e.g. restored from an old backup).
			return 0, badRequest("token is from a newer revision than this server has")
		}
		if c.Mode == "at_exact_snapshot" {
			return rev, nil
		}
		if q := s.quantizedHead(); q >= rev {
			return q, nil
		}
		return head, nil
	default:
		return 0, badRequest("unknown consistency mode %q", c.Mode)
	}
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) error {
	if s.audit != nil && !s.audit.Healthy() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "audit log unavailable",
			"revision": strconv.FormatUint(uint64(s.st.Head()), 10)})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "revision": strconv.FormatUint(uint64(s.st.Head()), 10)})
	return nil
}

func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", metrics.ContentType)
	return s.m.Write(w)
}

func (s *Server) getSchema(w http.ResponseWriter, r *http.Request) error {
	_, src := s.st.Schema()
	if src == "" {
		return store.ErrNoSchema
	}
	writeJSON(w, http.StatusOK, map[string]string{"schema": src})
	return nil
}

func (s *Server) putSchema(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Schema string `json:"schema"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if strings.TrimSpace(body.Schema) == "" {
		return badRequest("schema is empty")
	}
	rev, err := s.st.WriteSchema(body.Schema)
	if err != nil {
		return err
	}
	_, src := s.st.Schema()
	at := s.tokens.Encode(rev)
	sum := sha256.Sum256([]byte(src))
	s.record(r.Context(), audit.Envelope{Action: "schema.write"},
		audit.SchemaWritten{Revision: at, SHA256: hex.EncodeToString(sum[:]), Bytes: len(src)})
	writeJSON(w, http.StatusOK, map[string]string{"schema": src, "written_at": at})
	return nil
}

type writeBody struct {
	Updates []struct {
		Op           string `json:"op"`
		Relationship string `json:"relationship"`
	} `json:"updates"`
	Preconditions []store.Precondition `json:"preconditions"`
}

func (s *Server) write(w http.ResponseWriter, r *http.Request) error {
	var body writeBody
	if err := decode(r, &body); err != nil {
		return err
	}
	updates := make([]store.Update, len(body.Updates))
	for i, u := range body.Updates {
		rel, err := store.ParseRelationship(u.Relationship)
		if err != nil {
			return fmt.Errorf("updates[%d]: %w", i, err)
		}
		updates[i] = store.Update{Op: store.Op(u.Op), Relationship: rel}
	}
	rev, err := s.st.Write(updates, body.Preconditions)
	if err != nil {
		return err
	}
	at := s.tokens.Encode(rev)
	p := audit.RelationshipsWritten{Revision: at, Preconditions: len(body.Preconditions)}
	for _, u := range updates {
		switch u.Op {
		case store.OpTouch:
			p.Touch++
		case store.OpCreate:
			p.Create++
		case store.OpDelete:
			p.Delete++
		}
	}
	s.record(r.Context(), audit.Envelope{Action: "relationships.write"}, p)
	writeJSON(w, http.StatusOK, map[string]string{"written_at": at})
	return nil
}

func (s *Server) read(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Filter      store.Filter `json:"filter"`
		Consistency Consistency  `json:"consistency"`
		Cursor      string       `json:"cursor"`
		Limit       int          `json:"limit"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if body.Limit < 0 || body.Limit > store.MaxReadLimit {
		return badRequest("limit must be between 0 and %d (0 uses the default of %d)", store.MaxReadLimit, store.DefaultReadLimit)
	}
	if len(body.Cursor) > 1024 {
		return badRequest("cursor is too long")
	}
	rev, err := s.resolve(body.Consistency)
	if err != nil {
		return err
	}
	rels, next, err := s.st.Read(rev, body.Filter, body.Cursor, body.Limit)
	if err != nil {
		return err
	}
	out := make([]string, len(rels))
	for i, rel := range rels {
		out[i] = rel.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"relationships": out, "cursor": next, "read_at": s.tokens.Encode(rev)})
	return nil
}

type checkItem struct {
	Resource   string `json:"resource"`   // type:id
	Permission string `json:"permission"` // relation or permission
	Subject    string `json:"subject"`    // type:id or type:id#relation
}

func (c checkItem) request() (check.Request, error) {
	rt, rid, ok := strings.Cut(c.Resource, ":")
	if !ok || rt == "" || rid == "" {
		return check.Request{}, badRequest("resource %q must be type:id", c.Resource)
	}
	subj, err := store.ParseSubject(c.Subject, false)
	if err != nil {
		return check.Request{}, err
	}
	return check.Request{ResourceType: rt, ResourceID: rid, Permission: c.Permission, Subject: subj}, nil
}

func (s *Server) runCheck(ctx context.Context, sc *schema.Schema, rev store.Revision, c checkItem) (bool, error) {
	q, err := c.request()
	if err != nil {
		return false, err
	}
	start := time.Now()
	ok, stats, err := s.eng.Check(ctx, sc, rev, q)
	s.m.Histogram("grantd_check_duration_seconds", "", "Time to evaluate one check.").Observe(time.Since(start))
	s.m.Counter("grantd_check_dispatches_total", "", "object#relation evaluations across all checks.").Add(uint64(stats.Dispatches))
	s.m.Counter("grantd_check_cache_hits_total", "", "Check sub-results served from the cache.").Add(uint64(stats.CacheHits))
	return ok, err
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		checkItem
		Consistency Consistency `json:"consistency"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	rev, err := s.resolve(body.Consistency)
	if err != nil {
		return err
	}
	sc, _ := s.st.Schema()
	ctx, cancel := s.withTimeout(r)
	defer cancel()
	ok, err := s.runCheck(ctx, sc, rev, body.checkItem)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowed": ok, "checked_at": s.tokens.Encode(rev)})
	return nil
}

func (s *Server) checkBulk(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Items       []checkItem `json:"items"`
		Consistency Consistency `json:"consistency"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if len(body.Items) == 0 || len(body.Items) > MaxBulkChecks {
		return badRequest("items must have between 1 and %d checks", MaxBulkChecks)
	}
	rev, err := s.resolve(body.Consistency)
	if err != nil {
		return err
	}
	sc, _ := s.st.Schema()
	ctx, cancel := s.withTimeout(r)
	defer cancel()
	type result struct {
		Allowed bool   `json:"allowed"`
		Error   string `json:"error,omitempty"`
	}
	results := make([]result, len(body.Items))
	for i, it := range body.Items {
		ok, err := s.runCheck(ctx, sc, rev, it)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, store.ErrUnavailable) || errors.Is(err, store.ErrSnapshotExpired) {
				return err
			}
			results[i].Error = err.Error()
			continue
		}
		results[i].Allowed = ok
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "checked_at": s.tokens.Encode(rev)})
	return nil
}

func (s *Server) lookup(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		ResourceType string      `json:"resource_type"`
		Permission   string      `json:"permission"`
		Subject      string      `json:"subject"`
		Consistency  Consistency `json:"consistency"`
		Cursor       string      `json:"cursor"`
		Limit        int         `json:"limit"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if body.Limit < 0 || body.Limit > check.MaxLookupLimit {
		return badRequest("limit must be between 0 and %d (0 uses the default of %d)", check.MaxLookupLimit, check.DefaultLookupLimit)
	}
	if body.Cursor != "" && !store.ValidID(body.Cursor) {
		return badRequest("cursor is not valid")
	}
	subj, err := store.ParseSubject(body.Subject, false)
	if err != nil {
		return err
	}
	rev, err := s.resolve(body.Consistency)
	if err != nil {
		return err
	}
	sc, _ := s.st.Schema()
	ctx, cancel := s.withTimeout(r)
	defer cancel()
	res, err := s.eng.LookupResources(ctx, sc, s.st, rev, body.ResourceType, body.Permission, subj, body.Cursor, body.Limit)
	if err != nil {
		return err
	}
	ids := res.IDs
	if ids == nil {
		ids = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"resource_ids": ids, "cursor": res.Next, "looked_up_at": s.tokens.Encode(rev)})
	return nil
}

// watch long-polls for changes after a token. An empty token starts from the
// current head, so the first call returns at once with a starting token.
func (s *Server) watch(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		After       string `json:"after"`
		WaitSeconds int    `json:"wait_seconds"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	wait := time.Duration(body.WaitSeconds) * time.Second
	if body.WaitSeconds < 0 || wait > MaxWatchWait {
		return badRequest("wait_seconds must be between 0 and %d", int(MaxWatchWait/time.Second))
	}
	if body.After == "" {
		writeJSON(w, http.StatusOK, map[string]any{"changes": []store.Change{}, "next": s.tokens.Encode(s.st.Head())})
		return nil
	}
	after, err := s.tokens.Decode(body.After)
	if err != nil {
		return err
	}
	if after > s.st.Head() {
		return badRequest("token is from a newer revision than this server has")
	}
	if wait > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), wait)
		err := s.st.WaitForRevision(ctx, after)
		cancel()
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	head := s.st.Head() // read before Changes, so a write landing in between is not skipped
	changes, err := s.st.Changes(after, maxWatchChanges)
	if err != nil {
		return err
	}
	next := after
	if len(changes) > 0 {
		next = changes[len(changes)-1].Revision
	} else if head > next {
		next = head // schema writes advance the head without relationship changes
	}
	type change struct {
		Revision     string `json:"revision"`
		Op           string `json:"op"`
		Relationship string `json:"relationship"`
	}
	out := make([]change, len(changes))
	for i, c := range changes {
		out[i] = change{Revision: s.tokens.Encode(c.Revision), Op: string(c.Op), Relationship: c.Relationship.String()}
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": out, "next": s.tokens.Encode(next)})
	return nil
}
