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
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laiwf94/authz/internal/authz/check"
	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/logging"
	"github.com/laiwf94/authz/internal/platform/metrics"
	"github.com/laiwf94/authz/internal/platform/ratelimit"
)

// Request limits.
const (
	MaxBodyBytes      = 1 << 20
	MaxBulkChecks     = engine.MaxBulkChecks
	DefaultTimeout    = 5 * time.Second
	MaxWatchWait      = 30 * time.Second
	DefaultQuantum    = engine.DefaultQuantum
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
	// fingerprint as the actor and the request's correlation ID (see
	// logging.Correlate). It should be opened with audit.Default() schemas.
	// The server does not close it.
	Audit *audit.Log
	// AuditChecks also records every answered check, single or bulk, as an
	// authz.check_decided decision record in Audit: the resource as the
	// subject, the permission as the action, the result as the decision.
	// The record is durable before the answer is sent, and a check whose
	// record cannot be written is answered 503 instead, so every decision a
	// client acted on is in the chain. Each record costs a shared fsync.
	AuditChecks bool
	// KeyLimit is the request rate allowed per API key, enforced with the
	// platform limiter; requests over it get 429 with Retry-After. A zero
	// Rate (the default) means no limit.
	KeyLimit ratelimit.Limit
	// Now is the limiter's clock; nil means time.Now.
	Now func() time.Time
}

// Server is the HTTP API.
type Server struct {
	st      *store.Store
	eng     *engine.Local
	tokens  *token.Issuer
	keys    atomic.Pointer[keySet]
	keyLim  *ratelimit.Limiter
	limit   ratelimit.Limit
	audit   *audit.Log
	checks  bool // record check decisions in audit
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
	s := &Server{st: cfg.Store, tokens: cfg.Tokens, log: cfg.Logger, m: cfg.Metrics,
		quantum: cfg.Quantum, timeout: cfg.Timeout, audit: cfg.Audit, limit: cfg.KeyLimit}
	if cfg.AuditChecks {
		if cfg.Audit == nil {
			return nil, errors.New("api: AuditChecks needs an audit log")
		}
		s.checks = true
	}
	if err := s.SetAPIKeys(cfg.APIKeys); err != nil {
		return nil, err
	}
	if !cfg.KeyLimit.Unlimited() {
		// Keys are limited by fingerprint, so a key kept across SetAPIKeys
		// keeps its bucket. The table holds more than the keys configured
		// so that keys added later do not evict the others.
		s.keyLim = ratelimit.New(ratelimit.Options{Now: cfg.Now, MaxKeys: max(4*len(cfg.APIKeys), minLimiterKeys)})
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
	eng, err := engine.New(engine.Options{Store: cfg.Store, Tokens: cfg.Tokens, CacheSize: cfg.CacheSize,
		Snapshot: s.quantizedHead, Metrics: s.m})
	if err != nil {
		return nil, err
	}
	s.eng = eng
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

// minLimiterKeys is the smallest per-key limiter table.
const minLimiterKeys = 64

// keySet is the API keys a server accepts, replaced whole by SetAPIKeys.
type keySet struct {
	sums    [][sha256.Size]byte
	ids     []string // fingerprints, for audit actors
	limKeys []string // limiter key per API key
}

// SetAPIKeys replaces the bearer keys the server accepts. A request already
// authorized finishes; every request that starts afterwards is checked
// against the new keys only. It refuses an empty list and a key shorter
// than MinKeyLength, leaving the keys in place.
func (s *Server) SetAPIKeys(keys []string) error {
	if len(keys) == 0 {
		return errors.New("api: at least one API key is required")
	}
	ks := &keySet{}
	for _, k := range keys {
		if len(k) < MinKeyLength {
			return fmt.Errorf("api: API keys must be at least %d characters", MinKeyLength)
		}
		ks.sums = append(ks.sums, sha256.Sum256([]byte(k)))
		ks.ids = append(ks.ids, KeyID(k))
		ks.limKeys = append(ks.limKeys, ratelimit.Key("api_key", KeyID(k)))
	}
	s.keys.Store(ks)
	return nil
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
		// The correlation ID (the traceparent's trace ID, or a new one) goes
		// into every log line written with ctx and every audit record.
		r, _ = logging.Correlate(r)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		r = r.WithContext(ctx)
		defer func() {
			if p := recover(); p != nil {
				s.log.ErrorContext(ctx, "panic", "request_id", id, "route", path, "panic", fmt.Sprint(p))
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
			ks, k := s.authorized(r)
			if k < 0 {
				sw.Header().Set("WWW-Authenticate", `Bearer realm="grantd"`)
				writeError(sw, r, http.StatusUnauthorized, "unauthenticated", "missing or invalid API key")
				return
			}
			if s.keyLim != nil {
				if ok, wait := s.keyLim.Take(ks.limKeys[k], s.limit); !ok {
					sw.Header().Set("Retry-After", strconv.FormatInt(int64(math.Ceil(min(wait.Seconds(), 86400))), 10))
					s.m.Counter("grantd_rate_limited_total", "", "Requests refused by the per-key rate limit.").Inc()
					writeError(sw, r, http.StatusTooManyRequests, "resource_exhausted", "API key rate limit exceeded; retry later")
					return
				}
			}
			r = r.WithContext(context.WithValue(r.Context(), actorKey, ks.ids[k]))
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
// and returns the key set it used and the index of the key it matches, or
// -1.
func (s *Server) authorized(r *http.Request) (*keySet, int) {
	ks := s.keys.Load()
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" {
		return ks, -1
	}
	sum := sha256.Sum256([]byte(tok))
	match := -1
	for i, k := range ks.sums {
		match = subtle.ConstantTimeSelect(subtle.ConstantTimeCompare(sum[:], k[:]), i, match)
	}
	return ks, match
}

// record appends one typed audit record, when an audit log is configured.
// The write it describes has committed, so a failure is counted and logged
// rather than returned; /healthz then reports the log unavailable.
func (s *Server) record(ctx context.Context, env audit.Envelope, p audit.Payload) {
	if s.audit == nil {
		return
	}
	env.Actor, _ = ctx.Value(actorKey).(string)
	env.CorrelationID = logging.CorrelationID(ctx)
	if err := s.audit.Write(env, p); err != nil {
		s.m.Counter("grantd_audit_failures_total", "", "Audit records that could not be written.").Inc()
		s.log.ErrorContext(ctx, "audit write failed", "event", p.AuditEvent(), "request_id", ctx.Value(requestIDKey), "error", err.Error())
		return
	}
	s.m.Counter("grantd_audit_records_total", fmt.Sprintf("event=%q", p.AuditEvent()), "Audit records written.").Inc()
}

// errAuditUnavailable answers a check whose decision record could not be
// written.
var errAuditUnavailable = &apiError{status: http.StatusServiceUnavailable, code: "unavailable",
	msg: "the audit log is unavailable, so the decision cannot be recorded; retry later"}

// recordDecisions writes one authz.check_decided record per answered check
// when check auditing is on. Unlike the records of writes, which describe
// something already committed, a decision is only given once its record is
// durable, so a failure is returned.
func (s *Server) recordDecisions(ctx context.Context, at string, items []checkItem, allowed []bool, answered []bool) error {
	if !s.checks {
		return nil
	}
	actor, _ := ctx.Value(actorKey).(string)
	corr := logging.CorrelationID(ctx)
	bulk := 0 // a single check
	if answered != nil {
		bulk = len(items)
	}
	envs := make([]audit.Envelope, 0, len(items))
	ps := make([]audit.Payload, 0, len(items))
	for i, it := range items {
		if answered != nil && !answered[i] {
			continue
		}
		d := audit.Deny
		if allowed[i] {
			d = audit.Allow
		}
		envs = append(envs, audit.Envelope{Actor: actor, Subject: audit.Clean(it.Resource, audit.MaxEnvelopeBytes),
			Action: audit.Clean(it.Permission, audit.MaxEnvelopeBytes), Decision: d, CorrelationID: corr})
		ps = append(ps, audit.CheckDecided{Principal: it.Subject, Revision: at, Bulk: bulk})
	}
	// A bulk check's records share one fsync.
	if err := s.audit.WriteAll(envs, ps); err != nil {
		s.m.Counter("grantd_audit_failures_total", "", "Audit records that could not be written.").Inc()
		s.log.ErrorContext(ctx, "audit write failed", "event", audit.EventCheckDecided, "request_id", ctx.Value(requestIDKey), "error", err.Error())
		return errAuditUnavailable
	}
	s.m.Counter("grantd_audit_records_total", fmt.Sprintf("event=%q", audit.EventCheckDecided), "Audit records written.").Add(uint64(len(ps)))
	return nil
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
	case errors.Is(err, engine.ErrInvalidArgument), errors.Is(err, store.ErrInvalid), errors.Is(err, check.ErrUnknownType), errors.Is(err, check.ErrUnknownName),
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
		s.log.ErrorContext(r.Context(), "store unavailable", "request_id", r.Context().Value(requestIDKey), "error", err.Error())
		writeError(w, r, http.StatusServiceUnavailable, "unavailable", "storage is unavailable; retry later")
	default:
		s.log.ErrorContext(r.Context(), "internal error", "request_id", r.Context().Value(requestIDKey), "error", err.Error())
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

// Consistency picks the snapshot a read uses: engine.Consistency, whose
// JSON form is the "consistency" member of every read.
type Consistency = engine.Consistency

// Engine returns the engine the handlers answer with, for callers in the
// same process: they share its cache, its minimize_latency snapshot and
// its consistency tokens with the HTTP API.
func (s *Server) Engine() *engine.Local { return s.eng }

// quantizedHead is the minimize_latency snapshot, shared between the HTTP
// handlers and in-process callers of Engine for up to Quantum.
func (s *Server) quantizedHead() store.Revision {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	if time.Since(s.snapTime) >= s.quantum {
		s.snapRev, s.snapTime = s.st.Head(), time.Now()
	}
	return s.snapRev
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
	res, err := s.eng.Write(r.Context(), engine.WriteRequest{Updates: updates, Preconditions: body.Preconditions})
	if err != nil {
		return err
	}
	at := res.At.Token
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
	res, err := s.eng.ReadRelationships(r.Context(), engine.ReadRequest{Filter: body.Filter, Consistency: body.Consistency,
		Cursor: body.Cursor, Limit: body.Limit})
	if err != nil {
		return err
	}
	out := make([]string, len(res.Relationships))
	for i, rel := range res.Relationships {
		out[i] = rel.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"relationships": out, "cursor": res.Cursor, "read_at": res.At.Token})
	return nil
}

type checkItem struct {
	Resource   string `json:"resource"`   // type:id
	Permission string `json:"permission"` // relation or permission
	Subject    string `json:"subject"`    // type:id or type:id#relation
}

func (c checkItem) item() (engine.CheckItem, error) {
	rt, rid, ok := strings.Cut(c.Resource, ":")
	if !ok || rt == "" || rid == "" {
		return engine.CheckItem{}, badRequest("resource %q must be type:id", c.Resource)
	}
	subj, err := store.ParseSubject(c.Subject, false)
	if err != nil {
		return engine.CheckItem{}, err
	}
	return engine.CheckItem{ResourceType: rt, ResourceID: rid, Permission: c.Permission, Subject: subj}, nil
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		checkItem
		Consistency Consistency `json:"consistency"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	it, err := body.item()
	if err != nil {
		// Consistency is resolved first, so a bad mode or token is
		// reported ahead of a bad resource or subject.
		if _, rerr := s.eng.Resolve(body.Consistency); rerr != nil {
			return rerr
		}
		return err
	}
	ctx, cancel := s.withTimeout(r)
	defer cancel()
	res, err := s.eng.Check(ctx, engine.CheckRequest{ResourceType: it.ResourceType, ResourceID: it.ResourceID,
		Permission: it.Permission, Subject: it.Subject, Consistency: body.Consistency})
	if err != nil {
		return err
	}
	if err := s.recordDecisions(r.Context(), res.At.Token, []checkItem{body.checkItem}, []bool{res.Allowed}, nil); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowed": res.Allowed, "checked_at": res.At.Token})
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
	type result struct {
		Allowed bool   `json:"allowed"`
		Error   string `json:"error,omitempty"`
	}
	// An item that does not parse is answered with its error; the rest go
	// to the engine together, at one snapshot.
	results := make([]result, len(body.Items))
	items := make([]engine.CheckItem, 0, len(body.Items))
	index := make([]int, 0, len(body.Items))
	for i, c := range body.Items {
		it, err := c.item()
		if err != nil {
			results[i].Error = err.Error()
			continue
		}
		items = append(items, it)
		index = append(index, i)
	}
	ctx, cancel := s.withTimeout(r)
	defer cancel()
	res, err := s.eng.CheckBulk(ctx, engine.CheckBulkRequest{Items: items, Consistency: body.Consistency})
	if err != nil {
		return err
	}
	for j, ir := range res.Results {
		if ir.Err != nil {
			results[index[j]].Error = ir.Err.Error()
			continue
		}
		results[index[j]].Allowed = ir.Allowed
	}
	if s.checks {
		allowed, answered := make([]bool, len(results)), make([]bool, len(results))
		for i, res := range results {
			allowed[i], answered[i] = res.Allowed, res.Error == ""
		}
		if err := s.recordDecisions(r.Context(), res.At.Token, body.Items, allowed, answered); err != nil {
			return err
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "checked_at": res.At.Token})
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
	// The page is checked before the subject, as it always was.
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
	ctx, cancel := s.withTimeout(r)
	defer cancel()
	res, err := s.eng.LookupResources(ctx, engine.LookupResourcesRequest{ResourceType: body.ResourceType,
		Permission: body.Permission, Subject: subj, Consistency: body.Consistency, Cursor: body.Cursor, Limit: body.Limit})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"resource_ids": res.ResourceIDs, "cursor": res.Cursor, "looked_up_at": res.At.Token})
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
