// Package server is the gateway's HTTP surface: the forward-auth endpoint
// that reverse proxies call, the browser login and logout flows, the upstream
// token key set, and the admin API.
package server

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
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laiwf94/authz/internal/authn/config"
	"github.com/laiwf94/authz/internal/authn/metrics"
	"github.com/laiwf94/authz/internal/authn/saml"
	"github.com/laiwf94/authz/internal/authn/session"
	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/jose"
	"github.com/laiwf94/authz/internal/platform/seal"
)

// Request limits.
const (
	MaxJSONBody       = 64 << 10
	MaxFormBody       = 512 << 10
	loginTTL          = 10 * time.Minute
	requestIDHeader   = "X-Request-Id"
	DefaultLoginRate  = 30
	maxTokenCache     = 100_000
	adminListLimit    = 1000
	minAdminTokenSize = 16
)

// Options configures a Server.
type Options struct {
	// Load returns the current configuration; it is called at start and on
	// every reload.
	Load       func() (*config.Config, error)
	Sessions   *session.Store
	Keys       *seal.Keyring
	Signers    []*jose.Signer // [0] signs upstream tokens; all are published
	Logger     *slog.Logger
	Metrics    *metrics.Registry
	AdminToken string // empty: the admin API must only be reachable on loopback
	// TrustedProxies are the networks whose X-Forwarded-For is believed
	// when finding the client address for rate limiting.
	TrustedProxies []netip.Prefix
	// LoginRate is login, callback and logout requests per minute per
	// client address (0 means DefaultLoginRate).
	LoginRate int
	// Audit, when set, receives every audit event as a typed record in the
	// platform's hash chain, besides the "audit" log line. It should be
	// opened with audit.Default() schemas. The server does not close it.
	Audit *audit.Log

	// For tests.
	HTTPClient func(p *config.Provider) (*http.Client, error)
	Now        func() time.Time
}

// Server holds the gateway state. It is safe for concurrent use.
type Server struct {
	rt       atomic.Pointer[runtime]
	auditLog atomic.Pointer[audit.Log] // Options.Audit; nil: log lines only
	opts     Options
	sessions *session.Store
	keys     *seal.Keyring
	signers  []*jose.Signer
	jwks     []byte
	log      *slog.Logger
	m        *metrics.Registry
	now      func() time.Time
	replay   *saml.ReplayCache // assertion IDs, shared across reloads
	used     *saml.ReplayCache // consumed login states
	limiter  *rateLimiter
	admin    [sha256.Size]byte
	reloadMu sync.Mutex

	tokenMu sync.Mutex
	tokens  map[string]cachedToken

	public, adminMux *http.ServeMux
}

type cachedToken struct {
	value   string
	refresh time.Time
}

// New builds the server and loads the configuration once.
func New(opts Options) (*Server, error) {
	if opts.Load == nil || opts.Sessions == nil || opts.Keys == nil || len(opts.Signers) == 0 {
		return nil, errors.New("server: Load, Sessions, Keys and Signers are required")
	}
	if opts.AdminToken != "" && len(opts.AdminToken) < minAdminTokenSize {
		return nil, fmt.Errorf("server: the admin token must be at least %d characters", minAdminTokenSize)
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.New()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.LoginRate <= 0 {
		opts.LoginRate = DefaultLoginRate
	}
	s := &Server{opts: opts, sessions: opts.Sessions, keys: opts.Keys, signers: opts.Signers, log: opts.Logger,
		m: opts.Metrics, now: opts.Now, replay: saml.NewReplayCache(0, opts.Now), used: saml.NewReplayCache(0, opts.Now),
		limiter: newRateLimiter(opts.LoginRate, opts.Now), tokens: map[string]cachedToken{}}
	s.auditLog.Store(opts.Audit)
	if opts.AdminToken != "" {
		s.admin = sha256.Sum256([]byte(opts.AdminToken))
	}
	keys := make([]map[string]string, len(opts.Signers))
	for i, sg := range opts.Signers {
		keys[i] = jose.PublicJWK(sg.Public(), sg.KeyID())
	}
	s.jwks, _ = json.Marshal(map[string]any{"keys": keys})

	if err := s.Reload(context.Background()); err != nil {
		return nil, err
	}
	s.m.Gauge("wicket_sessions", "Sessions held in memory.", func() float64 { return float64(s.sessions.Len()) })
	s.routes()
	return s, nil
}

// Reload loads the configuration again and swaps it in atomically. On any
// error the running configuration stays in place.
func (s *Server) Reload(ctx context.Context) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	cfg, err := s.opts.Load()
	if err == nil {
		var rt *runtime
		if rt, err = buildRuntime(ctx, cfg, buildOptions{httpClient: s.opts.HTTPClient, now: s.now, replay: s.replay}); err == nil {
			s.sessions.SetTimeouts(time.Duration(cfg.Session.IdleTimeout), time.Duration(cfg.Session.AbsoluteTimeout))
			s.rt.Store(rt)
			s.audit(ctx, audit.Envelope{Action: "config.load"},
				audit.ConfigLoaded{Providers: len(rt.providers), Apps: len(rt.apps)},
				slog.Int("providers", len(rt.providers)), slog.Int("apps", len(rt.apps)))
			return nil
		}
	}
	s.audit(ctx, audit.Envelope{Action: "config.load", Decision: audit.Deny}, audit.ConfigLoadFailed{Error: err.Error()},
		slog.String("error", err.Error()))
	return err
}

func (s *Server) routes() {
	s.public = http.NewServeMux()
	s.route(s.public, "GET /auth", s.handleAuth)
	s.route(s.public, "/auth/envoy/", s.handleEnvoyAuth)
	s.route(s.public, "GET /login", s.limited(s.handleLogin))
	s.route(s.public, "GET /callback/{provider}", s.limited(s.handleCallback))
	s.route(s.public, "POST /saml/{provider}/acs", s.limited(s.handleACS))
	s.route(s.public, "GET /saml/{provider}/metadata", s.handleSAMLMetadata)
	s.route(s.public, "GET /logout", s.handleLogoutPage)
	s.route(s.public, "POST /logout", s.limited(s.handleLogout))
	s.route(s.public, "GET /logged-out", s.handleLoggedOut)
	s.route(s.public, "GET /.well-known/jwks.json", s.handleJWKS)
	s.route(s.public, "GET /healthz", s.handleHealth)
	s.route(s.public, "/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotFound, "not_found", "no such endpoint")
	})

	s.adminMux = http.NewServeMux()
	s.route(s.adminMux, "GET /admin/sessions", s.adminOnly(s.handleListSessions))
	s.route(s.adminMux, "DELETE /admin/sessions/{id}", s.adminOnly(s.handleRevokeSession))
	s.route(s.adminMux, "POST /admin/sessions/revoke", s.adminOnly(s.handleRevokeSubject))
	s.route(s.adminMux, "POST /admin/reload", s.adminOnly(s.handleReload))
	s.route(s.adminMux, "GET /metrics", s.adminOnly(s.handleMetrics))
	s.route(s.adminMux, "GET /healthz", s.handleHealth)
	s.route(s.adminMux, "/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotFound, "not_found", "no such endpoint")
	})
}

// Handler serves the public endpoints (forward-auth, login, logout, JWKS).
func (s *Server) Handler() http.Handler { return s.public }

// AdminHandler serves the admin API and metrics.
func (s *Server) AdminHandler() http.Handler { return s.adminMux }

// Sweep drops expired sessions; call it periodically.
func (s *Server) Sweep() {
	if err := s.sessions.Sweep(); err != nil {
		s.log.Error("session sweep failed", "error", err.Error())
	}
	s.tokenMu.Lock()
	now := s.now()
	for k, t := range s.tokens {
		if !now.Before(t.refresh) {
			delete(s.tokens, k)
		}
	}
	s.tokenMu.Unlock()
	s.limiter.sweep()
}

type ctxKey int

const requestIDKey ctxKey = 0

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func newRequestID(r *http.Request) string {
	if id := r.Header.Get(requestIDHeader); requestIDRe.MatchString(id) {
		return id
	}
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
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

// route wraps a handler with request IDs, security headers, panic recovery,
// logging and metrics.
func (s *Server) route(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	path := pattern[strings.IndexByte(pattern, ' ')+1:]
	latency := s.m.Histogram("wicket_http_request_duration_seconds", `route="`+path+`"`, "HTTP request latency.")
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := newRequestID(r)
		sw := &statusWriter{ResponseWriter: w}
		hd := sw.Header()
		hd.Set(requestIDHeader, id)
		hd.Set("Cache-Control", "no-store")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Strict-Transport-Security", "max-age=31536000")
		hd.Set("Content-Security-Policy", contentSecurityPolicy)
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
			s.m.Counter("wicket_http_requests_total", fmt.Sprintf(`route=%q,code="%d"`, path, code), "HTTP requests.").Inc()
			lvl := slog.LevelInfo
			if code >= 500 {
				lvl = slog.LevelError
			} else if path == "/auth" || path == "/auth/envoy/" || path == "/healthz" {
				lvl = slog.LevelDebug // every proxied request hits these
			}
			s.log.Log(ctx, lvl, "request", "request_id", id, "method", r.Method, "route", path,
				"status", code, "duration_ms", float64(time.Since(start).Microseconds())/1000)
		}()
		h(sw, r)
	})
}

// adminOnly requires the admin bearer token when one is configured.
func (s *Server) adminOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.opts.AdminToken != "" {
			tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			sum := sha256.Sum256([]byte(tok))
			if !ok || subtle.ConstantTimeCompare(sum[:], s.admin[:]) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="wicket-admin"`)
				writeError(w, r, http.StatusUnauthorized, "unauthenticated", "missing or invalid admin token")
				return
			}
		}
		h(w, r)
	}
}

// limited applies the per-client rate limit used for login endpoints.
func (s *Server) limited(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if wait, ok := s.limiter.allow(clientIP(r, s.opts.TrustedProxies)); !ok {
			w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
			s.m.Counter("wicket_rate_limited_total", "", "Requests refused by the login rate limit.").Inc()
			writeError(w, r, http.StatusTooManyRequests, "rate_limited", "too many requests; retry later")
			return
		}
		h(w, r)
	}
}

// audit records one event: an "audit" log line with attrs, as wicket wrote
// it, and, with Options.Audit, a typed record in the hash chain carrying the
// request ID as its correlation ID. A record that can't be written is
// counted and logged; the request it describes has already happened.
func (s *Server) audit(ctx context.Context, env audit.Envelope, p audit.Payload, attrs ...slog.Attr) {
	event := strings.TrimPrefix(p.AuditEvent(), "authn.")
	rid := requestIDFrom(ctx)
	attrs = append([]slog.Attr{slog.Bool("audit", true), slog.String("event", event),
		slog.String("request_id", rid)}, attrs...)
	s.log.LogAttrs(ctx, slog.LevelInfo, "audit", attrs...)
	al := s.auditLog.Load()
	if al == nil {
		return
	}
	env.Actor = audit.Clean(env.Actor, audit.MaxEnvelopeBytes)
	env.Subject = audit.Clean(env.Subject, audit.MaxEnvelopeBytes)
	env.CorrelationID = rid
	if err := al.Write(env, p); err != nil {
		s.m.Counter("wicket_audit_failures_total", "", "Audit records that could not be written.").Inc()
		s.log.Error("audit write failed", "event", event, "request_id", rid, "error", err.Error())
		return
	}
	s.m.Counter("wicket_audit_records_total", `event="`+event+`"`, "Audit records written.").Inc()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg,
		"request_id": requestIDFrom(r.Context())}})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if al := s.auditLog.Load(); al != nil && !al.Healthy() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "audit log unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(s.jwks)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_ = s.m.Write(w)
}
