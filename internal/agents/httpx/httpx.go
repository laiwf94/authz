// Package httpx holds the HTTP plumbing shared by every server in this
// repository: request IDs, structured access logs, metrics, panic recovery,
// security headers, strict JSON decoding and the error envelope
// {"error":{"code","message","request_id"}}.
package httpx

import (
	"bytes"
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
	"time"

	"github.com/laiwf94/authz/internal/platform/metrics"
)

// HeaderRequestID carries the request ID in both directions.
const HeaderRequestID = "X-Request-Id"

type ctxKey int

const requestIDKey ctxKey = 0

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// newRequestID returns a random request ID. The server always makes its own,
// because the ID ends up in audit records and a caller must not be able to
// choose or reuse it.
func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// clientRequestID returns the caller's X-Request-Id when it is short and
// plain enough to log, for correlating with the caller's own logs.
func clientRequestID(r *http.Request) string {
	if id := r.Header.Get(HeaderRequestID); requestIDRe.MatchString(id) {
		return id
	}
	return ""
}

// RequestID returns the request ID stored in ctx.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// WithRequestID returns ctx carrying id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// StatusWriter remembers the response code for logs and metrics.
type StatusWriter struct {
	http.ResponseWriter
	Code int
}

// WriteHeader records the first status written.
func (w *StatusWriter) WriteHeader(code int) {
	if w.Code == 0 {
		w.Code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *StatusWriter) Write(b []byte) (int, error) {
	if w.Code == 0 {
		w.Code = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Server names the component in metrics and logs.
type Server struct {
	Name    string // e.g. "gateway", "admin"
	Prefix  string // metric name prefix, e.g. "toolgate"
	Log     *slog.Logger
	Metrics *metrics.Registry
}

// Wrap adds request IDs, security headers, panic recovery, an access log line
// and request metrics around next. route is the metric label.
func (s *Server) Wrap(route string, next http.HandlerFunc) http.Handler {
	latency := s.Metrics.Histogram(s.Prefix+"_http_request_duration_seconds",
		metrics.Labels("server", s.Name, "route", route), "HTTP request latency.")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := newRequestID()
		clientID := clientRequestID(r)
		sw := &StatusWriter{ResponseWriter: w}
		hdr := sw.Header()
		hdr.Set(HeaderRequestID, id)
		hdr.Set("Cache-Control", "no-store")
		hdr.Set("X-Content-Type-Options", "nosniff")
		ctx := WithRequestID(r.Context(), id)
		r = r.WithContext(ctx)
		defer func() {
			if p := recover(); p != nil {
				s.Log.Error("panic", "request_id", id, "route", route, "panic", fmt.Sprint(p))
				if sw.Code == 0 {
					WriteError(sw, r, http.StatusInternalServerError, "internal", "internal error")
				}
			}
			code := sw.Code
			if code == 0 {
				code = http.StatusOK
			}
			latency.Observe(time.Since(start))
			s.Metrics.Counter(s.Prefix+"_http_requests_total",
				metrics.Labels("server", s.Name, "route", route, "code", strconv.Itoa(code)), "HTTP requests.").Inc()
			lvl := slog.LevelInfo
			if code >= 500 {
				lvl = slog.LevelError
			}
			attrs := []any{"request_id", id, "server", s.Name, "method", r.Method,
				"route", route, "status", code, "duration_ms", float64(time.Since(start).Microseconds()) / 1000}
			if clientID != "" {
				attrs = append(attrs, "client_request_id", clientID)
			}
			s.Log.Log(ctx, lvl, "request", attrs...)
		}()
		next(sw, r)
	})
}

// WriteJSON writes v as a JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		http.Error(w, `{"error":{"code":"internal","message":"encoding failed"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}

// WriteError writes the error envelope.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	WriteJSON(w, status, map[string]any{"error": map[string]string{
		"code": code, "message": msg, "request_id": RequestID(r.Context())}})
}

// Error is an HTTP error with a stable code.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

// BadRequest builds a 400 invalid_argument error.
func BadRequest(format string, args ...any) error {
	return &Error{http.StatusBadRequest, "invalid_argument", fmt.Sprintf(format, args...)}
}

// Fail writes err: an *Error as itself, an oversized body as 413, anything
// else as a logged 500 that reveals nothing to the caller.
func Fail(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	var he *Error
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &he):
		WriteError(w, r, he.Status, he.Code, he.Msg)
	case errors.As(err, &mbe):
		WriteError(w, r, http.StatusRequestEntityTooLarge, "invalid_argument",
			fmt.Sprintf("request body is larger than %d bytes", mbe.Limit))
	default:
		log.Error("internal error", "request_id", RequestID(r.Context()), "error", err.Error())
		WriteError(w, r, http.StatusInternalServerError, "internal", "internal error")
	}
}

// DecodeJSON reads a JSON object body of at most limit bytes into v,
// rejecting a wrong content type, unknown fields and trailing data. An empty
// body decodes as {}.
func DecodeJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	if r.ContentLength != 0 && !IsJSON(r.Header.Get("Content-Type")) {
		return &Error{http.StatusUnsupportedMediaType, "invalid_argument", "Content-Type must be application/json"}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		body = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return BadRequest("invalid JSON body: %v", err)
	}
	if dec.More() {
		return BadRequest("request body must be a single JSON object")
	}
	return nil
}

// IsJSON reports whether a Content-Type names application/json.
func IsJSON(ct string) bool {
	mt, _, _ := strings.Cut(ct, ";")
	return strings.EqualFold(strings.TrimSpace(mt), "application/json")
}

// Bearer returns the token from an "Authorization: Bearer" header.
func Bearer(r *http.Request) string {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(tok)
}

// TokenMatches compares a presented secret with an expected one in constant
// time (over their SHA-256 digests, so length does not leak either).
func TokenMatches(presented, expected string) bool {
	if presented == "" || expected == "" {
		return false
	}
	a := sha256.Sum256([]byte(presented))
	b := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
