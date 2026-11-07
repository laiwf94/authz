package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// HeaderTraceparent is the W3C Trace Context header a correlation ID is
// read from and carried upstream in.
const HeaderTraceparent = "traceparent"

type ctxKey int

const (
	correlationKey ctxKey = iota
	tenantKey
)

// WithCorrelationID returns ctx carrying id. Every record a Handler writes
// with that context gets a correlation_id attribute, and audit records take
// the same value in their envelope.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationKey, id)
}

// CorrelationID returns the correlation ID stored in ctx, or "".
func CorrelationID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(correlationKey).(string)
	return id
}

// WithTenant returns ctx carrying tenant, which a Handler adds to every
// record as the tenant attribute. The default tenant is "" and adds nothing.
func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey, tenant)
}

// Tenant returns the tenant stored in ctx, or "".
func Tenant(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	t, _ := ctx.Value(tenantKey).(string)
	return t
}

// NewCorrelationID returns a random correlation ID in the form of a W3C
// trace ID: 32 lowercase hex characters, never all zeros.
func NewCorrelationID() string {
	var b [16]byte
	for {
		_, _ = rand.Read(b[:])
		if b != [16]byte{} {
			return hex.EncodeToString(b[:])
		}
	}
}

// ParseTraceparent returns the trace ID of a W3C traceparent header value
// (https://www.w3.org/TR/trace-context/#traceparent-header). It accepts
// version 00 exactly, and a later version when the first 55 characters have
// the version 00 layout followed by nothing or a "-", as the specification
// asks of parsers. Version ff, uppercase hex and all-zero trace or parent
// IDs are refused.
func ParseTraceparent(v string) (traceID string, ok bool) {
	if len(v) < 55 {
		return "", false
	}
	if v[2] != '-' || v[35] != '-' || v[52] != '-' {
		return "", false
	}
	version, trace, parent, flags := v[0:2], v[3:35], v[36:52], v[53:55]
	if !lowerHex(version) || version == "ff" || !lowerHex(trace) || !lowerHex(parent) || !lowerHex(flags) {
		return "", false
	}
	if version == "00" && len(v) != 55 {
		return "", false
	}
	if len(v) > 55 && v[55] != '-' {
		return "", false
	}
	if allZero(trace) || allZero(parent) {
		return "", false
	}
	return trace, true
}

// FromRequest returns the correlation ID for an incoming request: the trace
// ID of its traceparent header when that is valid, otherwise a new one.
func FromRequest(r *http.Request) string {
	if id, ok := ParseTraceparent(r.Header.Get(HeaderTraceparent)); ok {
		return id
	}
	return NewCorrelationID()
}

// Middleware gives every request a correlation ID (see FromRequest) in its
// context, unless the context already has one, and passes it on to next.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if CorrelationID(r.Context()) == "" {
			r = r.WithContext(WithCorrelationID(r.Context(), FromRequest(r)))
		}
		next.ServeHTTP(w, r)
	})
}

// Traceparent returns a traceparent header value carrying correlation ID id
// to an upstream, with a new random parent ID and the sampled flag clear.
// It returns "" when id is not a trace ID (32 lowercase hex characters, not
// all zeros), so a caller never sends a header the upstream must drop.
func Traceparent(id string) string {
	if len(id) != 32 || !lowerHex(id) || allZero(id) {
		return ""
	}
	var b [8]byte
	for {
		_, _ = rand.Read(b[:])
		if b != [8]byte{} {
			break
		}
	}
	return "00-" + id + "-" + hex.EncodeToString(b[:]) + "-00"
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func allZero(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}
