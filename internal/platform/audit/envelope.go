package audit

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

// Decision is the outcome an event records, when it records one.
type Decision string

// The decisions. An event that decides nothing leaves Decision empty.
const (
	Allow Decision = "allow"
	Deny  Decision = "deny"
)

// Envelope is what every track's events have in common, so one query can
// follow a sign-in, the check it triggers and the tool call it allows. Every
// field is optional in the record format (toolgate's records have none);
// each event type's schema says which ones it needs.
type Envelope struct {
	// Tenant is the tenant the event belongs to; empty for the default one.
	Tenant string `json:"tenant,omitempty"`
	// Actor is who caused the event: a user's subject, an agent ID, an
	// admin key ID or a service name.
	Actor string `json:"actor,omitempty"`
	// Subject is what the event acted on: a session, a relationship's
	// resource, an application, a tool.
	Subject string `json:"subject,omitempty"`
	// Action is the operation attempted, such as "login", "write", "check"
	// or a permission or tool name.
	Action string `json:"action,omitempty"`
	// Decision is allow or deny for events that record a decision.
	Decision Decision `json:"decision,omitempty"`
	// CorrelationID ties together the records of one request across serve,
	// gateway and mcp: the trace ID of a W3C traceparent or a generated one.
	CorrelationID string `json:"correlation_id,omitempty"`
}

// Limits on envelope fields, in bytes.
const (
	MaxTenantBytes        = 128
	MaxEnvelopeBytes      = 512 // actor, subject and action
	MaxCorrelationIDBytes = 128
	maxEventBytes         = 64
)

// Check reports whether every field of e is well formed.
func (e Envelope) Check() error {
	for _, f := range []struct {
		name, v string
		max     int
	}{
		{"tenant", e.Tenant, MaxTenantBytes},
		{"actor", e.Actor, MaxEnvelopeBytes},
		{"subject", e.Subject, MaxEnvelopeBytes},
		{"action", e.Action, MaxEnvelopeBytes},
	} {
		if err := checkText(f.name, f.v, f.max); err != nil {
			return err
		}
	}
	switch e.Decision {
	case "", Allow, Deny:
	default:
		return fmt.Errorf("audit: decision %q is not allow or deny", truncate(string(e.Decision)))
	}
	return checkCorrelationID(e.CorrelationID)
}

// checkText accepts valid UTF-8 without control characters, at most max
// bytes long.
func checkText(name, v string, max int) error {
	if len(v) > max {
		return fmt.Errorf("audit: %s is longer than %d bytes", name, max)
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("audit: %s is not valid UTF-8", name)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("audit: %s contains a control character", name)
		}
	}
	return nil
}

// checkCorrelationID accepts the characters of trace IDs, request IDs and
// UUIDs: letters, digits and - _ . :
func checkCorrelationID(v string) error {
	if len(v) > MaxCorrelationIDBytes {
		return fmt.Errorf("audit: correlation_id is longer than %d bytes", MaxCorrelationIDBytes)
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; !isIDByte(c) {
			return fmt.Errorf("audit: correlation_id contains %q", c)
		}
	}
	return nil
}

func isIDByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '_' || c == '.' || c == ':'
}

// checkEvent accepts event types of lower-case letters, digits, '_' and '.',
// such as "tool_call" or "authn.login_succeeded".
func checkEvent(event string) error {
	if event == "" || len(event) > maxEventBytes {
		return fmt.Errorf("audit: event type must be 1 to %d bytes", maxEventBytes)
	}
	for i := 0; i < len(event); i++ {
		c := event[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return fmt.Errorf("audit: event type %q may only contain a-z, 0-9, '_' and '.'", truncate(event))
		}
	}
	return nil
}

func truncate(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

// Clean makes v fit an envelope field of at most max bytes: invalid UTF-8
// and control characters become U+FFFD and the result is cut on a character
// boundary. Values that come from outside (an identity provider's subject,
// a request's host) go through it, so a record is never refused, and the
// event lost, for a malformed name.
func Clean(v string, max int) string {
	ok := len(v) <= max && utf8.ValidString(v)
	if ok {
		for _, r := range v {
			if unicode.IsControl(r) {
				ok = false
				break
			}
		}
	}
	if ok {
		return v
	}
	b := make([]byte, 0, min(len(v), max))
	for _, r := range v { // invalid bytes arrive as utf8.RuneError
		if unicode.IsControl(r) {
			r = utf8.RuneError
		}
		if len(b)+utf8.RuneLen(r) > max {
			break
		}
		b = utf8.AppendRune(b, r)
	}
	return string(b)
}
