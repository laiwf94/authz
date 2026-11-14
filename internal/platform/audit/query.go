package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Queries
//
// A filter selects records of the one log by what every track's events
// have in common, so one query follows a sign-in, the check it led to and
// the tool call it allowed. It is a list of terms, all of which must hold:
//
//	track=agents decision=deny since=2026-11-16 until=-1h
//	agent=alice-bot tool=read_file,write_file rule!=default-deny
//
// A term is KEY=VALUE or KEY!=VALUE. A value is a comma-separated list of
// alternatives, any one of which matches (with !=, none may), or a
// double-quoted Go string, which is one value and may hold spaces and
// commas. A value ending in '*' matches every value that starts with what
// comes before it. The keys:
//
//	track        authz, authn, agents or audit (the log's own records),
//	             or empty for event types of no track
//	event        the event type, such as tool_call or authn.login_failed
//	tenant actor subject action decision correlation
//	             the envelope's fields (correlation is correlation_id)
//	agent tool rule
//	             the agent, the tool and the rule of an agent's records:
//	             the payload's agent, tool, and rule_id or
//	             constraint_rule_id
//	data.NAME    any payload field, compared by its text: a string's
//	             value, or a number's or boolean's JSON
//	since until  the record's time, at or after since and before until:
//	             an RFC 3339 time, a date (midnight UTC) or a duration
//	             before now such as -24h; = only
//
// toolgate's records (the agents track) carry no envelope, or one with only
// the request's correlation ID, so a query sees the envelope fields they
// leave empty as derived from the payload: actor is the agent, subject is
// "tool:" and the tool, action is the event type, and decision is the
// payload's, approved and denied read as allow and deny. A record a field
// does not apply to has the empty value, which only "KEY=" (or KEY!=X)
// matches.

// Filter selects records. The zero value matches every record.
type Filter struct {
	terms []term
	// Since and Until bound the records' times: at or after Since, before
	// Until. Zero means unbounded. A record whose time does not parse
	// matches neither bound.
	Since, Until time.Time
}

type term struct {
	key    string // a key of the list above; data fields as "data.NAME"
	negate bool
	values []string
}

// The keys a filter knows, apart from data.NAME.
var filterKeys = map[string]bool{
	"track": true, "event": true, "tenant": true, "actor": true, "subject": true,
	"action": true, "decision": true, "correlation": true,
	"agent": true, "tool": true, "rule": true, "since": true, "until": true,
}

// Limits on a filter, so a query string from a request stays small.
const (
	MaxFilterBytes = 4096
	maxFilterTerms = 64
)

// ParseFilter reads a filter from its text form: terms separated by
// spaces. now resolves relative times (since=-24h).
func ParseFilter(s string, now time.Time) (*Filter, error) {
	if len(s) > MaxFilterBytes {
		return nil, fmt.Errorf("audit: filter is longer than %d bytes", MaxFilterBytes)
	}
	var terms []string
	for i := 0; i < len(s); {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' {
			i++
			continue
		}
		j, quoted := i, false
		for ; j < len(s); j++ {
			c := s[j]
			if quoted {
				if c == '\\' && j+1 < len(s) {
					j++
				} else if c == '"' {
					quoted = false
				}
				continue
			}
			if c == '"' {
				quoted = true
			} else if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
				break
			}
		}
		if quoted {
			return nil, fmt.Errorf("audit: filter: unterminated quote in %q", truncate(s[i:]))
		}
		terms = append(terms, s[i:j])
		i = j
	}
	return ParseFilterTerms(terms, now)
}

// ParseFilterTerms reads a filter given as one term per string, as command
// line arguments give it.
func ParseFilterTerms(terms []string, now time.Time) (*Filter, error) {
	if len(terms) > maxFilterTerms {
		return nil, fmt.Errorf("audit: filter has more than %d terms", maxFilterTerms)
	}
	f := &Filter{}
	n := 0
	for _, t := range terms {
		if n += len(t) + 1; n > MaxFilterBytes+1 {
			return nil, fmt.Errorf("audit: filter is longer than %d bytes", MaxFilterBytes)
		}
		if err := f.add(t, now); err != nil {
			return nil, fmt.Errorf("audit: filter: %w", err)
		}
	}
	if !f.Since.IsZero() && !f.Until.IsZero() && !f.Until.After(f.Since) {
		return nil, errors.New("audit: filter: until must be later than since")
	}
	return f, nil
}

func (f *Filter) add(t string, now time.Time) error {
	i := strings.IndexByte(t, '=')
	if i <= 0 {
		return fmt.Errorf("term %q is not KEY=VALUE or KEY!=VALUE", truncate(t))
	}
	key, raw, negate := t[:i], t[i+1:], false
	if strings.HasSuffix(key, "!") {
		key, negate = key[:len(key)-1], true
	}
	if !validKey(key) {
		return fmt.Errorf("unknown key %q (track, event, tenant, actor, subject, action, decision, correlation, agent, tool, rule, data.NAME, since, until)", truncate(key))
	}
	values, err := termValues(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	switch key {
	case "since", "until":
		if negate || len(values) != 1 {
			return fmt.Errorf("%s takes one time with =", key)
		}
		at, err := parseQueryTime(values[0], now)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		bound := &f.Since
		if key == "until" {
			bound = &f.Until
		}
		if !bound.IsZero() {
			return fmt.Errorf("%s is given twice", key)
		}
		*bound = at
		return nil
	case "track":
		for _, v := range values {
			switch Track(strings.TrimSuffix(v, "*")) {
			case "", TrackAuthz, TrackAuthn, TrackAgents, TrackAudit:
			default:
				if !strings.HasSuffix(v, "*") {
					return fmt.Errorf("track %q is not authz, authn, agents or audit", truncate(v))
				}
			}
		}
	case "decision":
		for _, v := range values {
			if v != "" && v != string(Allow) && v != string(Deny) && !strings.HasSuffix(v, "*") {
				return fmt.Errorf("decision %q is not allow or deny", truncate(v))
			}
		}
	}
	f.terms = append(f.terms, term{key: key, negate: negate, values: values})
	return nil
}

func validKey(k string) bool {
	if name, ok := strings.CutPrefix(k, "data."); ok {
		if name == "" || len(name) > 128 {
			return false
		}
		for _, r := range name {
			if unicode.IsControl(r) || r == ' ' {
				return false
			}
		}
		return true
	}
	return filterKeys[k]
}

func termValues(raw string) ([]string, error) {
	var vs []string
	switch {
	case strings.HasPrefix(raw, `"`):
		v, err := strconv.Unquote(raw)
		if err != nil {
			return nil, fmt.Errorf("%s is not a valid quoted string", truncate(raw))
		}
		vs = []string{v}
	case strings.ContainsRune(raw, '"'):
		return nil, fmt.Errorf("%q: quote the whole value", truncate(raw))
	default:
		vs = strings.Split(raw, ",")
	}
	for _, v := range vs {
		if len(vs) > 1 && strings.ContainsAny(v, " \t") {
			return nil, errors.New("a value with spaces must be the only one; quote it")
		}
		// No envelope field holds these (see Clean).
		if !utf8.ValidString(v) || strings.ContainsFunc(v, unicode.IsControl) {
			return nil, errors.New("values must be UTF-8 text without control characters")
		}
	}
	return vs, nil
}

// quote is the shortest quoted form of v that strconv.Unquote reads back,
// for a value of valid UTF-8 without control characters.
func quote(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// parseQueryTime reads an RFC 3339 time, a date or a duration before now.
func parseQueryTime(s string, now time.Time) (time.Time, error) {
	if strings.HasPrefix(s, "-") {
		d, err := time.ParseDuration(s[1:])
		if err != nil || d <= 0 {
			return time.Time{}, fmt.Errorf("%q is not a duration before now, such as -24h", truncate(s))
		}
		return now.Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("%q is not an RFC 3339 time, a date (2006-01-02) or a duration such as -24h", truncate(s))
}

// String is the filter's text form, which ParseFilter reads back.
func (f *Filter) String() string {
	var b strings.Builder
	for _, t := range f.terms {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(t.key)
		if t.negate {
			b.WriteByte('!')
		}
		b.WriteByte('=')
		plain := true
		for _, v := range t.values {
			if strings.ContainsAny(v, ", \"") || strings.HasPrefix(v, `"`) {
				plain = false
			}
		}
		switch {
		case plain || len(t.values) != 1:
			// Several values never hold a comma: the parser split them.
			b.WriteString(strings.Join(t.values, ","))
		default:
			b.WriteString(quote(t.values[0]))
		}
	}
	for _, bound := range []struct {
		k string
		t time.Time
	}{{"since", f.Since}, {"until", f.Until}} {
		if !bound.t.IsZero() {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(bound.k + "=" + bound.t.UTC().Format(time.RFC3339Nano))
		}
	}
	return b.String()
}

// timed reports whether the filter bounds the records' times.
func (f *Filter) timed() bool { return f != nil && (!f.Since.IsZero() || !f.Until.IsZero()) }

// Match reports whether a record matches. s gives each event type's track
// (Default when nil); an event type it does not know belongs to the track
// its prefix names, or to none.
func (f *Filter) Match(rec *Record, s *Schemas) bool {
	if f == nil {
		return true
	}
	if f.timed() {
		t, err := time.Parse(time.RFC3339Nano, rec.Time)
		if err != nil || !f.Since.IsZero() && t.Before(f.Since) || !f.Until.IsZero() && !t.Before(f.Until) {
			return false
		}
	}
	if len(f.terms) == 0 {
		return true
	}
	v := view{rec: rec, s: s}
	for _, t := range f.terms {
		var hit bool
		if t.key == "rule" {
			// Either of a tool call's rules: the one that decided it, or
			// the one whose argument constraints refused it.
			// A record with neither has the empty rule.
			r, c := v.str("rule_id"), v.str("constraint_rule_id")
			hit = r != "" && t.hits(r) || c != "" && t.hits(c) || r == "" && c == "" && t.hits("")
		} else {
			hit = t.hits(v.field(t.key))
		}
		if hit == t.negate {
			return false
		}
	}
	return true
}

// hits reports whether got is one of the term's values.
func (t *term) hits(got string) bool {
	for _, want := range t.values {
		if p, ok := strings.CutSuffix(want, "*"); ok && strings.HasPrefix(got, p) || got == want {
			return true
		}
	}
	return false
}

// view reads a record's fields for a filter, decoding its payload once
// and only when a term needs it.
type view struct {
	rec     *Record
	s       *Schemas
	data    map[string]json.RawMessage
	decoded bool
}

func (v *view) field(key string) string {
	r := v.rec
	switch key {
	case "track":
		return string(TrackOf(r.Event, v.s))
	case "event":
		return r.Event
	case "tenant":
		return r.Tenant
	case "correlation":
		return r.CorrelationID
	case "actor":
		if r.Actor == "" && v.agents() {
			return v.str("agent")
		}
		return r.Actor
	case "subject":
		if r.Subject == "" && v.agents() {
			if t := v.str("tool"); t != "" {
				return "tool:" + t
			}
		}
		return r.Subject
	case "action":
		if r.Action == "" && v.agents() {
			return r.Event
		}
		return r.Action
	case "decision":
		if r.Decision == "" && v.agents() {
			switch d := v.str("decision"); d {
			case "approved":
				return string(Allow)
			case "denied":
				return string(Deny)
			default:
				return d
			}
		}
		return string(r.Decision)
	case "agent":
		return v.str("agent")
	case "tool":
		return v.str("tool")
	}
	return v.str(strings.TrimPrefix(key, "data."))
}

// agents reports whether the record is an agents-track record, whose
// envelope fields, when empty, come from its payload. authz mcp writes the
// records of a request with an envelope holding only the correlation ID
// (#241), so the envelope as a whole need not be empty.
func (v *view) agents() bool {
	return TrackOf(v.rec.Event, v.s) == TrackAgents
}

// str is a payload field's text: a string's value, another scalar's JSON,
// empty for a missing field, null, an array or an object.
func (v *view) str(name string) string {
	if !v.decoded {
		v.decoded = true
		_ = json.Unmarshal(v.rec.Data, &v.data)
	}
	raw := bytes.TrimSpace(v.data[name])
	if len(raw) == 0 {
		return ""
	}
	switch raw[0] {
	case '"':
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		return ""
	case '{', '[', 'n':
		return ""
	}
	return string(raw)
}

// TrackOf is the track an event type belongs to: its schema's in s
// (Default when nil), else the track its prefix names, else none.
func TrackOf(event string, s *Schemas) Track {
	if s == nil {
		s = Default()
	}
	if sc, ok := s.Lookup(event); ok {
		return sc.Track
	}
	if i := strings.IndexByte(event, '.'); i > 0 {
		switch t := Track(event[:i]); t {
		case TrackAuthz, TrackAuthn, TrackAgents, TrackAudit:
			return t
		}
	}
	return ""
}
