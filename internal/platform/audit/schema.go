package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Track names the part of the platform an event type belongs to.
type Track string

// The tracks.
const (
	TrackAuthz  Track = "authz"  // grantd: authz serve
	TrackAuthn  Track = "authn"  // wicket: authz gateway
	TrackAgents Track = "agents" // toolgate: authz mcp
)

// Kind is the JSON type a payload field must have.
type Kind uint8

// The kinds.
const (
	KindAny     Kind = iota // any JSON value
	KindString              // a string
	KindInteger             // a number without a fraction or exponent
	KindNumber              // any number
	KindBool                // true or false
	KindStrings             // an array of strings
	KindArray               // any array
	KindObject              // any object
)

var kindNames = [...]string{"any value", "a string", "an integer", "a number", "a boolean",
	"an array of strings", "an array", "an object"}

func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return fmt.Sprintf("Kind(%d)", k)
}

// Field describes one payload field.
type Field struct {
	Name string
	Kind Kind
	// Required fields must be present and, for strings, not empty.
	Required bool
}

// Need is the set of envelope fields an event type requires.
type Need uint8

// The envelope fields an event type can require.
const (
	NeedActor Need = 1 << iota
	NeedSubject
	NeedAction
	NeedDecision
)

// Schema is one event type's envelope rules and payload fields.
type Schema struct {
	Event  string
	Track  Track
	Need   Need
	Fields []Field // sorted by name
	byName map[string]int
}

// Payload is a typed event payload: a struct whose JSON fields are the
// payload's fields. A field is required unless its json tag has omitempty.
type Payload interface {
	AuditEvent() string
}

// Schemas is a set of event types. It is read-only once built and safe for
// concurrent use.
type Schemas struct {
	m map[string]*Schema
}

// Def defines one event type from its typed payload.
type Def struct {
	Track   Track
	Payload Payload // a zero value of the payload struct
	Need    Need
}

// NewSchemas builds a set from definitions. Each payload must be a struct
// (or pointer to one) whose exported fields all have json names and
// supported types (go vet's structtag check rejects a json name used twice),
// and event types must be unique.
func NewSchemas(defs ...Def) (*Schemas, error) {
	s := &Schemas{m: make(map[string]*Schema, len(defs))}
	for _, d := range defs {
		sc, err := schemaOf(d)
		if err != nil {
			return nil, err
		}
		if _, dup := s.m[sc.Event]; dup {
			return nil, fmt.Errorf("audit: event type %s is defined twice", sc.Event)
		}
		s.m[sc.Event] = sc
	}
	return s, nil
}

func schemaOf(d Def) (*Schema, error) {
	if d.Payload == nil {
		return nil, errors.New("audit: definition without a payload")
	}
	event := d.Payload.AuditEvent()
	if err := checkEvent(event); err != nil {
		return nil, err
	}
	switch d.Track {
	case TrackAuthz, TrackAuthn, TrackAgents, TrackAudit:
	default:
		return nil, fmt.Errorf("audit: %s: unknown track %q", event, d.Track)
	}
	if i := strings.IndexByte(event, '.'); i >= 0 && Track(event[:i]) != d.Track {
		return nil, fmt.Errorf("audit: %s is prefixed with another track than %s", event, d.Track)
	}
	t := reflect.TypeOf(d.Payload)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("audit: %s: payload %s is not a struct", event, t)
	}
	sc := &Schema{Event: event, Track: d.Track, Need: d.Need, byName: map[string]int{}}
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			return nil, fmt.Errorf("audit: %s: field %s has no json name", event, f.Name)
		}
		k, err := kindOf(f.Type)
		if err != nil {
			return nil, fmt.Errorf("audit: %s: field %s: %w", event, f.Name, err)
		}
		sc.Fields = append(sc.Fields, Field{Name: name, Kind: k, Required: !strings.Contains(","+opts+",", ",omitempty,")})
	}
	sort.Slice(sc.Fields, func(i, j int) bool { return sc.Fields[i].Name < sc.Fields[j].Name })
	for i, f := range sc.Fields {
		sc.byName[f.Name] = i
	}
	return sc, nil
}

func kindOf(t reflect.Type) (Kind, error) {
	switch t.Kind() {
	case reflect.String:
		return KindString, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return KindInteger, nil
	case reflect.Float32, reflect.Float64:
		return KindNumber, nil
	case reflect.Bool:
		return KindBool, nil
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.String {
			return KindStrings, nil
		}
		return KindArray, nil
	case reflect.Map, reflect.Struct:
		return KindObject, nil
	case reflect.Interface:
		return KindAny, nil
	}
	return 0, fmt.Errorf("unsupported type %s", t)
}

// Lookup returns an event type's schema.
func (s *Schemas) Lookup(event string) (*Schema, bool) {
	sc, ok := s.m[event]
	return sc, ok
}

// Events lists the event types, sorted.
func (s *Schemas) Events() []string {
	out := make([]string, 0, len(s.m))
	for e := range s.m {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// SchemaError is a record that does not match its event type's schema.
type SchemaError struct {
	Event string
	Field string // payload field or envelope field; empty for the record
	Msg   string
}

func (e *SchemaError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("%s: %s", e.Event, e.Msg)
	}
	return fmt.Sprintf("%s: %s %s", e.Event, e.Field, e.Msg)
}

// Check reports whether a record's envelope and payload match its event
// type's schema.
func (s *Schemas) Check(event string, env Envelope, data json.RawMessage) error {
	sc, ok := s.m[event]
	if !ok {
		return &SchemaError{Event: truncate(event), Msg: "is not a known event type"}
	}
	if err := env.Check(); err != nil {
		return &SchemaError{Event: event, Msg: strings.TrimPrefix(err.Error(), "audit: ")}
	}
	for _, n := range []struct {
		need Need
		name string
		v    string
	}{
		{NeedActor, "actor", env.Actor},
		{NeedSubject, "subject", env.Subject},
		{NeedAction, "action", env.Action},
		{NeedDecision, "decision", string(env.Decision)},
	} {
		if sc.Need&n.need != 0 && n.v == "" {
			return &SchemaError{Event: event, Field: n.name, Msg: "is required in the envelope"}
		}
	}
	return sc.checkPayload(data)
}

func (sc *Schema) checkPayload(data json.RawMessage) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return &SchemaError{Event: sc.Event, Msg: "payload is not a JSON object"}
	}
	seen := 0
	for name, v := range obj {
		i, ok := sc.byName[name]
		if !ok {
			return &SchemaError{Event: sc.Event, Field: truncate(name), Msg: "is not a field of this event type"}
		}
		seen++
		f := sc.Fields[i]
		if !kindMatches(f.Kind, v) {
			return &SchemaError{Event: sc.Event, Field: name, Msg: "must be " + f.Kind.String()}
		}
		if f.Required && f.Kind == KindString && string(v) == `""` {
			return &SchemaError{Event: sc.Event, Field: name, Msg: "must not be empty"}
		}
	}
	if seen < len(sc.Fields) {
		for _, f := range sc.Fields {
			if _, ok := obj[f.Name]; f.Required && !ok {
				return &SchemaError{Event: sc.Event, Field: f.Name, Msg: "is required"}
			}
		}
	}
	return nil
}

// kindMatches reports whether v, a valid JSON value, has kind k. A null
// matches no kind but KindAny.
func kindMatches(k Kind, v json.RawMessage) bool {
	v = bytes.TrimSpace(v)
	if len(v) == 0 {
		return false
	}
	switch k {
	case KindAny:
		return true
	case KindString:
		return v[0] == '"'
	case KindBool:
		return v[0] == 't' || v[0] == 'f'
	case KindNumber:
		return v[0] == '-' || v[0] >= '0' && v[0] <= '9'
	case KindInteger:
		return (v[0] == '-' || v[0] >= '0' && v[0] <= '9') && !bytes.ContainsAny(v, ".eE")
	case KindObject:
		return v[0] == '{'
	case KindArray:
		return v[0] == '['
	case KindStrings:
		if v[0] != '[' {
			return false
		}
		var elems []json.RawMessage
		if json.Unmarshal(v, &elems) != nil {
			return false
		}
		for _, e := range elems {
			if len(e) == 0 || e[0] != '"' {
				return false
			}
		}
		return true
	}
	return false
}
