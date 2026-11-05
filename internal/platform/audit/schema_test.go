package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func openWith(t *testing.T, s *Schemas) (string, *Log) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := OpenWith(path, Options{Now: fixedNow, Schemas: s})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return path, l
}

func verifyWithFile(t *testing.T, path string, s *Schemas) (Result, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return VerifyWith(f, s)
}

const cid = "4bf92f3577b34da6a3ce929d0e0e4736"

// mixedEvents is one request through all three tracks plus each track's
// other kinds of record.
func mixedEvents() []struct {
	env Envelope
	p   Payload
} {
	return []struct {
		env Envelope
		p   Payload
	}{
		{Envelope{Actor: "alice", Action: "login", Decision: Allow, CorrelationID: cid},
			LoginSucceeded{Provider: "corp", App: "wiki", Session: "s_1", Email: "alice@example.com", ClientIP: "203.0.113.7"}},
		{Envelope{Actor: "gateway", Subject: "document:readme", Action: "view", Decision: Allow, CorrelationID: cid},
			CheckDecided{Principal: "user:alice", Revision: "GhUKEzE3MDAwMDAwMDA"}},
		{Envelope{CorrelationID: cid},
			ToolCall{Agent: "alice-bot", Auth: "token", Upstream: "fake", Tool: "echo", Decision: "allow", Stage: "completed",
				Outcome: "ok", LatencyMS: 3, ResponseBytes: 12, RequestID: cid}},
		{Envelope{Tenant: "acme", Actor: "key:ops", Action: "schema.write"},
			SchemaWritten{Revision: "r1", SHA256: strings.Repeat("a", 64), Bytes: 120}},
		{Envelope{Actor: "key:ops", Action: "relationships.write"},
			RelationshipsWritten{Revision: "r2", Touch: 2, Delete: 1}},
		{Envelope{Action: "login", Decision: Deny}, LoginFailed{Reason: "state_invalid"}},
		{Envelope{Actor: "admin", Subject: "s_1", Action: "session.revoke"}, SessionRevoked{Session: "s_1", By: "admin"}},
		{Envelope{Subject: "wiki", Action: "access", Decision: Deny}, AccessDenied{Reason: "group", App: "wiki"}},
		{Envelope{Actor: "alice", Action: "logout", CorrelationID: cid}, Logout{Provider: "corp", Session: "s_1"}},
		{Envelope{Action: "config.load"}, ConfigLoaded{Providers: 1, Apps: 2}},
		{Envelope{}, PolicyApplied{Previous: "a", Current: "b"}},
	}
}

func TestMixedChainVerifies(t *testing.T) {
	path, l := openWith(t, Default())
	if err := l.Append("tool_call", map[string]any{"agent": "old", "auth": "token", "decision": "deny", "stage": "refused"}); err != nil {
		t.Fatal(err)
	}
	for _, e := range mixedEvents() {
		if err := l.Write(e.env, e.p); err != nil {
			t.Fatalf("%s: %v", e.p.AuditEvent(), err)
		}
	}
	n, head := l.Head()
	res, err := verifyWithFile(t, path, Default())
	if err != nil || res.Records != n || res.Head != head {
		t.Fatalf("verify with schemas: %+v %v (head %d %s)", res, err, n, head)
	}
	l.Close()

	// The chain reopens and continues, and every record keeps its envelope.
	l2, err := OpenWith(path, Options{Now: fixedNow, Schemas: Default()})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if s, h := l2.Head(); s != n || h != head {
		t.Fatalf("reopened head %d %s", s, h)
	}
	if err := l2.Write(Envelope{Action: "config.load"}, ConfigLoadFailed{Error: "bad provider"}); err != nil {
		t.Fatal(err)
	}
	if res, err := verifyWithFile(t, path, Default()); err != nil || res.Records != n+1 {
		t.Fatalf("after reopen: %+v %v", res, err)
	}
	var byCID []string
	for i, line := range lines(t, path) {
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if i == 0 && rec.Envelope != (Envelope{}) {
			t.Fatalf("Append wrote an envelope: %s", line)
		}
		if rec.CorrelationID == cid {
			byCID = append(byCID, rec.Event)
		}
	}
	want := []string{EventLoginSucceeded, EventCheckDecided, EventToolCall, EventLogout}
	if !reflect.DeepEqual(byCID, want) {
		t.Fatalf("records under one correlation ID: %v, want %v", byCID, want)
	}
}

func TestEnvelopeRecordFormat(t *testing.T) {
	path, l := openWith(t, Default())
	err := l.Write(Envelope{Tenant: "acme", Actor: "alice", Subject: "document:readme", Action: "view", Decision: Allow, CorrelationID: cid},
		CheckDecided{Principal: "user:alice", Revision: "r<1>"})
	if err != nil {
		t.Fatal(err)
	}
	got := lines(t, path)[0]
	want := `{"seq":1,"time":"2023-11-14T22:13:20Z","prev":"` + Genesis + `","event":"authz.check_decided",` +
		`"tenant":"acme","actor":"alice","subject":"document:readme","action":"view","decision":"allow",` +
		`"correlation_id":"` + cid + `","data":{"principal":"user:alice","revision":"r<1>"}}`
	if got != want {
		t.Fatalf("record\n got %s\nwant %s", got, want)
	}
}

func TestTamperedEnvelopeDetected(t *testing.T) {
	path, l := openWith(t, Default())
	for _, e := range mixedEvents() {
		if err := l.Write(e.env, e.p); err != nil {
			t.Fatal(err)
		}
	}
	ls := lines(t, path)
	ls[1] = strings.Replace(ls[1], `"decision":"allow"`, `"decision":"deny"`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := verifyWithFile(t, path, Default())
	var le *LineError
	if !errors.As(err, &le) || le.Line != 2 {
		t.Fatalf("changed decision: %v", err)
	}
}

// A record with a valid chain but a payload outside its schema passes
// Verify and fails VerifyWith on its line.
func TestVerifyWithFindsSchemaViolations(t *testing.T) {
	cases := []struct {
		name  string
		event string
		env   Envelope
		data  any
		want  string
	}{
		{"unknown event", "authz.nope", Envelope{}, map[string]any{}, "authz.nope: is not a known event type"},
		{"missing field", EventToolCall, Envelope{}, map[string]any{"agent": "a", "auth": "t", "decision": "deny"}, "tool_call: stage is required"},
		{"empty required", EventToolCall, Envelope{}, map[string]any{"agent": "", "auth": "t", "decision": "deny", "stage": "x"}, "tool_call: agent must not be empty"},
		{"unknown field", EventToolApproved, Envelope{}, map[string]any{"tool": "t", "hash": "h", "password": "x"}, "tool_approved: password is not a field of this event type"},
		{"wrong kind", EventToolCall, Envelope{}, map[string]any{"agent": "a", "auth": "t", "decision": "deny", "stage": "x", "latency_ms": "3"}, "tool_call: latency_ms must be an integer"},
		{"fraction", EventToolCall, Envelope{}, map[string]any{"agent": "a", "auth": "t", "decision": "deny", "stage": "x", "latency_ms": 1.5}, "tool_call: latency_ms must be an integer"},
		{"null", EventToolCall, Envelope{}, map[string]any{"agent": "a", "auth": "t", "decision": "deny", "stage": "x", "error": nil}, "tool_call: error must be a string"},
		{"not an object", EventToolApproved, Envelope{}, []string{"x"}, "tool_approved: payload is not a JSON object"},
		{"missing envelope", EventCheckDecided, Envelope{Action: "view", Decision: Deny}, CheckDecided{Principal: "p", Revision: "r"}, "authz.check_decided: subject is required in the envelope"},
		{"missing decision", EventLoginFailed, Envelope{Action: "login"}, LoginFailed{Reason: "x"}, "authn.login_failed: decision is required in the envelope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path, l := openWith(t, nil)
			if err := l.Append(EventToolApproved, ToolApproved{Tool: "t", Hash: "h"}); err != nil {
				t.Fatal(err)
			}
			if err := l.AppendWith(c.event, c.env, c.data); err != nil {
				t.Fatal(err)
			}
			if _, err := verifyFileReader(t, path); err != nil {
				t.Fatalf("chain: %v", err)
			}
			_, err := verifyWithFile(t, path, Default())
			var le *LineError
			if !errors.As(err, &le) || le.Line != 2 || le.Msg != c.want {
				t.Fatalf("got %v, want line 2: %s", err, c.want)
			}

			// A log with schemas refuses the same record and writes nothing.
			_, sl := openWith(t, Default())
			err = sl.AppendWith(c.event, c.env, c.data)
			var se *SchemaError
			if !errors.As(err, &se) || se.Error() != c.want {
				t.Fatalf("append with schemas: %v", err)
			}
			if n, h := sl.Head(); n != 0 || h != Genesis {
				t.Fatalf("refused record was written: %d %s", n, h)
			}
		})
	}
}

func verifyFileReader(t *testing.T, path string) (Result, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return Verify(f)
}

func TestEnvelopeAndEventChecks(t *testing.T) {
	long := strings.Repeat("a", MaxEnvelopeBytes+1)
	bad := []struct {
		event string
		env   Envelope
		want  string
	}{
		{"", Envelope{}, "event type must be 1 to 64 bytes"},
		{strings.Repeat("a", 65), Envelope{}, "event type must be 1 to 64 bytes"},
		{"Tool_Call", Envelope{}, "may only contain"},
		{"tool call", Envelope{}, "may only contain"},
		{"x", Envelope{Tenant: strings.Repeat("t", MaxTenantBytes+1)}, "tenant is longer than 128 bytes"},
		{"x", Envelope{Actor: long}, "actor is longer than 512 bytes"},
		{"x", Envelope{Subject: "a\nb"}, "subject contains a control character"},
		{"x", Envelope{Action: "\xff"}, "action is not valid UTF-8"},
		{"x", Envelope{Decision: "maybe"}, `decision "maybe" is not allow or deny`},
		{"x", Envelope{CorrelationID: "a b"}, "correlation_id contains ' '"},
		{"x", Envelope{CorrelationID: strings.Repeat("c", MaxCorrelationIDBytes+1)}, "correlation_id is longer than 128 bytes"},
	}
	for _, b := range bad {
		_, l := openWith(t, nil)
		if err := l.AppendWith(b.event, b.env, map[string]any{}); err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("%q %+v: got %v, want %q", b.event, b.env, err, b.want)
		}
		if n, _ := l.Head(); n != 0 {
			t.Errorf("%q: refused record was written", b.event)
		}
	}
	ok := Envelope{Tenant: "acme", Actor: "user:ålice", Subject: "doc:1", Action: "view", Decision: Deny,
		CorrelationID: "00-4bf92f35_77b3.4da6:a3ce"}
	if err := ok.Check(); err != nil {
		t.Fatal(err)
	}
	_, l := openWith(t, nil)
	if err := l.Write(Envelope{}, nil); err == nil {
		t.Fatal("nil payload accepted")
	}
	if err := l.AppendWith("x", Envelope{}, func() {}); err == nil {
		t.Fatal("unencodable payload accepted")
	}
	_, sl := openWith(t, Default())
	if err := sl.AppendWith(EventToolApproved, Envelope{}, func() {}); err == nil || !strings.Contains(err.Error(), "encoding tool_approved payload") {
		t.Fatalf("unencodable payload with schemas: %v", err)
	}
	if _, err := VerifyWith(strings.NewReader(""), nil); err == nil {
		t.Fatal("VerifyWith without schemas")
	}
	// A record whose envelope is malformed fails VerifyWith even though its
	// chain is intact: a hand-made line, re-chained.
	line := `{"seq":1,"time":"t","prev":"` + Genesis + `","event":"tool_approved","decision":"maybe","data":{"tool":"t","hash":"h"}}` + "\n"
	if _, err := Verify(strings.NewReader(line)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWith(strings.NewReader(line), Default()); err == nil || !strings.Contains(err.Error(), "line 1: tool_approved: decision") {
		t.Fatalf("malformed envelope: %v", err)
	}
}

// The log the old toolgate binary wrote matches the agents schemas.
func TestOldBinaryChainMatchesSchemas(t *testing.T) {
	res, err := verifyWithFile(t, filepath.Join("testdata", "toolgate-demo.jsonl"), Default())
	if err != nil || res.Records != 23 {
		t.Fatalf("%+v %v", res, err)
	}
}

// filled returns p's struct with every field set, so each field appears in
// its JSON.
func filled(p Payload) any {
	v := reflect.New(reflect.TypeOf(p)).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString("x")
		case reflect.Int, reflect.Int64:
			f.SetInt(1)
		case reflect.Bool:
			f.SetBool(true)
		}
	}
	return v.Interface()
}

func TestDefaultSchemas(t *testing.T) {
	s := Default()
	defs := Defs()
	if got := len(s.Events()); got != len(defs) {
		t.Fatalf("%d event types, %d definitions", got, len(defs))
	}
	tracks := map[Track]int{}
	for _, d := range defs {
		ev := d.Payload.AuditEvent()
		sc, ok := s.Lookup(ev)
		if !ok || sc.Track != d.Track || sc.Event != ev {
			t.Fatalf("%s: %+v", ev, sc)
		}
		tracks[d.Track]++
		env := Envelope{Actor: "a", Subject: "s", Action: "x", Decision: Allow}
		raw, err := marshal(filled(d.Payload))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Check(ev, env, raw); err != nil {
			t.Errorf("%s with every field: %v", ev, err)
		}
		// The zero payload passes exactly when nothing is required.
		zero, _ := marshal(d.Payload)
		required := 0
		for _, f := range sc.Fields {
			if f.Required && f.Kind == KindString {
				required++
			}
		}
		if err := s.Check(ev, env, zero); (err == nil) != (required == 0) {
			t.Errorf("%s zero payload with %d required strings: %v", ev, required, err)
		}
		if sc.Need != 0 {
			if err := s.Check(ev, Envelope{}, raw); err == nil {
				t.Errorf("%s: empty envelope accepted though it needs %b", ev, sc.Need)
			}
		}
	}
	if tracks[TrackAuthz] == 0 || tracks[TrackAuthn] == 0 || tracks[TrackAgents] == 0 {
		t.Fatalf("tracks %v", tracks)
	}
	sc, _ := s.Lookup(EventToolCall)
	want := map[string]Field{
		"agent":      {Name: "agent", Kind: KindString, Required: true},
		"truncated":  {Name: "truncated", Kind: KindBool},
		"latency_ms": {Name: "latency_ms", Kind: KindInteger},
		"owner":      {Name: "owner", Kind: KindString},
	}
	for _, f := range sc.Fields {
		if w, ok := want[f.Name]; ok && w != f {
			t.Errorf("field %+v, want %+v", f, w)
		}
	}
	if _, ok := s.Lookup("policy_reload"); ok {
		t.Fatal("unexpected event type")
	}
}

type badPayload struct{ ev string }

func (b badPayload) AuditEvent() string { return b.ev }

type noTag struct{ A string }

func (noTag) AuditEvent() string { return "authz.no_tag" }

type badType struct {
	C chan int `json:"c"`
}

func (badType) AuditEvent() string { return "authz.bad_type" }

type notStruct string

func (notStruct) AuditEvent() string { return "authz.not_struct" }

type allKinds struct {
	S  string            `json:"s"`
	I  uint8             `json:"i"`
	F  float64           `json:"f"`
	B  bool              `json:"b"`
	SS []string          `json:"ss"`
	A  []int             `json:"a"`
	O  map[string]string `json:"o"`
	T  struct{}          `json:"t"`
	X  any               `json:"x"`
	_  int
}

func (allKinds) AuditEvent() string { return "authz.all_kinds" }

func TestNewSchemas(t *testing.T) {
	bad := []struct {
		name string
		defs []Def
		want string
	}{
		{"nil payload", []Def{{Track: TrackAuthz}}, "definition without a payload"},
		{"bad event", []Def{{TrackAuthz, badPayload{"Bad"}, 0}}, "may only contain"},
		{"unknown track", []Def{{"billing", noTag{}, 0}}, `unknown track "billing"`},
		{"other prefix", []Def{{TrackAuthn, noTag{}, 0}}, "prefixed with another track than authn"},
		{"no json name", []Def{{TrackAuthz, noTag{}, 0}}, "field A has no json name"},
		{"unsupported", []Def{{TrackAuthz, badType{}, 0}}, "unsupported type chan int"},
		{"not a struct", []Def{{TrackAuthz, notStruct(""), 0}}, "is not a struct"},
		{"duplicate event", []Def{{TrackAgents, ToolCall{}, 0}, {TrackAgents, &ToolCall{}, 0}}, "tool_call is defined twice"},
	}
	for _, b := range bad {
		if _, err := NewSchemas(b.defs...); err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("%s: got %v, want %q", b.name, err, b.want)
		}
	}
	s, err := NewSchemas(Def{TrackAuthz, &allKinds{}, NeedActor})
	if err != nil {
		t.Fatal(err)
	}
	sc, _ := s.Lookup("authz.all_kinds")
	kinds := map[string]Kind{}
	for _, f := range sc.Fields {
		kinds[f.Name] = f.Kind
	}
	want := map[string]Kind{"s": KindString, "i": KindInteger, "f": KindNumber, "b": KindBool, "ss": KindStrings,
		"a": KindArray, "o": KindObject, "t": KindObject, "x": KindAny}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("kinds %v", kinds)
	}
	good := `{"s":"v","i":2,"f":1.5e3,"b":false,"ss":["a","null"],"a":[1,null],"o":{},"t":{"k":1},"x":null}`
	if err := s.Check("authz.all_kinds", Envelope{Actor: "a"}, json.RawMessage(good)); err != nil {
		t.Fatal(err)
	}
	for field, v := range map[string]string{"s": `1`, "i": `-1e2`, "f": `"1"`, "b": `null`, "ss": `["a",null]`,
		"a": `{}`, "o": `[]`, "t": `"x"`} {
		var m map[string]json.RawMessage
		_ = json.Unmarshal([]byte(good), &m)
		m[field] = json.RawMessage(v)
		raw, _ := json.Marshal(m)
		err := s.Check("authz.all_kinds", Envelope{Actor: "a"}, raw)
		if err == nil || !strings.Contains(err.Error(), field+" must be") {
			t.Errorf("%s=%s: %v", field, v, err)
		}
	}
	if err := s.Check("authz.all_kinds", Envelope{}, json.RawMessage(good)); err == nil {
		t.Fatal("missing actor accepted")
	}
	if err := s.Check("authz.all_kinds", Envelope{Actor: "a"}, json.RawMessage(`null`)); err == nil {
		t.Fatal("null payload accepted")
	}
	if Kind(99).String() != "Kind(99)" || KindStrings.String() != "an array of strings" {
		t.Fatal("kind names")
	}
	if kindMatches(Kind(99), json.RawMessage(`1`)) || kindMatches(KindAny, nil) || kindMatches(KindStrings, json.RawMessage(`[`)) {
		t.Fatal("kindMatches")
	}
	if (&SchemaError{Event: "e", Msg: "m"}).Error() != "e: m" {
		t.Fatal("SchemaError")
	}
}
