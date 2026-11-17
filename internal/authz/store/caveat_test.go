package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/clock"
)

const caveatRelSchema = `
caveat ip_allowed(allowed cidr, client_ip ipaddress) {
  allowed.containsIP(client_ip)
}

caveat quota(limit int, used int) { used < limit }

definition user {}

definition group {
  relation member: user | user with quota
}

definition doc {
  relation viewer: user | user with ip_allowed | user:* with ip_allowed | group#member with quota
  relation guest: user with ip_allowed
}
`

func caveatStore(t *testing.T, dir string) *Store {
	t.Helper()
	s := newStore(t, dir)
	if _, err := s.WriteSchema(caveatRelSchema); err != nil {
		t.Fatal(err)
	}
	return s
}

func touchCaveat(t *testing.T, s *Store, rel string, c *Caveat) Revision {
	t.Helper()
	rev, err := s.Write([]Update{{Op: OpTouch, Relationship: mustRel(t, rel), Caveat: c}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

// storedCaveats maps each relationship ReadDirectCaveated returns to its
// caveat rendered as JSON, "" for none.
func storedCaveats(t *testing.T, s *Store, rev Revision, typ, id, rel string) map[string]string {
	t.Helper()
	st, err := s.ReadDirectCaveated(rev, typ, id, rel)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range st {
		v := ""
		if r.Caveat != nil {
			b, err := json.Marshal(r.Caveat)
			if err != nil {
				t.Fatal(err)
			}
			v = string(b)
		}
		out[r.String()] = v
	}
	return out
}

func TestCaveatedRelationships(t *testing.T) {
	s := caveatStore(t, "")
	ctx := map[string]any{"allowed": "10.0.0.0/8"}
	r1 := touchCaveat(t, s, "doc:a#viewer@user:x", &Caveat{Name: "ip_allowed", Context: ctx})
	touchCaveat(t, s, "doc:a#viewer@user:y", nil)
	r3 := touchCaveat(t, s, "doc:a#viewer@user:*", &Caveat{Name: "ip_allowed"})

	got := storedCaveats(t, s, r3, "doc", "a", "viewer")
	want := map[string]string{
		"doc:a#viewer@user:x": `{"name":"ip_allowed","context":{"allowed":"10.0.0.0/8"}}`,
		"doc:a#viewer@user:y": "",
		"doc:a#viewer@user:*": `{"name":"ip_allowed"}`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stored %v, want %v", got, want)
	}
	// ReadDirect leaves caveated relationships out; Read and filters see
	// them, since they exist.
	plain := direct(t, s, r3, "doc", "a", "viewer")
	if len(plain) != 1 || plain[0] != "user:y" {
		t.Fatalf("ReadDirect = %v", plain)
	}
	all, _, err := s.Read(r3, Filter{ResourceType: "doc"}, "", 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("Read = %v, %v", all, err)
	}
	if _, err := s.Write([]Update{{Op: OpCreate, Relationship: mustRel(t, "doc:a#viewer@user:x")}}, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("create over a caveated relationship: %v", err)
	}
	// The context was copied: changing the caller's map changes nothing.
	ctx["allowed"] = "0.0.0.0/0"
	if got := storedCaveats(t, s, r1, "doc", "a", "viewer")["doc:a#viewer@user:x"]; !strings.Contains(got, "10.0.0.0/8") {
		t.Fatalf("stored context changed with the caller's map: %s", got)
	}

	// Watch sees the caveat on the touch.
	ch, err := s.Changes(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch) != 3 || ch[0].Caveat == nil || ch[0].Caveat.Name != "ip_allowed" || ch[1].Caveat != nil {
		t.Fatalf("changes %+v", ch)
	}
}

func TestCaveatTouchSemantics(t *testing.T) {
	s := caveatStore(t, "")
	c1 := &Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": "10.0.0.0/8"}}
	r1 := touchCaveat(t, s, "doc:a#viewer@user:x", c1)
	// The same caveat and context, even built afresh and with an integer
	// written another way, is no change.
	if r := touchCaveat(t, s, "doc:a#viewer@user:x", &Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": "10.0.0.0/8"}}); r != r1 {
		t.Fatalf("touching the same caveat made revision %d", r)
	}
	g1 := touchCaveat(t, s, "group:g#member@user:x", &Caveat{Name: "quota", Context: map[string]any{"limit": 3}})
	if r := touchCaveat(t, s, "group:g#member@user:x", &Caveat{Name: "quota", Context: map[string]any{"limit": json.Number("3")}}); r != g1 {
		t.Fatalf("3 and json.Number(3) differ: revision %d", r)
	}
	if r := touchCaveat(t, s, "group:g#member@user:x", &Caveat{Name: "quota", Context: map[string]any{"limit": 3.0}}); r != g1 {
		t.Fatalf("3 and 3.0 differ: revision %d", r)
	}
	// Another context replaces the first; the old snapshot keeps it.
	r2 := touchCaveat(t, s, "doc:a#viewer@user:x", &Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": "192.168.0.0/16"}})
	if got := storedCaveats(t, s, r1, "doc", "a", "viewer")["doc:a#viewer@user:x"]; !strings.Contains(got, "10.0.0.0/8") {
		t.Fatalf("old snapshot sees %s", got)
	}
	if got := storedCaveats(t, s, r2, "doc", "a", "viewer")["doc:a#viewer@user:x"]; !strings.Contains(got, "192.168") {
		t.Fatalf("new snapshot sees %s", got)
	}
	// Dropping the caveat is a change too, and an empty context is none.
	r3 := touchCaveat(t, s, "doc:a#viewer@user:x", nil)
	if got := storedCaveats(t, s, r3, "doc", "a", "viewer")["doc:a#viewer@user:x"]; got != "" {
		t.Fatalf("caveat kept: %s", got)
	}
	r4 := touchCaveat(t, s, "doc:a#viewer@user:x", &Caveat{Name: "ip_allowed", Context: map[string]any{}})
	if r5 := touchCaveat(t, s, "doc:a#viewer@user:x", &Caveat{Name: "ip_allowed"}); r5 != r4 {
		t.Fatalf("empty context and none differ: %d, %d", r4, r5)
	}
	if got := storedCaveats(t, s, r4, "doc", "a", "viewer")["doc:a#viewer@user:x"]; got != `{"name":"ip_allowed"}` {
		t.Fatalf("empty context stored as %s", got)
	}
	// A delete ignores the caveat it is given.
	if _, err := s.Write([]Update{{Op: OpDelete, Relationship: mustRel(t, "doc:a#viewer@user:x"), Caveat: &Caveat{Name: "nope!"}}}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCaveatValidation(t *testing.T) {
	s := caveatStore(t, "")
	big := strings.Repeat("x", MaxCaveatContextSize)
	for _, tc := range []struct {
		name, rel string
		c         *Caveat
		want      string
	}{
		{"undeclared caveat", "doc:a#viewer@user:x", &Caveat{Name: "nope"}, `caveat "nope" is not defined`},
		{"bad name", "doc:a#viewer@user:x", &Caveat{Name: "Bad"}, `caveat name "Bad" is not a valid name`},
		{"caveat the relation does not list", "doc:a#viewer@user:x", &Caveat{Name: "quota"}, "does not allow user with quota"},
		{"caveat on a plain-only type", "group:g#member@group:h#member", &Caveat{Name: "quota"}, "does not allow group#member with quota"},
		{"unknown parameter", "doc:a#viewer@user:x", &Caveat{Name: "ip_allowed", Context: map[string]any{"ip": "10.0.0.1"}}, `has no parameter "ip"`},
		{"wrong type", "doc:a#viewer@user:x", &Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": 7}}, "parameter allowed"},
		{"bad range", "doc:a#viewer@user:x", &Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": "10.0.0.0/99"}}, "parameter allowed"},
		{"not a whole number", "group:g#member@user:x", &Caveat{Name: "quota", Context: map[string]any{"limit": 1.5}}, "parameter limit"},
		{"too big", "doc:a#viewer@user:x", &Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": big}}, "bytes encoded (max 4096)"},
		{"not encodable", "doc:a#viewer@user:x", &Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": make(chan int)}}, "context: json: unsupported type"},
		{"plain on caveat-only", "doc:a#guest@user:x", nil, "does not allow user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Write([]Update{{Op: OpTouch, Relationship: mustRel(t, tc.rel), Caveat: tc.c}}, nil)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
	if s.Head() != 1 {
		t.Fatalf("a refused write committed: head %d", s.Head())
	}
	// CheckStored is the same rule for callers that own a schema.
	sc, _ := s.Schema()
	if err := CheckStored(sc, mustRel(t, "doc:a#guest@user:x"), &Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": "10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	if err := CheckStored(sc, mustRel(t, "doc:a#guest@user:x"), nil); err == nil {
		t.Fatal("CheckStored allowed a plain relationship on a caveat-only relation")
	}
}

func TestCaveatsAndSchemaChanges(t *testing.T) {
	s := caveatStore(t, "")
	touchCaveat(t, s, "doc:a#viewer@user:x", &Caveat{Name: "ip_allowed", Context: map[string]any{"allowed": "10.0.0.0/8"}})
	for name, src := range map[string]string{
		// The relation no longer lists user with ip_allowed.
		"type removed": strings.Replace(caveatRelSchema, "user | user with ip_allowed | user:* with ip_allowed", "user | user:* with ip_allowed", 1),
		// allowed becomes an int, which the stored context is not.
		"parameter retyped": strings.Replace(caveatRelSchema, "ip_allowed(allowed cidr, client_ip ipaddress) {\n  allowed.containsIP(client_ip)", "ip_allowed(allowed int, client_ip ipaddress) {\n  allowed > 0", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.WriteSchema(src); !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "doc:a#viewer@user:x") {
				t.Fatalf("WriteSchema: %v", err)
			}
			dry, err := s.DryRunSchema(src, 0)
			if err != nil || dry.BrokenCount != 1 || dry.Broken[0].Relationship.String() != "doc:a#viewer@user:x" {
				t.Fatalf("dry run %+v, %v", dry, err)
			}
		})
	}
	// A schema that still allows it, with the caveat rewritten, is fine.
	same := strings.Replace(caveatRelSchema, "allowed.containsIP(client_ip)", "client_ip.in_cidr(allowed)", 1)
	if _, err := s.WriteSchema(same); err != nil {
		t.Fatal(err)
	}
}

func TestCaveatRecovery(t *testing.T) {
	dir := t.TempDir()
	c := clock.NewFake(t0)
	s := clockStore(t, dir, c, 0)
	if _, err := s.WriteSchema(caveatRelSchema); err != nil {
		t.Fatal(err)
	}
	// A number too large for a float64 keeps every digit.
	quota := &Caveat{Name: "quota", Context: map[string]any{"limit": json.Number("9007199254740993")}}
	if _, err := s.Write([]Update{
		{Op: OpTouch, Relationship: mustRel(t, "group:g#member@user:x"), Caveat: quota},
		{Op: OpTouch, Relationship: mustRel(t, "doc:a#viewer@user:x"), Caveat: &Caveat{Name: "ip_allowed"}, ExpiresAt: t0.Add(time.Hour)},
		{Op: OpTouch, Relationship: mustRel(t, "doc:a#viewer@user:y")},
	}, nil); err != nil {
		t.Fatal(err)
	}
	head := s.Head()
	before := storedCaveats(t, s, head, "group", "g", "member")
	beforeDoc := storedCaveats(t, s, head, "doc", "a", "viewer")
	if !strings.Contains(before["group:g#member@user:x"], "9007199254740993") {
		t.Fatalf("stored %v", before)
	}
	s.Close()

	// From the write record, then from the checkpoint the restart wrote.
	for i := range 2 {
		s = clockStore(t, dir, c, 0)
		if got := storedCaveats(t, s, head, "group", "g", "member"); !reflect.DeepEqual(got, before) {
			t.Fatalf("restart %d: %v, want %v", i, got, before)
		}
		if got := storedCaveats(t, s, head, "doc", "a", "viewer"); !reflect.DeepEqual(got, beforeDoc) {
			t.Fatalf("restart %d: %v, want %v", i, got, beforeDoc)
		}
		st, _ := s.ReadDirectCaveated(head, "group", "g", "member")
		if n, ok := st[0].Caveat.Context["limit"].(json.Number); !ok || n != "9007199254740993" {
			t.Fatalf("restart %d: limit is %T %v", i, st[0].Caveat.Context["limit"], st[0].Caveat.Context["limit"])
		}
		// Touching with the same caveat after recovery is still no change.
		if r := touchCaveat(t, s, "group:g#member@user:x", quota); r != head {
			t.Fatalf("restart %d: touch after recovery made revision %d", i, r)
		}
		s.Close()
	}
	ck, err := os.ReadFile(filepath.Join(dir, walName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ck), `"caveated"`) || !strings.Contains(string(ck), `"limit":9007199254740993`) {
		t.Fatalf("checkpoint:\n%s", ck)
	}
	// The expiry and the caveat end together.
	c.Advance(2 * time.Hour)
	s = clockStore(t, dir, c, 0)
	r := touchCaveat(t, s, "doc:b#viewer@user:x", nil)
	if got := storedCaveats(t, s, r, "doc", "a", "viewer"); len(got) != 1 {
		t.Fatalf("after expiry %v", got)
	}
}

func TestBadCaveatRecordsAreRefused(t *testing.T) {
	x := Relationship{ResourceType: "doc", ResourceID: "a", Relation: "viewer", SubjectType: "user", SubjectID: "x"}
	for name, line := range map[string]walRecord{
		"caveated without caveat":     {Rev: 1, Type: recCheckpoint, Caveated: []caveatedRel{{Relationship: x}}},
		"caveated bad expiry":         {Rev: 1, Type: recCheckpoint, Caveated: []caveatedRel{{Relationship: x, ExpiresAt: -1, Caveat: &Caveat{Name: "c"}}}},
		"caveated bad relationship":   {Rev: 1, Type: recCheckpoint, Caveated: []caveatedRel{{Relationship: Relationship{ResourceType: "doc"}, Caveat: &Caveat{Name: "c"}}}},
		"caveated bad caveat name":    {Rev: 1, Type: recCheckpoint, Caveated: []caveatedRel{{Relationship: x, Caveat: &Caveat{Name: "C"}}}},
		"write with bad caveat name":  {Rev: 1, Type: recWrite, Changes: []Change{{Revision: 1, Op: OpTouch, Relationship: x, Caveat: &Caveat{Name: "C"}}}},
		"write with too big a caveat": {Rev: 1, Type: recWrite, Changes: []Change{{Revision: 1, Op: OpTouch, Relationship: x, Caveat: &Caveat{Name: "c", Context: map[string]any{"v": strings.Repeat("x", MaxCaveatContextSize)}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			b, err := encodeRecord(line)
			if err != nil {
				t.Fatal(err)
			}
			next, _ := encodeRecord(walRecord{Rev: 2, Type: recSchema, Schema: testSchema})
			if err := os.WriteFile(filepath.Join(dir, walName), append(b, next...), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(Options{Dir: dir}); err == nil {
				t.Fatal("opened a log with a bad record")
			}
		})
	}
}

func TestCaveatJSON(t *testing.T) {
	var c Caveat
	if err := json.Unmarshal([]byte(`{"name":"q","context":{"n":12345678901234567890,"l":[1.5]}}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.Context["n"] != json.Number("12345678901234567890") || c.Context["l"].([]any)[0] != json.Number("1.5") {
		t.Fatalf("decoded %#v", c)
	}
	for _, in := range []string{`{"name":"q","context":null}`, `{"name":"q","context":{}}`, `{"name":"q"}`} {
		var c Caveat
		if err := json.Unmarshal([]byte(in), &c); err != nil || c.Context != nil || c.Name != "q" {
			t.Fatalf("%s: %#v, %v", in, c, err)
		}
	}
	for _, in := range []string{`{"name":1}`, `{"name":"q","context":[1]}`, `[`} {
		var c Caveat
		if err := json.Unmarshal([]byte(in), &c); err == nil {
			t.Fatalf("%s decoded", in)
		}
	}
	if _, err := decodeContext([]byte(`{} {}`)); err == nil {
		t.Fatal("trailing data decoded")
	}
}
