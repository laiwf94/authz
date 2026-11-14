package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseFilter(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		in, want string
		since    time.Time
		until    time.Time
	}{
		{in: "", want: ""},
		{in: "  track=agents\tdecision=deny ", want: "track=agents decision=deny"},
		{in: "agent=a,b tool!=x rule=r*", want: "agent=a,b tool!=x rule=r*"},
		{in: `actor="a b,c"`, want: `actor="a b,c"`},
		{in: `actor="plain"`, want: `actor=plain`},
		{in: `subject="say \"hi\""`, want: `subject="say \"hi\""`},
		{in: "data.stage=started data.latency_ms!= decision=", want: "data.stage=started data.latency_ms!= decision="},
		{in: "event=authn.login_failed correlation=abc tenant=t1 action=login",
			want: "event=authn.login_failed correlation=abc tenant=t1 action=login"},
		{in: "since=2026-11-16", want: "since=2026-11-16T00:00:00Z", since: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)},
		{in: "until=-90m since=-24h", want: "since=2026-11-19T12:00:00Z until=2026-11-20T10:30:00Z",
			since: now.Add(-24 * time.Hour), until: now.Add(-90 * time.Minute)},
		{in: "since=2026-11-16T08:00:00.5+08:00", want: "since=2026-11-16T00:00:00.5Z",
			since: time.Date(2026, 11, 16, 0, 0, 0, 5e8, time.UTC)},
		{in: "track=auth* decision=d*", want: "track=auth* decision=d*"},
	} {
		f, err := ParseFilter(c.in, now)
		if err != nil {
			t.Errorf("ParseFilter(%q): %v", c.in, err)
			continue
		}
		if got := f.String(); got != c.want {
			t.Errorf("ParseFilter(%q).String() = %q, want %q", c.in, got, c.want)
		}
		if !f.Since.Equal(c.since) || !f.Until.Equal(c.until) {
			t.Errorf("ParseFilter(%q): since %v until %v", c.in, f.Since, f.Until)
		}
		// The text form reads back to the same filter.
		g, err := ParseFilter(f.String(), now)
		if err != nil || g.String() != f.String() {
			t.Errorf("round trip of %q: %v, %q", f.String(), err, g)
		}
	}
	for _, c := range []struct{ in, msg string }{
		{"track", "not KEY=VALUE"},
		{"=x", "not KEY=VALUE"},
		{"colour=red", "unknown key"},
		{"data.=x", "unknown key"},
		{"data.a b=x", "not KEY=VALUE"},
		{"track=billing", "not authz, authn, agents or audit"},
		{"decision=maybe", "not allow or deny"},
		{"since=yesterday", "not an RFC 3339 time"},
		{"since=-0s", "duration before now"},
		{"since=-1h,-2h", "one time"},
		{"since!=-1h", "one time"},
		{"since=-1h since=-2h", "given twice"},
		{"since=-1h until=-2h", "later than since"},
		{`actor="open`, "unterminated quote"},
		{`actor="a"b`, "not a valid quoted string"},
		{`actor="\x00"`, "without control characters"},
		{"actor=\xff", "UTF-8"},
		{`actor=a"b`, "unterminated quote"},
		{`actor=a"b"`, "quote the whole value"},
		{"actor=" + strings.Repeat("a", MaxFilterBytes), "longer than"},
		{strings.Repeat("actor=a ", maxFilterTerms+1), "more than"},
	} {
		_, err := ParseFilter(c.in, now)
		if err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("ParseFilter(%.40q) = %v, want an error with %q", c.in, err, c.msg)
		}
	}
	if _, err := ParseFilterTerms([]string{"actor=Ann Lee,Bob"}, now); err == nil || !strings.Contains(err.Error(), "must be the only one") {
		t.Errorf("a list with a spaced value: %v", err)
	}
	if _, err := ParseFilterTerms([]string{"actor=" + strings.Repeat("a", MaxFilterBytes)}, now); err == nil {
		t.Error("ParseFilterTerms took an over-long term")
	}
	// A term per argument may hold spaces without quotes.
	f, err := ParseFilterTerms([]string{"actor=Ann Lee", "tool=a,b"}, now)
	if err != nil || f.String() != `actor="Ann Lee" tool=a,b` {
		t.Errorf("ParseFilterTerms = %v, %v", f, err)
	}
}

func rec(t *testing.T, line string) *Record {
	t.Helper()
	var r Record
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

func TestFilterMatch(t *testing.T) {
	login := rec(t, `{"seq":1,"time":"2026-11-16T10:00:00Z","prev":"","event":"authn.login_succeeded","actor":"alice","subject":"app:wiki","action":"login","decision":"allow","correlation_id":"c1","data":{"provider":"google","session":"s1"}}`)
	check := rec(t, `{"seq":2,"time":"2026-11-16T10:00:01Z","prev":"","event":"authz.check_decided","tenant":"t1","subject":"doc:1","action":"view","decision":"deny","data":{"principal":"user:alice","revision":"r1"}}`)
	call := rec(t, `{"seq":3,"time":"2026-11-16T10:00:02.5Z","prev":"","event":"tool_call","data":{"agent":"alice-bot","auth":"static","tool":"read_file","decision":"deny","rule_id":"default-deny","constraint_rule_id":"read-workspace","stage":"refused","latency_ms":12,"truncated":false,"extra":{"a":1},"nothing":null}}`)
	plain := rec(t, `{"seq":4,"time":"2026-11-16T10:00:03Z","prev":"","event":"tool_call","data":{"agent":"bob-bot","auth":"key","tool":"write_file","decision":"allow","stage":"policy"}}`)
	approved := rec(t, `{"seq":5,"time":"2026-11-16T10:00:04Z","prev":"","event":"approval_decided","data":{"approval_id":"a1","decision":"approved","agent":"bob-bot","tool":"write_file","args_sha256":"x","expires_at":"y"}}`)
	denied := rec(t, `{"seq":6,"time":"2026-11-16T10:00:05Z","prev":"","event":"approval_decided","data":{"approval_id":"a2","decision":"denied","agent":"bob-bot","tool":"rm","args_sha256":"x","expires_at":"y"}}`)
	rotate := rec(t, `{"seq":7,"time":"2026-11-16T10:00:06Z","prev":"","event":"audit.segment_started","action":"audit.rotate","data":{"previous":"f.00000000000000000001","previous_first":1,"reason":"size"}}`)
	odd := rec(t, `{"seq":8,"time":"not a time","prev":"","event":"authz.future_event","data":{}}`)
	unknown := rec(t, `{"seq":9,"time":"2026-11-16T10:00:07Z","prev":"","event":"mystery","data":"not an object"}`)
	all := []*Record{login, check, call, plain, approved, denied, rotate, odd, unknown}
	now := time.Date(2026, 11, 16, 10, 0, 10, 0, time.UTC)
	for _, c := range []struct {
		filter string
		want   []uint64
	}{
		{"", []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9}},
		{"track=authn", []uint64{1}},
		{"track=authz", []uint64{2, 8}},
		{"track=agents", []uint64{3, 4, 5, 6}},
		{"track=audit", []uint64{7}},
		{"track=", []uint64{9}},
		{"track!=agents,authz", []uint64{1, 7, 9}},
		{"decision=deny", []uint64{2, 3, 6}},
		{"decision=allow", []uint64{1, 4, 5}},
		{"decision=", []uint64{7, 8, 9}},
		{"actor=alice-bot", []uint64{3}},
		{"actor=alice*", []uint64{1, 3}},
		{"agent=bob-bot", []uint64{4, 5, 6}},
		{"agent=", []uint64{1, 2, 7, 8, 9}},
		{"subject=tool:write_file", []uint64{4, 5}},
		{"subject=app:*,doc:*", []uint64{1, 2}},
		{"tool=read_file,rm", []uint64{3, 6}},
		{"action=tool_call", []uint64{3, 4}},
		{"action=login,view", []uint64{1, 2}},
		{"rule=read-workspace", []uint64{3}},
		{"rule=default-deny", []uint64{3}},
		{"rule!=read-workspace track=agents", []uint64{4, 5, 6}},
		{"rule= track=agents", []uint64{4, 5, 6}},
		{"event=approval_decided decision=deny", []uint64{6}},
		{"tenant=t1", []uint64{2}},
		{"correlation=c1", []uint64{1}},
		{"data.latency_ms=12", []uint64{3}},
		{"data.truncated=false", []uint64{3}},
		{"data.extra=", []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9}},
		{"data.nothing=", []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9}},
		{"data.provider=google", []uint64{1}},
		{"data.previous_first=1", []uint64{7}},
		{"since=2026-11-16T10:00:02.5Z", []uint64{3, 4, 5, 6, 7, 9}},
		{"until=2026-11-16T10:00:02.5Z", []uint64{1, 2}},
		{"since=-8s until=-5s", []uint64{3, 4, 5}},
		{"agent=bob-bot data.tool!=rm since=2026-11-16T10:00:03Z", []uint64{4, 5}},
	} {
		f, err := ParseFilter(c.filter, now)
		if err != nil {
			t.Fatalf("%q: %v", c.filter, err)
		}
		var got []uint64
		for _, r := range all {
			if f.Match(r, nil) {
				got = append(got, r.Seq)
			}
		}
		if !equalSeqs(got, c.want) {
			t.Errorf("%q matched %v, want %v", c.filter, got, c.want)
		}
	}
	var nilFilter *Filter
	if !nilFilter.Match(odd, nil) {
		t.Error("a nil filter does not match")
	}
	// An event type the schemas do not know belongs to its prefix's track.
	s, err := NewSchemas(Def{TrackAgents, ToolCall{}, 0})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := ParseFilter("track=authn", now)
	g, _ := ParseFilter("track=agents", now)
	if !f.Match(login, s) || !g.Match(call, s) || g.Match(approved, s) {
		t.Error("tracks from other schemas")
	}
	if TrackOf("approval_decided", s) != "" || TrackOf("authz.anything", s) != TrackAuthz || TrackOf("billing.x", nil) != "" {
		t.Error("TrackOf")
	}
}

func equalSeqs(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FuzzParseFilter checks that any filter that parses reads back from its
// text form to the same filter, and that matching never panics.
func FuzzParseFilter(f *testing.F) {
	for _, s := range []string{"", "track=agents decision=deny since=-24h", `actor="a b" tool=x,y*`,
		"data.n!= until=2026-11-16 since=2026-11-15T00:00:00Z", `subject="\x00"`, "rule!=r1,r2 event=tool_call"} {
		f.Add(s)
	}
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	r := &Record{Seq: 1, Time: "2026-11-16T00:00:00Z", Event: "tool_call", Data: []byte(`{"agent":"a","tool":"x","decision":"deny"}`)}
	f.Fuzz(func(t *testing.T, s string) {
		flt, err := ParseFilter(s, now)
		if err != nil {
			return
		}
		if len(flt.String()) > MaxFilterBytes {
			return // relative times grow; nothing else does
		}
		g, err := ParseFilter(flt.String(), now)
		if err != nil {
			t.Fatalf("%q: String() %q does not parse: %v", s, flt.String(), err)
		}
		if g.String() != flt.String() || !g.Since.Equal(flt.Since) || !g.Until.Equal(flt.Until) || g.Match(r, nil) != flt.Match(r, nil) {
			t.Fatalf("%q: %q reads back as %q", s, flt.String(), g.String())
		}
	})
}

// FuzzParseIndex checks that an index that parses is in its one canonical
// form.
func FuzzParseIndex(f *testing.F) {
	h := strings.Repeat("ab", 32)
	f.Add([]byte(indexMagic + "\nsegment a.00000000000000000002 first 2 records 3 size 900\nstart " + h +
		" previous a.00000000000000000001\nhead " + h + "\ntime 2026-11-16T00:00:00Z 2026-11-16T00:00:02Z\nentry 3 400 " + h + " 2026-11-16T00:00:00Z\n"))
	f.Add([]byte(indexMagic + "\nsegment a.00000000000000000001 first 1 records 1 size 9\nstart " + Genesis + " previous -\nhead " + h + "\ntime - -\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ix, err := parseIndex(b)
		if err != nil {
			return
		}
		if out := ix.marshal(); !bytes.Equal(out, b) {
			t.Fatalf("%q parses but marshals as %q", b, out)
		}
	})
}

// The records authz mcp writes for a request carry an envelope with only
// the correlation ID; their actor, subject, action and decision still come
// from the payload (#241). An envelope field that is set wins.
func TestFilterMatchCorrelatedAgentRecords(t *testing.T) {
	call := rec(t, `{"seq":1,"time":"2026-11-16T10:00:00Z","prev":"","event":"tool_call","correlation_id":"c1","data":{"agent":"report-bot","auth":"static","tool":"http_get","decision":"deny","rule_id":"default-deny","stage":"refused"}}`)
	denied := rec(t, `{"seq":2,"time":"2026-11-16T10:00:01Z","prev":"","event":"approval_decided","correlation_id":"c2","data":{"approval_id":"a1","decision":"denied","agent":"bob-bot","tool":"rm","args_sha256":"x","expires_at":"y"}}`)
	set := rec(t, `{"seq":3,"time":"2026-11-16T10:00:02Z","prev":"","event":"tool_call","actor":"svc","subject":"tool:other","action":"call","decision":"allow","correlation_id":"c3","data":{"agent":"report-bot","auth":"static","tool":"read_file","decision":"deny","stage":"policy"}}`)
	all := []*Record{call, denied, set}
	for _, c := range []struct {
		filter string
		want   []uint64
	}{
		{"decision=deny", []uint64{1, 2}},
		{"decision=allow", []uint64{3}},
		{"actor=report-bot", []uint64{1}},
		{"actor=svc,bob-bot", []uint64{2, 3}},
		{"subject=tool:http_get,tool:rm", []uint64{1, 2}},
		{"subject=tool:other", []uint64{3}},
		{"action=tool_call", []uint64{1}},
		{"action=approval_decided", []uint64{2}},
		{"agent=report-bot tool=http_get decision=deny rule=default-deny correlation=c1", []uint64{1}},
	} {
		f, err := ParseFilter(c.filter, time.Time{})
		if err != nil {
			t.Fatalf("%q: %v", c.filter, err)
		}
		var got []uint64
		for _, r := range all {
			if f.Match(r, nil) {
				got = append(got, r.Seq)
			}
		}
		if !equalSeqs(got, c.want) {
			t.Errorf("%q matched %v, want %v", c.filter, got, c.want)
		}
	}
}
