package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/ratelimit"
)

func zone(t testing.TB, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func mustWindow(t testing.TB, fw fileWindow) window {
	t.Helper()
	w, err := compileWindow(0, fw)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// minutesInside counts the minutes of the local calendar day of date in loc
// (from its midnight to the next) that w contains.
func minutesInside(w window, loc *time.Location, y int, m time.Month, d int) int {
	start := time.Date(y, m, d, 0, 0, 0, 0, loc)
	end := ratelimit.EndOfDay(start, loc)
	n := 0
	for t := start; t.Before(end); t = t.Add(time.Minute) {
		if w.contains(t) {
			n++
		}
	}
	return n
}

// Windows are wall-clock times in their zone. On the days the clocks
// change, a window over the skipped hour shrinks (or never opens) and one
// over the repeated hour grows, in both hemispheres.
func TestWindowsAcrossDSTInThreeZones(t *testing.T) {
	for _, c := range []struct {
		zone     string
		y        int
		m        time.Month
		d        int
		from, to string
		minutes  int
	}{
		// New York: 02:00 becomes 03:00 on 8 March, 02:00 becomes 01:00 on 1 November.
		{"America/New_York", 2026, 3, 8, "02:00", "02:30", 0},
		{"America/New_York", 2026, 3, 8, "01:00", "04:00", 120},
		{"America/New_York", 2026, 3, 7, "01:00", "04:00", 180},
		{"America/New_York", 2026, 11, 1, "01:00", "02:00", 120},
		{"America/New_York", 2026, 11, 1, "09:00", "17:00", 480},
		// Berlin: 02:00 becomes 03:00 on 29 March, 03:00 becomes 02:00 on 25 October.
		{"Europe/Berlin", 2026, 3, 29, "02:00", "03:00", 0},
		{"Europe/Berlin", 2026, 3, 29, "00:00", "24:00", 23 * 60},
		{"Europe/Berlin", 2026, 10, 25, "02:00", "03:00", 120},
		{"Europe/Berlin", 2026, 10, 25, "00:00", "24:00", 25 * 60},
		// Sydney: 02:00 becomes 03:00 on 4 October, 03:00 becomes 02:00 on 5 April.
		{"Australia/Sydney", 2026, 10, 4, "02:00", "03:00", 0},
		{"Australia/Sydney", 2026, 10, 4, "01:30", "03:30", 60},
		{"Australia/Sydney", 2026, 4, 5, "02:00", "03:00", 120},
		{"Australia/Sydney", 2026, 4, 5, "22:00", "24:00", 120},
	} {
		loc := zone(t, c.zone)
		fw := fileWindow{Zone: c.zone, From: c.from, To: c.to}
		if c.from == "00:00" && c.to == "24:00" {
			// All day needs a day; the day in question is a Sunday.
			fw.Days = []string{dayNames[time.Date(c.y, c.m, c.d, 12, 0, 0, 0, loc).Weekday()]}
		}
		w := mustWindow(t, fw)
		if got := minutesInside(w, loc, c.y, c.m, c.d); got != c.minutes {
			t.Errorf("%s %d-%02d-%02d %s-%s: open %d minutes, want %d", c.zone, c.y, c.m, c.d, c.from, c.to, got, c.minutes)
		}
	}
}

// The same UTC instant is inside or outside a local window depending on the
// zone's offset that day, and the day of the week is the zone's.
func TestWindowsAtFixedInstants(t *testing.T) {
	office := func(zone string) window {
		return mustWindow(t, fileWindow{Zone: zone, Days: []string{"mon", "tue", "wed", "thu", "fri"}, From: "09:00", To: "17:00"})
	}
	berlin, ny, sydney := office("Europe/Berlin"), office("America/New_York"), office("Australia/Sydney")
	for _, c := range []struct {
		w    window
		at   string
		want bool
	}{
		// Berlin is UTC+1 until 29 March and UTC+2 after.
		{berlin, "2026-03-27T15:30:00Z", true},  // Fri 16:30 CET
		{berlin, "2026-03-30T15:30:00Z", false}, // Mon 17:30 CEST
		{berlin, "2026-03-30T07:30:00Z", true},  // Mon 09:30 CEST
		{berlin, "2026-03-27T07:30:00Z", false}, // Fri 08:30 CET
		{berlin, "2026-03-28T10:00:00Z", false}, // Saturday
		// New York is UTC-5 from 1 November.
		{ny, "2026-10-30T20:30:00Z", true},  // Fri 16:30 EDT
		{ny, "2026-11-02T20:30:00Z", true},  // Mon 15:30 EST
		{ny, "2026-11-02T22:00:00Z", false}, // Mon 17:00 EST: the end is excluded
		{ny, "2026-11-02T14:00:00Z", true},  // Mon 09:00 EST: the start is included
		{ny, "2026-11-02T13:59:59Z", false},
		// Sunday 22:30 UTC is Monday 09:30 in Sydney (UTC+11 in summer).
		{sydney, "2026-11-08T22:30:00Z", true},
		{sydney, "2026-11-09T22:30:00Z", true},
		{sydney, "2026-11-13T22:30:00Z", false}, // Saturday in Sydney
		// In winter Sydney is UTC+10: 22:30 UTC is 08:30, before the window.
		{sydney, "2026-06-07T22:30:00Z", false},
	} {
		at, err := time.Parse(time.RFC3339, c.at)
		if err != nil {
			t.Fatal(err)
		}
		if got := c.w.contains(at); got != c.want {
			t.Errorf("%s at %s (%s): %v, want %v", c.w.text, c.at, at.In(c.w.loc).Format("Mon 15:04 MST"), got, c.want)
		}
	}
}

func TestOvernightWindows(t *testing.T) {
	loc := zone(t, "Europe/Berlin")
	w := mustWindow(t, fileWindow{Zone: "Europe/Berlin", Days: []string{"sat"}, From: "22:00", To: "06:00"})
	at := func(m time.Month, d, h, min int) time.Time { return time.Date(2026, m, d, h, min, 0, 0, loc) }
	for _, c := range []struct {
		t    time.Time
		want bool
	}{
		{at(10, 17, 21, 59), false}, // Saturday before
		{at(10, 17, 22, 0), true},
		{at(10, 18, 5, 59), true}, // Sunday morning, after a Saturday start
		{at(10, 18, 6, 0), false},
		{at(10, 18, 22, 30), false}, // Sunday night: the window starts on Saturdays only
		{at(10, 19, 1, 0), false},   // Monday morning
		{at(10, 16, 23, 0), false},  // Friday night
	} {
		if got := w.contains(c.t); got != c.want {
			t.Errorf("%s: %v, want %v", c.t.Format("Mon 15:04"), got, c.want)
		}
	}
	// The night the clocks go back is an hour longer: Saturday 24 October
	// 22:00 to Sunday 06:00 is nine hours.
	n := 0
	for tt := at(10, 24, 20, 0); tt.Before(at(10, 25, 8, 0)); tt = tt.Add(time.Minute) {
		if w.contains(tt) {
			n++
		}
	}
	if n != 9*60 {
		t.Errorf("overnight across the change: %d minutes, want %d", n, 9*60)
	}
}

func TestWindowErrors(t *testing.T) {
	for _, c := range []struct {
		w    fileWindow
		want string
	}{
		{fileWindow{From: "09:00", To: "17:00"}, "zone: name an IANA time zone"},
		{fileWindow{Zone: "Local", From: "09:00", To: "17:00"}, "name an IANA"},
		{fileWindow{Zone: "Mars/Olympus", From: "09:00", To: "17:00"}, `unknown time zone "Mars/Olympus"`},
		{fileWindow{Zone: "UTC", From: "9:00", To: "17:00"}, `from: "9:00" must be HH:MM`},
		{fileWindow{Zone: "UTC", From: "09:60", To: "17:00"}, "must be HH:MM from 00:00"},
		{fileWindow{Zone: "UTC", From: "24:00", To: "17:00"}, "or 24:00 as an end"},
		{fileWindow{Zone: "UTC", From: "09:00", To: "24:01"}, "to:"},
		{fileWindow{Zone: "UTC", From: "+1:00", To: "17:00"}, "must be HH:MM"},
		{fileWindow{Zone: "UTC", From: "09:00", To: "09:00"}, "must differ"},
		{fileWindow{Zone: "UTC", From: "00:00", To: "24:00"}, "no condition"},
		{fileWindow{Zone: "UTC", Days: []string{"Mon"}, From: "09:00", To: "17:00"}, `"Mon" is not one of sun, mon`},
		{fileWindow{Zone: "UTC", Days: []string{"mon", "mon"}, From: "09:00", To: "17:00"}, "listed twice"},
	} {
		if _, err := compileWindow(0, c.w); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.w, err, c.want)
		}
	}
	// All day on some days is a condition.
	if _, err := compileWindow(0, fileWindow{Zone: "UTC", Days: []string{"sat", "sun"}, From: "00:00", To: "24:00"}); err != nil {
		t.Error(err)
	}
}

const windowPolicy = `{"version":1,"rules":[
 {"id":"no-deploy-friday-night","effect":"deny","agents":["*"],"upstreams":["ops"],"tools":["deploy"],
  "windows":[{"zone":"America/New_York","days":["fri"],"from":"16:00","to":"24:00"}]},
 {"id":"deploy-office-hours","effect":"allow","agents":["ci-bot"],"upstreams":["ops"],"tools":["deploy"],
  "windows":[{"zone":"Europe/Berlin","days":["mon","tue","wed","thu","fri"],"from":"09:00","to":"12:00"},
             {"zone":"Europe/Berlin","days":["mon","tue","wed","thu","fri"],"from":"13:00","to":"17:00"}]},
 {"id":"deploy-staging","effect":"allow","agents":["ci-bot"],"upstreams":["ops"],"tools":["deploy"],
  "when":"has(args.env) && args.env == 'staging'"}
]}`

func at(t testing.TB, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDecideWithWindows(t *testing.T) {
	p := mustParse(t, windowPolicy)
	ci := Subject{AgentID: "ci-bot"}
	ctx := context.Background()
	prod := map[string]any{"env": "prod"}
	for _, c := range []struct {
		now        string
		args       map[string]any
		allowed    bool
		rule       string
		constraint string
		reason     string
	}{
		{"2026-12-01T10:00:00+01:00", prod, true, "deploy-office-hours", "", ""},
		{"2026-12-01T12:30:00+01:00", prod, false, DefaultDenyID, "deploy-office-hours",
			"rule deploy-office-hours applies only mon,tue,wed,thu,fri 09:00-12:00 Europe/Berlin; mon,tue,wed,thu,fri 13:00-17:00 Europe/Berlin"},
		{"2026-12-01T12:30:00+01:00", map[string]any{"env": "staging"}, true, "deploy-staging", "", ""},
		{"2026-12-05T10:00:00+01:00", prod, false, DefaultDenyID, "deploy-office-hours", "applies only"},
		// Friday 16:30 in Berlin is 10:30 in New York; Friday 22:30 in Berlin
		// is 16:30 there, inside the deny window, which beats every allow.
		{"2026-12-04T16:30:00+01:00", prod, true, "deploy-office-hours", "", ""},
		{"2026-12-04T22:30:00+01:00", map[string]any{"env": "staging"}, false, "no-deploy-friday-night", "", "forbids"},
	} {
		d := p.DecideAt(ctx, at(t, c.now), ci, "ops", "deploy", c.args, nil)
		if d.Allowed != c.allowed || d.RuleID != c.rule || d.ConstraintRuleID != c.constraint || !strings.Contains(d.Reason, c.reason) {
			t.Errorf("%s %v: %+v", c.now, c.args, d)
		}
	}
	// An unknown time does not open an allow rule's window, and closes the
	// deny rule's (fail closed).
	d := p.DecideAt(ctx, time.Time{}, ci, "ops", "deploy", prod, nil)
	if d.Allowed || d.RuleID != "no-deploy-friday-night" || !strings.Contains(d.Reason, "time of the call is unknown") {
		t.Errorf("unknown time: %+v", d)
	}
	// Visible: a deny rule with a window does not hide the tool.
	if !p.Visible(ci, "ops", "deploy") {
		t.Error("deploy hidden by a windowed deny rule")
	}
	// Decide uses the current time; the allow rules are reached or not, but
	// the decision names one of the policy's rules.
	if d := p.Decide(ctx, ci, "ops", "deploy", map[string]any{"env": "staging"}, nil); d.RuleID == "" {
		t.Errorf("Decide: %+v", d)
	}
}

const whenPolicy = `{"version":1,"rules":[
 {"id":"no-prod-unsigned","effect":"deny","agents":["*"],"upstreams":["ops"],"tools":["*"],
  "when":"args.env == 'prod' && session.auth != 'signed'"},
 {"id":"small-batches","effect":"allow","agents":["*"],"upstreams":["ops"],"tools":["deploy"],
  "when":"int(args.count) <= 10 && 'ops:deploy' in scopes && owner.startsWith('team-')"},
 {"id":"berlin-mornings","effect":"allow","agents":["*"],"upstreams":["ops"],"tools":["report"],
  "when":"now.getHours('Europe/Berlin') < 12 && tool == 'report' && upstream == 'ops' && agent != 'blocked'"},
 {"id":"old-protocol","effect":"deny","agents":["*"],"upstreams":["ops"],"tools":["*"],
  "when":"session.protocol < '2025-03-26'"}
]}`

func TestDecideWithWhen(t *testing.T) {
	p := mustParse(t, whenPolicy)
	ctx := context.Background()
	signed := Session{Auth: "signed", Protocol: "2025-06-18"}
	static := Session{Auth: "static", Protocol: "2025-06-18"}
	team := Subject{AgentID: "a1", Owner: "team-ops", Scopes: []string{"ops:deploy"}, Session: signed}
	now := at(t, "2026-12-01T09:00:00Z")
	for _, c := range []struct {
		name    string
		s       Subject
		tool    string
		args    any
		allowed bool
		rule    string
		reason  string
	}{
		{"signed prod", team, "deploy", map[string]any{"env": "prod", "count": 3}, true, "small-batches", ""},
		{"static prod", Subject{AgentID: "a1", Owner: "team-ops", Scopes: []string{"ops:deploy"}, Session: static},
			"deploy", map[string]any{"env": "prod", "count": 3}, false, "no-prod-unsigned", "forbids"},
		{"too many", team, "deploy", map[string]any{"env": "prod", "count": 11}, false, DefaultDenyID, "condition of rule small-batches is false"},
		{"no scope", Subject{AgentID: "a1", Owner: "team-ops", Session: signed}, "deploy",
			map[string]any{"env": "dev", "count": 1}, false, DefaultDenyID, "is false"},
		// A missing argument is a runtime error: the deny rule fails closed,
		// unless the other side of && decides it (CEL's commutative &&).
		{"no env, signed", team, "deploy", map[string]any{"count": 1}, true, "small-batches", ""},
		{"no env", Subject{AgentID: "a1", Owner: "team-ops", Scopes: []string{"ops:deploy"}, Session: static}, "deploy", map[string]any{"count": 1}, false, "no-prod-unsigned", "forbids this call: condition of rule no-prod-unsigned failed"},
		// json.Number arguments, as the gateway decodes them.
		{"number", team, "deploy", map[string]any{"env": "dev", "count": jsonNumber("4")}, true, "small-batches", ""},
		{"not a number", team, "deploy", map[string]any{"env": "dev", "count": "lots"}, false, DefaultDenyID, "condition of rule small-batches failed"},
		{"report", team, "report", map[string]any{"env": "dev"}, true, "berlin-mornings", ""},
		{"blocked", Subject{AgentID: "blocked", Session: signed}, "report", map[string]any{"env": "dev"}, false, DefaultDenyID, "berlin-mornings"},
		{"old protocol", Subject{AgentID: "a1", Session: Session{Auth: "signed", Protocol: "2024-11-05"}},
			"report", map[string]any{"env": "dev"}, false, "old-protocol", "forbids"},
	} {
		d := p.DecideAt(ctx, now, c.s, "ops", c.tool, c.args, nil)
		if d.Allowed != c.allowed || d.RuleID != c.rule || !strings.Contains(d.Reason, c.reason) {
			t.Errorf("%s: %+v", c.name, d)
		}
	}
	// now.getHours in a zone follows its offset on either side of the
	// change: 10:30 UTC is 11:30 in Berlin in winter and 12:30 in summer.
	rep := map[string]any{"env": "dev"}
	if d := p.DecideAt(ctx, at(t, "2026-03-28T10:30:00Z"), team, "ops", "report", rep, nil); !d.Allowed {
		t.Errorf("winter: %+v", d)
	}
	if d := p.DecideAt(ctx, at(t, "2026-03-29T10:30:00Z"), team, "ops", "report", rep, nil); d.Allowed {
		t.Errorf("summer: %+v", d)
	}
	// Without a time, an expression that reads now is unknown.
	d := p.DecideAt(ctx, time.Time{}, team, "ops", "report", rep, nil)
	if d.Allowed || d.ConstraintRuleID != "berlin-mornings" || !strings.Contains(d.Reason, "needs now") {
		t.Errorf("unknown time: %+v", d)
	}
	// nil arguments are an empty object, and nil scopes an empty list.
	if d := p.DecideAt(ctx, now, Subject{AgentID: "x", Session: signed}, "ops", "report", nil, nil); !d.Allowed {
		t.Errorf("no arguments: %+v", d)
	}
}

func TestConditionsSpareTheEngine(t *testing.T) {
	p := mustParse(t, `{"version":1,"rules":[
	 {"id":"edit","effect":"allow","agents":["*"],"upstreams":["fs"],"tools":["write_file"],
	  "when":"args.project != 'frozen'","check":{"resource":"project:{args.project}","permission":"edit"}}]}`)
	f := fakeEngine(t, "project:frozen#editor@user:alice", "project:p1#editor@user:alice")
	alice := Subject{AgentID: "alice-bot", Owner: "alice"}
	d := p.DecideAt(context.Background(), time.Now(), alice, "fs", "write_file", map[string]any{"project": "frozen"}, f.get)
	if d.Allowed || f.checks.Load() != 0 || f.gets.Load() != 0 || len(d.Checks) != 0 {
		t.Fatalf("a false condition asked the engine: %+v (%d checks)", d, f.checks.Load())
	}
	d = p.DecideAt(context.Background(), time.Now(), alice, "fs", "write_file", map[string]any{"project": "p1"}, f.get)
	if !d.Allowed || f.checks.Load() != 1 {
		t.Fatalf("p1: %+v (%d checks)", d, f.checks.Load())
	}
}

func TestWhenErrors(t *testing.T) {
	rule := func(extra string) string {
		return `{"version":1,"rules":[{"id":"r","effect":"allow","agents":["*"],"upstreams":["u"],"tools":["t"],` + extra + `}]}`
	}
	for _, c := range []struct{ src, want string }{
		{rule(`"when":"args.n + 1"`), "when:"},
		{rule(`"when":"nobody == 1"`), "nobody"},
		{rule(`"when":"("`), "when:"},
		{rule(`"when":""`), "when:"},
		{rule(`"when":"session.auth == 1"`), "when:"},
		{rule(`"when":"` + strings.Repeat("(", 200) + `true` + strings.Repeat(")", 200) + `"`), "when:"},
		{rule(`"windows":[]` + `,"when":"true","limits":{}`), "limits must set rate, daily or both"},
		{rule(`"windows":[` + strings.Repeat(`{"zone":"UTC","from":"01:00","to":"02:00"},`, MaxWindows) + `{"zone":"UTC","from":"01:00","to":"02:00"}]`), "at most 16 windows"},
		{rule(`"windows":[{"zone":"UTC","from":"01:00","to":"01:00"}]`), "rule 0 (\"r\"): windows[0]: from and to must differ"},
		{rule(`"windows":[{"zone":"UTC","from":"01:00","to":"02:00","extra":1}]`), "unknown field"},
	} {
		if _, err := Parse([]byte(c.src)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.src, err, c.want)
		}
	}
	// A when expression whose evaluation goes over the cost limit fails, and
	// an allow rule then does not apply.
	p := mustParse(t, rule(`"when":"args.xs.all(x, args.xs.all(y, args.xs.all(z, true)))"`))
	xs := make([]any, 100)
	for i := range xs {
		xs[i] = i
	}
	d := p.DecideAt(context.Background(), time.Now(), Subject{AgentID: "a"}, "u", "t", map[string]any{"xs": xs}, nil)
	if d.Allowed || !strings.Contains(d.Reason, "cost limit") {
		t.Errorf("costly: %+v", d)
	}
}

func TestLimitsParseAndKeys(t *testing.T) {
	rule := func(id, limits string) string {
		return `{"version":1,"rules":[{"id":"` + id + `","effect":"allow","agents":["*"],"upstreams":["u"],"tools":["t"],"limits":` + limits + `},
		 {"id":"other","effect":"allow","agents":["*"],"upstreams":["v"],"tools":["t"]}]}`
	}
	lim := func(src string) *Limits {
		t.Helper()
		d := mustParse(t, src).Evaluate(Subject{AgentID: "a"}, "u", "t", nil)
		if !d.Allowed || d.Limits == nil {
			t.Fatalf("%s: %+v", src, d)
		}
		return d.Limits
	}
	a := lim(rule("r", `{"rate":2,"burst":5,"daily":100,"zone":"Europe/Berlin"}`))
	if a.Rate != (ratelimit.Limit{Rate: 2, Burst: 5}) || a.Daily != 100 || a.Zone.String() != "Europe/Berlin" ||
		a.String() != "2/s burst 5, 100 a day (Europe/Berlin)" {
		t.Fatalf("limits %+v %q", a, a.String())
	}
	// The same rule id and limits give the same key in another document;
	// other limits, another id or another agent give another.
	same := lim(`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["x","a"],"upstreams":["u","w"],"tools":["t","t2"],
		"limits":{"daily":100,"rate":2,"zone":"Europe/Berlin","burst":5}}]}`)
	if same.Key("a") != a.Key("a") {
		t.Error("unchanged limits changed key")
	}
	for _, other := range []*Limits{
		lim(rule("r", `{"rate":2,"burst":5,"daily":101,"zone":"Europe/Berlin"}`)),
		lim(rule("r", `{"rate":2,"burst":5,"daily":100,"zone":"UTC"}`)),
		lim(rule("r", `{"rate":2,"burst":4,"daily":100,"zone":"Europe/Berlin"}`)),
		lim(rule("r", `{"rate":2.5,"burst":5,"daily":100,"zone":"Europe/Berlin"}`)),
		lim(rule("r2", `{"rate":2,"burst":5,"daily":100,"zone":"Europe/Berlin"}`)),
	} {
		if other.Key("a") == a.Key("a") {
			t.Errorf("%+v shares a key with %+v", other, a)
		}
	}
	if a.Key("a") == a.Key("b") {
		t.Error("agents share a key")
	}
	if d := lim(rule("r", `{"daily":3}`)); !d.Rate.Unlimited() || d.Zone != time.UTC || d.String() != "3 a day (UTC)" {
		t.Errorf("daily only: %+v %q", d, d.String())
	}
	if d := lim(rule("r", `{"rate":0.5}`)); d.Rate.Burst != 1 || d.Daily != 0 || d.String() != "0.5/s burst 1" {
		t.Errorf("rate only: %+v %q", d, d.String())
	}
	if d := mustParse(t, rule("r", `{"rate":1}`)).Evaluate(Subject{AgentID: "a"}, "v", "t", nil); d.Limits != nil {
		t.Errorf("a rule without limits: %+v", d.Limits)
	}

	for _, c := range []struct{ limits, want string }{
		{`{}`, "must set rate, daily or both"},
		{`{"rate":-1}`, "limits.rate must be from 0"},
		{`{"rate":2e6}`, "limits.rate"},
		{`{"rate":1,"burst":-1}`, "limits.burst"},
		{`{"rate":1,"burst":2000000}`, "limits.burst"},
		{`{"burst":3}`, "limits.burst needs limits.rate"},
		{`{"daily":-1}`, "limits.daily"},
		{`{"daily":2000000000}`, "limits.daily"},
		{`{"rate":1,"zone":"UTC"}`, "limits.zone applies only with limits.daily"},
		{`{"daily":1,"zone":"Nowhere/Land"}`, "unknown time zone"},
		{`{"daily":1,"per":"hour"}`, "unknown field"},
	} {
		if _, err := Parse([]byte(rule("r", c.limits))); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.limits, err, c.want)
		}
	}
	deny := `{"version":1,"rules":[{"id":"r","effect":"deny","agents":["*"],"upstreams":["u"],"tools":["t"],"limits":{"rate":1}}]}`
	if _, err := Parse([]byte(deny)); err == nil || !strings.Contains(err.Error(), "limits apply only to allow rules") {
		t.Errorf("deny rule with limits: %v", err)
	}
}

func TestCasesWithTimeAndSession(t *testing.T) {
	p := mustParse(t, windowPolicy)
	pw := mustParse(t, whenPolicy)
	cs := mustCases(t, casesDoc(
		`{"name":"office hours","subject":{"agent":"ci-bot"},"now":"2026-12-01T10:00:00+01:00",
		  "call":{"tool":"ops.deploy","arguments":{"env":"prod"}},"expect":{"decision":"allow","rule":"deploy-office-hours"}}`,
		`{"name":"lunch","subject":{"agent":"ci-bot"},"now":"2026-12-01T11:30:00Z",
		  "call":{"tool":"ops.deploy","arguments":{"env":"prod"}},
		  "expect":{"decision":"deny","rule":"default-deny","constraint_rule":"deploy-office-hours","reason_contains":"applies only"}}`,
		`{"name":"no time","subject":{"agent":"ci-bot"},
		  "call":{"tool":"ops.deploy","arguments":{"env":"staging"}},"expect":{"decision":"deny","rule":"no-deploy-friday-night"}}`,
	))
	if rep := RunCases(p, cs); rep.Failed != 0 {
		var b bytes.Buffer
		rep.WriteText(&b, false)
		t.Fatal(b.String())
	}
	cs = mustCases(t, casesDoc(
		`{"name":"signed","subject":{"agent":"a1","owner":"team-x","scopes":["ops:deploy"],"session":{"auth":"signed","protocol":"2025-06-18"}},
		  "call":{"tool":"ops.deploy","arguments":{"env":"prod","count":2}},"expect":{"decision":"allow","rule":"small-batches"}}`,
		`{"name":"static","subject":{"agent":"a1","owner":"team-x","scopes":["ops:deploy"],"session":{"auth":"static","key_id":"k1","issuer":"","protocol":"2025-06-18"}},
		  "call":{"tool":"ops.deploy","arguments":{"env":"prod","count":2}},"expect":{"decision":"deny","rule":"no-prod-unsigned"}}`,
		`{"name":"big","subject":{"agent":"a1","owner":"team-x","scopes":["ops:deploy"],"session":{"auth":"signed","protocol":"2025-06-18"}},
		  "call":{"tool":"ops.deploy","arguments":{"env":"prod","count":20}},"expect":{"decision":"allow"}}`,
	))
	rep := RunCases(pw, cs)
	if rep.Failed != 1 || !strings.Contains(rep.Results[2].Got, "(conditions of small-batches not met)") {
		t.Fatalf("%+v", rep)
	}
	for _, c := range []struct{ src, want string }{
		{`{"name":"c","subject":{"agent":"a"},"now":"yesterday","call":{"tool":"u.t"},"expect":{"decision":"deny"}}`, "must be an RFC 3339 time"},
		{`{"name":"c","subject":{"agent":"a"},"now":"0001-01-01T00:00:00Z","call":{"tool":"u.t"},"expect":{"decision":"deny"}}`, "must be an RFC 3339 time"},
		{`{"name":"c","subject":{"agent":"a"},"now":"2026-12-01T10:00:00Z","list":["u.t"],"expect":{"visible":[]}}`, `"now" applies only to call cases`},
		{`{"name":"c","subject":{"agent":"a","session":{"auth":"a\u0001"}},"call":{"tool":"u.t"},"expect":{"decision":"deny"}}`, "session values"},
		{`{"name":"c","subject":{"agent":"a","session":{"method":"x"}},"call":{"tool":"u.t"},"expect":{"decision":"deny"}}`, "unknown field"},
	} {
		if _, err := ParseCases([]byte(casesDoc(c.src))); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.src, err, c.want)
		}
	}
}

func BenchmarkDecideWithConditions(b *testing.B) {
	p := mustParse(b, whenPolicy)
	pw := mustParse(b, windowPolicy)
	s := Subject{AgentID: "a1", Owner: "team-ops", Scopes: []string{"ops:deploy"}, Session: Session{Auth: "signed", Protocol: "2025-06-18"}}
	now := at(b, "2026-12-01T10:00:00+01:00")
	args := map[string]any{"env": "prod", "count": 3}
	ctx := context.Background()
	b.Run("when", func(b *testing.B) {
		for b.Loop() {
			if !p.DecideAt(ctx, now, s, "ops", "deploy", args, nil).Allowed {
				b.Fatal("denied")
			}
		}
	})
	b.Run("windows", func(b *testing.B) {
		ci := Subject{AgentID: "ci-bot"}
		for b.Loop() {
			if !pw.DecideAt(ctx, now, ci, "ops", "deploy", args, nil).Allowed {
				b.Fatal("denied")
			}
		}
	})
}

func jsonNumber(s string) json.Number { return json.Number(s) }

// FuzzConditions decides calls under random windows and when expressions at
// random times: compiling either never panics, and an evaluation always
// names a rule, with an allow only from a rule whose conditions hold.
func FuzzConditions(f *testing.F) {
	f.Add("Europe/Berlin", "mon", "09:00", "17:00", "args.n < 3 && session.auth == 'signed'", int64(1796112000), int64(2))
	f.Add("America/New_York", "sun", "22:00", "02:00", "now.getHours('Australia/Sydney') > 6", int64(1793512800), int64(-1))
	f.Add("UTC", "", "00:00", "24:00", "has(args.n) || scopes.exists(s, s == 'x')", int64(0), int64(0))
	f.Fuzz(func(t *testing.T, zone, day, from, to, when string, unix, n int64) {
		w := fileWindow{Zone: zone, From: from, To: to}
		if day != "" {
			w.Days = []string{day}
		}
		wb, _ := json.Marshal([]fileWindow{w})
		eb, _ := json.Marshal(when)
		for _, src := range []string{
			`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["*"],"upstreams":["u"],"tools":["t"],"windows":` + string(wb) + `}]}`,
			`{"version":1,"rules":[{"id":"r","effect":"allow","agents":["*"],"upstreams":["u"],"tools":["t"],"when":` + string(eb) + `}]}`,
			`{"version":1,"rules":[{"id":"d","effect":"deny","agents":["*"],"upstreams":["u"],"tools":["t"],"when":` + string(eb) + `,"windows":` + string(wb) + `},
			 {"id":"r","effect":"allow","agents":["*"],"upstreams":["u"],"tools":["t"]}]}`,
		} {
			p, err := Parse([]byte(src))
			if err != nil {
				continue
			}
			now := time.Unix(unix%(1<<40), 0)
			s := Subject{AgentID: "a", Scopes: []string{"x"}, Session: Session{Auth: "signed"}}
			for _, at := range []time.Time{now, {}} {
				d := p.DecideAt(context.Background(), at, s, "u", "t", map[string]any{"n": n}, nil)
				if d.RuleID == "" || d.Allowed && d.RuleID == DefaultDenyID {
					t.Fatalf("bad decision %+v", d)
				}
				if r := p.Rules[0]; d.Allowed && d.RuleID == r.ID && r.conditional() {
					in := condInput{now: at, s: s, up: "u", tool: "t", args: map[string]any{"n": n}}
					if out, why := r.conditions(&in); out != condTrue {
						t.Fatalf("allowed by %s whose conditions do not hold: %s", r.ID, why)
					}
				}
			}
		}
	})
}
