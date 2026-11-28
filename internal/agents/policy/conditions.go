package policy

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/platform/cel"
	"github.com/laiwf94/authz/internal/platform/ratelimit"
)

// A rule may also carry conditions on when and how a call is made, and
// limits on how often its calls are allowed:
//
//	{"id": "deploy-office-hours", "effect": "allow", "agents": ["ci-bot"],
//	 "upstreams": ["ops"], "tools": ["deploy"],
//	 "windows": [{"zone": "Europe/Berlin", "days": ["mon", "tue", "wed", "thu", "fri"],
//	              "from": "09:00", "to": "17:00"}],
//	 "when": "args.env != 'prod' || session.auth == 'signed'",
//	 "limits": {"rate": 0.1, "burst": 2, "daily": 20, "zone": "Europe/Berlin"}}
//
// windows: the rule applies only while the local time in the window's zone
// is in [from, to) on one of its days (every day when days is absent). A
// window whose to is earlier than its from runs overnight, into the next
// day. Windows are wall-clock times, so on the days the clocks change a
// window covering the skipped hour is that much shorter and one covering
// the repeated hour that much longer, and a window entirely inside the
// skipped hour does not open that day. With several windows the rule
// applies inside any of them.
//
// when: a CEL expression (internal/platform/cel) that must be true for the
// rule to apply. It may use
//
//   - now: the time of the call, a timestamp; now.getHours("Asia/Tokyo")
//     and the other accessors take a zone;
//   - args: the call's arguments, map<string, dyn>; use has(args.x) before
//     reading an argument the call may lack;
//   - agent, owner, upstream and tool: strings;
//   - scopes: the agent's scopes, list<string>;
//   - session: map<string, string> of facts about how the agent connected:
//     auth ("static" or "signed"), issuer, key_id and protocol (the MCP
//     protocol version), each "" when there is none.
//
// The expression is checked when the policy loads and must be a bool.
//
// Conditions are tested after the argument schema and before the
// relationship check, which they can spare. In an allow rule a condition
// that is false, fails with a runtime error or depends on something the
// call does not have (now, in a case file that gives no time) does not
// allow the call; evaluation moves on, and a default deny names the first
// such rule as its ConstraintRuleID. In a deny rule conditions say when it
// forbids the call, and fail closed: an error or an unknown counts as true.
//
// limits (allow rules only): rate calls a second with a burst of burst
// (1 when absent) and daily calls a day, the day of zone (UTC when absent),
// counted per agent and rule when this rule allows a call. The gateway
// keeps the counts; a rule whose limits are unchanged keeps its counts
// across policy reloads, and changing a rule's limits starts it afresh.
type fileWindow struct {
	Zone string   `json:"zone"`
	Days []string `json:"days"`
	From string   `json:"from"`
	To   string   `json:"to"`
}

type fileLimits struct {
	Rate  float64 `json:"rate"`
	Burst int     `json:"burst"`
	Daily int     `json:"daily"`
	Zone  string  `json:"zone"`
}

// Limits on conditions.
const (
	MaxWindows  = 16
	MaxWhenCost = 10_000 // CEL cost units per evaluation
	MaxRate     = 1e6
	MaxBurst    = 1_000_000
	MaxDaily    = 1_000_000_000
)

var dayNames = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

type window struct {
	loc      *time.Location
	days     uint8 // bit per time.Weekday the window starts on
	from, to int   // seconds since local midnight; to may be 86400
	text     string
}

func compileWindow(i int, fw fileWindow) (window, error) {
	field := fmt.Sprintf("windows[%d]", i)
	w := window{}
	var err error
	if w.loc, err = loadZone(fw.Zone); err != nil {
		return w, fmt.Errorf("%s.zone: %w", field, err)
	}
	if len(fw.Days) == 0 {
		w.days = 0x7f
	}
	for _, d := range fw.Days {
		n := slices.Index(dayNames, d)
		if n < 0 {
			return w, fmt.Errorf("%s.days: %q is not one of %s", field, d, strings.Join(dayNames, ", "))
		}
		if w.days&(1<<n) != 0 {
			return w, fmt.Errorf("%s.days: %q is listed twice", field, d)
		}
		w.days |= 1 << n
	}
	if w.from, err = clockTime(fw.From, false); err != nil {
		return w, fmt.Errorf("%s.from: %w", field, err)
	}
	if w.to, err = clockTime(fw.To, true); err != nil {
		return w, fmt.Errorf("%s.to: %w", field, err)
	}
	if w.from == w.to || w.from == 0 && w.to == 86400 && len(fw.Days) == 0 {
		return w, fmt.Errorf("%s: from and to must differ, and a window of every day all day is no condition; remove it", field)
	}
	days := "every day"
	if len(fw.Days) > 0 {
		days = strings.Join(fw.Days, ",")
	}
	w.text = days + " " + fw.From + "-" + fw.To + " " + w.loc.String()
	return w, nil
}

func loadZone(name string) (*time.Location, error) {
	if name == "" || name == "Local" || len(name) > 64 {
		return nil, errors.New(`name an IANA time zone such as "UTC" or "Europe/Berlin"`)
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("unknown time zone %q", name)
	}
	return loc, nil
}

// clockTime reads "HH:MM" as seconds since midnight; "24:00" only as an
// end.
func clockTime(s string, end bool) (int, error) {
	if len(s) != 5 || s[2] != ':' {
		return 0, fmt.Errorf("%q must be HH:MM", s)
	}
	h, err1 := strconv.Atoi(s[:2])
	m, err2 := strconv.Atoi(s[3:])
	if err1 != nil || err2 != nil || s[0] < '0' || s[0] > '9' || s[3] < '0' || s[3] > '9' || h > 24 || m > 59 ||
		h == 24 && (m != 0 || !end) {
		return 0, fmt.Errorf("%q must be HH:MM from 00:00 to 23:59 (or 24:00 as an end)", s)
	}
	return h*3600 + m*60, nil
}

// contains reports whether t is inside the window.
func (w window) contains(t time.Time) bool {
	l := t.In(w.loc)
	sec := l.Hour()*3600 + l.Minute()*60 + l.Second()
	day := l.Weekday()
	if w.from < w.to {
		return w.days&(1<<day) != 0 && sec >= w.from && sec < w.to
	}
	// Overnight: from today's from to midnight, or from midnight to to on
	// the day after a day the window starts.
	if sec >= w.from {
		return w.days&(1<<day) != 0
	}
	return sec < w.to && w.days&(1<<((day+6)%7)) != 0
}

// whenEnv is the CEL environment of when expressions.
var whenEnv = func() *cel.Env {
	e, err := cel.NewEnv([]cel.Var{
		{Name: "now", Type: cel.Timestamp},
		{Name: "args", Type: cel.MapOf(cel.String, cel.Dyn)},
		{Name: "agent", Type: cel.String},
		{Name: "owner", Type: cel.String},
		{Name: "upstream", Type: cel.String},
		{Name: "tool", Type: cel.String},
		{Name: "scopes", Type: cel.ListOf(cel.String)},
		{Name: "session", Type: cel.MapOf(cel.String, cel.String)},
	})
	if err != nil {
		panic(err)
	}
	return e
}()

func compileWhen(src string) (*cel.Program, error) {
	c, err := whenEnv.CompileAs(src, cel.Bool)
	if err != nil {
		return nil, fmt.Errorf("when: %w", err)
	}
	return c.Program(MaxWhenCost), nil
}

// Session is what the gateway knows about how an agent connected, the
// session facts of when expressions.
type Session struct {
	Auth     string // "static" or "signed"
	Issuer   string // signed tokens: the issuer
	KeyID    string // the key that verified a signed token, or an issued static key's id
	Protocol string // the MCP protocol version of the request
}

// Limits are a rule's limits on the calls it allows, per agent.
type Limits struct {
	Rate  ratelimit.Limit // Rate 0 means no rate limit
	Daily int             // 0 means no daily quota
	Zone  *time.Location  // the day Daily counts
	key   string          // rule id and the limits, so changed limits start afresh
}

// Key is the limiter key of agent's counts under these limits. It is the
// same across reloads for as long as the rule keeps its id and its limits.
func (l *Limits) Key(agent string) string { return ratelimit.Key(l.key, agent) }

// Prefix is the first dimension of every Key of these limits: Key(agent)
// is ratelimit.Key(Prefix(), agent), so ratelimit.SplitKey of a key
// returns the prefix and the agent.
func (l *Limits) Prefix() string { return l.key }

// String is the limits as written, for messages.
func (l *Limits) String() string {
	var parts []string
	if !l.Rate.Unlimited() {
		parts = append(parts, fmt.Sprintf("%g/s burst %d", l.Rate.Rate, max(l.Rate.Burst, 1)))
	}
	if l.Daily > 0 {
		parts = append(parts, fmt.Sprintf("%d a day (%s)", l.Daily, l.Zone))
	}
	return strings.Join(parts, ", ")
}

func compileLimits(id string, fl *fileLimits) (*Limits, error) {
	if math.IsNaN(fl.Rate) || fl.Rate < 0 || fl.Rate > MaxRate {
		return nil, fmt.Errorf("limits.rate must be from 0 to %g calls a second", float64(MaxRate))
	}
	if fl.Burst < 0 || fl.Burst > MaxBurst {
		return nil, fmt.Errorf("limits.burst must be from 1 to %d", MaxBurst)
	}
	if fl.Burst > 0 && fl.Rate == 0 {
		return nil, errors.New("limits.burst needs limits.rate")
	}
	if fl.Daily < 0 || fl.Daily > MaxDaily {
		return nil, fmt.Errorf("limits.daily must be from 1 to %d", MaxDaily)
	}
	if fl.Rate == 0 && fl.Daily == 0 {
		return nil, errors.New("limits must set rate, daily or both")
	}
	l := &Limits{Rate: ratelimit.Limit{Rate: fl.Rate, Burst: max(fl.Burst, 1)}, Daily: fl.Daily, Zone: time.UTC}
	if fl.Zone != "" {
		if fl.Daily == 0 {
			return nil, errors.New("limits.zone applies only with limits.daily")
		}
		var err error
		if l.Zone, err = loadZone(fl.Zone); err != nil {
			return nil, fmt.Errorf("limits.zone: %w", err)
		}
	}
	l.key = ratelimit.Key("rule", id, strconv.FormatFloat(fl.Rate, 'g', -1, 64), strconv.Itoa(l.Rate.Burst),
		strconv.Itoa(fl.Daily), l.Zone.String())
	return l, nil
}

// condInput holds what conditions are evaluated against, built once per
// call when a rule with a when expression is reached.
type condInput struct {
	now  time.Time // zero: unknown
	s    Subject
	up   string
	tool string
	args any
	vars map[string]any
}

func (c *condInput) celVars() map[string]any {
	if c.vars != nil {
		return c.vars
	}
	scopes := c.s.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	c.vars = map[string]any{
		"args": c.args, "agent": c.s.AgentID, "owner": c.s.Owner, "upstream": c.up, "tool": c.tool,
		"scopes": scopes,
		"session": map[string]string{"auth": c.s.Session.Auth, "issuer": c.s.Session.Issuer,
			"key_id": c.s.Session.KeyID, "protocol": c.s.Session.Protocol},
	}
	if !c.now.IsZero() {
		c.vars["now"] = c.now
	}
	return c.vars
}

// Condition outcomes.
const (
	condTrue = iota
	condFalse
	condUnknown // depends on a fact the call lacks, or an error
)

// conditions tests r's windows and when expression. why explains an
// outcome other than condTrue.
func (r *Rule) conditions(in *condInput) (outcome int, why string) {
	if len(r.windows) > 0 {
		if in.now.IsZero() {
			return condUnknown, "rule " + r.ID + " has time windows and the time of the call is unknown"
		}
		inside := false
		for _, w := range r.windows {
			if w.contains(in.now) {
				inside = true
				break
			}
		}
		if !inside {
			texts := make([]string, len(r.windows))
			for i, w := range r.windows {
				texts[i] = w.text
			}
			return condFalse, "rule " + r.ID + " applies only " + strings.Join(texts, "; ")
		}
	}
	if r.when == nil {
		return condTrue, ""
	}
	res, err := r.when.Eval(in.celVars())
	switch {
	case err != nil:
		return condUnknown, "condition of rule " + r.ID + " failed: " + err.Error()
	case !res.Known():
		return condUnknown, "condition of rule " + r.ID + " needs " + strings.Join(res.Missing, ", ")
	case res.Value != true:
		return condFalse, "condition of rule " + r.ID + " is false"
	}
	return condTrue, ""
}
