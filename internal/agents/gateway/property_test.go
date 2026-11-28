package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/agents/jsonrpc"
	"github.com/laiwf94/authz/internal/agents/mcp"
	"github.com/laiwf94/authz/internal/agents/policy"
	"github.com/laiwf94/authz/internal/agents/ratelimit"
	platformlimit "github.com/laiwf94/authz/internal/platform/ratelimit"
)

// Property tests for tool rules with time windows, when conditions,
// per-rule limits and result rules (#87). Random policies are put in force
// in a real gateway on a fake clock that walks across the clock changes of
// three zones, random calls are made through CallTool to an upstream with
// fixed results, and every outcome is compared with propModel, a
// deliberately naive restatement of the documented rules: windows as a
// table of the minutes of a week, limits as a token bucket holding credit
// in nanoseconds and a count per local date, result rules as a list of the
// markers each result holds. Policies are reloaded as the calls go, either
// unchanged in every rule (counts carry over) or with one rule's limits
// changed (that rule counts afresh).
//
// TestPropertyBreakages runs the same comparison against deliberately
// broken gateways and fails when the comparison does not notice, so the
// property cannot silently lose its teeth.

// propResult is one of the upstream's fixed results and the markers its
// scanned text holds (text, structured values and keys; not image data).
type propResult struct {
	body    string
	markers []string
}

var propResults = []propResult{
	{`{"content":[{"type":"text","text":"all clear"}]}`, nil},
	{`{"content":[{"type":"text","text":"ref SECRET-12 here"}]}`, []string{"SECRET"}},
	{`{"content":[{"type":"text","text":"1 row"}],"structuredContent":{"rows":[{"note":"INTERNAL-7"}]}}`, []string{"INTERNAL"}},
	{`{"content":[{"type":"text","text":"ok"}],"structuredContent":{"SECRET-3":true}}`, []string{"SECRET"}},
	{`{"content":[{"type":"image","mimeType":"image/png","data":"SECRET-9"},{"type":"text","text":"img"}]}`, nil},
	{`{"content":[{"type":"text","text":"token ` + ghToken + `"}]}`, []string{"GH"}},
	{`{"content":[{"type":"text","text":"SECRET-1"}],"structuredContent":{"x":"INTERNAL-2"}}`, []string{"SECRET", "INTERNAL"}},
	{`{"content":[{"type":"text","text":"INTERNAL-5 and ` + ghToken + `"}]}`, []string{"INTERNAL", "GH"}},
}

// Deny patterns the generator chooses from and the marker each finds.
var (
	propBuiltinDeny = map[string]string{"github_token": "GH", "private_key": ""}
	propCustomDeny  = map[string]string{"SECRET-[0-9]+": "SECRET", "INTERNAL-[0-9]+": "INTERNAL", "zz[0-9]q": ""}
	propZones       = []string{"UTC", "America/New_York", "Europe/Berlin", "Australia/Sydney"}
	propTools       = []string{"t0", "t1", "t2", "x_read"}
	propAgents      = []string{"a1", "a2", "a3"}
)

func propUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Arguments struct {
					R int `json:"r"`
				} `json:"arguments"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &m)
		w.Header().Set("Content-Type", "application/json")
		if m.Method == "tools/list" {
			var tools []string
			for _, n := range propTools {
				tools = append(tools, fmt.Sprintf(`{"name":%q,"inputSchema":{"type":"object"}}`, n))
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[%s]}}`, m.ID, strings.Join(tools, ","))
			return
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, m.ID, propResults[m.Params.Arguments.R].body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type propWindow struct {
	zone     string
	days     []int // weekdays the window starts on; nil for every day
	from, to int   // minutes since local midnight; to may be 1440
}

type propLimits struct {
	rate  float64 // calls a second, 0 for none
	burst int     // 0 when not written (1)
	daily int     // 0 for none
	zone  string  // "" for UTC
}

type propRule struct {
	id          string
	deny        bool
	agents      []string
	tools       []string
	windows     []propWindow
	whenBelow   int // when "args.n < whenBelow"; 0 for no when
	limits      *propLimits
	denyBuiltin []string
	denyCustom  []string
}

func hhmm(m int) string { return fmt.Sprintf("%02d:%02d", m/60, m%60) }

func (r propRule) json() map[string]any {
	effect := "allow"
	if r.deny {
		effect = "deny"
	}
	j := map[string]any{"id": r.id, "effect": effect, "agents": r.agents, "upstreams": []string{"up"}, "tools": r.tools}
	if len(r.windows) > 0 {
		var ws []any
		for _, w := range r.windows {
			fw := map[string]any{"zone": w.zone, "from": hhmm(w.from), "to": hhmm(w.to)}
			if w.days != nil {
				var names []string
				for _, d := range w.days {
					names = append(names, dayNames[d])
				}
				fw["days"] = names
			}
			ws = append(ws, fw)
		}
		j["windows"] = ws
	}
	if r.whenBelow > 0 {
		j["when"] = fmt.Sprintf("args.n < %d", r.whenBelow)
	}
	if l := r.limits; l != nil {
		fl := map[string]any{}
		if l.rate > 0 {
			fl["rate"] = l.rate
		}
		if l.burst > 0 {
			fl["burst"] = l.burst
		}
		if l.daily > 0 {
			fl["daily"] = l.daily
		}
		if l.zone != "" {
			fl["zone"] = l.zone
		}
		j["limits"] = fl
	}
	if len(r.denyBuiltin)+len(r.denyCustom) > 0 {
		o := map[string]any{}
		if len(r.denyBuiltin) > 0 {
			o["deny"] = r.denyBuiltin
		}
		if len(r.denyCustom) > 0 {
			o["deny_patterns"] = r.denyCustom
		}
		j["output"] = o
	}
	return j
}

var dayNames = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

func propPolicy(rules []propRule, filler bool) []byte {
	js := []any{}
	for _, r := range rules {
		js = append(js, r.json())
	}
	if filler {
		// A rule for another upstream: the policy changes, no rule of "up" does.
		js = append(js, map[string]any{"id": "filler", "effect": "allow", "agents": []string{"*"},
			"upstreams": []string{"elsewhere"}, "tools": []string{"*"}})
	}
	src, _ := json.Marshal(map[string]any{"version": 1, "rules": js})
	return src
}

func propSubset(rng *rand.Rand, xs []string) []string {
	var out []string
	for _, x := range xs {
		if rng.IntN(3) == 0 {
			out = append(out, x)
		}
	}
	return out
}

func propPick[T any](rng *rand.Rand, xs []T) T { return xs[rng.IntN(len(xs))] }

func randomWindow(rng *rand.Rand) propWindow {
	for {
		w := propWindow{zone: propPick(rng, propZones), from: 30 * rng.IntN(48), to: 30 * (1 + rng.IntN(48))}
		if rng.IntN(2) == 0 {
			for d := range 7 {
				if rng.IntN(2) == 0 {
					w.days = append(w.days, d)
				}
			}
		}
		if w.from == w.to || w.from == 0 && w.to == 1440 && w.days == nil {
			continue
		}
		return w
	}
}

func randomLimits(rng *rand.Rand) *propLimits {
	l := &propLimits{}
	for l.rate == 0 && l.daily == 0 {
		if rng.IntN(3) > 0 {
			// Rates whose emission interval is a whole number of
			// nanoseconds, so the reference bucket is exact.
			l.rate = propPick(rng, []float64{0.25, 0.5, 1, 2, 4})
			l.burst = rng.IntN(4)
		}
		if rng.IntN(2) == 0 {
			l.daily = 1 + rng.IntN(4)
			if rng.IntN(4) > 0 {
				l.zone = propPick(rng, propZones[1:])
			}
		}
	}
	return l
}

func randomPropRule(rng *rand.Rand, i int) propRule {
	r := propRule{id: fmt.Sprintf("r%d", i), deny: rng.IntN(5) == 0}
	if rng.IntN(4) == 0 {
		r.agents = []string{"*"}
	} else if r.agents = propSubset(rng, propAgents); len(r.agents) == 0 {
		r.agents = []string{propPick(rng, propAgents)}
	}
	if rng.IntN(5) == 0 {
		r.tools = []string{"*"}
	} else if r.tools = propSubset(rng, []string{"t0", "t1", "t2", "x_*"}); len(r.tools) == 0 {
		r.tools = []string{"t0"}
	}
	for range rng.IntN(3) {
		r.windows = append(r.windows, randomWindow(rng))
	}
	if rng.IntN(4) == 0 {
		r.whenBelow = 1 + rng.IntN(9)
	}
	if !r.deny {
		if rng.IntN(2) == 0 {
			r.limits = randomLimits(rng)
		}
		if rng.IntN(2) == 0 {
			r.denyBuiltin = propSubset(rng, []string{"github_token", "private_key"})
			for _, p := range rng.Perm(3)[:rng.IntN(4)%3] {
				r.denyCustom = append(r.denyCustom, []string{"SECRET-[0-9]+", "INTERNAL-[0-9]+", "zz[0-9]q"}[p])
			}
		}
	}
	return r
}

// propModel is the reference: the documented semantics, written naively.
type propModel struct {
	rules   []propRule
	buckets map[string]*refBucket
	days    map[string]*refDay
}

type refBucket struct {
	credit int64 // nanoseconds; one call costs one emission interval
	last   time.Time
}

type refDay struct {
	date  string
	count int
}

func newPropModel(rules []propRule) *propModel {
	return &propModel{rules: rules, buckets: map[string]*refBucket{}, days: map[string]*refDay{}}
}

func (r propRule) targets(agent, tool string) bool {
	if !slices.Contains(r.agents, "*") && !slices.Contains(r.agents, agent) {
		return false
	}
	for _, t := range r.tools {
		if t == "*" || t == tool || strings.HasSuffix(t, "*") && strings.HasPrefix(tool, strings.TrimSuffix(t, "*")) {
			return true
		}
	}
	return false
}

// open reports whether now is inside w, by filling in the minutes of the
// week the window covers and looking the local wall-clock minute up.
func (w propWindow) open(now time.Time) bool {
	var week [7][1440]bool
	days := w.days
	if days == nil {
		days = []int{0, 1, 2, 3, 4, 5, 6}
	}
	for _, d := range days {
		if w.from < w.to {
			for m := w.from; m < w.to; m++ {
				week[d][m] = true
			}
			continue
		}
		for m := w.from; m < 1440; m++ {
			week[d][m] = true
		}
		for m := 0; m < w.to; m++ {
			week[(d+1)%7][m] = true
		}
	}
	loc, err := time.LoadLocation(w.zone)
	if err != nil {
		panic(err)
	}
	l := now.In(loc)
	return week[l.Weekday()][l.Hour()*60+l.Minute()]
}

func (r propRule) holds(now time.Time, n int) bool {
	if len(r.windows) > 0 && !slices.ContainsFunc(r.windows, func(w propWindow) bool { return w.open(now) }) {
		return false
	}
	return r.whenBelow == 0 || n < r.whenBelow
}

func (l *propLimits) key(id, agent string) string {
	zone := l.zone
	if zone == "" {
		zone = "UTC"
	}
	return fmt.Sprintf("%s|%g|%d|%d|%s|%s", id, l.rate, max(l.burst, 1), l.daily, zone, agent)
}

func (m *propModel) call(now time.Time, agent, tool string, n, res int) string {
	for _, r := range m.rules {
		if r.deny && r.targets(agent, tool) && r.holds(now, n) {
			return "denied " + r.id
		}
	}
	constraint := ""
	var sel *propRule
	for i, r := range m.rules {
		if r.deny || !r.targets(agent, tool) {
			continue
		}
		if r.holds(now, n) {
			sel = &m.rules[i]
			break
		}
		if constraint == "" {
			constraint = r.id
		}
	}
	if sel == nil {
		if constraint == "" {
			return "unknown_tool"
		}
		return "denied " + policy.DefaultDenyID
	}
	if l := sel.limits; l != nil {
		key := l.key(sel.id, agent)
		if l.rate > 0 {
			interval := int64(float64(time.Second) / l.rate)
			full := int64(max(l.burst, 1)) * interval
			b := m.buckets[key]
			if b == nil {
				b = &refBucket{credit: full, last: now}
				m.buckets[key] = b
			}
			b.credit = min(full, b.credit+now.Sub(b.last).Nanoseconds())
			b.last = now
			if b.credit < interval {
				return "rate_limited " + sel.id + " (scope rule)"
			}
			b.credit -= interval
		}
		if l.daily > 0 {
			zone := l.zone
			if zone == "" {
				zone = "UTC"
			}
			loc, _ := time.LoadLocation(zone)
			date := now.In(loc).Format("2006-01-02")
			d := m.days[key]
			if d == nil || d.date != date {
				d = &refDay{date: date}
				m.days[key] = d
			}
			if d.count >= l.daily {
				return "quota_exceeded " + sel.id
			}
			d.count++
		}
	}
	marks := propResults[res].markers
	for _, b := range sel.denyBuiltin {
		if slices.Contains(marks, propBuiltinDeny[b]) {
			return "result_refused " + sel.id + " " + b
		}
	}
	for i, c := range sel.denyCustom {
		if slices.Contains(marks, propCustomDeny[c]) {
			return fmt.Sprintf("result_refused %s deny_patterns[%d]", sel.id, i)
		}
	}
	return "ok"
}

// outcomeOf reads what CallTool answered in the reference's terms.
func outcomeOf(res map[string]any, err error, want int) string {
	if err == nil {
		got, _ := json.Marshal(res)
		var a, b any
		_ = json.Unmarshal(got, &a)
		_ = json.Unmarshal([]byte(propResults[want].body), &b)
		if !reflect.DeepEqual(a, b) {
			return "ok, but the result was changed"
		}
		return "ok"
	}
	var e *mcp.Error
	if !errors.As(err, &e) {
		return "error " + err.Error()
	}
	d, _ := e.RPC.Data.(map[string]any)
	switch e.RPC.Code {
	case mcp.CodePolicyDenied:
		return fmt.Sprint("denied ", d["rule_id"])
	case jsonrpc.CodeInvalidParams:
		return "unknown_tool"
	case mcp.CodeRateLimited:
		return fmt.Sprintf("rate_limited %v (scope %v)", d["rule_id"], d["scope"])
	case mcp.CodeQuotaExceeded:
		return fmt.Sprint("quota_exceeded ", d["rule_id"])
	case mcp.CodeResultRefused:
		return fmt.Sprint("result_refused ", d["rule_id"], " ", d["pattern"])
	}
	return fmt.Sprintf("error %d %s", e.RPC.Code, e.RPC.Message)
}

// The days the clocks change in 2026 in the zones the windows use.
var propClockChanges = []time.Time{
	time.Date(2026, 3, 8, 7, 0, 0, 0, time.UTC),   // America/New_York forward
	time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC),  // Europe/Berlin forward
	time.Date(2026, 4, 4, 16, 0, 0, 0, time.UTC),  // Australia/Sydney back
	time.Date(2026, 10, 3, 16, 0, 0, 0, time.UTC), // Australia/Sydney forward
	time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC), // Europe/Berlin back
	time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC),  // America/New_York back
}

// propStep moves the clock forward: a fraction of a second, seconds, hours,
// or to just before or onto the next half hour, where windows open and
// close and local days end.
func propStep(rng *rand.Rand, now time.Time) time.Time {
	switch k := rng.IntN(20); {
	case k < 7:
		return now.Add(time.Duration(rng.IntN(9)) * 250 * time.Millisecond)
	case k < 11:
		return now.Add(time.Duration(1+rng.IntN(90)) * time.Second)
	case k < 17:
		next := now.Truncate(30 * time.Minute).Add(30 * time.Minute)
		if early := next.Add(-time.Duration(rng.IntN(3)) * 250 * time.Millisecond); early.After(now) {
			return early
		}
		return next
	default:
		return now.Add(time.Duration(1+rng.IntN(9)) * time.Hour)
	}
}

// breakage alters what a gateway runs with, for TestPropertyBreakages:
// rules rewrites the policy it is given (reporting whether anything
// changed), and reloaded runs after each reload.
type breakage struct {
	name     string
	rules    func([]propRule) ([]propRule, bool)
	reloaded func(g *Gateway)
}

func cloneRules(rules []propRule) []propRule {
	out := make([]propRule, len(rules))
	for i, r := range rules {
		r.windows = slices.Clone(r.windows)
		if r.limits != nil {
			l := *r.limits
			r.limits = &l
		}
		r.denyCustom = slices.Clone(r.denyCustom)
		r.denyBuiltin = slices.Clone(r.denyBuiltin)
		out[i] = r
	}
	return out
}

// runProperty puts one random policy in a fresh gateway, makes calls, and
// returns the first disagreement with the reference ("" when none).
// skipped reports that brk changes nothing in this policy.
func runProperty(t *testing.T, rng *rand.Rand, calls int, brk *breakage) (mismatch string, skipped bool) {
	t.Helper()
	var rules []propRule
	for i := range 1 + rng.IntN(6) {
		rules = append(rules, randomPropRule(rng, i))
	}
	served := func(rules []propRule) ([]propRule, bool) {
		if brk == nil || brk.rules == nil {
			return rules, false
		}
		return brk.rules(cloneRules(rules))
	}
	if brk != nil && brk.rules != nil {
		if _, changed := served(rules); !changed {
			return "", true
		}
	}

	srv := propUpstream(t)
	e := newEnv(t, func(c *Config) {
		c.Upstreams = append(c.Upstreams, UpstreamConfig{Name: "up", URL: srv.URL, TimeoutMS: 2000,
			MaxResponseBytes: 1 << 16, MaxConcurrency: 4, ToolsTTLSeconds: 3600})
		c.Limits = Limits{}
	})
	start := propPick(rng, propClockChanges).Add(-time.Duration(rng.IntN(36*60)) * time.Minute)
	e.clk.mu.Lock()
	e.clk.t = start
	e.clk.mu.Unlock()
	// The limiters measure from the clock as it was when they were made,
	// which was before it was set back to start.
	e.gw.limiter = ratelimit.NewLimiter(e.gw.now)
	e.gw.ruleQuota = platformlimit.NewDaily(platformlimit.Options{Now: e.gw.now})
	filler := false
	install := func() string {
		r, _ := served(rules)
		if err := os.WriteFile(e.policyPath, propPolicy(r, filler), 0o600); err != nil {
			t.Fatal(err)
		}
		if res := e.gw.opt.Policy.Reload(); res.Err != nil {
			t.Fatalf("generated policy rejected: %v\n%s", res.Err, propPolicy(r, filler))
		}
		if brk != nil && brk.reloaded != nil {
			brk.reloaded(e.gw)
		}
		return string(propPolicy(rules, filler))
	}
	src := install()
	model := newPropModel(rules)
	var history []string
	for i := range calls {
		if i > 0 && rng.IntN(25) == 0 {
			// Reload: the same rules for "up" (counts carry over), or one
			// rule's limits changed (it counts afresh).
			if j := rng.IntN(len(rules)); rng.IntN(2) == 0 && !rules[j].deny {
				rules = cloneRules(rules)
				if rules[j].limits == nil || rng.IntN(3) > 0 {
					rules[j].limits = randomLimits(rng)
				} else {
					rules[j].limits = nil
				}
				model.rules = rules
			} else {
				filler = !filler
			}
			src = install()
			history = append(history, "reload")
		}
		now := propStep(rng, e.clk.now())
		e.clk.mu.Lock()
		e.clk.t = now
		e.clk.mu.Unlock()
		agent, tool := propPick(rng, propAgents), propPick(rng, propTools)
		n, res := rng.IntN(10), rng.IntN(len(propResults))
		id := &identity.Identity{AgentID: agent, Owner: "o-" + agent, Method: "static"}
		args := map[string]any{"n": json.Number(strconv.Itoa(n)), "r": json.Number(strconv.Itoa(res))}
		out, err := e.gw.CallTool(context.Background(), &mcp.Caller{Principal: id, Version: mcp.VersionModern}, "up."+tool, args)
		got := outcomeOf(out, err, res)
		want := model.call(now, agent, tool, n, res)
		history = append(history, fmt.Sprintf("%s %s up.%s n=%d r=%d: %s", now.Format(time.RFC3339Nano), agent, tool, n, res, want))
		if got != want {
			if len(history) > 12 {
				history = history[len(history)-12:]
			}
			return fmt.Sprintf("call %d at %s (%s): %s up.%s n=%d result %d\ngateway:   %s\nreference: %s\nlast calls:\n  %s\npolicy: %s",
				i, now.Format(time.RFC3339Nano), now.Format(time.RFC1123Z), agent, tool, n, res, got, want,
				strings.Join(history, "\n  "), src), false
		}
	}
	return "", false
}

// propShards is how many groups of policies run in parallel: each call
// waits on the audit log's fsync, so the shards overlap their waits.
const propShards = 6

func TestPropertyRulesMatchReference(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	policies := 8 // per shard
	if testing.Short() {
		policies = 2
	}
	for shard := range uint64(propShards) {
		t.Run(fmt.Sprint("shard", shard), func(t *testing.T) {
			t.Parallel()
			rng := rand.New(rand.NewPCG(seed, 87+shard))
			for range policies {
				if m, _ := runProperty(t, rng, 200, nil); m != "" {
					t.Fatalf("seed %d shard %d: %s", seed, shard, m)
				}
			}
		})
	}
}

// Deliberate breakages of what the gateway runs with. Each emulates a
// plausible bug in the engine: windows read in the wrong zone or with an
// inclusive end, conditions skipped, a day counted in UTC, a burst one too
// large, counts dropped on every reload, deny patterns matched only as a
// whole string or built-in deny names ignored.
var propBreakages = []breakage{
	{name: "windows read in UTC", rules: func(rs []propRule) ([]propRule, bool) {
		changed := false
		for i := range rs {
			for j := range rs[i].windows {
				changed = changed || rs[i].windows[j].zone != "UTC"
				rs[i].windows[j].zone = "UTC"
			}
		}
		return rs, changed
	}},
	{name: "window end inclusive", rules: func(rs []propRule) ([]propRule, bool) {
		changed := false
		for i := range rs {
			for j, w := range rs[i].windows {
				if w.to < 1440 {
					rs[i].windows[j].to++
					changed = true
				}
			}
		}
		return rs, changed
	}},
	{name: "deny rule conditions ignored", rules: func(rs []propRule) ([]propRule, bool) {
		changed := false
		for i := range rs {
			if rs[i].deny && (len(rs[i].windows) > 0 || rs[i].whenBelow > 0) {
				rs[i].windows, rs[i].whenBelow, changed = nil, 0, true
			}
		}
		return rs, changed
	}},
	{name: "when expressions ignored", rules: func(rs []propRule) ([]propRule, bool) {
		changed := false
		for i := range rs {
			changed = changed || rs[i].whenBelow > 0
			rs[i].whenBelow = 0
		}
		return rs, changed
	}},
	{name: "daily quota counted in UTC", rules: func(rs []propRule) ([]propRule, bool) {
		changed := false
		for i := range rs {
			if l := rs[i].limits; l != nil && l.zone != "" {
				l.zone, changed = "", true
			}
		}
		return rs, changed
	}},
	{name: "burst one too large", rules: func(rs []propRule) ([]propRule, bool) {
		changed := false
		for i := range rs {
			if l := rs[i].limits; l != nil && l.rate > 0 {
				l.burst, changed = max(l.burst, 1)+1, true
			}
		}
		return rs, changed
	}},
	{name: "rule counts dropped on reload", reloaded: func(g *Gateway) {
		g.limiter = ratelimit.NewLimiter(g.now)
		g.ruleQuota = platformlimit.NewDaily(platformlimit.Options{Now: g.now})
	}},
	{name: "deny patterns matched as a whole string", rules: func(rs []propRule) ([]propRule, bool) {
		changed := false
		for i := range rs {
			for j, p := range rs[i].denyCustom {
				if propCustomDeny[p] != "" {
					rs[i].denyCustom[j], changed = "^"+p+"$", true
				}
			}
		}
		return rs, changed
	}},
	{name: "built-in deny names ignored", rules: func(rs []propRule) ([]propRule, bool) {
		changed := false
		for i := range rs {
			if slices.Contains(rs[i].denyBuiltin, "github_token") {
				rs[i].denyBuiltin, changed = nil, true
			}
		}
		return rs, changed
	}},
}

// TestPropertyBreakages: the comparison of TestPropertyRulesMatchReference
// must find each deliberate breakage within a bounded number of random
// policies the breakage changes.
func TestPropertyBreakages(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	for _, b := range propBreakages {
		t.Run(strings.ReplaceAll(b.name, " ", "_"), func(t *testing.T) {
			t.Parallel()
			rng := rand.New(rand.NewPCG(seed, 5))
			for tried := 0; tried < 300; {
				m, skipped := runProperty(t, rng, 200, &b)
				if skipped {
					continue
				}
				tried++
				if m != "" {
					t.Logf("found after %d policies: %s", tried, firstLine(m))
					return
				}
			}
			t.Fatalf("seed %d: the property did not notice %q in 300 policies", seed, b.name)
		})
	}
}

func firstLine(s string) string { l, _, _ := strings.Cut(s, "\n"); return l }
