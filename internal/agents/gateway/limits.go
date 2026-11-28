package gateway

import (
	"cmp"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/laiwf94/authz/internal/agents/httpx"
	"github.com/laiwf94/authz/internal/agents/policy"
	"github.com/laiwf94/authz/internal/platform/metrics"
	platformlimit "github.com/laiwf94/authz/internal/platform/ratelimit"
)

// The state of tool rules' own limits (a rule's "limits": rate, burst and
// daily quota per agent), read from the gateway's limiter and day counter
// by GET /admin/limits and at each metrics scrape. Nothing here is kept
// on the call path: the counts are found by walking the two tables and
// splitting each key into the rule's limits prefix and the agent (see
// policy.Limits.Key), so an agent appears only while it holds state: a
// rate bucket that is not full, or calls counted in a day that has not
// ended. Counts held under limits the policy no longer has (a rule that
// was removed or whose limits changed) are not reported; they run out
// on their own and are swept.

const (
	// The help of toolgate_rule_limit_refusals_total.
	ruleRefusalsHelp = "Calls refused by a tool rule's own rate limit or daily quota, by rule."

	// Agents listed per rule by GET /admin/limits, by default and at most.
	defaultLimitAgents = 100
	maxLimitAgents     = 1000
)

// ruleLimitFamilies are the gauges collectRuleLimits reports. Their only
// labels are the rule id and which limit, so their series are bounded by
// the policy's rules (at most policy.MaxRules, two limits each) and go
// when the rule or its limit does; the registry's series cap holds too.
var ruleLimitFamilies = []metrics.GaugeFamily{
	{Name: "toolgate_rule_limit_agents", Help: "Agents holding state under a tool rule's limit: a rate bucket that is not full, or calls counted today."},
	{Name: "toolgate_rule_limit_exhausted", Help: "Agents that a tool rule's limit refuses now: less than one token in the rate bucket, or the daily quota used up."},
	{Name: "toolgate_rule_limit_daily_used", Help: "Calls counted today under a tool rule's daily quota, all agents together."},
}

// ruleLimits is the state of one rule's limits.
type ruleLimits struct {
	rule *policy.Rule
	lim  *policy.Limits

	rateAgents, rateExhausted   int
	dailyAgents, dailyExhausted int
	dailyUsed                   int

	agents map[string]*agentLimits // nil when only counting
}

// agentLimits is one agent's state under a rule.
type agentLimits struct {
	debt  time.Duration // time until the rate bucket is full again
	used  int           // calls counted today
	dayAt time.Time     // when today ends, if used > 0
}

// scanRuleLimits returns the state of the limits of every rule in p that
// has limits, keyed by the limits' prefix, in a slice in policy order.
// With list set it also keeps each agent's state, for agent (every agent
// when empty) and rule (every rule when empty).
func (g *Gateway) scanRuleLimits(p *policy.Policy, list bool, rule, agent string) []*ruleLimits {
	var out []*ruleLimits
	byPrefix := map[string]*ruleLimits{}
	for _, r := range p.Rules {
		lim := r.Limits()
		if lim == nil || rule != "" && r.ID != rule {
			continue
		}
		rl := &ruleLimits{rule: r, lim: lim}
		if list {
			rl.agents = map[string]*agentLimits{}
		}
		out = append(out, rl)
		byPrefix[lim.Prefix()] = rl
	}
	if len(out) == 0 {
		return nil
	}
	// find returns the rule and agent of a key, or nil.
	find := func(key string) (*ruleLimits, string) {
		prefix, rest, ok := platformlimit.CutKey(key)
		if !ok {
			return nil, ""
		}
		rl := byPrefix[prefix]
		if rl == nil {
			return nil, ""
		}
		a, tail, ok := platformlimit.CutKey(rest)
		if !ok || tail != "" || agent != "" && a != agent {
			return nil, ""
		}
		return rl, a
	}
	at := func(rl *ruleLimits, a string) *agentLimits {
		s := rl.agents[a]
		if s == nil {
			s = &agentLimits{}
			rl.agents[a] = s
		}
		return s
	}
	g.limiter.Range(func(key string, debt time.Duration) bool {
		rl, a := find(key)
		if rl == nil || rl.lim.Rate.Unlimited() {
			return true
		}
		rl.rateAgents++
		if rl.lim.Rate.TokensAt(debt) < 1 {
			rl.rateExhausted++
		}
		if rl.agents != nil {
			at(rl, a).debt = debt
		}
		return true
	})
	g.ruleQuota.Range(func(key string, n int, end time.Time) bool {
		rl, a := find(key)
		if rl == nil || rl.lim.Daily <= 0 {
			return true
		}
		rl.dailyAgents++
		rl.dailyUsed += n
		if n >= rl.lim.Daily {
			rl.dailyExhausted++
		}
		if rl.agents != nil {
			s := at(rl, a)
			s.used, s.dayAt = n, end
		}
		return true
	})
	return out
}

// collectRuleLimits reports ruleLimitFamilies at each scrape, from the
// policy in force then.
func (g *Gateway) collectRuleLimits() {
	g.m.Collect(ruleLimitFamilies, func(emit func(name, labels string, v float64)) {
		for _, rl := range g.scanRuleLimits(g.opt.Policy.Current(), false, "", "") {
			id := rl.rule.ID
			if !rl.lim.Rate.Unlimited() {
				l := metrics.Labels("rule_id", id, "limit", "rate")
				emit("toolgate_rule_limit_agents", l, float64(rl.rateAgents))
				emit("toolgate_rule_limit_exhausted", l, float64(rl.rateExhausted))
			}
			if rl.lim.Daily > 0 {
				l := metrics.Labels("rule_id", id, "limit", "daily")
				emit("toolgate_rule_limit_agents", l, float64(rl.dailyAgents))
				emit("toolgate_rule_limit_exhausted", l, float64(rl.dailyExhausted))
				emit("toolgate_rule_limit_daily_used", metrics.Labels("rule_id", id), float64(rl.dailyUsed))
			}
		}
	})
}

// limitsView is one rule in GET /admin/limits.
type limitsView struct {
	RuleID string      `json:"rule_id"`
	Rate   *rateView   `json:"rate,omitempty"`
	Daily  *dailyView  `json:"daily,omitempty"`
	Agents []agentView `json:"agents"`
	More   int         `json:"agents_omitted,omitempty"`
}

type rateView struct {
	PerSecond float64 `json:"per_second"`
	Burst     int     `json:"burst"`
	Agents    int     `json:"agents"`
	Exhausted int     `json:"exhausted"`
}

type dailyView struct {
	Limit     int    `json:"limit"`
	Zone      string `json:"zone"`
	Agents    int    `json:"agents"`
	Exhausted int    `json:"exhausted"`
	Used      int    `json:"used"`
}

// agentView is one agent's state under a rule. Rate fields are present
// when the rule has a rate limit, daily fields when it has a daily quota.
type agentView struct {
	Agent string `json:"agent"`
	// Tokens is what the agent's bucket holds now (a call takes one), and
	// FullInMs how long until it holds Burst again.
	Tokens   *float64 `json:"tokens,omitempty"`
	FullInMs *int64   `json:"full_in_ms,omitempty"`
	// Used is the calls counted today and Remaining the calls left;
	// ResetsAt is the end of the day in the rule's zone.
	Used      *int   `json:"used,omitempty"`
	Remaining *int   `json:"remaining,omitempty"`
	ResetsAt  string `json:"resets_at,omitempty"`

	room float64 // the smaller share left of either limit, for ordering
}

// listLimits: GET /admin/limits. For every rule of the policy in force
// with "limits", what they are and the agents holding state under them,
// nearest to being refused first. ?rule=ID keeps one rule, ?agent=ID one
// agent, and ?agents=N lists at most N agents per rule (100 by default, at
// most 1000; agents_omitted counts the rest; the totals count every
// agent). It reads the counts without changing them.
func (g *Gateway) listLimits(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	for name, v := range q {
		if name != "rule" && name != "agent" && name != "agents" || len(v) != 1 {
			return httpx.BadRequest("the parameters are rule, agent and agents, each at most once")
		}
	}
	rule, agent := q.Get("rule"), q.Get("agent")
	if q.Has("rule") && rule == "" || q.Has("agent") && agent == "" {
		return httpx.BadRequest("rule and agent must not be empty")
	}
	n := defaultLimitAgents
	if v := q.Get("agents"); q.Has("agents") {
		var err error
		if n, err = strconv.Atoi(v); err != nil || n < 0 || n > maxLimitAgents || strconv.Itoa(n) != v {
			return httpx.BadRequest("agents must be a count from 0 to %d", maxLimitAgents)
		}
	}
	p := g.opt.Policy.Current()
	if rule != "" && !slices.ContainsFunc(p.Rules, func(x *policy.Rule) bool { return x.ID == rule }) {
		return &httpx.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "the policy has no rule " + strconv.Quote(rule)}
	}
	now := g.now()
	rules := []limitsView{}
	for _, rl := range g.scanRuleLimits(p, true, rule, agent) {
		v := limitsView{RuleID: rl.rule.ID, Agents: []agentView{}}
		if !rl.lim.Rate.Unlimited() {
			v.Rate = &rateView{PerSecond: rl.lim.Rate.Rate, Burst: max(rl.lim.Rate.Burst, 1),
				Agents: rl.rateAgents, Exhausted: rl.rateExhausted}
		}
		if rl.lim.Daily > 0 {
			v.Daily = &dailyView{Limit: rl.lim.Daily, Zone: rl.lim.Zone.String(),
				Agents: rl.dailyAgents, Exhausted: rl.dailyExhausted, Used: rl.dailyUsed}
		}
		for a, s := range rl.agents {
			av := agentView{Agent: a, room: 1}
			if v.Rate != nil {
				tokens := rl.lim.Rate.TokensAt(s.debt)
				ms := (s.debt + time.Millisecond - 1).Milliseconds()
				av.Tokens, av.FullInMs = &tokens, &ms
				av.room = min(av.room, tokens/float64(v.Rate.Burst))
			}
			if v.Daily != nil {
				used := s.used
				left := max(rl.lim.Daily-used, 0)
				av.Used, av.Remaining = &used, &left
				if used > 0 {
					av.ResetsAt = s.dayAt.UTC().Format(time.RFC3339)
				} else {
					av.ResetsAt = platformlimit.EndOfDay(now, rl.lim.Zone).UTC().Format(time.RFC3339)
				}
				av.room = min(av.room, float64(left)/float64(rl.lim.Daily))
			}
			v.Agents = append(v.Agents, av)
		}
		slices.SortFunc(v.Agents, func(a, b agentView) int {
			return cmp.Or(cmp.Compare(a.room, b.room), cmp.Compare(a.Agent, b.Agent))
		})
		if len(v.Agents) > n {
			v.More = len(v.Agents) - n
			v.Agents = v.Agents[:n]
		}
		rules = append(rules, v)
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"policy": p.Hash, "now": now.UTC().Format(time.RFC3339Nano), "rules": rules})
	return nil
}
