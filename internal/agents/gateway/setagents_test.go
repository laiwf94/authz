package gateway

import (
	"bytes"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/laiwf94/authz/internal/agents/identity"
	"github.com/laiwf94/authz/internal/agents/mcp"
)

const carolKey = "tgk_carol_0123456789abcdefghijklmnopqrstu"

// replaced returns a copy of the gateway's config with mutate applied and
// an authenticator for it, as a reload builds them.
func (e *env) replaced(t *testing.T, mutate func(*Config)) (*Config, *identity.Authenticator) {
	t.Helper()
	c := *e.gw.cfg
	c.Agents = slices.Clone(c.Agents)
	mutate(&c)
	auth, err := c.NewAuthenticator(map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	return &c, auth
}

func TestSetAgents(t *testing.T) {
	e := newEnv(t)
	if err := e.gw.SetAgents(nil, e.auth); err == nil {
		t.Fatal("SetAgents(nil config) succeeded")
	}
	if err := e.gw.SetAgents(e.gw.cfg, nil); err == nil {
		t.Fatal("SetAgents(nil authenticator) succeeded")
	}
	if r := e.rpc(carolKey, "tools/list", nil, nil); r.status != 401 {
		t.Fatalf("carol before she is added: %s", r.raw)
	}
	for range 2 {
		if r := e.call(quotaKey, "fake.echo", map[string]any{"text": "q"}); r.status != 200 {
			t.Fatalf("quota call: %s", r.raw)
		}
	}
	if r := e.call(quotaKey, "fake.echo", map[string]any{"text": "q"}); r.errCode() != mcp.CodeQuotaExceeded {
		t.Fatalf("quota not reached: %s", r.raw)
	}

	// bob goes, carol comes, quota-bot's quota is raised to 3 and the
	// default agent rate is limited.
	c, auth := e.replaced(t, func(c *Config) {
		c.Agents = []AgentConfig{c.Agents[0], c.Agents[2],
			{ID: "carol-bot", Owner: "carol", Scopes: []string{"files:read"}, TokenSHA256: hashHex(carolKey)}}
		c.Agents[1].Limits = &Limits{DailyQuota: 3}
		c.Limits = Limits{AgentRPS: 1, AgentBurst: 2}
	})
	if err := e.gw.SetAgents(c, auth); err != nil {
		t.Fatal(err)
	}
	if r := e.rpc(bobKey, "tools/list", nil, nil); r.status != 401 {
		t.Fatalf("bob after he was removed: %s", r.raw)
	}
	if r := e.call(carolKey, "fake.read_file", map[string]any{"path": "notes/a.md"}); r.status != 200 || r.text() != "note" {
		t.Fatalf("carol after she was added: %s", r.raw)
	}
	// The quota already used is kept: one more call, then none.
	if r := e.call(quotaKey, "fake.echo", map[string]any{"text": "q"}); r.status != 200 {
		t.Fatalf("raised quota: %s", r.raw)
	}
	if r := e.call(quotaKey, "fake.echo", map[string]any{"text": "q"}); r.errCode() != mcp.CodeQuotaExceeded {
		t.Fatalf("raised quota not reached: %s", r.raw)
	}
	// The new default limit applies to carol, who has none of her own.
	e.rpc(carolKey, "tools/list", nil, nil)
	if r := e.rpc(carolKey, "tools/list", nil, nil); r.status != 429 || r.errData()["scope"] != "agent" {
		t.Fatalf("new default agent limit: %s", r.raw)
	}
	// The upstreams are those the gateway was built with.
	if len(e.gw.ups) != 1 || e.gw.ups["fake"] == nil {
		t.Fatalf("upstreams changed: %v", e.gw.upNames)
	}
}

// An agent kept by every version never fails while the agents are
// replaced under it.
func TestSetAgentsUnderLoad(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Agents[1].Limits = &Limits{} })
	with, withAuth := e.replaced(t, func(c *Config) {
		c.Agents = append(c.Agents, AgentConfig{ID: "carol-bot", Owner: "carol", TokenSHA256: hashHex(carolKey)})
	})
	without, withoutAuth := e.replaced(t, func(*Config) {})

	var stop atomic.Bool
	var calls, failures atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				calls.Add(1)
				if r := e.rpc(bobKey, "tools/list", nil, nil); r.status != 200 || r.body["error"] != nil {
					failures.Add(1)
				}
			}
		}()
	}
	swaps := 0
	for ; swaps < 400 || calls.Load() < 2000; swaps++ {
		c, a := with, withAuth
		if swaps%2 == 1 {
			c, a = without, withoutAuth
		}
		if err := e.gw.SetAgents(c, a); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if failures.Load() != 0 || calls.Load() == 0 {
		t.Fatalf("%d of %d requests failed while the agents were replaced", failures.Load(), calls.Load())
	}
	t.Logf("%d requests across %d replacements, 0 failures", calls.Load(), swaps)
}
