package config

import (
	"reflect"
	"testing"

	"github.com/laiwf94/authz/internal/authn/policy"
)

func TestClaimConditions(t *testing.T) {
	doc := `{
  "public_url": "https://auth.example.com",
  "providers": [
    {"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "SECRET"}
  ],
  "apps": [
    {"id": "wiki", "hosts": ["wiki.example.com"], "providers": ["corp"],
     "allow": {"claims": [{"claim": "tenant", "equals": "acme"}]},
     "paths": [
       {"path": "/admin", "allow": {"groups": ["admins"], "claims": [{"claim": "department", "in": ["it", "sec"]}]}},
       {"path": "/docs/{id}", "allow": {"claims": [{"claim": "clearance", "matches": "level-?"}]},
        "check": {"resource": "doc:{path.id}", "permission": "view"}}
     ]}
  ]
}`
	r := Check([]byte(doc), getenvSecret)
	// A rule whose only condition is a claim allows those who meet it:
	// no "nobody is allowed" warning.
	expect(t, r.Problems)
	p, err := r.Config.Apps[0].Policy()
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ClaimNames(); !reflect.DeepEqual(got, []string{"clearance", "department", "tenant"}) {
		t.Errorf("ClaimNames = %v", got)
	}
	acme := &policy.Identity{Provider: "corp", Subject: "alice", Groups: []string{"admins"},
		Claims: map[string][]string{"tenant": {"acme"}, "department": {"sec"}}}
	for _, c := range []struct {
		path   string
		id     *policy.Identity
		ok     bool
		reason string
	}{
		{"/", acme, true, policy.Allowed},
		{"/", &policy.Identity{Provider: "corp", Subject: "bob", Claims: map[string][]string{"tenant": {"other"}}}, false, policy.DeniedClaims},
		{"/admin", acme, true, policy.Allowed},
		{"/admin", &policy.Identity{Provider: "corp", Subject: "carol", Groups: []string{"admins"}}, false, policy.DeniedClaims},
		{"/docs/plan", acme, false, policy.DeniedClaims},
	} {
		if ok, reason := p.Decide("GET", c.path, c.id); ok != c.ok || reason != c.reason {
			t.Errorf("%s for %s: %v %s, want %v %s", c.path, c.id.Subject, ok, reason, c.ok, c.reason)
		}
	}
}

func TestClaimConditionProblems(t *testing.T) {
	doc := `{
  "public_url": "https://auth.example.com",
  "providers": [
    {"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "SECRET"}
  ],
  "apps": [
    {"id": "wiki", "hosts": ["wiki.example.com"], "providers": ["corp"],
     "allow": {"any_user": true, "claims": [{"claim": "tenant", "equals": "acme"}, {"claim": "", "equals": "x"}]},
     "paths": [
       {"path": "/a", "allow": {"claims": [{"claim": "ok", "equals": "v"}, {"claim": "d", "equals": "x", "in": ["y"]}, {"claim": "e", "matches": "x\\"}]}},
       {"path": "/b", "public": true, "allow": {"claims": [{"claim": "d", "equals": "x"}]}},
       {"path": "/c", "allow": {"claims": [{"claim": "d", "in": ["x", "x"]}, {"claim": "d", "equals": "y", "matchs": "z"}]}}
     ]}
  ]
}`
	ps := checkDoc(t, doc)
	expect(t, ps,
		want{"$.apps[0].allow.claims[1]", SeverityError, "a claim name is 1 to 256 bytes"},
		want{"$.apps[0].paths[0].allow.claims[1]", SeverityError, `claim "d": give exactly one of equals, in or matches`},
		want{"$.apps[0].paths[0].allow.claims[2]", SeverityError, `ends in a lone '\'`},
		want{"$.apps[0].paths[1]", SeverityError, "a public or deny rule takes no allow"},
		want{"$.apps[0].paths[2].allow.claims[0]", SeverityError, `in lists "x" twice`},
		want{"$.apps[0].paths[2].allow.claims[1].matchs", SeverityError, `unknown field (did you mean "matches"?)`},
	)
	// Each problem points at its condition in the file.
	for _, p := range ps {
		if p.Line == 0 {
			t.Errorf("%s has no line", p.Path)
		}
	}
	if ps[1].Line != ps[2].Line || ps[1].Column >= ps[2].Column {
		t.Errorf("claims[1] at %d:%d and claims[2] at %d:%d", ps[1].Line, ps[1].Column, ps[2].Line, ps[2].Column)
	}
}
