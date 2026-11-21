package config

import (
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authn/policy"
)

func TestPathStepUpRules(t *testing.T) {
	doc := `{
  "public_url": "https://auth.example.com",
  "providers": [
    {"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "SECRET"}
  ],
  "apps": [
    {"id": "wiki", "hosts": ["wiki.example.com"], "providers": ["corp"], "allow": {"any_user": true},
     "paths": [
       {"path": "/admin", "allow": {"groups": ["admins"]}, "step_up": {"max_age": "15m"}},
       {"path": "/admin/keys", "allow": {"groups": ["admins"]}, "step_up": {"max_age": "1h", "acr_values": ["urn:mfa"]}},
       {"path": "/docs/{id}", "methods": ["PUT"], "check": {"resource": "doc:{path.id}", "permission": "edit"},
        "step_up": {"acr_values": ["urn:mfa", "urn:hwk"]}},
       {"path": "/a", "allow": {"any_user": true}, "step_up": {"max_age": "30s"}},
       {"path": "/b", "public": true, "step_up": {"max_age": "1h"}},
       {"path": "/c", "allow": {"any_user": true}, "step_up": {"acr_values": []}},
       {"path": "/d", "allow": {"any_user": true}, "step_up": {"acr_values": ["two words"]}},
       {"path": "/e", "allow": {"any_user": true}, "step_up": {"max_age": 60}},
       {"path": "/f", "allow": {"any_user": true}, "step_up": {"maxage": "1h"}}
     ]}
  ]
}`
	ps := checkDoc(t, doc)
	expect(t, ps,
		want{"$.apps[0].paths[3]", SeverityError, "step_up max_age 30s must be between 1m0s and 720h0m0s"},
		want{"$.apps[0].paths[4]", SeverityError, "a public or deny rule takes no step_up"},
		want{"$.apps[0].paths[5]", SeverityError, "step_up needs max_age, acr_values or both"},
		want{"$.apps[0].paths[6]", SeverityError, `step_up acr value "two words" must be`},
		want{"$.apps[0].paths[7].step_up.max_age", SeverityError, `must be a duration string like "90s" or "8h", not a number`},
		want{"$.apps[0].paths[8].step_up.maxage", SeverityError, `unknown field (did you mean "max_age"?)`},
	)

	good := doc[:strings.Index(doc, `,
       {"path": "/a"`)] + "]}]}"
	c, err := Parse([]byte(good), getenvSecret)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Apps[0].Policy()
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		method, path string
		want         policy.StepUp
	}{
		{"GET", "/admin/users", policy.StepUp{MaxAge: 15 * time.Minute}},
		{"GET", "/admin/keys", policy.StepUp{MaxAge: time.Hour, ACRValues: []string{"urn:mfa"}}},
		{"PUT", "/docs/plan", policy.StepUp{ACRValues: []string{"urn:mfa", "urn:hwk"}}},
	} {
		m := p.Match(x.method, x.path)
		su := p.StepUp(&m)
		if su == nil || su.MaxAge != x.want.MaxAge || strings.Join(su.ACRValues, " ") != strings.Join(x.want.ACRValues, " ") {
			t.Errorf("%s %s: %+v, want %+v", x.method, x.path, su, x.want)
		}
	}
	if m := p.Match("GET", "/docs/plan"); p.StepUp(&m) != nil {
		t.Fatal("GET /docs/plan has a step-up")
	}
}
