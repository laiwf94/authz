package config

import (
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authn/policy"
)

const pathsDoc = `{
  "public_url": "https://auth.example.com",
  "providers": [
    {"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "SECRET"}
  ],
  "apps": [
    {"id": "wiki", "hosts": ["wiki.example.com"], "providers": ["corp"], "allow": {"any_user": true},
     "public": ["/static", "/"],
     "paths": [
       {"path": "/wiki", "methods": ["GET"], "public": true},
       {"path": "/admin", "allow": {"groups": ["admins"]}},
       {"path": "/admin/audit", "methods": ["DELETE"], "deny": true},
       {"path": "/docs/{doc}/edit", "exact": true, "allow": {"emails": ["a@example.com"], "email_domains": ["example.com"]}}
     ]}
  ]
}`

func TestPathRules(t *testing.T) {
	c, err := Parse([]byte(pathsDoc), getenvSecret)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Apps[0].Policy()
	if err != nil {
		t.Fatal(err)
	}
	m := p.Match("GET", "/docs/d1/edit")
	if p.RuleName(m.Rule) != "paths[3]" || m.Params[0] != "d1" {
		t.Fatalf("matched %s %v", p.RuleName(m.Rule), m.Params)
	}
	if m := p.Match("GET", "/static/x.css"); p.RuleName(m.Rule) != "public[0]" || !m.Public {
		t.Fatalf("matched %s", p.RuleName(m.Rule))
	}
	if m := p.Match("DELETE", "/admin/audit"); p.RuleName(m.Rule) != "paths[2]" {
		t.Fatalf("matched %s", p.RuleName(m.Rule))
	}
	// The original file without paths still has none.
	c, err = Parse([]byte(goodDoc), getenvSecret)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := c.Apps[0].Policy(); err != nil || p.HasPathRules() {
		t.Fatalf("goodDoc: %v %v", p, err)
	}
}

func TestPathRuleProblems(t *testing.T) {
	doc := `{
  "public_url": "https://auth.example.com",
  "providers": [
    {"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "SECRET"}
  ],
  "apps": [
    {"id": "wiki", "hosts": ["wiki.example.com"], "providers": ["corp"], "allow": {"any_user": true},
     "public": ["static", "/ok"],
     "paths": [
       {"path": "/ok", "allow": {"any_user": true}},
       {"path": "/a", "methods": ["FETCH"], "deny": true},
       {"path": "/b", "public": true, "allow": {"groups": ["x"]}},
       {"path": "/c"},
       {"path": "/d", "allow": {"emails": ["nobody"], "email_domains": ["@x"]}},
       {"path": "/e/{Id}", "deny": true},
       {"path": "/f", "deny": true, "exect": true}
     ]}
  ]
}`
	ps := checkDoc(t, doc)
	expect(t, ps,
		want{"$.apps[0].public[0]", SeverityError, `path "static" must start with '/'`},
		want{"$.apps[0].public[1]", SeverityError, `pattern "/ok" overlaps paths[0] ("/ok")`},
		want{"$.apps[0].paths[1]", SeverityError, `unknown method "FETCH"`},
		want{"$.apps[0].paths[2]", SeverityError, "a public or deny rule takes no allow"},
		want{"$.apps[0].paths[3].allow", SeverityWarning, "nobody is allowed"},
		want{"$.apps[0].paths[4].allow.emails[0]", SeverityError, `"nobody" is not an email address`},
		want{"$.apps[0].paths[4].allow.email_domains[0]", SeverityError, "should look like example.com"},
		want{"$.apps[0].paths[5]", SeverityError, "a parameter is a whole segment {name}"},
		want{"$.apps[0].paths[6].exect", SeverityError, `unknown field (did you mean "exact"?)`},
	)
}

func TestPathCheckRules(t *testing.T) {
	doc := `{
  "public_url": "https://auth.example.com",
  "providers": [
    {"id": "corp", "type": "oidc", "issuer": "https://idp.example.com", "client_id": "c", "client_secret_env": "SECRET"}
  ],
  "apps": [
    {"id": "wiki", "hosts": ["wiki.example.com"], "providers": ["corp"], "allow": {"any_user": true},
     "paths": [
       {"path": "/docs/{id}", "methods": ["PUT"], "check": {"resource": "doc:{path.id}", "permission": "edit"}},
       {"path": "/docs/{id}", "methods": ["GET"], "allow": {"groups": ["staff"]},
        "check": {"resource": "doc:{path.id}", "permission": "view", "subject": "user:{claims.idp}.{claims.sub}"}},
       {"path": "/x/{id}", "check": {"resource": "doc:{path.doc}", "permission": "view"}},
       {"path": "/y", "deny": true, "check": {"resource": "doc:y", "permission": "view"}},
       {"path": "/z", "check": {"resource": "doc:z", "permision": "view"}}
     ]}
  ]
}`
	ps := checkDoc(t, doc)
	// The first two are clean: a check rule naming nobody asks the engine
	// for everyone, so there is no "nobody is allowed" warning.
	expect(t, ps,
		want{"$.apps[0].paths[2]", SeverityError, "the rule's path has no {doc} parameter"},
		want{"$.apps[0].paths[3]", SeverityError, "a public or deny rule takes no check"},
		want{"$.apps[0].paths[4]", SeverityError, `check.permission "" must be a relation or permission name`},
		want{"$.apps[0].paths[4].check.permision", SeverityError, `unknown field (did you mean "permission"?)`},
	)

	good := doc[:strings.Index(doc, `,
       {"path": "/x/{id}"`)] + "]}]}"
	c, err := Parse([]byte(good), getenvSecret)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Apps[0].Policy()
	if err != nil || !p.HasChecks() {
		t.Fatalf("%v %v", p, err)
	}
	m := p.Match("GET", "/docs/plan")
	req, ok, err := p.CheckFor(&m, &policy.Identity{Provider: "corp", Subject: "alice", Groups: []string{"staff"}})
	if !ok || err != nil || req.ResourceID != "plan" || req.Permission != "view" || req.Subject.ID != "corp.alice" {
		t.Fatalf("%+v %v %v", req, ok, err)
	}
}
