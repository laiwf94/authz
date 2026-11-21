package policy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/enginetest"
	"github.com/laiwf94/authz/internal/authz/store"
)

const wikiSchema = `definition user {}

definition group {
  relation member: user
}

definition space {
  relation admin: user | group#member
}

definition page {
  relation space: space
  relation editor: user | group#member
  relation viewer: user | user:*
  permission edit = editor + space->admin
  permission view = viewer + edit
}
`

// recorder wraps an engine and keeps every check it is asked.
type recorder struct {
	engine.Engine
	mu   sync.Mutex
	reqs []engine.CheckRequest
	fail error
}

func (r *recorder) Check(ctx context.Context, req engine.CheckRequest) (engine.CheckResult, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	fail := r.fail
	r.mu.Unlock()
	if fail != nil {
		return engine.CheckResult{}, fail
	}
	return r.Engine.Check(ctx, req)
}

func (r *recorder) last() engine.CheckRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reqs[len(r.reqs)-1]
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

func wikiPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := CompileApp(App{
		Rule:   Rule{Providers: []string{"corp", "partner"}, AnyUser: true},
		Public: []string{"/static"},
		Paths: []PathRule{
			{Path: "/pages/{page}", Methods: []string{"GET"}, Check: &CheckRule{Resource: "page:{path.page}", Permission: "view"}},
			{Path: "/pages/{page}", Methods: []string{"PUT", "DELETE"}, Check: &CheckRule{Resource: "page:{path.page}", Permission: "edit"}},
			// Only the ops group, and of them only space admins.
			{Path: "/spaces/{space}/settings", Groups: []string{"ops"},
				Check: &CheckRule{Resource: "space:{path.space}", Permission: "admin"}},
			// The subject is built from two claims.
			{Path: "/by-idp/{page}", Check: &CheckRule{Resource: "page:{path.page}", Permission: "view", Subject: "user:{claims.idp}.{claims.sub}"}},
			// A userset subject: the request is allowed when the group
			// named in the path is a page editor.
			{Path: "/groups/{group}/pages/{page}", Check: &CheckRule{Resource: "page:{path.page}", Permission: "edit", Subject: "group:{path.group}#member"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func wikiEngine(t *testing.T) *enginetest.Fake {
	t.Helper()
	f, err := enginetest.NewFake(wikiSchema,
		"page:home#viewer@user:*",
		"page:plan#viewer@user:alice",
		"page:plan#space@space:eng",
		"space:eng#admin@group:leads#member",
		"group:leads#member@user:carol",
		"page:spec#editor@user:bob",
		"page:spec#editor@group:writers#member",
		"page:spec#viewer@user:corp.dave",
	)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAuthorizeRelationshipRules(t *testing.T) {
	p := wikiPolicy(t)
	eng := &recorder{Engine: wikiEngine(t)}
	ctx := context.Background()
	user := func(sub string, groups ...string) *Identity {
		return &Identity{Provider: "corp", Subject: sub, Groups: groups}
	}
	cases := []struct {
		method, path string
		id           *Identity
		allowed      bool
		reason       string
		check        string // resource#permission@subject asked, "" for none
	}{
		{"GET", "/pages/home", user("anyone"), true, Allowed, "page:home#view@user:anyone"},
		{"GET", "/pages/plan", user("alice"), true, Allowed, "page:plan#view@user:alice"},
		{"GET", "/pages/plan", user("bob"), false, DeniedCheck, "page:plan#view@user:bob"},
		// Carol edits plan through space eng's admins, the leads group.
		{"PUT", "/pages/plan", user("carol"), true, Allowed, "page:plan#edit@user:carol"},
		{"PUT", "/pages/plan", user("alice"), false, DeniedCheck, "page:plan#edit@user:alice"},
		{"DELETE", "/pages/spec", user("bob"), true, Allowed, "page:spec#edit@user:bob"},
		// HEAD is GET.
		{"HEAD", "/pages/plan", user("alice"), true, Allowed, "page:plan#view@user:alice"},
		// POST matches no rule and the app-wide any_user decides.
		{"POST", "/pages/plan", user("bob"), true, Allowed, ""},
		// The groups prerequisite comes first: no engine call without it.
		{"GET", "/spaces/eng/settings", user("carol"), false, DeniedNoMatch, ""},
		{"GET", "/spaces/eng/settings", user("carol", "ops"), true, Allowed, "space:eng#admin@user:carol"},
		{"GET", "/spaces/eng/settings", user("bob", "ops"), false, DeniedCheck, "space:eng#admin@user:bob"},
		{"GET", "/by-idp/spec", user("dave"), true, Allowed, "page:spec#view@user:corp.dave"},
		{"GET", "/by-idp/spec", &Identity{Provider: "partner", Subject: "dave"}, false, DeniedCheck, "page:spec#view@user:partner.dave"},
		{"GET", "/groups/writers/pages/spec", user("x"), true, Allowed, "page:spec#edit@group:writers#member"},
		{"GET", "/groups/readers/pages/spec", user("x"), false, DeniedCheck, "page:spec#edit@group:readers#member"},
		// No session, another provider, public paths: decided without asking.
		{"GET", "/pages/home", nil, false, DeniedNoSubject, ""},
		{"GET", "/pages/home", &Identity{Provider: "other", Subject: "alice"}, false, DeniedProvider, ""},
		{"GET", "/static/x.css", nil, true, AllowedPublic, ""},
		// A path value that is no object ID is denied without asking.
		{"GET", "/pages/a%20b", user("alice"), false, DeniedCheckInput, "page:a b#view@user:alice"},
		{"GET", "/pages/" + strings.Repeat("x", 129), user("alice"), false, DeniedCheckInput, ""},
		{"GET", "/pages/plan", user("al ice"), false, DeniedCheckInput, ""},
		{"GET", "/pages/*", user("alice"), false, DeniedCheckInput, ""},
		// A subject claim of "*" is not the wildcard.
		{"GET", "/pages/home", user("*"), false, DeniedCheckInput, "page:home#view@user:*"},
	}
	for _, c := range cases {
		before := eng.count()
		m := p.Match(c.method, c.path)
		d := p.Authorize(ctx, &m, c.id, eng, "")
		if d.Allowed != c.allowed || d.Reason != c.reason {
			t.Errorf("%s %s as %v: %v %s, want %v %s (%+v)", c.method, c.path, c.id, d.Allowed, d.Reason, c.allowed, c.reason, d.Check)
			continue
		}
		asked := eng.count() > before
		if wantAsk := c.check != "" && c.reason != DeniedCheckInput; asked != wantAsk {
			t.Errorf("%s %s: engine asked %v, want %v", c.method, c.path, asked, wantAsk)
		}
		if c.check != "" {
			if d.Check == nil {
				t.Errorf("%s %s: no check trace", c.method, c.path)
				continue
			}
			q := d.Check.Request
			if got := q.ResourceType + ":" + q.ResourceID + "#" + q.Permission + "@" + q.Subject.String(); got != c.check {
				t.Errorf("%s %s: asked %s, want %s", c.method, c.path, got, c.check)
			}
		}
		if c.reason == DeniedCheckInput && (d.Check == nil || d.Check.Err == nil) {
			t.Errorf("%s %s: a bad input has no error in the trace", c.method, c.path)
		}
		if d.Check != nil && d.Check.Err == nil && d.Check.Result.At.Token == "" {
			t.Errorf("%s %s: the engine's answer has no token", c.method, c.path)
		}
		// Evaluate alone never allows a relationship rule.
		if ok, reason := p.Evaluate(&m, c.id); asked && (ok || reason != CheckRequired) {
			t.Errorf("%s %s: Evaluate %v %s, want false %s", c.method, c.path, ok, reason, CheckRequired)
		}
	}
}

// TestAuthorizeConsistency: the session's token makes the check read a
// snapshot at least as fresh, so a revocation seen once stays seen; a
// token the engine refuses is dropped for a fully consistent check.
func TestAuthorizeConsistency(t *testing.T) {
	p := wikiPolicy(t)
	f := wikiEngine(t)
	eng := &recorder{Engine: f}
	ctx := context.Background()
	alice := &Identity{Provider: "corp", Subject: "alice"}
	m := p.Match("GET", "/pages/plan")

	d := p.Authorize(ctx, &m, alice, eng, "")
	if !d.Allowed || eng.last().Consistency != (engine.Consistency{}) {
		t.Fatalf("first check: %+v, asked with %+v", d, eng.last().Consistency)
	}
	tok := d.Check.Result.At.Token

	// Alice loses the page; the write's token is newer than hers.
	w, err := f.Write(ctx, engine.WriteRequest{Updates: []store.Update{{Op: store.OpDelete,
		Relationship: store.Relationship{ResourceType: "page", ResourceID: "plan", Relation: "viewer", SubjectType: "user", SubjectID: "alice"}}}})
	if err != nil {
		t.Fatal(err)
	}
	d = p.Authorize(ctx, &m, alice, eng, tok)
	if want := (engine.Consistency{Mode: engine.AtLeastAsFresh, Token: tok}); eng.last().Consistency != want {
		t.Fatalf("asked with %+v, want %+v", eng.last().Consistency, want)
	}
	if d.Allowed || d.Reason != DeniedCheck || d.Check.Result.At.Revision < w.At.Revision || d.Check.Retried {
		t.Fatalf("after the delete: %+v %+v", d, d.Check)
	}

	// A token from another key is refused and the check asked again
	// fully consistent.
	other, err := enginetest.NewFake(wikiSchema)
	if err != nil {
		t.Fatal(err)
	}
	foreign := other.Tokens().Encode(1)
	foreign = foreign[:len(foreign)-2] + "AA"
	before := eng.count()
	d = p.Authorize(ctx, &m, alice, eng, foreign)
	if !d.Check.Retried || eng.count()-before != 2 || eng.last().Consistency != (engine.Consistency{Mode: engine.FullyConsistent}) {
		t.Fatalf("foreign token: %+v, %d calls, last %+v", d.Check, eng.count()-before, eng.last().Consistency)
	}
	if d.Reason != DeniedCheck {
		t.Fatalf("foreign token: %s", d.Reason)
	}
	// So is a token from a revision the engine has not reached.
	ahead := f.Tokens().Encode(f.Head() + 10)
	if d := p.Authorize(ctx, &m, alice, eng, ahead); !d.Check.Retried || d.Reason != DeniedCheck {
		t.Fatalf("token ahead: %+v", d.Check)
	}
	// An oversized token is not sent at all.
	before = eng.count()
	if d := p.Authorize(ctx, &m, alice, eng, strings.Repeat("a", MaxTokenBytes+1)); d.Check.Retried || eng.count()-before != 1 ||
		eng.last().Consistency != (engine.Consistency{}) {
		t.Fatalf("oversized token: %+v", d.Check)
	}
}

func TestAuthorizeUnavailable(t *testing.T) {
	p := wikiPolicy(t)
	ctx := context.Background()
	alice := &Identity{Provider: "corp", Subject: "alice"}
	m := p.Match("GET", "/pages/plan")
	if d := p.Authorize(ctx, &m, alice, nil, ""); d.Allowed || d.Reason != CheckUnavailable || d.Check.Err == nil ||
		d.Check.Request.ResourceID != "plan" {
		t.Fatalf("no engine: %+v %+v", d, d.Check)
	}
	f := wikiEngine(t)
	down := errors.Join(store.ErrUnavailable, errors.New("disk on fire"))
	f.Fail(down)
	if d := p.Authorize(ctx, &m, alice, f, ""); d.Allowed || d.Reason != CheckUnavailable || !errors.Is(d.Check.Err, store.ErrUnavailable) {
		t.Fatalf("failing engine: %+v %+v", d, d.Check)
	}
	// A failure is not retried, even with a token.
	eng := &recorder{Engine: wikiEngine(t), fail: down}
	if d := p.Authorize(ctx, &m, alice, eng, "tok"); d.Check.Retried || eng.count() != 1 || d.Reason != CheckUnavailable {
		t.Fatalf("failing engine with a token: %+v, %d calls", d.Check, eng.count())
	}
	// A check that only holds under caveat parameters nobody gave is not
	// an allow.
	cf := enginetest.NewLocal(t, `caveat office(allowed cidr, client_ip ipaddress) { allowed.containsIP(client_ip) }

definition user {}

definition page {
  relation viewer: user with office
  permission view = viewer
}
`, engine.Options{})
	if _, err := cf.Write(ctx, engine.WriteRequest{Updates: []store.Update{{Op: store.OpTouch,
		Relationship: store.Relationship{ResourceType: "page", ResourceID: "plan", Relation: "viewer", SubjectType: "user", SubjectID: "alice"},
		Caveat:       &store.Caveat{Name: "office", Context: map[string]any{"allowed": "10.0.0.0/8"}}}}}); err != nil {
		t.Fatal(err)
	}
	if d := p.Authorize(ctx, &m, alice, cf, ""); d.Allowed || d.Reason != DeniedCheckConditional || len(d.Check.Result.Missing) != 1 {
		t.Fatalf("conditional: %+v %+v", d, d.Check)
	}
	// A schema without the resource's type is the engine's error, an
	// outage of this rule rather than a denial.
	sf, err := enginetest.NewFake("definition user {}\n")
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Authorize(ctx, &m, alice, sf, ""); d.Reason != CheckUnavailable || d.Check.Err == nil {
		t.Fatalf("unknown type: %+v %+v", d, d.Check)
	}
}

func TestCheckRuleProblems(t *testing.T) {
	cases := []struct {
		rule PathRule
		want string
	}{
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Permission: "view"}}, "check.resource is required"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc", Permission: "view"}}, "must be type:id"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "Doc:{path.id}", Permission: "view"}}, `type "Doc"`},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:{path.id}", Permission: "View"}}, "check.permission"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:{path.id}"}}, "check.permission"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:{path.doc}", Permission: "view"}}, "has no {doc} parameter"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:{claims.email}", Permission: "view"}}, "unknown variable {claims.email}"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:{path.id", Permission: "view"}}, "'{' without '}'"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:path.id}", Permission: "view"}}, "'}' without '{'"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:", Permission: "view"}}, "the id is empty"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:a b{path.id}", Permission: "view"}}, "object ID characters"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:*", Permission: "view"}}, "object ID characters"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:{path.id}", Permission: "view", Subject: "user:*"}}, "object ID characters"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:x*{path.id}", Permission: "view"}}, "object ID characters"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:{path.id}#viewer", Permission: "view"}}, "without #relation"},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:{path.id}", Permission: "view", Subject: "group:{path.id}#Member"}}, `relation "Member"`},
		{PathRule{Path: "/d/{id}", Check: &CheckRule{Resource: "doc:{path.id}", Permission: "view", Subject: "{claims.sub}"}}, "must be type:id"},
		{PathRule{Path: "/d/{id}", Public: true, Check: &CheckRule{Resource: "doc:{path.id}", Permission: "view"}}, "takes no check"},
		{PathRule{Path: "/d/{id}", Deny: true, Check: &CheckRule{Resource: "doc:{path.id}", Permission: "view"}}, "takes no check"},
	}
	for _, c := range cases {
		_, err := CompileApp(App{Rule: Rule{Providers: []string{"corp"}}, Paths: []PathRule{c.rule}})
		var re *RuleError
		if err == nil || !errors.As(err, &re) || re.Rule != "paths[0]" || !strings.Contains(re.Msg, c.want) {
			t.Errorf("%+v: %v, want paths[0]: ...%s...", c.rule.Check, err, c.want)
		}
	}
	// What is allowed: literal text around variables, a rule without
	// parameters.
	for _, ok := range []CheckRule{
		{Resource: "doc:v1.{path.id}-draft", Permission: "view", Subject: "user:{claims.idp}|{claims.sub}"},
		{Resource: "site:main", Permission: "admin"},
	} {
		ok := ok
		p, err := CompileApp(App{Rule: Rule{Providers: []string{"corp"}}, Paths: []PathRule{{Path: "/d/{id}", Check: &ok}}})
		if err != nil || !p.HasChecks() {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	if p, _ := CompileApp(App{Rule: Rule{Providers: []string{"corp"}}, Paths: []PathRule{{Path: "/d", AnyUser: true}}}); p.HasChecks() {
		t.Error("a policy without check rules reports checks")
	}
}

func TestCheckForTemplates(t *testing.T) {
	p, err := CompileApp(App{Rule: Rule{Providers: []string{"corp"}}, Paths: []PathRule{
		{Path: "/o/{org}/d/{doc}", Check: &CheckRule{Resource: "doc:{path.org}/{path.doc}", Permission: "view", Subject: "user:{claims.idp}|{claims.sub}"}},
		{Path: "/plain", AnyUser: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{Provider: "corp", Subject: "u-1"}
	m := p.Match("GET", "/o/acme/d/plan/history")
	req, ok, err := p.CheckFor(&m, id)
	if !ok || err != nil || req.ResourceID != "acme/plan" || req.Subject != (store.Subject{Type: "user", ID: "corp|u-1"}) {
		t.Fatalf("%+v %v %v", req, ok, err)
	}
	// An empty claim leaves nothing to ask.
	if _, _, err := p.CheckFor(&m, &Identity{Provider: "corp"}); err == nil {
		t.Fatal("an empty subject built a check")
	}
	if _, ok, _ := p.CheckFor(&Match{Rule: -1}, id); ok {
		t.Fatal("the app-wide rule has a check")
	}
	m = p.Match("GET", "/plain")
	if _, ok, _ := p.CheckFor(&m, id); ok {
		t.Fatal("a plain rule has a check")
	}
}
