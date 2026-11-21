package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/laiwf94/authz/internal/authz/engine"
	"github.com/laiwf94/authz/internal/authz/enginetest"
	"github.com/laiwf94/authz/internal/authz/store"
)

const docsSchema = `definition user {}

definition doc {
  relation editor: user
  relation viewer: user
  permission edit = editor
  permission view = viewer + edit
}
`

// checkRules gives the whoami app relationship rules: reading a doc needs
// view on it, writing needs edit, and both are asked of the engine.
func checkRules(cfg map[string]any) {
	app := cfg["apps"].([]any)[0].(map[string]any)
	app["allow"] = map[string]any{"any_user": true}
	app["paths"] = []any{
		map[string]any{"path": "/docs/{id}", "methods": []string{"GET"},
			"check": map[string]any{"resource": "doc:{path.id}", "permission": "view"}},
		map[string]any{"path": "/docs/{id}", "methods": []string{"PUT"},
			"check": map[string]any{"resource": "doc:{path.id}", "permission": "edit"}},
	}
}

// checkEngine records the consistency of every check it passes on.
type checkEngine struct {
	engine.Engine
	mu   sync.Mutex
	seen []engine.Consistency
	fail error
}

func (e *checkEngine) Check(ctx context.Context, req engine.CheckRequest) (engine.CheckResult, error) {
	e.mu.Lock()
	e.seen = append(e.seen, req.Consistency)
	fail := e.fail
	e.mu.Unlock()
	if fail != nil {
		return engine.CheckResult{}, fail
	}
	return e.Engine.Check(ctx, req)
}

func (e *checkEngine) last() engine.Consistency {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.seen[len(e.seen)-1]
}

func TestForwardAuthRelationshipRules(t *testing.T) {
	h := newHarness(t, harnessOpts{cfgMutate: checkRules})
	f, err := enginetest.NewFake(docsSchema, "doc:plan#viewer@user:alice", "doc:spec#editor@user:bob")
	if err != nil {
		t.Fatal(err)
	}
	eng := &checkEngine{Engine: f}
	var engErr error
	h.srv.opts.Engine = func(context.Context) (engine.Engine, error) {
		if engErr != nil {
			return nil, engErr
		}
		return eng, nil
	}
	ctx := context.Background()

	alice, bob := h.browser(), h.browser()
	alice.loginOIDC("alice", "alice-pass", "")
	bob.loginOIDC("bob", "bob-pass", "")
	put := http.Header{"X-Forwarded-Method": {"PUT"}}

	// Signed out: sign in first, without asking the engine.
	if resp := h.browser().auth("/docs/plan", nil); resp.StatusCode != http.StatusUnauthorized || len(eng.seen) != 0 {
		t.Fatalf("anonymous: %d, %d checks", resp.StatusCode, len(eng.seen))
	}
	if resp := alice.auth("/docs/plan", nil); resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderUser) != "alice" {
		t.Fatalf("alice GET plan: %d", resp.StatusCode)
	}
	// Her first check reads a recent snapshot; its token is kept in her
	// session, and her next check is at least as fresh.
	if c := eng.last(); c != (engine.Consistency{}) {
		t.Fatalf("first check asked with %+v", c)
	}
	sess := h.sessions.UserSessions("corp", "alice")[0]
	tok := sess.ConsistencyToken()
	if tok == "" {
		t.Fatal("the session kept no token")
	}
	if resp := alice.auth("/docs/plan", put); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alice PUT plan: %d", resp.StatusCode)
	}
	if c := eng.last(); c != (engine.Consistency{Mode: engine.AtLeastAsFresh, Token: tok}) {
		t.Fatalf("second check asked with %+v, want at least as fresh as %s", c, tok)
	}
	h.expectAudit("access_denied", "check_denied")
	if !strings.Contains(h.logs.String(), `"check":"doc:plan#edit@user:alice"`) || !strings.Contains(h.logs.String(), `"rule":"paths[1]"`) {
		t.Fatalf("the denial does not name the rule and check:\n%s", h.logs.String())
	}
	if resp := bob.auth("/docs/spec", put); resp.StatusCode != http.StatusOK || resp.Header.Get(HeaderUser) != "bob" {
		t.Fatalf("bob PUT spec: %d", resp.StatusCode)
	}
	if resp := bob.auth("/docs/spec", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("bob GET spec (edit implies view): %d", resp.StatusCode)
	}
	// Other paths are decided by the app-wide rule alone.
	n := len(eng.seen)
	if resp := bob.auth("/elsewhere", nil); resp.StatusCode != http.StatusOK || len(eng.seen) != n {
		t.Fatalf("bob /elsewhere: %d, %d new checks", resp.StatusCode, len(eng.seen)-n)
	}
	// A path value that is not an object ID is denied without asking.
	if resp := bob.auth("/docs/a%20b", nil); resp.StatusCode != http.StatusForbidden || len(eng.seen) != n {
		t.Fatalf("bob /docs/a%%20b: %d", resp.StatusCode)
	}
	h.expectAudit("access_denied", "check_bad_input")

	// Alice is given edit: the write's token is newer than hers, and her
	// next check sees it. Then she loses view, and the next denies.
	w, err := f.Write(ctx, engine.WriteRequest{Updates: []store.Update{{Op: store.OpTouch,
		Relationship: store.Relationship{ResourceType: "doc", ResourceID: "plan", Relation: "editor", SubjectType: "user", SubjectID: "alice"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if resp := alice.auth("/docs/plan", put); resp.StatusCode != http.StatusOK {
		t.Fatalf("alice PUT plan after the grant: %d", resp.StatusCode)
	}
	if got := h.sessions.UserSessions("corp", "alice")[0].ConsistencyToken(); got != w.At.Token {
		t.Fatalf("the session's token is %s, want the grant's %s", got, w.At.Token)
	}
	if _, err := f.Write(ctx, engine.WriteRequest{Updates: []store.Update{
		{Op: store.OpDelete, Relationship: store.Relationship{ResourceType: "doc", ResourceID: "plan", Relation: "editor", SubjectType: "user", SubjectID: "alice"}},
		{Op: store.OpDelete, Relationship: store.Relationship{ResourceType: "doc", ResourceID: "plan", Relation: "viewer", SubjectType: "user", SubjectID: "alice"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if resp := alice.auth("/docs/plan", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alice GET plan after the revocation: %d", resp.StatusCode)
	}

	// The engine failing, or missing, is an outage: 503, logged as an
	// error, and not an access denial.
	audits := strings.Count(h.logs.String(), `"event":"access_denied"`)
	eng.fail = errors.Join(store.ErrUnavailable, errors.New("disk on fire"))
	if resp := bob.auth("/docs/spec", nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("failing engine: %d", resp.StatusCode)
	}
	eng.fail = nil
	engErr = errors.New("no in-process engine: run authz run with its serve part")
	if resp := bob.auth("/docs/spec", nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("no engine: %d", resp.StatusCode)
	}
	h.srv.opts.Engine = nil
	if resp := bob.auth("/docs/spec", nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("no engine option: %d", resp.StatusCode)
	}
	logs := h.logs.String()
	if got := strings.Count(logs, `"event":"access_denied"`); got != audits {
		t.Fatalf("an outage was audited as a denial (%d, want %d)", got, audits)
	}
	for _, want := range []string{`"msg":"relationship check failed"`, "disk on fire", "run authz run with its serve part", "no authorization engine"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("logs lack %q:\n%s", want, logs)
		}
	}

	var buf bytes.Buffer
	if err := h.srv.m.Write(&buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`wicket_relationship_checks_total{result="allowed"} 4`,
		`wicket_relationship_checks_total{result="check_denied"} 2`,
		`wicket_relationship_checks_total{result="check_bad_input"} 1`,
		`wicket_relationship_checks_total{result="check_unavailable"} 3`,
		`wicket_auth_decisions_total{decision="unavailable"} 3`,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("metrics lack %s:\n%s", want, buf.String())
		}
	}
}
