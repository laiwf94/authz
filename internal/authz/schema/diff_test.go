package schema

import (
	"fmt"
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Schema {
	t.Helper()
	s, err := Parse(src)
	if err != nil {
		t.Fatalf("%v\n%s", err, src)
	}
	return s
}

func renderChanges(cs []Change) string {
	var b strings.Builder
	for _, c := range cs {
		fmt.Fprintf(&b, "%s %s %s", c.Kind, c.Object, c.Name)
		if c.Detail != "" {
			fmt.Fprintf(&b, ": %s", c.Detail)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func TestCompareIdenticalAndReordered(t *testing.T) {
	a := mustParse(t, docs)
	if d := Compare(a, mustParse(t, docs)); len(d.Changes) != 0 || len(d.Affected) != 0 {
		t.Fatalf("same schema: %+v", d)
	}
	// Definition order, member order and the order of allowed subjects
	// change nothing a check can see.
	reordered := `
definition document {
  permission view = (viewer + edit + parent->view) - banned
  permission edit = owner + editor
  relation banned: user
  relation viewer: group#member | user
  relation editor: group#member | user
  relation owner: user
  relation parent: folder
}
definition folder {
  permission view = viewer + parent->view
  relation viewer: group#member | user | user:*
  relation parent: folder
}
definition group { relation member: group#member | user }
definition user {}
`
	if d := Compare(a, mustParse(t, reordered)); len(d.Changes) != 0 || len(d.Affected) != 0 {
		t.Fatalf("reordered: %s %v", renderChanges(d.Changes), d.Affected)
	}
}

func TestCompareFromNothing(t *testing.T) {
	d := Compare(nil, mustParse(t, docs))
	want := "added definition user\nadded definition group\nadded definition folder\nadded definition document\n"
	if got := renderChanges(d.Changes); got != want || len(d.Affected) != 0 || d.Affected == nil {
		t.Fatalf("got\n%s%v", got, d.Affected)
	}
}

func TestCompareChanges(t *testing.T) {
	prev := mustParse(t, `
definition user {}
definition team { relation member: user }
definition group {
  relation member: user | group#member
}
definition folder {
  relation parent: folder
  relation viewer: user | group#member
  permission view = viewer + parent->view
}
definition doc {
  relation parent: folder
  relation owner: user
  relation editor: user
  relation viewer: user
  relation banned: user
  permission edit = owner + editor
  permission view = (viewer + edit + parent->view) - banned
  permission comment = viewer
  permission audit = owner
}`)
	next := mustParse(t, `
definition user {}
definition group {
  relation member: user | group#member
  permission everyone = member
}
definition folder {
  relation parent: folder
  relation viewer: user | user:* | group#member
  permission view = viewer + parent->view
}
definition doc {
  relation parent: folder
  relation owner: user
  permission editor = owner
  relation viewer: user
  permission edit = owner + editor
  permission view = (viewer + edit + parent->view) - banned
  permission comment = viewer
  relation banned: user | group#member
  relation reviewer: user
}
definition report {
  relation doc: doc
  permission read = doc->view
}`)
	d := Compare(prev, next)
	want := `added permission group#everyone
changed relation folder#viewer: group#member | user -> group#member | user | user:*
changed permission doc#editor: relation -> permission
changed relation doc#banned: user -> group#member | user
added relation doc#reviewer
removed permission doc#audit
added definition report
removed definition team
`
	if got := renderChanges(d.Changes); got != want {
		t.Fatalf("changes:\n%s\nwant:\n%s", got, want)
	}
	// folder#viewer reaches folder#view and, across parent->view, doc#view;
	// doc#editor reaches doc#edit and doc#view. doc#comment reads only
	// doc#viewer, which did not change, and report#read and
	// group#everyone are new.
	if got := strings.Join(d.Affected, " "); got != "folder#view doc#edit doc#view" {
		t.Fatalf("affected: %s", got)
	}
}

func TestCompareExpressionChange(t *testing.T) {
	prev := mustParse(t, docs)
	next := mustParse(t, strings.Replace(docs, "permission edit = owner + editor", "permission edit = owner", 1))
	d := Compare(prev, next)
	if got := renderChanges(d.Changes); got != "changed permission document#edit: owner + editor -> owner\n" {
		t.Fatalf("changes: %s", got)
	}
	if got := strings.Join(d.Affected, " "); got != "document#edit document#view" {
		t.Fatalf("affected: %s", got)
	}
}

// A change to a relation or permission that a userset names reaches every
// relation allowing that userset and the permissions reading them,
// through chains of usersets and arrows in any definition order.
func TestCompareFollowsUsersetsAndArrows(t *testing.T) {
	src := `
definition doc {
  relation folder: folder
  permission view = folder->see
}
definition folder {
  relation reader: role#holder
  permission see = reader
}
definition role {
  relation grantee: user
  relation blocked: user
  permission holder = grantee - blocked
}
definition user {}
definition other {
  relation reader: user
  permission see = reader
}`
	prev := mustParse(t, src)
	next := mustParse(t, strings.Replace(src, "permission holder = grantee - blocked", "permission holder = grantee", 1))
	d := Compare(prev, next)
	if got := strings.Join(d.Affected, " "); got != "doc#view folder#see role#holder" {
		t.Fatalf("affected: %s (changes %s)", got, renderChanges(d.Changes))
	}
	// Dependency cycles through data still terminate.
	cyc := `
definition user {}
definition group {
  relation member: user | group#member
  relation ban: user
  permission active = member - ban
}`
	d = Compare(mustParse(t, cyc), mustParse(t, strings.Replace(cyc, "relation member: user | group#member", "relation member: user | group#active", 1)))
	if got := strings.Join(d.Affected, " "); got != "group#active" {
		t.Fatalf("cycle: %s", got)
	}
}
