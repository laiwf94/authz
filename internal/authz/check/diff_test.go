package check

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
)

// schema.Compare's affected permissions are sound: on random data valid
// under both schemas, every permission it leaves out answers every check
// the same under the old schema and the new one. Each variant that is not
// conservative must also change at least one answer of a permission it
// lists, so the variants exercise the walk rather than pass trivially.
func TestCompareAffectedIsSound(t *testing.T) {
	type edit struct{ from, to string }
	variants := []struct {
		name     string
		edits    []edit
		affected string
		// conservative variants list permissions no stored data can
		// change yet: a relation gains a subject type nothing uses.
		conservative bool
	}{
		{"folder view", []edit{{"permission view = viewer + parent->view", "permission view = viewer"}},
			"folder#view doc#view doc#both", false},
		{"doc edit", []edit{{"permission edit = owner + editor", "permission edit = owner"}},
			"doc#edit doc#view doc#both", false},
		{"doc view", []edit{{"permission view = (viewer + edit + parent->view) - banned", "permission view = viewer + edit + parent->view"}},
			"doc#view", false},
		{"doc both", []edit{{"permission both = edit & parent->view", "permission both = edit + parent->view"}},
			"doc#both", false},
		{"group admins", []edit{{"relation member: user | group#member\n}", "relation member: user | group#member\n  relation admin: user\n  permission member_or_admin = member + admin\n}"}},
			"", false},
		{"folder admins", []edit{
			{"relation member: user | group#member\n}", "relation member: user | group#member\n  relation admin: user\n}"},
			{"relation viewer: user | user:* | group#member\n", "relation viewer: user | user:* | group#member | group#admin\n"}},
			"folder#view doc#view doc#both", true},
	}
	prev, err := schema.Parse(model)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range variants {
		src := model
		for _, e := range v.edits {
			if !strings.Contains(src, e.from) {
				t.Fatalf("%s: %q is not in the model", v.name, e.from)
			}
			src = strings.Replace(src, e.from, e.to, 1)
		}
		next, err := schema.Parse(src)
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		d := schema.Compare(prev, next)
		if got := strings.Join(d.Affected, " "); got != v.affected {
			t.Fatalf("%s: affected %q, want %q", v.name, got, v.affected)
		}
		listed := map[string]bool{}
		for _, a := range d.Affected {
			listed[a] = true
		}
		differed := map[string]bool{}
		for seed := int64(0); seed < 25; seed++ {
			rng := rand.New(rand.NewSource(seed))
			users, groups, folders, docs := 5, 2+rng.Intn(4), 2+rng.Intn(4), 6
			w := randomWorld(rng, users, groups, folders, docs)
			f := newFixture(t, nil, w.rels...)
			rev := f.st.Head()
			objects := map[string]int{"group": groups, "folder": folders, "doc": docs}
			prefix := map[string]string{"group": "g", "folder": "f", "doc": "d"}
			for _, typ := range []string{"group", "folder", "doc"} {
				for _, perm := range prev.Defs[typ].Order {
					if !prev.Defs[typ].IsPermission(perm) || !next.Defs[typ].IsPermission(perm) {
						continue
					}
					name := typ + "#" + perm
					for o := 0; o < objects[typ]; o++ {
						for u := 0; u < users; u++ {
							q := Request{ResourceType: typ, ResourceID: fmt.Sprintf("%s%d", prefix[typ], o), Permission: perm,
								Subject: store.Subject{Type: "user", ID: fmt.Sprintf("u%d", u)}}
							before, _, err := f.eng.Check(context.Background(), prev, rev, q)
							if err != nil {
								t.Fatal(err)
							}
							after, _, err := f.eng.Check(context.Background(), next, rev, q)
							if err != nil {
								t.Fatal(err)
							}
							if before == after {
								continue
							}
							if !listed[name] {
								t.Fatalf("%s, seed %d: %s:%s#%s@%s changed from %v to %v, but %s is not affected (%v)",
									v.name, seed, typ, q.ResourceID, perm, q.Subject, before, after, name, d.Affected)
							}
							differed[name] = true
						}
					}
				}
			}
		}
		if len(d.Affected) > 0 && !v.conservative && len(differed) == 0 {
			t.Errorf("%s: no listed permission answered differently on any seed", v.name)
		}
	}
}
