package store

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// A dry run lists exactly the relationships WriteSchema refuses over, in
// text order, counts them past the limit, and changes nothing.
func TestDryRunSchema(t *testing.T) {
	s := newStore(t, t.TempDir())
	if res, err := s.DryRunSchema(testSchema, 0); err != nil || res.Previous != nil || res.BrokenCount != 0 || res.Revision != 0 {
		t.Fatalf("before any schema: %+v %v", res, err)
	}
	withSchema(t, s)
	head := write(t, s, OpTouch,
		"doc:b#viewer@user:*", "doc:a#viewer@user:*", "doc:a#viewer@group:eng#member",
		"doc:a#owner@user:olga", "group:eng#member@user:alice")

	// No group type, no wildcard on viewer, and owner turned into a permission.
	next := `
definition user {}
definition doc {
  relation viewer: user
  relation editor: user
  permission owner = editor
  permission view = viewer + owner
}`
	res, err := s.DryRunSchema(next, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != head || res.Previous == nil || !res.Previous.Defs["group"].IsRelation("member") || res.Schema.Defs["group"] != nil {
		t.Fatalf("snapshot: %+v", res)
	}
	var got []string
	for _, b := range res.Broken {
		got = append(got, b.Relationship.String()+": "+b.Reason)
	}
	want := []string{
		`doc:a#owner@user:olga: doc#owner is a permission; relationships can only be written to relations`,
		`doc:a#viewer@group:eng#member: doc#viewer does not allow group#member (allowed: user)`,
		`doc:a#viewer@user:*: doc#viewer does not allow user:* (allowed: user)`,
		`doc:b#viewer@user:*: doc#viewer does not allow user:* (allowed: user)`,
		`group:eng#member@user:alice: type "group" is not defined in the schema`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") || res.BrokenCount != 5 {
		t.Fatalf("broken (%d):\n%s", res.BrokenCount, strings.Join(got, "\n"))
	}
	if !strings.HasPrefix(res.Source, "definition user {}\n\ndefinition doc {") {
		t.Fatalf("canonical source: %q", res.Source)
	}

	res, err = s.DryRunSchema(next, 2)
	if err != nil || len(res.Broken) != 2 || res.BrokenCount != 5 || res.Broken[1].Relationship.String() != "doc:a#viewer@group:eng#member" {
		t.Fatalf("limit 2: %+v %v", res, err)
	}
	for _, limit := range []int{-1, MaxBrokenListed + 1} {
		if _, err := s.DryRunSchema(next, limit); !errors.Is(err, ErrInvalid) {
			t.Errorf("limit %d: %v", limit, err)
		}
	}
	if _, err := s.DryRunSchema("definition broken {", 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad schema: %v", err)
	}
	if s.Head() != head {
		t.Fatalf("a dry run moved the head from %d to %d", head, s.Head())
	}
	if _, src := s.Schema(); !strings.Contains(src, "definition group") {
		t.Fatalf("a dry run replaced the schema:\n%s", src)
	}

	// Deleted relationships are not counted.
	write(t, s, OpDelete, "doc:b#viewer@user:*")
	if res, _ := s.DryRunSchema(next, 0); res.BrokenCount != 4 {
		t.Fatalf("after a delete: %d", res.BrokenCount)
	}
}

// On random data the dry run agrees with WriteSchema: it finds nothing
// broken exactly when the write succeeds, and when it finds something, the
// write's error names the first relationship it lists.
func TestDryRunAgreesWithWriteSchema(t *testing.T) {
	variants := []string{
		testSchema,
		strings.Replace(testSchema, "user | user:* | group#member", "user | group#member", 1),
		strings.Replace(testSchema, "user | user:* | group#member", "user | user:*", 1),
		strings.Replace(testSchema, "relation owner: user", "relation owner: user | group#member", 1),
		strings.Replace(testSchema, "relation member: user | group#member", "relation member: user", 1),
		strings.Replace(testSchema, "relation owner: user\n", "", 1) + "\n",
	}
	variants[5] = strings.Replace(variants[5], "viewer + owner", "viewer", 1)
	accepted, refused := 0, 0
	for seed := int64(0); seed < 40; seed++ {
		rng := rand.New(rand.NewSource(seed))
		s := newStore(t, "")
		withSchema(t, s)
		var rels []string
		seen := map[string]bool{}
		for i := 0; i < 1+rng.Intn(12); i++ {
			switch rng.Intn(5) {
			case 0:
				rels = append(rels, fmt.Sprintf("doc:d%d#viewer@user:*", rng.Intn(4)))
			case 1:
				rels = append(rels, fmt.Sprintf("doc:d%d#viewer@group:g%d#member", rng.Intn(4), rng.Intn(3)))
			case 2:
				rels = append(rels, fmt.Sprintf("doc:d%d#owner@user:u%d", rng.Intn(4), rng.Intn(3)))
			case 3:
				rels = append(rels, fmt.Sprintf("group:g%d#member@group:g%d#member", rng.Intn(3), rng.Intn(3)))
			default:
				rels = append(rels, fmt.Sprintf("doc:d%d#viewer@user:u%d", rng.Intn(4), rng.Intn(3)))
			}
		}
		var uniq []string
		for _, r := range rels {
			if !seen[r] {
				seen[r] = true
				uniq = append(uniq, r)
			}
		}
		write(t, s, OpTouch, uniq...)
		v := variants[rng.Intn(len(variants))]
		res, err := s.DryRunSchema(v, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, werr := s.WriteSchema(v)
		switch {
		case res.BrokenCount == 0 && werr != nil:
			t.Fatalf("seed %d: dry run found nothing, write failed: %v", seed, werr)
		case res.BrokenCount > 0 && (!errors.Is(werr, ErrPrecondition) || !strings.Contains(werr.Error(), "relationship "+res.Broken[0].Relationship.String()+" ")):
			t.Fatalf("seed %d: dry run listed %v first, write said %v", seed, res.Broken[0].Relationship, werr)
		case werr == nil:
			accepted++
		default:
			refused++
		}
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("the seeds should both accept and refuse: %d accepted, %d refused", accepted, refused)
	}
}
