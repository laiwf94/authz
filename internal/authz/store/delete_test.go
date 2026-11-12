package store

import (
	"bytes"
	"container/heap"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

func deleteBy(t testing.TB, s *Store, req DeleteRequest) DeleteResult {
	t.Helper()
	res, err := s.DeleteByFilter(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func readAll(t testing.TB, s *Store, rev Revision, typ string) []string {
	t.Helper()
	var out []string
	cursor := ""
	for {
		rels, next, err := s.Read(rev, Filter{ResourceType: typ}, cursor, MaxReadLimit)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rels {
			out = append(out, r.String())
		}
		if next == "" {
			return out
		}
		cursor = next
	}
}

func TestDeleteByFilter(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	before := write(t, s, OpTouch,
		"doc:a#viewer@user:x", "doc:a#viewer@user:y", "doc:a#owner@user:x",
		"doc:b#viewer@user:x", "doc:b#viewer@user:*", "doc:b#viewer@group:g#member",
		"group:g#member@user:x")

	for _, c := range []struct {
		name   string
		filter Filter
		left   string // doc relationships left afterwards
	}{
		{"subject relation", Filter{ResourceType: "doc", SubjectType: "group", SubjectRelation: "member"},
			"doc:a#owner@user:x doc:a#viewer@user:x doc:a#viewer@user:y doc:b#viewer@user:* doc:b#viewer@user:x"},
		{"wildcard subject", Filter{ResourceType: "doc", SubjectType: "user", SubjectID: "*"},
			"doc:a#owner@user:x doc:a#viewer@user:x doc:a#viewer@user:y doc:b#viewer@user:x"},
		{"one subject on any object", Filter{ResourceType: "doc", Relation: "viewer", SubjectType: "user", SubjectID: "x"},
			"doc:a#owner@user:x doc:a#viewer@user:y"},
		{"one object", Filter{ResourceType: "doc", ResourceID: "a"}, ""},
	} {
		head := s.Head()
		res := deleteBy(t, s, DeleteRequest{Filter: c.filter})
		if res.Revision != head+1 || res.Partial || res.Deleted == 0 {
			t.Fatalf("%s: %+v at head %d", c.name, res, head)
		}
		if got := strings.Join(readAll(t, s, s.Head(), "doc"), " "); got != c.left {
			t.Fatalf("%s: left %q, want %q", c.name, got, c.left)
		}
		// Every change of the delete is at its one revision.
		ch, err := s.Changes(head, 0)
		if err != nil || len(ch) != res.Deleted {
			t.Fatalf("%s: changes %v %v", c.name, ch, err)
		}
		for i, c := range ch {
			if c.Revision != res.Revision || c.Op != OpDelete || (i > 0 && ch[i-1].Relationship.String() >= c.Relationship.String()) {
				t.Fatalf("change %d: %+v", i, c)
			}
		}
	}
	// Other types are untouched, and the snapshot before the deletes still
	// reads everything.
	if got := readAll(t, s, s.Head(), "group"); len(got) != 1 {
		t.Fatalf("group: %v", got)
	}
	if got := readAll(t, s, before, "doc"); len(got) != 6 {
		t.Fatalf("old snapshot: %v", got)
	}

	// Nothing matches: no new revision.
	head := s.Head()
	if res := deleteBy(t, s, DeleteRequest{Filter: Filter{ResourceType: "doc"}}); res != (DeleteResult{Revision: head}) {
		t.Fatalf("empty delete: %+v", res)
	}
	if s.Head() != head {
		t.Fatal("an empty delete moved the head")
	}
	// Deleted relationships can be written again.
	write(t, s, OpCreate, "doc:a#viewer@user:x")
}

func TestDeleteByFilterLimit(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	var rels []string
	for i := range 10 {
		rels = append(rels, fmt.Sprintf("doc:d%d#viewer@user:u%d", (i*7)%10, i))
	}
	write(t, s, OpTouch, rels...)
	all := readAll(t, s, s.Head(), "doc")
	head := s.Head()

	// More match than the limit: nothing is deleted.
	_, err := s.DeleteByFilter(DeleteRequest{Filter: Filter{ResourceType: "doc"}, Limit: 9})
	if !errors.Is(err, ErrPrecondition) || !strings.Contains(err.Error(), "more than 9") {
		t.Fatalf("over the limit: %v", err)
	}
	if s.Head() != head || len(readAll(t, s, head, "doc")) != 10 {
		t.Fatal("a refused delete changed the store")
	}

	// With allow_partial, pages of 3 in text order, the last one complete.
	var deleted []string
	for _, want := range []struct {
		n       int
		partial bool
	}{{3, true}, {3, true}, {3, true}, {1, false}} {
		prev := s.Head()
		res := deleteBy(t, s, DeleteRequest{Filter: Filter{ResourceType: "doc"}, Limit: 3, AllowPartial: true})
		if res.Deleted != want.n || res.Partial != want.partial || res.Revision != prev+1 {
			t.Fatalf("page: %+v, want %+v", res, want)
		}
		ch, _ := s.Changes(prev, 0)
		for _, c := range ch {
			deleted = append(deleted, c.Relationship.String())
		}
	}
	if !reflect.DeepEqual(deleted, all) {
		t.Fatalf("deleted in order\n%v\nwant\n%v", deleted, all)
	}

	// Exactly the limit is not partial.
	write(t, s, OpTouch, rels[:4]...)
	if res := deleteBy(t, s, DeleteRequest{Filter: Filter{ResourceType: "doc"}, Limit: 4}); res.Deleted != 4 || res.Partial {
		t.Fatalf("exactly the limit: %+v", res)
	}
}

// The default limit is MaxDeletesPerFilter, and it is enforced.
func TestDeleteByFilterDefaultLimit(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	for b := range 2 {
		var ups []Update
		for i := range MaxUpdatesPerWrite {
			ups = append(ups, Update{Op: OpTouch, Relationship: mustRel(t, fmt.Sprintf("doc:d%d#viewer@user:u%04d", b, i))})
		}
		if _, err := s.Write(ups, nil); err != nil {
			t.Fatal(err)
		}
	}
	write(t, s, OpTouch, "doc:d2#viewer@user:extra")
	if _, err := s.DeleteByFilter(DeleteRequest{Filter: Filter{ResourceType: "doc"}}); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("over the default limit: %v", err)
	}
	res := deleteBy(t, s, DeleteRequest{Filter: Filter{ResourceType: "doc"}, AllowPartial: true})
	if res.Deleted != MaxDeletesPerFilter || !res.Partial {
		t.Fatalf("first page: %+v", res)
	}
	// The first page is all of d0, the smallest in text order.
	if got := readAll(t, s, s.Head(), "doc"); len(got) != MaxUpdatesPerWrite+1 || !strings.HasPrefix(got[0], "doc:d1#") {
		t.Fatalf("left %d, first %q", len(got), got[0])
	}
	res = deleteBy(t, s, DeleteRequest{Filter: Filter{ResourceType: "doc"}, AllowPartial: true})
	if res.Deleted != MaxDeletesPerFilter || !res.Partial {
		t.Fatalf("second page: %+v", res)
	}
	if res = deleteBy(t, s, DeleteRequest{Filter: Filter{ResourceType: "doc"}}); res.Deleted != 1 || res.Partial {
		t.Fatalf("last: %+v", res)
	}
}

func TestDeleteByFilterPreconditions(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	write(t, s, OpTouch, "doc:a#viewer@user:x", "doc:a#owner@user:o", "doc:b#viewer@user:x")
	head := s.Head()
	f := Filter{ResourceType: "doc", Relation: "viewer"}
	for i, p := range []Precondition{
		{MustExist: true, Filter: Filter{ResourceType: "doc", ResourceID: "c"}},
		{MustExist: false, Filter: Filter{ResourceType: "doc", Relation: "owner"}},
	} {
		if _, err := s.DeleteByFilter(DeleteRequest{Filter: f, Preconditions: []Precondition{p}}); !errors.Is(err, ErrPrecondition) {
			t.Fatalf("precondition %d: %v", i, err)
		}
	}
	if s.Head() != head || len(readAll(t, s, head, "doc")) != 3 {
		t.Fatal("a failed precondition changed the store")
	}
	// A precondition over what the delete removes is checked before it.
	res := deleteBy(t, s, DeleteRequest{Filter: f, Preconditions: []Precondition{
		{MustExist: true, Filter: Filter{ResourceType: "doc", Relation: "owner", SubjectType: "user", SubjectID: "o"}},
		{MustExist: true, Filter: f},
	}})
	if res.Deleted != 2 || res.Revision != head+1 {
		t.Fatalf("guarded delete: %+v", res)
	}
	// A failed precondition fails even when nothing would match.
	if _, err := s.DeleteByFilter(DeleteRequest{Filter: f, Preconditions: []Precondition{{MustExist: true, Filter: f}}}); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("precondition on an empty delete: %v", err)
	}
}

func TestDeleteByFilterValidation(t *testing.T) {
	s := newStore(t, "")
	if _, err := s.DeleteByFilter(DeleteRequest{Filter: Filter{ResourceType: "doc"}}); !errors.Is(err, ErrNoSchema) {
		t.Fatalf("before a schema: %v", err)
	}
	withSchema(t, s)
	tooMany := make([]Precondition, MaxPreconditions+1)
	for i := range tooMany {
		tooMany[i] = Precondition{Filter: Filter{ResourceType: "doc"}}
	}
	for _, c := range []struct {
		name string
		req  DeleteRequest
		msg  string
	}{
		{"no type", DeleteRequest{}, "filter: invalid argument: filter needs a valid resource_type"},
		{"bad id", DeleteRequest{Filter: Filter{ResourceType: "doc", ResourceID: "a b"}}, "resource_id"},
		{"subject id alone", DeleteRequest{Filter: Filter{ResourceType: "doc", SubjectID: "x"}}, "needs subject_type"},
		{"negative limit", DeleteRequest{Filter: Filter{ResourceType: "doc"}, Limit: -1}, "limit must be between 0 and 1000"},
		{"large limit", DeleteRequest{Filter: Filter{ResourceType: "doc"}, Limit: MaxDeletesPerFilter + 1}, "limit must be"},
		{"preconditions", DeleteRequest{Filter: Filter{ResourceType: "doc"}, Preconditions: tooMany}, "at most 100 preconditions"},
		{"precondition filter", DeleteRequest{Filter: Filter{ResourceType: "doc"}, Preconditions: []Precondition{{}}}, "precondition 0:"},
	} {
		if _, err := s.DeleteByFilter(c.req); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// A type the schema does not define is a valid filter that matches
	// nothing, as for Read.
	if res := deleteBy(t, s, DeleteRequest{Filter: Filter{ResourceType: "ghost"}}); res.Deleted != 0 || res.Revision != s.Head() {
		t.Fatalf("unknown type: %+v", res)
	}
}

// Relationships the schema no longer allows can still be deleted by filter,
// as Write lets them be deleted one by one.
func TestDeleteByFilterAfterSchemaChange(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	write(t, s, OpTouch, "doc:a#viewer@user:*", "doc:a#viewer@user:x")
	if _, err := s.WriteSchema(strings.Replace(testSchema, " | user:*", "", 1)); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("schema change over stored data: %v", err)
	}
	deleteBy(t, s, DeleteRequest{Filter: Filter{ResourceType: "doc", SubjectType: "user", SubjectID: "*"}})
	if _, err := s.WriteSchema(strings.Replace(testSchema, " | user:*", "", 1)); err != nil {
		t.Fatalf("schema change after the delete: %v", err)
	}
}

func walLines(t *testing.T, dir string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, walName))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.SplitAfter(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
}

// A delete by filter is one log record listing every relationship it
// removed, and recovery replays it to the same state and the same head.
func TestDeleteByFilterLogAndRecovery(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	withSchema(t, s)
	var rels []string
	for i := range 50 {
		rels = append(rels, fmt.Sprintf("doc:d%d#viewer@user:u%d", i%5, i))
	}
	write(t, s, OpTouch, rels...)
	n := len(walLines(t, dir))
	res := deleteBy(t, s, DeleteRequest{Filter: Filter{ResourceType: "doc", ResourceID: "d3"}})
	lines := walLines(t, dir)
	if len(lines) != n+1 || res.Deleted != 10 {
		t.Fatalf("log grew from %d to %d records for %d deletes", n, len(lines), res.Deleted)
	}
	rec, err := decodeRecord(lines[len(lines)-1])
	if err != nil || rec.Type != recWrite || rec.Rev != res.Revision || len(rec.Changes) != 10 {
		t.Fatalf("record %+v: %v", rec, err)
	}
	// An empty delete writes nothing.
	deleteBy(t, s, DeleteRequest{Filter: Filter{ResourceType: "doc", ResourceID: "d3"}})
	if len(walLines(t, dir)) != n+1 {
		t.Fatal("an empty delete was logged")
	}
	want := readAll(t, s, s.Head(), "doc")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := newStore(t, dir)
	if s2.Head() != res.Revision || !reflect.DeepEqual(readAll(t, s2, s2.Head(), "doc"), want) {
		t.Fatalf("recovered head %d with %d relationships", s2.Head(), len(readAll(t, s2, s2.Head(), "doc")))
	}
}

// Cut the log at every byte of a delete by filter's record: recovery keeps
// all of its deletes or none.
func TestDeleteByFilterCrashAtEveryByte(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir)
	withSchema(t, s)
	write(t, s, OpTouch, "doc:a#viewer@user:x", "doc:a#viewer@user:y", "doc:a#owner@user:o", "doc:b#viewer@user:x")
	beforeHead, before := s.Head(), dump(t, s)
	fi, err := os.Stat(filepath.Join(dir, walName))
	if err != nil {
		t.Fatal(err)
	}
	res := deleteBy(t, s, DeleteRequest{Filter: Filter{ResourceType: "doc", Relation: "viewer"}})
	after := dump(t, s)
	s.Close()
	full, err := os.ReadFile(filepath.Join(dir, walName))
	if err != nil {
		t.Fatal(err)
	}
	for n := int(fi.Size()); n <= len(full); n++ {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, walName), full[:n], 0o600); err != nil {
			t.Fatal(err)
		}
		r, err := Open(Options{Dir: d})
		if err != nil {
			t.Fatalf("cut at %d: %v", n, err)
		}
		got := dump(t, r)
		switch {
		case r.Head() == beforeHead && got == before:
		case r.Head() == res.Revision && got == after:
			if n != len(full) {
				t.Fatalf("cut at %d of %d: the torn record was replayed", n, len(full))
			}
		default:
			t.Fatalf("cut at %d: head %d with %q", n, r.Head(), got)
		}
		r.Close()
	}
}

func TestDeleteByFilterOnBrokenLog(t *testing.T) {
	dir := t.TempDir()
	s := newStore(t, dir)
	withSchema(t, s)
	write(t, s, OpTouch, "doc:a#viewer@user:x")
	head := s.Head()
	s.wal.f.Close()
	if _, err := s.DeleteByFilter(DeleteRequest{Filter: Filter{ResourceType: "doc"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("delete on a closed log: %v", err)
	}
	if s.Head() != head || len(readAll(t, s, head, "doc")) != 1 {
		t.Fatal("a failed delete changed the store")
	}
}

// Random relationships and filters against a plain model: the delete
// removes exactly the first Limit matches in text order, or all of them.
func TestDeleteByFilterMatchesModel(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	pick := func(xs ...string) string { return xs[rng.Intn(len(xs))] }
	for round := range 40 {
		s := newStore(t, "")
		withSchema(t, s)
		model := map[string]Relationship{}
		var ups []Update
		for range 30 + rng.Intn(60) {
			var txt string
			switch rng.Intn(4) {
			case 0:
				txt = fmt.Sprintf("doc:d%d#owner@user:u%d", rng.Intn(6), rng.Intn(6))
			case 1:
				txt = fmt.Sprintf("doc:d%d#viewer@user:%s", rng.Intn(6), pick("u0", "u1", "u2", "*"))
			case 2:
				txt = fmt.Sprintf("doc:d%d#viewer@group:g%d#member", rng.Intn(6), rng.Intn(3))
			default:
				txt = fmt.Sprintf("group:g%d#member@user:u%d", rng.Intn(3), rng.Intn(6))
			}
			if _, ok := model[txt]; ok {
				continue
			}
			r := mustRel(t, txt)
			model[txt] = r
			ups = append(ups, Update{Op: OpTouch, Relationship: r})
		}
		if _, err := s.Write(ups, nil); err != nil {
			t.Fatal(err)
		}
		for step := range 6 {
			f := Filter{ResourceType: pick("doc", "doc", "group")}
			if rng.Intn(2) == 0 {
				f.ResourceID = fmt.Sprintf("d%d", rng.Intn(6))
				if f.ResourceType == "group" {
					f.ResourceID = fmt.Sprintf("g%d", rng.Intn(3))
				}
			}
			if rng.Intn(2) == 0 {
				f.Relation = pick("owner", "viewer", "member")
			}
			if rng.Intn(2) == 0 {
				f.SubjectType = pick("user", "group")
				if rng.Intn(2) == 0 {
					f.SubjectID = pick("u0", "u1", "*", "g0")
				}
				if rng.Intn(3) == 0 {
					f.SubjectRelation = pick(NoRelation, "member")
				}
			}
			var match []string
			for k, r := range model {
				if f.matches(r) {
					match = append(match, k)
				}
			}
			sort.Strings(match)
			limit := rng.Intn(8)
			partial := rng.Intn(2) == 0
			head := s.Head()
			res, err := s.DeleteByFilter(DeleteRequest{Filter: f, Limit: limit, AllowPartial: partial})
			over := limit > 0 && len(match) > limit
			if over && !partial {
				if !errors.Is(err, ErrPrecondition) || s.Head() != head {
					t.Fatalf("round %d step %d: %+v over the limit: %v", round, step, f, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("round %d step %d: %+v: %v", round, step, f, err)
			}
			want := match
			if over {
				want = match[:limit]
			}
			if res.Deleted != len(want) || res.Partial != over {
				t.Fatalf("round %d step %d: %+v limit %d: %+v, want %d deleted", round, step, f, limit, res, len(want))
			}
			ch, _ := s.Changes(head, 0)
			var got []string
			for _, c := range ch {
				got = append(got, c.Relationship.String())
			}
			if !reflect.DeepEqual(got, want) && len(want) > 0 {
				t.Fatalf("round %d step %d: %+v deleted\n%v\nwant\n%v", round, step, f, got, want)
			}
			for _, k := range want {
				delete(model, k)
			}
			var left []string
			for k := range model {
				left = append(left, k)
			}
			sort.Strings(left)
			now := append(readAll(t, s, s.Head(), "doc"), readAll(t, s, s.Head(), "group")...)
			sort.Strings(now)
			if strings.Join(now, " ") != strings.Join(left, " ") {
				t.Fatalf("round %d step %d: store\n%v\nmodel\n%v", round, step, now, left)
			}
		}
	}
}

// Readers racing a delete by filter see all of its matches or none of
// them at every revision.
func TestDeleteByFilterIsAtomicToReaders(t *testing.T) {
	s := newStore(t, "")
	withSchema(t, s)
	for round := range 20 {
		var rels []string
		for i := range 40 {
			rels = append(rels, fmt.Sprintf("doc:r%d#viewer@user:u%d", round, i))
		}
		write(t, s, OpTouch, rels...)
		var wg sync.WaitGroup
		stop := make(chan struct{})
		errs := make(chan error, 4)
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					rels, _, err := s.Read(s.Head(), Filter{ResourceType: "doc", ResourceID: fmt.Sprintf("r%d", round)}, "", MaxReadLimit)
					if err != nil || (len(rels) != 0 && len(rels) != 40) {
						errs <- fmt.Errorf("read %d relationships: %v", len(rels), err)
						return
					}
				}
			}()
		}
		deleteBy(t, s, DeleteRequest{Filter: Filter{ResourceType: "doc", ResourceID: fmt.Sprintf("r%d", round)}})
		close(stop)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
	}
}

func TestRelHeap(t *testing.T) {
	h := &relHeap{}
	for _, r := range []string{"doc:b#viewer@user:x", "doc:d#viewer@user:x", "doc:a#viewer@user:x", "doc:c#viewer@user:x"} {
		heap.Push(h, mustRel(t, r))
	}
	var got []string
	for h.Len() > 0 {
		got = append(got, heap.Pop(h).(Relationship).ResourceID)
	}
	if strings.Join(got, "") != "dcba" {
		t.Fatalf("popped %v", got)
	}
}

// compareText agrees with comparing String forms, including where one part
// is a prefix of another and separators meet ID characters.
func TestCompareText(t *testing.T) {
	ids := []string{"a", "a_b", "a-b", "a.b", "a|b", "a/b", "ab", "a=", "b", "A", "a@b", "*"}
	rng := rand.New(rand.NewSource(5))
	rels := []Relationship{}
	for range 400 {
		r := Relationship{ResourceType: []string{"doc", "do", "docs"}[rng.Intn(3)], ResourceID: ids[rng.Intn(len(ids)-1)],
			Relation: []string{"viewer", "view", "owner"}[rng.Intn(3)], SubjectType: []string{"user", "group", "us"}[rng.Intn(3)],
			SubjectID: ids[rng.Intn(len(ids))]}
		if rng.Intn(3) == 0 {
			r.SubjectRelation = []string{"member", "m"}[rng.Intn(2)]
		}
		rels = append(rels, r)
	}
	for _, a := range rels {
		for _, b := range rels[:60] {
			if got, want := compareText(a, b), strings.Compare(a.String(), b.String()); got != want {
				t.Fatalf("compareText(%s, %s) = %d, want %d", a, b, got, want)
			}
		}
	}
}

// BenchmarkDeleteByFilter deletes a page of 1,000 from an object type with
// 100,000 relationships, then writes them back so every round deletes the
// same amount.
func BenchmarkDeleteByFilter(b *testing.B) {
	s := newStore(b, "")
	withSchema(b, s)
	for blk := range 100 {
		ups := make([]Update, MaxUpdatesPerWrite)
		for i := range ups {
			ups[i] = Update{Op: OpTouch, Relationship: mustRel(b, fmt.Sprintf("doc:d%03d#viewer@user:u%04d", blk, i))}
		}
		if _, err := s.Write(ups, nil); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		res, err := s.DeleteByFilter(DeleteRequest{Filter: Filter{ResourceType: "doc"}, AllowPartial: true})
		if err != nil || res.Deleted != MaxDeletesPerFilter {
			b.Fatal(res, err)
		}
		b.StopTimer()
		ch, _ := s.Changes(res.Revision-1, 0)
		ups := make([]Update, len(ch))
		for i, c := range ch {
			ups[i] = Update{Op: OpTouch, Relationship: c.Relationship}
		}
		if _, err := s.Write(ups, nil); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}
