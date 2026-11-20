package check

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/platform/clock"
)

// TestConformance runs the cases in testdata/conformance/*.txt. Each file
// holds one schema and any number of cases, each on a fresh store whose
// clock starts at conformanceEpoch:
//
//	schema
//	  <schema, indented by two spaces>
//	case <name>
//	at <duration>                    set the clock to the epoch plus duration
//	write <relationship> [with <caveat> [<json context>]] [expires <duration>]
//	delete <relationship>
//	mark <label>                     name the head revision
//	check [@<label>] <resource>#<permission>@<subject> [<json context>] => <answer>
//	resources [@<label>] <type>#<permission>@<subject> [<json context>] => <ids>
//	subjects [@<label>] <resource>#<permission>@<type> [<json context>] => <found>
//
// Each write and delete is a revision of its own, committed at the clock's
// time. An answer is allowed, denied, conditional[<names>] or
// error <text>; ids are the allowed IDs, then conditional ones as
// id?[names]; found subjects are written as showFound prints them. "-"
// stands for an empty list. Lines starting with # are comments.
//
// Every check also runs on a cached engine, twice, and through
// LookupResources and LookupSubjects, which must agree with it.
func TestConformance(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "conformance", "*.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no conformance files: %v", err)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".txt"), func(t *testing.T) {
			runConformanceFile(t, file)
		})
	}
}

var conformanceEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type conformanceCase struct {
	name  string
	lines []conformanceLine
}

type conformanceLine struct {
	n    int
	text string
}

func runConformanceFile(t *testing.T, file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var sch strings.Builder
	var cases []*conformanceCase
	inSchema := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if inSchema && (line == "" || strings.HasPrefix(line, "  ")) {
			sch.WriteString(strings.TrimPrefix(line, "  ") + "\n")
			continue
		}
		inSchema = false
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case line == "schema":
			inSchema = true
		case strings.HasPrefix(line, "case "):
			cases = append(cases, &conformanceCase{name: strings.TrimPrefix(line, "case ")})
		case len(cases) == 0:
			t.Fatalf("%s:%d: %q before the first case", file, n, line)
		default:
			c := cases[len(cases)-1]
			c.lines = append(c.lines, conformanceLine{n, line})
		}
	}
	if len(cases) == 0 {
		t.Fatalf("%s: no cases", file)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newConformanceRun(t, file, sch.String())
			for _, l := range c.lines {
				r.line(l)
			}
		})
	}
}

type conformanceRun struct {
	t      *testing.T
	file   string
	clk    *clock.Fake
	st     *store.Store
	cf     *caveatFixture
	fresh  *Engine
	cached *Engine
	marks  map[string]store.Revision
}

func newConformanceRun(t *testing.T, file, schemaSrc string) *conformanceRun {
	clk := clock.NewFake(conformanceEpoch)
	st, err := store.Open(store.Options{Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.WriteSchema(schemaSrc); err != nil {
		t.Fatalf("%s: schema: %v", file, err)
	}
	cached := New(st, NewCache(10_000))
	return &conformanceRun{t: t, file: file, clk: clk, st: st, fresh: New(st, nil), cached: cached,
		cf: &caveatFixture{t: t, st: st, sc: mustSchema(t, st), eng: cached}, marks: map[string]store.Revision{}}
}

func (r *conformanceRun) fatalf(l conformanceLine, format string, args ...any) {
	r.t.Helper()
	r.t.Fatalf("%s:%d: %s: %s", r.file, l.n, l.text, fmt.Sprintf(format, args...))
}

func (r *conformanceRun) duration(l conformanceLine, s string) time.Duration {
	r.t.Helper()
	d, err := time.ParseDuration(s)
	if err != nil {
		r.fatalf(l, "%v", err)
	}
	return d
}

// splitContext cuts "<subject-ish> [<json>]" into the word and the decoded
// context (nil when there is none).
func (r *conformanceRun) splitContext(l conformanceLine, s string) (string, map[string]any) {
	r.t.Helper()
	word, rest, _ := strings.Cut(strings.TrimSpace(s), " ")
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return word, nil
	}
	d := json.NewDecoder(strings.NewReader(rest))
	d.UseNumber()
	var ctx map[string]any
	if err := d.Decode(&ctx); err != nil {
		r.fatalf(l, "context: %v", err)
	}
	return word, ctx
}

// revision takes an optional "@label" off the front of s.
func (r *conformanceRun) revision(l conformanceLine, s string) (store.Revision, string) {
	r.t.Helper()
	if !strings.HasPrefix(s, "@") {
		return r.st.Head(), s
	}
	label, rest, _ := strings.Cut(s[1:], " ")
	rev, ok := r.marks[label]
	if !ok {
		r.fatalf(l, "no mark %q", label)
	}
	return rev, rest
}

func (r *conformanceRun) line(l conformanceLine) {
	r.t.Helper()
	verb, rest, _ := strings.Cut(l.text, " ")
	switch verb {
	case "at":
		r.clk.Set(conformanceEpoch.Add(r.duration(l, rest)))
	case "mark":
		r.marks[rest] = r.st.Head()
	case "write":
		r.write(l, rest)
	case "delete":
		rel, err := store.ParseRelationship(rest)
		if err != nil {
			r.fatalf(l, "%v", err)
		}
		if _, err := r.st.Write([]store.Update{{Op: store.OpDelete, Relationship: rel}}, nil); err != nil {
			r.fatalf(l, "%v", err)
		}
	case "check", "resources", "subjects":
		q, want, ok := strings.Cut(rest, " => ")
		if !ok {
			r.fatalf(l, "no => answer")
		}
		rev, q := r.revision(l, q)
		switch verb {
		case "check":
			r.check(l, rev, q, want)
		case "resources":
			r.resources(l, rev, q, want)
		default:
			r.subjects(l, rev, q, want)
		}
	default:
		r.fatalf(l, "unknown directive %q", verb)
	}
}

func (r *conformanceRun) write(l conformanceLine, rest string) {
	r.t.Helper()
	var exp time.Time
	if body, d, ok := strings.Cut(rest, " expires "); ok {
		rest, exp = body, conformanceEpoch.Add(r.duration(l, d))
	}
	relText, cav, _ := strings.Cut(rest, " with ")
	rel, err := store.ParseRelationship(strings.TrimSpace(relText))
	if err != nil {
		r.fatalf(l, "%v", err)
	}
	u := store.Update{Op: store.OpTouch, Relationship: rel, ExpiresAt: exp}
	if cav != "" {
		name, ctx := r.splitContext(l, cav)
		u.Caveat = &store.Caveat{Name: name, Context: ctx}
	}
	if _, err := r.st.Write([]store.Update{u}, nil); err != nil {
		r.fatalf(l, "%v", err)
	}
}

func (r *conformanceRun) check(l conformanceLine, rev store.Revision, q, want string) {
	r.t.Helper()
	spec, ctx := r.splitContext(l, q)
	resource, permSubject, _ := strings.Cut(spec, "#")
	perm, subject, ok := strings.Cut(permSubject, "@")
	if !ok {
		r.fatalf(l, "want <resource>#<permission>@<subject>")
	}
	req := mustRequest(r.t, resource, perm, subject)
	var first string
	for i, eng := range []*Engine{r.fresh, r.cached, r.cached} {
		res, _, err := eng.CheckResult(context.Background(), r.cf.sc, rev, req, ctx)
		got := answer(res)
		if err != nil {
			got = "error " + err.Error()
		}
		if strings.HasPrefix(want, "error ") {
			if err == nil || !strings.Contains(err.Error(), strings.TrimPrefix(want, "error ")) {
				r.fatalf(l, "engine %d: got %s", i, got)
			}
			continue
		}
		if got != want {
			r.fatalf(l, "engine %d: got %s", i, got)
		}
		first = got
	}
	if first == "" {
		return
	}
	// Lookups for a plain subject give it the same answer.
	if req.Subject.Relation != "" {
		return
	}
	res, err := r.cached.LookupResourcesContext(context.Background(), r.cf.sc, r.st, rev, req.ResourceType, perm, req.Subject, "", 0, ctx)
	if err != nil {
		r.fatalf(l, "lookup resources: %v", err)
	}
	viaLookup := denied
	for _, id := range res.IDs {
		if id == req.ResourceID {
			viaLookup = allowed
		}
	}
	for _, c := range res.Conditional {
		if c.ID == req.ResourceID {
			viaLookup = Result{Permissionship: Conditional, Missing: c.Missing}
		}
	}
	if answer(viaLookup) != want {
		r.fatalf(l, "lookup resources gives %s", answer(viaLookup))
	}
	found, _, err := r.cf.lookupAllSubjects(rev, resource, perm, req.Subject.Type, ctx, 0)
	if err != nil {
		r.fatalf(l, "lookup subjects: %v", err)
	}
	if got := answer(answerFor(found, req.Subject.ID)); got != want {
		r.fatalf(l, "lookup subjects gives %s (%s)", got, showFound(found))
	}
}

func (r *conformanceRun) resources(l conformanceLine, rev store.Revision, q, want string) {
	r.t.Helper()
	spec, ctx := r.splitContext(l, q)
	typePerm, subject, _ := strings.Cut(spec, "@")
	typ, perm, _ := strings.Cut(typePerm, "#")
	sub, err := store.ParseSubject(subject, false)
	if err != nil {
		r.fatalf(l, "%v", err)
	}
	res, err := r.cached.LookupResourcesContext(context.Background(), r.cf.sc, r.st, rev, typ, perm, sub, "", 0, ctx)
	if err != nil {
		r.fatalf(l, "%v", err)
	}
	parts := append([]string(nil), res.IDs...)
	for _, c := range res.Conditional {
		parts = append(parts, fmt.Sprintf("%s?%v", c.ID, c.Missing))
	}
	if got := orDash(strings.Join(parts, " ")); got != want {
		r.fatalf(l, "got %s", got)
	}
}

func (r *conformanceRun) subjects(l conformanceLine, rev store.Revision, q, want string) {
	r.t.Helper()
	spec, ctx := r.splitContext(l, q)
	resPerm, subjectType, _ := strings.Cut(spec, "@")
	i := strings.LastIndexByte(resPerm, '#')
	found, _, err := r.cf.lookupAllSubjects(rev, resPerm[:i], resPerm[i+1:], subjectType, ctx, 0)
	if err != nil {
		r.fatalf(l, "%v", err)
	}
	if got := orDash(showFound(found)); got != want {
		r.fatalf(l, "got %s", got)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
