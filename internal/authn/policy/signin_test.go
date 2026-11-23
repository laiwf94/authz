package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestClaimNames(t *testing.T) {
	p, err := CompileApp(App{
		Rule: Rule{Providers: []string{"corp"}, Claims: []ClaimCondition{{Claim: "tenant", Equals: "acme"}, {Claim: "email", Matches: "*@acme.example"}}},
		Paths: []PathRule{
			{Path: "/admin", Claims: []ClaimCondition{{Claim: "department", In: []string{"it", "sec"}}, {Claim: "groups", Equals: "admins"}}},
			{Path: "/hr", Groups: []string{"hr"}, Claims: []ClaimCondition{{Claim: "tenant", Equals: "acme"}, {Claim: "clearance", Matches: "level-?"}}},
			{Path: "/pub", Public: true},
			{Path: "/sub", Claims: []ClaimCondition{{Claim: "sub", Equals: "alice"}, {Claim: "idp", Equals: "corp"}, {Claim: "name", Equals: "A"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := p.ClaimNames(), []string{"clearance", "department", "tenant"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ClaimNames = %v, want %v", got, want)
	}
	plain, _ := CompileApp(App{Rule: Rule{Providers: []string{"corp"}, AnyUser: true}})
	if got := plain.ClaimNames(); len(got) != 0 {
		t.Errorf("an app without conditions names %v", got)
	}
}

func TestCleanClaims(t *testing.T) {
	got, err := CleanClaims(map[string][]string{
		"department": {"eng", "", "eng", "ops"},
		"empty":      {"", ""},
		"none":       nil,
		"sub":        {"mallory"}, // reads the verified identity, never kept
		"groups":     {"admins"},
		"tenant":     {"acme"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"department": {"eng", "ops"}, "tenant": {"acme"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CleanClaims = %v, want %v", got, want)
	}
	if got, err := CleanClaims(map[string][]string{"x": {""}, "email": {"a@b"}}); err != nil || got != nil {
		t.Errorf("nothing left: %v, %v; want nil, nil", got, err)
	}
	if err := CheckClaims(want); err != nil {
		t.Errorf("CheckClaims(clean) = %v", err)
	}

	manyValues := make([]string, MaxSessionClaimValues+1)
	for i := range manyValues {
		manyValues[i] = fmt.Sprint(i)
	}
	manyNames := map[string][]string{}
	for i := 0; i <= MaxSessionClaims; i++ {
		manyNames[fmt.Sprintf("c%d", i)] = []string{"v"}
	}
	big := map[string][]string{}
	for i := 0; i < 20; i++ {
		big[fmt.Sprintf("c%d", i)] = []string{strings.Repeat("v", MaxClaimValueBytes)}
	}
	for name, c := range map[string]struct {
		in   map[string][]string
		want string
	}{
		"bad name":       {map[string][]string{"a b": {"v"}}, "visible ASCII"},
		"long name":      {map[string][]string{strings.Repeat("n", 257): {"v"}}, "visible ASCII"},
		"long value":     {map[string][]string{"a": {strings.Repeat("v", MaxClaimValueBytes+1)}}, "longer than 1024"},
		"invalid UTF-8":  {map[string][]string{"a": {"\xff"}}, "not valid UTF-8"},
		"many values":    {map[string][]string{"a": manyValues}, "more than 256 values"},
		"many claims":    {manyNames, "more than 64 claims"},
		"too many bytes": {big, "larger than 16384 bytes"},
	} {
		if _, err := CleanClaims(c.in); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want %q", name, err, c.want)
		}
		if err := CheckClaims(c.in); err == nil {
			t.Errorf("%s: CheckClaims accepts it", name)
		}
	}
	for name, c := range map[string]map[string][]string{
		"builtin":     {"sub": {"x"}},
		"no values":   {"a": {}},
		"empty value": {"a": {"x", ""}},
		"repeated":    {"a": {"x", "x"}},
	} {
		if err := CheckClaims(c); err == nil {
			t.Errorf("CheckClaims(%s) accepts %v", name, c)
		}
	}
}

func TestSelectClaims(t *testing.T) {
	in := map[string][]string{"department": {"eng"}, "secret_attr": {"x"}, "tenant": {"acme", "acme"}}
	got, err := SelectClaims(in, []string{"department", "tenant", "absent"})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string][]string{"department": {"eng"}, "tenant": {"acme"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("SelectClaims = %v, want %v", got, want)
	}
	if got, err := SelectClaims(in, nil); got != nil || err != nil {
		t.Errorf("no names: %v, %v", got, err)
	}
	if _, err := SelectClaims(map[string][]string{"a": {"\xff"}}, []string{"a"}); err == nil {
		t.Error("a bad value of a selected claim is accepted")
	}
	if _, err := SelectClaims(map[string][]string{"a": {"\xff"}, "b": {"ok"}}, []string{"b"}); err != nil {
		t.Errorf("a bad value of a claim not selected fails: %v", err)
	}
}

func TestIdentityClone(t *testing.T) {
	id := Identity{Provider: "corp", Subject: "alice", Groups: []string{"eng"}, Claims: map[string][]string{"tenant": {"acme"}}}
	cp := id.Clone()
	if !reflect.DeepEqual(cp, id) {
		t.Fatalf("clone %+v differs from %+v", cp, id)
	}
	cp.Groups[0] = "x"
	cp.Claims["tenant"][0] = "x"
	cp.Claims["new"] = []string{"y"}
	if id.Groups[0] != "eng" || id.Claims["tenant"][0] != "acme" || len(id.Claims) != 1 {
		t.Errorf("the clone shares memory with the original: %+v", id)
	}
	if (Identity{}).Clone().Claims != nil {
		t.Error("cloning no claims makes a map")
	}
}

func TestCandidatesForClaims(t *testing.T) {
	p, err := CompileApp(App{
		Rule: Rule{Providers: []string{"corp"}, AnyUser: true, Claims: []ClaimCondition{{Claim: "tenant", Equals: "acme"}}},
		Paths: []PathRule{
			{Path: "/admin", Claims: []ClaimCondition{{Claim: "department", In: []string{"it", "sec"}}, {Claim: "clearance", Matches: "level-?"}}},
			{Path: "/admin/pub", Public: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{Provider: "corp", Subject: "alice", Claims: map[string][]string{"tenant": {"acme"}, "department": {"hr", "sec"}, "clearance": {"level-10"}}}
	m, cands := p.CandidatesFor("GET", "/admin/x", id)
	if m.Rule != 0 || len(cands) != 2 {
		t.Fatalf("match %+v, candidates %+v", m, cands)
	}
	yes, no := true, false
	want := []ClaimResult{
		{Claim: "department", In: []string{"it", "sec"}, Holds: &yes},
		{Claim: "clearance", Matches: "level-?", Holds: &no},
	}
	if !reflect.DeepEqual(cands[0].Claims, want) {
		t.Errorf("paths[0] claims = %s", js(cands[0].Claims))
	}
	if w := []ClaimResult{{Claim: "tenant", Equals: "acme", Holds: &yes}}; !reflect.DeepEqual(cands[1].Claims, w) {
		t.Errorf("allow claims = %s", js(cands[1].Claims))
	}
	// The decision agrees: the failed condition denies.
	if ok, reason := p.Evaluate(&m, id); ok || reason != DeniedClaims {
		t.Errorf("Evaluate = %v %s", ok, reason)
	}

	// Without an identity the conditions are listed with no answer.
	_, cands = p.Candidates("GET", "/admin/x")
	for _, c := range cands {
		for _, r := range c.Claims {
			if r.Holds != nil {
				t.Errorf("%s: %s has an answer without an identity", c.Rule, r.Claim)
			}
		}
	}
	if b := js(cands[0].Claims); !strings.Contains(b, `"in":["it","sec"]`) || strings.Contains(b, "holds") {
		t.Errorf("JSON %s", b)
	}
	// A public rule has no conditions to show.
	_, cands = p.CandidatesFor("GET", "/admin/pub", id)
	if cands[0].Rule != "paths[1]" || cands[0].Claims != nil || cands[1].Claims == nil {
		t.Errorf("public rule %+v", cands[0])
	}
}

func TestClaimErrorsNameTheCondition(t *testing.T) {
	_, err := CompileApp(App{
		Rule: Rule{Providers: []string{"corp"}, Claims: []ClaimCondition{{Claim: "ok", Equals: "v"}, {Claim: "a"}}},
		Paths: []PathRule{
			{Path: "/x", Claims: []ClaimCondition{{Claim: "a b", Equals: "x"}, {Claim: "ok", Equals: "v"}, {Claim: "c", Matches: `x\`}}},
			{Path: "/y", Claims: make([]ClaimCondition, MaxClaimConditions+1)},
			{Path: "/z", Methods: []string{"BREW"}},
		},
	})
	var got []string
	for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
		var re *RuleError
		if !errors.As(e, &re) {
			t.Fatalf("%v is not a RuleError", e)
		}
		got = append(got, re.Rule+"|"+re.Field)
	}
	want := []string{"allow|claims[1]", "paths[0]|claims[0]", "paths[0]|claims[2]", "paths[1]|claims", "paths[2]|"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("errors at %v, want %v\n%v", got, want, err)
	}
	if !strings.Contains(err.Error(), "paths[0]: claims[2]: claim \"c\": pattern") {
		t.Errorf("message %v", err)
	}
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
