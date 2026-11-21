package policy

import (
	"strings"
	"testing"
	"time"
)

func TestStepUpSatisfied(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	age := &StepUp{MaxAge: 15 * time.Minute}
	acr := &StepUp{ACRValues: []string{"mfa", "hwk"}}
	both := &StepUp{MaxAge: 15 * time.Minute, ACRValues: []string{"mfa"}}
	for _, c := range []struct {
		name   string
		s      *StepUp
		a      Auth
		ok     bool
		reason string
	}{
		{"no requirement", nil, Auth{}, true, ""},
		{"fresh", age, Auth{Time: now.Add(-time.Minute)}, true, ""},
		{"exactly max_age", age, Auth{Time: now.Add(-15 * time.Minute)}, true, ""},
		{"a second too old", age, Auth{Time: now.Add(-15*time.Minute - time.Second)}, false, StepUpMaxAge},
		{"unknown time", age, Auth{}, false, StepUpMaxAge},
		{"provider clock ahead", age, Auth{Time: now.Add(time.Hour)}, true, ""},
		{"listed acr", acr, Auth{ACR: "hwk"}, true, ""},
		{"other acr", acr, Auth{ACR: "pwd"}, false, StepUpACR},
		{"no acr", acr, Auth{}, false, StepUpACR},
		{"acr compared exactly", acr, Auth{ACR: "MFA"}, false, StepUpACR},
		{"both met", both, Auth{Time: now, ACR: "mfa"}, true, ""},
		{"age checked first", both, Auth{Time: now.Add(-time.Hour), ACR: "pwd"}, false, StepUpMaxAge},
		{"fresh but weak", both, Auth{Time: now, ACR: "pwd"}, false, StepUpACR},
	} {
		ok, reason := c.s.Satisfied(c.a, now)
		if ok != c.ok || reason != c.reason {
			t.Errorf("%s: got %v %q, want %v %q", c.name, ok, reason, c.ok, c.reason)
		}
		if IsStepUp(reason) == c.ok {
			t.Errorf("%s: IsStepUp(%q) = %v", c.name, reason, IsStepUp(reason))
		}
	}
	if IsStepUp(StepUpLoop) || IsStepUp(DeniedNoMatch) {
		t.Fatal("a loop or a refusal is not a step-up")
	}
}

func TestStepUpSatisfiedDoesNotAllocate(t *testing.T) {
	s := &StepUp{MaxAge: time.Hour, ACRValues: []string{"a", "b", "c"}}
	now := time.Now()
	a := Auth{Time: now, ACR: "c"}
	if n := testing.AllocsPerRun(100, func() { s.Satisfied(a, now) }); n != 0 {
		t.Fatalf("Satisfied allocates %v times", n)
	}
}

func TestStepUpLoop(t *testing.T) {
	created := time.Unix(1_800_000_000, 0)
	s := &StepUp{MaxAge: 10 * time.Minute, ACRValues: []string{"mfa"}}
	good := Auth{Time: created.Add(-time.Minute), ACR: "mfa"}
	// A sign-in that met the rule when the session was made is no loop,
	// even when it has since aged out within the window.
	old := Auth{Time: created.Add(-10*time.Minute + time.Second), ACR: "mfa"}
	if s.IsStepUpLoop(good, created, created.Add(time.Second)) || s.IsStepUpLoop(old, created, created.Add(30*time.Second)) {
		t.Fatal("a sign-in that met the rule is taken for a loop")
	}
	weak := Auth{Time: created, ACR: "pwd"}
	if !s.IsStepUpLoop(weak, created, created.Add(time.Second)) {
		t.Fatal("a session that never met its rule is not a loop")
	}
	if !s.IsStepUpLoop(Auth{ACR: "mfa"}, created, created) {
		t.Fatal("a session without auth_time for a max_age rule is not a loop")
	}
	// After the window the user may try again.
	if s.IsStepUpLoop(weak, created, created.Add(StepUpLoopWindow)) {
		t.Fatal("the loop window does not end")
	}
}

func TestStepUpChallenge(t *testing.T) {
	for _, c := range []struct {
		s    StepUp
		want string
		secs int64
	}{
		{StepUp{MaxAge: 15 * time.Minute}, `max_age="900"`, 900},
		{StepUp{ACRValues: []string{"urn:a", "urn:b"}}, `acr_values="urn:a urn:b"`, -1},
		{StepUp{MaxAge: time.Hour, ACRValues: []string{"mfa"}}, `max_age="3600", acr_values="mfa"`, 3600},
	} {
		if got := c.s.Challenge(); got != c.want {
			t.Errorf("Challenge = %s, want %s", got, c.want)
		}
		if got := c.s.MaxAgeSeconds(); got != c.secs {
			t.Errorf("MaxAgeSeconds = %d, want %d", got, c.secs)
		}
	}
	if (*StepUp)(nil).MaxAgeSeconds() != -1 {
		t.Fatal("nil MaxAgeSeconds")
	}
}

func TestCompileStepUp(t *testing.T) {
	long := strings.Repeat("a", MaxACRBytes+1)
	many := make([]string, MaxACRValues+1)
	for i := range many {
		many[i] = "c" + strings.Repeat("x", i)
	}
	for _, c := range []struct {
		r    PathRule
		want string
	}{
		{PathRule{Path: "/a", StepUp: &StepUp{}}, "needs max_age, acr_values or both"},
		{PathRule{Path: "/a", StepUp: &StepUp{MaxAge: 59 * time.Second}}, "must be between 1m0s and 720h0m0s"},
		{PathRule{Path: "/a", StepUp: &StepUp{MaxAge: 31 * 24 * time.Hour}}, "must be between"},
		{PathRule{Path: "/a", StepUp: &StepUp{MaxAge: 90*time.Second + time.Millisecond}}, "whole seconds"},
		{PathRule{Path: "/a", StepUp: &StepUp{ACRValues: []string{"a b"}}}, `acr value "a b" must be`},
		{PathRule{Path: "/a", StepUp: &StepUp{ACRValues: []string{`a"`}}}, "must be 1-256 visible ASCII"},
		{PathRule{Path: "/a", StepUp: &StepUp{ACRValues: []string{""}}}, "must be 1-256"},
		{PathRule{Path: "/a", StepUp: &StepUp{ACRValues: []string{long}}}, "must be 1-256"},
		{PathRule{Path: "/a", StepUp: &StepUp{ACRValues: []string{"x", "x"}}}, `"x" is listed twice`},
		{PathRule{Path: "/a", StepUp: &StepUp{ACRValues: many}}, "more than 8 acr_values"},
		{PathRule{Path: "/a", Public: true, StepUp: &StepUp{MaxAge: time.Hour}}, "a public or deny rule takes no step_up"},
		{PathRule{Path: "/a", Deny: true, StepUp: &StepUp{MaxAge: time.Hour}}, "a public or deny rule takes no step_up"},
	} {
		_, err := CompileApp(App{Rule: Rule{Providers: []string{"corp"}}, Paths: []PathRule{c.r}})
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.HasPrefix(err.Error(), "paths[0]: ") {
			t.Errorf("%+v: got %v, want %q", c.r.StepUp, err, c.want)
		}
	}
}

func TestPolicyStepUp(t *testing.T) {
	acr := []string{"mfa"}
	p, err := CompileApp(App{Rule: Rule{Providers: []string{"corp"}, AnyUser: true},
		Public: []string{"/static"},
		Paths: []PathRule{
			{Path: "/admin", AnyUser: true, StepUp: &StepUp{MaxAge: 10 * time.Minute}},
			{Path: "/admin/keys", Methods: []string{"POST"}, Groups: []string{"ops"}, StepUp: &StepUp{ACRValues: acr}},
			{Path: "/admin/help", AnyUser: true},
		}})
	if err != nil {
		t.Fatal(err)
	}
	acr[0] = "changed" // the policy keeps its own copy
	for _, c := range []struct {
		method, path string
		maxAge       time.Duration
		acr          string
	}{
		{"GET", "/admin/users", 10 * time.Minute, ""},
		{"POST", "/admin/keys/1", 0, "mfa"},
		{"GET", "/admin/keys/1", 10 * time.Minute, ""}, // the POST rule does not match
		{"GET", "/admin/help", 0, ""},
		{"GET", "/static/x.css", 0, ""},
		{"GET", "/elsewhere", 0, ""},
	} {
		m := p.Match(c.method, c.path)
		su := p.StepUp(&m)
		switch {
		case c.maxAge == 0 && c.acr == "":
			if su != nil {
				t.Errorf("%s %s: unexpected step-up %+v", c.method, c.path, su)
			}
		case su == nil || su.MaxAge != c.maxAge || (c.acr != "" && (len(su.ACRValues) != 1 || su.ACRValues[0] != c.acr)):
			t.Errorf("%s %s: step-up %+v", c.method, c.path, su)
		}
	}
	if su := p.StepUpRule("paths[1]"); su == nil || su.ACRValues[0] != "mfa" {
		t.Fatalf("StepUpRule(paths[1]) = %+v", su)
	}
	for _, name := range []string{"paths[2]", "public[0]", "paths[9]", "allow", ""} {
		if p.StepUpRule(name) != nil {
			t.Fatalf("StepUpRule(%q) is not nil", name)
		}
	}
	// A step-up does not change who the rule lets through.
	id := &Identity{Provider: "corp", Subject: "bob", Groups: []string{"sales"}}
	if ok, reason := p.Decide("POST", "/admin/keys/1", id); ok || reason != DeniedNoMatch {
		t.Fatalf("bob POST /admin/keys: %v %s", ok, reason)
	}
	if ok, _ := p.Decide("GET", "/admin/users", id); !ok {
		t.Fatal("bob GET /admin/users is refused")
	}
}

func TestValidACR(t *testing.T) {
	for v, want := range map[string]bool{
		"urn:mace:incommon:iap:silver": true, "1": true, "a b": false, "": false,
		"tab\t": false, `q"`: false, `b\`: false, "é": false, strings.Repeat("x", MaxACRBytes): true,
	} {
		if ValidACR(v) != want {
			t.Errorf("ValidACR(%q) != %v", v, want)
		}
	}
}
