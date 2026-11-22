package guard

import (
	"strings"
	"testing"
)

func TestNewRulesRejectsBadDenyPatterns(t *testing.T) {
	many := make([]string, MaxPatterns+1)
	for i := range many {
		many[i] = "x"
	}
	for name, o := range map[string]Rules{
		"unknown built-in": {Deny: []string{"nope"}},
		"twice":            {Deny: []string{"jwt", "jwt"}},
		"empty":            {DenyPatterns: []string{""}},
		"too long":         {DenyPatterns: []string{strings.Repeat("a", MaxPatternBytes+1)}},
		"invalid":          {DenyPatterns: []string{"("}},
		"matches empty":    {DenyPatterns: []string{"a*"}},
		"too many":         {DenyPatterns: many},
		"too many mixed":   {Deny: []string{"jwt"}, DenyPatterns: many[1:]},
	} {
		if _, err := NewRules(o); err == nil || !strings.Contains(err.Error(), "deny") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The redaction and deny lists have a limit each.
	if _, err := NewRules(Rules{RedactPatterns: many[1:], DenyPatterns: many[1:]}); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRefusesWhereRedactionLooks(t *testing.T) {
	g, err := NewRules(Rules{Redact: []string{"aws_access_key_id"}, Deny: []string{"github_token"},
		DenyPatterns: []string{`secret-[0-9]+`, `(?i)do not share`}})
	if err != nil {
		t.Fatal(err)
	}
	tok := "ghp_" + strings.Repeat("a", 36)
	refused := map[string]string{
		"text":       `{"content":[{"type":"text","text":"x ` + tok + `"}]}`,
		"structured": `{"content":[],"structuredContent":{"rows":[1,{"n":"secret-4"}]}}`,
		"key":        `{"content":[],"structuredContent":{"secret-9":true}}`,
		"resource":   `{"content":[{"type":"resource","resource":{"uri":"file:///a","text":"Do Not Share"}}]}`,
		"error":      `{"content":[{"type":"text","text":"secret-1"}],"isError":true}`,
	}
	want := map[string]string{"text": "github_token", "structured": "deny_patterns[0]", "key": "deny_patterns[0]",
		"resource": "deny_patterns[1]", "error": "deny_patterns[0]"}
	for name, src := range refused {
		res := decode(t, src)
		before := encode(t, res)
		rep := g.Apply(res)
		if rep.Refused != want[name] || rep.Decision() != "refuse" {
			t.Errorf("%s: %+v", name, rep)
		}
		if got := encode(t, res); got != before || rep.BytesAfter != rep.BytesBefore || rep.Redactions != 0 {
			t.Errorf("%s: a refused result was changed: %s %+v", name, got, rep)
		}
	}
	// Base64 payloads are exempt, as from redaction.
	for _, src := range []string{
		`{"content":[{"type":"image","mimeType":"image/png","data":"secret-1"}]}`,
		`{"content":[{"type":"audio","mimeType":"audio/wav","data":"` + tok + `"}]}`,
		`{"content":[{"type":"resource","resource":{"uri":"file:///a","blob":"secret-2"}}]}`,
	} {
		if rep := g.Apply(decode(t, src)); rep.Refused != "" || rep.Decision() != "allow" {
			t.Errorf("binary refused: %s %+v", src, rep)
		}
	}
	res := decode(t, `{"content":[{"type":"text","text":"AKIAIOSFODNN7EXAMPLE"}]}`)
	if rep := g.Apply(res); rep.Refused != "" || rep.Redactions != 1 || rep.Decision() != "redact" {
		t.Fatalf("redaction without a deny match: %+v", rep)
	}
}

// TestApplyReportsFirstListedPattern: when several deny patterns match in
// different places, the report names the one listed first, whatever order
// the result's maps are walked in.
func TestApplyReportsFirstListedPattern(t *testing.T) {
	g, err := NewRules(Rules{DenyPatterns: []string{"alpha", "beta", "gamma"}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		res := decode(t, `{"structuredContent":{"a":"gamma","b":"beta","c":{"d":"x beta","e":["gamma"]},"f":"alpha"}}`)
		if rep := g.Apply(res); rep.Refused != "deny_patterns[0]" {
			t.Fatalf("got %q", rep.Refused)
		}
		res = decode(t, `{"structuredContent":{"a":"gamma","b":"beta","c":"gamma beta"}}`)
		if rep := g.Apply(res); rep.Refused != "deny_patterns[1]" {
			t.Fatalf("got %q", rep.Refused)
		}
	}
}

func TestDeniedTextAndNilGuard(t *testing.T) {
	var nilGuard *Guard
	if nilGuard.DeniedText("anything") != "" || nilGuard.Denies() {
		t.Fatal("a nil guard denies")
	}
	if rep := nilGuard.Apply(map[string]any{"content": []any{}}); rep.Decision() != "allow" {
		t.Fatalf("nil guard: %+v", rep)
	}
	g, _ := NewRules(Rules{Deny: []string{"jwt", "bearer_token"}})
	if !g.Denies() {
		t.Fatal("Denies is false")
	}
	if got := g.DeniedText("Authorization: Bearer abcdefghijklmnopqrstuvwxyz"); got != "bearer_token" {
		t.Fatalf("got %q", got)
	}
	if got := g.DeniedText("Bearer eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl"); got != "jwt" {
		t.Fatalf("first listed: %q", got)
	}
	if got := g.DeniedText("plain prose"); got != "" {
		t.Fatalf("prose: %q", got)
	}
	if g, _ := New(nil, nil, 0); g.Denies() {
		t.Fatal("a guard without deny patterns denies")
	}
}

func TestReportDecisionTruncated(t *testing.T) {
	g, _ := NewRules(Rules{MaxBytes: 3})
	rep := g.Apply(decode(t, `{"content":[{"type":"text","text":"abcdef"}]}`))
	if !rep.Truncated || rep.Decision() != "redact" {
		t.Fatalf("%+v", rep)
	}
}

func BenchmarkApplyWithDeny(b *testing.B) {
	g, err := NewRules(Rules{Redact: BuiltinNames(), Deny: BuiltinNames(), DenyPatterns: []string{`INTERNAL-ONLY-[0-9]+`}})
	if err != nil {
		b.Fatal(err)
	}
	text := strings.Repeat("ordinary tool output with numbers 12345 and words. ", 80)
	b.ReportAllocs()
	for b.Loop() {
		res := map[string]any{"content": []any{map[string]any{"type": "text", "text": text}},
			"structuredContent": map[string]any{"rows": []any{"a", "b", map[string]any{"k": "v"}}}}
		g.Apply(res)
	}
}
