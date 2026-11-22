package policy

import (
	"strings"
	"testing"
)

func TestOutputDenyPatterns(t *testing.T) {
	p, err := Parse([]byte(`{"version":1,"rules":[
	 {"id":"search","effect":"allow","agents":["*"],"upstreams":["web"],"tools":["search"],
	  "output":{"redact":["jwt"],"deny":["github_token","private_key"],"deny_patterns":["INTERNAL-[0-9]+"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(Subject{AgentID: "a"}, "web", "search", map[string]any{})
	if !d.Allowed || !d.Output.Denies() {
		t.Fatalf("deny patterns not attached: %+v", d)
	}
	if got := d.Output.DeniedText("ticket INTERNAL-12"); got != "deny_patterns[0]" {
		t.Fatalf("got %q", got)
	}
	res := map[string]any{"content": []any{map[string]any{"type": "text", "text": "ghp_" + strings.Repeat("x", 36)}}}
	if rep := d.Output.Apply(res); rep.Refused != "github_token" {
		t.Fatalf("%+v", rep)
	}

	rule := func(out string) string {
		return `{"version":1,"rules":[{"id":"r","effect":"allow","agents":["a"],"upstreams":["u"],"tools":["t"],"output":` + out + `}]}`
	}
	for src, want := range map[string]string{
		rule(`{"deny":["nope"]}`):        "unknown deny pattern",
		rule(`{"deny_patterns":["("]}`):  "deny pattern",
		rule(`{"deny_patterns":[""]}`):   "deny patterns must be",
		rule(`{"deny_patterns":["x?"]}`): "matches the empty string",
		rule(`{"deny":["jwt","jwt"]}`):   "listed twice",
		rule(`{"deny_pattern":["x"]}`):   "unknown field",
		`{"version":1,"rules":[{"id":"r","effect":"deny","agents":["a"],"upstreams":["u"],"tools":["t"],"output":{"deny":["jwt"]}}]}`: "only to allow rules",
	} {
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", src, err, want)
		}
	}
}
