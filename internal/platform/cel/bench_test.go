package cel

import "testing"

// benchCaveat is a caveat of the size schemas write: an address range, an
// office-hours window in a named zone and a list membership.
const benchCaveat = `user_ip.in_cidr("10.0.0.0/8") && now.getHours("Europe/Berlin") >= 9 &&
	now.getHours("Europe/Berlin") < 17 && region in allowed && spent + 100 <= budget`

func benchEnv(b *testing.B) *Env {
	env, err := NewEnv([]Var{
		{"user_ip", IPAddress}, {"now", Timestamp}, {"region", String},
		{"allowed", ListOf(String)}, {"spent", Int}, {"budget", Int},
	})
	if err != nil {
		b.Fatal(err)
	}
	return env
}

func BenchmarkParse(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Parse(benchCaveat); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompile(b *testing.B) {
	env := benchEnv(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := env.CompileAs(benchCaveat, Bool); err != nil {
			b.Fatal(err)
		}
	}
}

// benchVars is a context for benchCaveat that makes it true, so every
// condition is evaluated, as the check walk passes it: stored and request
// context merged, in the types JSON gives.
var benchVars = map[string]any{
	"user_ip": "10.20.30.40", "now": "2026-11-23T10:15:00Z", "region": "eu-west",
	"allowed": []any{"us-east", "eu-west", "ap-south"}, "spent": 1200.0, "budget": 5000.0,
}

func BenchmarkEval(b *testing.B) {
	c, err := benchEnv(b).CompileAs(benchCaveat, Bool)
	if err != nil {
		b.Fatal(err)
	}
	p := c.Program(0)
	b.ReportAllocs()
	for b.Loop() {
		r, err := p.Eval(benchVars)
		if err != nil || r.Value != true {
			b.Fatal(r, err)
		}
	}
}

// BenchmarkEvalMissing is the same caveat with the request context not yet
// supplied: the result is conditional on two parameters.
func BenchmarkEvalMissing(b *testing.B) {
	c, err := benchEnv(b).CompileAs(benchCaveat, Bool)
	if err != nil {
		b.Fatal(err)
	}
	p := c.Program(0)
	vars := map[string]any{"allowed": benchVars["allowed"], "spent": 1200.0, "budget": 5000.0}
	b.ReportAllocs()
	for b.Loop() {
		r, err := p.Eval(vars)
		if err != nil || len(r.Missing) != 3 {
			b.Fatal(r, err)
		}
	}
}
