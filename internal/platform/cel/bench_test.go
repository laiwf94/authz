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
