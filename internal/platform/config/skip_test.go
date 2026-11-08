package config

import (
	"errors"
	"reflect"
	"testing"
)

type rateSection struct {
	Rate  float64 `json:"rate"`
	Burst int     `json:"burst"`
}

func TestFloat(t *testing.T) {
	sc := MustSchema(NewSection[rateSection]("limit", func(s *rateSection) { s.Rate = 1.5 }, nil))
	r := sc.Check([]byte(`{"version": 1, "limit": {"rate": 2.25}}`), nil)
	if err := r.Problems.Err(); err != nil {
		t.Fatal(err)
	}
	if got := Get[rateSection](r.Config, "limit").Rate; got != 2.25 {
		t.Fatalf("rate from the file = %v", got)
	}
	r = sc.Check([]byte(`{"version": 1, "limit": {"rate": 2}}`), []string{"AUTHZ_LIMIT_RATE= 0.5 "})
	if err := r.Problems.Err(); err != nil {
		t.Fatal(err)
	}
	if got := Get[rateSection](r.Config, "limit").Rate; got != 0.5 {
		t.Fatalf("rate from the environment = %v", got)
	}
	r = sc.Check([]byte(`{"version": 1, "limit": {}}`), nil)
	if got := Get[rateSection](r.Config, "limit").Rate; got != 1.5 {
		t.Fatalf("default rate = %v", got)
	}

	for _, c := range []struct {
		doc  string
		env  []string
		want []string
	}{
		{`{"version": 1, "limit": {"rate": "2"}}`, nil,
			[]string{`1:34 error $.limit.rate: must be a number, not a string`}},
		{`{"version": 1, "limit": {"rate": 1e999}}`, nil,
			[]string{`1:34 error $.limit.rate: 1e999 is not a finite number`}},
		{`{"version": 1, "limit": {"rate": [1]}}`, nil,
			[]string{`1:34 error $.limit.rate: must be a number, not an array`}},
		{`{"version": 1, "limit": {}}`, []string{"AUTHZ_LIMIT_RATE=fast"},
			[]string{`0:0 error $.limit.rate (AUTHZ_LIMIT_RATE): "fast" is not a finite number`}},
		{`{"version": 1, "limit": {}}`, []string{"AUTHZ_LIMIT_RATE=NaN"},
			[]string{`0:0 error $.limit.rate (AUTHZ_LIMIT_RATE): "NaN" is not a finite number`}},
		{`{"version": 1, "limit": {}}`, []string{"AUTHZ_LIMIT_RATE=+Inf"},
			[]string{`0:0 error $.limit.rate (AUTHZ_LIMIT_RATE): "+Inf" is not a finite number`}},
	} {
		got := lines(sc.Check([]byte(c.doc), c.env).Problems)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %q:\n got %q\nwant %q", c.doc, c.env, got, c.want)
		}
	}
	if got, want := sc.EnvNames("limit"), []string{"AUTHZ_LIMIT_BURST", "AUTHZ_LIMIT_RATE"}; !reflect.DeepEqual(got, want) {
		t.Errorf("EnvNames = %q, want %q", got, want)
	}
}

func TestSkip(t *testing.T) {
	sc := MustSchema(NewSection("serve", serveDefaults, checkServe), Skip("gateway"), Skip("mcp"))
	env := []string{"AUTHZ_SERVE_API_KEYS=k", "AUTHZ_GATEWAY_NOPE=1", "AUTHZ_GATEWAY_PUBLIC_URL=http://x"}

	// Another subcommand's sections are read past whatever they hold, even
	// what their own schema would refuse, and their variables are theirs.
	doc := `{"version": 1, "serve": {"addr": ":9"},
	  "gateway": {"public_url": "http://not-https", "unknown": [1, {"a": [true]}]},
	  "mcp": "not even an object"}`
	r := sc.Check([]byte(doc), env)
	if len(r.Problems) != 0 {
		t.Fatalf("problems: %q", lines(r.Problems))
	}
	if r.Config.Has("gateway") || r.Config.Has("mcp") || !r.Config.Has("serve") {
		t.Fatalf("Has: gateway %v, mcp %v, serve %v", r.Config.Has("gateway"), r.Config.Has("mcp"), r.Config.Has("serve"))
	}
	if Get[serveSection](r.Config, "serve").Addr != ":9" {
		t.Fatal("serve section not decoded")
	}
	if got := sc.EnvNames("gateway"); got != nil {
		t.Errorf("EnvNames(gateway) = %q", got)
	}

	// A section no subcommand has is still an error, with the skipped
	// names among the suggestions; a skipped section is still read once.
	got := lines(sc.Check([]byte(`{"version": 1, "gatway": {}, "mcp": null, "mcp": 1}`), nil).Problems)
	want := []string{
		`1:16 error $.gatway: unknown member (did you mean "gateway"?)`,
		`1:43 error $.mcp: duplicate member "mcp"`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}

	// A broken skipped section still breaks the document's JSON.
	got = lines(sc.Check([]byte(`{"version": 1, "mcp": {"a": [}`), nil).Problems)
	if len(got) != 1 || got[0][:5] != "1:30 " {
		t.Errorf("syntax error inside a skipped section: %q", got)
	}

	if _, err := NewSchema(Skip("mcp"), Skip("mcp")); err == nil {
		t.Error("two Skip sections with one name were accepted")
	}
	if _, err := NewSchema(Skip("Mcp")); err == nil {
		t.Error("a bad Skip name was accepted")
	}
}

func TestWatchValidate(t *testing.T) {
	f := newFiles(t)
	sc := MustSchema(NewSection[rateSection]("limit", nil, nil), Skip("other"))
	needLimit := func(c *Config) error {
		if !c.Has("limit") {
			return errors.New("no limit section")
		}
		return nil
	}
	f.write(f.config, `{"version": 1, "other": {}}`)
	if _, err := NewWatcher(sc, f.config, WatchOptions{Validate: needLimit}); err == nil || err.Error() != "no limit section" {
		t.Fatalf("first load without the section: %v", err)
	}
	f.write(f.config, `{"version": 1, "limit": {"rate": 1}}`)
	var refused []string
	w, err := NewWatcher(sc, f.config, WatchOptions{Validate: needLimit, OnError: func(err error) { refused = append(refused, err.Error()) }})
	if err != nil {
		t.Fatal(err)
	}
	f.write(f.config, `{"version": 1, "other": {"limit": {"rate": 2}}}`)
	if err := w.Poll(); err == nil {
		t.Fatal("a document without the section was put in place")
	}
	if got := Get[rateSection](w.Current(), "limit"); got == nil || got.Rate != 1 {
		t.Fatalf("current after a refused change: %+v", got)
	}
	f.write(f.config, `{"version": 1, "limit": {"rate": 3}}`)
	if err := w.Poll(); err != nil {
		t.Fatal(err)
	}
	if got := Get[rateSection](w.Current(), "limit").Rate; got != 3 {
		t.Fatalf("rate after a good change: %v", got)
	}
	if !reflect.DeepEqual(refused, []string{"no limit section"}) {
		t.Fatalf("OnError calls: %q", refused)
	}
}

func TestEnviron(t *testing.T) {
	t.Setenv("AUTHZ_TEST_PROCESS_ONLY", "p")
	sc := MustSchema(NewSection[rateSection]("limit", nil, nil), Skip("other"))
	m := map[string]string{"AUTHZ_LIMIT_RATE": "2", "AUTHZ_TEST_PROCESS_ONLY": "from getenv", "UNLISTED": "x"}
	got := sc.Environ(func(k string) string { return m[k] })
	want := []string{"AUTHZ_LIMIT_RATE=2", "AUTHZ_TEST_PROCESS_ONLY=from getenv"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Environ = %q, want %q", got, want)
	}
}
