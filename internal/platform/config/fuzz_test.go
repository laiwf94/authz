package config

import (
	"strings"
	"testing"
)

func FuzzCheck(f *testing.F) {
	for _, seed := range []string{
		`{"version": 1, "serve": {"addr": ":1", "api_keys": {"env": "K"}, "hosts": ["a"], "limits": {"burst": 1, "window": "1s"}}}`,
		`{"version": 1, "serve": {"upstreams": {"a": {"url": "u", "credential": {"env": "K"}}}, "tokens": [{"env": "K"}], "labels": {"x y": "z"}}}`,
		`{"version": 1, "gateway": {"public_url": "https://x"}}`,
		`{"version": 2}`, `[]`, `null`, `{"version": 1} x`, `{"version": "1", "serv": 1, "serve": []}`,
		`{"version": 1, "serve": {"api_keys": "literal", "timeout": "-1s", "shards": 1e3}}`,
	} {
		f.Add(seed)
	}
	sc := testSchema(f)
	env := []string{"K=k", "AUTHZ_SERVE_CACHE_SIZE=3"}
	f.Fuzz(func(t *testing.T, doc string) {
		r := sc.Check([]byte(doc), env)
		for _, p := range r.Problems {
			if !strings.HasPrefix(p.Path, "$") || p.Line < 0 || p.Column < 0 || p.Message == "" {
				t.Fatalf("bad problem %+v", p)
			}
			if p.Line > 0 && p.Line > strings.Count(doc, "\n")+1 {
				t.Fatalf("problem past the end of the document: %+v", p)
			}
		}
		if r.Problems.Err() == nil {
			if r.Config == nil || r.Config.Version != Version {
				t.Fatalf("no errors but config %+v", r.Config)
			}
			if s := Get[serveSection](r.Config, "serve"); s != nil && s.CacheSize != 3 {
				t.Fatalf("override lost: cache_size %d", s.CacheSize)
			}
		}
	})
}
