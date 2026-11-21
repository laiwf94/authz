package session

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAuthContextSurvivesRestartAndCompaction: when and how the user
// authenticated, and the rule a step-up login was for, are kept with the
// session through a restart and the compaction that follows it, and stay
// out of the admin API's JSON.
func TestAuthContextSurvivesRestartAndCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.log")
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, path, c)
	authAt := c.now().Add(-3 * time.Minute)
	secret, sess, err := s.CreateWith(alice(), Extra{AuthTime: authAt, ACR: "urn:mfa", StepUp: "paths[3]"})
	if err != nil {
		t.Fatal(err)
	}
	plainSecret, plain, err := s.CreateWith(alice(), Extra{})
	if err != nil {
		t.Fatal(err)
	}
	check := func(s *Store, step string) {
		t.Helper()
		got, err := s.Lookup(secret)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		if a := got.Auth(); !a.Time.Equal(authAt) || a.ACR != "urn:mfa" || got.StepUp() != "paths[3]" {
			t.Fatalf("%s: auth %+v, step-up %q", step, a, got.StepUp())
		}
		p, err := s.Lookup(plainSecret)
		if err != nil || !p.Auth().Time.IsZero() || p.Auth().ACR != "" || p.StepUp() != "" {
			t.Fatalf("%s: plain session %+v %v", step, p.Auth(), err)
		}
	}
	check(s, "created")
	if a := sess.Auth(); !a.Time.Equal(authAt) || plain.StepUp() != "" {
		t.Fatalf("returned session: %+v", a)
	}
	s.Close()
	s2 := open(t, path, c)
	check(s2, "reopen")
	raw, _ := os.ReadFile(path)
	if n := strings.Count(string(raw), "\n"); n != 2 || !strings.Contains(string(raw), `"acr":"urn:mfa"`) ||
		strings.Count(string(raw), `"auth_time"`) != 1 {
		t.Fatalf("compacted log:\n%s", raw)
	}
	s2.Close()
	check(open(t, path, c), "second reopen")

	// The admin API shows sessions as their JSON, which has none of it.
	if b, _ := jsonOf(sess); strings.Contains(b, "acr") || strings.Contains(b, "auth_time") || strings.Contains(b, "step_up") {
		t.Fatalf("session JSON shows the auth context: %s", b)
	}
}

func TestAuthContextRefused(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, filepath.Join(t.TempDir(), "s.log"), c)
	for name, e := range map[string]Extra{
		"acr with a space":  {ACR: "two words"},
		"acr too long":      {ACR: strings.Repeat("a", 257)},
		"step-up too long":  {StepUp: strings.Repeat("p", MaxStepUpBytes+1)},
		"step-up with a NL": {StepUp: "paths[1]\n"},
	} {
		if _, _, err := s.CreateWith(alice(), e); !errors.Is(err, ErrBadAuth) {
			t.Errorf("%s: %v", name, err)
		}
	}
	sess := &Session{ID: strings.Repeat("a", 32), Identity: alice(), CreatedAt: time.Unix(100, 0), LastSeen: time.Unix(100, 0),
		ExpiresAt: time.Unix(10_000, 0)}
	for name, rec := range map[string]record{
		"bad acr":     {Op: opCreate, Session: sess, ACR: "a\tb"},
		"bad step-up": {Op: opCreate, Session: sess, StepUp: "x y"},
	} {
		if err := validate(rec); err == nil {
			t.Errorf("%s accepted on replay", name)
		}
	}
	if err := validate(record{Op: opCreate, Session: sess, ACR: "urn:mfa", StepUp: "paths[0]", AuthTime: time.Unix(90, 0)}); err != nil {
		t.Fatal(err)
	}
}

func jsonOf(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
