package keys

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var st0 = time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)

func digest(s string) [sha256.Size]byte { return sha256.Sum256([]byte(s)) }

func cfgKeys() []ConfigKey {
	return []ConfigKey{{Agent: "alice-bot", SHA256: digest("alice")}, {Agent: "bob-bot", SHA256: digest("bob")}}
}

func ids(list []StaticKey) []string {
	out := make([]string, len(list))
	for i, k := range list {
		out[i] = k.Agent + "/" + k.Source + "/" + k.ID
	}
	return out
}

func TestStaticKeyLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "static-keys.json")
	s, err := OpenStatic(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cfgKeys()
	if v, list := s.List(cfg, st0); v != 0 || len(list) != 2 || list[0].Source != StaticConfig || list[0].ID != StaticKeyID(digest("alice")) {
		t.Fatalf("fresh key set: version %d, %v", v, ids(list))
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("opening wrote the file: %v", err)
	}

	// Issue a second key for alice.
	k, v, err := s.Create(0, cfg, "alice-bot", digest("alice-2"), st0)
	if err != nil || v != 1 || k.ID != StaticKeyID(digest("alice-2")) || k.Source != StaticIssued || !k.Created.Equal(st0) {
		t.Fatalf("create: %+v, %d, %v", k, v, err)
	}
	if agent, id, ok := s.Issued(digest("alice-2"), st0); !ok || agent != "alice-bot" || id != k.ID {
		t.Fatalf("issued lookup: %q %q %v", agent, id, ok)
	}
	if _, _, ok := s.Issued(digest("alice"), st0); ok {
		t.Fatal("a configured key was found among the issued ones")
	}

	// A stale version is refused and changes nothing.
	if _, _, err := s.Create(0, cfg, "bob-bot", digest("bob-2"), st0); !errors.Is(err, ErrVersion) {
		t.Fatalf("stale create: %v", err)
	}
	if s.Version() != 1 {
		t.Fatalf("version after a refused change: %d", s.Version())
	}

	// Rotate alice's configured key with an hour of overlap.
	old, nk, v, err := s.Rotate(1, cfg, StaticKeyID(digest("alice")), digest("alice-3"), time.Hour, st0.Add(time.Minute))
	if err != nil || v != 2 || old.Source != StaticConfig || !old.Until.Equal(st0.Add(time.Minute+time.Hour)) || nk.Agent != "alice-bot" {
		t.Fatalf("rotate config key: %+v %+v %d %v", old, nk, v, err)
	}
	if !s.ConfigActive(digest("alice"), st0.Add(time.Hour)) {
		t.Fatal("the rotated configured key stopped verifying inside its overlap")
	}
	if s.ConfigActive(digest("alice"), st0.Add(61*time.Minute)) {
		t.Fatal("the rotated configured key verifies after its overlap")
	}
	// Rotating it again inside the overlap keeps the earlier end.
	again, _, v, err := s.Rotate(2, cfg, old.ID, digest("alice-4"), 2*time.Hour, st0.Add(2*time.Minute))
	if err != nil || v != 3 || !again.Until.Equal(old.Until) {
		t.Fatalf("second rotation: %+v %d %v", again, v, err)
	}

	// Rotate an issued key with no overlap: it goes at once.
	_, _, v, err = s.Rotate(3, cfg, k.ID, digest("alice-5"), 0, st0.Add(3*time.Minute))
	if err != nil || v != 4 {
		t.Fatalf("rotate issued key: %d %v", v, err)
	}
	if _, _, ok := s.Issued(digest("alice-2"), st0.Add(3*time.Minute)); ok {
		t.Fatal("an issued key rotated without overlap still verifies")
	}

	// Revoke bob's configured key and an issued key.
	rk, v, err := s.Revoke(4, cfg, StaticKeyID(digest("bob")), st0.Add(4*time.Minute))
	if err != nil || v != 5 || rk.Source != StaticConfig || rk.Agent != "bob-bot" {
		t.Fatalf("revoke config key: %+v %d %v", rk, v, err)
	}
	if s.ConfigActive(digest("bob"), st0.Add(4*time.Minute)) {
		t.Fatal("a revoked configured key verifies")
	}
	if _, v, err = s.Revoke(5, cfg, StaticKeyID(digest("alice-4")), st0.Add(5*time.Minute)); err != nil || v != 6 {
		t.Fatalf("revoke issued key: %d %v", v, err)
	}
	if _, _, err := s.Revoke(6, cfg, StaticKeyID(digest("bob")), st0.Add(5*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking a revoked key: %v", err)
	}
	// A revoked or used digest can't be issued again.
	for _, d := range []string{"bob", "alice", "alice-3"} {
		if _, _, err := s.Create(6, cfg, "bob-bot", digest(d), st0.Add(6*time.Minute)); err == nil || !strings.Contains(err.Error(), "already in use or was revoked") {
			t.Fatalf("reissuing %s: %v", d, err)
		}
	}

	at := st0.Add(2 * time.Hour)
	want := []string{"alice-bot/issued/" + StaticKeyID(digest("alice-3")), "alice-bot/issued/" + StaticKeyID(digest("alice-5"))}
	if _, list := s.List(cfg, at); fmt.Sprint(ids(list)) != fmt.Sprint(want) {
		t.Fatalf("key set: %v, want %v", ids(list), want)
	}

	// The file brings back everything, and revocations hold whatever
	// the configuration says later.
	r, err := OpenStatic(path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version() != 6 {
		t.Fatalf("reopened at version %d", r.Version())
	}
	if _, list := r.List(cfg, at); fmt.Sprint(ids(list)) != fmt.Sprint(want) {
		t.Fatalf("reopened key set: %v, want %v", ids(list), want)
	}
	if r.ConfigActive(digest("bob"), at) || r.ConfigActive(digest("alice"), at) || !r.ConfigActive(digest("carol"), at) {
		t.Fatal("reopened revocations differ")
	}
	if _, list := r.List(nil, at); len(list) != 2 {
		t.Fatalf("without configured keys: %v", ids(list))
	}
	b, _ := os.ReadFile(path)
	for _, secret := range []string{"alice-3", "alice-5"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("the file holds %s", secret)
		}
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", fi.Mode())
	}
}

func TestStaticKeyLimits(t *testing.T) {
	s, _ := OpenStatic("")
	v := uint64(0)
	for i := range MaxStaticKeysPerAgent {
		_, nv, err := s.Create(v, nil, "a", digest(fmt.Sprint("a", i)), st0)
		if err != nil {
			t.Fatal(err)
		}
		v = nv
	}
	if _, _, err := s.Create(v, nil, "a", digest("a-extra"), st0); !errors.Is(err, ErrStaticLimit) {
		t.Fatalf("one key too many for an agent: %v", err)
	}
	// A key inside its overlap still counts; one whose overlap ended doesn't.
	id := StaticKeyID(digest("a0"))
	if _, _, _, err := s.Rotate(v, nil, id, digest("a-extra"), time.Minute, st0); !errors.Is(err, ErrStaticLimit) {
		t.Fatalf("rotation over the limit: %v", err)
	}
	if _, _, nv, err := s.Rotate(v, nil, id, digest("a-extra"), 0, st0); err != nil {
		t.Fatalf("rotation without overlap at the limit: %v", err)
	} else {
		v = nv
	}
	for _, tc := range []struct {
		agent string
		ov    time.Duration
	}{{"", 0}, {strings.Repeat("x", 129), 0}, {"a\nb", 0}, {"\xff", 0}} {
		if _, _, err := s.Create(v, nil, tc.agent, digest("z"), st0); err == nil {
			t.Errorf("agent %q accepted", tc.agent)
		}
	}
	for _, ov := range []time.Duration{-time.Second, MaxStaticOverlap + time.Second} {
		if _, _, _, err := s.Rotate(v, nil, StaticKeyID(digest("a1")), digest("z"), ov, st0); err == nil {
			t.Errorf("overlap %s accepted", ov)
		}
	}
	if _, _, _, err := s.Rotate(v, nil, "nosuch", digest("z"), 0, st0); !errors.Is(err, ErrNotFound) {
		t.Errorf("rotating an unknown key: %v", err)
	}
	if s.Version() != v {
		t.Fatalf("refused changes moved the version to %d", s.Version())
	}

	// Revocations of configured keys are bounded too.
	var cfg []ConfigKey
	for i := range MaxStaticKeys + 1 {
		cfg = append(cfg, ConfigKey{Agent: "c", SHA256: digest(fmt.Sprint("c", i))})
	}
	r, _ := OpenStatic("")
	for i := range MaxStaticKeys {
		if _, _, err := r.Revoke(uint64(i), cfg, StaticKeyID(cfg[i].SHA256), st0); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := r.Revoke(MaxStaticKeys, cfg, StaticKeyID(cfg[MaxStaticKeys].SHA256), st0); !errors.Is(err, ErrStaticLimit) {
		t.Fatalf("one revocation too many: %v", err)
	}
}

func TestStaticKeyFileConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "static-keys.json")
	a, _ := OpenStatic(path)
	b, _ := OpenStatic(path)
	if _, _, err := a.Create(0, nil, "x", digest("x1"), st0); err != nil {
		t.Fatal(err)
	}
	// b read the file before a wrote it: it must not overwrite a's key.
	if _, _, err := b.Create(0, nil, "x", digest("x2"), st0); !errors.Is(err, ErrConflict) {
		t.Fatalf("second writer: %v", err)
	}
	if b.Version() != 0 {
		t.Fatal("a refused save took effect")
	}
	if _, _, ok := a.Issued(digest("x1"), st0); !ok {
		t.Fatal("first writer lost its key")
	}
	os.Remove(path)
	if _, _, err := a.Create(1, nil, "x", digest("x3"), st0); !errors.Is(err, ErrConflict) {
		t.Fatalf("file removed under the store: %v", err)
	}
	// A save that can't be written leaves the key set as it was.
	ro := filepath.Join(t.TempDir(), "ro")
	os.Mkdir(ro, 0o500)
	c, _ := OpenStatic(filepath.Join(ro, "static-keys.json"))
	if _, _, err := c.Create(0, nil, "x", digest("x4"), st0); err == nil && os.Getuid() != 0 {
		t.Fatal("a save into a read-only directory succeeded")
	} else if err != nil && c.Version() != 0 {
		t.Fatal("a failed save took effect")
	}
}

func TestOpenStaticRejectsBadFiles(t *testing.T) {
	h := func(s string) string { d := digest(s); return fmt.Sprintf("%x", d[:]) }
	key := func(agent, sum string) string {
		return fmt.Sprintf(`{"agent":%q,"sha256":%q,"created":"2026-11-23T09:00:00Z"}`, agent, sum)
	}
	many := func(n int, agent bool) string {
		var parts []string
		for i := range n {
			a := "a"
			if agent {
				a = fmt.Sprint("a", i)
			}
			parts = append(parts, key(a, h(fmt.Sprint(i))))
		}
		return strings.Join(parts, ",")
	}
	for name, src := range map[string]string{
		"not json":         `{`,
		"unknown field":    `{"format":1,"version":1,"issued":[],"revoked":[],"x":1}`,
		"trailing data":    `{"format":1,"version":1,"issued":[],"revoked":[]} {}`,
		"format":           `{"format":2,"version":1,"issued":[],"revoked":[]}`,
		"bad digest":       `{"format":1,"version":1,"issued":[` + key("a", "zz") + `],"revoked":[]}`,
		"upper-case hex":   `{"format":1,"version":1,"issued":[` + key("a", strings.ToUpper(h("x"))) + `],"revoked":[]}`,
		"short digest":     `{"format":1,"version":1,"issued":[` + key("a", h("x")[:62]) + `],"revoked":[]}`,
		"duplicate":        `{"format":1,"version":1,"issued":[` + key("a", h("x")) + `,` + key("b", h("x")) + `],"revoked":[]}`,
		"issued revoked":   `{"format":1,"version":1,"issued":[` + key("a", h("x")) + `],"revoked":[{"agent":"a","sha256":"` + h("x") + `","revoked":"2026-11-23T09:00:00Z"}]}`,
		"no agent":         `{"format":1,"version":1,"issued":[` + key("", h("x")) + `],"revoked":[]}`,
		"revoked no agent": `{"format":1,"version":1,"issued":[],"revoked":[{"agent":"","sha256":"` + h("x") + `","revoked":"2026-11-23T09:00:00Z"}]}`,
		"no created":       `{"format":1,"version":1,"issued":[{"agent":"a","sha256":"` + h("x") + `"}],"revoked":[]}`,
		"version 0":        `{"format":1,"version":0,"issued":[` + key("a", h("x")) + `],"revoked":[]}`,
		"per agent":        `{"format":1,"version":1,"issued":[` + many(MaxStaticKeysPerAgent+1, false) + `],"revoked":[]}`,
		"too many":         `{"format":1,"version":1,"issued":[` + many(MaxStaticKeys+1, true) + `],"revoked":[]}`,
		"too large":        strings.Repeat(" ", MaxFileBytes+1),
	} {
		path := filepath.Join(t.TempDir(), "static-keys.json")
		os.WriteFile(path, []byte(src), 0o600)
		if _, err := OpenStatic(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The limits themselves are accepted.
	path := filepath.Join(t.TempDir(), "static-keys.json")
	os.WriteFile(path, []byte(`{"format":1,"version":9,"issued":[`+many(MaxStaticKeysPerAgent, false)+`],"revoked":[]}`), 0o600)
	s, err := OpenStatic(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, list := s.List(nil, st0); s.Version() != 9 || len(list) != MaxStaticKeysPerAgent {
		t.Fatalf("version %d, %d keys", s.Version(), len(list))
	}
	if _, err := OpenStatic(t.TempDir()); err == nil {
		t.Error("a directory was read as a key file")
	}
}

func TestStaticKeyFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "static-keys.json")
	s, _ := OpenStatic(path)
	cfg := cfgKeys()
	s.Create(0, cfg, "alice-bot", digest("n1"), st0)
	s.Rotate(1, cfg, StaticKeyID(digest("n1")), digest("n2"), time.Hour, st0)
	s.Rotate(2, cfg, StaticKeyID(digest("bob")), digest("n3"), time.Hour, st0)
	b, _ := os.ReadFile(path)
	var f staticFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Format != 1 || f.Version != 3 || len(f.Issued) != 3 || len(f.Revoked) != 1 || f.Issued[0].Until == nil || f.Revoked[0].Until == nil {
		t.Fatalf("file: %s", b)
	}
	r, err := OpenStatic(path)
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := marshalStatic(r.state.Load())
	if string(mb) != string(b) {
		t.Fatalf("reopened file encodes differently:\n%s\n%s", mb, b)
	}
}

func TestOpenStaticRemovesStaleTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "static-keys.json")
	stale := filepath.Join(dir, ".static-keys.json.123456")
	other := filepath.Join(dir, ".pins.json.123456")
	for _, p := range []string{stale, other} {
		os.WriteFile(p, []byte("{"), 0o600)
	}
	if _, err := OpenStatic(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temporary file kept: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("another file's temporary file removed: %v", err)
	}
}
