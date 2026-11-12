package keys

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/clock"
)

var (
	daily      = Policy{RotateEvery: 24 * time.Hour, Overlap: 72 * time.Hour}
	everyMin   = Policy{RotateEvery: time.Minute, Overlap: 3 * time.Minute}
	specConsis = Spec{Name: RingConsistency, Alg: HS256, Policy: daily}
	specUp     = Spec{Name: RingUpstream, Alg: ES256, Policy: daily}
)

func openFile(t *testing.T, path string, c clock.Clock) *File {
	t.Helper()
	f, err := OpenFile(path, c)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFileEnsureCreatesAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	fc := clock.NewFake(t0)
	f := openFile(t, path, fc)
	if f.Path() != path || len(f.Set().Names()) != 0 {
		t.Fatalf("new file: %s %v", f.Path(), f.Set().Names())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenFile wrote the file: %v", err)
	}
	rings, err := f.Ensure(specConsis, specUp)
	if err != nil {
		t.Fatal(err)
	}
	if len(rings) != 2 || rings[0].Alg() != HS256 || rings[1].Alg() != ES256 || rings[0].Policy() != daily {
		t.Fatalf("rings %+v", rings)
	}
	if rings[0] != f.Set().Ring(RingConsistency) || rings[0].Next() == nil {
		t.Fatal("Ensure did not return the set's ring with a next key")
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("saved file: %v %v", fi, err)
	}
	// Asking again changes nothing and returns the same rings.
	before, _ := os.ReadFile(path)
	again, err := f.Ensure(specUp)
	if err != nil || again[0] != rings[1] {
		t.Fatalf("second Ensure: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("an Ensure that changed nothing rewrote the file")
	}

	// A restart reads the same keys back, and adds a ring it now needs.
	g := openFile(t, path, fc)
	got, err := g.Ensure(specConsis, Spec{Name: RingSession, Alg: A256GCM, Policy: daily})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Current().ID() != rings[0].Current().ID() || got[0].Next().ID() != rings[0].Next().ID() {
		t.Fatal("reopened ring has other keys")
	}
	if strings.Join(g.Set().Names(), ",") != "consistency,upstream,session" {
		t.Fatalf("names %v", g.Set().Names())
	}
	h := openFile(t, path, fc)
	if h.Set().Ring(RingSession) == nil {
		t.Fatal("added ring not saved")
	}
}

func TestFileEnsureRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	f := openFile(t, path, clock.NewFake(t0))
	if _, err := f.Ensure(specConsis); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(path)
	for _, c := range []struct {
		specs []Spec
		want  string
	}{
		{[]Spec{{Name: "Bad", Alg: HS256}}, `ring name "Bad"`},
		{[]Spec{{Name: "a", Alg: HS256}, {Name: "a", Alg: HS256}}, "ring a asked for twice"},
		{[]Spec{{Name: "a", Alg: "HS512"}}, "ring a: keys: unknown algorithm"},
		{[]Spec{{Name: "a", Alg: HS256, Policy: Policy{RotateEvery: time.Hour}}}, "ring a: keys: a ring that rotates on schedule needs an overlap"},
		{[]Spec{{Name: RingConsistency, Alg: ES256, Policy: daily}}, "ring consistency holds HS256 keys, want ES256"},
		{[]Spec{{Name: RingConsistency, Alg: HS256, Policy: everyMin}}, "ring consistency is already in use with rotation every 24h0m0s and overlap 72h0m0s, not rotation every 1m0s and overlap 3m0s"},
		{[]Spec{{Name: RingConsistency, Alg: HS256}}, "already in use with rotation every 24h0m0s and overlap 72h0m0s, not no scheduled rotation"},
	} {
		if _, err := f.Ensure(c.specs...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.specs, err, c.want)
		}
	}
	if _, err := f.Ensure(Spec{Name: RingConsistency, Alg: ES256}); !errors.Is(err, ErrRingAlg) {
		t.Errorf("alg mismatch is not ErrRingAlg: %v", err)
	}
	if now, _ := os.ReadFile(path); string(now) != string(saved) {
		t.Fatal("a refused Ensure changed the file")
	}
	if strings.Join(f.Set().Names(), ",") != "consistency" {
		t.Fatalf("a refused Ensure changed the set: %v", f.Set().Names())
	}
}

// A process started with another rotation policy keeps the ring's keys
// and saves the new policy.
func TestFileEnsurePolicyChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	fc := clock.NewFake(t0)
	r1, err := openFile(t, path, fc).Ensure(specConsis)
	if err != nil {
		t.Fatal(err)
	}
	f := openFile(t, path, fc)
	r2, err := f.Ensure(Spec{Name: RingConsistency, Alg: HS256, Policy: everyMin})
	if err != nil {
		t.Fatal(err)
	}
	if r2[0].Policy() != everyMin || r2[0].Current().ID() != r1[0].Current().ID() {
		t.Fatalf("policy %+v, same key %v", r2[0].Policy(), r2[0].Current().ID() == r1[0].Current().ID())
	}
	if f.Set().Ring(RingConsistency) != r2[0] {
		t.Fatal("set still holds the old ring")
	}
	if p := openFile(t, path, fc).Set().Ring(RingConsistency).Policy(); p != everyMin {
		t.Fatalf("saved policy %+v", p)
	}
}

func TestFileConflict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	fc := clock.NewFake(t0)
	f := openFile(t, path, fc)
	if _, err := f.Ensure(Spec{Name: RingAgent, Alg: HS256, Policy: everyMin}); err != nil {
		t.Fatal(err)
	}
	// Another process writes its own rings to the same file.
	other := openFile(t, filepath.Join(dir, "other.json"), fc)
	if _, err := other.Ensure(specConsis); err != nil {
		t.Fatal(err)
	}
	theirs, _ := os.ReadFile(filepath.Join(dir, "other.json"))
	if err := os.WriteFile(path, theirs, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Ensure(specUp); !errors.Is(err, ErrConflict) {
		t.Fatalf("Ensure over another writer's file: %v", err)
	}
	if f.Set().Ring(RingUpstream) != nil {
		t.Fatal("the set changed although the file was not written")
	}
	var mu sync.Mutex
	var seen []error
	f.OnChange(func(_ []string, err error) { mu.Lock(); seen = append(seen, err); mu.Unlock() })
	fc.Advance(time.Minute)
	changed, err := f.Check()
	if strings.Join(changed, ",") != "agent" || !errors.Is(err, ErrConflict) {
		t.Fatalf("Check: %v %v", changed, err)
	}
	if b, _ := os.ReadFile(path); string(b) != string(theirs) {
		t.Fatal("Check overwrote the other writer's file")
	}
	mu.Lock()
	if len(seen) != 1 || !errors.Is(seen[0], ErrConflict) {
		t.Fatalf("OnChange saw %v", seen)
	}
	mu.Unlock()

	// A removed file is a conflict too: something else manages it.
	g := openFile(t, filepath.Join(dir, "g.json"), fc)
	if _, err := g.Ensure(specConsis); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "g.json"))
	if _, err := g.Ensure(specUp); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("removed file: %v", err)
	}
}

func TestFileStartRotatesAndSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	fc := clock.NewFake(t0)
	f := openFile(t, path, fc)
	rings, err := f.Ensure(Spec{Name: RingAgent, Alg: HS256, Policy: everyMin}, specUp)
	if err != nil {
		t.Fatal(err)
	}
	first := rings[0].Current().ID()
	events := make(chan []string, 10)
	remove := f.OnChange(func(changed []string, err error) {
		if err != nil {
			t.Error(err)
		}
		events <- changed
	})
	second := make(chan []string, 10)
	f.OnChange(func(changed []string, _ error) { second <- changed })

	// Two users: the rings rotate once per tick, and keep rotating until
	// both contexts end.
	ctx1, stop1 := context.WithCancel(context.Background())
	ctx2, stop2 := context.WithCancel(context.Background())
	f.Start(ctx1)
	f.Start(ctx2)
	wait, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fc.BlockUntil(wait, 1); err != nil {
		t.Fatal(err)
	}
	if n := fc.Pending(); n != 1 {
		t.Fatalf("%d tickers for one file", n)
	}
	advance := func(d time.Duration) []string {
		t.Helper()
		for step := DefaultCheckEvery; step <= d; step += DefaultCheckEvery {
			fc.Advance(DefaultCheckEvery)
		}
		select {
		case c := <-events:
			return c
		case <-wait.Done():
			t.Fatal("no change reported")
			return nil
		}
	}
	if got := advance(time.Minute); strings.Join(got, ",") != "agent" {
		t.Fatalf("changed %v", got)
	}
	if got := <-second; strings.Join(got, ",") != "agent" {
		t.Fatalf("second subscriber saw %v", got)
	}
	if rings[0].Current().ID() == first || rings[0].Lookup(first, fc.Now()) == nil {
		t.Fatal("rotation did not keep the old key verifying")
	}
	saved := openFile(t, path, fc).Set().Ring(RingAgent)
	if saved.Current().ID() != rings[0].Current().ID() || saved.Lookup(first, fc.Now()) == nil {
		t.Fatal("the rotation was not saved")
	}

	remove()
	stop1()
	// ctx2 still runs the rings: the next rotation still reaches second.
	for step := time.Duration(0); step < time.Minute; step += DefaultCheckEvery {
		fc.Advance(DefaultCheckEvery)
	}
	select {
	case got := <-second:
		if strings.Join(got, ",") != "agent" {
			t.Fatalf("second subscriber saw %v", got)
		}
	case <-wait.Done():
		t.Fatal("rings stopped rotating while a user remained")
	}
	if len(events) != 0 {
		t.Fatal("a removed subscriber was called")
	}
	stop2()
	deadline := time.Now().Add(5 * time.Second)
	for fc.Pending() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the ticker outlived the last user")
		}
		time.Sleep(time.Millisecond)
	}

	// Starting again after every user left starts a new ticker.
	ctx3, stop3 := context.WithCancel(context.Background())
	defer stop3()
	f.Start(ctx3)
	if err := fc.BlockUntil(wait, 1); err != nil {
		t.Fatal(err)
	}
}

func TestFilesShare(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var fs Files
	a, err := fs.Open("keys.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := fs.Open(filepath.Join(dir, ".", "keys.json"))
	if err != nil || a != b {
		t.Fatalf("same path, other File: %v", err)
	}
	c, err := fs.Open("other.json")
	if err != nil || c == a {
		t.Fatalf("other path shares: %v", err)
	}
	if _, err := fs.Open(""); err == nil {
		t.Error("empty path accepted")
	}
	if _, err := OpenFile("", nil); err == nil {
		t.Error("empty path accepted")
	}
	os.WriteFile("broken.json", []byte(`{"version": 1, "rings": [{}]}`), 0o600)
	if _, err := fs.Open("broken.json"); err == nil || !strings.HasPrefix(err.Error(), "broken.json: keys: ring file") {
		t.Errorf("broken file: %v", err)
	}
	os.Mkdir("adir", 0o700)
	if _, err := OpenFile("adir", nil); err == nil {
		t.Error("a directory opened as a ring file")
	}
	// The real clock is the default.
	if a.clock.Now().Before(time.Now().Add(-time.Minute)) {
		t.Error("default clock is not the wall clock")
	}
}

func TestCheckFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "keys.json")
	if _, err := openFile(t, good, nil).Ensure(specConsis); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(dir, "broken.json")
	os.WriteFile(broken, []byte("{"), 0o600)
	notDir := filepath.Join(dir, "file")
	os.WriteFile(notDir, nil, 0o600)
	for path, want := range map[string]string{
		good:                                 "",
		filepath.Join(dir, "new.json"):       "",
		filepath.Join(dir, "no", "new.json"): "does not exist and can't be created",
		filepath.Join(notDir, "new.json"):    "not a directory",
		broken:                               "keys: ring file",
		dir:                                  "is a directory",
	} {
		err := CheckFile(path, specUp, specConsis)
		if (want == "" && err != nil) || (want != "" && (err == nil || !strings.Contains(err.Error(), want))) {
			t.Errorf("%s: %v, want %q", path, err, want)
		}
	}
	if err := CheckFile(good, Spec{Name: RingConsistency, Alg: A256GCM}); err == nil ||
		!strings.Contains(err.Error(), "ring consistency holds HS256 keys, want A256GCM") {
		t.Errorf("wrong alg: %v", err)
	}
}
