package pins

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/platform/storage/wal"
)

func reopen(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// A pins file written by the old store, a JSON array, is converted to a pin
// log in place, keeping every pin and its exact definition bytes.
func TestOldFileIsConverted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.json")
	old := []Pin{
		{Tool: "a.echo", Hash: Hash(defA), Definition: defA, FirstSeen: now().UTC(), ApprovedAt: now().UTC(), ApprovedBy: "first-use",
			PendingHash: Hash(defB), PendingDefinition: defB, ChangedAt: now().UTC()},
		{Tool: "b.echo", Hash: Hash(defC), Definition: defC, FirstSeen: now().UTC(), ApprovedAt: now().UTC(), ApprovedBy: "admin"},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // as the old store wrote it
	if err := enc.Encode(old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.TrimSuffix(buf.Bytes(), []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	s := reopen(t, path)
	check := func(s *Store) {
		t.Helper()
		l := s.List()
		if len(l) != 2 || !l[0].Quarantined() || !bytes.Equal(l[0].Definition, defA) || !bytes.Equal(l[0].PendingDefinition, defB) ||
			l[1].ApprovedBy != "admin" || !bytes.Equal(l[1].Definition, defC) {
			t.Fatalf("pins %+v", l)
		}
	}
	check(s)
	data, _ := os.ReadFile(path)
	if data[0] == '[' || bytes.Count(data, []byte("\n")) != 2 {
		t.Fatalf("not converted to a pin log:\n%s", data)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".pins-*.tmp")); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
	s.Close()
	check(reopen(t, path))

	// An empty array converts to an empty log.
	empty := filepath.Join(t.TempDir(), "pins.json")
	os.WriteFile(empty, []byte("[]"), 0o600)
	if s := reopen(t, empty); len(s.List()) != 0 {
		t.Fatal("pins from nothing")
	}
	if fi, _ := os.Stat(empty); fi.Size() != 0 {
		t.Fatal("empty array not converted")
	}
}

// A conversion that cannot write leaves the old file untouched.
func TestFailedConversionKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pins.json")
	old := `[{"tool":"a","hash":"` + Hash(defC) + `","definition":` + string(defC) + `,"first_seen":"2000-01-01T00:00:00Z","approved_at":"2000-01-01T00:00:00Z","approved_by":"first-use"}]`
	os.WriteFile(path, []byte(old), 0o600)
	defer func() { createTemp, rename = os.CreateTemp, os.Rename }()
	injected := errors.New("injected")
	for name, set := range map[string]func(){
		"create": func() { createTemp = func(string, string) (*os.File, error) { return nil, injected } },
		"rename": func() { rename = func(string, string) error { return injected } },
	} {
		createTemp, rename = os.CreateTemp, os.Rename
		set()
		if _, err := Open(path, now); !errors.Is(err, injected) || !strings.Contains(err.Error(), "converting") {
			t.Fatalf("%s: %v", name, err)
		}
		if data, _ := os.ReadFile(path); string(data) != old {
			t.Fatalf("%s: the old file changed", name)
		}
		if left, _ := filepath.Glob(filepath.Join(dir, ".pins-*.tmp")); len(left) != 0 {
			t.Fatalf("%s: temp files left behind: %v", name, left)
		}
	}
	createTemp, rename = os.CreateTemp, os.Rename
	if s := reopen(t, path); len(s.List()) != 1 {
		t.Fatal("conversion after the failures")
	}
}

// Writes to a closed log fail, and the store fails closed with them.
func TestPinLogClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.json")
	s := reopen(t, path)
	s.Observe("a.x", defA)
	s.Close()
	if ok, _, err := s.Observe("a.y", defA); ok || !errors.Is(err, wal.ErrClosed) {
		t.Fatalf("append to a closed log: %v %v", ok, err)
	}
	if ok, _, err := s.Observe("a.z", defA); ok || !errors.Is(err, wal.ErrClosed) {
		t.Fatalf("snapshot of a closed log: %v %v", ok, err)
	}
}

// A crash can cut the log anywhere. Every prefix opens and holds the state
// of its complete records.
func TestPinLogCutAtEveryByte(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pins.json")
	s := reopen(t, path)
	s.Observe("a.x", defA)
	s.Observe("a.y", defC)
	s.Observe("a.x", defB)
	s.Approve("a.x", Hash(defB))
	s.Close()
	data, _ := os.ReadFile(path)
	type st struct{ hash, pending string }
	want := []map[string]st{{},
		{"a.x": {Hash(defA), ""}},
		{"a.x": {Hash(defA), ""}, "a.y": {Hash(defC), ""}},
		{"a.x": {Hash(defA), Hash(defB)}, "a.y": {Hash(defC), ""}},
		{"a.x": {Hash(defB), ""}, "a.y": {Hash(defC), ""}},
	}
	if n := bytes.Count(data, []byte("\n")); n != len(want)-1 {
		t.Fatalf("%d records, want %d", n, len(want)-1)
	}
	cut := filepath.Join(dir, "cut.json")
	for n := 0; n <= len(data); n++ {
		os.WriteFile(cut, data[:n], 0o600)
		s, err := Open(cut, now)
		if err != nil {
			t.Fatalf("cut at %d: %v", n, err)
		}
		w := want[bytes.Count(data[:n], []byte("\n"))]
		l := s.List()
		if len(l) != len(w) {
			t.Fatalf("cut at %d: %+v, want %v", n, l, w)
		}
		for _, p := range l {
			if w[p.Tool] != (st{p.Hash, p.PendingHash}) {
				t.Fatalf("cut at %d: %s is %+v, want %v", n, p.Tool, p, w[p.Tool])
			}
		}
		if ok, _, err := s.Observe("a.z", defA); !ok || err != nil {
			t.Fatalf("cut at %d: write after recovery: %v %v", n, ok, err)
		}
		s.Close()
	}
}

// Damage before the last record, or a record whose hash does not match its
// definition, stops Open.
func TestPinLogDamage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pins.json")
	s := reopen(t, path)
	s.Observe("a.x", defA)
	s.Observe("a.y", defC)
	s.Close()
	data, _ := os.ReadFile(path)
	data[20] ^= 0x01
	os.WriteFile(path, data, 0o600)
	if _, err := Open(path, now); !errors.Is(err, wal.ErrCorrupt) {
		t.Fatalf("damaged log: %v", err)
	}
	bad, _ := codec{}.Marshal(Pin{Tool: "a.x", Hash: Hash(defC), Definition: defA})
	good, _ := codec{}.Marshal(Pin{Tool: "a.y", Hash: Hash(defC), Definition: defC})
	p := filepath.Join(dir, "mismatch.json")
	os.WriteFile(p, append(append(wal.Frame(nil, bad), '\n'), append(wal.Frame(nil, good), '\n')...), 0o600)
	if _, err := Open(p, now); !errors.Is(err, wal.ErrCorrupt) {
		t.Fatalf("mismatched hash: %v", err)
	}
	for name, content := range map[string]string{"short.json": "nop", "space.json": "0123abcdX{}", "hexish.json": "0123abcg {}\n"} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o600)
		if _, err := Open(p, now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A torn first record is a crash, not damage.
	p = filepath.Join(dir, "torn.json")
	os.WriteFile(p, wal.Frame(nil, good)[:12], 0o600)
	if s, err := Open(p, now); err != nil || len(s.List()) != 0 {
		t.Fatalf("torn first record: %v", err)
	}
}

// Rewriting definitions keeps the log bounded.
func TestPinLogCompacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.json")
	s := reopen(t, path)
	defs := [][]byte{defA, defB}
	s.Observe("a.x", defA)
	for i := range 1000 {
		s.Observe("a.x", defs[(i+1)%2]) // quarantine, then back
	}
	if n := s.log.Records(); n > compactAfter+1 {
		t.Fatalf("%d records for one tool", n)
	}
	s.Close()
	if p, ok := reopen(t, path).Get("a.x"); !ok || p.Hash != Hash(defA) {
		t.Fatalf("after compaction: %+v", p)
	}
}

// A pins file removed or replaced while the gateway runs is rewritten from
// memory on the next change, instead of appends going to a file nobody will
// read.
func TestPinLogReplacedUnderneath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.json")
	s := reopen(t, path)
	s.Observe("a.x", defA)
	s.Observe("a.x", defB)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := s.Observe("a.y", defC); !ok || err != nil {
		t.Fatal(err)
	}
	// Another file under the same name.
	os.WriteFile(path+".new", nil, 0o600)
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := s.Observe("a.z", defC); !ok || err != nil {
		t.Fatal(err)
	}
	s2 := reopen(t, path)
	if l := s2.List(); len(l) != 3 || !l[0].Quarantined() {
		t.Fatalf("after rewrites: %+v", l)
	}
}

// After a failed write the next one restores everything held in memory,
// including a quarantine that could not be saved when it happened.
func TestPinLogResyncsAfterFailure(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0o700)
	path := filepath.Join(sub, "pins.json")
	s := reopen(t, path)
	s.Observe("a.x", defA)
	os.RemoveAll(sub)
	if _, q, err := s.Observe("a.x", defB); !q || err == nil {
		t.Fatal("quarantine")
	}
	os.Mkdir(sub, 0o700)
	if ok, _, err := s.Observe("a.y", defC); !ok || err != nil {
		t.Fatal(err)
	}
	s2 := reopen(t, path)
	if p, _ := s2.Get("a.x"); !p.Quarantined() || p.PendingHash != Hash(defB) {
		t.Fatalf("the quarantine was lost: %+v", p)
	}
	if _, ok := s2.Get("a.y"); !ok {
		t.Fatal("the new pin was lost")
	}
}

func TestMemoryStoreClose(t *testing.T) {
	s, _ := Open("", nil)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
