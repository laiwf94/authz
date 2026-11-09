package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// Poll applies and reports a version of the file once, as a tick of Watch
// does, while Reload always reads and reports.
func TestStorePoll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	write := func(src string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"version":1,"rules":[]}`)
	var events []ReloadResult
	s, err := OpenStore(path, func(r ReloadResult) { events = append(events, r) })
	if err != nil {
		t.Fatal(err)
	}
	first := s.Current().Hash
	if r := s.Poll(); r.Changed || r.Err != nil || len(events) != 0 {
		t.Fatalf("unchanged file: %+v, %d events", r, len(events))
	}
	write(`{"version":1,"rules":[{"id":"r","effect":"allow","scopes":["a"],"upstreams":["u"],"tools":["t"]}]}`)
	if r := s.Poll(); !r.Changed || r.PrevHash != first || r.Hash == first || len(events) != 1 {
		t.Fatalf("changed file: %+v, %d events", r, len(events))
	}
	if r := s.Poll(); r.Changed || len(events) != 1 {
		t.Fatalf("same change again: %+v, %d events", r, len(events))
	}
	write(`{"version":1,"rules":[`)
	if r := s.Poll(); r.Err == nil || r.Changed || len(events) != 2 {
		t.Fatalf("broken file: %+v, %d events", r, len(events))
	}
	// The broken version is reported once; Reload reports it again.
	if r := s.Poll(); r.Err != nil || len(events) != 2 {
		t.Fatalf("broken file polled again: %+v, %d events", r, len(events))
	}
	if r := s.Reload(); r.Err == nil || len(events) != 3 {
		t.Fatalf("broken file reloaded: %+v, %d events", r, len(events))
	}
}
