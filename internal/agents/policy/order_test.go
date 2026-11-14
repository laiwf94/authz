package policy

import (
	"path/filepath"
	"sync"
	"testing"
)

// TestReloadHookBeforeSwap: the reload hook of a change runs before the new
// policy is in force, so once Current shows it, what the hook wrote (the
// policy_applied audit record) is already there (#242). A failed reload
// still reports with the old policy in force.
func TestReloadHookBeforeSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writeFile(t, path, `{"version":1,"rules":[]}`)
	var s *Store
	var mu sync.Mutex
	var seenInForce []string
	s, err := OpenStore(path, func(r ReloadResult) {
		mu.Lock()
		seenInForce = append(seenInForce, s.Current().Hash)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	h1 := s.Current().Hash
	writeFile(t, path, `{"version":1,"rules":[{"id":"a","effect":"allow","agents":["*"],"upstreams":["*"],"tools":["*"]}]}`)
	r := s.Reload()
	if !r.Changed || s.Current().Hash != r.Hash {
		t.Fatalf("reload: %+v", r)
	}
	writeFile(t, path, `{"version":1,"rules":[{"id":"x"`)
	if r := s.Reload(); r.Err == nil {
		t.Fatalf("torn file accepted: %+v", r)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seenInForce) != 2 || seenInForce[0] != h1 || seenInForce[1] != r.Hash {
		t.Fatalf("policy in force when the hook ran: %v, want [%s %s]", seenInForce, h1, r.Hash)
	}
}
