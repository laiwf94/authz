package policy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ReloadResult describes one reload attempt.
type ReloadResult struct {
	Changed  bool   // a new policy is now in force
	Hash     string // hash of the policy in force after the attempt
	PrevHash string
	Err      error // the file was unreadable or invalid; the previous policy stays
}

// Store holds the policy in force and replaces it atomically when its file
// changes. A file that does not parse or validate is rejected and the previous
// policy stays in force, so a half-written edit can never open access.
type Store struct {
	path     string
	cur      atomic.Pointer[Policy]
	mu       sync.Mutex        // serializes reloads
	seen     [sha256.Size]byte // hash of the file contents last looked at, valid or not
	onReload func(ReloadResult)
}

// missing stands in for the contents of a file that could not be read, so a
// missing file is reported once rather than on every poll.
var missing = sha256.Sum256([]byte("\x00missing"))

// OpenStore loads the policy at path. onReload, if set, is called after every
// reload that changed the policy or failed.
func OpenStore(path string, onReload func(ReloadResult)) (*Store, error) {
	s := &Store{path: path, onReload: onReload}
	src, err := s.read()
	if err != nil {
		return nil, err
	}
	p, err := Parse(src)
	if err != nil {
		return nil, err
	}
	s.cur.Store(p)
	s.seen = sha256.Sum256(src)
	return s, nil
}

// SetOnReload replaces the reload callback.
func (s *Store) SetOnReload(f func(ReloadResult)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onReload = f
}

// Current returns the policy in force.
func (s *Store) Current() *Policy { return s.cur.Load() }

func (s *Store) read() ([]byte, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	defer f.Close()
	src, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return src, nil
}

// Reload re-reads the file now and reports the outcome, even when the
// contents have not changed since the last look.
func (s *Store) Reload() ReloadResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloadLocked(true)
}

// Poll reads the file and applies it if its contents differ from the last
// contents looked at, as one tick of Watch does: a policy already in force,
// or one already rejected, is not applied or reported again. Something
// else that watches the file, such as the platform configuration watcher,
// calls it when it sees the file change.
func (s *Store) Poll() ReloadResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloadLocked(false)
}

// reloadLocked reads and applies the file. Unless force is set, contents
// already looked at (valid or not) are skipped silently.
func (s *Store) reloadLocked(force bool) ReloadResult {
	prev := s.cur.Load()
	res := ReloadResult{Hash: prev.Hash, PrevHash: prev.Hash}
	src, err := s.read()
	sum := missing
	if err == nil {
		sum = sha256.Sum256(src)
	}
	if !force && sum == s.seen {
		return res
	}
	s.seen = sum
	var p *Policy
	if err == nil {
		p, err = Parse(src)
	}
	switch {
	case err != nil:
		res.Err = err
	case p.Hash != prev.Hash:
		s.cur.Store(p)
		res.Changed, res.Hash = true, p.Hash
	default:
		return res
	}
	if s.onReload != nil {
		s.onReload(res)
	}
	return res
}

// Watch re-reads the file every interval and applies it when its contents
// change. Comparing contents rather than size and mtime catches a same-size
// rewrite within one mtime tick; the file is at most 1 MiB, so reading it
// every couple of seconds costs nothing. It returns when ctx ends.
func (s *Store) Watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.mu.Lock()
		s.reloadLocked(false)
		s.mu.Unlock()
	}
}
