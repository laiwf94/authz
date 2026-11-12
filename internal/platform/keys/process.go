package keys

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/platform/clock"
)

// Spec is a ring a subcommand needs from its process's ring file.
type Spec struct {
	Name   string
	Alg    Alg
	Policy Policy
}

// ErrConflict is returned when a ring file changed under a File since the
// File last read or wrote it: another process rotates the same file. The
// File keeps its rings and does not overwrite the other writer's keys.
var ErrConflict = errors.New("keys: the ring file changed since this process read it; is another process using it?")

// DefaultCheckEvery is how often a started File checks its rings.
const DefaultCheckEvery = time.Second

// File is the ring file of one process: the rings every subcommand in the
// process signs, seals and MACs with, saved where a restart finds them.
// Subcommands ask for the rings they need with Ensure; Start rotates them
// on their schedules, saving the file after every change. It is safe for
// concurrent use.
//
// One process owns a ring file. Before each write a File checks that the
// file still holds what it last read or wrote, and refuses with ErrConflict
// otherwise, so a second process pointed at the same file is reported
// instead of silently replacing the first one's keys.
type File struct {
	path  string
	clock clock.Clock
	every time.Duration

	mu    sync.Mutex
	set   *Set
	sum   [sha256.Size]byte // of the bytes last read or written; zero while the file does not exist
	inUse map[string]bool   // rings Ensure handed out
	subs  map[int]func(changed []string, err error)
	subID int
	users int
	stop  context.CancelFunc
	done  chan struct{}
}

// OpenFile reads the ring file at path, or starts an empty one when there
// is none yet; the file is written the first time Ensure adds a ring. c is
// the clock rotations run on; nil is the wall clock.
func OpenFile(path string, c clock.Clock) (*File, error) {
	if path == "" {
		return nil, errors.New("keys: no ring file path")
	}
	f := &File{path: path, clock: clock.Or(c), every: DefaultCheckEvery, set: NewSet(),
		inUse: map[string]bool{}, subs: map[int]func([]string, error){}}
	b, err := readLimited(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return f, nil
	case err != nil:
		return nil, err
	}
	if f.set, err = Unmarshal(b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	f.sum = sha256.Sum256(b)
	return f, nil
}

// Path returns the file's path.
func (f *File) Path() string { return f.path }

// Set returns the rings of the file. The set is the one Start rotates.
func (f *File) Set() *Set { return f.set }

// Ensure returns the rings specs name, in order, adding to the file the
// ones it lacks with fresh keys. A ring the file holds must have the alg
// its spec asks for. When the policy differs, the ring keeps its keys and
// takes the spec's policy, unless an earlier Ensure already handed it out
// under another one: two subcommands of one process must agree. The file is
// saved before Ensure returns when anything changed, and the set changes
// only once it is.
func (f *File) Ensure(specs ...Spec) ([]*Ring, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.clock.Now()
	type change struct {
		name  string
		ring  *Ring
		added bool
	}
	var changes []change
	seen := map[string]bool{}
	for _, sp := range specs {
		if !nameRe.MatchString(sp.Name) {
			return nil, fmt.Errorf("keys: ring name %q must be 1 to 32 lower-case letters, digits, '_' or '-', starting with a letter", sp.Name)
		}
		if seen[sp.Name] {
			return nil, fmt.Errorf("keys: ring %s asked for twice", sp.Name)
		}
		seen[sp.Name] = true
		if !sp.Alg.Valid() {
			return nil, fmt.Errorf("keys: ring %s: %w: %q", sp.Name, ErrAlg, sp.Alg)
		}
		if err := sp.Policy.Check(); err != nil {
			return nil, fmt.Errorf("keys: ring %s: %w", sp.Name, err)
		}
		r := f.set.Ring(sp.Name)
		switch {
		case r == nil:
			nr, err := NewRing(sp.Alg, sp.Policy, now)
			if err != nil {
				return nil, fmt.Errorf("keys: ring %s: %w", sp.Name, err)
			}
			changes = append(changes, change{sp.Name, nr, true})
		case r.Alg() != sp.Alg:
			return nil, fmt.Errorf("%w: %s: ring %s holds %s keys, want %s", ErrRingAlg, f.path, sp.Name, r.Alg(), sp.Alg)
		case r.Policy() != sp.Policy:
			if f.inUse[sp.Name] {
				return nil, fmt.Errorf("keys: ring %s is already in use with %s, not %s", sp.Name, describe(r.Policy()), describe(sp.Policy))
			}
			nr, err := Restore(sp.Alg, sp.Policy, r.Snapshot())
			if err != nil {
				return nil, fmt.Errorf("keys: ring %s: %w", sp.Name, err)
			}
			changes = append(changes, change{sp.Name, nr, false})
		}
	}
	if len(changes) > 0 {
		next := NewSet()
		for _, n := range f.set.Names() {
			next.rings[n], next.names = f.set.Ring(n), append(next.names, n)
		}
		for _, c := range changes {
			if c.added {
				next.names = append(next.names, c.name)
			}
			next.rings[c.name] = c.ring
		}
		if err := f.write(next); err != nil {
			return nil, err
		}
		for _, c := range changes {
			if c.added {
				if err := f.set.Add(c.name, c.ring); err != nil {
					return nil, err // impossible: checked above under f.mu
				}
			} else {
				f.set.replace(c.name, c.ring)
			}
		}
	}
	out := make([]*Ring, len(specs))
	for i, sp := range specs {
		f.inUse[sp.Name] = true
		out[i] = f.set.Ring(sp.Name)
	}
	return out, nil
}

func describe(p Policy) string {
	if p.RotateEvery == 0 {
		return "no scheduled rotation"
	}
	return fmt.Sprintf("rotation every %s and overlap %s", p.RotateEvery, p.Overlap)
}

// write saves s to the file, unless the file no longer holds what f last
// read or wrote. Called with f.mu held.
func (f *File) write(s *Set) error {
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	b = append(b, '\n')
	cur, err := readLimited(f.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if f.sum != ([sha256.Size]byte{}) {
			return fmt.Errorf("%s: %w (it was removed)", f.path, ErrConflict)
		}
	case err != nil:
		return err
	case sha256.Sum256(cur) != f.sum:
		return fmt.Errorf("%s: %w", f.path, ErrConflict)
	}
	if err := saveBytes(f.path, b); err != nil {
		return err
	}
	f.sum = sha256.Sum256(b)
	return nil
}

// OnChange registers fn to be called after every check that rotated or
// pruned rings, with their names, once the file is saved, and after every
// check that failed, with the error: the place to refresh a published JWKS
// and to log. It returns a function that removes fn.
func (f *File) OnChange(fn func(changed []string, err error)) (remove func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.subID
	f.subID++
	f.subs[id] = fn
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.subs, id)
	}
}

// Start rotates the file's rings on their schedules until ctx ends. Every
// subcommand sharing the file calls it with its own context; the rings
// rotate once however many do, and stop when the last context ends.
func (f *File) Start(ctx context.Context) {
	f.mu.Lock()
	f.users++
	if f.users == 1 {
		rctx, stop := context.WithCancel(context.Background())
		f.stop, f.done = stop, make(chan struct{})
		go f.run(rctx, f.done)
	}
	f.mu.Unlock()
	go func() {
		<-ctx.Done()
		f.mu.Lock()
		f.users--
		var done chan struct{}
		if f.users == 0 {
			f.stop()
			done = f.done
		}
		f.mu.Unlock()
		if done != nil {
			<-done
		}
	}()
}

func (f *File) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	t := f.clock.NewTicker(f.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
		}
		f.Check()
	}
}

// Check rotates the rings that are due and prunes the others, as one tick
// of Start does, saves the file when that changed anything and tells the
// OnChange functions. It returns the names of the rings that changed.
func (f *File) Check() ([]string, error) {
	f.mu.Lock()
	changed, err := f.set.Tick(f.clock.Now())
	if len(changed) > 0 {
		if werr := f.write(f.set); werr != nil {
			err = errors.Join(err, werr)
		}
	}
	subs := make([]func([]string, error), 0, len(f.subs))
	ids := make([]int, 0, len(f.subs))
	for id := range f.subs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		subs = append(subs, f.subs[id])
	}
	f.mu.Unlock()
	if len(changed) > 0 || err != nil {
		for _, fn := range subs {
			fn(changed, err)
		}
	}
	return changed, err
}

// Files is the ring files of one process, so that subcommands running
// together ("authz run") and naming the same file share one File: one set
// of rings, rotated once. The zero Files is ready to use.
type Files struct {
	// Clock is the clock the files' rings rotate on; nil is the wall clock.
	Clock clock.Clock

	mu    sync.Mutex
	files map[string]*File
}

// Open returns the File for path, opening it the first time. Paths that
// clean to the same absolute path share a File.
func (fs *Files) Open(path string) (*File, error) {
	if path == "" {
		return nil, errors.New("keys: no ring file path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if f := fs.files[abs]; f != nil {
		return f, nil
	}
	f, err := OpenFile(path, fs.Clock)
	if err != nil {
		return nil, err
	}
	if fs.files == nil {
		fs.files = map[string]*File{}
	}
	fs.files[abs] = f
	return f, nil
}

// CheckFile reports whether path can serve as a ring file holding specs:
// a file that is not there yet must be creatable in an existing directory,
// and one that is must read and hold each spec's ring, if it holds it at
// all, with the spec's alg. It writes nothing.
func CheckFile(path string, specs ...Spec) error {
	b, err := readLimited(path)
	if errors.Is(err, fs.ErrNotExist) {
		dir := filepath.Dir(path)
		if _, err := os.Stat(dir); err != nil {
			return fmt.Errorf("%s does not exist and can't be created: %w", path, err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	s, err := Unmarshal(b)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, sp := range specs {
		if r := s.Ring(sp.Name); r != nil && r.Alg() != sp.Alg {
			return fmt.Errorf("%s: ring %s holds %s keys, want %s", path, sp.Name, r.Alg(), sp.Alg)
		}
	}
	return nil
}
