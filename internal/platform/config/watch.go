package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laiwf94/authz/internal/platform/clock"
)

// DefaultInterval is how often a Watcher looks at its files. A change is
// applied within one interval and the time a load takes, well inside the
// five seconds the platform promises.
const DefaultInterval = time.Second

// WatchOptions configures a Watcher.
type WatchOptions struct {
	// Environ is the process environment (os.Environ()). It is read once:
	// a process's environment does not change while it runs.
	Environ []string
	// Interval is how often the files are compared with what was loaded;
	// zero means DefaultInterval.
	Interval time.Duration
	// Clock drives the polling ticker; nil is the wall clock. Tests pass a
	// *clock.Fake and advance it one interval at a time.
	Clock clock.Clock
	// Validate, if set, is a last check on a configuration that has no
	// errors, before it is put in place: an error refuses it as a problem
	// in the document would. A subcommand uses it to require its section.
	Validate func(*Config) error
	// OnReload, if set, is called after a new configuration is in place,
	// with the one it replaced and the warnings it has.
	OnReload func(old, cur *Config, warnings Problems)
	// OnError, if set, is called when a changed file does not load. The
	// configuration in place is kept. It is called once per bad version of
	// the files, not on every poll.
	OnError func(err error)
}

// Watcher holds the current configuration of a file and replaces it when
// the file, or a secret file it references, changes. Readers call Current
// on every use and see either the old configuration or the new one, never a
// mix; an invalid change is refused and the old configuration kept.
type Watcher struct {
	schema *Schema
	path   string
	env    map[string]string
	opts   WatchOptions

	cur atomic.Pointer[Config]

	mu      sync.Mutex // serializes polls
	watched []Source   // what the last load attempt read
	refused error      // why the last load attempt was refused; nil once one succeeds
}

// NewWatcher loads the file at path. It fails if the first load does: a
// process must not start without a valid configuration.
func NewWatcher(sc *Schema, path string, opts WatchOptions) (*Watcher, error) {
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	w := &Watcher{schema: sc, path: path, env: envMap(opts.Environ), opts: opts}
	r, err := sc.load(path, &loader{env: w.env})
	if err != nil {
		return nil, err
	}
	if err := w.validate(r); err != nil {
		return nil, err
	}
	w.cur.Store(r.Config)
	w.watched = r.Sources
	return w, nil
}

// Current returns the configuration in place. It never returns nil.
func (w *Watcher) Current() *Config { return w.cur.Load() }

// Run polls the files every interval until ctx is done, and returns
// ctx.Err().
func (w *Watcher) Run(ctx context.Context) error {
	t := clock.Or(w.opts.Clock).NewTicker(w.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C():
			w.Poll()
		}
	}
}

// ErrUnchanged is returned by Poll when no file changed since the last
// load attempt.
var ErrUnchanged = errors.New("config: unchanged")

// Poll compares the files with what the last load attempt read and, when
// any differs, loads them again. It returns nil when a new configuration
// was put in place, ErrUnchanged when nothing changed, and the load error
// when the change was refused. A refused version of the files is not
// retried until one of them changes again. Poll is what Run calls; call it
// directly to reload at once, on SIGHUP for example.
func (w *Watcher) Poll() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.changed() {
		return ErrUnchanged
	}
	r, err := w.schema.load(w.path, &loader{env: w.env})
	w.watched = r.Sources
	if err == nil {
		err = w.validate(r)
	}
	if err != nil {
		w.refused = err
		if w.opts.OnError != nil {
			w.opts.OnError(err)
		}
		return err
	}
	w.refused = nil
	old := w.cur.Swap(r.Config)
	if w.opts.OnReload != nil {
		var warnings Problems
		for _, p := range r.Problems {
			if p.Severity == SeverityWarning {
				warnings = append(warnings, p)
			}
		}
		w.opts.OnReload(old, r.Config, warnings)
	}
	return nil
}

// Refused returns the error that refused the files as they were last read,
// or nil when the configuration in place is the one they hold. A Poll that
// finds the files unchanged returns ErrUnchanged either way, so a reload
// someone asked for checks Refused to tell "nothing to do" from "still
// broken".
func (w *Watcher) Refused() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.refused
}

// validate returns the errors of a loaded document, then Validate's.
func (w *Watcher) validate(r *Result) error {
	if err := r.Problems.Err(); err != nil {
		return err
	}
	if w.opts.Validate != nil {
		return w.opts.Validate(r.Config)
	}
	return nil
}

// changed reads every watched file again and reports whether any now reads
// differently: other contents, or readable when it was not or the reverse.
func (w *Watcher) changed() bool {
	for _, s := range w.watched {
		b, err := readLimited(s.Path, s.limit)
		if (err != nil) != (s.Err != "") {
			return true
		}
		if err != nil {
			if err.Error() != s.Err {
				return true
			}
			continue
		}
		sum := sha256.Sum256(b)
		if !bytes.Equal(sum[:], s.Sum[:]) {
			return true
		}
	}
	return false
}
