package logging

import (
	"io"
	"sync"
	"sync/atomic"
)

// Sources Observe is called with.
const (
	SourceLog   = "log"   // a record a Handler wrote
	SourceAudit = "audit" // a record the audit log appended
)

// A Watcher sees the bytes of every record a Handler or the audit log
// writes, after redaction, while it is registered. It must not keep or
// change p, and it runs on the writer's goroutine, under its lock.
type Watcher func(source string, p []byte)

type watch struct{ fn Watcher }

var (
	watchMu  sync.Mutex
	watchers atomic.Pointer[[]*watch]
)

// Watch registers fn until the returned function is called. It is how the
// secret scan sees every log line and audit record a test produces (see
// the logtest package and secretscan.go); nothing in a running server
// registers one.
func Watch(fn Watcher) (remove func()) {
	w := &watch{fn: fn}
	watchMu.Lock()
	defer watchMu.Unlock()
	cur := watchers.Load()
	var next []*watch
	if cur != nil {
		next = append(next, *cur...)
	}
	next = append(next, w)
	watchers.Store(&next)
	var once sync.Once
	return func() {
		once.Do(func() {
			watchMu.Lock()
			defer watchMu.Unlock()
			cur := watchers.Load()
			var next []*watch
			for _, x := range *cur {
				if x != w {
					next = append(next, x)
				}
			}
			if len(next) == 0 {
				watchers.Store(nil)
				return
			}
			watchers.Store(&next)
		})
	}
}

// Observe hands p to every registered Watcher. Writers of log and audit
// output call it once per record; with no Watcher it costs one atomic load.
func Observe(source string, p []byte) {
	ws := watchers.Load()
	if ws == nil {
		return
	}
	for _, w := range *ws {
		w.fn(source, p)
	}
}

// observed is the writer a Handler writes through.
type observed struct{ w io.Writer }

func (o observed) Write(p []byte) (int, error) {
	n, err := o.w.Write(p)
	if n > 0 {
		Observe(SourceLog, p[:n])
	}
	return n, err
}
