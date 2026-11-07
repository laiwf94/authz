package config

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// reloadSection is valid only when its key file holds "key-<gen>", so a
// reader that saw a configuration put together from two versions of the
// files would notice.
type reloadSection struct {
	Gen   int    `json:"gen"`
	Key   Secret `json:"key"`
	Debug bool   `json:"debug"`
}

func reloadSchema(t testing.TB) *Schema {
	t.Helper()
	return MustSchema(NewSection("app", nil, func(s *reloadSection, c *Checker) {
		if want := fmt.Sprintf("key-%d", s.Gen); s.Key.Value() != want {
			c.Errorf(c.Field("key"), "holds a key for another generation (want %s)", want)
		}
		if s.Debug {
			c.Warnf(c.Field("debug"), "debug is on")
		}
	}))
}

type files struct {
	t        testing.TB
	dir      string
	config   string
	key      string
	tmpCount atomic.Int64
}

func newFiles(t testing.TB) *files {
	dir := t.TempDir()
	return &files{t: t, dir: dir, config: filepath.Join(dir, "authz.json"), key: filepath.Join(dir, "key")}
}

// write replaces path atomically, the way editors and Kubernetes do.
func (f *files) write(path, content string) {
	tmp := filepath.Join(f.dir, fmt.Sprintf(".tmp%d", f.tmpCount.Add(1)))
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		f.t.Error(err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		f.t.Error(err)
	}
}

// overwrite truncates and rewrites path in place, so a reader can see it
// empty or half written.
func (f *files) overwrite(path, content string) {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o600)
	if err != nil {
		f.t.Error(err)
		return
	}
	half := len(content) / 2
	fh.WriteString(content[:half])
	fh.Sync()
	fh.WriteString(content[half:])
	if err := fh.Close(); err != nil {
		f.t.Error(err)
	}
}

func (f *files) doc(gen int, key string) string {
	return fmt.Sprintf(`{"version": 1, "app": {"gen": %d, "key": {"file": %q}}}`, gen, key)
}

func gen(w *Watcher) int { return Get[reloadSection](w.Current(), "app").Gen }

func TestWatcherPoll(t *testing.T) {
	f := newFiles(t)
	f.write(f.key, "key-1\n")
	f.write(f.config, f.doc(1, f.key))
	var reloads, errs []string
	w, err := NewWatcher(reloadSchema(t), f.config, WatchOptions{
		OnReload: func(old, cur *Config, warnings Problems) {
			reloads = append(reloads, fmt.Sprintf("%d->%d [%s]", Get[reloadSection](old, "app").Gen, Get[reloadSection](cur, "app").Gen, warnings.Error()))
		},
		OnError: func(err error) { errs = append(errs, err.Error()) },
	})
	if err != nil {
		t.Fatal(err)
	}
	step := func(name string, want error, wantGen int) {
		t.Helper()
		got := w.Poll()
		if (want == nil) != (got == nil) || (want == ErrUnchanged) != errors.Is(got, ErrUnchanged) {
			t.Errorf("%s: Poll() = %v, want %v", name, got, want)
		}
		if g := gen(w); g != wantGen {
			t.Errorf("%s: gen %d, want %d", name, g, wantGen)
		}
	}
	errFailed := errors.New("refused")

	step("nothing changed", ErrUnchanged, 1)

	// The file moves to generation 2 before its key does: refused, and not
	// retried until something changes.
	f.write(f.config, f.doc(2, f.key))
	step("config ahead of its key", errFailed, 1)
	step("same bad files", ErrUnchanged, 1)
	f.write(f.key, "key-2\n")
	step("key catches up", nil, 2)

	f.write(f.config, `{"version": 1, "app": {"gen": 3,`)
	step("truncated JSON", errFailed, 2)
	f.write(f.config, f.doc(3, f.key))
	step("JSON fixed, key behind", errFailed, 2)
	f.write(f.key, "key-3")
	step("key written", nil, 3)

	// A change to a secret file alone reloads.
	f.write(f.key, "key-3\n\n")
	step("key file rewritten", nil, 3)

	if err := os.Remove(f.config); err != nil {
		t.Fatal(err)
	}
	step("config deleted", errFailed, 3)
	step("still deleted", ErrUnchanged, 3)
	f.write(f.config, f.doc(3, f.key))
	step("config restored", nil, 3)

	// A newly referenced secret file is watched from then on.
	key2 := filepath.Join(f.dir, "key2")
	f.write(key2, "key-4")
	f.write(f.config, f.doc(4, key2))
	step("new key file", nil, 4)
	f.write(key2, "key-5")
	step("new key file changed, behind", errFailed, 4)
	f.write(f.config, strings.Replace(f.doc(5, key2), `"gen"`, `"debug": true, "gen"`, 1))
	step("caught up with a warning", nil, 5)

	// A secret file that disappears is refused like the config file.
	if err := os.Remove(key2); err != nil {
		t.Fatal(err)
	}
	step("key file deleted", errFailed, 5)
	f.write(key2, "key-5")
	step("key file back", nil, 5)

	wantReloads := []string{
		"1->2 []", "2->3 []", "3->3 []", "3->3 []", "3->4 []",
		"4->5 [$.app.debug: debug is on]", "5->5 [$.app.debug: debug is on]",
	}
	if fmt.Sprint(reloads) != fmt.Sprint(wantReloads) {
		t.Errorf("reloads:\n got %q\nwant %q", reloads, wantReloads)
	}
	if len(errs) != 6 {
		t.Errorf("OnError called %d times, want 6: %q", len(errs), errs)
	}
	for _, want := range []string{"holds a key for another generation", "invalid JSON: unexpected end of file", "no such file"} {
		if !strings.Contains(strings.Join(errs, "\n"), want) {
			t.Errorf("no error mentions %q: %q", want, errs)
		}
	}
}

func TestNewWatcherRefuses(t *testing.T) {
	f := newFiles(t)
	if _, err := NewWatcher(reloadSchema(t), f.config, WatchOptions{}); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("missing file: %v", err)
	}
	f.write(f.key, "key-9")
	f.write(f.config, f.doc(1, f.key))
	if _, err := NewWatcher(reloadSchema(t), f.config, WatchOptions{}); err == nil || !strings.Contains(err.Error(), "another generation") {
		t.Errorf("invalid file: %v", err)
	}
}

// TestWatcherDefaultInterval measures how long a change takes to apply with
// the interval a deployment uses: the platform promises five seconds.
func TestWatcherDefaultInterval(t *testing.T) {
	f := newFiles(t)
	f.write(f.key, "key-1")
	f.write(f.config, f.doc(1, f.key))
	w, err := NewWatcher(reloadSchema(t), f.config, WatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v", err)
		}
	}()

	for g := 2; g <= 3; g++ {
		f.write(f.key, fmt.Sprintf("key-%d", g))
		f.write(f.config, f.doc(g, f.key))
		start := time.Now()
		for gen(w) != g {
			if time.Since(start) > 5*time.Second {
				t.Fatalf("generation %d not applied after 5s", g)
			}
			time.Sleep(10 * time.Millisecond)
		}
		elapsed := time.Since(start)
		t.Logf("generation %d applied after %v", g, elapsed.Round(time.Millisecond))
		if elapsed > DefaultInterval+time.Second {
			t.Errorf("generation %d took %v, more than one interval (%v) and a second", g, elapsed, DefaultInterval)
		}
	}
}

// TestReloadUnderLoad serves requests from the current configuration while
// the files are rewritten: atomically, in place (so they are read half
// written), out of order and with garbage. Every request must see one whole,
// valid configuration, and the generations a client sees never go back.
func TestReloadUnderLoad(t *testing.T) {
	f := newFiles(t)
	f.write(f.key, "key-1")
	f.write(f.config, f.doc(1, f.key))
	var refused atomic.Int64
	w, err := NewWatcher(reloadSchema(t), f.config, WatchOptions{
		Interval: 2 * time.Millisecond,
		OnError:  func(error) { refused.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		s := Get[reloadSection](w.Current(), "app")
		if s == nil || s.Key.Value() != fmt.Sprintf("key-%d", s.Gen) {
			http.Error(rw, "inconsistent configuration", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(rw, s.Gen)
	}))
	defer srv.Close()

	const last = 60
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var requests, failures atomic.Int64
	var lastSeen sync.Map
	for c := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := srv.Client()
			prev := 0
			for {
				select {
				case <-stop:
					lastSeen.Store(c, prev)
					return
				default:
				}
				resp, err := client.Get(srv.URL)
				if err != nil {
					failures.Add(1)
					t.Errorf("request: %v", err)
					return
				}
				var g int
				_, scanErr := fmt.Fscan(resp.Body, &g)
				resp.Body.Close()
				requests.Add(1)
				if resp.StatusCode != http.StatusOK || scanErr != nil {
					failures.Add(1)
					continue
				}
				if g < prev {
					failures.Add(1)
					t.Errorf("client %d went back from generation %d to %d", c, prev, g)
				}
				prev = g
			}
		}()
	}

	for g := 2; g <= last; g++ {
		key := fmt.Sprintf("key-%d", g)
		switch g % 4 {
		case 0: // the config first: refused until the key follows
			f.write(f.config, f.doc(g, f.key))
			time.Sleep(3 * time.Millisecond)
			f.write(f.key, key)
		case 1: // garbage, then the real thing written in place
			f.overwrite(f.config, `{"version": 1, "app": [`)
			time.Sleep(3 * time.Millisecond)
			f.overwrite(f.key, key)
			f.overwrite(f.config, f.doc(g, f.key))
		case 2: // in place, key first
			f.overwrite(f.key, key)
			f.overwrite(f.config, f.doc(g, f.key))
		default: // atomic, key first
			f.write(f.key, key)
			f.write(f.config, f.doc(g, f.key))
		}
		time.Sleep(5 * time.Millisecond)
	}
	deadline := time.Now().Add(5 * time.Second)
	for gen(w) != last && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	wg.Wait()

	if g := gen(w); g != last {
		t.Errorf("final generation %d, want %d", g, last)
	}
	if n := failures.Load(); n != 0 {
		t.Errorf("%d of %d requests failed", n, requests.Load())
	}
	if requests.Load() < 100 {
		t.Errorf("only %d requests ran", requests.Load())
	}
	if refused.Load() == 0 {
		t.Error("no change was refused; the test did not exercise refusal")
	}
	t.Logf("%d requests, 0 failed, %d reloads refused", requests.Load(), refused.Load())
}
