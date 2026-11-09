package config

import (
	"errors"
	"path/filepath"
	"testing"
)

// Refused keeps the reason a version of the files was refused until a load
// succeeds, while Poll reports those files as unchanged.
func TestWatcherRefused(t *testing.T) {
	f := newFiles(t)
	list := filepath.Join(f.dir, "list")
	f.write(list, "x")
	f.write(f.config, `{"version": 1, "app": {"gen": 1, "list": "`+list+`"}}`)
	var read []string
	w, err := NewWatcher(listSchema(4, &read), f.config, WatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if w.Refused() != nil {
		t.Fatal("refusal before any change")
	}
	f.write(list, "xx")
	perr := w.Poll()
	if perr == nil || w.Refused() == nil || w.Refused().Error() != perr.Error() {
		t.Fatalf("Poll %v, Refused %v", perr, w.Refused())
	}
	if err := w.Poll(); !errors.Is(err, ErrUnchanged) || w.Refused() == nil {
		t.Fatalf("unchanged after a refusal: Poll %v, Refused %v", err, w.Refused())
	}
	f.write(f.config, `{"version": 1, "app": {"gen": 2, "list": "`+list+`"}}`)
	if err := w.Poll(); err != nil || w.Refused() != nil {
		t.Fatalf("after the fix: Poll %v, Refused %v", err, w.Refused())
	}
}
