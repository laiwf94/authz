package config

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// listSection names a file its check reads with ReadFile: the file must
// hold the section's gen.
type listSection struct {
	Gen  int    `json:"gen"`
	List string `json:"list"`
}

func listSchema(limit int64, read *[]string) *Schema {
	return MustSchema(NewSection("app", nil, func(s *listSection, c *Checker) {
		b, err := c.ReadFile(s.List, limit)
		if err != nil {
			c.Errorf(c.Field("list"), "%v", err)
			return
		}
		*read = append(*read, string(b))
		if want := strings.Repeat("x", s.Gen); string(b) != want {
			c.Errorf(c.Field("list"), "holds %q, not %q", b, want)
		}
	}))
}

// A file a check reads with ReadFile is a source: the Watcher loads the
// configuration again when it changes, refuses a version the check
// refuses, and reads it with the check's limit.
func TestCheckerReadFile(t *testing.T) {
	f := newFiles(t)
	list := filepath.Join(f.dir, "list")
	f.write(list, "x")
	f.write(f.config, `{"version": 1, "app": {"gen": 1, "list": "`+list+`"}}`)
	var read []string
	var refused []error
	w, err := NewWatcher(listSchema(4, &read), f.config, WatchOptions{OnError: func(err error) { refused = append(refused, err) }})
	if err != nil {
		t.Fatal(err)
	}
	srcs := w.Current().Sources()
	if len(srcs) != 2 || srcs[0].Path != f.config || srcs[1].Path != list {
		t.Fatalf("sources: %+v", srcs)
	}
	if err := w.Poll(); !errors.Is(err, ErrUnchanged) {
		t.Fatalf("nothing changed: %v", err)
	}
	// Only the listed file changes, to something the check refuses.
	f.write(list, "xx")
	if err := w.Poll(); err == nil || !strings.Contains(err.Error(), `holds "xx", not "x"`) || len(refused) != 1 {
		t.Fatalf("refused change: %v, %d refusals", err, len(refused))
	}
	// Then the configuration catches up.
	f.write(f.config, `{"version": 1, "app": {"gen": 2, "list": "`+list+`"}}`)
	if err := w.Poll(); err != nil || Get[listSection](w.Current(), "app").Gen != 2 {
		t.Fatalf("change: %v", err)
	}
	// Over the check's limit: refused, then noticed again once it shrinks.
	f.write(list, "xxxxx")
	if err := w.Poll(); err == nil || !strings.Contains(err.Error(), "file larger than 4 bytes") {
		t.Fatalf("over the limit: %v", err)
	}
	if err := w.Poll(); !errors.Is(err, ErrUnchanged) {
		t.Fatalf("same oversized file: %v", err)
	}
	f.write(list, "xx")
	if err := w.Poll(); err != nil {
		t.Fatalf("back under the limit: %v", err)
	}
	// Removed: refused, and the configuration in place is kept.
	if err := os.Remove(list); err != nil {
		t.Fatal(err)
	}
	if err := w.Poll(); err == nil || Get[listSection](w.Current(), "app").Gen != 2 {
		t.Fatalf("removed: %v", err)
	}
	if got := strings.Join(read, ","); got != "x,xx,xx,xx" {
		t.Fatalf("contents the check saw: %s", got)
	}
}

// A limit of zero, or above MaxFileBytes, reads up to MaxFileBytes.
func TestCheckerReadFileDefaultLimit(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "list")
	if err := os.WriteFile(list, []byte(strings.Repeat("x", MaxSecretBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int64{0, -1, MaxFileBytes + 1} {
		var read []string
		r := listSchema(limit, &read).Check([]byte(`{"version": 1, "app": {"gen": `+
			strconv.Itoa(MaxSecretBytes+1)+`, "list": "`+list+`"}}`), nil)
		if err := r.Problems.Err(); err != nil || len(r.Sources) != 1 {
			t.Fatalf("limit %d: %v, %+v", limit, err, r.Sources)
		}
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte(strings.Repeat("x", MaxFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	var read []string
	r := listSchema(0, &read).Check([]byte(`{"version": 1, "app": {"gen": 1, "list": "`+big+`"}}`), nil)
	if err := r.Problems.Err(); err == nil || !strings.Contains(err.Error(), "file larger than") {
		t.Fatalf("over MaxFileBytes: %v", err)
	}
}
