package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/platform/logging"
)

// Every record the log appends is handed to the platform's watchers (the
// secret scan) in chain order, as the exact line written without its
// newline; a record that is refused or not written is not.
func TestAppendIsObserved(t *testing.T) {
	var seen []string
	remove := logging.Watch(func(source string, p []byte) {
		if source == logging.SourceAudit {
			seen = append(seen, string(p))
		}
	})
	defer remove()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := OpenWith(path, Options{Schemas: Default()})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Append("tool_call", map[string]any{"agent": "a", "auth": "key", "decision": "allow", "stage": "policy"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Envelope{Actor: "api_key:0a1b2c3d", Action: "write"}, SchemaWritten{Revision: "r1", SHA256: "x", Bytes: 1}); err != nil {
		t.Fatal(err)
	}
	if err := l.AppendWith("no_such_event", Envelope{}, map[string]any{}); err == nil {
		t.Fatal("unknown event appended")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n"); len(seen) != 2 || seen[0] != want[0] || seen[1] != want[1] {
		t.Errorf("seen %q\nwant %q", seen, want)
	}

	// A failed write is not observed.
	seen = nil
	l.f = &failingFile{file: l.f}
	if err := l.Append("tool_call", map[string]any{}); err == nil {
		t.Fatal("append on a failing file succeeded")
	}
	if len(seen) != 0 {
		t.Errorf("failed write observed: %q", seen)
	}
}

type failingFile struct{ file }

func (f *failingFile) Write(p []byte) (int, error) { return 0, errors.New("disk full") }
