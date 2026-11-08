package logtest

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/laiwf94/authz/internal/platform/audit"
	"github.com/laiwf94/authz/internal/platform/logging"
)

// fakeT records what a Hook reports and runs its cleanups on demand.
type fakeT struct {
	testing.TB
	mu       sync.Mutex
	errors   []string
	fatal    string
	cleanups []func()
}

func (f *fakeT) Helper()           {}
func (f *fakeT) Cleanup(fn func()) { f.cleanups = append(f.cleanups, fn) }
func (f *fakeT) Errorf(s string, a ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errors = append(f.errors, fmt.Sprintf(s, a...))
}
func (f *fakeT) Fatal(a ...any) { f.fatal = fmt.Sprint(a...) }

// end runs the cleanups last-in first-out, as testing does.
func (f *fakeT) end() []string {
	for i := len(f.cleanups) - 1; i >= 0; i-- {
		f.cleanups[i]()
	}
	f.cleanups = nil
	return f.errors
}

const bearer = "Bearer abcdef0123456789"

func TestCheckSeesHandlerAndAudit(t *testing.T) {
	ft := &fakeT{TB: t}
	Check(ft)
	var buf bytes.Buffer
	log := logging.NewLogger(&buf, logging.Options{})
	log.Info("clean", "password", "hunter22") // redacted: no finding
	log.Info("leak", "header", bearer)
	l, err := audit.OpenWith(filepath.Join(t.TempDir(), "audit.log"), audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Append("tool_call", map[string]string{"upstream_url": "https://u:p4ssw0rd@h/x"}); err != nil {
		t.Fatal(err)
	}
	errs := ft.end()
	if len(errs) != 2 || !strings.Contains(errs[0], "log: auth_header: abcd…[16 bytes]") ||
		!strings.Contains(errs[1], "audit: url_password: [8 bytes]") {
		t.Fatalf("errors %q", errs)
	}
	for _, e := range errs {
		if strings.Contains(e, "0123456789") || strings.Contains(e, "p4ssw0rd") {
			t.Errorf("report carries the secret: %s", e)
		}
	}
	// After the test, nothing is watched.
	ft2 := &fakeT{TB: t}
	h := Check(ft2)
	ft2.end()
	log.Info("leak after the end", "header", bearer)
	if len(ft2.errors) != 0 || len(h.findings) != 0 {
		t.Errorf("watched after the end: %q", ft2.errors)
	}
}

func TestCheckClean(t *testing.T) {
	ft := &fakeT{TB: t}
	Check(ft).Known("configured-client-secret")
	logging.NewLogger(&bytes.Buffer{}, logging.Options{}).Info("m", "client_secret", "configured-client-secret")
	if errs := ft.end(); len(errs) != 0 {
		t.Errorf("errors %q", errs)
	}
}

func TestKnown(t *testing.T) {
	ft := &fakeT{TB: t}
	secret := "configured-client-secret"
	h := Check(ft).Known(secret)
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(h.Writer(&buf), nil)).Info("m", "opaque", base64.StdEncoding.EncodeToString([]byte(secret)))
	if !strings.Contains(buf.String(), `"opaque"`) {
		t.Fatalf("writer did not pass the record on: %q", buf.String())
	}
	errs := ft.end()
	if len(errs) != 1 || !strings.Contains(errs[0], "writer: known: [32 bytes] (base64)") {
		t.Errorf("errors %q", errs)
	}
	ft = &fakeT{TB: t}
	Check(ft).Known("short")
	if ft.fatal == "" {
		t.Error("a short known value did not fail the test")
	}
	ft.end()
}

func TestAllow(t *testing.T) {
	ft := &fakeT{TB: t}
	h := Check(ft).Allow(logging.RuleAuthHeader)
	h.Bytes("fixture", []byte(bearer))
	if errs := ft.end(); len(errs) != 0 {
		t.Errorf("allowed rule reported: %q", errs)
	}
	ft = &fakeT{TB: t}
	Check(ft).Allow("no_such_rule")
	if ft.fatal == "" {
		t.Error("an unknown rule did not fail the test")
	}
	ft.end()
}

func TestWriterLines(t *testing.T) {
	ft := &fakeT{TB: t}
	h := Check(ft)
	var buf bytes.Buffer
	w := h.Writer(&buf)
	// A secret split across writes is still seen, and a last line without
	// a newline is scanned at the end.
	for _, part := range []string{"Authorization: Bear", "er abcdef01", "23456789\nnext ", "password=hunter22"} {
		if _, err := w.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if buf.String() != "Authorization: Bearer abcdef0123456789\nnext password=hunter22" {
		t.Fatalf("passed on %q", buf.String())
	}
	errs := ft.end()
	if len(errs) != 2 || !strings.Contains(errs[0], "auth_header") || !strings.Contains(errs[1], "credential_param") {
		t.Errorf("errors %q", errs)
	}
}

type failWriter struct{}

func (failWriter) Write(p []byte) (int, error) { return 3, fmt.Errorf("disk full") }

func TestWriterScansOnlyWritten(t *testing.T) {
	ft := &fakeT{TB: t}
	w := Check(ft).Writer(failWriter{})
	if n, err := w.Write([]byte("abcpassword=hunter22\n")); n != 3 || err == nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if errs := ft.end(); len(errs) != 0 {
		t.Errorf("errors %q", errs)
	}
}

func TestFile(t *testing.T) {
	dir := t.TempDir()
	ft := &fakeT{TB: t}
	h := Check(ft)
	leak := filepath.Join(dir, "leak.log")
	h.File(leak)
	h.File(filepath.Join(dir, "never-written.log"))
	unreadable := filepath.Join(dir, "a-directory")
	if err := os.Mkdir(unreadable, 0o755); err != nil {
		t.Fatal(err)
	}
	h.File(unreadable)
	// Written after File was called: the file is read when the test ends.
	if err := os.WriteFile(leak, []byte(`{"seq":1}`+"\n"+`{"refresh_token":"r-0123456789"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	errs := ft.end()
	if len(errs) != 2 || !strings.Contains(errs[0], "reading "+unreadable) ||
		!strings.Contains(errs[1], leak+": credential_field: r-01…[12 bytes]") {
		t.Errorf("errors %q", errs)
	}
}

// Two hooks at once each see every record.
func TestTwoHooks(t *testing.T) {
	a, b := &fakeT{TB: t}, &fakeT{TB: t}
	Check(a)
	Check(b)
	logging.NewLogger(&bytes.Buffer{}, logging.Options{}).Info("m", "h", bearer)
	if ea, eb := a.end(), b.end(); len(ea) != 1 || len(eb) != 1 {
		t.Errorf("errors %q %q", ea, eb)
	}
}

// The hook on a real test: this test's own output is clean.
func TestCheckRealTest(t *testing.T) {
	h := Check(t).Known("a-value-never-logged")
	var buf bytes.Buffer
	log := logging.NewLogger(h.Writer(&buf), logging.Options{Subcommand: "serve"})
	log.Info("request", "authorization", bearer, "password", "a-value-never-logged")
	if !strings.Contains(buf.String(), logging.Redacted) {
		t.Fatalf("not redacted: %s", buf.String())
	}
}
