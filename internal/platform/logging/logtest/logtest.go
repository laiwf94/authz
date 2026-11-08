// Package logtest is the secret scanner's test hook: a test that calls
// Check fails if any log line or audit record written while it runs, any
// writer it wraps with Writer, or any file it names with File carries a
// key, token or password (see logging.Scanner for the rules).
//
//	h := logtest.Check(t).Known(clientSecret, apiKey)
//	srv := server.New(server.Config{Logger: slog.New(slog.NewJSONHandler(h.Writer(&buf), nil))})
//	h.File(filepath.Join(dir, "audit.log"))
//
// Records written through internal/platform/logging and
// internal/platform/audit are seen without wrapping anything. They are seen
// process-wide, so a finding in a test running in parallel with another may
// be reported by both. CI also runs every suite with -tags secretscan,
// which scans the same records without a call to Check (scripts/secret-scan.go).
package logtest

import (
	"bytes"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/laiwf94/authz/internal/platform/logging"
)

// Hook scans what a test writes and fails the test at its end on a finding.
type Hook struct {
	t testing.TB
	s *logging.Scanner

	mu       sync.Mutex
	findings []string
}

// Check starts scanning every record the platform's log handler and audit
// log write until t ends, and fails t then if any carried a secret.
func Check(t testing.TB) *Hook {
	t.Helper()
	h := &Hook{t: t, s: logging.NewScanner()}
	remove := logging.Watch(func(source string, p []byte) { h.scan(source, p) })
	t.Cleanup(func() {
		remove()
		h.report()
	})
	return h
}

// Known adds values that must not appear in any encoding, such as the
// passwords, client secrets and keys the test configures. A value shorter
// than logging.MinKnownBytes fails the test at once.
func (h *Hook) Known(values ...string) *Hook {
	h.t.Helper()
	if err := h.s.Known(values...); err != nil {
		h.t.Fatal(err)
	}
	return h
}

// Allow turns rules off for this test, whose output is meant to carry such
// a value. An unknown rule fails the test at once.
func (h *Hook) Allow(rules ...string) *Hook {
	h.t.Helper()
	if err := h.s.Allow(rules...); err != nil {
		h.t.Fatal(err)
	}
	return h
}

// Writer returns a writer that passes everything to w and scans it line by
// line, for loggers that do not write through internal/platform/logging. A
// last line without a newline is scanned when the test ends.
func (h *Hook) Writer(w io.Writer) io.Writer {
	lw := &lineWriter{h: h, w: w}
	h.t.Cleanup(lw.flush)
	return lw
}

// File scans the file at path when the test ends, before its temporary
// directories are removed if File is called after they were made. A file
// that does not exist then is not an error: the code under test may not
// have written it.
func (h *Hook) File(path string) {
	h.t.Cleanup(func() {
		b, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			h.t.Errorf("logtest: reading %s: %v", path, err)
			return
		}
		h.scan(path, b)
	})
}

// Bytes scans b now; a finding is reported when the test ends.
func (h *Hook) Bytes(source string, b []byte) { h.scan(source, b) }

func (h *Hook) scan(source string, p []byte) {
	fs := h.s.Scan(p)
	if len(fs) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, f := range fs {
		h.findings = append(h.findings, source+": "+f.Rule+": "+f.Excerpt)
	}
}

func (h *Hook) report() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, f := range h.findings {
		h.t.Errorf("logtest: secret in %s", f)
	}
}

type lineWriter struct {
	h *Hook
	w io.Writer

	mu  sync.Mutex
	buf []byte
}

func (l *lineWriter) Write(p []byte) (int, error) {
	n, err := l.w.Write(p)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p[:n]...)
	if i := bytes.LastIndexByte(l.buf, '\n'); i >= 0 {
		l.h.scan("writer", l.buf[:i+1])
		l.buf = append(l.buf[:0], l.buf[i+1:]...)
	}
	return n, err
}

func (l *lineWriter) flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buf) > 0 {
		l.h.scan("writer", l.buf)
		l.buf = nil
	}
}
