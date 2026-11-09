package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Severity says whether a Problem stops a document from loading.
type Severity int

// Severities.
const (
	SeverityError Severity = iota
	SeverityWarning
)

func (s Severity) String() string {
	if s == SeverityWarning {
		return "warning"
	}
	return "error"
}

// Problem is one finding about a configuration.
type Problem struct {
	// Path is a JSON path into the document, such as $.gateway.apps[0].hosts[1].
	// For a missing field it names the object the field belongs in.
	Path string
	// Env names the environment variable the value at Path came from, when
	// an override set it. Such a problem has no Line or Column.
	Env string
	// Line and Column locate the value at Path in the file (1-based); 0 when
	// it is not in the file.
	Line, Column int
	Severity     Severity
	Message      string
}

func (p Problem) String() string {
	if p.Env != "" {
		return p.Path + " (" + p.Env + "): " + p.Message
	}
	return p.Path + ": " + p.Message
}

// Problems is every finding about a configuration, in document order.
type Problems []Problem

// Count returns how many problems have severity s.
func (ps Problems) Count(s Severity) int {
	n := 0
	for _, p := range ps {
		if p.Severity == s {
			n++
		}
	}
	return n
}

// Err returns the errors as one error, or nil when there are none. Warnings
// never fail a load.
func (ps Problems) Err() error {
	var errs Problems
	for _, p := range ps {
		if p.Severity == SeverityError {
			errs = append(errs, p)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// Error joins the problems as "path: message; path: message".
func (ps Problems) Error() string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, "; ")
}

// Checker records problems at JSON paths and locates them in the source. A
// section's Check function receives one. It is safe for concurrent use.
type Checker struct {
	// Path is the JSON path of the section being checked, such as $.serve.
	Path string

	r *report
	l *loader
}

// ReadFile reads a file the section names, such as a policy or a list of
// clients, of at most limit bytes. The file becomes one of the
// configuration's sources: a Watcher loads the configuration again, and
// checks the section again, when it changes, so a check that reads a file
// with ReadFile makes that file reload live as the configuration does.
func (c *Checker) ReadFile(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > MaxFileBytes {
		limit = MaxFileBytes
	}
	return c.l.read(path, limit)
}

// Errorf records an error at path.
func (c *Checker) Errorf(path, format string, args ...any) {
	c.r.add(SeverityError, path, format, args...)
}

// Warnf records a warning at path.
func (c *Checker) Warnf(path, format string, args ...any) {
	c.r.add(SeverityWarning, path, format, args...)
}

// Field returns the path of a member of the section: Field("addr") is
// $.serve.addr in the serve section.
func (c *Checker) Field(name string) string { return KeyPath(c.Path, name) }

type report struct {
	src      []byte
	pos      map[string]int    // path -> byte offset of its value
	fromEnv  map[string]string // path -> variable that overrode it
	unplaced map[string]bool   // sections given only by the environment
	mu       sync.Mutex
	problems Problems
}

func newReport(src []byte) *report {
	return &report{src: src, pos: map[string]int{}, fromEnv: map[string]string{}, unplaced: map[string]bool{}}
}

// add records a problem at path. A path an environment variable set (or
// that lies under one) names the variable and has no position; any other
// path is located at its value, or at the nearest enclosing value for a
// path that is not in the document, unless that is a section only the
// environment gave.
func (r *report) add(sev Severity, path, format string, args ...any) {
	p := Problem{Path: path, Severity: sev, Message: fmt.Sprintf(format, args...)}
	for q := path; q != ""; q = parentPath(q) {
		if env, ok := r.fromEnv[q]; ok {
			p.Env = env
			break
		}
	}
	if p.Env == "" {
		for q := path; q != "" && !r.unplaced[q]; q = parentPath(q) {
			if off, ok := r.pos[q]; ok {
				p.Line, p.Column = lineCol(r.src, off)
				break
			}
		}
	}
	r.mu.Lock()
	r.problems = append(r.problems, p)
	r.mu.Unlock()
}

func (r *report) errorf(path, format string, args ...any) {
	r.add(SeverityError, path, format, args...)
}

// sorted returns the problems in file order; problems from the environment
// follow those in the file, and problems at the same place keep the order
// they were found in.
func (r *report) sorted() Problems {
	r.mu.Lock()
	defer r.mu.Unlock()
	ps := append(Problems(nil), r.problems...)
	rank := func(p Problem) int {
		if p.Line == 0 {
			return 1 << 30
		}
		return p.Line
	}
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		return a.Column < b.Column
	})
	return ps
}

// parentPath drops the last segment: $.a[0].b -> $.a[0] -> $.a -> $ -> "".
// A quoted key segment such as $["a.b"] is dropped whole.
func parentPath(p string) string {
	if p == "$" || p == "" {
		return ""
	}
	if strings.HasSuffix(p, `"]`) {
		if i := strings.LastIndex(p, `["`); i > 0 {
			return p[:i]
		}
	}
	i := strings.LastIndexAny(p, ".[")
	if i <= 0 {
		return "$"
	}
	return p[:i]
}

func lineCol(src []byte, off int) (int, int) {
	off = min(max(off, 0), len(src))
	before := src[:off]
	line := bytes.Count(before, []byte("\n")) + 1
	col := off - bytes.LastIndexByte(before, '\n')
	return line, col
}

var plainKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// KeyPath returns the path of member key of the object at parent: $.a.b, or
// $.a["odd key"] when the key is not a plain identifier.
func KeyPath(parent, key string) string {
	if plainKey.MatchString(key) {
		return parent + "." + key
	}
	b, _ := json.Marshal(key)
	return parent + "[" + string(b) + "]"
}

// IndexPath returns the path of element i of the array at parent.
func IndexPath(parent string, i int) string { return fmt.Sprintf("%s[%d]", parent, i) }
