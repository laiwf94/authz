// Package gate holds the checks the CI gate runs on top of the go tool:
// a staticcheck run with an exact allow list for test files that the week 1
// moves froze, and a coverage floor computed from a cover profile.
package gate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Finding is one staticcheck diagnostic, as printed by `staticcheck -f json`.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Location struct {
		File   string `json:"file"`
		Line   int    `json:"line"`
		Column int    `json:"column"`
	} `json:"location"`
	Message string `json:"message"`

	// File is Location.File relative to the module root, with slashes.
	File string `json:"-"`
	// Text is the source line the finding points at, without surrounding
	// whitespace. It is what an allow entry matches, so an entry survives
	// edits elsewhere in the file but not a change to the line itself.
	Text string `json:"-"`
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d:%d: %s (%s)", f.File, f.Location.Line, f.Location.Column, f.Message, f.Code)
}

// ParseFindings reads staticcheck's JSON output, one object per line, and
// fills in File relative to root and Text from the source file.
func ParseFindings(r io.Reader, root string) ([]Finding, error) {
	var out []Finding
	lines := map[string][]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	n := 0
	for sc.Scan() {
		n++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var f Finding
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("staticcheck output line %d: %v", n, err)
		}
		if f.Code == "" || f.Location.File == "" {
			return nil, fmt.Errorf("staticcheck output line %d: no code or file", n)
		}
		f.File = relPath(root, f.Location.File)
		if f.Location.Line > 0 {
			src, ok := lines[f.Location.File]
			if !ok {
				src = readLines(f.Location.File)
				lines[f.Location.File] = src
			}
			if i := f.Location.Line - 1; i >= 0 && i < len(src) {
				f.Text = strings.TrimSpace(src[i])
			}
		}
		out = append(out, f)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func relPath(root, file string) string {
	if root != "" && filepath.IsAbs(file) {
		if r, err := filepath.Rel(root, file); err == nil && !strings.HasPrefix(r, "..") {
			file = r
		}
	}
	return filepath.ToSlash(file)
}

func readLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(b), "\n")
}

// LintAllowed is one staticcheck finding that the gate accepts: "FILE CHECK
// TEXT", where TEXT is the flagged source line without its indentation.
type LintAllowed struct {
	File, Code, Text string
	// Line is where the entry is in the allow file, for messages.
	Line int
}

func (a LintAllowed) String() string { return a.File + " " + a.Code + " " + a.Text }

// ParseLintAllow reads a staticcheck allow list. Blank lines and lines
// starting with # are ignored. Only _test.go files may be listed: code that
// is not a test is fixed, not excused. Compiler errors ("compile") cannot be
// listed either.
func ParseLintAllow(r io.Reader) ([]LintAllowed, error) {
	var out []LintAllowed
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		file, rest, ok1 := strings.Cut(line, " ")
		code, text, ok2 := strings.Cut(strings.TrimLeft(rest, " "), " ")
		text = strings.TrimSpace(text)
		if !ok1 || !ok2 || code == "" || text == "" {
			return nil, fmt.Errorf("line %d: want FILE CHECK TEXT", n)
		}
		if !strings.HasSuffix(file, "_test.go") {
			return nil, fmt.Errorf("line %d: %s is not a test file; fix the finding instead", n, file)
		}
		if code == "compile" {
			return nil, fmt.Errorf("line %d: a compile error cannot be allowed", n)
		}
		out = append(out, LintAllowed{File: file, Code: code, Text: text, Line: n})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// FilterLint splits findings into those an allow entry accepts and those it
// does not. Each entry accepts exactly one finding. Entries that matched
// nothing are returned too: the gate fails on them so the list cannot
// outlive the findings it explains. The rejected findings come back sorted
// by file, line and column.
func FilterLint(findings []Finding, allow []LintAllowed) (rejected, accepted []Finding, stale []LintAllowed) {
	used := make([]bool, len(allow))
	for _, f := range findings {
		hit := false
		for j, a := range allow {
			if !used[j] && a.File == f.File && a.Code == f.Code && a.Text == f.Text {
				used[j], hit = true, true
				break
			}
		}
		if hit {
			accepted = append(accepted, f)
		} else {
			rejected = append(rejected, f)
		}
	}
	for j, a := range allow {
		if !used[j] {
			stale = append(stale, a)
		}
	}
	sort.SliceStable(rejected, func(i, j int) bool {
		a, b := rejected[i], rejected[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		return a.Location.Column < b.Location.Column
	})
	return rejected, accepted, stale
}
