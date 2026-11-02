package testbody

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Allowed is one changed line that a move had to make, such as a relative
// fixture path that gained a directory level. It names the file (its new
// path for an inserted line, its old path for a deleted one), the operation
// and the line's text without its indentation.
type Allowed struct {
	File string
	Op   Op
	Text string
	// Line is where the entry is in the allow file, for messages.
	Line int
}

func (a Allowed) String() string {
	return fmt.Sprintf("%s %c %s", a.File, a.Op, a.Text)
}

// ParseAllow reads an allow list: one entry per line, "FILE OP TEXT" with OP
// "-" or "+" and TEXT the changed line without leading whitespace. Blank
// lines and lines starting with # are ignored.
func ParseAllow(r io.Reader) ([]Allowed, error) {
	var out []Allowed
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
		op, text, ok2 := strings.Cut(strings.TrimLeft(rest, " "), " ")
		text = strings.TrimSpace(text)
		if !ok1 || !ok2 || (op != "-" && op != "+") || text == "" {
			return nil, fmt.Errorf("line %d: want FILE -|+ TEXT", n)
		}
		out = append(out, Allowed{File: file, Op: Op(op[0]), Text: text, Line: n})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Allow moves every change that matches an allowed entry from Changes to
// Allowed. Each entry accepts exactly one changed line. It returns the
// entries that matched nothing, which Report.OK treats as a failure so the
// list cannot outlive the changes it explains.
func (r *Report) Allow(list []Allowed) []Allowed {
	used := make([]bool, len(list))
	for i := range r.Files {
		f := &r.Files[i]
		var kept []Change
		for _, c := range f.Changes {
			file := f.Old
			if c.Op == Insert {
				file = f.New
			}
			text := strings.TrimSpace(c.Line.Text)
			hit := false
			for j, a := range list {
				if !used[j] && a.File == file && a.Op == c.Op && a.Text == text {
					used[j], hit = true, true
					break
				}
			}
			if hit {
				f.Allowed = append(f.Allowed, c)
			} else {
				kept = append(kept, c)
			}
		}
		f.Changes = kept
	}
	r.Stale = nil
	for j, a := range list {
		if !used[j] {
			r.Stale = append(r.Stale, a)
		}
	}
	return r.Stale
}
