package testbody

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Merge pairs an old test file with its new home explicitly, in place of
// git's rename detection. It is for packages that collapsed into one: the
// three byte-identical metrics packages of grantd, wicket and toolgate became
// internal/platform/metrics in week 2 (#77), and git can only call one of
// them a rename. Every old file of a merge is compared with the new file in
// full, so each must still find all its declarations and tests there.
type Merge struct {
	Old, New string
	// Line is where the entry is in the merge file, for messages.
	Line int
}

// ParseMerges reads a merge list: one "OLD NEW" entry per line, both paths
// relative to the repository root. Blank lines and lines starting with # are
// ignored. An old path may appear only once.
func ParseMerges(r io.Reader) ([]Merge, error) {
	var out []Merge
	seen := map[string]int{}
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 || !strings.HasSuffix(f[0], "_test.go") || !strings.HasSuffix(f[1], "_test.go") {
			return nil, fmt.Errorf("line %d: want OLD_test.go NEW_test.go", n)
		}
		if prev, ok := seen[f[0]]; ok {
			return nil, fmt.Errorf("line %d: %s is already merged on line %d", n, f[0], prev)
		}
		seen[f[0]] = n
		out = append(out, Merge{Old: f[0], New: f[1], Line: n})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ApplyMerges sets each merge in renames, overriding what git found. An
// entry whose old file is not in oldFiles or whose new file is not in
// newFiles is an error, so the list cannot outlive the move it explains.
func ApplyMerges(renames map[string]string, merges []Merge, oldFiles, newFiles []string) error {
	inOld, inNew := set(oldFiles), set(newFiles)
	for _, m := range merges {
		if !inOld[m.Old] {
			return fmt.Errorf("merge entry on line %d: %s is not in the old tree", m.Line, m.Old)
		}
		if !inNew[m.New] {
			return fmt.Errorf("merge entry on line %d: %s is not in the new tree", m.Line, m.New)
		}
		renames[m.Old] = m.New
	}
	return nil
}

func set(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
