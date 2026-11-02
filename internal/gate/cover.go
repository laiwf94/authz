package gate

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Coverage is the statement coverage of a cover profile, per file.
type Coverage struct {
	Mode  string
	files map[string]*fileCover
}

type fileCover struct {
	// blocks maps "start,end" to the block's statement count and whether
	// any run executed it. The same block can appear more than once when
	// profiles are concatenated; it counts once, covered if any copy is.
	blocks map[string]*block
}

type block struct {
	stmts   int
	covered bool
}

// Stat is a number of statements and how many of them ran.
type Stat struct {
	Statements, Covered int
}

// Percent is the share of statements covered, 0 to 100. A Stat with no
// statements is 100% covered: there is nothing left to run.
func (s Stat) Percent() float64 {
	if s.Statements == 0 {
		return 100
	}
	return 100 * float64(s.Covered) / float64(s.Statements)
}

func (s Stat) String() string {
	return fmt.Sprintf("%.1f%% of %d statements", s.Percent(), s.Statements)
}

// ParseCoverProfile reads a profile written by `go test -coverprofile`.
// Several profiles may be concatenated, each with its own mode line, as long
// as the modes agree.
func ParseCoverProfile(r io.Reader) (*Coverage, error) {
	c := &Coverage{files: map[string]*fileCover{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if mode, ok := strings.CutPrefix(line, "mode: "); ok {
			if c.Mode != "" && c.Mode != mode {
				return nil, fmt.Errorf("line %d: mode %q after mode %q", n, mode, c.Mode)
			}
			c.Mode = mode
			continue
		}
		if c.Mode == "" {
			return nil, fmt.Errorf("line %d: block before the mode line", n)
		}
		// file:startLine.startCol,endLine.endCol numStmt count
		colon := strings.LastIndexByte(line, ':')
		if colon <= 0 {
			return nil, fmt.Errorf("line %d: no file name", n)
		}
		file, rest := line[:colon], line[colon+1:]
		f := strings.Fields(rest)
		if len(f) != 3 || !validRange(f[0]) {
			return nil, fmt.Errorf("line %d: want FILE:L.C,L.C STMTS COUNT", n)
		}
		stmts, err1 := strconv.Atoi(f[1])
		count, err2 := strconv.ParseInt(f[2], 10, 64)
		if err1 != nil || err2 != nil || stmts < 0 || count < 0 {
			return nil, fmt.Errorf("line %d: bad statement count or hit count", n)
		}
		fc := c.files[file]
		if fc == nil {
			fc = &fileCover{blocks: map[string]*block{}}
			c.files[file] = fc
		}
		b := fc.blocks[f[0]]
		if b == nil {
			b = &block{stmts: stmts}
			fc.blocks[f[0]] = b
		} else if b.stmts != stmts {
			return nil, fmt.Errorf("line %d: %s:%s has %d statements here and %d before", n, file, f[0], stmts, b.stmts)
		}
		b.covered = b.covered || count > 0
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if c.Mode == "" {
		return nil, fmt.Errorf("empty cover profile")
	}
	return c, nil
}

// validRange reports whether s looks like "12.3,45.6".
func validRange(s string) bool {
	a, b, ok := strings.Cut(s, ",")
	return ok && validPos(a) && validPos(b)
}

func validPos(s string) bool {
	l, c, ok := strings.Cut(s, ".")
	if !ok {
		return false
	}
	_, e1 := strconv.Atoi(l)
	_, e2 := strconv.Atoi(c)
	return e1 == nil && e2 == nil
}

func (fc *fileCover) stat() Stat {
	var s Stat
	for _, b := range fc.blocks {
		s.Statements += b.stmts
		if b.covered {
			s.Covered += b.stmts
		}
	}
	return s
}

// Total is the coverage over every file in the profile.
func (c *Coverage) Total() Stat {
	var s Stat
	for _, fc := range c.files {
		st := fc.stat()
		s.Statements += st.Statements
		s.Covered += st.Covered
	}
	return s
}

// Group is a named set of import path prefixes, such as one of the three
// trees that went into the module.
type Group struct {
	Name     string
	Prefixes []string
}

// ParseGroup reads "NAME=PREFIX[,PREFIX...]".
func ParseGroup(s string) (Group, error) {
	name, list, ok := strings.Cut(s, "=")
	if !ok || name == "" || list == "" {
		return Group{}, fmt.Errorf("group %q: want NAME=PREFIX[,PREFIX...]", s)
	}
	g := Group{Name: name}
	for _, p := range strings.Split(list, ",") {
		if p = strings.TrimSpace(p); p == "" {
			return Group{}, fmt.Errorf("group %q: empty prefix", s)
		}
		g.Prefixes = append(g.Prefixes, p)
	}
	return g, nil
}

// matches reports whether file is under prefix (given without a trailing
// slash), matching whole path elements: "a/b" covers "a/b/c.go" but not "a/bc/d.go".
func matches(file, prefix string) bool {
	return strings.HasPrefix(file, prefix+"/")
}

// ByGroup splits the coverage between groups. A file goes to the group with
// the longest matching prefix, the earlier group on a tie; files no group
// matches go to rest, which is
// returned last under the name rest when it has any statements.
func (c *Coverage) ByGroup(groups []Group, rest string) []NamedStat {
	stats := make([]Stat, len(groups)+1)
	files := make([]string, 0, len(c.files))
	for f := range c.files {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, file := range files {
		best, bestLen := len(groups), -1
		for i, g := range groups {
			for _, p := range g.Prefixes {
				p = strings.TrimSuffix(p, "/")
				if matches(file, p) && len(p) > bestLen {
					best, bestLen = i, len(p)
				}
			}
		}
		st := c.files[file].stat()
		stats[best].Statements += st.Statements
		stats[best].Covered += st.Covered
	}
	out := make([]NamedStat, 0, len(stats))
	for i, g := range groups {
		out = append(out, NamedStat{Name: g.Name, Stat: stats[i]})
	}
	if last := stats[len(groups)]; last.Statements > 0 {
		out = append(out, NamedStat{Name: rest, Stat: last})
	}
	return out
}

// NamedStat is a Stat with the name of the group it belongs to.
type NamedStat struct {
	Name string
	Stat
}
