// Package datasets generates the seeded datasets every product in the
// benchmark is loaded with: a document-sharing relationship graph of users,
// nested groups, folder trees and documents (1M, 10M and 100M
// relationships, or any size), the user population that signs in for
// forward-auth sessions, and catalogs of MCP tools with valid calls.
//
// Everything is a pure function of the size and a seed. Each user, group,
// folder and document draws from its own random stream, seeded from the
// dataset seed and its number, so a dataset is the same on every machine
// and in every output format, a user's groups in the population match its
// group memberships in the graph, and nothing is held in memory: a
// 100M-relationship graph streams out in constant space.
//
// Object IDs follow authzbench's naming: documents are doc:d<n>, users
// user:u<n>, groups group:g<n> and folders folder:f<n>, for n from 0, so
// `-resource-prefix d -resources Docs -subject-prefix u -subjects Users`
// draws from exactly the objects that exist.
package datasets

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
)

// Schema is the dataset's schema in the authz schema language, which
// SpiceDB reads as is.
const Schema = `// Benchmark dataset (bench/datasets): users, nested groups, folder trees
// with inherited viewers, documents with owners, editors and bans.
definition user {}

definition group {
  relation member: user | group#member
}

definition folder {
  relation parent: folder
  relation viewer: user | user:* | group#member
  permission view = viewer + parent->view
}

definition doc {
  relation parent: folder
  relation owner: user
  relation editor: user | group#member
  relation banned: user
  permission edit = owner + editor
  permission view = (edit + parent->view) - banned
}
`

// OpenFGAModel is Schema in the OpenFGA modeling language (schema 1.1),
// with the same relations and the same meaning.
const OpenFGAModel = `model
  schema 1.1

type user

type group
  relations
    define member: [user, group#member]

type folder
  relations
    define parent: [folder]
    define viewer: [user, user:*, group#member]
    define view: viewer or view from parent

type doc
  relations
    define parent: [folder]
    define owner: [user]
    define editor: [user, group#member]
    define banned: [user]
    define edit: owner or editor
    define view: (edit or view from parent) but not banned
`

// Shape constants. They are part of a dataset's identity: changing one
// changes every dataset, so the published results name the generator's
// commit.
const (
	docsPerUser       = 10   // one user for every ten documents
	usersPerGroup     = 50   // one group for every fifty users
	docsPerFolder     = 50   // one folder for every fifty documents
	foldersPerRoot    = 1000 // one folder tree for every thousand folders
	folderFanout      = 8    // subfolders of a folder
	groupsPerUser     = 2    // groups each user is a direct member of
	rootGroupShare    = 4    // one group in four is top-level; the rest nest
	bannedEvery       = 50   // one document in fifty bans a user
	userViewerEvery   = 10   // one folder in ten is shared with a user, not a group
	publicFolderEvery = 1000 // one folder in a thousand is shared with user:*
	// Group popularity is Zipf with exponent zipfS and offset zipfV: a few
	// groups are large (the first has about 6% of the users at 1M), most
	// are small, as in a real directory.
	zipfS = 1.1
	zipfV = 10
)

// Stream kinds, mixed into each object's seed so that the user, group,
// folder and document streams are independent.
const (
	kindUser uint64 = iota + 1
	kindGroup
	kindFolder
	kindDoc
	kindPassword
)

// Graph is the shape of one relationship dataset. Size computes it from a
// relationship count; the fields can also be set directly.
type Graph struct {
	Seed    uint64 `json:"seed"`
	Users   int    `json:"users"`
	Groups  int    `json:"groups"`
	Folders int    `json:"folders"`
	Docs    int    `json:"docs"`
}

// Presets are the published dataset sizes.
var Presets = map[string]int64{"1m": 1_000_000, "10m": 10_000_000, "100m": 100_000_000}

// ParseSize reads a preset name (1m, 10m, 100m) or a relationship count
// with an optional k or m suffix, such as 250k or 2500000.
func ParseSize(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if n, ok := Presets[s]; ok {
		return n, nil
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "k"):
		mult, s = 1_000, s[:len(s)-1]
	case strings.HasSuffix(s, "m"):
		mult, s = 1_000_000, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > MaxRelationships/mult {
		return 0, fmt.Errorf("size %q: want 1m, 10m, 100m or a count from %d to %d", s, MinRelationships, MaxRelationships)
	}
	if n*mult < MinRelationships {
		return 0, fmt.Errorf("size %d: the smallest graph has %d relationships", n*mult, MinRelationships)
	}
	return n * mult, nil
}

// MinRelationships and MaxRelationships bound Size.
const (
	MinRelationships = 100
	MaxRelationships = 10_000_000_000
)

func shape(docs int, seed uint64) Graph {
	users := max(docs/docsPerUser, groupsPerUser*2)
	return Graph{Seed: seed, Docs: docs, Users: users, Groups: max(users/usersPerGroup, groupsPerUser*2),
		Folders: max(docs/docsPerFolder, 1)}
}

// Size returns the largest graph with at most n relationships.
func Size(n int64, seed uint64) (Graph, error) {
	if n < MinRelationships || n > MaxRelationships {
		return Graph{}, fmt.Errorf("size %d: want %d to %d relationships", n, MinRelationships, MaxRelationships)
	}
	// Count grows with docs, so search for the largest docs that fits.
	lo, hi := 1, int(n/4)+1
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		if shape(mid, seed).Count() <= n {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	g := shape(lo, seed)
	if g.Count() > n {
		return Graph{}, fmt.Errorf("size %d: too small for a graph", n)
	}
	return g, nil
}

// Validate checks that the counts can make a graph.
func (g Graph) Validate() error {
	switch {
	case g.Users < 1 || g.Docs < 1 || g.Folders < 1:
		return errors.New("graph: users, folders and docs must be at least 1")
	case g.Groups < groupsPerUser:
		return fmt.Errorf("graph: groups must be at least %d", groupsPerUser)
	}
	return nil
}

func (g Graph) groupRoots() int  { return max(g.Groups/rootGroupShare, 1) }
func (g Graph) folderRoots() int { return max(g.Folders/foldersPerRoot, 1) }

// Count is the exact number of relationships Each emits.
func (g Graph) Count() int64 {
	return int64(g.Users)*groupsPerUser + int64(g.Groups-g.groupRoots()) +
		int64(g.Folders-g.folderRoots()) + int64(g.Folders) +
		int64(g.Docs)*4 + int64(g.Docs/bannedEvery)
}

// Object types. The prefix of each type's IDs is its first letter.
const (
	TypeUser   = "user"
	TypeGroup  = "group"
	TypeFolder = "folder"
	TypeDoc    = "doc"
)

// Wildcard is the subject number of type:*.
const Wildcard = -1

// Relationship is one generated relationship. IDs are numbers; the string
// form puts the type's prefix letter before them.
type Relationship struct {
	ResourceType    string
	Resource        int
	Relation        string
	SubjectType     string
	Subject         int // Wildcard for type:*
	SubjectRelation string
}

// AppendObject appends type:<prefix><n>, or type:* for Wildcard.
func AppendObject(b []byte, typ string, n int) []byte {
	b = append(b, typ...)
	b = append(b, ':')
	if n == Wildcard {
		return append(b, '*')
	}
	b = append(b, typ[0])
	return strconv.AppendInt(b, int64(n), 10)
}

// ObjectID is the ID of object n of a type, such as d42.
func ObjectID(typ string, n int) string { return typ[:1] + strconv.Itoa(n) }

// AppendSubject appends the subject: type:id or type:id#relation.
func (r *Relationship) AppendSubject(b []byte) []byte {
	b = AppendObject(b, r.SubjectType, r.Subject)
	if r.SubjectRelation != "" {
		b = append(b, '#')
		b = append(b, r.SubjectRelation...)
	}
	return b
}

// AppendTuple appends type:id#relation@subject, the form authz and SpiceDB
// read.
func (r *Relationship) AppendTuple(b []byte) []byte {
	b = AppendObject(b, r.ResourceType, r.Resource)
	b = append(b, '#')
	b = append(b, r.Relation...)
	b = append(b, '@')
	return r.AppendSubject(b)
}

func (r Relationship) String() string { return string(r.AppendTuple(nil)) }

// stream is a reseedable random source: one PCG reseeded for each object,
// so drawing allocates nothing.
type stream struct {
	pcg *rand.PCG
	r   *rand.Rand
	// groups draws a group number, Zipf distributed.
	groups *rand.Zipf
}

func (g Graph) newStream() *stream {
	s := &stream{pcg: rand.NewPCG(0, 0)}
	s.r = rand.New(s.pcg)
	s.groups = rand.NewZipf(s.r, zipfS, zipfV, uint64(g.Groups-1))
	return s
}

func (s *stream) seed(seed, kind uint64, n int) {
	s.pcg.Seed(seed, kind<<56^uint64(n))
}

// UserGroups appends the groups user u is a direct member of: groupsPerUser
// distinct groups, popular ones more often.
func (g Graph) UserGroups(u int, dst []int) []int {
	return g.userGroups(g.newStream(), u, dst)
}

func (g Graph) userGroups(s *stream, u int, dst []int) []int {
	s.seed(g.Seed, kindUser, u)
	start := len(dst)
	for len(dst)-start < groupsPerUser {
		x := int(s.groups.Uint64())
		for dup := true; dup; {
			dup = false
			for _, y := range dst[start:] {
				if y == x {
					// Taken: the next group up, wrapping, is still drawn
					// from the stream's state and keeps the set distinct.
					x, dup = (x+1)%g.Groups, true
					break
				}
			}
		}
		dst = append(dst, x)
	}
	return dst
}

// Each calls fn for every relationship, in a fixed order: group
// memberships of users, nested groups, folder parents, folder viewers,
// then each document's parent, owner, editors and ban. fn must not keep
// r. Each stops at the first error fn returns and returns it.
func (g Graph) Each(fn func(r *Relationship) error) error {
	return g.EachRange(0, g.Count(), fn)
}

// EachRange is Each for the relationships numbered from..to-1 in Each's
// order, so a dataset can be split among writers. Ranges skip whole
// sections without generating them.
func (g Graph) EachRange(from, to int64, fn func(r *Relationship) error) error {
	if err := g.Validate(); err != nil {
		return err
	}
	if from < 0 || to > g.Count() || from > to {
		return fmt.Errorf("graph: range %d..%d outside 0..%d", from, to, g.Count())
	}
	s := g.newStream()
	var r Relationship
	var pos int64 // number of the next relationship of the section
	// section emits count relationships, per items of each; it skips the
	// items wholly before from and stops after to.
	section := func(items, each int, emit func(i int) error) error {
		end := pos + int64(items)*int64(each)
		if end <= from || pos >= to {
			pos = end
			return nil
		}
		first := 0
		if from > pos {
			first = int((from - pos) / int64(each))
		}
		pos += int64(first) * int64(each)
		for i := first; i < items && pos < to; i++ {
			if err := emit(i); err != nil {
				return err
			}
		}
		pos = end
		return nil
	}
	// out passes r on when it is in range.
	out := func() error {
		defer func() { pos++ }()
		if pos < from || pos >= to {
			return nil
		}
		return fn(&r)
	}

	groups := make([]int, 0, groupsPerUser)
	err := section(g.Users, groupsPerUser, func(u int) error {
		groups = g.userGroups(s, u, groups[:0])
		for _, x := range groups {
			r = Relationship{TypeGroup, x, "member", TypeUser, u, ""}
			if err := out(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// Group i past the roots nests in a group numbered below i/2, so the
	// group graph has no cycles and is a few levels deep.
	roots := g.groupRoots()
	err = section(g.Groups-roots, 1, func(k int) error {
		i := roots + k
		s.seed(g.Seed, kindGroup, i)
		r = Relationship{TypeGroup, s.r.IntN(max(i/2, 1)), "member", TypeGroup, i, "member"}
		return out()
	})
	if err != nil {
		return err
	}
	// Folder trees: the first folderRoots folders are roots, and the
	// others hang below them, folderFanout to a parent, breadth first.
	froots := g.folderRoots()
	err = section(g.Folders-froots, 1, func(k int) error {
		i := froots + k
		r = Relationship{TypeFolder, i, "parent", TypeFolder, (i - froots) / folderFanout, ""}
		return out()
	})
	if err != nil {
		return err
	}
	err = section(g.Folders, 1, func(i int) error {
		s.seed(g.Seed, kindFolder, i)
		switch {
		case i%publicFolderEvery == publicFolderEvery-1:
			r = Relationship{TypeFolder, i, "viewer", TypeUser, Wildcard, ""}
		case i%userViewerEvery == 0:
			r = Relationship{TypeFolder, i, "viewer", TypeUser, s.r.IntN(g.Users), ""}
		default:
			r = Relationship{TypeFolder, i, "viewer", TypeGroup, int(s.groups.Uint64()), "member"}
		}
		return out()
	})
	if err != nil {
		return err
	}
	// Documents: four relationships each, and a fifth for every
	// bannedEvery-th. The section counts them exactly so ranges stay
	// aligned: blocks of bannedEvery documents have bannedEvery*4+1.
	return g.docs(s, &r, &pos, from, to, out)
}

func (g Graph) docs(s *stream, r *Relationship, pos *int64, from, to int64, out func() error) error {
	const block = bannedEvery*4 + 1
	first := 0
	if from > *pos {
		// Skip whole blocks before from.
		skip := (from - *pos) / block
		// A last, partial block has fewer than block relationships, so
		// skip never passes the last full block.
		first = int(skip) * bannedEvery
		*pos += int64(first/bannedEvery) * block
	}
	for d := first; d < g.Docs && *pos < to; d++ {
		s.seed(g.Seed, kindDoc, d)
		*r = Relationship{TypeDoc, d, "parent", TypeFolder, s.r.IntN(g.Folders), ""}
		if err := out(); err != nil {
			return err
		}
		*r = Relationship{TypeDoc, d, "owner", TypeUser, s.r.IntN(g.Users), ""}
		if err := out(); err != nil {
			return err
		}
		*r = Relationship{TypeDoc, d, "editor", TypeUser, s.r.IntN(g.Users), ""}
		if err := out(); err != nil {
			return err
		}
		*r = Relationship{TypeDoc, d, "editor", TypeGroup, int(s.groups.Uint64()), "member"}
		if err := out(); err != nil {
			return err
		}
		if d%bannedEvery == bannedEvery-1 {
			*r = Relationship{TypeDoc, d, "banned", TypeUser, s.r.IntN(g.Users), ""}
			if err := out(); err != nil {
				return err
			}
		}
	}
	return nil
}
