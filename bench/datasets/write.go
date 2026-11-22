package datasets

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
)

// Output formats of WriteGraph.
const (
	// FormatTuples is one type:id#relation@subject per line, the form of
	// authz's write API and of SpiceDB relationships.
	FormatTuples = "tuples"
	// FormatOpenFGA is one JSON object per line with user, relation and
	// object, the tuple key of OpenFGA's write API.
	FormatOpenFGA = "openfga"
)

// WriteGraph writes the relationships numbered from..to-1 (all of them
// with 0 and g.Count()) to w in format, one per line, and returns how
// many it wrote.
func WriteGraph(w io.Writer, g Graph, format string, from, to int64) (int64, error) {
	var line func(b []byte, r *Relationship) []byte
	switch format {
	case FormatTuples:
		line = func(b []byte, r *Relationship) []byte { return r.AppendTuple(b) }
	case FormatOpenFGA:
		line = appendOpenFGA
	default:
		return 0, fmt.Errorf("format %q: want %s or %s", format, FormatTuples, FormatOpenFGA)
	}
	bw := bufio.NewWriterSize(w, 1<<16)
	var n int64
	buf := make([]byte, 0, 128)
	err := g.EachRange(from, to, func(r *Relationship) error {
		buf = append(line(buf[:0], r), '\n')
		n++
		_, err := bw.Write(buf)
		return err
	})
	if err == nil {
		err = bw.Flush()
	}
	return n, err
}

// appendOpenFGA appends {"user":...,"relation":...,"object":...}. Every
// string is made of type names, relation names, letters, digits, '#', ':'
// and '*', none of which JSON escapes.
func appendOpenFGA(b []byte, r *Relationship) []byte {
	b = append(b, `{"user":"`...)
	b = r.AppendSubject(b)
	b = append(b, `","relation":"`...)
	b = append(b, r.Relation...)
	b = append(b, `","object":"`...)
	b = AppendObject(b, r.ResourceType, r.Resource)
	return append(b, `"}`...)
}

// Manifest describes a graph: its counts, the runner flags that draw from
// its objects, and the shape constants, so a result can say what it ran
// against.
type Manifest struct {
	Graph
	Relationships int64    `json:"relationships"`
	BenchFlags    []string `json:"authzbench_flags"`
	Shape         Shape    `json:"shape"`
}

// Shape is the generator's fixed proportions.
type Shape struct {
	DocsPerUser       int     `json:"docs_per_user"`
	UsersPerGroup     int     `json:"users_per_group"`
	DocsPerFolder     int     `json:"docs_per_folder"`
	FoldersPerRoot    int     `json:"folders_per_tree"`
	FolderFanout      int     `json:"folder_fanout"`
	GroupsPerUser     int     `json:"groups_per_user"`
	RootGroupShare    int     `json:"one_root_group_in"`
	BannedEvery       int     `json:"one_ban_in_docs"`
	UserViewerEvery   int     `json:"one_user_shared_folder_in"`
	PublicFolderEvery int     `json:"one_public_folder_in"`
	ZipfS             float64 `json:"group_zipf_s"`
	ZipfV             float64 `json:"group_zipf_v"`
}

// Describe returns g's manifest.
func (g Graph) Describe() Manifest {
	return Manifest{Graph: g, Relationships: g.Count(),
		BenchFlags: []string{"-resource-type", TypeDoc, "-resource-prefix", "d", "-resources", strconv.Itoa(g.Docs),
			"-subject-type", TypeUser, "-subject-prefix", "u", "-subjects", strconv.Itoa(g.Users),
			"-permission", "view", "-relation", "editor"},
		Shape: Shape{docsPerUser, usersPerGroup, docsPerFolder, foldersPerRoot, folderFanout, groupsPerUser,
			rootGroupShare, bannedEvery, userViewerEvery, publicFolderEvery, zipfS, zipfV}}
}
