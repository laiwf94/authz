package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Query and the time index
//
// Query streams the records of a log that match a filter (query.go), oldest
// first, across every segment, checking the chain as it reads: each record
// must link to the one before it and carry the next sequence number, each
// segment must continue the one before it, and with schemas each payload
// must match its event type. A record is given to the caller once it is
// linked to the records before it; a change to it is found at the next
// record, and the query then fails after the records it already gave.
//
// A query bounded in time need not read the whole log. Each rotated-out
// segment gets a sparse time index beside it, FILE.<first record>.idx,
// written by the first query that reads the segment in full (a segment
// never changes once rotated out). It holds the segment's first record,
// record count, size, chain start and head, its earliest and latest record
// times, and one entry every 64 KiB: the entry's record, its byte offset,
// the hash it links to and the latest time of any record before it.
// Records' times need not rise (writers sharing a file stamp them with
// their own clocks), so an entry's time is the latest of all records before
// it, and the query starts a segment at the last entry whose earlier
// records are all before since. A segment whose records all fall outside
// [since, until) is not read at all.
//
// The index cannot vouch for the records it lets a query skip. What the
// query does read is still checked: it must start at the entry's record
// with the hash the entry names, and end at the record count and head the
// index holds, so a segment changed after its index was made, at or after
// the point the query started reading, fails the query. A skipped segment
// must have the size its index records, and the segment after it must
// continue the head its index records. Records the index skipped are
// counted in QueryResult.Skipped; authz audit verify, or a query with
// QueryOptions.Full, reads them all. An index that does not describe its
// segment (wrong name, size or shape) is ignored and made again. The
// active segment has no index: rotation bounds how much of it a query
// reads.

// IndexEvery is the spacing of time index entries, in bytes of segment.
const IndexEvery = 64 << 10

// indexEvery is IndexEvery; tests make it smaller.
var indexEvery int64 = IndexEvery

// maxIndexBytes bounds an index file read: a segment of 1 TiB has 16 Mi
// entries of 64 KiB, which no rotation limit allows.
const maxIndexBytes = 64 << 20

const indexMagic = "authz audit index 1"

// IndexPath is the time index file of the segment at path.
func IndexPath(segment string) string { return segment + ".idx" }

// timeIndex describes one rotated-out segment.
type timeIndex struct {
	Segment  string // the segment's base name
	First    uint64
	Records  uint64
	Size     int64
	Start    string // the hash the first record links to
	Previous string // the segment its start record names; empty at the chain's beginning
	Head     string // the hash of the last record
	Min, Max time.Time
	Entries  []indexEntry
}

type indexEntry struct {
	Seq    uint64
	Offset int64
	Prev   string    // the hash the record links to
	Before time.Time // the latest time of the records before it; zero if none has one
}

func formatIndexTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseIndexTime(s string) (time.Time, error) {
	if s == "-" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err == nil && formatIndexTime(t) != s {
		err = errors.New("not a canonical time")
	}
	return t, err
}

func (ix *timeIndex) marshal() []byte {
	var b bytes.Buffer
	prev := ix.Previous
	if prev == "" {
		prev = "-"
	}
	fmt.Fprintf(&b, "%s\nsegment %s first %d records %d size %d\nstart %s previous %s\nhead %s\ntime %s %s\n",
		indexMagic, ix.Segment, ix.First, ix.Records, ix.Size, ix.Start, prev, ix.Head,
		formatIndexTime(ix.Min), formatIndexTime(ix.Max))
	for _, e := range ix.Entries {
		fmt.Fprintf(&b, "entry %d %d %s %s\n", e.Seq, e.Offset, e.Prev, formatIndexTime(e.Before))
	}
	return b.Bytes()
}

// parseIndex reads an index and checks its shape: the fields are well
// formed and the entries lie inside the segment, in order.
func parseIndex(b []byte) (*timeIndex, error) {
	lines := strings.Split(string(b), "\n")
	if len(lines) < 6 || lines[0] != indexMagic || lines[len(lines)-1] != "" {
		return nil, errors.New("not a time index")
	}
	lines = lines[1 : len(lines)-1]
	var ix timeIndex
	bad := func(what string) (*timeIndex, error) { return nil, fmt.Errorf("bad %s line", what) }
	f := strings.Split(lines[0], " ")
	if len(f) != 8 || f[0] != "segment" || f[2] != "first" || f[4] != "records" || f[6] != "size" || !validSegmentFile(f[1]) {
		return bad("segment")
	}
	ix.Segment = f[1]
	var err1, err2, err3 error
	ix.First, err1 = parseNum(f[3])
	ix.Records, err2 = parseNum(f[5])
	var sz uint64
	sz, err3 = parseNum(f[7])
	ix.Size = int64(sz)
	if err1 != nil || err2 != nil || err3 != nil || ix.First == 0 || ix.Records == 0 || ix.Size <= 0 ||
		ix.First+ix.Records-1 < ix.First {
		return bad("segment")
	}
	f = strings.Split(lines[1], " ")
	if len(f) != 4 || f[0] != "start" || f[2] != "previous" || !isHash(f[1]) || f[3] != "-" && !validSegmentFile(f[3]) {
		return bad("start")
	}
	ix.Start, ix.Previous = f[1], f[3]
	if ix.Previous == "-" {
		ix.Previous = ""
	}
	if (ix.Start == Genesis) != (ix.Previous == "") || (ix.Start == Genesis) != (ix.First == 1) {
		return bad("start")
	}
	f = strings.Split(lines[2], " ")
	if len(f) != 2 || f[0] != "head" || !isHash(f[1]) {
		return bad("head")
	}
	ix.Head = f[1]
	f = strings.Split(lines[3], " ")
	if len(f) != 3 || f[0] != "time" {
		return bad("time")
	}
	var err error
	if ix.Min, err = parseIndexTime(f[1]); err != nil {
		return bad("time")
	}
	if ix.Max, err = parseIndexTime(f[2]); err != nil || ix.Min.IsZero() != ix.Max.IsZero() || ix.Max.Before(ix.Min) {
		return bad("time")
	}
	last := indexEntry{Seq: ix.First}
	for _, l := range lines[4:] {
		f = strings.Split(l, " ")
		if len(f) != 5 || f[0] != "entry" || !isHash(f[3]) {
			return bad("entry")
		}
		var e indexEntry
		var off uint64
		e.Seq, err1 = parseNum(f[1])
		off, err2 = parseNum(f[2])
		e.Offset = int64(off)
		e.Prev = f[3]
		e.Before, err3 = parseIndexTime(f[4])
		if err1 != nil || err2 != nil || err3 != nil || e.Seq <= last.Seq || e.Seq > ix.First+ix.Records-1 ||
			e.Offset <= last.Offset || e.Offset >= ix.Size || e.Before.Before(last.Before) || e.Before.After(ix.Max) {
			return bad("entry")
		}
		ix.Entries = append(ix.Entries, e)
		last = e
	}
	return &ix, nil
}

// parseNum reads a decimal number in its one canonical form, below 2^63.
func parseNum(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 63)
	if err != nil || strconv.FormatUint(n, 10) != s {
		return 0, errors.New("not a number")
	}
	return n, nil
}

func isHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// loadIndex reads the index of the segment at p, which is named for record
// first and is size bytes long; nil if there is none that describes it.
func loadIndex(p string, first uint64, size int64) *timeIndex {
	f, err := os.Open(IndexPath(p))
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxIndexBytes+1))
	if err != nil || len(b) > maxIndexBytes {
		return nil
	}
	ix, err := parseIndex(b)
	if err != nil || ix.Segment != filepath.Base(p) || ix.First != first || ix.Size != size {
		return nil
	}
	return ix
}

// saveIndex writes an index beside its segment, atomically.
func saveIndex(p string, ix *timeIndex) error {
	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(p)+".idx-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(ix.marshal())
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), IndexPath(p))
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// indexBuilder makes a segment's index as it is read from its start.
type indexBuilder struct {
	ix     timeIndex
	off    int64 // where the next record starts
	last   int64 // offset of the last entry
	before time.Time
}

func (b *indexBuilder) add(rec *Record, line []byte, sum [sha256.Size]byte) {
	if b.ix.Records == 0 {
		b.ix.First, b.ix.Start = rec.Seq, rec.Prev
	} else if b.off-b.last >= indexEvery {
		b.ix.Entries = append(b.ix.Entries, indexEntry{Seq: rec.Seq, Offset: b.off, Prev: rec.Prev, Before: b.before})
		b.last = b.off
	}
	if t, err := time.Parse(time.RFC3339Nano, rec.Time); err == nil {
		t = t.UTC()
		if b.ix.Min.IsZero() || t.Before(b.ix.Min) {
			b.ix.Min = t
		}
		if t.After(b.ix.Max) {
			b.ix.Max = t
		}
		if t.After(b.before) {
			b.before = t
		}
	}
	b.ix.Records++
	b.ix.Head = hex.EncodeToString(sum[:])
	b.off += int64(len(line)) + 1
}

// QueryOptions configures Query.
type QueryOptions struct {
	// Filter selects the records; nil selects all.
	Filter *Filter
	// Schemas, if set, is enforced on every record read, as VerifyWith
	// does, and gives event types their tracks (Default otherwise).
	Schemas *Schemas
	// Full reads every record, so the whole chain is checked, instead of
	// skipping what the time indexes show is outside the filter's times.
	Full bool
	// Limit, if not zero, stops the query after that many matches.
	Limit uint64
	// ReadOnly never writes index files, as for a copy of a log an
	// auditor must not change.
	ReadOnly bool
}

// QueryResult summarizes a query.
type QueryResult struct {
	Segments int    // files of the log, the active one included
	Records  uint64 // the sequence number of the last record read or skipped
	Head     string // its hash
	Read     uint64 // records read, with the chain checked
	Skipped  uint64 // records the time indexes let the query leave unread
	Matched  uint64 // records given to the caller
	Indexed  int    // index files written
	// Stopped means Limit was reached; the records after the last match
	// were not read.
	Stopped bool
}

var errStop = errors.New("stop")

// Query calls emit with every record of the log at path that o.Filter
// matches, oldest first, with its line (without the newline; emit may
// keep both). An error from emit stops the query and is returned. See
// "Query and the time index" above for what is checked.
func Query(path string, o QueryOptions, emit func(rec *Record, line []byte) error) (QueryResult, error) {
	var out QueryResult
	tracks := o.Schemas
	if tracks == nil {
		tracks = Default()
	}
	active, err := os.Open(path)
	if err != nil {
		if segs, _ := Segments(path); len(segs) > 0 && errors.Is(err, os.ErrNotExist) {
			return out, &SegmentError{path, errors.New("the active segment is missing; the newest records were removed")}
		}
		return out, fmt.Errorf("audit: %w", err)
	}
	defer active.Close()
	// The active file is opened first: a rotation after that gives it a
	// segment's name, and the listing then stops before it.
	segs, removed, err := liveSegments(path)
	if err != nil {
		return out, err
	}
	if afi, err := active.Stat(); err == nil {
		for i, p := range segs {
			if fi, err := os.Stat(p); err == nil && os.SameFile(fi, afi) {
				segs = segs[:i]
				break
			}
		}
	}
	out.Head = Genesis
	prevName := ""
	if removed != nil {
		// Retention removed records 1 to removed.size: the oldest
		// segment continues them.
		out.Records, out.Head, prevName = removed.size, removed.head, removed.last
	}
	f := o.Filter
	visit := func(rec *Record, line []byte, _ [sha256.Size]byte) error {
		out.Read++
		if !f.Match(rec, tracks) {
			return nil
		}
		out.Matched++
		if err := emit(rec, line); err != nil {
			return err
		}
		if o.Limit > 0 && out.Matched >= o.Limit {
			return errStop
		}
		return nil
	}
	// link checks that a segment of first record first, starting from
	// start and naming previous, continues the files before it.
	link := func(p string, i int, first uint64, start, previous string) error {
		if i == 0 && removed == nil {
			if start != Genesis {
				return &SegmentError{p, fmt.Errorf("the oldest segment starts at record %d, not 1; the segments before it (%s) were removed", first, previous)}
			}
			return nil
		}
		switch {
		case first > out.Records+1:
			return &SegmentError{p, fmt.Errorf("records %d to %d are missing between %s and this segment; a segment (%s) was removed", out.Records+1, first-1, prevName, previous)}
		case first <= out.Records:
			return &SegmentError{p, fmt.Errorf("segment starts at record %d, which %s already holds; segments were reordered or copied", first, prevName)}
		case previous != prevName:
			return &SegmentError{p, fmt.Errorf("segment names %s as the one before it, not %s; segments were renamed or reordered", previous, prevName)}
		case start != out.Head:
			return &SegmentError{p, fmt.Errorf("first record does not match the hash of the last record of %s; that record was modified or the segment was replaced", prevName)}
		}
		return nil
	}
	for i, p := range append(segs, path) {
		out.Segments++
		isActive := i == len(segs)
		base := filepath.Base(p)
		var fh *os.File
		if isActive {
			fh = active
		} else {
			if fh, err = os.Open(p); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					if nb, _ := readBase(path); nb != nil && (removed == nil || nb.size > removed.size) {
						err = errors.New("retention removed this segment while it was queried; run the query again")
					}
				}
				return out, &SegmentError{p, err}
			}
		}
		res, stop, err := querySegment(fh, p, i, isActive, filepath.Base(path), o, &out, visit, link)
		if !isActive {
			fh.Close()
		}
		if err != nil {
			return out, err
		}
		if res.Records > 0 {
			out.Records, out.Head = res.Records, res.Head
		}
		prevName = base
		if stop {
			out.Stopped = true
			return out, nil
		}
	}
	return out, nil
}

// querySegment reads or skips one file of a log for Query.
func querySegment(fh *os.File, p string, i int, isActive bool, activeBase string, o QueryOptions, out *QueryResult,
	visit visitor, link func(string, int, uint64, string, string) error) (Result, bool, error) {
	var first uint64
	var size int64
	if !isActive {
		first, _ = segmentFirst(activeBase, filepath.Base(p))
		fi, err := fh.Stat()
		if err != nil {
			return Result{}, false, &SegmentError{p, err}
		}
		size = fi.Size()
	}
	f := o.Filter
	var ix *timeIndex
	if !isActive && (!o.Full && f.timed() || !o.ReadOnly) {
		ix = loadIndex(p, first, size)
	}
	if ix != nil && !o.Full && f.timed() {
		if err := link(p, i, ix.First, ix.Start, ix.Previous); err != nil {
			return Result{}, false, err
		}
		last := ix.First + ix.Records - 1
		if ix.Max.IsZero() || !f.Since.IsZero() && ix.Max.Before(f.Since) || !f.Until.IsZero() && !ix.Min.Before(f.Until) {
			// Nothing in the segment can match.
			out.Skipped += ix.Records
			return Result{Records: last, Head: ix.Head, First: ix.First, Start: ix.Start}, false, nil
		}
		from := indexEntry{Seq: ix.First, Prev: ix.Start}
		if !f.Since.IsZero() {
			for _, e := range ix.Entries {
				if !e.Before.Before(f.Since) {
					break
				}
				from = e
			}
		}
		res := Result{Records: from.Seq - 1, Head: from.Prev, First: ix.First, Start: ix.Start, Size: from.Offset}
		if from.Seq == ix.First {
			// The whole segment is read: its start record is checked as
			// a first line.
			res = Result{Head: Genesis}
		}
		if _, err := fh.Seek(from.Offset, io.SeekStart); err != nil {
			return Result{}, false, &SegmentError{p, err}
		}
		out.Skipped += from.Seq - ix.First
		res, err := verifyRecords(fh, false, o.Schemas, res, int(from.Seq-ix.First), visit)
		if err == errStop {
			return res, true, nil
		}
		if err != nil {
			if _, ok := err.(*LineError); ok {
				return res, false, &SegmentError{p, err}
			}
			return res, false, err
		}
		if res.Records != last || res.Head != ix.Head || res.First != ix.First || res.Start != ix.Start {
			return res, false, &SegmentError{p, errors.New("segment does not match its time index; it was changed after the index was made")}
		}
		return res, false, nil
	}
	var b *indexBuilder
	if !isActive && !o.ReadOnly && ix == nil {
		b = &indexBuilder{ix: timeIndex{Segment: filepath.Base(p), Size: size}}
	}
	// The segment's link to the one before it is checked at its first
	// record, before that record is given to the caller.
	linked := false
	each := func(rec *Record, line []byte, sum [sha256.Size]byte) error {
		if !linked {
			linked = true
			if !isActive && rec.Seq != first {
				return &SegmentError{p, fmt.Errorf("segment is named for record %d but starts at record %d; it was renamed or another file put in its place", first, rec.Seq)}
			}
			previous := ""
			if rec.Event == EventSegmentStarted {
				var ss SegmentStarted
				_ = json.Unmarshal(rec.Data, &ss) // verifyRecords checked it
				previous = ss.Previous
			}
			if err := link(p, i, rec.Seq, rec.Prev, previous); err != nil {
				return err
			}
		}
		if b != nil {
			b.add(rec, line, sum)
		}
		return visit(rec, line, sum)
	}
	res, err := verifyRecords(bufio.NewReader(fh), isActive, o.Schemas, Result{Head: Genesis}, 0, each)
	stopped := err == errStop
	if err != nil && !stopped {
		if _, ok := err.(*LineError); ok {
			return res, false, &SegmentError{p, err}
		}
		return res, false, err
	}
	switch {
	case res.Records == 0 && !isActive:
		return res, false, &SegmentError{p, errors.New("segment is empty")}
	case res.Records == 0 && i > 0:
		return res, false, &SegmentError{p, errors.New("the active segment is empty, but segments come before it; its records were removed")}
	case res.Records == 0:
		return res, false, nil
	}
	if b != nil && !stopped && b.ix.Records == res.Records-res.First+1 && b.off == size {
		b.ix.Previous = res.Previous
		if saveIndex(p, &b.ix) == nil {
			out.Indexed++
		}
	}
	return res, stopped, nil
}
