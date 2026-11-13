//go:build unix

package audit

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// smallIndex makes index entries every n bytes for one test.
func smallIndex(t testing.TB, n int64) {
	old := indexEvery
	indexEvery = n
	t.Cleanup(func() { indexEvery = old })
}

// mixedLog writes n records of every track to a log rotating every
// segBytes, with the clock moving by step plus up to jitter either way per
// record, so times are not in order.
func mixedLog(t testing.TB, n int, segBytes int64, step, jitter time.Duration, seed uint64) (string, *clock) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	c := newClock()
	l, err := OpenWith(path, Options{Now: c.now, Schemas: Default(), Rotation: Rotation{MaxBytes: segBytes}})
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewPCG(seed, 1))
	agents := []string{"alice-bot", "bob-bot", "carol-bot"}
	tools := []string{"read_file", "write_file", "search"}
	for i := range n {
		d := step
		if jitter > 0 {
			d += time.Duration(r.Int64N(int64(2*jitter))) - jitter
		}
		c.add(d)
		var err error
		switch i % 4 {
		case 0, 1:
			dec := []string{"allow", "deny"}[r.IntN(2)]
			call := ToolCall{Agent: agents[r.IntN(3)], Auth: "static", Tool: tools[r.IntN(3)], Decision: dec,
				Stage: "policy", RuleID: fmt.Sprintf("rule-%d", r.IntN(4))}
			err = l.AppendWith(EventToolCall, Envelope{}, call)
		case 2:
			err = l.Write(Envelope{Actor: "user:" + agents[r.IntN(3)], Subject: "app:wiki", Action: "login", Decision: Allow},
				LoginSucceeded{Provider: "idp", Session: fmt.Sprintf("s%d", i)})
		default:
			err = l.Write(Envelope{Subject: "doc:" + fmt.Sprint(i), Action: "view", Decision: []Decision{Allow, Deny}[r.IntN(2)]},
				CheckDecided{Principal: "user:alice", Revision: "r"})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return path, c
}

// query runs Query and returns the matched sequence numbers.
func query(t testing.TB, path string, o QueryOptions) ([]uint64, QueryResult, error) {
	t.Helper()
	var seqs []uint64
	res, err := Query(path, o, func(r *Record, line []byte) error {
		if !bytes.HasPrefix(line, []byte(fmt.Sprintf(`{"seq":%d,`, r.Seq))) {
			t.Fatalf("record %d given with line %.40s", r.Seq, line)
		}
		seqs = append(seqs, r.Seq)
		return nil
	})
	return seqs, res, err
}

// bruteForce filters every record of the log.
func bruteForce(t *testing.T, path string, f *Filter) []uint64 {
	t.Helper()
	_, recs := chainRecords(t, path)
	var out []uint64
	for i := range recs {
		if f.Match(&recs[i], nil) {
			out = append(out, recs[i].Seq)
		}
	}
	return out
}

func TestQueryMatchesBruteForce(t *testing.T) {
	smallIndex(t, 1024)
	path, c := mixedLog(t, 1500, 16<<10, time.Second, 3*time.Second, 7)
	segs, _ := Segments(path)
	if len(segs) < 8 {
		t.Fatalf("only %d segments", len(segs))
	}
	start, end := fixedNow(), c.now()
	total := uint64(1500 + len(segs)) // and a segment start record each
	r := rand.New(rand.NewPCG(3, 4))
	filters := []string{"", "track=agents decision=deny", "agent=bob-bot rule=rule-1,rule-2", "track=authn", "decision=allow tool!=search"}
	// The first queries make the indexes; a ReadOnly query writes none.
	_, res, err := query(t, path, QueryOptions{ReadOnly: true})
	if err != nil || res.Indexed != 0 || res.Read != total || res.Records != total || res.Segments != len(segs)+1 {
		t.Fatalf("ReadOnly query: %+v, %v", res, err)
	}
	if _, err := os.Stat(IndexPath(segs[0])); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ReadOnly query wrote an index")
	}
	var skipped uint64
	for i := range 60 {
		a := start.Add(time.Duration(r.Int64N(int64(end.Sub(start)))))
		b := a.Add(time.Duration(r.Int64N(int64(end.Sub(start)) / 3)))
		expr := filters[i%len(filters)]
		switch i % 3 {
		case 0:
			expr += " since=" + a.UTC().Format(time.RFC3339Nano)
		case 1:
			expr += " until=" + b.UTC().Format(time.RFC3339Nano)
		default:
			expr += " since=" + a.UTC().Format(time.RFC3339Nano) + " until=" + b.Add(time.Nanosecond).UTC().Format(time.RFC3339Nano)
		}
		f, err := ParseFilter(expr, end)
		if err != nil {
			t.Fatal(err)
		}
		want := bruteForce(t, path, f)
		for _, full := range []bool{true, false} {
			got, res, err := query(t, path, QueryOptions{Filter: f, Schemas: Default(), Full: full})
			if err != nil {
				t.Fatalf("%q full=%v: %v", expr, full, err)
			}
			if !equalSeqs(got, want) {
				t.Fatalf("%q full=%v: matched %d records, brute force %d", expr, full, len(got), len(want))
			}
			if res.Read+res.Skipped != total || res.Matched != uint64(len(want)) || res.Records != total {
				t.Fatalf("%q full=%v: %+v", expr, full, res)
			}
			if full && res.Skipped != 0 {
				t.Fatalf("a full query skipped %d records", res.Skipped)
			}
			if i == 0 && full && res.Indexed != len(segs) {
				t.Fatalf("the first query wrote %d indexes, want %d", res.Indexed, len(segs))
			}
			if i > 0 && res.Indexed != 0 {
				t.Fatalf("query %d rewrote %d indexes", i, res.Indexed)
			}
			if !full {
				skipped += res.Skipped
			}
		}
	}
	if skipped < 60*total/4 {
		t.Errorf("the indexes skipped only %d of %d records", skipped, 60*total)
	}
}

// TestQuerySkipsInsideSegments checks that with one big segment the index
// starts the read at the right entry, and that records out of time order
// are still found.
func TestQuerySkipsInsideSegments(t *testing.T) {
	smallIndex(t, 512)
	path, c := mixedLog(t, 600, 64<<10, time.Second, 20*time.Second, 11)
	segs, _ := Segments(path)
	if _, _, err := query(t, path, QueryOptions{}); err != nil {
		t.Fatal(err)
	}
	ix := loadIndex(segs[0], 1, fileSize(t, segs[0]))
	if ix == nil || len(ix.Entries) < 20 {
		t.Fatalf("index of %s: %+v", segs[0], ix)
	}
	for _, e := range ix.Entries {
		f, _ := ParseFilter("since="+e.Before.Add(time.Nanosecond).Format(time.RFC3339Nano), c.now())
		got, res, err := query(t, path, QueryOptions{Filter: f})
		if err != nil {
			t.Fatal(err)
		}
		if want := bruteForce(t, path, f); !equalSeqs(got, want) {
			t.Fatalf("since entry %d: %d records, want %d", e.Seq, len(got), len(want))
		}
		if res.Skipped < e.Seq-1 {
			t.Fatalf("since entry %d skipped only %d", e.Seq, res.Skipped)
		}
	}
}

func fileSize(t *testing.T, p string) int64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func TestQueryLimitAndEmitError(t *testing.T) {
	path, _ := mixedLog(t, 300, 8<<10, time.Second, 0, 1)
	f, _ := ParseFilter("track=agents", fixedNow())
	got, res, err := query(t, path, QueryOptions{Filter: f, Limit: 5})
	if err != nil || len(got) != 5 || !res.Stopped || res.Matched != 5 || res.Read >= 300 || res.Indexed != 0 {
		t.Fatalf("Limit: %v %+v %v", got, res, err)
	}
	if !equalSeqs(got, []uint64{1, 2, 5, 6, 9}) {
		t.Fatalf("Limit: %v", got)
	}
	boom := errors.New("boom")
	n := 0
	res, err = Query(path, QueryOptions{}, func(*Record, []byte) error {
		if n++; n == 120 {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) || res.Matched != 120 {
		t.Fatalf("emit error: %+v %v", res, err)
	}
}

func TestQueryEmptyAndMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if _, _, err := query(t, path, QueryOptions{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing log: %v", err)
	}
	os.WriteFile(path, nil, 0o600)
	got, res, err := query(t, path, QueryOptions{})
	if err != nil || len(got) != 0 || res.Head != Genesis || res.Segments != 1 {
		t.Fatalf("empty log: %v %+v %v", got, res, err)
	}
	// A torn final line of the active file is a write in progress.
	l, _ := Open(path, fixedNow)
	appendCalls(t, l, 0, 3)
	l.Close()
	fh, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString(`{"seq":4,"ti`)
	fh.Close()
	if got, _, err := query(t, path, QueryOptions{}); err != nil || len(got) != 3 {
		t.Fatalf("torn line: %v %v", got, err)
	}
}

// tamperCase damages a rotated, indexed log.
type tamperCase struct {
	name string
	do   func(t *testing.T, path string, segs []string)
	// fullErr and indexErr are what a full query and a query since the
	// last segments' records report; "" means it passes.
	fullErr, indexErr string
}

func TestQueryFindsTampering(t *testing.T) {
	smallIndex(t, 1024)
	replaceLine := func(t *testing.T, p string, n int, f func(string) string) {
		ls := lines(t, p)
		ls[n] = f(ls[n])
		writeLines(t, p, ls)
	}
	edit := func(s string) string { return strings.Replace(s, `"time":"20`, `"time":"21`, 1) }
	for _, c := range []tamperCase{
		{name: "intact"},
		{name: "record edited early in a skipped segment", do: func(t *testing.T, path string, segs []string) {
			replaceLine(t, segs[1], 3, edit) // the same size, as the index says
		}, fullErr: "line 4: record does not match the hash stored in line 5"},
		{name: "record edited after the entry the query starts at", do: func(t *testing.T, path string, segs []string) {
			p := segs[len(segs)-1]
			ls := lines(t, p)
			replaceLine(t, p, len(ls)-3, edit)
		}, fullErr: "record does not match", indexErr: "record does not match"},
		{name: "last record of a segment edited", do: func(t *testing.T, path string, segs []string) {
			p := segs[len(segs)-1]
			replaceLine(t, p, len(lines(t, p))-1, edit)
		}, fullErr: "first record does not match the hash of the last record", indexErr: "does not match its time index"},
		{name: "middle segment removed", do: func(t *testing.T, path string, segs []string) {
			os.Remove(segs[2])
			os.Remove(IndexPath(segs[2]))
		}, fullErr: ") was removed", indexErr: ") was removed"},
		{name: "oldest segment removed", do: func(t *testing.T, path string, segs []string) {
			os.Remove(segs[0])
		}, fullErr: "the segments before it", indexErr: "the segments before it"},
		{name: "active file removed", do: func(t *testing.T, path string, segs []string) {
			os.Remove(path)
		}, fullErr: "the active segment is missing", indexErr: "the active segment is missing"},
		{name: "segment cut short", do: func(t *testing.T, path string, segs []string) {
			p := segs[len(segs)-2]
			ls := lines(t, p)
			writeLines(t, p, ls[:len(ls)-2])
		}, fullErr: "are missing between", indexErr: "are missing between"},
		{name: "segment renamed over a gap", do: func(t *testing.T, path string, segs []string) {
			os.Rename(segs[3], segs[3][:len(segs[3])-1]+"9")
		}, fullErr: "renamed", indexErr: "renamed"},
		{name: "index damaged", do: func(t *testing.T, path string, segs []string) {
			os.WriteFile(IndexPath(segs[1]), []byte("garbage\n"), 0o600)
			b, _ := os.ReadFile(IndexPath(segs[2]))
			os.WriteFile(IndexPath(segs[2]), bytes.Replace(b, []byte("entry "), []byte("entry 9"), 1), 0o600)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			path, clk := mixedLog(t, 900, 16<<10, time.Second, 0, 5)
			segs, _ := Segments(path)
			if _, _, err := query(t, path, QueryOptions{}); err != nil {
				t.Fatal(err)
			}
			// A query since the middle of the last rotated-out segment.
			lastSeg := segs[len(segs)-1]
			ix := loadIndex(lastSeg, ixFirst(t, lastSeg), fileSize(t, lastSeg))
			if ix == nil || len(ix.Entries) < 2 {
				t.Fatalf("index of %s: %+v", lastSeg, ix)
			}
			f, _ := ParseFilter("since="+ix.Min.Add(ix.Max.Sub(ix.Min)/2).Format(time.RFC3339Nano), clk.now())
			if c.do != nil {
				c.do(t, path, segs)
			}
			for _, o := range []struct {
				opt  QueryOptions
				want string
			}{{QueryOptions{Filter: f}, c.indexErr}, {QueryOptions{Full: true}, c.fullErr}} {
				_, res, err := query(t, path, o.opt)
				switch {
				case o.want == "" && err != nil:
					t.Errorf("full=%v: %v", o.opt.Full, err)
				case o.want != "" && (err == nil || !strings.Contains(err.Error(), o.want)):
					t.Errorf("full=%v: %v, want %q", o.opt.Full, err, o.want)
				case o.want == "" && !o.opt.Full && res.Skipped == 0:
					t.Errorf("the index query skipped nothing: %+v", res)
				}
			}
			if c.name == "index damaged" {
				// Both bad indexes were ignored and the full read made
				// them again.
				for _, p := range segs[1:3] {
					if loadIndex(p, ixFirst(t, p), fileSize(t, p)) == nil {
						t.Errorf("%s: index not rebuilt", p)
					}
				}
			}
		})
	}
}

func ixFirst(t *testing.T, p string) uint64 {
	n, ok := segmentFirst("audit.log", filepath.Base(p))
	if !ok {
		t.Fatalf("%s is not a segment", p)
	}
	return n
}

func TestQueryWhileRotating(t *testing.T) {
	smallIndex(t, 2048)
	path := filepath.Join(t.TempDir(), "audit.log")
	c := newClock()
	l := openRotating(t, path, Rotation{MaxBytes: 8 << 10}, c.now)
	defer l.Close()
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			c.add(time.Second)
			if err := l.Append(EventToolCall, callRec(i)); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	since, _ := ParseFilter("since="+fixedNow().Add(50*time.Second).Format(time.RFC3339Nano), fixedNow())
	var last uint64
	for i := 0; i < 40 || last < 400; i++ {
		o := QueryOptions{}
		if i%2 == 1 {
			o.Filter = since
		}
		got, res, err := query(t, path, o)
		if err != nil {
			close(done)
			wg.Wait()
			t.Fatalf("query %d: %v", i, err)
		}
		for j := 1; j < len(got); j++ {
			if got[j] != got[j-1]+1 {
				t.Fatalf("query %d: %d after %d", i, got[j], got[j-1])
			}
		}
		if res.Records < last {
			t.Fatalf("query %d saw %d records after %d", i, res.Records, last)
		}
		last = res.Records
	}
	close(done)
	wg.Wait()
	if segs, _ := Segments(path); len(segs) < 3 {
		t.Fatalf("only %d rotations", len(segs))
	}
}

func TestIndexFormat(t *testing.T) {
	smallIndex(t, 512)
	path, _ := mixedLog(t, 600, 32<<10, time.Second, 2*time.Second, 9)
	segs, _ := Segments(path)
	if _, _, err := query(t, path, QueryOptions{}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(IndexPath(segs[1]))
	if err != nil {
		t.Fatal(err)
	}
	ix, err := parseIndex(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ix.marshal(), b) || ix.Previous != filepath.Base(segs[0]) || len(ix.Entries) == 0 {
		t.Fatalf("index:\n%s", b)
	}
	b0, _ := os.ReadFile(IndexPath(segs[0]))
	if ix0, err := parseIndex(b0); err != nil || ix0.Start != Genesis || ix0.Previous != "" {
		t.Fatalf("first index: %v %+v", err, ix0)
	}
	// Every change to a line's shape is refused.
	ls := strings.SplitAfter(string(b), "\n")
	h := strings.Repeat("ab", 32)
	for _, c := range []struct {
		line int
		to   string
	}{
		{0, "authz audit index 2\n"},
		{1, "segment audit.log first 1 records 1 size 1\n"},
		{1, strings.Replace(ls[1], "first ", "first x", 1)},
		{1, strings.Replace(ls[1], "records ", "records 0", 1)},
		{1, strings.Replace(ls[1], "size ", "size -", 1)},
		{1, strings.Replace(ls[1], "segment ", "segment x/", 1)},
		{1, "segment audit.log.00000000000000000002 first 18446744073709551615 records 9 size 9\n"},
		{2, "start " + h + "\n"},
		{2, "start " + Genesis + " previous -\n"},
		{2, "start " + strings.ToUpper(h) + " previous " + filepath.Base(segs[0]) + "\n"},
		{2, "start " + h + " previous audit.log\n"},
		{3, "head xyz\n"},
		{3, "tail " + h + "\n"},
		{4, "time - 2026-11-16T00:00:00Z\n"},
		{4, "time 2026-11-16T00:00:01Z 2026-11-16T00:00:00Z\n"},
		{4, "time yesterday -\n"},
		{4, "times\n"},
		{5, "entry 1 2 " + h + "\n"},
		{5, strings.Replace(ls[5], "entry ", "entry 0", 1)},
		{5, strings.Replace(ls[5], "entry ", "entry x", 1)},
		{5, strings.Replace(ls[5], " ", " 99999999", 2)},
		{5, "entry " + strings.SplitN(ls[5], " ", 3)[1] + " 999999999 " + h + " -\n"},
		{5, strings.Replace(ls[5], " 2", " 1999", 1)},
		{5, ls[6]},
		{5, strings.TrimSuffix(ls[5], "\n")},
	} {
		mod := append([]string(nil), ls...)
		mod[c.line] = c.to
		if _, err := parseIndex([]byte(strings.Join(mod, ""))); err == nil {
			t.Errorf("line %d as %q was taken", c.line, c.to)
		}
	}
	if _, err := parseIndex(b[:len(b)-1]); err == nil {
		t.Error("an index without its final newline was taken")
	}
	// An index for another segment, or of another size, is not used.
	os.WriteFile(IndexPath(segs[2]), b, 0o600)
	if loadIndex(segs[2], ixFirst(t, segs[2]), fileSize(t, segs[2])) != nil {
		t.Error("another segment's index was used")
	}
	if loadIndex(segs[1], ixFirst(t, segs[1]), fileSize(t, segs[1])+1) != nil {
		t.Error("an index of another size was used")
	}
}

// BenchmarkQuery compares a query that reads the whole log with one that
// the time indexes let skip all but its last tenth.
func BenchmarkQuery(b *testing.B) {
	path, c := mixedLog(b, 50000, 1<<20, time.Second, 0, 2)
	since, _ := ParseFilter("since="+c.now().Add(-5000*time.Second).Format(time.RFC3339Nano), c.now())
	agent, _ := ParseFilter("track=agents agent=alice-bot decision=deny", c.now())
	if _, _, err := query(b, path, QueryOptions{}); err != nil {
		b.Fatal(err)
	}
	for _, bc := range []struct {
		name string
		o    QueryOptions
	}{
		{"full", QueryOptions{Full: true, Schemas: Default()}},
		{"agent-filter", QueryOptions{Filter: agent}},
		{"last-tenth-full", QueryOptions{Filter: since, Full: true}},
		{"last-tenth-indexed", QueryOptions{Filter: since}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := Query(path, bc.o, func(*Record, []byte) error { return nil }); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(50000*float64(b.N)/b.Elapsed().Seconds(), "records/s")
		})
	}
}
