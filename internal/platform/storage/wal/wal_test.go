package wal

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// event is a typed record like the ones the tracks keep: a kind, a key and
// an optional body.
type event struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
	Body string `json:"body,omitempty"`
	N    int    `json:"n,omitempty"`
}

// raw is a codec for opaque payloads, the second record type in these tests.
type raw struct{}

func (raw) Marshal(b []byte) ([]byte, error)   { return b, nil }
func (raw) Unmarshal(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }

func collect[T any](out *[]T) func(T) error {
	return func(v T) error { *out = append(*out, v); return nil }
}

func open(t testing.TB, path string, opts Options[event]) (*Stream[event], []event) {
	t.Helper()
	var got []event
	s, err := Open(path, opts, collect(&got))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, got
}

func sample(n int) []event {
	rng := rand.New(rand.NewSource(int64(n)))
	kinds := []string{"create", "touch", "revoke", "pin", "approve"}
	out := make([]event, n)
	for i := range out {
		out[i] = event{Kind: kinds[rng.Intn(len(kinds))], Key: fmt.Sprintf("k%d", rng.Intn(5)), N: i}
		if rng.Intn(2) == 0 {
			out[i].Body = strings.Repeat("x", rng.Intn(40)) + "\n\"quoted\""
		}
	}
	return out
}

func TestAppendAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.wal")
	s, got := open(t, path, Options[event]{})
	if len(got) != 0 || s.Records() != 0 || s.Size() != 0 || s.Path() != path {
		t.Fatalf("new stream: %d records, %d bytes, path %s", s.Records(), s.Size(), s.Path())
	}
	want := sample(6)
	if err := s.Append(want[0]); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(want[1:4]...); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(); err != nil {
		t.Fatal("empty append:", err)
	}
	if err := s.Append(want[4:]...); err != nil {
		t.Fatal(err)
	}
	if s.Records() != 6 {
		t.Fatalf("records = %d", s.Records())
	}
	size := s.Size()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Size() != size {
		t.Fatalf("file is %d bytes, stream said %d", fi.Size(), size)
	}
	s2, got := open(t, path, Options[event]{})
	if !reflect.DeepEqual(got, want) || s2.Records() != 6 || s2.Size() != size {
		t.Fatalf("replayed %+v (%d records, %d bytes)", got, s2.Records(), s2.Size())
	}
	// Appends continue after the replayed records.
	if err := s2.Append(event{Kind: "touch", Key: "after"}); err != nil {
		t.Fatal(err)
	}
	s2.Close()
	_, got = open(t, path, Options[event]{})
	if len(got) != 7 || got[6].Key != "after" {
		t.Fatalf("after reopen: %+v", got)
	}
}

// The framing is exactly what grantd's log and wicket's session log wrote,
// so their files open as streams.
func TestFramingMatchesTheOldLogs(t *testing.T) {
	body := []byte(`{"rev":1,"type":"schema","schema":"definition user {}"}`)
	old := fmt.Sprintf("%08x %s\n", crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)), body)
	if got := string(Frame(nil, body)); got != old {
		t.Fatalf("frame %q, old logs wrote %q", got, old)
	}
	upper := strings.ToUpper(old[:8]) + old[8:]
	payload, err := Unframe([]byte(strings.TrimSuffix(upper, "\n")))
	if err != nil || !bytes.Equal(payload, body) {
		t.Fatalf("upper-case checksum: %q %v", payload, err)
	}
	for _, bad := range []string{"", "short", "zzzzzzzz {}", "00000000x{}", "00000000 {}"} {
		if _, err := Unframe([]byte(bad)); err == nil {
			t.Fatalf("Unframe(%q) accepted", bad)
		}
	}
}

// Two streams with different record types side by side.
func TestTypedStreams(t *testing.T) {
	dir := t.TempDir()
	ev, _ := open(t, filepath.Join(dir, "events.wal"), Options[event]{})
	blobs, err := Open[[]byte](filepath.Join(dir, "blobs.wal"), Options[[]byte]{Codec: raw{}, Sync: SyncNever}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ev.Append(event{Kind: "a", Key: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := blobs.Append([]byte("one"), []byte("two words")); err != nil {
		t.Fatal(err)
	}
	if err := blobs.Append([]byte("line\nbreak")); err == nil {
		t.Fatal("payload with a newline accepted")
	}
	blobs.Close()
	var got [][]byte
	b2, err := Open(filepath.Join(dir, "blobs.wal"), Options[[]byte]{Codec: raw{}}, collect(&got))
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	if len(got) != 2 || string(got[0]) != "one" || string(got[1]) != "two words" {
		t.Fatalf("blobs %q", got)
	}
}

// TestCutAtEveryByte truncates a stream at every possible length, as a crash
// in the middle of any write would, and checks that recovery yields exactly
// the records whose lines are complete, trims the file to them and keeps
// appending cleanly.
func TestCutAtEveryByte(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "full.wal")
	s, _ := open(t, path, Options[event]{})
	want := sample(12)
	ends := []int64{0}
	for i := 0; i < len(want); {
		n := 1 + i%3 // single and grouped appends
		if i+n > len(want) {
			n = len(want) - i
		}
		if err := s.Append(want[i : i+n]...); err != nil {
			t.Fatal(err)
		}
		i += n
	}
	s.Close()
	full, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range full {
		if b == '\n' {
			ends = append(ends, int64(i+1))
		}
	}
	if len(ends) != len(want)+1 {
		t.Fatalf("%d lines for %d records", len(ends)-1, len(want))
	}
	for n := 0; n <= len(full); n++ {
		p := filepath.Join(dir, fmt.Sprintf("cut%d.wal", n))
		if err := os.WriteFile(p, full[:n], 0o600); err != nil {
			t.Fatal(err)
		}
		var got []event
		r, err := Open(p, Options[event]{}, collect(&got))
		if err != nil {
			t.Fatalf("cut at %d: %v", n, err)
		}
		k := 0
		for k+1 < len(ends) && ends[k+1] <= int64(n) {
			k++
		}
		if !reflect.DeepEqual(got, want[:k]) && !(k == 0 && len(got) == 0) {
			t.Fatalf("cut at %d: recovered %d records, want %d", n, len(got), k)
		}
		if r.Size() != ends[k] || r.Records() != k {
			t.Fatalf("cut at %d: size %d records %d, want %d %d", n, r.Size(), r.Records(), ends[k], k)
		}
		if fi, _ := os.Stat(p); fi.Size() != ends[k] {
			t.Fatalf("cut at %d: torn tail left on disk (%d bytes)", n, fi.Size())
		}
		if err := r.Append(event{Kind: "after", Key: "crash"}); err != nil {
			t.Fatal(err)
		}
		r.Close()
		got = nil
		r, err = Open(p, Options[event]{}, collect(&got))
		if err != nil || len(got) != k+1 || got[k].Kind != "after" {
			t.Fatalf("cut at %d: append after recovery: %v, %d records", n, err, len(got))
		}
		r.Close()
		os.Remove(p)
	}
}

// TestFlipEveryByte damages each byte in turn. Recovery must either refuse
// the file or return an unchanged prefix that stops before the damage, and
// it may only drop damage in the last line.
func TestFlipEveryByte(t *testing.T) {
	var buf []byte
	want := sample(5)
	for _, e := range want {
		b, err := Encode[event](JSON[event]{}, DefaultMaxRecord, e)
		if err != nil {
			t.Fatal(err)
		}
		buf = append(buf, b...)
	}
	lastStart := int64(bytes.LastIndexByte(buf[:len(buf)-1], '\n') + 1)
	for i := range buf {
		for _, mask := range []byte{0x01, 0x80} {
			d := append([]byte(nil), buf...)
			d[i] ^= mask
			var got []event
			good, n, err := Scan(bytes.NewReader(d), Options[event]{}, collect(&got))
			if err != nil {
				if !errors.Is(err, ErrCorrupt) {
					t.Fatalf("byte %d: %v", i, err)
				}
				continue
			}
			if !reflect.DeepEqual(got, want[:n]) && n > 0 {
				t.Fatalf("byte %d: recovered a changed record", i)
			}
			if int64(i) < good {
				t.Fatalf("byte %d flipped inside the recovered prefix of %d bytes", i, good)
			}
			if int64(i) < lastStart-1 {
				t.Fatalf("byte %d: damage before the last line was dropped silently", i)
			}
		}
	}
}

func TestDamage(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, recs ...string) string {
		var b []byte
		for _, r := range recs {
			b = append(b, r...)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	line := func(payload string) string { return string(Frame(nil, []byte(payload))) }
	a, b := line(`{"kind":"a","key":"1"}`), line(`{"kind":"b","key":"2"}`)

	// Damage in the middle is fatal.
	mid := []byte(a)
	mid[12] ^= 0xff
	if _, err := Open(write("mid.wal", string(mid), b), Options[event]{}, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("middle damage: %v", err)
	}
	// A bad payload behind a good checksum: dropped at the end, fatal before.
	if _, got := open(t, write("json-tail.wal", a, line("not json")), Options[event]{}); len(got) != 1 {
		t.Fatalf("bad final payload: %d records", len(got))
	}
	if _, err := Open(write("json-mid.wal", line("not json"), a), Options[event]{}, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad payload in the middle: %v", err)
	}
	// An empty final line is a torn write too.
	if _, got := open(t, write("empty.wal", a, "\n"), Options[event]{}); len(got) != 1 {
		t.Fatal("empty final line")
	}
	// Strict JSON refuses unknown fields and trailing data.
	strict := Options[event]{Codec: JSON[event]{Strict: true}}
	for _, p := range []string{`{"kind":"a","key":"1","x":1}`, `{"kind":"a","key":"1"} {}`, `{"kind":`} {
		if _, err := Open(write("strict.wal", line(p), a), strict, nil); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("strict %s: %v", p, err)
		}
	}
	if _, got := open(t, write("strict-ok.wal", a, b), strict); len(got) != 2 {
		t.Fatal("strict decoding refused good records")
	}
	// Validate rejects like damage; apply errors are always fatal.
	val := Options[event]{Validate: func(e event) error {
		if e.Kind == "b" {
			return errors.New("no b")
		}
		return nil
	}}
	if _, got := open(t, write("val-tail.wal", a, b), val); len(got) != 1 {
		t.Fatal("invalid final record kept")
	}
	if _, err := Open(write("val-mid.wal", b, a), val, nil); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "no b") {
		t.Fatalf("invalid record in the middle: %v", err)
	}
	refuse := func(event) error { return errors.New("refused") }
	if _, err := Open(write("apply.wal", a), Options[event]{}, refuse); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("apply error: %v", err)
	}
	// A line longer than MaxRecord is fatal, even without a newline, so a
	// damaged file can't make replay allocate without bound.
	small := Options[event]{MaxRecord: 64}
	long := line(`{"kind":"a","key":"` + strings.Repeat("k", 80) + `"}`)
	if _, err := Open(write("long.wal", a, long), small, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("long line: %v", err)
	}
	if _, err := Open(write("long-torn.wal", a, strings.Repeat("z", 100)), small, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("long torn line: %v", err)
	}
}

// Records longer than the read buffer are assembled across chunks.
func TestLargeRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.wal")
	s, _ := open(t, path, Options[event]{})
	big := []event{{Kind: "a", Body: strings.Repeat("b", 3*readChunk+17)}, {Kind: "small"}, {Kind: "c", Body: strings.Repeat("c", readChunk)}}
	if err := s.Append(big...); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(event{Body: strings.Repeat("x", DefaultMaxRecord)}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized append: %v", err)
	}
	if err := s.Replace([]event{{Body: strings.Repeat("x", DefaultMaxRecord)}}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized replace: %v", err)
	}
	s.Close()
	_, got := open(t, path, Options[event]{})
	if !reflect.DeepEqual(got, big) {
		t.Fatal("large records changed")
	}
}

type badCodec struct{}

func (badCodec) Marshal(event) ([]byte, error)   { return nil, errors.New("cannot encode") }
func (badCodec) Unmarshal([]byte) (event, error) { return event{}, nil }

func TestEncodeErrorWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.wal")
	s, err := Open(path, Options[event]{Codec: badCodec{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Append(event{}); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("encode error: %v", err)
	}
	if err := s.Replace([]event{{}}); err == nil {
		t.Fatal("replace with an encode error succeeded")
	}
	if s.Size() != 0 || s.Err() != nil {
		t.Fatal("encode error changed the stream")
	}
}

func TestReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.wal")
	// A leftover from a crash during an earlier Replace is ignored by Open
	// and overwritten by the next Replace.
	if err := os.WriteFile(path+".tmp", []byte("00000000 leftover\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := open(t, path, Options[event]{})
	if err := s.Append(sample(5)...); err != nil {
		t.Fatal(err)
	}
	snap := []event{{Kind: "snapshot", Key: "all", N: 5}}
	if err := s.Replace(snap); err != nil {
		t.Fatal(err)
	}
	if s.Records() != 1 {
		t.Fatalf("records after replace = %d", s.Records())
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary file left: %v", err)
	}
	if err := s.Append(event{Kind: "after"}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, got := open(t, path, Options[event]{})
	if len(got) != 2 || got[0].Kind != "snapshot" || got[1].Kind != "after" {
		t.Fatalf("after replace: %+v", got)
	}
	// Replacing with nothing empties the stream.
	s3, _ := open(t, path, Options[event]{})
	if err := s3.Replace(nil); err != nil || s3.Size() != 0 {
		t.Fatalf("empty replace: %v, %d bytes", err, s3.Size())
	}
}

func TestReplaceFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.wal")
	s, _ := open(t, path, Options[event]{})
	if err := s.Append(event{Kind: "keep"}); err != nil {
		t.Fatal(err)
	}
	keep := s.Size()
	check := func(what string) {
		t.Helper()
		if s.Size() != keep || s.Err() != nil {
			t.Fatalf("%s: stream changed (%d bytes, %v)", what, s.Size(), s.Err())
		}
		if _, err := os.Stat(path + ".tmp"); what != "open" && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: temporary file left", what)
		}
		if err := s.Append(event{Kind: "still"}); err != nil {
			t.Fatalf("%s: append after failed replace: %v", what, err)
		}
		keep = s.Size()
	}
	// The temporary file can't be created.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(nil); err == nil {
		t.Fatal("replace over a directory succeeded")
	}
	check("open")
	os.Remove(path + ".tmp")

	inject(t, func(f *faultFile) { f.writeErr = syscall.ENOSPC })
	if err := s.Replace([]event{{Kind: "x"}}); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("write: %v", err)
	}
	check("write")
	inject(t, func(f *faultFile) { f.syncErr = syscall.EIO })
	if err := s.Replace([]event{{Kind: "x"}}); !errors.Is(err, syscall.EIO) {
		t.Fatalf("sync: %v", err)
	}
	check("sync")
	inject(t, nil)
	rename = func(string, string) error { return syscall.EXDEV }
	t.Cleanup(func() { rename = os.Rename })
	if err := s.Replace([]event{{Kind: "x"}}); !errors.Is(err, syscall.EXDEV) {
		t.Fatalf("rename: %v", err)
	}
	check("rename")
	rename = os.Rename

	// A failed directory fsync after the rename leaves the new file in
	// place but stops appends: the rename might not survive a power cut.
	old := syncDir
	syncDir = func(string) error { return syscall.EIO }
	t.Cleanup(func() { syncDir = old })
	if err := s.Replace([]event{{Kind: "new"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("directory sync: %v", err)
	}
	if err := s.Append(event{}); !errors.Is(err, ErrUnavailable) || s.Err() == nil {
		t.Fatalf("append after a failed directory sync: %v", err)
	}
	// A later successful Replace heals it.
	syncDir = old
	if err := s.Replace([]event{{Kind: "healed"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(event{Kind: "after"}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, got := open(t, path, Options[event]{})
	if len(got) != 2 || got[0].Kind != "healed" {
		t.Fatalf("after healing: %+v", got)
	}
}

// faultFile wraps a real file and fails chosen operations.
type faultFile struct {
	*os.File
	writeErr    error
	shortWrite  int // with writeErr: bytes written before failing
	syncErr     error
	truncateErr error
	seekErr     error
	syncs       *atomic.Int64
}

func (f *faultFile) Write(b []byte) (int, error) {
	if f.writeErr != nil {
		n, _ := f.File.Write(b[:min(f.shortWrite, len(b))])
		return n, f.writeErr
	}
	return f.File.Write(b)
}

func (f *faultFile) Sync() error {
	if f.syncs != nil {
		f.syncs.Add(1)
	}
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}

func (f *faultFile) Truncate(n int64) error {
	if f.truncateErr != nil {
		return f.truncateErr
	}
	return f.File.Truncate(n)
}

func (f *faultFile) Seek(off int64, whence int) (int64, error) {
	if f.seekErr != nil {
		return 0, f.seekErr
	}
	return f.File.Seek(off, whence)
}

// inject makes the next files the package opens fault files, configured by
// set (nil for plain files).
func inject(t testing.TB, set func(*faultFile)) {
	t.Helper()
	openFile = func(path string, flag int) (file, error) {
		f, err := os.OpenFile(path, flag, 0o600)
		if err != nil {
			return nil, err
		}
		ff := &faultFile{File: f}
		if set != nil {
			set(ff)
		}
		return ff, nil
	}
	t.Cleanup(func() {
		openFile = func(path string, flag int) (file, error) { return os.OpenFile(path, flag, 0o600) }
	})
}

// openFault opens a stream whose file is ff, so the test can change faults
// after the stream is open.
func openFault(t *testing.T, path string, opts Options[event]) (*Stream[event], *faultFile) {
	t.Helper()
	var ff *faultFile
	inject(t, func(f *faultFile) { ff = f })
	s, err := Open(path, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	inject(t, nil)
	t.Cleanup(func() { s.Close() })
	return s, ff
}

func TestAppendRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.wal")
	s, ff := openFault(t, path, Options[event]{})
	if err := s.Append(event{Kind: "keep"}); err != nil {
		t.Fatal(err)
	}
	keep := s.Size()
	for _, c := range []struct {
		name string
		set  func()
	}{
		{"short write", func() { ff.writeErr, ff.shortWrite = io.ErrShortWrite, 7 }},
		{"ENOSPC", func() { ff.writeErr, ff.shortWrite = syscall.ENOSPC, 1<<20 }},
		{"fsync error", func() { ff.syncErr = syscall.EIO }},
	} {
		c.set()
		if err := s.Append(event{Kind: "lost", Body: "partial"}, event{Kind: "lost2"}); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s: %v", c.name, err)
		}
		ff.writeErr, ff.shortWrite, ff.syncErr = nil, 0, nil
		if fi, _ := os.Stat(path); fi.Size() != keep || s.Size() != keep || s.Records() != 1 {
			t.Fatalf("%s: partial append left on disk (%d bytes)", c.name, fi.Size())
		}
		if s.Err() != nil {
			t.Fatalf("%s: rolled-back stream marked broken", c.name)
		}
	}
	if err := s.Append(event{Kind: "next"}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, got := open(t, path, Options[event]{})
	if len(got) != 2 || got[1].Kind != "next" {
		t.Fatalf("after rollbacks: %+v", got)
	}
}

func TestUnremovablePartialRecordStopsAppends(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*faultFile)
	}{
		{"truncate", func(f *faultFile) { f.truncateErr = syscall.EIO }},
		{"seek", func(f *faultFile) { f.seekErr = syscall.EIO }},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "s.wal")
			s, ff := openFault(t, path, Options[event]{})
			if err := s.Append(event{Kind: "keep"}); err != nil {
				t.Fatal(err)
			}
			ff.writeErr, ff.shortWrite = syscall.ENOSPC, 5
			c.set(ff)
			if err := s.Append(event{Kind: "torn"}); !errors.Is(err, ErrUnavailable) {
				t.Fatal(err)
			}
			*ff = faultFile{File: ff.File}
			if err := s.Append(event{Kind: "after"}); !errors.Is(err, ErrUnavailable) || s.Err() == nil {
				t.Fatalf("append after an unremovable partial record: %v", err)
			}
			if err := s.Sync(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("sync on a broken stream: %v", err)
			}
			// The file on disk ends in a torn record, which recovery drops.
			s.Close()
			_, got := open(t, path, Options[event]{})
			if len(got) != 1 || got[0].Kind != "keep" {
				t.Fatalf("recovered %+v", got)
			}
		})
	}
}

func TestOpenFailures(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(filepath.Join(dir, "missing", "s.wal"), Options[event]{}, nil); err == nil {
		t.Fatal("open in a missing directory succeeded")
	}
	path := filepath.Join(dir, "s.wal")
	torn := append(Frame(nil, []byte(`{"kind":"a"}`)), "torn"...)
	for _, c := range []struct {
		name string
		set  func(*faultFile)
	}{
		{"truncate", func(f *faultFile) { f.truncateErr = syscall.EIO }},
		{"sync", func(f *faultFile) { f.syncErr = syscall.EIO }},
		{"seek", func(f *faultFile) { f.seekErr = syscall.EIO }},
	} {
		if err := os.WriteFile(path, torn, 0o600); err != nil {
			t.Fatal(err)
		}
		inject(t, c.set)
		if _, err := Open(path, Options[event]{}, nil); !errors.Is(err, syscall.EIO) {
			t.Fatalf("%s while dropping a torn tail: %v", c.name, err)
		}
	}
	inject(t, nil)
	if s, err := Open(path, Options[event]{}, nil); err != nil || s.Records() != 1 {
		t.Fatalf("open after the faults: %v", err)
	} else {
		s.Close()
	}
	// A read error is reported, not taken for the end of the file.
	if _, _, err := Scan(iotestErrReader{}, Options[event]{}, nil); !errors.Is(err, syscall.EIO) {
		t.Fatalf("read error: %v", err)
	}
}

type iotestErrReader struct{}

func (iotestErrReader) Read([]byte) (int, error) { return 0, syscall.EIO }

func TestSyncPolicies(t *testing.T) {
	dir := t.TempDir()
	count := func(t *testing.T, opts Options[event]) (*Stream[event], *atomic.Int64) {
		var n atomic.Int64
		inject(t, func(f *faultFile) { f.syncs = &n })
		s, err := Open(filepath.Join(dir, opts.Sync.String()+".wal"), opts, nil)
		if err != nil {
			t.Fatal(err)
		}
		inject(t, nil)
		return s, &n
	}
	t.Run("always", func(t *testing.T) {
		s, n := count(t, Options[event]{})
		for i := 0; i < 3; i++ {
			if err := s.Append(event{N: i}); err != nil {
				t.Fatal(err)
			}
		}
		if n.Load() != 3 {
			t.Fatalf("%d fsyncs for 3 appends", n.Load())
		}
		if err := s.Sync(); err != nil || n.Load() != 3 {
			t.Fatal("Sync with nothing unsynced called fsync")
		}
		s.Close()
		if n.Load() != 3 {
			t.Fatal("Close fsynced a clean stream")
		}
	})
	t.Run("never", func(t *testing.T) {
		s, n := count(t, Options[event]{Sync: SyncNever})
		for i := 0; i < 3; i++ {
			if err := s.Append(event{N: i}); err != nil {
				t.Fatal(err)
			}
		}
		if n.Load() != 0 {
			t.Fatalf("%d fsyncs under SyncNever", n.Load())
		}
		if err := s.Sync(); err != nil || n.Load() != 1 {
			t.Fatalf("Sync: %v, %d fsyncs", err, n.Load())
		}
		if err := s.Append(event{}); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil || n.Load() != 2 {
			t.Fatalf("Close: %v, %d fsyncs", err, n.Load())
		}
	})
	t.Run("interval", func(t *testing.T) {
		s, n := count(t, Options[event]{Sync: SyncInterval, Interval: 5 * time.Millisecond})
		if err := s.Append(event{}); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for n.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if n.Load() == 0 {
			t.Fatal("background fsync never ran")
		}
		time.Sleep(30 * time.Millisecond)
		if got := n.Load(); got != 1 {
			t.Fatalf("%d fsyncs for one append", got)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal("second close:", err)
		}
	})
	t.Run("interval default", func(t *testing.T) {
		s, _ := count(t, Options[event]{Sync: SyncInterval})
		if err := s.Append(event{}); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	})
	if SyncPolicy(9).String() != "SyncPolicy(9)" {
		t.Fatal(SyncPolicy(9).String())
	}
}

// An fsync failure after records were acknowledged without one means they
// may be gone, so the stream stops; Replace with the caller's state heals it.
func TestFailedSyncStopsAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.wal")
	s, ff := openFault(t, path, Options[event]{Sync: SyncInterval, Interval: time.Millisecond})
	ff.syncErr = syscall.EIO
	if err := s.Append(event{Kind: "acked"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.Err() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(s.Err(), ErrUnavailable) {
		t.Fatal("background fsync failure not reported")
	}
	if err := s.Append(event{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("append after a failed fsync: %v", err)
	}
	if err := s.Replace([]event{{Kind: "state"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(event{Kind: "more"}); err != nil {
		t.Fatal(err)
	}
	// A broken stream still closes.
	s2, ff2 := openFault(t, filepath.Join(t.TempDir(), "n.wal"), Options[event]{Sync: SyncNever})
	ff2.syncErr = syscall.EIO
	if err := s2.Append(event{}); err != nil {
		t.Fatal(err)
	}
	if err := s2.Sync(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Sync: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatalf("closing a broken stream: %v", err)
	}
	// Close reports a failed final fsync.
	s3, ff3 := openFault(t, filepath.Join(t.TempDir(), "c.wal"), Options[event]{Sync: SyncNever})
	if err := s3.Append(event{}); err != nil {
		t.Fatal(err)
	}
	ff3.syncErr = syscall.EIO
	if err := s3.Close(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Close with a failed fsync: %v", err)
	}
}

func TestClosed(t *testing.T) {
	s, _ := open(t, filepath.Join(t.TempDir(), "s.wal"), Options[event]{})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("second close:", err)
	}
	if err := s.Append(event{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("append: %v", err)
	}
	if err := s.Sync(); !errors.Is(err, ErrClosed) {
		t.Fatalf("sync: %v", err)
	}
	if err := s.Replace(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("replace: %v", err)
	}
}

func TestConcurrentAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.wal")
	s, _ := open(t, path, Options[event]{Sync: SyncInterval, Interval: time.Millisecond})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := s.Append(event{Kind: "w", Key: fmt.Sprint(g), N: i}); err != nil {
					t.Error(err)
					return
				}
				if i%10 == 0 {
					if err := s.Sync(); err != nil {
						t.Error(err)
					}
					_ = s.Size() + int64(s.Records())
				}
			}
		}(g)
	}
	wg.Wait()
	s.Close()
	_, got := open(t, path, Options[event]{})
	next := map[string]int{}
	for _, e := range got {
		if e.N != next[e.Key] {
			t.Fatalf("writer %s: record %d out of order", e.Key, e.N)
		}
		next[e.Key]++
	}
	if len(got) != 400 {
		t.Fatalf("%d records, want 400", len(got))
	}
}

func FuzzScan(f *testing.F) {
	f.Add([]byte(""))
	f.Add(Frame(nil, []byte("one")))
	f.Add(append(Frame(Frame(nil, []byte("one")), []byte("two")), "torn"...))
	f.Add([]byte("00000000 x\n\n\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		opts := Options[[]byte]{Codec: raw{}, MaxRecord: 1 << 10}
		var got [][]byte
		good, n, err := Scan(bytes.NewReader(data), opts, collect(&got))
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if good > int64(len(data)) || n != len(got) {
			t.Fatalf("good %d of %d bytes, %d records, %d applied", good, len(data), n, len(got))
		}
		// The intact prefix is exactly the records, re-framed (the
		// checksum's hex digits may be in either case).
		var again []byte
		for _, p := range got {
			again = Frame(again, p)
		}
		if !bytes.EqualFold(again, data[:good]) || len(again) != int(good) {
			t.Fatal("intact prefix is not the recovered records")
		}
		var prefix [][]byte
		g2, n2, err := Scan(bytes.NewReader(data[:good]), opts, collect(&prefix))
		if err != nil || g2 != good || n2 != n || !reflect.DeepEqual(prefix, got) {
			t.Fatalf("rescanning the intact prefix: %d %d %v", g2, n2, err)
		}
		for i, p := range got {
			if q, _ := Unframe(bytes.TrimSuffix(Frame(nil, p), []byte{'\n'})); !bytes.Equal(p, q) {
				t.Fatalf("record %d does not survive a round trip", i)
			}
		}
	})
}

func BenchmarkAppend(b *testing.B) {
	for _, p := range []SyncPolicy{SyncAlways, SyncInterval, SyncNever} {
		b.Run(p.String(), func(b *testing.B) {
			s, err := Open(filepath.Join(b.TempDir(), "b.wal"), Options[event]{Sync: p}, nil)
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			e := event{Kind: "touch", Key: "doc:readme#viewer@user:alice", Body: strings.Repeat("x", 64)}
			b.ReportAllocs()
			for b.Loop() {
				if err := s.Append(e); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkScan(b *testing.B) {
	var buf []byte
	for i := 0; i < 10000; i++ {
		p, _ := JSON[event]{}.Marshal(event{Kind: "touch", Key: fmt.Sprintf("doc:%d#viewer@user:u", i)})
		buf = Frame(buf, p)
	}
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for b.Loop() {
		if _, n, err := Scan(bytes.NewReader(buf), Options[event]{}, func(event) error { return nil }); err != nil || n != 10000 {
			b.Fatal(n, err)
		}
	}
}
