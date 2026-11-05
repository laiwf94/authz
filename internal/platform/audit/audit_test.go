package audit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedNow() time.Time { return time.Unix(1_700_000_000, 0) }

func writeLog(t testing.TB, n int) (string, *Log) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := l.Append("tool_call", map[string]any{"i": i, "agent": "alice-bot", "note": "line\nbreak"}); err != nil {
			t.Fatal(err)
		}
	}
	return path, l
}

func verifyFile(t *testing.T, path string) (Result, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return Verify(f)
}

func TestAppendVerifyReopen(t *testing.T) {
	path, l := writeLog(t, 5)
	seq, head := l.Head()
	if seq != 5 || len(head) != 64 || !l.Healthy() {
		t.Fatalf("head %d %s", seq, head)
	}
	res, err := verifyFile(t, path)
	if err != nil || res.Records != 5 || res.Head != head {
		t.Fatalf("verify: %+v %v", res, err)
	}
	l.Close()
	l2, err := Open(path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if s, h := l2.Head(); s != 5 || h != head {
		t.Fatalf("reopen head %d %s", s, h)
	}
	if err := l2.Append("policy_reload", map[string]string{"hash": "x"}); err != nil {
		t.Fatal(err)
	}
	l2.Close()
	if res, err := verifyFile(t, path); err != nil || res.Records != 6 {
		t.Fatalf("after reopen: %+v %v", res, err)
	}
	data, _ := os.ReadFile(path)
	first := strings.SplitN(string(data), "\n", 2)[0]
	if !strings.HasPrefix(first, `{"seq":1,"time":"2023-11-14T22:13:20Z","prev":"`+Genesis+`","event":"tool_call","data":{"agent":"alice-bot","i":0,"note":"line\nbreak"}}`) {
		t.Fatalf("unexpected record format: %s", first)
	}
	if empty, err := Verify(strings.NewReader("")); err != nil || empty.Head != Genesis || empty.Records != 0 {
		t.Fatalf("empty log: %+v %v", empty, err)
	}
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func writeLines(t *testing.T, path string, ls []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTamperDetection(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]string) []string
		line   int
	}{
		{"edit middle", func(ls []string) []string {
			ls[2] = strings.Replace(ls[2], `"i":2`, `"i":9`, 1)
			return ls
		}, 3},
		{"edit first", func(ls []string) []string {
			ls[0] = strings.Replace(ls[0], "alice-bot", "mallory", 1)
			return ls
		}, 1},
		{"break json", func(ls []string) []string { ls[1] = ls[1][:20]; return ls }, 2},
		{"delete middle", func(ls []string) []string { return append(ls[:2], ls[3:]...) }, 2},
		{"delete first", func(ls []string) []string { return ls[1:] }, 1},
		{"swap", func(ls []string) []string { ls[1], ls[2] = ls[2], ls[1]; return ls }, 1},
		{"duplicate", func(ls []string) []string { return append(ls[:3], ls[2:]...) }, 3},
		{"unknown field", func(ls []string) []string {
			ls[4] = strings.Replace(ls[4], `"event"`, `"x":1,"event"`, 1)
			return ls
		}, 5},
	}
	for _, c := range cases {
		path, l := writeLog(t, 5)
		l.Close()
		writeLines(t, path, c.mutate(lines(t, path)))
		_, err := verifyFile(t, path)
		var le *LineError
		if !errors.As(err, &le) || le.Line != c.line {
			t.Errorf("%s: got %v, want an error at line %d", c.name, err, c.line)
		}
		if _, err := Open(path, fixedNow); err == nil {
			t.Errorf("%s: Open accepted a tampered log", c.name)
		}
	}
}

// Any single-byte change anywhere is caught: either Verify fails, or the head
// hash changes (an edit of the newest line, caught by comparing heads).
func TestEveryByteFlipDetected(t *testing.T) {
	path, l := writeLog(t, 4)
	_, head := l.Head()
	l.Close()
	orig, _ := os.ReadFile(path)
	for i := range orig {
		mut := bytes.Clone(orig)
		mut[i] ^= 0x01
		res, err := Verify(bytes.NewReader(mut))
		if err == nil && res.Head == head {
			t.Fatalf("flip at byte %d (%q) went unnoticed", i, orig[i])
		}
	}
}

// Recovery after a crash: for every possible cut, Open keeps exactly the
// complete lines and the chain continues from them.
func TestTruncationAtEveryByte(t *testing.T) {
	path, l := writeLog(t, 4)
	l.Close()
	orig, _ := os.ReadFile(path)
	dir := t.TempDir()
	for cut := 0; cut <= len(orig); cut++ {
		p := filepath.Join(dir, fmt.Sprint(cut))
		if err := os.WriteFile(p, orig[:cut], 0o600); err != nil {
			t.Fatal(err)
		}
		l, err := Open(p, fixedNow)
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		want := uint64(bytes.Count(orig[:cut], []byte("\n")))
		if seq, _ := l.Head(); seq != want {
			t.Fatalf("cut %d: recovered %d records, want %d", cut, seq, want)
		}
		if err := l.Append("after", nil); err != nil {
			t.Fatal(err)
		}
		l.Close()
		f, _ := os.Open(p)
		res, err := Verify(f)
		f.Close()
		if err != nil || res.Records != want+1 {
			t.Fatalf("cut %d: chain after recovery: %+v %v", cut, res, err)
		}
	}
	if _, err := Verify(bytes.NewReader(orig[:len(orig)-3])); err == nil {
		t.Fatal("Verify must report a torn final line")
	}
}

func TestConcurrentAppends(t *testing.T) {
	path, l := writeLog(t, 0)
	var wg sync.WaitGroup
	for g := range 20 {
		wg.Go(func() {
			for i := range 25 {
				if err := l.Append("e", map[string]int{"g": g, "i": i}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	l.Close()
	res, err := verifyFile(t, path)
	if err != nil || res.Records != 500 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestLimitsAndOpenErrors(t *testing.T) {
	_, l := writeLog(t, 0)
	defer l.Close()
	if err := l.Append("big", strings.Repeat("x", MaxLineBytes)); err == nil {
		t.Fatal("oversized record accepted")
	}
	if err := l.Append("bad", func() {}); err == nil {
		t.Fatal("unencodable record accepted")
	}
	if !l.Healthy() {
		t.Fatal("rejected records must not break the log")
	}
	if _, err := Verify(strings.NewReader(strings.Repeat("x", MaxLineBytes+1) + "\n")); err == nil {
		t.Fatal("over-long line accepted")
	}
	if _, err := Open(t.TempDir(), nil); err == nil {
		t.Fatal("opened a directory")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing", "x"), nil); err == nil {
		t.Fatal("opened in a missing directory")
	}
	if _, err := Verify(errReader{}); err == nil {
		t.Fatal("read error not reported")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("disk on fire") }

// faultyFile wraps a real file and fails chosen operations.
type faultyFile struct {
	*os.File
	failWrite, partial, failTruncate, failSync, failSeek bool
}

func (f *faultyFile) Write(p []byte) (int, error) {
	if f.failWrite {
		if f.partial {
			n, _ := f.File.Write(p[:len(p)/2])
			return n, errors.New("short write")
		}
		return 0, errors.New("write failed")
	}
	return f.File.Write(p)
}

func (f *faultyFile) Truncate(n int64) error {
	if f.failTruncate {
		return errors.New("truncate failed")
	}
	return f.File.Truncate(n)
}

func (f *faultyFile) Seek(o int64, w int) (int64, error) {
	if f.failSeek {
		return 0, errors.New("seek failed")
	}
	return f.File.Seek(o, w)
}

func (f *faultyFile) Sync() error {
	if f.failSync {
		return errors.New("fsync failed")
	}
	return f.File.Sync()
}

func TestWriteFailures(t *testing.T) {
	// A partial write is cut off and the log keeps working.
	path, l := writeLog(t, 2)
	ff := &faultyFile{File: l.f.(*os.File), failWrite: true, partial: true}
	l.f = ff
	if err := l.Append("x", nil); err == nil {
		t.Fatal("failed write reported success")
	}
	if !l.Healthy() {
		t.Fatal("recoverable write failure broke the log")
	}
	ff.failWrite = false
	if err := l.Append("y", nil); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if res, err := verifyFile(t, path); err != nil || res.Records != 3 {
		t.Fatalf("after partial write: %+v %v", res, err)
	}

	// If the partial write cannot be cut off, appends stop for good.
	for _, mode := range []string{"truncate", "seek"} {
		_, l = writeLog(t, 1)
		ff = &faultyFile{File: l.f.(*os.File), failWrite: true, partial: true,
			failTruncate: mode == "truncate", failSeek: mode == "seek"}
		l.f = ff
		if err := l.Append("x", nil); err == nil {
			t.Fatal("write failure hidden")
		}
		ff.failWrite = false
		if err := l.Append("y", nil); !errors.Is(err, ErrBroken) || l.Healthy() {
			t.Fatalf("%s: log not marked broken: %v", mode, err)
		}
		l.Close()
	}

	// A failed fsync also stops the log.
	_, l = writeLog(t, 1)
	l.f = &faultyFile{File: l.f.(*os.File), failSync: true}
	if err := l.Append("x", nil); err == nil || errors.Is(err, ErrBroken) {
		t.Fatalf("fsync failure: %v", err)
	}
	if err := l.Append("y", nil); !errors.Is(err, ErrBroken) {
		t.Fatalf("after fsync failure: %v", err)
	}
	if err := l.syncTo(1 << 40); !errors.Is(err, ErrBroken) {
		t.Fatalf("syncTo on a broken log: %v", err)
	}
	l.Close()
}

func BenchmarkAppend(b *testing.B) {
	_, l := writeLog(b, 0)
	defer l.Close()
	data := map[string]any{"agent": "alice-bot", "tool": "fs.read_file", "decision": "allow", "rule_id": "fs-read"}
	for b.Loop() {
		if err := l.Append("tool_call", data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAppendParallel(b *testing.B) {
	_, l := writeLog(b, 0)
	defer l.Close()
	data := map[string]any{"agent": "alice-bot", "tool": "fs.read_file", "decision": "allow", "rule_id": "fs-read"}
	b.SetParallelism(16)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := l.Append("tool_call", data); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func FuzzVerify(f *testing.F) {
	path, l := writeLog(f, 3)
	l.Close()
	data, _ := os.ReadFile(path)
	f.Add(data)
	f.Add([]byte("{}\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := Verify(bytes.NewReader(data))
		if err != nil {
			var le *LineError
			if !errors.As(err, &le) || le.Line < 1 {
				t.Fatalf("error without a line: %v", err)
			}
			return
		}
		if res.Size != int64(len(data)) || int(res.Records) != bytes.Count(data, []byte("\n")) {
			t.Fatalf("accepted log with %d records, %d bytes", res.Records, res.Size)
		}
	})
}
