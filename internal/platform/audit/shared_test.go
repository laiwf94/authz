//go:build unix

package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Two writers on one file, as authz serve and authz mcp pointed at the same
// path: each append follows the other's records, so the file is one chain
// and each writer's head moves past what the other wrote.
func TestSharedWritersInterleave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenWith(path, Options{Now: fixedNow, Schemas: Default()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenWith(path, Options{Now: fixedNow, Schemas: Default()})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for i := range 3 {
		if err := a.Write(Envelope{Actor: "api_key:0a1b2c3d", Action: "schema.write"},
			SchemaWritten{Revision: "r" + strconv.Itoa(i), SHA256: "x", Bytes: i}); err != nil {
			t.Fatal(err)
		}
		if err := b.Append("tool_call", map[string]any{"agent": "bot", "auth": "key", "decision": "allow", "stage": "policy"}); err != nil {
			t.Fatal(err)
		}
	}
	// Head reads the other writer's records first: both report the file's.
	sa, ha := a.Head()
	sb, hb := b.Head()
	if sa != 6 || sb != 6 || ha != hb {
		t.Fatalf("heads %d %s and %d %s, want the file's", sa, ha, sb, hb)
	}
	f, _ := os.Open(path)
	res, err := VerifyWith(f, Default())
	f.Close()
	if err != nil || res.Records != 6 || res.Head != hb {
		t.Fatalf("verify: %+v %v", res, err)
	}
	// And a appends after b's last record.
	if err := a.Append("tool_call", map[string]any{"agent": "bot", "auth": "key", "decision": "deny", "stage": "policy"}); err != nil {
		t.Fatal(err)
	}
	// Reopened, the file is one log of six records.
	c, err := Open(path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	_, ha = a.Head()
	if s, h := c.Head(); s != 7 || h != ha {
		t.Fatalf("reopened head %d %s", s, h)
	}
	c.Close()
}

// Many goroutines on several writers in one process: every append lands
// once, in one chain.
func TestSharedWritersConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	const writers, each = 3, 200
	logs := make([]*Log, writers)
	for i := range logs {
		l, err := Open(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		logs[i] = l
	}
	var wg sync.WaitGroup
	for w, l := range logs {
		for g := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range each / 4 {
					if err := l.Append("tool_call", map[string]any{"w": w, "g": g, "i": i}); err != nil {
						t.Error(err)
						return
					}
				}
			}()
		}
	}
	wg.Wait()
	checkShared(t, path, writers*each)
}

// checkShared verifies the file and requires n records with no record
// written twice.
func checkShared(t *testing.T, path string, n int) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify(strings.NewReader(string(raw)))
	if err != nil || res.Records != uint64(n) {
		t.Fatalf("verify: %+v %v, want %d records", res, err, n)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if seen[string(r.Data)] {
			t.Fatalf("record %s written twice", r.Data)
		}
		seen[string(r.Data)] = true
	}
}

// Separate processes appending at once, the deployment the lock is for.
// The helper below is the child: it appends sharedEach records to the file
// in AUDIT_SHARED_PATH.
func TestSharedWriterProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	const procs = 4
	cmds := make([]*exec.Cmd, procs)
	outs := make([]bytes.Buffer, procs)
	for i := range cmds {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSharedWriterChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), "AUDIT_SHARED_PATH="+path, "AUDIT_SHARED_ID="+strconv.Itoa(i))
		cmd.Stdout, cmd.Stderr = &outs[i], &outs[i]
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds[i] = cmd
	}
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("writer %d: %v\n%s", i, err, outs[i].String())
		}
	}
	checkShared(t, path, procs*sharedEach)
}

const sharedEach = 150

func TestSharedWriterChild(t *testing.T) {
	path := os.Getenv("AUDIT_SHARED_PATH")
	if path == "" {
		t.Skip("run by TestSharedWriterProcesses")
	}
	l, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	id := os.Getenv("AUDIT_SHARED_ID")
	var wg sync.WaitGroup
	for g := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range sharedEach / 3 {
				if err := l.Append("tool_call", map[string]any{"p": id, "g": g, "i": i}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// A torn final line another writer left (it died mid-write; the flock it
// held died with it) is cut off by the next append, as Open would.
func TestSharedTornLineFromAnotherWriter(t *testing.T) {
	path, a := writeLog(t, 2)
	defer a.Close()
	b, err := Open(path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Append("tool_call", map[string]any{"from": "b"}); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"seq":4,"time":"x","prev":"`)
	f.Close()
	if err := a.Append("tool_call", map[string]any{"from": "a"}); err != nil {
		t.Fatal(err)
	}
	if res, err := verifyFile(t, path); err != nil || res.Records != 4 {
		t.Fatalf("verify: %+v %v", res, err)
	}
	// b reads a's record in turn.
	if err := b.Append("tool_call", map[string]any{"from": "b", "n": 2}); err != nil {
		t.Fatal(err)
	}
	if res, err := verifyFile(t, path); err != nil || res.Records != 5 {
		t.Fatalf("verify: %+v %v", res, err)
	}
}

// Records that do not continue the chain, or a file that shrank, stop the
// writer that finds them: it cannot know where its record would belong.
func TestSharedDamageStopsTheWriter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		damage func(path string)
	}{
		{"forged record", func(path string) {
			f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			fmt.Fprintf(f, `{"seq":3,"time":"x","prev":"%s","event":"tool_call","data":{}}`+"\n", Genesis)
			f.Close()
		}},
		{"not a record", func(path string) {
			f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			f.WriteString("garbage\n")
			f.Close()
		}},
		{"shrank", func(path string) {
			raw, _ := os.ReadFile(path)
			os.WriteFile(path, raw[:strings.IndexByte(string(raw), '\n')+1], 0o600)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, l := writeLog(t, 2)
			defer l.Close()
			tc.damage(path)
			// Head finds the damage too, and keeps the last good head.
			if seq, _ := l.Head(); seq != 2 || l.Healthy() {
				t.Fatalf("head after damage: %d, healthy %v", seq, l.Healthy())
			}
			if err := l.Append("tool_call", map[string]any{}); !errors.Is(err, ErrBroken) || l.Healthy() {
				t.Fatalf("append after damage: %v, healthy %v", err, l.Healthy())
			}
			if err := l.Append("tool_call", map[string]any{}); !errors.Is(err, ErrBroken) {
				t.Fatalf("second append: %v", err)
			}
		})
	}
}

// Open waits for the lock, so it never cuts off a line a live writer is
// still writing.
func TestSharedOpenWaitsForTheLock(t *testing.T) {
	path, l := writeLog(t, 1)
	defer l.Close()
	seq, head := l.Head()
	holder, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := lockFile(holder); err != nil {
		t.Fatal(err)
	}
	// Half a record, as a writer mid-write leaves it.
	holder.Seek(0, 2)
	holder.WriteString(`{"seq":2,`)
	opened := make(chan *Log, 1)
	go func() {
		o, err := Open(path, fixedNow)
		if err != nil {
			t.Error(err)
		}
		opened <- o
	}()
	select {
	case <-opened:
		t.Fatal("Open did not wait for the writer's lock")
	case <-time.After(100 * time.Millisecond):
	}
	// The writer finishes its line and lets go.
	rest, _ := marshal(record{Seq: seq + 1, Time: "t", Prev: head, Event: "tool_call", Data: map[string]any{}})
	holder.WriteString(strings.TrimPrefix(string(rest), `{"seq":2,`) + "\n")
	unlockFile(holder)
	o := <-opened
	if o == nil {
		return
	}
	defer o.Close()
	if s, _ := o.Head(); s != 2 {
		t.Fatalf("opened at %d records, want 2: the writer's line was cut", s)
	}
}

// A writer that cannot cut off a torn line another left, or cannot move to
// the end of the others' records, stops.
func TestSharedCatchUpFailures(t *testing.T) {
	for _, mode := range []string{"truncate", "seek"} {
		t.Run(mode, func(t *testing.T) {
			path, a := writeLog(t, 1)
			defer a.Close()
			b, err := Open(path, fixedNow)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			if err := b.Append("tool_call", map[string]any{"from": "b"}); err != nil {
				t.Fatal(err)
			}
			if mode == "truncate" {
				f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				f.WriteString(`{"seq":3,`)
				f.Close()
			}
			a.f = &faultyFile{File: a.f.(*os.File), failTruncate: mode == "truncate", failSeek: mode == "seek"}
			if err := a.Append("tool_call", map[string]any{"from": "a"}); !errors.Is(err, ErrBroken) || a.Healthy() {
				t.Fatalf("append: %v, healthy %v", err, a.Healthy())
			}
		})
	}
}
