//go:build unix

package auditcmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/platform/audit"
)

func queryLines(t *testing.T, out string) []audit.Record {
	t.Helper()
	var recs []audit.Record
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if l == "" {
			continue
		}
		var r audit.Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		recs = append(recs, r)
	}
	return recs
}

// An operator asks a rotated log for an agent's denied tool calls, for
// sign-on denials, and for what happened in a time window.
func TestQuery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	records, _ := writeLog(t, path, 90, audit.Rotation{MaxBytes: 4096})
	segs, _ := audit.Segments(path)
	if len(segs) < 3 {
		t.Fatalf("%d segments", len(segs))
	}

	code, out, errs := run("query", path, "track=agents", "agent=bot", "decision=allow", "tool=t3,t6,t9*")
	if code != OK {
		t.Fatalf("query: %d %q %q", code, out, errs)
	}
	recs := queryLines(t, out)
	if len(recs) != 3 || recs[0].Event != audit.EventToolCall || !strings.Contains(string(recs[2].Data), `"tool":"t9"`) {
		t.Fatalf("tool calls: %s", out)
	}
	if want := "authz audit query: 3 of " + strconv.FormatUint(records, 10) + " records matched; chain checked, head "; !strings.HasPrefix(errs, want) {
		t.Fatalf("summary %q, want %q", errs, want)
	}
	// The lines are the log's own bytes.
	all, _ := os.ReadFile(segs[0])
	if !bytes.Contains(all, []byte(strings.SplitN(out, "\n", 2)[0]+"\n")) {
		t.Fatal("a printed record is not a line of the log")
	}

	code, out, _ = run("query", "-count", path, "track=authn", "decision=deny", "subject=x.*")
	if code != OK || out != "30\n" {
		t.Fatalf("-count: %d %q", code, out)
	}
	code, out, errs = run("query", "-limit", "2", path, "action=view")
	if recs := queryLines(t, out); code != OK || len(recs) != 2 || recs[1].Seq != 5 || !strings.Contains(errs, "stopped at the limit") {
		t.Fatalf("-limit: %d %q %q", code, out, errs)
	}
	// A filter with a space in one argument needs no quotes.
	if code, out, _ := run("query", "-count", path, "data.reason=unknown_app", "actor=no one"); code != OK || out != "0\n" {
		t.Fatalf("spaced value: %d %q", code, out)
	}

	// A time window: the first query writes the time indexes, a later
	// one skips by them, and -full or -read-only do neither.
	_, out, _ = run("query", path)
	every := queryLines(t, out)
	if uint64(len(every)) != records {
		t.Fatalf("query without terms printed %d of %d records", len(every), records)
	}
	from := every[len(every)-10].Time
	code, out, errs = run("query", path, "since="+from)
	if code != OK || len(queryLines(t, out)) < 10 || !strings.Contains(errs, "skipped by the time index") {
		t.Fatalf("since: %d %q %q", code, out, errs)
	}
	code, out2, errs := run("query", "-full", path, "since="+from)
	if code != OK || out2 != out || strings.Contains(errs, "skipped") {
		t.Fatalf("-full: %d %q", code, errs)
	}
	ro := filepath.Join(t.TempDir(), "copy.jsonl")
	writeLog(t, ro, 60, audit.Rotation{MaxBytes: 4096})
	run("query", "-read-only", ro)
	if m, _ := filepath.Glob(ro + ".*.idx"); len(m) != 0 {
		t.Fatalf("-read-only wrote %v", m)
	}
	if m, _ := filepath.Glob(path + ".*.idx"); len(m) != len(segs) {
		t.Fatalf("indexes %v for %d segments", m, len(segs))
	}

	// A broken chain fails after the records read before it.
	ls := bytes.Split(bytes.TrimSuffix(all, []byte("\n")), []byte("\n"))
	ls[2] = bytes.Replace(ls[2], []byte(`"seq":3`), []byte(`"seq":3 `), 1)
	os.WriteFile(segs[0], append(bytes.Join(ls, []byte("\n")), '\n'), 0o600)
	code, out, errs = run("query", path, "track=agents")
	if code != Failed || !strings.HasPrefix(errs, "FAIL "+path+": "+segs[0]+": line 3: record does not match the hash stored in line 4") || len(queryLines(t, out)) != 1 {
		t.Fatalf("broken chain: %d %q %q", code, out, errs)
	}
	os.WriteFile(segs[0], all, 0o600)
	os.Remove(path)
	if code, _, errs := run("query", path); code != Failed || !strings.Contains(errs, "FAIL "+path+": the active segment is missing") {
		t.Fatalf("missing active: %d %q", code, errs)
	}

	for _, c := range []struct {
		args []string
		msg  string
	}{
		{[]string{"query"}, "usage: authz audit query"},
		{[]string{"query", "-limit", "x", path}, "invalid value"},
		{[]string{"query", path, "colour=red"}, "filter: unknown key"},
		{[]string{"query", path, "since=-1h", "until=-2h"}, "until must be later than since"},
		{[]string{"query", filepath.Join(dir, "none.jsonl")}, "no such file"},
	} {
		if code, _, errs := run(c.args...); code != Usage || !strings.Contains(errs, c.msg) {
			t.Errorf("%v: %d %q, want %q", c.args, code, errs, c.msg)
		}
	}
	if code, _, _ := run("query", "-h"); code != OK {
		t.Error("query -h")
	}
}

// Relative times are resolved against the clock queryCmd is given.
func TestQueryRelativeTime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeLog(t, path, 6, audit.Rotation{})
	var out, errb bytes.Buffer
	future := func() time.Time { return time.Now().Add(48 * time.Hour) }
	if code := queryCmd([]string{"-count", path, "since=-24h"}, future, &out, &errb); code != OK || out.String() != "0\n" {
		t.Fatalf("since=-24h two days on: %d %q %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := queryCmd([]string{"-count", path, "since=-72h"}, future, &out, &errb); code != OK || out.String() != "6\n" {
		t.Fatalf("since=-72h: %d %q", code, out.String())
	}
}
