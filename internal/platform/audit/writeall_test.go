package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type countingFile struct {
	*os.File
	syncs int
}

func (f *countingFile) Sync() error { f.syncs++; return f.File.Sync() }

// WriteAll writes the records in order and waits for one fsync for all of
// them; a record that does not match its schema stops the batch before
// anything is written.
func TestWriteAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := OpenWith(path, Options{Now: fixedNow, Schemas: Default()})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cf := &countingFile{File: l.f.(*os.File)}
	l.f = cf
	env := func(d Decision) Envelope {
		return Envelope{Subject: "doc:readme", Action: "view", Decision: d, CorrelationID: "4bf92f3577b34da6a3ce929d0e0e4736"}
	}
	if err := l.WriteAll([]Envelope{env(Allow), env(Deny), env(Allow)}, []Payload{
		CheckDecided{Principal: "user:alice", Revision: "r", Bulk: 3},
		CheckDecided{Principal: "user:bob", Revision: "r", Bulk: 3},
		CheckDecided{Principal: "user:carol", Revision: "r", Bulk: 3},
	}); err != nil {
		t.Fatal(err)
	}
	if cf.syncs != 1 {
		t.Errorf("%d fsyncs for three records, want 1", cf.syncs)
	}
	raw, _ := os.ReadFile(path)
	f, _ := os.Open(path)
	res, err := VerifyWith(f, Default())
	f.Close()
	if err != nil || res.Records != 3 {
		t.Fatalf("verify: %+v %v", res, err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for i, who := range []string{"alice", "bob", "carol"} {
		if !strings.Contains(lines[i], `"principal":"user:`+who+`"`) {
			t.Errorf("line %d: %s", i+1, lines[i])
		}
	}

	// Refused as a whole: a payload missing a required field, a missing
	// envelope field, a nil payload, mismatched lengths.
	for name, tc := range map[string]struct {
		envs []Envelope
		ps   []Payload
	}{
		"bad payload":  {[]Envelope{env(Allow), env(Allow)}, []Payload{CheckDecided{Principal: "user:a", Revision: "r"}, CheckDecided{Revision: "r"}}},
		"bad envelope": {[]Envelope{env(Allow), {Action: "view"}}, []Payload{CheckDecided{Principal: "user:a", Revision: "r"}, CheckDecided{Principal: "user:b", Revision: "r"}}},
		"nil payload":  {[]Envelope{env(Allow)}, []Payload{nil}},
		"lengths":      {[]Envelope{env(Allow)}, nil},
	} {
		if err := l.WriteAll(tc.envs, tc.ps); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if s, _ := l.Head(); s != 3 {
		t.Errorf("refused batches wrote records: %d", s)
	}
	if err := l.WriteAll(nil, nil); err != nil || cf.syncs != 1 {
		t.Errorf("empty batch: %v, %d fsyncs", err, cf.syncs)
	}

	// A write failure stops the batch.
	l.f = &failingFile{file: cf}
	if err := l.WriteAll([]Envelope{env(Allow)}, []Payload{CheckDecided{Principal: "user:a", Revision: "r"}}); err == nil {
		t.Error("failed write reported success")
	}
}
