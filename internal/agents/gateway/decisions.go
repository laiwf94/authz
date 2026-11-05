package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/laiwf94/authz/internal/agents/jsonrpc"
	"github.com/laiwf94/authz/internal/platform/audit"
)

// Recorded decisions are an audit log with everything that changes from one
// run of the same scenario to the next taken out, so that two gateways (the
// old toolgate binary and `authz mcp`, say) can be shown to decide the same
// way by comparing files byte for byte.
//
// Each output line is {"seq":N,"event":"…","data":{…}} with the data keys in
// sorted order. The record's time and hash link are dropped; the chain itself
// is checked by audit.Verify, not here. Within data:
//
//   - args_hmac, request_id and approval_id are random or keyed per run. Each
//     distinct value is replaced by "<key>#n", numbered in order of first
//     appearance, so a recording still shows which records share arguments,
//     which records belong to one request and which call used which approval.
//   - latency_ms and expires_at depend on the clock and become "<key>".
//
// Every other field, including decisions, rule ids, reasons, outcomes,
// argument previews, redaction counts and policy and tool hashes, is kept
// exactly.

// numberedFields are replaced by "<name>#n".
var numberedFields = []string{"args_hmac", "request_id", "approval_id"}

// clockFields are replaced by "<name>".
var clockFields = []string{"latency_ms", "expires_at"}

// RecordDecisions reads an audit log and writes its recorded decisions to w.
// It fails on a line that is not a record or on a sequence number that is not
// one more than the previous one.
func RecordDecisions(log io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(log)
	sc.Buffer(make([]byte, 0, 64<<10), audit.MaxLineBytes)
	seen := map[string]map[string]int{}
	for _, f := range numberedFields {
		seen[f] = map[string]int{}
	}
	var want uint64 = 1
	out := bufio.NewWriter(w)
	for line := 1; sc.Scan(); line++ {
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			return fmt.Errorf("line %d: empty line", line)
		}
		var rec audit.Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("line %d: %v", line, err)
		}
		if rec.Seq != want {
			return fmt.Errorf("line %d: seq is %d, want %d", line, rec.Seq, want)
		}
		if rec.Event == "" {
			return fmt.Errorf("line %d: no event", line)
		}
		want++
		var data map[string]any
		if len(rec.Data) > 0 && string(rec.Data) != "null" {
			v, err := jsonrpc.DecodeValue(rec.Data)
			if err != nil {
				return fmt.Errorf("line %d: data: %v", line, err)
			}
			m, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("line %d: data is not an object", line)
			}
			data = m
		}
		for _, f := range numberedFields {
			v, ok := data[f]
			if !ok {
				continue
			}
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("line %d: %s is not a string", line, f)
			}
			n, ok := seen[f][s]
			if !ok {
				n = len(seen[f]) + 1
				seen[f][s] = n
			}
			data[f] = "<" + f + ">#" + strconv.Itoa(n)
		}
		for _, f := range clockFields {
			if _, ok := data[f]; ok {
				data[f] = "<" + f + ">"
			}
		}
		b, err := jsonrpc.Marshal(struct {
			Seq   uint64         `json:"seq"`
			Event string         `json:"event"`
			Data  map[string]any `json:"data"`
		}{rec.Seq, rec.Event, data})
		if err != nil {
			return fmt.Errorf("line %d: %v", line, err)
		}
		out.Write(b)
		out.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("a line is longer than %d bytes", audit.MaxLineBytes)
		}
		return err
	}
	return out.Flush()
}

// DiffDecisions compares two recordings line by line and describes the
// first difference, or returns "" when they are equal.
func DiffDecisions(want, got []byte) string {
	wl := splitLines(want)
	gl := splitLines(got)
	for i := 0; i < len(wl) || i < len(gl); i++ {
		switch {
		case i >= len(wl):
			return fmt.Sprintf("line %d: extra record %s (%d recorded, %d now)", i+1, gl[i], len(wl), len(gl))
		case i >= len(gl):
			return fmt.Sprintf("line %d: missing record %s (%d recorded, %d now)", i+1, wl[i], len(wl), len(gl))
		case !bytes.Equal(wl[i], gl[i]):
			return fmt.Sprintf("line %d differs:\n  recorded: %s\n  now:      %s", i+1, wl[i], gl[i])
		}
	}
	return ""
}

func splitLines(b []byte) [][]byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	if len(b) == 0 {
		return nil
	}
	return bytes.Split(b, []byte("\n"))
}
