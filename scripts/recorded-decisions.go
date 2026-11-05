//go:build ignore

// recorded-decisions compares what a gateway decided in a scenario with a
// recording checked in earlier. It turns an audit log into recorded
// decisions (see gateway.RecordDecisions: timestamps, hash links, latencies
// and per-run identifiers are normalised) and diffs them with the recording.
//
//	go run scripts/recorded-decisions.go [-update] RECORDING AUDIT_LOG
//
// It exits 0 when they match, 1 when they differ (printing the first
// difference) and 2 when a file cannot be read. -update writes the recording
// from the audit log instead of comparing. toolgate/examples/demo.sh uses it
// so that the demo scenarios must decide exactly as the recording says.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/laiwf94/authz/internal/agents/gateway"
	"github.com/laiwf94/authz/internal/platform/audit"
)

func main() {
	update := flag.Bool("update", false, "write RECORDING from AUDIT_LOG instead of comparing")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/recorded-decisions.go [-update] RECORDING AUDIT_LOG")
	}
	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}
	recording, logPath := flag.Arg(0), flag.Arg(1)
	f, err := os.Open(logPath)
	if err != nil {
		fail(2, err)
	}
	res, err := audit.Verify(f)
	if err != nil {
		fail(1, fmt.Errorf("%s does not verify: %w", logPath, err))
	}
	if _, err := f.Seek(0, 0); err != nil {
		fail(2, err)
	}
	var got bytes.Buffer
	if err := gateway.RecordDecisions(f, &got); err != nil {
		fail(2, fmt.Errorf("%s: %w", logPath, err))
	}
	f.Close()
	if *update {
		if err := os.WriteFile(recording, got.Bytes(), 0o644); err != nil {
			fail(2, err)
		}
		fmt.Printf("recorded %d decisions in %s\n", res.Records, recording)
		return
	}
	want, err := os.ReadFile(recording)
	if err != nil {
		fail(2, err)
	}
	if d := gateway.DiffDecisions(want, got.Bytes()); d != "" {
		fmt.Printf("FAIL decisions differ from %s\n%s\n", recording, d)
		os.Exit(1)
	}
	fmt.Printf("OK %d decisions match %s\n", res.Records, recording)
}

func fail(code int, err error) {
	fmt.Fprintln(os.Stderr, "recorded-decisions:", err)
	os.Exit(code)
}
