//go:build secretscan

package logging

import (
	"fmt"
	"os"
	"sync"
)

// Built with -tags secretscan, every process scans all the log and audit
// output it writes through this package and internal/platform/audit and
// reports each finding on stderr as a ScanMarker line. CI runs every suite
// this way and scripts/secret-scan.go fails the test that printed one. The
// tag is never used for a release build.
func init() {
	s := NewScanner()
	var mu sync.Mutex
	Watch(func(source string, p []byte) {
		fs := s.Scan(p)
		if len(fs) == 0 {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, f := range fs {
			fmt.Fprintf(os.Stderr, "%s %s %s: %s\n", ScanMarker, source, f.Rule, f.Excerpt)
		}
	})
}
