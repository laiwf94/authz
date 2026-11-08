//go:build secretscan

package logging

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// In the secretscan build every record is scanned and each finding is
// written to stderr as a ScanMarker line, without the secret.
func TestSecretScanBuildReports(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = w
	NewLogger(&bytes.Buffer{}, Options{}).Info("m", "header", "Bearer abcdef0123456789", "password", "redacted-anyway")
	Observe(SourceAudit, []byte(`{"data":{"url":"https://u:p4ssw0rd@h"}}`))
	Observe(SourceAudit, []byte(`{"data":{"clean":true}}`))
	os.Stderr = stderr
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	want := ScanMarker + " log auth_header: abcd…[16 bytes]\n" + ScanMarker + " audit url_password: [8 bytes]\n"
	if string(out) != want {
		t.Errorf("stderr %q\nwant %q", out, want)
	}
	if strings.Contains(string(out), "0123456789") || strings.Contains(string(out), "redacted-anyway") {
		t.Error("a report carries the secret")
	}
}
