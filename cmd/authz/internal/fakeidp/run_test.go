package fakeidp

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Run maps fakeidp's outcomes to exit codes: 0 for a clean stop or help, 2
// for flags it does not define, 1 for everything that stops it starting.
func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.json")
	if err := os.WriteFile(cfg, []byte(`{"issuer":"http://127.0.0.1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stopped, stop := context.WithCancel(context.Background())
	stop()
	for _, tc := range []struct {
		args []string
		code int
		errb string // a prefix of stderr
	}{
		{[]string{"-h"}, 0, "usage: authz fakeidp -config "},
		{[]string{"gencert", "-h"}, 0, "usage: authz fakeidp -config "},
		{[]string{"-no-such-flag"}, 2, "flag provided but not defined: -no-such-flag\nusage: authz fakeidp "},
		{[]string{"gencert", "-x"}, 2, "flag provided but not defined: -x\nusage: authz fakeidp "},
		{nil, 1, "authz fakeidp: -config is required\n"},
		{[]string{"gencert"}, 1, "authz fakeidp: gencert: -dir is required\n"},
		{[]string{"-config", filepath.Join(dir, "missing.json")}, 1, "authz fakeidp: open "},
		{[]string{"gencert", "-dir", filepath.Join(dir, "certs")}, 0, ""},
		// A stopped context serves nothing and exits cleanly once bound.
		{[]string{"-config", cfg, "-addr", "127.0.0.1:0"}, 0, `{"time":`},
	} {
		var errb bytes.Buffer
		if code := Run(stopped, tc.args, os.Getenv, nil, io.Discard, &errb); code != tc.code || !strings.HasPrefix(errb.String(), tc.errb) {
			t.Errorf("%q: exit %d %q, want %d %q", tc.args, code, errb.String(), tc.code, tc.errb)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "certs", "ca.pem")); err != nil {
		t.Fatal(err)
	}
}
