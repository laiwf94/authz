package mcpfake

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// Under its old name the fake server prints its usage and errors as the
// mcpfake binary did, with "mcpfake" where "authz mcpfake" is otherwise.
func TestMcpfakeNameMessages(t *testing.T) {
	noEnv := func(string) string { return "" }
	for _, tc := range []struct {
		args       []string
		env        map[string]string
		exit       int
		old, new   string
		prefixOnly bool
	}{
		// What the mcpfake binary at dec2e96 printed and exited with.
		{nil, nil, 1, "mcpfake: MCPFAKE_SANDBOX is required\n", "authz mcpfake: MCPFAKE_SANDBOX is required\n", false},
		{[]string{"extra"}, nil, 2,
			"mcpfake: unexpected argument \"extra\"; configuration comes from the environment\n",
			"authz mcpfake: unexpected argument \"extra\"; configuration comes from the environment\n", false},
		{nil, map[string]string{"MCPFAKE_ADDR": "a", "AUTHZ_MCPFAKE_ADDR": "b"}, 2,
			"mcpfake: AUTHZ_MCPFAKE_ADDR and MCPFAKE_ADDR set to different values; unset one\n",
			"authz mcpfake: AUTHZ_MCPFAKE_ADDR and MCPFAKE_ADDR set to different values; unset one\n", false},
		{[]string{"-h"}, nil, 0, "usage: mcpfake\n\n", "usage: authz mcpfake\n\n", true},
		{[]string{"-bogus"}, nil, 2, "flag provided but not defined: -bogus\nusage: mcpfake\n\n",
			"flag provided but not defined: -bogus\nusage: authz mcpfake\n\n", true},
	} {
		getenv := noEnv
		if tc.env != nil {
			getenv = func(k string) string { return tc.env[k] }
		}
		for _, c := range []struct {
			run  func(context.Context, []string, func(string) string, io.Reader, io.Writer, io.Writer) int
			want string
		}{{Mcpfake, tc.old}, {Run, tc.new}} {
			var errOut bytes.Buffer
			code := c.run(context.Background(), tc.args, getenv, nil, io.Discard, &errOut)
			got := errOut.String()
			if tc.prefixOnly && len(got) > len(c.want) {
				got = got[:len(c.want)]
			}
			if code != tc.exit || got != c.want {
				t.Errorf("%v: got exit %d %q, want exit %d %q", tc.args, code, errOut.String(), tc.exit, c.want)
			}
		}
	}
}
