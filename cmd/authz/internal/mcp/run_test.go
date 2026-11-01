package mcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompatEnv(t *testing.T) {
	src := map[string]string{
		"TOOLGATE_ADDR":       "127.0.0.1:1",
		"AUTHZ_MCP_CONFIG":    "/new/config.json",
		"TOOLGATE_POLICY":     "/same.json",
		"AUTHZ_MCP_POLICY":    "/same.json",
		"UP_TOKEN":            "secret",
		"TOOLGATE_UNRELATED":  "kept",
		"AUTHZ_MCP_UNRELATED": "ignored",
	}
	env, err := compatEnv(func(k string) string { return src[k] }, gatewayEnv)
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"TOOLGATE_ADDR":       "127.0.0.1:1",      // old name only
		"AUTHZ_MCP_ADDR":      "127.0.0.1:1",      // either spelling reads it
		"TOOLGATE_CONFIG":     "/new/config.json", // new name answers the old lookup
		"TOOLGATE_POLICY":     "/same.json",       // both, equal
		"TOOLGATE_AUDIT_LOG":  "",                 // neither
		"UP_TOKEN":            "secret",           // credential_env passes through
		"TOOLGATE_UNRELATED":  "kept",             // unknown names pass through
		"AUTHZ_MCP_UNRELATED": "ignored",          // and are not aliased
		"MCPFAKE_ADDR":        "",
	} {
		if got := env(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	src["AUTHZ_MCP_ADDR"] = "127.0.0.1:2"
	src["AUTHZ_MCP_AUDIT_KEY"] = "aa"
	src["TOOLGATE_AUDIT_KEY"] = "bb"
	_, err = compatEnv(func(k string) string { return src[k] }, gatewayEnv)
	if err == nil {
		t.Fatal("conflicting values were accepted")
	}
	for _, want := range []string{"AUTHZ_MCP_ADDR and TOOLGATE_ADDR", "AUTHZ_MCP_AUDIT_KEY and TOOLGATE_AUDIT_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
	if strings.Contains(err.Error(), "aa") || strings.Contains(err.Error(), "bb") {
		t.Errorf("error %q leaks a value", err)
	}
}

func TestAliasHint(t *testing.T) {
	if got := aliasHint("TOOLGATE_ADMIN_TOKEN"); got != " (or AUTHZ_MCP_ADMIN_TOKEN)" {
		t.Fatalf("hint = %q", got)
	}
	if got := aliasHint("UP_TOKEN"); got != "" {
		t.Fatalf("hint for a credential variable = %q", got)
	}
}

func TestRunHelpAndUsage(t *testing.T) {
	for _, h := range []string{"-h", "-help", "--help", "help"} {
		var out, errb bytes.Buffer
		if code := Run(context.Background(), []string{h}, func(string) string { return "" }, nil, &out, &errb); code != 0 {
			t.Fatalf("%s: exit %d", h, code)
		}
		if !strings.HasPrefix(errb.String(), "usage: authz mcp") || out.Len() != 0 {
			t.Fatalf("%s: help on stderr %q, stdout %q", h, errb.String(), out.String())
		}
		for _, name := range gatewayEnv {
			if !strings.Contains(errb.String(), legacyPrefix+name) || !strings.Contains(errb.String(), newPrefix+name) {
				t.Errorf("help does not document %s under both names", name)
			}
		}
	}
	var errb bytes.Buffer
	if code := Run(context.Background(), []string{"-sub", "x"}, func(string) string { return "" }, nil, io.Discard, &errb); code != 2 || !strings.Contains(errb.String(), "flag -sub") {
		t.Fatalf("leading flag: exit %d, %q", code, errb.String())
	}
	// The required-variable error names both spellings.
	errb.Reset()
	if code := Run(context.Background(), nil, func(string) string { return "" }, nil, io.Discard, &errb); code != 1 ||
		!strings.Contains(errb.String(), "authz mcp: TOOLGATE_ADMIN_TOKEN is required (or AUTHZ_MCP_ADMIN_TOKEN)") {
		t.Fatalf("missing admin token: exit %d, %q", code, errb.String())
	}
}

func TestRunRejectsConflictingEnv(t *testing.T) {
	s := newSetup(t)
	s.env["AUTHZ_MCP_POLICY"] = filepath.Join(s.dir, "other.json")
	var errb bytes.Buffer
	if code := Run(context.Background(), nil, s.getenv, nil, io.Discard, &errb); code != 2 ||
		!strings.Contains(errb.String(), "AUTHZ_MCP_POLICY and TOOLGATE_POLICY set to different values") {
		t.Fatalf("exit %d, %q", code, errb.String())
	}
}

// A deployment that has moved every variable to the AUTHZ_MCP_ names starts
// the same gateway and passes the same commands.
func TestRunWithNewNames(t *testing.T) {
	s := newSetup(t)
	renamed := map[string]string{}
	for k, v := range s.env {
		if rest, ok := strings.CutPrefix(k, legacyPrefix); ok {
			k = newPrefix + rest
		}
		renamed[k] = v
	}
	renamed["AUTHZ_MCP_LOG_LEVEL"] = "info" // the "listening" line carries the address
	getenv := func(k string) string { return renamed[k] }

	var tok bytes.Buffer
	if code := Run(context.Background(), []string{"token", "mint", "-sub", "ci-bot", "-scope", "files:read"}, getenv, nil, &tok, io.Discard); code != 0 {
		t.Fatal("token mint with AUTHZ_MCP_ names failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- Run(ctx, []string{"serve"}, getenv, nil, logs, logs) }()
	gw := waitForLog(t, logs, done)
	resp, err := http.Get("http://" + gw + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %d", resp.StatusCode)
	}
	res := mcpCall(t, "http://"+gw, strings.TrimSpace(tok.String()), "tools/call", map[string]any{"name": "fake.read_file", "arguments": map[string]any{"path": "notes/a.txt"}})
	if !strings.Contains(fmt.Sprint(res["result"]), "hello") {
		t.Fatalf("call with a minted token: %v", res)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, logs.String())
	}
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"audit", "verify", renamed["AUTHZ_MCP_AUDIT_LOG"]}, getenv, nil, &out, io.Discard); code != 0 || !strings.HasPrefix(out.String(), "OK ") {
		t.Fatalf("audit verify: exit %d, %q", code, out.String())
	}
}

// waitForLog waits for the gateway's "listening" line and returns its agent address.
func waitForLog(t *testing.T, logs *syncBuffer, done chan int) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case code := <-done:
			t.Fatalf("exited %d before listening: %s", code, logs.String())
		default:
		}
		for _, line := range strings.Split(logs.String(), "\n") {
			if !strings.Contains(line, `"msg":"listening"`) {
				continue
			}
			_, rest, _ := strings.Cut(line, `"addr":"`)
			addr, _, _ := strings.Cut(rest, `"`)
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("gateway did not start: %s", logs.String())
	return ""
}
