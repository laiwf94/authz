package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/bench/datasets"
	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

const key = "authzdata-key-0123456789"

func env(k string) string {
	if k == "AUTHZBENCH_API_KEY" {
		return key
	}
	return ""
}

func runCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, env, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestManifestAndSchema(t *testing.T) {
	code, out, _ := runCmd(t, "manifest", "-size", "100m", "-seed", "3")
	var m datasets.Manifest
	if code != 0 || json.Unmarshal([]byte(out), &m) != nil {
		t.Fatalf("manifest: %d %q", code, out)
	}
	if m.Relationships != 99_999_998 || m.Docs != 23_466_026 || m.Seed != 3 || !strings.Contains(strings.Join(m.BenchFlags, " "), "-resources 23466026") {
		t.Errorf("manifest %+v", m)
	}
	if code, out, _ := runCmd(t, "schema"); code != 0 || out != datasets.Schema {
		t.Errorf("schema: %d", code)
	}
	if code, out, _ := runCmd(t, "schema", "-format", "openfga"); code != 0 || out != datasets.OpenFGAModel {
		t.Errorf("schema openfga: %d", code)
	}
}

func TestGraphUsersTools(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "g.txt")
	if code, _, e := runCmd(t, "graph", "-size", "10k", "-seed", "2", "-o", file); code != 0 {
		t.Fatalf("graph: %d %s", code, e)
	}
	g, _ := datasets.Size(10_000, 2)
	var want bytes.Buffer
	datasets.WriteGraph(&want, g, datasets.FormatTuples, 0, g.Count())
	if got, _ := os.ReadFile(file); !bytes.Equal(got, want.Bytes()) {
		t.Error("graph -o differs from WriteGraph")
	}
	code, out, _ := runCmd(t, "graph", "-size", "10k", "-seed", "2", "-format", "openfga", "-from", "5", "-to", "8")
	if code != 0 || strings.Count(out, "\n") != 3 || !strings.HasPrefix(out, `{"user":"user:u2"`) {
		t.Errorf("graph range: %d %q", code, out)
	}
	code, out, _ = runCmd(t, "users", "-size", "10k", "-seed", "2", "-n", "3", "-format", "credentials")
	if lines := strings.Split(strings.TrimSpace(out), "\n"); code != 0 || len(lines) != 3 || lines[2] != "u2:"+g.Password(2) {
		t.Errorf("users: %d, %d lines", code, len(lines))
	}
	code, out, _ = runCmd(t, "users", "-size", "10k")
	if code != 0 || strings.Count(out, "\n") != g.Users {
		t.Errorf("all users: %d, %d lines, want %d", code, strings.Count(out, "\n"), g.Users)
	}
	code, out, _ = runCmd(t, "tools", "-n", "7")
	var cat struct{ Tools []datasets.Tool }
	if code != 0 || json.Unmarshal([]byte(out), &cat) != nil || len(cat.Tools) != 7 {
		t.Errorf("tools: %d %q", code, out)
	}
	callsFile := filepath.Join(dir, "calls.json")
	if code, _, _ := runCmd(t, "tools", "-n", "7", "-calls", "20", "-o", callsFile); code != 0 {
		t.Fatalf("calls: %d", code)
	}
	b, _ := os.ReadFile(callsFile)
	var calls []datasets.Call
	if json.Unmarshal(b, &calls) != nil || len(calls) != 20 || calls[0].Name == "" {
		t.Errorf("calls file %s", b)
	}
}

func TestLoad(t *testing.T) {
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{5}, token.KeySize))
	s, err := api.New(api.Config{Store: st, Tokens: tok, APIKeys: []string{key}, Metrics: metrics.New(),
		CacheSize: 100, Quantum: time.Second, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	defer srv.Close()
	code, out, e := runCmd(t, "load", "-size", "5k", "-api", srv.URL, "-schema", "-batch", "300", "-workers", "2")
	g, _ := datasets.Size(5_000, 1)
	if code != 0 || !strings.HasPrefix(out, "loaded 4997 relationships in 17 writes (0 retried)") {
		t.Fatalf("load: %d %q %s (%d relationships)", code, out, e, g.Count())
	}
	// A relationship of the dataset is there.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/check", strings.NewReader(
		`{"resource":"doc:d0","permission":"edit","subject":"user:u`+strings.TrimPrefix(firstOwner(t, g), "user:u")+`","consistency":{"mode":"fully_consistent"}}`))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ans struct{ Allowed bool }
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if json.Unmarshal(b, &ans) != nil || !ans.Allowed {
		t.Errorf("the owner of doc:d0 cannot edit it after the load: %d %s", resp.StatusCode, b)
	}
	// Without the schema the engine refuses the types: exit 1.
	srv2 := httptest.NewServer(mustAPI(t))
	defer srv2.Close()
	if code, _, e := runCmd(t, "load", "-size", "1k", "-api", srv2.URL); code != 1 || !strings.Contains(e, "status 424") {
		t.Errorf("load without a schema: %d %s", code, e)
	}
}

func mustAPI(t *testing.T) http.Handler {
	st, _ := store.Open(store.Options{})
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{6}, token.KeySize))
	s, err := api.New(api.Config{Store: st, Tokens: tok, APIKeys: []string{key}, Metrics: metrics.New(), Quantum: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func firstOwner(t *testing.T, g datasets.Graph) string {
	var owner string
	g.Each(func(r *datasets.Relationship) error {
		if r.ResourceType == datasets.TypeDoc && r.Resource == 0 && r.Relation == "owner" {
			owner = string(datasets.AppendObject(nil, r.SubjectType, r.Subject))
		}
		return nil
	})
	if owner == "" {
		t.Fatal("doc:d0 has no owner")
	}
	return owner
}

func TestBadArguments(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"nope"},
		{"graph", "-size", "lots"},
		{"graph", "-size", "1k", "-format", "csv"},
		{"graph", "-size", "1k", "-from", "5", "-to", "2"},
		{"graph", "-size", "1k", "-to", "100000"},
		{"graph", "extra"},
		{"graph", "-bogus"},
		{"manifest", "-size", "5"},
		{"schema", "-format", "yaml"},
		{"users", "-size", "1k", "-n", "1000000"},
		{"users", "-size", "1k", "-format", "xml"},
		{"tools", "-n", "0"},
		{"tools", "-calls", "-1"},
		{"load", "-size", "1k"},
		{"load", "-size", "1k", "-api", "http://127.0.0.1:1", "-batch", "5000"},
		{"load", "-size", "1"},
	} {
		if code, _, _ := runCmd(t, args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
	if code, out, _ := runCmd(t, "help"); code != 0 || !strings.Contains(out, "usage: authzdata") {
		t.Errorf("help: %d", code)
	}
	if code, _, _ := runCmd(t, "graph", "-h"); code != 0 {
		t.Errorf("graph -h: %d", code)
	}
	if code, _, _ := runCmd(t, "graph", "-size", "1k", "-o", filepath.Join(t.TempDir(), "no", "such", "dir")); code != 1 {
		t.Errorf("unwritable output: %d", code)
	}
	if code, _, _ := runCmd(t, "load", "-size", "1k", "-api", "http://127.0.0.1:1", "-schema"); code != 1 {
		t.Errorf("unreachable API: %d", code)
	}
}
