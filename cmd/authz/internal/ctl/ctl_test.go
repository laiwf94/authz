package ctl

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
)

const apiKey = "ctl-test-key-0123456789"

const docsSchema = `definition user {}

definition group {
  relation member: user | group#member
}

definition doc {
  relation owner: user
  relation viewer: user | group#member
  permission view = viewer + owner
}
`

// recorder keeps the paths and bodies the server saw.
type recorder struct {
	mu     sync.Mutex
	bodies []string
}

func (r *recorder) seen() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.bodies, "\n")
}

func newServer(t *testing.T) (*httptest.Server, *recorder) {
	t.Helper()
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key, _ := token.RandomKey()
	tokens, _ := token.NewIssuer(key)
	srv, err := api.New(api.Config{Store: st, Tokens: tokens, APIKeys: []string{apiKey}})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.bodies = append(rec.bodies, r.Method+" "+r.URL.Path+" "+string(b))
		rec.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(b))
		srv.ServeHTTP(w, r)
	}))
	t.Cleanup(hs.Close)
	return hs, rec
}

type result struct {
	code        int
	out, errout string
}

func ctl(t *testing.T, addr, stdin string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	e := map[string]string{"AUTHZ_URL": addr, "AUTHZ_API_KEY": apiKey}
	code := Run(context.Background(), args, func(k string) string { return e[k] }, strings.NewReader(stdin), &out, &errb)
	return result{code, out.String(), errb.String()}
}

func must(t *testing.T, r result, code int) string {
	t.Helper()
	if r.code != code {
		t.Fatalf("exit %d, want %d; stdout %q stderr %q", r.code, code, r.out, r.errout)
	}
	return strings.TrimSpace(r.out)
}

func TestSchemaAndRelationshipsRoundTrip(t *testing.T) {
	hs, rec := newServer(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "docs.schema")
	os.WriteFile(file, []byte(docsSchema), 0o600)

	if tok := must(t, ctl(t, hs.URL, "", "schema", "write", file), OK); tok == "" {
		t.Fatal("schema write printed no token")
	}
	got := must(t, ctl(t, hs.URL, "", "schema", "read"), OK)
	if !strings.Contains(got, "permission view = viewer + owner") {
		t.Fatalf("schema read = %q", got)
	}
	// From stdin, the canonical form back again.
	must(t, ctl(t, hs.URL, got, "schema", "write", "-"), OK)

	written := must(t, ctl(t, hs.URL, "", "rel", "touch", "group:eng#member@user:alice", "doc:plan#viewer@group:eng#member"), OK)
	if !strings.Contains(rec.seen(), `"op":"touch","relationship":"doc:plan#viewer@group:eng#member"`) {
		t.Fatalf("write body: %s", rec.seen())
	}
	// Each check names the token from the write, so it reads its own write.
	if r := must(t, ctl(t, hs.URL, "", "check", "-token", written, "doc:plan", "view", "user:alice"), OK); r != "allowed" {
		t.Fatalf("check = %q", r)
	}
	if r := must(t, ctl(t, hs.URL, "", "check", "-full", "doc:plan", "view", "user:bob"), Denied); r != "denied" {
		t.Fatalf("check = %q", r)
	}
	if !strings.Contains(rec.seen(), `"consistency":{"mode":"at_least_as_fresh","token":"`+written+`"}`) ||
		!strings.Contains(rec.seen(), `"consistency":{"mode":"fully_consistent"}`) {
		t.Fatalf("consistency not sent: %s", rec.seen())
	}

	// Writes from stdin skip blanks and comments.
	var lines []string
	for i := range 7 {
		lines = append(lines, fmt.Sprintf("doc:d%d#owner@user:alice", i))
	}
	stdin := "// owners\n\n" + strings.Join(lines, "\n") + "\n"
	tok := must(t, ctl(t, hs.URL, stdin, "rel", "create", "-"), OK)
	// create of an existing relationship is a conflict reported by the server.
	r := ctl(t, hs.URL, "", "rel", "create", "doc:d0#owner@user:alice")
	if r.code != Failed || !strings.Contains(r.errout, "already_exists") || !strings.Contains(r.errout, "(request ") {
		t.Fatalf("conflict: %+v", r)
	}

	// Paged reads print every relationship once, all at the first page's snapshot.
	got = must(t, ctl(t, hs.URL, "", "rel", "read", "-limit", "2", "-token", tok, "doc#owner@user:alice"), OK)
	if want := strings.Join(lines, "\n"); got != want {
		t.Fatalf("paged read:\n%s\nwant\n%s", got, want)
	}
	if n := strings.Count(rec.seen(), `"mode":"at_exact_snapshot"`); n != 3 {
		t.Fatalf("pages after the first should pin the snapshot; saw %d:\n%s", n, rec.seen())
	}
	got = must(t, ctl(t, hs.URL, "", "rel", "read", "-full", "doc:plan"), OK)
	if got != "doc:plan#viewer@group:eng#member" {
		t.Fatalf("read by resource = %q", got)
	}

	got = must(t, ctl(t, hs.URL, "", "lookup", "-limit", "3", "-full", "doc", "view", "user:alice"), OK)
	if want := "d0\nd1\nd2\nd3\nd4\nd5\nd6\nplan"; got != want {
		t.Fatalf("lookup = %q, want %q", got, want)
	}

	must(t, ctl(t, hs.URL, "", "rel", "delete", "group:eng#member@user:alice"), OK)
	must(t, ctl(t, hs.URL, "", "check", "-full", "doc:plan", "view", "user:alice"), Denied)
	if got := must(t, ctl(t, hs.URL, "", "rel", "read", "-full", "group"), OK); got != "" {
		t.Fatalf("read after delete = %q", got)
	}
}

func TestServerErrors(t *testing.T) {
	hs, _ := newServer(t)
	r := ctl(t, hs.URL, "", "schema", "read")
	if r.code != Failed || !strings.Contains(r.errout, "authz ctl: no_schema:") {
		t.Fatalf("no schema: %+v", r)
	}
	r = ctl(t, hs.URL, "", "check", "doc:x", "view", "user:a")
	if r.code != Failed || !strings.Contains(r.errout, "no_schema") {
		t.Fatalf("check without schema: %+v", r)
	}
	var out, errb bytes.Buffer
	code := Run(context.Background(), []string{"schema", "read"}, func(k string) string {
		return map[string]string{"AUTHZ_URL": hs.URL + "/", "AUTHZ_API_KEY": "wrong-key-0123456789"}[k]
	}, nil, &out, &errb)
	if code != Failed || !strings.Contains(errb.String(), "unauthenticated") {
		t.Fatalf("wrong key: %d %q", code, errb.String())
	}

	// Not every failure is a JSON error body.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/schema":
			http.Error(w, "upstream down", http.StatusBadGateway)
		case "/v1/check":
			io.WriteString(w, "not json")
		default:
			w.Write(bytes.Repeat([]byte{' '}, maxResponse+1))
		}
	}))
	defer plain.Close()
	for args, want := range map[string]string{
		"schema read":             "server answered 502 Bad Gateway",
		"check doc:x view user:a": "decoding the response",
		"rel read doc":            "response is larger than",
	} {
		r := ctl(t, plain.URL, "", strings.Fields(args)...)
		if r.code != Failed || !strings.Contains(r.errout, want) {
			t.Errorf("%s: %+v, want %q", args, r, want)
		}
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	if r := ctl(t, closed.URL, "", "schema", "read"); r.code != Failed || !strings.Contains(r.errout, "connection refused") {
		t.Fatalf("server down: %+v", r)
	}
}

func TestUsageErrors(t *testing.T) {
	hs, rec := newServer(t)
	many := strings.Repeat("doc:a#owner@user:b\n", store.MaxUpdatesPerWrite+1)
	cases := []struct {
		stdin string
		args  []string
		want  string
	}{
		{"", nil, "usage: authz ctl"},
		{"", []string{"nope"}, `unknown command "nope"`},
		{"", []string{"schema"}, "schema needs read or write"},
		{"", []string{"schema", "drop"}, `unknown schema command "drop"`},
		{"", []string{"schema", "read", "x"}, "usage: schema read"},
		{"", []string{"schema", "write"}, "usage: schema write"},
		{"", []string{"rel"}, "rel needs touch"},
		{"", []string{"rel", "move"}, `unknown rel command "move"`},
		{"", []string{"rel", "touch"}, "usage: rel touch"},
		{"// only a comment\n", []string{"rel", "touch", "-"}, "no relationships to touch"},
		{"", []string{"rel", "touch", "doc:a#owner@user:b", "doc:a#owner"}, "argument 2: relationship \"doc:a#owner\" has no '@'"},
		{"doc:a#owner@user:b\nbad\n", []string{"rel", "delete", "-"}, "stdin:2: relationship \"bad\" has no '@'"},
		{many, []string{"rel", "touch", "-"}, "more than the 1000 one atomic write can hold"},
		{"", []string{"rel", "read"}, "usage: rel read"},
		{"", []string{"rel", "read", "@user:a"}, "needs a resource type"},
		{"", []string{"rel", "read", "doc@"}, "empty subject type"},
		{"", []string{"rel", "read", "-exact", "doc"}, "-exact needs -token"},
		{"", []string{"rel", "read", "-limit", "x", "doc"}, "invalid value"},
		{"", []string{"check", "doc:a", "view"}, "usage: check"},
		{"", []string{"check", "-full", "-token", "t", "doc:a", "view", "user:b"}, "-full and -token cannot be combined"},
		{"", []string{"lookup", "doc"}, "usage: lookup"},
		{"", []string{"lookup", "-exact", "doc", "view", "user:a"}, "-exact needs -token"},
		{"", []string{"-timeout", "0", "schema", "read"}, "-timeout must be positive"},
		{"", []string{"-addr", "localhost:8080", "schema", "read"}, "must be an http:// or https:// URL"},
	}
	for _, c := range cases {
		r := ctl(t, hs.URL, c.stdin, c.args...)
		if r.code != Usage || !strings.Contains(r.errout, c.want) {
			t.Errorf("%q: exit %d stderr %q, want 2 and %q", c.args, r.code, r.errout, c.want)
		}
	}
	if s := rec.seen(); s != "" {
		t.Fatalf("usage errors must not reach the server:\n%s", s)
	}

	var errb bytes.Buffer
	if code := Run(context.Background(), []string{"schema", "read"}, func(string) string { return "" }, nil, io.Discard, &errb); code != Usage ||
		!strings.Contains(errb.String(), "set AUTHZ_API_KEY") {
		t.Fatalf("no key: %d %q", code, errb.String())
	}
	for _, args := range [][]string{{"-h"}, {"check", "-h"}, {"rel", "read", "-h"}, {"lookup", "-h"}} {
		if r := ctl(t, hs.URL, "", args...); r.code != OK || !strings.Contains(r.errout, "usage: authz ctl") {
			t.Errorf("%q: %+v", args, r)
		}
	}
	if r := ctl(t, hs.URL, "", "schema", "write", filepath.Join(t.TempDir(), "missing")); r.code != Failed || !strings.Contains(r.errout, "no such file") {
		t.Fatalf("missing schema file: %+v", r)
	}
}

func TestAddrFlagWinsOverEnv(t *testing.T) {
	// The -addr flag wins over AUTHZ_URL, which wins over DefaultAddr.
	hs, rec := newServer(t)
	var errb bytes.Buffer
	e := map[string]string{"AUTHZ_URL": "http://127.0.0.1:1", "AUTHZ_API_KEY": apiKey}
	code := Run(context.Background(), []string{"-addr", hs.URL, "schema", "read"}, func(k string) string { return e[k] }, nil, io.Discard, &errb)
	if code != Failed || !strings.Contains(errb.String(), "no_schema") || !strings.Contains(rec.seen(), "GET /v1/schema") {
		t.Fatalf("-addr over AUTHZ_URL: %d %q", code, errb.String())
	}
	if DefaultAddr != "http://localhost:8080" {
		t.Fatalf("DefaultAddr = %q; grantd listened on :8080", DefaultAddr)
	}
}
