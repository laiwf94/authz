package ops

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/api"
	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

const benchKey = "bench-key-0123456789"

const schema = `
definition user {}
definition doc {
  relation viewer: user
  permission view = viewer
}`

// newAPI serves the real authorization API in process with doc:dN viewed
// by user:uN for N below 10.
func newAPI(t *testing.T) *API {
	t.Helper()
	st, err := store.Open(store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := token.NewIssuer(bytes.Repeat([]byte{9}, token.KeySize))
	s, err := api.New(api.Config{Store: st, Tokens: tok, APIKeys: []string{benchKey}, Metrics: metrics.New(),
		CacheSize: 1000, Quantum: time.Second, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := NewClient(4, "")
	if err != nil {
		t.Fatal(err)
	}
	a := &API{Client: c, URL: srv.URL, Key: benchKey}
	ctx := context.Background()
	var out map[string]any
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/schema", strings.NewReader(fmt.Sprintf(`{"schema": %q}`, schema)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+benchKey)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAnswer(resp, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	var updates []map[string]string
	for i := range 10 {
		updates = append(updates, map[string]string{"op": "touch", "relationship": fmt.Sprintf("doc:d%d#viewer@user:u%d", i, i)})
	}
	if err := postJSON(ctx, c, srv.URL+"/v1/relationships/write", a.header(), map[string]any{"updates": updates}, &out); err != nil {
		t.Fatal(err)
	}
	return a
}

var keys = Keyspace{ResourceType: "doc", ResourcePrefix: "d", Resources: 10, SubjectType: "user", SubjectPrefix: "u", Subjects: 10}

func rng() *rand.Rand { return rand.New(rand.NewPCG(1, 2)) }

// Every authorization operation succeeds against the real API, many times
// over drawn keys, in each consistency mode.
func TestAPIOperations(t *testing.T) {
	a := newAPI(t)
	ctx := context.Background()
	for _, mode := range []string{"", "fully_consistent"} {
		a.Consistency = mode
		r := rng()
		for _, op := range []interface {
			Name() string
			Do(context.Context, int, *rand.Rand) error
		}{
			&Check{API: a, Keys: keys, Permission: "view"},
			&BulkCheck{API: a, Keys: keys, Permission: "view", Items: 100},
			&Lookup{API: a, Keys: keys, Permission: "view", Limit: 5},
			&Lookup{API: a, Keys: keys, Permission: "view"},
			&Write{API: a, Keys: keys, Relation: "viewer"},
		} {
			for range 20 {
				if err := op.Do(ctx, 0, r); err != nil {
					t.Fatalf("%s (%q): %v", op.Name(), mode, err)
				}
			}
		}
	}
	names := []string{(&Check{}).Name(), (&BulkCheck{}).Name(), (&Lookup{}).Name(), (&Write{}).Name()}
	if strings.Join(names, ",") != "check,bulk_check,lookup,write" {
		t.Fatalf("names %v", names)
	}
}

// A wrong key, a permission the schema does not have and an unknown
// relation all fail with the server's answer in the error.
func TestAPIOperationsReportFailures(t *testing.T) {
	a := newAPI(t)
	ctx := context.Background()
	bad := *a
	bad.Key = "wrong-key-0123456789"
	var se *StatusError
	if err := (&Check{API: &bad, Keys: keys, Permission: "view"}).Do(ctx, 0, rng()); !errors.As(err, &se) || se.Status != 401 ||
		!strings.Contains(err.Error(), "unauthenticated") {
		t.Fatalf("wrong key: %v", err)
	}
	if err := (&Check{API: a, Keys: keys, Permission: "nope"}).Do(ctx, 0, rng()); !errors.As(err, &se) || se.Status != 400 {
		t.Fatalf("unknown permission: %v", err)
	}
	if err := (&BulkCheck{API: a, Keys: keys, Permission: "nope", Items: 3}).Do(ctx, 0, rng()); err == nil ||
		!strings.Contains(err.Error(), "bulk check item 0") {
		t.Fatalf("bulk with unknown permission: %v", err)
	}
	if err := (&Write{API: a, Keys: keys, Relation: "editor"}).Do(ctx, 0, rng()); !errors.As(err, &se) || se.Status != 400 {
		t.Fatalf("unknown relation: %v", err)
	}
	if err := (&Lookup{API: a, Keys: keys, Permission: "nope"}).Do(ctx, 0, rng()); !errors.As(err, &se) || se.Status != 400 {
		t.Fatalf("lookup unknown permission: %v", err)
	}
	down := *a
	down.URL = "http://127.0.0.1:1"
	if err := (&Write{API: &down, Keys: keys, Relation: "viewer"}).Do(ctx, 0, rng()); err == nil {
		t.Fatal("write to a closed port succeeded")
	}
}

// Answers of the right status but the wrong shape are failures too.
func TestAPIOperationsCheckTheAnswer(t *testing.T) {
	answer := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, answer)
	}))
	defer srv.Close()
	a := &API{Client: srv.Client(), URL: srv.URL, Key: "k"}
	ctx := context.Background()
	for _, tc := range []struct {
		op interface {
			Do(context.Context, int, *rand.Rand) error
		}
		answer     string
		wantSubstr string
	}{
		{&Check{API: a, Keys: keys}, `not json`, "not the expected JSON"},
		{&Check{API: a, Keys: keys}, `{}`, "no allowed field"},
		{&BulkCheck{API: a, Keys: keys, Items: 2}, `{"results":[{"allowed":true}]}`, "answered 1 of 2"},
		{&BulkCheck{API: a, Keys: keys, Items: 1}, `{"results":[{}]}`, "no allowed field"},
		{&Lookup{API: a, Keys: keys}, `{}`, "no resource_ids"},
		{&Write{API: a, Keys: keys}, `{}`, "no written_at"},
	} {
		answer = tc.answer
		if err := tc.op.Do(ctx, 0, rng()); err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
			t.Errorf("%T on %s: %v, want %q", tc.op, tc.answer, err, tc.wantSubstr)
		}
	}
	long := strings.Repeat("x", 500)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, long, http.StatusServiceUnavailable)
	}))
	defer srv2.Close()
	a.URL = srv2.URL
	err := (&Check{API: a, Keys: keys}).Do(ctx, 0, rng())
	if err == nil || len(err.Error()) > 220 || !strings.HasPrefix(err.Error(), "status 503: xxx") {
		t.Fatalf("long error body: %v", err)
	}
	if (&StatusError{Status: 418}).Error() != "status 418" {
		t.Fatal("status error without a body")
	}
	ctxDone, cancel := context.WithCancel(ctx)
	cancel()
	if err := (&Check{API: a, Keys: keys}).Do(ctxDone, 0, rng()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	if err := postJSON(ctx, a.Client, a.URL, nil, func() {}, nil); err == nil {
		t.Fatal("marshalled a function")
	}
	if err := postJSON(ctx, a.Client, "::", nil, 1, nil); err == nil {
		t.Fatal("posted to a bad URL")
	}
}

func TestKeyspace(t *testing.T) {
	for _, bad := range []Keyspace{
		{SubjectType: "user", Resources: 1, Subjects: 1},
		{ResourceType: "doc", SubjectType: "user", Resources: 0, Subjects: 1},
		{ResourceType: "doc", SubjectType: "user", Resources: 1, Subjects: 1, Zipf: 0.5},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if err := keys.Validate(); err != nil {
		t.Fatal(err)
	}
	// Uniform draws cover the range evenly; Zipf draws favour the low end
	// at the expected ratio and stay in range.
	r := rng()
	count := func(k Keyspace, n int) []int {
		c := make([]int, n)
		for range 100000 {
			v := k.draw(r, n)
			if v < 0 || v >= n {
				t.Fatalf("draw %d out of [0, %d)", v, n)
			}
			c[v]++
		}
		return c
	}
	u := count(Keyspace{}, 10)
	for i, c := range u {
		if c < 9000 || c > 11000 {
			t.Fatalf("uniform bucket %d has %d of 100000", i, c)
		}
	}
	z := count(Keyspace{Zipf: 2}, 1000)
	// P(0)/P(1) = 2^2 = 4.
	if ratio := float64(z[0]) / float64(z[1]); ratio < 3.6 || ratio > 4.4 {
		t.Fatalf("zipf first/second %v, want about 4", ratio)
	}
	if one := (Keyspace{Zipf: 2}).draw(r, 1); one != 0 {
		t.Fatalf("draw from one: %d", one)
	}
	k := Keyspace{ResourceType: "doc", ResourcePrefix: "d", Resources: 1, SubjectType: "user", Subjects: 1}
	if k.resource(r) != "doc:d0" || k.subject(r) != "user:0" {
		t.Fatalf("names %s %s", k.resource(r), k.subject(r))
	}
}

func TestNewClient(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the refused handshake below
	srv.StartTLS()
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(2, ca)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if tr := c.Transport.(*http.Transport); tr.TLSClientConfig.MinVersion != tls.VersionTLS12 || tr.MaxIdleConnsPerHost != 2 {
		t.Fatal("transport settings")
	}
	plain, _ := NewClient(1, "")
	if _, err := plain.Get(srv.URL); err == nil {
		t.Fatal("trusted the test CA without -cacert")
	}
	if _, err := NewClient(1, filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("missing CA file accepted")
	}
	junk := filepath.Join(dir, "junk.pem")
	os.WriteFile(junk, []byte("not pem"), 0o600)
	if _, err := NewClient(1, junk); err == nil {
		t.Fatal("CA file without certificates accepted")
	}
	// Redirects are answers, not followed.
	redir := httptest.NewServer(http.RedirectHandler("/elsewhere", http.StatusFound))
	defer redir.Close()
	resp, err = plain.Get(redir.URL)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect: %v %v", resp, err)
	}
	resp.Body.Close()
}
