package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/laiwf94/authz/internal/authz/store"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestLoadConfig(t *testing.T) {
	c, err := loadConfig(env(map[string]string{"GRANTD_API_KEYS": " k1-aaaaaaaaaaaaaaaa , ,k2-bbbbbbbbbbbbbbbb"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.addr != ":8080" || len(c.apiKeys) != 2 || c.cacheSize != 100_000 || c.retention != store.DefaultRetention || c.tokenKey != nil {
		t.Fatalf("defaults wrong: %+v", c)
	}
	c, err = loadConfig(env(map[string]string{"GRANTD_API_KEYS": "k", "GRANTD_ADDR": ":9", "GRANTD_DATA_DIR": "/d",
		"GRANTD_TOKEN_KEY": key, "GRANTD_CACHE_SIZE": "0", "GRANTD_RETENTION": "5", "GRANTD_LOG_LEVEL": "debug"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.addr != ":9" || c.dataDir != "/d" || len(c.tokenKey) != 32 || c.cacheSize != 0 || c.retention != 5 || c.logLevel.String() != "DEBUG" {
		t.Fatalf("overrides wrong: %+v", c)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"GRANTD_API_KEYS is required":       {},
		"GRANTD_TOKEN_KEY must be 64 hex":   {"GRANTD_API_KEYS": "k", "GRANTD_TOKEN_KEY": "abc"},
		"GRANTD_TOKEN_KEY is required with": {"GRANTD_API_KEYS": "k", "GRANTD_DATA_DIR": "/d"},
		"GRANTD_CACHE_SIZE must be":         {"GRANTD_API_KEYS": "k", "GRANTD_CACHE_SIZE": "-1"},
		"GRANTD_RETENTION must be":          {"GRANTD_API_KEYS": "k", "GRANTD_RETENTION": "0"},
		"GRANTD_LOG_LEVEL":                  {"GRANTD_API_KEYS": "k", "GRANTD_LOG_LEVEL": "loud"},
	}
	for want, e := range cases {
		if _, err := loadConfig(env(e)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("env %v: err = %v, want %q", e, err, want)
		}
	}
}

func TestRunServesAndShutsDown(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	addrc := make(chan string, 1)
	done := make(chan error, 1)
	var logs bytes.Buffer
	go func() {
		done <- run(ctx, env(map[string]string{"GRANTD_ADDR": "127.0.0.1:0", "GRANTD_API_KEYS": "integration-key-0123",
			"GRANTD_DATA_DIR": dir, "GRANTD_TOKEN_KEY": key}), &logs, func(a string) { addrc <- a })
	}()
	var addr string
	select {
	case addr = <-addrc:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}
	put := func(path, body string) int {
		req, _ := http.NewRequest("PUT", "http://"+addr+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer integration-key-0123")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := put("/v1/schema", `{"schema":"definition user {}"}`); code != 200 {
		t.Fatalf("schema write: %d", code)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
	if !strings.Contains(logs.String(), `"msg":"shutting down"`) {
		t.Fatalf("logs: %s", logs.String())
	}
	// The schema survived the restart.
	st, err := store.Open(store.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if sc, _ := st.Schema(); sc == nil {
		t.Fatal("data lost across restart")
	}
}

func TestRunErrors(t *testing.T) {
	ctx := context.Background()
	if err := run(ctx, env(map[string]string{}), io.Discard, nil); err == nil {
		t.Fatal("missing API keys accepted")
	}
	if err := run(ctx, env(map[string]string{"GRANTD_API_KEYS": "short"}), io.Discard, nil); err == nil {
		t.Fatal("short API key accepted")
	}
	if err := run(ctx, env(map[string]string{"GRANTD_API_KEYS": "integration-key-0123", "GRANTD_ADDR": "256.0.0.1:1"}), io.Discard, nil); err == nil {
		t.Fatal("bad address accepted")
	}
	file := t.TempDir() + "/f"
	os.WriteFile(file, nil, 0o600)
	if err := run(ctx, env(map[string]string{"GRANTD_API_KEYS": "integration-key-0123", "GRANTD_DATA_DIR": file + "/x", "GRANTD_TOKEN_KEY": key}), io.Discard, nil); err == nil {
		t.Fatal("unusable data dir accepted")
	}
}
