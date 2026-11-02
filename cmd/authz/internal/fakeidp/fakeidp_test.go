package fakeidp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGencertAndServeTLS(t *testing.T) {
	dir := t.TempDir()
	if err := run(context.Background(), []string{"gencert", "-dir", dir, "-hosts", "localhost,127.0.0.1"}, os.Getenv, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ca.pem", "tls.pem", "tls-key.pem", "sp.pem", "sp-key.pem"} {
		if info, err := os.Stat(filepath.Join(dir, f)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v", f, err)
		}
	}
	cfg := map[string]any{
		"issuer":  "https://127.0.0.1",
		"clients": []any{map[string]any{"id": "c", "secret_env": "FAKE_SECRET", "redirect_uris": []string{"https://gw/cb"}}},
		"service_providers": []any{map[string]any{"entity_id": "https://gw/md", "acs_url": "https://gw/acs", "sign_assertion": true,
			"encrypt_cert_file": filepath.Join(dir, "sp.pem"), "request_cert_file": filepath.Join(dir, "sp.pem")}},
	}
	b, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(dir, "fakeidp.json")
	os.WriteFile(cfgPath, b, 0o600)

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	getenv := func(k string) string {
		if k == "FAKE_SECRET" {
			return "pw"
		}
		return ""
	}
	go func() {
		done <- run(ctx, []string{"-config", cfgPath, "-addr", "127.0.0.1:0", "-tls-cert", filepath.Join(dir, "tls.pem"),
			"-tls-key", filepath.Join(dir, "tls-key.pem")}, getenv, io.Discard, func(a string) { ready <- a })
	}()
	addr := <-ready
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := c.Get("https://" + addr + "/saml/metadata")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "IDPSSODescriptor") {
		t.Fatal("metadata over TLS signed by the generated CA")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServePlainAndErrors(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.json")
	os.WriteFile(cfgPath, []byte(`{"issuer":"http://127.0.0.1"}`), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-config", cfgPath, "-addr", "127.0.0.1:0"}, os.Getenv, io.Discard, func(a string) { ready <- a })
	}()
	addr := <-ready
	if resp, err := http.Get("http://" + addr + "/healthz"); err != nil || resp.StatusCode != 200 {
		t.Fatal("health")
	}
	cancel()
	<-done

	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	bad := map[string][]string{
		"no config":      {},
		"bad flag":       {"-nope"},
		"missing file":   {"-config", filepath.Join(dir, "missing.json")},
		"bad json":       {"-config", write("bad.json", "{")},
		"empty secret":   {"-config", write("sec.json", `{"issuer":"http://x","clients":[{"id":"c","secret_env":"NOPE"}]}`)},
		"bad issuer":     {"-config", write("iss.json", `{"issuer":"nope"}`)},
		"missing cert":   {"-config", write("cert.json", `{"issuer":"http://x","service_providers":[{"entity_id":"e","encrypt_cert_file":"/missing"}]}`)},
		"bad cert":       {"-config", write("badcert.json", `{"issuer":"http://x","service_providers":[{"entity_id":"e","request_cert_file":"`+write("x.pem", "x")+`"}]}`)},
		"bad addr":       {"-config", cfgPath, "-addr", "256.0.0.1:0"},
		"gencert no dir": {"gencert"},
		"gencert flag":   {"gencert", "-nope"},
	}
	for name, args := range bad {
		if err := run(context.Background(), args, os.Getenv, io.Discard, nil); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
