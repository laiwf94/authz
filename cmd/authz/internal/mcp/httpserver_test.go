package mcp

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	pcfg "github.com/laiwf94/authz/internal/platform/config"
	"github.com/laiwf94/authz/internal/platform/httpserver/httpservertest"
)

// TestRunTLSAndDrain: both listeners serve TLS, and on shutdown the admin
// /readyz turns 503 for the drain delay while the agent listener answers.
func TestRunTLSAndDrain(t *testing.T) {
	s := newSetup(t)
	tf := httpservertest.Write(t)
	s.env["TOOLGATE_TLS_CERT"] = tf.CertFile
	s.env["TOOLGATE_TLS_KEY"] = tf.KeyFile
	s.env["TOOLGATE_DRAIN_DELAY"] = "1s"
	r := s.start(t)
	gw := strings.Replace(r.gw, "http://", "https://", 1)
	admin := strings.Replace(r.admin, "http://", "https://", 1)
	get := func(u string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := tf.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	if code, _ := get(gw + "/healthz"); code != 200 {
		t.Fatalf("agent listener over TLS: %d", code)
	}
	if code, body := get(admin + "/readyz"); code != 200 || body != `{"status":"ready"}`+"\n" {
		t.Fatalf("admin readyz: %d %q", code, body)
	}
	if code, _ := get(admin + "/admin/audit/head"); code != 200 {
		t.Fatalf("admin API over TLS: %d", code)
	}
	if resp, err := http.Get(r.admin + "/readyz"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("plain HTTP answered on a TLS listener")
		}
	}
	start := time.Now()
	r.cancel()
	draining := false
	for !draining && time.Since(start) < 800*time.Millisecond {
		code, _ := get(admin + "/readyz")
		draining = code == 503
	}
	if !draining {
		t.Fatal("admin readyz did not turn 503")
	}
	if code, _ := get(gw + "/healthz"); code != 200 {
		t.Errorf("agent listener during the drain delay: %d", code)
	}
	select {
	case code := <-r.done:
		if code != 0 {
			t.Fatalf("exit %d: %s", code, r.logs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("gateway did not stop")
	}
	if d := time.Since(start); d < time.Second {
		t.Errorf("stopped after %s, inside the 1s drain delay", d)
	}
}

func TestLoadConfigHTTP(t *testing.T) {
	s := newSetup(t)
	c, err := loadConfig(s.getenv)
	if err != nil || c.http.TLS != nil || c.http.DrainTimeout != 20*time.Second {
		t.Fatalf("defaults: %+v %v", c.http, err)
	}
	// The AUTHZ_MCP_ names stand in for the TOOLGATE_ ones.
	s.env["AUTHZ_MCP_DRAIN_TIMEOUT"] = "3s"
	s.env["AUTHZ_MCP_DRAIN_DELAY"] = "1s"
	getenv, err := compatEnv(s.getenv, gatewayEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c, err = loadConfig(getenv); err != nil || c.http.DrainTimeout != 3*time.Second || c.http.DrainDelay != time.Second {
		t.Fatalf("AUTHZ_MCP_DRAIN_*: %+v %v", c.http, err)
	}
	s.env["TOOLGATE_TLS_KEY"] = "k.pem"
	if _, err := loadConfig(s.getenv); err == nil || !strings.Contains(err.Error(), "TOOLGATE_TLS_CERT and TOOLGATE_TLS_KEY") {
		t.Fatalf("key alone: %v", err)
	}
}

func TestSectionTLS(t *testing.T) {
	tf := httpservertest.Write(t)
	r := mcpSchema(t, upstreamEnv).Check(goodSection(t, map[string]any{"tls_cert": tf.CertFile, "tls_key": tf.KeyFile,
		"drain_delay": "5s", "drain_timeout": "1m"}), goodEnviron)
	if len(r.Problems) != 0 {
		t.Fatalf("problems: %v", r.Problems)
	}
	s := pcfg.Get[Settings](r.Config, SectionName)
	if s.TLSCert != tf.CertFile || time.Duration(s.DrainTimeout) != time.Minute || time.Duration(s.DrainDelay) != 5*time.Second {
		t.Fatalf("settings %+v", s)
	}
	r = mcpSchema(t, upstreamEnv).Check(goodSection(t, nil), goodEnviron)
	if s := pcfg.Get[Settings](r.Config, SectionName); time.Duration(s.DrainTimeout) != 20*time.Second || s.DrainDelay != 0 {
		t.Fatalf("drain defaults %+v", s)
	}
}
