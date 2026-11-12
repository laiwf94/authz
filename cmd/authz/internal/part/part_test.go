package part

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/laiwf94/authz/internal/platform/httpserver"
	"github.com/laiwf94/authz/internal/platform/keys"
	"github.com/laiwf94/authz/internal/platform/metrics"
)

func TestHostDefaults(t *testing.T) {
	var h Host
	a, b := h.Registry(), h.Registry()
	if a == nil || a == b {
		t.Fatal("a zero Host should give a new registry each time")
	}
	srv, err := h.Binder()(httpserver.Options{}, httpserver.Spec{Name: "x", Addr: "127.0.0.1:0", Handler: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	srv.(*httpserver.Group).Close()

	reg := metrics.New()
	s := httpserver.NewShared(httpserver.Options{}, 1)
	h = Host{Name: "serve", Bind: s.Part(0), Metrics: reg}
	if h.Registry() != reg {
		t.Fatal("Registry should return the shared registry")
	}
	if _, err := h.Binder()(httpserver.Options{}, httpserver.Spec{Name: "x", Addr: "127.0.0.1:0", Handler: http.NotFoundHandler()}); err != nil {
		t.Fatal(err)
	}
	if len(s.Addrs()) != 1 {
		t.Fatal("Binder should join the shared group")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Serve(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestHostKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	var alone Host
	a, err := alone.KeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := alone.KeyFile(path); b == a {
		t.Fatal("a zero Host shares ring files")
	}
	shared := Host{Keys: new(keys.Files)}
	c, err := shared.KeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := (Host{Name: "gateway", Keys: shared.Keys}).KeyFile(path); d != c {
		t.Fatal("parts of one process do not share a ring file")
	}
	if _, err := shared.KeyFile(""); err == nil {
		t.Fatal("empty path accepted")
	}
}
