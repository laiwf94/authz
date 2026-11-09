package gateway

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// An admin reload of a broken file fails even when the watcher's own poll
// refused the file first, so the reload finds it unchanged (#238).
func TestAdminReloadAfterWatcherRefused(t *testing.T) {
	g := startFileGateway(t, cookieKey)
	withA := cookie(t, cookieKey, g.secret)
	refusals := strings.Count(g.log.String(), "configuration change refused")
	replaceFile(t, g.config, `{"version": 1, "gateway": {"cookie_keys": {"env": "NOT_SET"}}}`)
	deadline := time.Now().Add(10 * time.Second)
	for strings.Count(g.log.String(), "configuration change refused") == refusals {
		if time.Now().After(deadline) {
			t.Fatalf("the watcher never refused the broken file:\n%s", g.log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	for range 2 { // and again: still refused, not "nothing changed"
		resp, err := http.Post("http://"+g.admin+"/admin/reload", "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("admin reload of a file the watcher refused succeeded")
		}
	}
	if c := g.status("app.example.com", withA); c != 200 {
		t.Fatalf("after the refused reloads: %d", c)
	}
	// Fixed, the file reloads and later reloads succeed again.
	g.write(gatewayDoc{extraHosts: []string{"fixed.example.com"}})
	resp, err := http.Post("http://"+g.admin+"/admin/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin reload of the fixed file: %d", resp.StatusCode)
	}
	if resp, err = http.Post("http://"+g.admin+"/admin/reload", "application/json", nil); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin reload with nothing changed: %d", resp.StatusCode)
	}
}
