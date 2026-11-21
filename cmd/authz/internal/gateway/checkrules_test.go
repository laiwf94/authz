package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/cmd/authz/internal/part"
)

// TestCheckRulesNeedEngine: a gateway whose path rules ask the engine,
// started where no engine can be, says so at start; under authz run with
// a serve part it does not.
func TestCheckRulesNeedEngine(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]any{
		"public_url": "https://auth.example.com",
		"providers": []any{map[string]any{"id": "corp", "type": "oidc", "issuer": "https://idp.example.com",
			"client_id": "c", "client_secret_env": "CORP_SECRET"}},
		"apps": []any{
			map[string]any{"id": "plain", "hosts": []string{"plain.example.com"}, "providers": []string{"corp"},
				"allow": map[string]any{"any_user": true}},
			map[string]any{"id": "wiki", "hosts": []string{"wiki.example.com"}, "providers": []string{"corp"},
				"allow": map[string]any{"any_user": true},
				"paths": []any{map[string]any{"path": "/pages/{id}",
					"check": map[string]any{"resource": "page:{path.id}", "permission": "view"}}}},
		},
	}
	b, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "wicket.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	e := map[string]string{"WICKET_CONFIG": path, "WICKET_COOKIE_KEYS": cookieKey, "CORP_SECRET": "s",
		"WICKET_ADDR": "127.0.0.1:0", "WICKET_ADMIN_ADDR": "127.0.0.1:0"}
	const warning = "path rules with a check need the authorization engine in this process"

	start := func(h part.Host) string {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		logs := &syncBuf{}
		done := make(chan error, 1)
		go func() { done <- Part(ctx, h, env(e), "", logs, make(chan os.Signal)) }()
		waitFor(t, func() bool { return strings.Contains(logs.String(), `"event":"config_loaded"`) })
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("%v\n%s", err, logs.String())
		}
		return logs.String()
	}
	alone := start(part.Host{})
	if strings.Count(alone, warning) != 1 || !strings.Contains(alone, `"app":"wiki"`) {
		t.Fatalf("alone: want one warning naming wiki:\n%s", alone)
	}
	if withServe := start(part.Host{Engines: part.NewEngines()}); strings.Contains(withServe, warning) {
		t.Fatalf("with a serve part:\n%s", withServe)
	}
}
