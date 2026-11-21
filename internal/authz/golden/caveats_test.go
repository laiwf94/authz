package golden

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var updateCaveatsDemo = flag.Bool("update-caveats-demo", false, "rewrite testdata/caveats-demo.golden from the demo's output")

// TestCaveatsDemo builds the authz command, starts `authz serve` and runs
// examples/caveats/demo.sh against it, as the README tells an operator to:
// IP-restricted edit access through a caveat, a time-limited viewer link
// through expires_at, and conditional answers from checks, both lookups and
// reads. The output must match testdata/caveats-demo.golden, recorded from
// authz (grantd had no caveats, so there is no grantd recording to hold it
// to). It needs bash, curl and python3, as the script does. The server runs
// once in memory and once on a data directory, which it is then restarted
// on: the caveat and the expired link must read back the same way.
func TestCaveatsDemo(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the authz binary and waits for an expiry")
	}
	for _, tool := range []string{"bash", "curl", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("examples/caveats/demo.sh needs %s: %v", tool, err)
		}
	}
	bin := filepath.Join(t.TempDir(), "authz")
	build := exec.Command("go", "build", "-o", bin, "github.com/laiwf94/authz/cmd/authz")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	golden := filepath.Join("testdata", "caveats-demo.golden")
	start := Exec(bin, "serve")

	for _, dataDir := range []string{"", t.TempDir()} {
		srv, err := start(Env("127.0.0.1:0", dataDir))
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", filepath.Join("..", "..", "..", "examples", "caveats", "demo.sh"))
		cmd.Env = append(os.Environ(), "GRANTD_URL="+srv.URL, "GRANTD_API_KEY="+APIKey)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		runErr := cmd.Run()
		log, stopErr := srv.Stop()
		if runErr != nil {
			t.Fatalf("examples/caveats/demo.sh (data directory %q): %v\n%s%s\nserver log:\n%s", dataDir, runErr, out.Bytes(), stderr.Bytes(), log)
		}
		if stopErr != nil {
			t.Fatal(stopErr)
		}
		if *updateCaveatsDemo && dataDir == "" {
			if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if d := Diff(want, out.Bytes()); d != "" {
			t.Fatalf("examples/caveats/demo.sh (data directory %q) differs from %s at %s\n%s", dataDir, golden, d, out.Bytes())
		}
		if dataDir != "" {
			restartedReads(t, start, dataDir)
		}
	}
}

// restartedReads restarts the server on the demo's data directory and reads
// doc:design back: the editor's caveat and stored context survive recovery,
// and bob's link, which ran out before the last write, is gone.
func restartedReads(t *testing.T, start StartFunc, dataDir string) {
	t.Helper()
	srv, err := start(Env("127.0.0.1:0", dataDir))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	body := `{"filter":{"resource_type":"doc","resource_id":"design"},"consistency":{"mode":"fully_consistent"}}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/relationships/read", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		Relationships []string                   `json:"relationships"`
		Caveats       map[string]json.RawMessage `json:"caveats"`
		ExpiresAt     map[string]string          `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("read after restart: status %d, %v", resp.StatusCode, err)
	}
	const editor = "doc:design#editor@group:eng#member"
	if strings.Join(got.Relationships, " ") != editor+" doc:design#parent@folder:root" {
		t.Errorf("relationships after restart: %q", got.Relationships)
	}
	if c := string(got.Caveats[editor]); c != `{"name":"ip_allowed","context":{"allowed":"10.0.0.0/8"}}` || len(got.Caveats) != 1 {
		t.Errorf("caveats after restart: %v", got.Caveats)
	}
	if got.ExpiresAt != nil {
		t.Errorf("expiries after restart: %v", got.ExpiresAt)
	}
}
