package golden

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAuthzBinary builds the authz command and plays the scenario through
// `authz serve` as a separate process, the way scripts/serve-golden.go runs
// grantd: the transcript must be grantd's recording, byte for byte.
func TestAuthzBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the authz binary")
	}
	bin := filepath.Join(t.TempDir(), "authz")
	build := exec.Command("go", "build", "-o", bin, "github.com/laiwf94/authz/cmd/authz")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "serve.golden"))
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	got, err := Run(Exec(bin, "serve"), t.TempDir(), Options{AfterFresh: func(dir string) error {
		ents, err := os.ReadDir(dir)
		for _, e := range ents {
			kept = append(kept, e.Name())
		}
		return err
	}})
	if err != nil {
		t.Fatalf("%v\n%s", err, got)
	}
	if d := Diff(want, got); d != "" {
		t.Fatalf("authz serve differs from grantd's recording at %s", d)
	}
	if strings.Join(kept, ",") != "grantd.wal" {
		t.Fatalf("data directory after the fresh phase holds %v, want grantd.wal only", kept)
	}
	// The log grantd wrote in the same phase is byte for byte what authz
	// writes: the store is deterministic given the same requests.
	ours := t.TempDir()
	if _, err := Run(Exec(bin, "serve"), ours, Options{AfterFresh: func(dir string) error {
		a, err := os.ReadFile(filepath.Join(dir, "grantd.wal"))
		if err != nil {
			return err
		}
		b, err := os.ReadFile(filepath.Join("testdata", "grantd-data", "grantd.wal"))
		if err != nil {
			return err
		}
		if !bytes.Equal(a, b) {
			t.Errorf("authz wrote a different log from grantd's:\n%s", Diff(b, a))
		}
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
}

func TestFixedCredentials(t *testing.T) {
	k, err := hex.DecodeString(TokenKey)
	if err != nil || len(k) != 32 {
		t.Fatalf("TokenKey is not 32 bytes of hex: %v", err)
	}
	if len(APIKey) < 16 {
		t.Fatal("APIKey is shorter than the server accepts")
	}
	if Env("a", "d")["GRANTD_DATA_DIR"] != "d" || Env("a", "")["GRANTD_ADDR"] != "a" {
		t.Fatal("Env")
	}
	if tokenAt(2) != "AQAAAAAAAAACVIsn7hbd5ONinrQhKsnBfA" {
		t.Fatalf("tokenAt(2) = %s, not the token grantd issued in serve.golden", tokenAt(2))
	}
}

func TestDiff(t *testing.T) {
	cases := []struct{ want, got, out string }{
		{"a\nb\n", "a\nb\n", ""},
		{"a\nb\n", "a\nc\n", "line 2:\n  want \"b\"\n  got  \"c\""},
		{"a", "a\nb", `line 2: extra line "b"`},
		{"a\nb", "a", `line 2: missing line "b"`},
	}
	for _, c := range cases {
		if d := Diff([]byte(c.want), []byte(c.got)); d != c.out {
			t.Errorf("Diff(%q, %q) = %q, want %q", c.want, c.got, d, c.out)
		}
	}
}

func TestOneLine(t *testing.T) {
	if got := oneLine("{\n  \"a\": 1\n}"); got != `{"a":1}` {
		t.Fatal(got)
	}
	if got := oneLine("not\njson"); got != `not\njson` {
		t.Fatal(got)
	}
}

func TestWriteLog(t *testing.T) {
	var out bytes.Buffer
	log := `{"time":"t","level":"INFO","msg":"listening","addr":"127.0.0.1:1","revision":0}
{"time":"t","level":"INFO","msg":"request","request_id":"x"}

{"time":"t","level":"WARN","msg":"bye"}
`
	if err := writeLog(&out, []byte(log)); err != nil {
		t.Fatal(err)
	}
	want := `{"addr":"\u003caddr\u003e","level":"INFO","msg":"listening","revision":0}
{"level":"WARN","msg":"bye"}
`
	if out.String() != want {
		t.Fatalf("got\n%s", out.String())
	}
	if err := writeLog(&out, []byte("plain text\n")); err == nil {
		t.Fatal("a non-JSON log line was accepted")
	}
}

// fake serves a canned handler and stops with the given log.
func fake(h http.HandlerFunc, log string) StartFunc {
	return func(map[string]string) (*Server, error) {
		s := httptest.NewServer(h)
		return &Server{URL: s.URL, Stop: func() ([]byte, error) { s.Close(); return []byte(log), nil }}, nil
	}
}

func TestStepErrors(t *testing.T) {
	notJSON := fake(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("no")) }, "")
	// The first restart steps save nothing; the first that does fails.
	if _, err := Restart(notJSON, ""); err == nil || !strings.Contains(err.Error(), "every relationship survived") {
		t.Fatalf("err = %v, want a JSON error at the first saving step", err)
	}
	denied := fake(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }, "")
	if _, err := Run(denied, "", Options{}); err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("err = %v, want a status error at the first saving step", err)
	}
	noField := fake(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"x":1}`)) }, "")
	if _, err := Run(noField, "", Options{}); err == nil || !strings.Contains(err.Error(), `no string field "written_at"`) {
		t.Fatalf("err = %v", err)
	}
	badLog := fake(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"written_at":"t","cursor":"c","read_at":"r"}`))
	}, "oops")
	if _, err := Restart(badLog, ""); err == nil || !strings.Contains(err.Error(), "not JSON") {
		t.Fatalf("err = %v", err)
	}
	ok := fake(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"written_at":"t","cursor":"c","read_at":"r"}`))
	}, "")
	afterErr := os.ErrPermission
	if _, err := Run(ok, "", Options{AfterFresh: func(string) error { return afterErr }}); err != afterErr {
		t.Fatalf("err = %v, want the AfterFresh error", err)
	}
	failStart := func(map[string]string) (*Server, error) { return nil, os.ErrNotExist }
	if _, err := Run(failStart, "", Options{}); err == nil || !strings.Contains(err.Error(), "start") {
		t.Fatalf("err = %v", err)
	}
	unset := step{name: "x", method: "GET", path: "/", body: "{{nope}}"}
	if err := unset.run(&bytes.Buffer{}, "http://127.0.0.1:1", 1, nil); err == nil || !strings.Contains(err.Error(), "unset variable") {
		t.Fatalf("err = %v", err)
	}
	badURL := step{name: "x", method: "GET", path: "/"}
	if err := badURL.run(&bytes.Buffer{}, "http://127.0.0.1:1", 1, nil); err == nil {
		t.Fatal("a refused connection passed")
	}
	if err := badURL.run(&bytes.Buffer{}, "://", 1, nil); err == nil {
		t.Fatal("a bad URL passed")
	}
}

func TestExecErrors(t *testing.T) {
	if _, err := Exec()(nil); err == nil {
		t.Fatal("no command accepted")
	}
	if _, err := Exec(filepath.Join(t.TempDir(), "missing"))(nil); err == nil {
		t.Fatal("a missing command started")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	_, err = Exec(sh, "-c", "echo booting; echo no keys >&2; exit 1")(nil)
	if err == nil || !strings.Contains(err.Error(), "exited before listening") || !strings.Contains(err.Error(), "no keys") {
		t.Fatalf("err = %v", err)
	}
	// Listening, then exits 1 on SIGTERM: Stop reports it with stderr.
	srv, err := Exec(sh, "-c", `trap 'echo stopping badly >&2; exit 1' TERM
echo '{"msg":"listening","addr":"127.0.0.1:9"}'
while :; do sleep 0.05; done`)(map[string]string{"X": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if srv.URL != "http://127.0.0.1:9" {
		t.Fatalf("URL = %s", srv.URL)
	}
	log, err := srv.Stop()
	if err == nil || !strings.Contains(err.Error(), "stopping badly") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(string(log), "listening") {
		t.Fatalf("log = %q", log)
	}
	// A clean stop.
	srv, err = Exec(sh, "-c", `trap 'exit 0' TERM
echo '{"msg":"listening","addr":"127.0.0.1:9"}'
while :; do sleep 0.05; done`)(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Stop(); err != nil {
		t.Fatal(err)
	}

	// Never listens, then ignores SIGTERM: both waits give up.
	defer func(a, b time.Duration) { startTimeout, stopTimeout = a, b }(startTimeout, stopTimeout)
	startTimeout, stopTimeout = 200*time.Millisecond, 200*time.Millisecond
	if _, err := Exec(sh, "-c", "exec sleep 5")(nil); err == nil || !strings.Contains(err.Error(), "did not report listening") {
		t.Fatalf("err = %v", err)
	}
	srv, err = Exec(sh, "-c", `trap '' TERM
echo '{"msg":"listening","addr":"127.0.0.1:9"}'
while :; do sleep 0.05; done`)(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Stop(); err == nil || !strings.Contains(err.Error(), "did not stop") {
		t.Fatalf("err = %v", err)
	}
}

func TestStopError(t *testing.T) {
	start := func(map[string]string) (*Server, error) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"written_at":"t","cursor":"c","read_at":"r"}`))
		}))
		return &Server{URL: s.URL, Stop: func() ([]byte, error) { s.Close(); return nil, os.ErrClosed }}, nil
	}
	if _, err := Restart(start, ""); err == nil || !strings.Contains(err.Error(), "stop: ") {
		t.Fatalf("err = %v", err)
	}
}
