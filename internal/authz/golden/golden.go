// Package golden replays the authorization API's end-to-end scenario
// against a running server and writes what a client and an operator can
// observe as a text transcript, so that `authz serve` can be compared byte
// for byte with a recording made from the grantd binary before the move.
//
// The scenario is the README's walk-through (examples/demo.sh) followed by
// every endpoint and every error code a single node can produce, then a
// restart on the same data directory. Nothing in it is random: the server
// gets a fixed API key and token key, so consistency tokens are the same on
// every run, every request carries its own X-Request-Id, and every read
// names its snapshot, so the 100 ms shared snapshot of minimize_latency never
// decides an answer. The transcript keeps the status, every response header
// except Date and Content-Length (the body is compared in full) and the body.
// For /metrics it keeps the "# TYPE" lines, the names and kinds dashboards
// depend on, and not the values. After each phase it keeps the server's log
// lines other than the per-request ones, without their time and address.
package golden

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/laiwf94/authz/internal/authz/store"
	"github.com/laiwf94/authz/internal/authz/token"
)

// APIKey and TokenKey are the fixed credentials the scenario gives the
// server. TokenKey is GRANTD_TOKEN_KEY: 32 bytes in hex.
const (
	APIKey   = "golden-api-key-0123456789"
	TokenKey = "676f6c64656e2d746f6b656e2d6b65792d303030303030303030303030303030"
)

// Schema is the README's schema, the same as examples/docs.schema without
// its comment line.
const Schema = `definition user {}

definition group {
  relation member: user | group#member
}

definition folder {
  relation parent: folder
  relation viewer: user | user:* | group#member
  permission view = viewer + parent->view
}

definition doc {
  relation parent: folder
  relation owner: user
  relation editor: user | group#member
  relation banned: user
  permission edit = owner + editor
  permission view = (edit + parent->view) - banned
}
`

// RestartMarker starts the restart phase in a transcript. Restart's output
// is the part of a full transcript from this line on.
const RestartMarker = "# phase restart\n"

// Env returns the environment for a server under test. An empty dataDir
// keeps everything in memory.
func Env(addr, dataDir string) map[string]string {
	return map[string]string{
		"GRANTD_ADDR":      addr,
		"GRANTD_API_KEYS":  APIKey,
		"GRANTD_TOKEN_KEY": TokenKey,
		"GRANTD_DATA_DIR":  dataDir,
	}
}

// Server is a started server. Stop shuts it down gracefully and returns its
// log, which must be JSON lines.
type Server struct {
	URL  string
	Stop func() (log []byte, err error)
}

// StartFunc starts a server with the given environment, on a loopback port
// of its choosing (GRANTD_ADDR is 127.0.0.1:0), and returns once it accepts
// requests.
type StartFunc func(env map[string]string) (*Server, error)

// Options adjusts Run.
type Options struct {
	// AfterFresh, when set, is called with the data directory after the
	// fresh phase has stopped and before the restart, e.g. to keep a copy.
	AfterFresh func(dataDir string) error
}

// Run starts a server on the empty dataDir, plays the fresh phase, stops it,
// starts it again on the same directory and plays the restart phase. It
// returns the whole transcript.
func Run(start StartFunc, dataDir string, opt Options) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("# phase fresh\n")
	if err := phase(&out, start, dataDir, freshSteps()); err != nil {
		return out.Bytes(), err
	}
	if opt.AfterFresh != nil {
		if err := opt.AfterFresh(dataDir); err != nil {
			return out.Bytes(), err
		}
	}
	rest, err := Restart(start, dataDir)
	out.Write(rest)
	return out.Bytes(), err
}

// Restart plays only the restart phase, on a data directory that holds what
// the fresh phase wrote (possibly written by another binary).
func Restart(start StartFunc, dataDir string) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(RestartMarker)
	err := phase(&out, start, dataDir, restartSteps())
	return out.Bytes(), err
}

func phase(out *bytes.Buffer, start StartFunc, dataDir string, steps []step) error {
	srv, err := start(Env("127.0.0.1:0", dataDir))
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	vars := map[string]string{}
	var runErr error
	for i, s := range steps {
		if runErr = s.run(out, srv.URL, i+1, vars); runErr != nil {
			break
		}
	}
	log, err := srv.Stop()
	if runErr != nil {
		return runErr
	}
	if err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	out.WriteString("# log\n")
	return writeLog(out, log)
}

// step is one request. Body may name variables as {{name}}; Save copies
// top-level string fields of a 200 response into variables.
type step struct {
	name        string
	method      string
	path        string
	body        string
	noAuth      bool
	contentType string // default application/json for a body
	save        map[string]string
	typesOnly   bool // keep only "# TYPE" lines of the body
}

func (s step) run(out *bytes.Buffer, base string, n int, vars map[string]string) error {
	body := s.body
	for k, v := range vars {
		body = strings.ReplaceAll(body, "{{"+k+"}}", v)
	}
	if strings.Contains(body, "{{") {
		return fmt.Errorf("step %q: unset variable in %s", s.name, body)
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(s.method, base+s.path, rd)
	if err != nil {
		return err
	}
	id := fmt.Sprintf("golden-%02d", n)
	req.Header.Set("X-Request-Id", id)
	if !s.noAuth {
		req.Header.Set("Authorization", "Bearer "+APIKey)
	}
	if body != "" {
		ct := s.contentType
		if ct == "" {
			ct = "application/json"
		}
		req.Header.Set("Content-Type", ct)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("step %q: %w", s.name, err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("step %q: %w", s.name, err)
	}
	fmt.Fprintf(out, "## %02d %s\n> %s %s\n", n, s.name, s.method, s.path)
	if body != "" {
		fmt.Fprintf(out, "> %s\n", oneLine(body))
	}
	fmt.Fprintf(out, "< %d\n", resp.StatusCode)
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		if k != "Date" && k != "Content-Length" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			fmt.Fprintf(out, "< %s: %s\n", k, v)
		}
	}
	if s.typesOnly {
		var kept []string
		for l := range strings.SplitSeq(string(got), "\n") {
			if strings.HasPrefix(l, "# TYPE ") {
				kept = append(kept, l)
			}
		}
		slices.Sort(kept)
		got = []byte(strings.Join(kept, "\n") + "\n")
	}
	out.Write(got)
	if len(got) > 0 && got[len(got)-1] != '\n' {
		out.WriteString("\n")
	}
	if len(s.save) > 0 {
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("step %q: status %d, want 200: %s", s.name, resp.StatusCode, got)
		}
		var m map[string]any
		if err := json.Unmarshal(got, &m); err != nil {
			return fmt.Errorf("step %q: %w", s.name, err)
		}
		for v, field := range s.save {
			str, ok := m[field].(string)
			if !ok {
				return fmt.Errorf("step %q: no string field %q in %s", s.name, field, got)
			}
			vars[v] = str
		}
	}
	return nil
}

var client = &http.Client{Timeout: 30 * time.Second}

// oneLine compacts a JSON body so each request is one transcript line; other
// bodies have their newlines escaped.
func oneLine(body string) string {
	var b bytes.Buffer
	if json.Compact(&b, []byte(body)) == nil {
		return b.String()
	}
	return strings.ReplaceAll(body, "\n", `\n`)
}

// writeLog keeps every log line except the per-request ones (their order
// against the responses is not fixed and their durations vary), without
// the time and the listener address.
func writeLog(out *bytes.Buffer, log []byte) error {
	for l := range strings.SplitSeq(strings.TrimRight(string(log), "\n"), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			return fmt.Errorf("log line is not JSON: %q", l)
		}
		if m["msg"] == "request" {
			continue
		}
		delete(m, "time")
		if _, ok := m["addr"]; ok {
			m["addr"] = "<addr>"
		}
		b, err := json.Marshal(m) // sorted keys
		if err != nil {
			return err
		}
		out.Write(b)
		out.WriteString("\n")
	}
	return nil
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func check(resource, permission, subject, consistency string) string {
	return fmt.Sprintf(`{"resource":%q,"permission":%q,"subject":%q,"consistency":%s}`, resource, permission, subject, consistency)
}

func fresh(tok string) string { return `{"mode":"at_least_as_fresh","token":"{{` + tok + `}}"}` }
func exact(tok string) string { return `{"mode":"at_exact_snapshot","token":"{{` + tok + `}}"}` }

const full = `{"mode":"fully_consistent"}`

func freshSteps() []step {
	// The README's relationships, as examples/demo.sh writes them.
	demo := `{"updates":[
  {"op":"touch","relationship":"group:eng#member@user:alice"},
  {"op":"touch","relationship":"group:staff#member@group:eng#member"},
  {"op":"touch","relationship":"group:staff#member@user:carol"},
  {"op":"touch","relationship":"folder:root#viewer@group:staff#member"},
  {"op":"touch","relationship":"folder:specs#parent@folder:root"},
  {"op":"touch","relationship":"doc:design#parent@folder:specs"},
  {"op":"touch","relationship":"doc:design#editor@group:eng#member"}
]}`
	return []step{
		{name: "health without a key", method: "GET", path: "/healthz", noAuth: true},
		{name: "readiness", method: "GET", path: "/readyz", noAuth: true},
		{name: "schema without a key", method: "GET", path: "/v1/schema", noAuth: true},
		{name: "schema before one is written", method: "GET", path: "/v1/schema"},
		{name: "check before a schema", method: "POST", path: "/v1/check", body: check("doc:design", "view", "user:alice", full)},
		{name: "write before a schema", method: "POST", path: "/v1/relationships/write", body: `{"updates":[{"op":"touch","relationship":"group:eng#member@user:alice"}]}`},
		{name: "schema as text/plain", method: "PUT", path: "/v1/schema", body: `{"schema":"definition user {}"}`, contentType: "text/plain"},
		{name: "schema that does not parse", method: "PUT", path: "/v1/schema", body: `{"schema":"definition doc {\n  relation owner: nobody\n}\n"}`},
		{name: "schema that refers to itself", method: "PUT", path: "/v1/schema", body: `{"schema":"definition user {}\ndefinition doc {\n  permission view = view\n}\n"}`},
		{name: "empty schema", method: "PUT", path: "/v1/schema", body: `{"schema":"  "}`},
		{name: "unknown field", method: "PUT", path: "/v1/schema", body: `{"schema":"definition user {}","extra":1}`},
		{name: "README schema (demo step 1)", method: "PUT", path: "/v1/schema", body: `{"schema":` + jsonString(Schema) + `}`, save: map[string]string{"schema": "written_at"}},
		{name: "schema in canonical form", method: "GET", path: "/v1/schema"},
		{name: "README relationships (demo step 2)", method: "POST", path: "/v1/relationships/write", body: demo, save: map[string]string{"w1": "written_at"}},
		{name: "alice can edit (demo step 3)", method: "POST", path: "/v1/check", body: check("doc:design", "edit", "user:alice", fresh("w1"))},
		{name: "carol can view (demo step 3)", method: "POST", path: "/v1/check", body: check("doc:design", "view", "user:carol", fresh("w1"))},
		{name: "carol cannot edit (demo step 3)", method: "POST", path: "/v1/check", body: check("doc:design", "edit", "user:carol", fresh("w1"))},
		{name: "ban carol (demo step 4)", method: "POST", path: "/v1/relationships/write", body: `{"updates":[{"op":"touch","relationship":"doc:design#banned@user:carol"}]}`, save: map[string]string{"w2": "written_at"}},
		{name: "carol cannot view at the ban's token (demo step 4)", method: "POST", path: "/v1/check", body: check("doc:design", "view", "user:carol", fresh("w2"))},
		{name: "carol could view just before the ban", method: "POST", path: "/v1/check", body: check("doc:design", "view", "user:carol", exact("w1"))},
		{name: "docs alice can view (demo step 5)", method: "POST", path: "/v1/lookup/resources", body: `{"resource_type":"doc","permission":"view","subject":"user:alice","consistency":{"mode":"fully_consistent"}}`},
		{name: "the README's curl: alice can view doc:design", method: "POST", path: "/v1/check", body: check("doc:design", "view", "user:alice", full)},
		{name: "nobody wrote doc:plan", method: "POST", path: "/v1/check", body: check("doc:plan", "view", "user:alice", full)},
		{name: "bulk check at one snapshot", method: "POST", path: "/v1/check/bulk", body: `{"items":[
  {"resource":"doc:design","permission":"view","subject":"user:alice"},
  {"resource":"folder:root","permission":"view","subject":"group:eng#member"},
  {"resource":"doc:design","permission":"nope","subject":"user:alice"},
  {"resource":"doc:design","permission":"view","subject":"user:carol"}
],"consistency":` + exact("w2") + `}`},
		{name: "read groups, first page", method: "POST", path: "/v1/relationships/read", body: `{"filter":{"resource_type":"group"},"limit":2,"consistency":` + exact("w2") + `}`, save: map[string]string{"cursor": "cursor"}},
		{name: "read groups, next page", method: "POST", path: "/v1/relationships/read", body: `{"filter":{"resource_type":"group"},"limit":2,"cursor":"{{cursor}}","consistency":` + exact("w2") + `}`},
		{name: "read by subject", method: "POST", path: "/v1/relationships/read", body: `{"filter":{"resource_type":"group","subject_type":"group","subject_id":"eng","subject_relation":"member"},"consistency":` + full + `}`},
		{name: "read without a type", method: "POST", path: "/v1/relationships/read", body: `{"filter":{},"consistency":` + full + `}`},
		{name: "read limit too large", method: "POST", path: "/v1/relationships/read", body: `{"filter":{"resource_type":"doc"},"limit":100000}`},
		{name: "create one that exists", method: "POST", path: "/v1/relationships/write", body: `{"updates":[{"op":"create","relationship":"group:eng#member@user:alice"}]}`},
		{name: "precondition that fails", method: "POST", path: "/v1/relationships/write", body: `{"updates":[{"op":"touch","relationship":"doc:design#owner@user:bob"}],"preconditions":[{"must_exist":false,"filter":{"resource_type":"doc","resource_id":"design","relation":"banned"}}]}`},
		{name: "relationship the schema forbids", method: "POST", path: "/v1/relationships/write", body: `{"updates":[{"op":"touch","relationship":"doc:design#banned@group:eng#member"}]}`},
		{name: "relationship that does not parse", method: "POST", path: "/v1/relationships/write", body: `{"updates":[{"op":"touch","relationship":"doc:design"}]}`},
		{name: "unknown op", method: "POST", path: "/v1/relationships/write", body: `{"updates":[{"op":"upsert","relationship":"doc:design#owner@user:bob"}]}`},
		{name: "public folder and an owner, with a precondition that holds", method: "POST", path: "/v1/relationships/write", body: `{"updates":[
  {"op":"create","relationship":"folder:pub#viewer@user:*"},
  {"op":"touch","relationship":"doc:notes#parent@folder:pub"},
  {"op":"touch","relationship":"doc:notes#owner@user:bob"}
],"preconditions":[{"must_exist":true,"filter":{"resource_type":"doc","resource_id":"design","relation":"banned"}}]}`, save: map[string]string{"w3": "written_at"}},
		{name: "anyone can view a public doc", method: "POST", path: "/v1/check", body: check("doc:notes", "view", "user:zed", fresh("w3"))},
		{name: "lift the ban", method: "POST", path: "/v1/relationships/write", body: `{"updates":[{"op":"delete","relationship":"doc:design#banned@user:carol"}]}`, save: map[string]string{"w4": "written_at"}},
		{name: "carol can view again", method: "POST", path: "/v1/check", body: check("doc:design", "view", "user:carol", fresh("w4"))},
		{name: "docs carol can view, one per page", method: "POST", path: "/v1/lookup/resources", body: `{"resource_type":"doc","permission":"view","subject":"user:carol","limit":1,"consistency":` + exact("w4") + `}`, save: map[string]string{"lc": "cursor"}},
		{name: "docs carol can view, next page", method: "POST", path: "/v1/lookup/resources", body: `{"resource_type":"doc","permission":"view","subject":"user:carol","limit":1,"cursor":"{{lc}}","consistency":` + exact("w4") + `}`},
		{name: "check an unknown permission", method: "POST", path: "/v1/check", body: check("doc:design", "nope", "user:alice", full)},
		{name: "check an unknown type", method: "POST", path: "/v1/check", body: check("page:design", "view", "user:alice", full)},
		{name: "check a forged token", method: "POST", path: "/v1/check", body: check("doc:design", "view", "user:alice", `{"mode":"at_least_as_fresh","token":"AQAAAAAAAAAJAAAAAAAAAAAAAAAAAAAAAA"}`)},
		{name: "check an unknown mode", method: "POST", path: "/v1/check", body: check("doc:design", "view", "user:alice", `{"mode":"eventually"}`)},
		{name: "check without a token", method: "POST", path: "/v1/check", body: check("doc:design", "view", "user:alice", `{"mode":"at_least_as_fresh"}`)},
		{name: "two JSON objects", method: "POST", path: "/v1/check", body: check("doc:design", "view", "user:alice", full) + check("doc:design", "view", "user:alice", full)},
		{name: "watch from the start", method: "POST", path: "/v1/watch", body: `{"after":"{{schema}}"}`},
		{name: "watch from the head", method: "POST", path: "/v1/watch", body: `{"after":""}`},
		{name: "watch from the last write, no wait", method: "POST", path: "/v1/watch", body: `{"after":"{{w4}}"}`},
		{name: "watch too long", method: "POST", path: "/v1/watch", body: `{"after":"{{w4}}","wait_seconds":3600}`},
		{name: "schema change that would orphan data", method: "PUT", path: "/v1/schema", body: `{"schema":"definition user {}\ndefinition group {\n  relation member: user | group#member\n}\ndefinition folder {\n  relation parent: folder\n  relation viewer: user | group#member\n  permission view = viewer + parent->view\n}\ndefinition doc {\n  relation parent: folder\n  relation owner: user\n  relation editor: user | group#member\n  relation banned: user\n  permission edit = owner + editor\n  permission view = (edit + parent->view) - banned\n}\n"}`},
		{name: "metric names", method: "GET", path: "/metrics", typesOnly: true},
		{name: "metrics without a key", method: "GET", path: "/metrics", noAuth: true},
		{name: "unknown path", method: "GET", path: "/v1/nope"},
		{name: "wrong method", method: "GET", path: "/v1/check"},
	}
}

func restartSteps() []step {
	// Revisions of the fresh phase: 1 the schema, 2 the README's
	// relationships, 3 the ban, 4 the public folder, 5 the ban lifted. On
	// start the log is compacted into a checkpoint at the head, so tokens
	// for 5 work and older snapshots are gone (snapshot_expired).
	beforeLift := `{"mode":"at_exact_snapshot","token":"` + tokenAt(4) + `"}`
	return []step{
		{name: "health after restart", method: "GET", path: "/healthz", noAuth: true},
		{name: "a token from before the restart still verifies", method: "POST", path: "/v1/check", body: `{"resource":"doc:design","permission":"view","subject":"user:carol","consistency":{"mode":"at_least_as_fresh","token":"` + tokenAt(5) + `"}}`},
		{name: "watch from the head token of before the restart", method: "POST", path: "/v1/watch", body: `{"after":"` + tokenAt(5) + `"}`},
		{name: "schema survived", method: "GET", path: "/v1/schema"},
		{name: "every relationship survived", method: "POST", path: "/v1/relationships/read", body: `{"filter":{"resource_type":"doc"},"consistency":` + full + `}`, save: map[string]string{"head": "read_at"}},
		{name: "history before the restart is compacted away", method: "POST", path: "/v1/check", body: `{"resource":"doc:design","permission":"view","subject":"user:carol","consistency":` + beforeLift + `}`},
		{name: "watch from before the restart", method: "POST", path: "/v1/watch", body: `{"after":"` + tokenAt(3) + `"}`},
		{name: "write after restart", method: "POST", path: "/v1/relationships/write", body: `{"updates":[{"op":"touch","relationship":"group:eng#member@user:dana"}]}`, save: map[string]string{"w5": "written_at"}},
		{name: "dana can edit", method: "POST", path: "/v1/check", body: check("doc:design", "edit", "user:dana", fresh("w5"))},
		{name: "docs dana can view", method: "POST", path: "/v1/lookup/resources", body: `{"resource_type":"doc","permission":"view","subject":"user:dana","consistency":` + fresh("w5") + `}`},
	}
}

// How long Exec waits for a server to listen and to stop.
var startTimeout, stopTimeout = 30 * time.Second, 10 * time.Second

// Exec returns a StartFunc that runs argv as a child process with the
// current environment plus the server's. It reads the bound address from
// the server's "listening" log line on stdout; Stop sends SIGTERM and wants
// exit status 0 within 10 seconds.
func Exec(argv ...string) StartFunc {
	return func(env map[string]string) (*Server, error) {
		if len(argv) == 0 {
			return nil, errors.New("no command")
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = os.Environ()
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		var stderr syncBuffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		var log syncBuffer
		addr := make(chan string, 1)
		scanned := make(chan struct{})
		go func() {
			defer close(scanned)
			sc := bufio.NewScanner(stdout)
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			for sc.Scan() {
				line := sc.Bytes()
				log.Write(append(line, '\n'))
				var m struct{ Msg, Addr string }
				if json.Unmarshal(line, &m) == nil && m.Msg == "listening" {
					select {
					case addr <- m.Addr:
					default:
					}
				}
			}
		}()
		exited := make(chan error, 1)
		go func() {
			<-scanned
			exited <- cmd.Wait()
		}()
		select {
		case a := <-addr:
			return &Server{URL: "http://" + a, Stop: func() ([]byte, error) {
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					return log.Bytes(), err
				}
				select {
				case err := <-exited:
					if err != nil {
						return log.Bytes(), fmt.Errorf("%v: %s", err, stderr.Bytes())
					}
					return log.Bytes(), nil
				case <-time.After(stopTimeout):
					cmd.Process.Kill()
					<-exited
					return log.Bytes(), fmt.Errorf("server did not stop within %v of SIGTERM", stopTimeout)
				}
			}}, nil
		case err := <-exited:
			return nil, fmt.Errorf("server exited before listening (%v): %s%s", err, log.Bytes(), stderr.Bytes())
		case <-time.After(startTimeout):
			cmd.Process.Kill()
			<-exited
			return nil, fmt.Errorf("server did not report listening within %v", startTimeout)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.b.Bytes())
}

// Diff describes the first line where got differs from want, or returns ""
// when they are equal.
func Diff(want, got []byte) string {
	if bytes.Equal(want, got) {
		return ""
	}
	w := strings.Split(string(want), "\n")
	g := strings.Split(string(got), "\n")
	for i := 0; ; i++ {
		var wl, gl string
		wok, gok := i < len(w), i < len(g)
		if wok {
			wl = w[i]
		}
		if gok {
			gl = g[i]
		}
		if wok && gok && wl == gl {
			continue
		}
		switch {
		case !wok:
			return fmt.Sprintf("line %d: extra line %q", i+1, gl)
		case !gok:
			return fmt.Sprintf("line %d: missing line %q", i+1, wl)
		}
		return fmt.Sprintf("line %d:\n  want %q\n  got  %q", i+1, wl, gl)
	}
}

// tokenAt is the consistency token for rev under TokenKey. The restart
// phase needs tokens for revisions the fresh phase wrote, which may have
// been played by another process or another binary. The fresh phase's
// transcript pins the tokens the server itself issued, so a change to the
// token format still shows there.
func tokenAt(rev store.Revision) string {
	k, _ := hex.DecodeString(TokenKey)
	iss, err := token.NewIssuer(k)
	if err != nil {
		return "invalid-token-key"
	}
	return iss.Encode(rev)
}
