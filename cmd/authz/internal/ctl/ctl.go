// Package ctl implements "authz ctl", a command-line client for a running
// "authz serve": it reads and writes the schema and relationships, runs
// checks and lookups, and pages through long answers at one snapshot.
package ctl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/authz/store"
)

// Summary is the one-line description shown in "authz help".
const Summary = "talk to a running authz serve: schema, relationships, checks and lookups"

// Exit codes of "authz ctl".
const (
	OK     = 0 // done; for check, the permission is granted
	Failed = 1 // the request failed or the server returned an error
	Usage  = 2 // bad flags or arguments
	Denied = 3 // check only: the permission is not granted
)

// DefaultAddr is used when neither -addr nor AUTHZ_URL is set.
const DefaultAddr = "http://localhost:8080"

// maxResponse bounds a response body. The largest answer is one page of
// 1000 relationships, well under this.
const maxResponse = 8 << 20

const usage = `usage: authz ctl [-addr url] [-timeout 10s] <command> [arguments]

Commands:
  schema read                          print the current schema
  schema write [-dry-run] <file|->     replace the schema; prints the write's token.
                                       -dry-run writes nothing and prints the changes,
                                       affected permissions and broken relationships
  rel touch|create|delete <rel...|->   one atomic write of relationships (or one per
                                       line on stdin); prints the write's token
  rel read <filter>                    print matching relationships, one per line
  check <resource> <permission> <subject>
                                       print allowed or denied
  lookup <type> <permission> <subject> print the IDs of resources the subject can access

A relationship is type:id#relation@type:id[#relation]. A filter is
type[:id][#relation][@type[:id][#relation]], for example doc#viewer@user:alice.
Reads take -token t (at least as fresh as t), -exact (exactly t's snapshot) or
-full (the newest write). Long answers are paged at one snapshot.

The server address comes from -addr or AUTHZ_URL (default ` + DefaultAddr + `);
the API key comes from AUTHZ_API_KEY, never from a flag, so it stays out of
process listings.

Exit codes: 0 done (check: allowed), 1 request failed, 2 usage error,
3 check denied.
`

// Run is the "authz ctl" subcommand.
func Run(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "", "server `url` (default $AUTHZ_URL or "+DefaultAddr+")")
	timeout := fs.Duration("timeout", 10*time.Second, "time limit for each request")
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return OK
		}
		return Usage
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return Usage
	}
	base := *addr
	if base == "" {
		base = getenv("AUTHZ_URL")
	}
	if base == "" {
		base = DefaultAddr
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fmt.Fprintf(stderr, "authz ctl: server address %q must be an http:// or https:// URL\n", base)
		return Usage
	}
	if *timeout <= 0 {
		fmt.Fprint(stderr, "authz ctl: -timeout must be positive\n")
		return Usage
	}
	c := &client{
		base:   strings.TrimRight(base, "/"),
		key:    getenv("AUTHZ_API_KEY"),
		http:   &http.Client{Timeout: *timeout},
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
	}
	cmd, rest := fs.Arg(0), fs.Args()[1:]
	var run func(context.Context, []string) int
	switch cmd {
	case "schema":
		run = c.schema
	case "rel", "relationships":
		run = c.rel
	case "check":
		run = c.check
	case "lookup":
		run = c.lookup
	default:
		fmt.Fprintf(stderr, "authz ctl: unknown command %q; run \"authz ctl -h\" for the list\n", cmd)
		return Usage
	}
	if c.key == "" {
		fmt.Fprint(stderr, "authz ctl: set AUTHZ_API_KEY to one of the server's GRANTD_API_KEYS\n")
		return Usage
	}
	return run(ctx, rest)
}

type client struct {
	base   string
	key    string
	http   *http.Client
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// apiError is the server's error body.
type apiError struct {
	Status    int
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func (e *apiError) Error() string {
	s := fmt.Sprintf("%s: %s", e.Code, e.Message)
	if e.RequestID != "" {
		s += " (request " + e.RequestID + ")"
	}
	return s
}

// call sends body as JSON (or no body when nil) and decodes a 200 answer
// into out.
func (c *client) call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("reading the response: %w", err)
	}
	if len(data) > maxResponse {
		return fmt.Errorf("response is larger than %d bytes", maxResponse)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error *apiError `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != nil && e.Error.Code != "" {
			e.Error.Status = resp.StatusCode
			return e.Error
		}
		return fmt.Errorf("server answered %s", resp.Status)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decoding the response: %w", err)
	}
	return nil
}

func (c *client) fail(err error) int {
	fmt.Fprintln(c.stderr, "authz ctl:", err)
	return Failed
}

func (c *client) usageErr(format string, args ...any) int {
	fmt.Fprintf(c.stderr, "authz ctl: "+format+"\n", args...)
	return Usage
}

func (c *client) readInput(name string) ([]byte, error) {
	var r io.Reader
	if name == "-" {
		r = c.stdin
	} else {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	// The server refuses bodies over 1 MiB; reading one byte more lets the
	// server's limit be the one that is reported.
	return io.ReadAll(io.LimitReader(r, 1<<20+1))
}

func (c *client) schema(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return c.usageErr("schema needs read or write")
	}
	switch args[0] {
	case "read":
		if len(args) != 1 {
			return c.usageErr("usage: schema read")
		}
		var out struct {
			Schema string `json:"schema"`
		}
		if err := c.call(ctx, http.MethodGet, "/v1/schema", nil, &out); err != nil {
			return c.fail(err)
		}
		fmt.Fprint(c.stdout, out.Schema)
		if !strings.HasSuffix(out.Schema, "\n") {
			fmt.Fprintln(c.stdout)
		}
		return OK
	case "write":
		var dry bool
		fs, code, ok := c.subFlags("schema write", "schema write [-dry-run] <file|->", args[1:], func(fs *flag.FlagSet) {
			fs.BoolVar(&dry, "dry-run", false, "write nothing; print the changes, the affected permissions and the relationships the schema would break")
		})
		if !ok {
			return code
		}
		if fs.NArg() != 1 {
			return c.usageErr("usage: schema write [-dry-run] <file|->")
		}
		src, err := c.readInput(fs.Arg(0))
		if err != nil {
			return c.fail(err)
		}
		if dry {
			return c.schemaDryRun(ctx, string(src))
		}
		var out struct {
			WrittenAt string `json:"written_at"`
		}
		if err := c.call(ctx, http.MethodPut, "/v1/schema", map[string]string{"schema": string(src)}, &out); err != nil {
			return c.fail(err)
		}
		fmt.Fprintln(c.stdout, out.WrittenAt)
		return OK
	default:
		return c.usageErr("unknown schema command %q; use read or write", args[0])
	}
}

// schemaDryRun prints what writing src would do: one line per change, the
// affected permissions, and each relationship it would break. It exits
// Failed when the write would be refused.
func (c *client) schemaDryRun(ctx context.Context, src string) int {
	var out struct {
		Changes []struct {
			Kind, Object, Name, Detail string
		} `json:"changes"`
		Affected []string `json:"affected_permissions"`
		Breaking []struct {
			Relationship, Reason string
		} `json:"breaking_relationships"`
		Count int `json:"breaking_count"`
	}
	if err := c.call(ctx, http.MethodPut, "/v1/schema?dry_run=true", map[string]string{"schema": src}, &out); err != nil {
		return c.fail(err)
	}
	for _, ch := range out.Changes {
		fmt.Fprintf(c.stdout, "%s %s %s", ch.Kind, ch.Object, ch.Name)
		if ch.Detail != "" {
			fmt.Fprintf(c.stdout, ": %s", ch.Detail)
		}
		fmt.Fprintln(c.stdout)
	}
	if len(out.Changes) == 0 {
		fmt.Fprintln(c.stdout, "no changes")
	}
	if len(out.Affected) > 0 {
		fmt.Fprintf(c.stdout, "affected permissions: %s\n", strings.Join(out.Affected, " "))
	}
	for _, b := range out.Breaking {
		fmt.Fprintf(c.stdout, "breaks %s: %s\n", b.Relationship, b.Reason)
	}
	if out.Count > len(out.Breaking) {
		fmt.Fprintf(c.stdout, "breaks %d more\n", out.Count-len(out.Breaking))
	}
	if out.Count > 0 {
		fmt.Fprintf(c.stderr, "authz ctl: the schema would break %d stored relationships; nothing was written\n", out.Count)
		return Failed
	}
	return OK
}

// consistency holds the read flags shared by rel read, check and lookup.
type consistency struct {
	token string
	exact bool
	full  bool
}

func (cs *consistency) register(fs *flag.FlagSet) {
	fs.StringVar(&cs.token, "token", "", "read at least as fresh as this consistency `token`")
	fs.BoolVar(&cs.exact, "exact", false, "with -token, read exactly at the token's snapshot")
	fs.BoolVar(&cs.full, "full", false, "read the newest committed write")
}

func (cs *consistency) body() (map[string]string, error) {
	switch {
	case cs.full && cs.token != "":
		return nil, errors.New("-full and -token cannot be combined")
	case cs.exact && cs.token == "":
		return nil, errors.New("-exact needs -token")
	case cs.full:
		return map[string]string{"mode": "fully_consistent"}, nil
	case cs.exact:
		return map[string]string{"mode": "at_exact_snapshot", "token": cs.token}, nil
	case cs.token != "":
		return map[string]string{"mode": "at_least_as_fresh", "token": cs.token}, nil
	}
	return map[string]string{}, nil
}

// subFlags parses a nested command's flags. Its help goes to stderr and
// returns ok=false with the exit code to use.
func (c *client) subFlags(name, synopsis string, args []string, setup func(*flag.FlagSet)) (*flag.FlagSet, int, bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	setup(fs)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: authz ctl %s\n", synopsis)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, OK, false
		}
		return nil, Usage, false
	}
	return fs, 0, true
}

func (c *client) rel(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return c.usageErr("rel needs touch, create, delete or read")
	}
	switch op := args[0]; op {
	case "touch", "create", "delete":
		return c.write(ctx, op, args[1:])
	case "read":
		return c.read(ctx, args[1:])
	default:
		return c.usageErr("unknown rel command %q; use touch, create, delete or read", op)
	}
}

func (c *client) write(ctx context.Context, op string, args []string) int {
	if len(args) == 0 {
		return c.usageErr("usage: rel %s <relationship...|->", op)
	}
	type where struct {
		src string
		rel string
	}
	var rels []where
	if len(args) == 1 && args[0] == "-" {
		sc := bufio.NewScanner(c.stdin)
		sc.Buffer(make([]byte, 4096), 64<<10)
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			rels = append(rels, where{fmt.Sprintf("stdin:%d", n), line})
		}
		if err := sc.Err(); err != nil {
			return c.fail(fmt.Errorf("reading stdin: %w", err))
		}
	} else {
		for i, a := range args {
			rels = append(rels, where{fmt.Sprintf("argument %d", i+1), a})
		}
	}
	if len(rels) == 0 {
		return c.usageErr("no relationships to %s", op)
	}
	if len(rels) > store.MaxUpdatesPerWrite {
		// One write is atomic; splitting it would silently give that up.
		return c.usageErr("%d relationships is more than the %d one atomic write can hold", len(rels), store.MaxUpdatesPerWrite)
	}
	type update struct {
		Op           string `json:"op"`
		Relationship string `json:"relationship"`
	}
	updates := make([]update, len(rels))
	bad := 0
	for i, r := range rels {
		if _, err := store.ParseRelationship(r.rel); err != nil {
			fmt.Fprintf(c.stderr, "authz ctl: %s: %s\n", r.src, strings.TrimPrefix(err.Error(), store.ErrInvalid.Error()+": "))
			bad++
		}
		updates[i] = update{op, r.rel}
	}
	if bad > 0 {
		return Usage
	}
	var out struct {
		WrittenAt string `json:"written_at"`
	}
	if err := c.call(ctx, http.MethodPost, "/v1/relationships/write", map[string]any{"updates": updates}, &out); err != nil {
		return c.fail(err)
	}
	fmt.Fprintln(c.stdout, out.WrittenAt)
	return OK
}

// parseFilter parses type[:id][#relation][@type[:id][#relation]].
func parseFilter(s string) (store.Filter, error) {
	var f store.Filter
	res, sub, hasSub := strings.Cut(s, "@")
	res, f.Relation, _ = strings.Cut(res, "#")
	f.ResourceType, f.ResourceID, _ = strings.Cut(res, ":")
	if f.ResourceType == "" {
		return f, fmt.Errorf("filter %q needs a resource type", s)
	}
	if hasSub {
		sub, f.SubjectRelation, _ = strings.Cut(sub, "#")
		f.SubjectType, f.SubjectID, _ = strings.Cut(sub, ":")
		if f.SubjectType == "" {
			return f, fmt.Errorf("filter %q has an empty subject type after '@'", s)
		}
	}
	return f, nil
}

func (c *client) read(ctx context.Context, args []string) int {
	var cs consistency
	limit := 0
	fs, code, ok := c.subFlags("rel read", "rel read [-token t [-exact] | -full] [-limit n] <filter>", args, func(fs *flag.FlagSet) {
		cs.register(fs)
		fs.IntVar(&limit, "limit", 0, "relationships per page (0 uses the server's default)")
	})
	if !ok {
		return code
	}
	if fs.NArg() != 1 {
		return c.usageErr("usage: rel read [flags] <filter>")
	}
	f, err := parseFilter(fs.Arg(0))
	if err != nil {
		return c.usageErr("%v", err)
	}
	cons, err := cs.body()
	if err != nil {
		return c.usageErr("%v", err)
	}
	cursor := ""
	for {
		var out struct {
			Relationships []string `json:"relationships"`
			Cursor        string   `json:"cursor"`
			ReadAt        string   `json:"read_at"`
		}
		body := map[string]any{"filter": f, "consistency": cons, "cursor": cursor, "limit": limit}
		if err := c.call(ctx, http.MethodPost, "/v1/relationships/read", body, &out); err != nil {
			return c.fail(err)
		}
		for _, r := range out.Relationships {
			fmt.Fprintln(c.stdout, r)
		}
		if out.Cursor == "" {
			return OK
		}
		// Later pages read the first page's snapshot, so the listing is
		// one consistent view even while writes continue.
		cursor, cons = out.Cursor, map[string]string{"mode": "at_exact_snapshot", "token": out.ReadAt}
	}
}

func (c *client) check(ctx context.Context, args []string) int {
	var cs consistency
	fs, code, ok := c.subFlags("check", "check [-token t [-exact] | -full] <resource> <permission> <subject>", args, cs.register)
	if !ok {
		return code
	}
	if fs.NArg() != 3 {
		return c.usageErr("usage: check [flags] <resource> <permission> <subject>")
	}
	cons, err := cs.body()
	if err != nil {
		return c.usageErr("%v", err)
	}
	var out struct {
		Allowed bool `json:"allowed"`
	}
	body := map[string]any{"resource": fs.Arg(0), "permission": fs.Arg(1), "subject": fs.Arg(2), "consistency": cons}
	if err := c.call(ctx, http.MethodPost, "/v1/check", body, &out); err != nil {
		return c.fail(err)
	}
	if out.Allowed {
		fmt.Fprintln(c.stdout, "allowed")
		return OK
	}
	fmt.Fprintln(c.stdout, "denied")
	return Denied
}

func (c *client) lookup(ctx context.Context, args []string) int {
	var cs consistency
	limit := 0
	fs, code, ok := c.subFlags("lookup", "lookup [-token t [-exact] | -full] [-limit n] <type> <permission> <subject>", args, func(fs *flag.FlagSet) {
		cs.register(fs)
		fs.IntVar(&limit, "limit", 0, "IDs per page (0 uses the server's default)")
	})
	if !ok {
		return code
	}
	if fs.NArg() != 3 {
		return c.usageErr("usage: lookup [flags] <type> <permission> <subject>")
	}
	cons, err := cs.body()
	if err != nil {
		return c.usageErr("%v", err)
	}
	cursor := ""
	for {
		var out struct {
			IDs        []string `json:"resource_ids"`
			Cursor     string   `json:"cursor"`
			LookedUpAt string   `json:"looked_up_at"`
		}
		body := map[string]any{"resource_type": fs.Arg(0), "permission": fs.Arg(1), "subject": fs.Arg(2),
			"consistency": cons, "cursor": cursor, "limit": limit}
		if err := c.call(ctx, http.MethodPost, "/v1/lookup/resources", body, &out); err != nil {
			return c.fail(err)
		}
		for _, id := range out.IDs {
			fmt.Fprintln(c.stdout, id)
		}
		if out.Cursor == "" {
			return OK
		}
		cursor, cons = out.Cursor, map[string]string{"mode": "at_exact_snapshot", "token": out.LookedUpAt}
	}
}
