// Command authzbench offers an open-loop mix of requests to a running
// deployment and reports latency percentiles, corrected for coordinated
// omission, with the HDR histograms behind them.
//
//	authzbench [flags]
//
// The mix names operations and their weights, for example
// -mix check=70,bulk_check=10,lookup=10,write=10. The operations are
//
//	check         POST /v1/check on -api
//	bulk_check    POST /v1/check/bulk of -bulk-items checks on -api
//	lookup        POST /v1/lookup/resources on -api
//	write         POST /v1/relationships/write of one touch on -api
//	forward_auth  GET -forward-url with a session cookie, as nginx asks
//	oidc_login    a whole browser sign-in from -login-start
//	mcp_call      a JSON-RPC tools/call on -mcp-url
//
// Requests go out at -rate per second for -warmup (not recorded) and then
// -duration, whatever the server's speed; latency counts from the time a
// request was due, so queueing behind a slow answer is measured. -out
// writes the whole result as JSON, histograms included. The exit status is
// 0 when the run kept up and errors stayed within -max-error-rate, 1 when
// not, and 2 for bad flags or a failed setup.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/laiwf94/authz/bench/hdr"
	"github.com/laiwf94/authz/bench/load"
	"github.com/laiwf94/authz/bench/ops"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type options struct {
	mix                                   string
	rate                                  float64
	warmup, duration, timeout, drain      time.Duration
	workers, backlog                      int
	arrival                               string
	seed                                  uint64
	out, label, cacert                    string
	maxErrorRate                          float64
	api, consistency                      string
	keys                                  ops.Keyspace
	permission, relation                  string
	bulkItems, lookupLimit                int
	forwardURL, forwardHost, forwardPaths string
	forwardExpect, sessions               int
	sessionsFile                          string
	loginStart, loginCreds, loginCookie   string
	loginUserField, loginPassField        string
	mcpURL, mcpTools, mcpProtocol         string
}

func parse(args []string, stderr io.Writer) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet("authzbench", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.mix, "mix", "check=100", "operations and weights: NAME=WEIGHT,...")
	fs.Float64Var(&o.rate, "rate", 1000, "offered requests per second, over the whole mix")
	fs.DurationVar(&o.warmup, "warmup", 5*time.Second, "time sending before recording")
	fs.DurationVar(&o.duration, "duration", 30*time.Second, "recorded time")
	fs.IntVar(&o.workers, "workers", 64, "most requests in flight")
	fs.IntVar(&o.backlog, "backlog", 0, "due requests that may wait for a worker (0: 4 per worker)")
	fs.DurationVar(&o.timeout, "timeout", 10*time.Second, "limit for one request")
	fs.DurationVar(&o.drain, "drain", 10*time.Second, "time after the last due request to finish")
	fs.StringVar(&o.arrival, "arrival", "uniform", "spacing of requests: uniform or poisson")
	fs.Uint64Var(&o.seed, "seed", 1, "seed for the schedule and every drawn request")
	fs.StringVar(&o.out, "out", "", "write the result as JSON to this file")
	fs.StringVar(&o.label, "label", "", "name of the run in the result, such as the product and dataset")
	fs.StringVar(&o.cacert, "cacert", "", "PEM file of extra CA certificates to trust")
	fs.Float64Var(&o.maxErrorRate, "max-error-rate", 0.001, "highest share of failed requests that still passes")

	fs.StringVar(&o.api, "api", "", "authorization API base URL, such as http://127.0.0.1:8080")
	fs.StringVar(&o.consistency, "consistency", "minimize_latency", "consistency mode of reads")
	fs.StringVar(&o.keys.ResourceType, "resource-type", "doc", "type of the resources checked")
	fs.StringVar(&o.keys.ResourcePrefix, "resource-prefix", "", "resource IDs are this followed by a number")
	fs.IntVar(&o.keys.Resources, "resources", 1000, "resource IDs are drawn from this many")
	fs.StringVar(&o.keys.SubjectType, "subject-type", "user", "type of the subjects")
	fs.StringVar(&o.keys.SubjectPrefix, "subject-prefix", "", "subject IDs are this followed by a number")
	fs.IntVar(&o.keys.Subjects, "subjects", 1000, "subject IDs are drawn from this many")
	fs.Float64Var(&o.keys.Zipf, "zipf", 0, "Zipf exponent (above 1) for drawing IDs; 0 draws uniformly")
	fs.StringVar(&o.permission, "permission", "view", "permission checked and looked up")
	fs.StringVar(&o.relation, "relation", "viewer", "relation written")
	fs.IntVar(&o.bulkItems, "bulk-items", 10, "checks in one bulk check")
	fs.IntVar(&o.lookupLimit, "lookup-limit", 100, "most resources one lookup returns (0: server default)")

	fs.StringVar(&o.forwardURL, "forward-url", "", "forward-auth URL, such as http://127.0.0.1:4180/auth")
	fs.StringVar(&o.forwardHost, "forward-host", "", "X-Forwarded-Host of forward-auth requests")
	fs.StringVar(&o.forwardPaths, "forward-paths", "/", "comma-separated X-Forwarded-Uri values to draw from")
	fs.IntVar(&o.forwardExpect, "forward-expect", 200, "status a forward-auth answer must have")
	fs.IntVar(&o.sessions, "sessions", 0, "sign in this many times before the run for forward-auth cookies")
	fs.StringVar(&o.sessionsFile, "sessions-file", "", "file of NAME=VALUE session cookies, one per line, for forward-auth")

	fs.StringVar(&o.loginStart, "login-start", "", "URL a sign-in starts at, such as http://127.0.0.1:4180/login?app=APP&provider=ID")
	fs.StringVar(&o.loginCreds, "login-credentials", "", "USER:PASSWORD,... or @FILE with one USER:PASSWORD per line")
	fs.StringVar(&o.loginCookie, "login-cookie", "__Host-wicket", "session cookie a successful sign-in sets")
	fs.StringVar(&o.loginUserField, "login-user-field", "username", "user name input of the sign-in form")
	fs.StringVar(&o.loginPassField, "login-password-field", "password", "password input of the sign-in form")

	fs.StringVar(&o.mcpURL, "mcp-url", "", "MCP endpoint, such as http://127.0.0.1:8080/mcp")
	fs.StringVar(&o.mcpTools, "mcp-tools", "", `JSON list of tools to call, [{"name":..., "arguments":{...}}], or @FILE`)
	fs.StringVar(&o.mcpProtocol, "mcp-protocol", ops.MCPStateless, "MCP revision: "+ops.MCPStateless+" (no session) or "+ops.MCPSession)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return o, nil
}

// parseMix reads NAME=WEIGHT,... in order.
func parseMix(s string) ([]string, []int, error) {
	var names []string
	var weights []int
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		name, w, ok := strings.Cut(strings.TrimSpace(part), "=")
		n, err := strconv.Atoi(w)
		if !ok || name == "" || err != nil || n <= 0 {
			return nil, nil, fmt.Errorf("mix: %q is not NAME=WEIGHT with a positive weight", part)
		}
		if seen[name] {
			return nil, nil, fmt.Errorf("mix: %s is named twice", name)
		}
		seen[name] = true
		names = append(names, name)
		weights = append(weights, n)
	}
	return names, weights, nil
}

// readArg returns s, or the contents of the file s names after an @.
func readArg(s string) (string, error) {
	if f, ok := strings.CutPrefix(s, "@"); ok {
		b, err := os.ReadFile(f)
		return string(b), err
	}
	return s, nil
}

func parseCredentials(s string) ([]ops.Credential, error) {
	s, err := readArg(s)
	if err != nil {
		return nil, err
	}
	var out []ops.Credential
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		u, p, ok := strings.Cut(strings.TrimSpace(f), ":")
		if !ok || u == "" {
			return nil, errors.New("login credentials: want USER:PASSWORD")
		}
		out = append(out, ops.Credential{User: u, Password: p})
	}
	if len(out) == 0 {
		return nil, errors.New("login credentials: none given")
	}
	return out, nil
}

func readSessions(path string) ([]*http.Cookie, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []*http.Cookie
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || name == "" || value == "" {
			return nil, fmt.Errorf("%s: %q is not NAME=VALUE", path, line)
		}
		out = append(out, &http.Cookie{Name: name, Value: value})
	}
	return out, sc.Err()
}

// build makes the operations of the mix, signing in first if forward-auth
// needs sessions.
func build(ctx context.Context, o *options, getenv func(string) string, names []string, weights []int) ([]load.Weighted, error) {
	client, err := ops.NewClient(o.workers, o.cacert)
	if err != nil {
		return nil, err
	}
	api := &ops.API{Client: client, URL: strings.TrimSuffix(o.api, "/"), Key: getenv("AUTHZBENCH_API_KEY"), Consistency: o.consistency}
	needAPI := func(name string) error {
		if o.api == "" {
			return fmt.Errorf("%s needs -api", name)
		}
		if api.Key == "" {
			return fmt.Errorf("%s needs the API key in AUTHZBENCH_API_KEY", name)
		}
		return o.keys.Validate()
	}
	var login *ops.Login
	loginOp := func() (*ops.Login, error) {
		if login != nil {
			return login, nil
		}
		if o.loginStart == "" {
			return nil, errors.New("signing in needs -login-start")
		}
		creds, err := parseCredentials(o.loginCreds)
		if err != nil {
			return nil, err
		}
		login = &ops.Login{Client: client, Start: o.loginStart, Credentials: creds, SessionCookie: o.loginCookie,
			UserField: o.loginUserField, PasswordField: o.loginPassField}
		return login, nil
	}
	var mix []load.Weighted
	for i, name := range names {
		var op load.Op
		switch name {
		case "check":
			if err := needAPI(name); err != nil {
				return nil, err
			}
			op = &ops.Check{API: api, Keys: o.keys, Permission: o.permission}
		case "bulk_check":
			if err := needAPI(name); err != nil {
				return nil, err
			}
			if o.bulkItems < 1 || o.bulkItems > 100 {
				return nil, fmt.Errorf("-bulk-items %d, want 1 to 100", o.bulkItems)
			}
			op = &ops.BulkCheck{API: api, Keys: o.keys, Permission: o.permission, Items: o.bulkItems}
		case "lookup":
			if err := needAPI(name); err != nil {
				return nil, err
			}
			op = &ops.Lookup{API: api, Keys: o.keys, Permission: o.permission, Limit: o.lookupLimit}
		case "write":
			if err := needAPI(name); err != nil {
				return nil, err
			}
			op = &ops.Write{API: api, Keys: o.keys, Relation: o.relation}
		case "forward_auth":
			if o.forwardURL == "" || o.forwardHost == "" {
				return nil, errors.New("forward_auth needs -forward-url and -forward-host")
			}
			fa := &ops.ForwardAuth{Client: client, URL: o.forwardURL, Host: o.forwardHost, Expect: o.forwardExpect}
			for _, p := range strings.Split(o.forwardPaths, ",") {
				if p = strings.TrimSpace(p); p != "" {
					fa.Paths = append(fa.Paths, p)
				}
			}
			if o.sessionsFile != "" {
				s, err := readSessions(o.sessionsFile)
				if err != nil {
					return nil, err
				}
				fa.Sessions = append(fa.Sessions, s...)
			}
			if o.sessions > 0 {
				l, err := loginOp()
				if err != nil {
					return nil, err
				}
				rng := rand.New(rand.NewPCG(o.seed, 0x5e55))
				for n := range o.sessions {
					c, err := l.Session(ctx, rng)
					if err != nil {
						return nil, fmt.Errorf("signing in for session %d: %w", n+1, err)
					}
					fa.Sessions = append(fa.Sessions, c)
				}
			}
			op = fa
		case "oidc_login":
			l, err := loginOp()
			if err != nil {
				return nil, err
			}
			op = l
		case "mcp_call":
			if o.mcpURL == "" || o.mcpTools == "" {
				return nil, errors.New("mcp_call needs -mcp-url and -mcp-tools")
			}
			raw, err := readArg(o.mcpTools)
			if err != nil {
				return nil, err
			}
			var tools []ops.Tool
			if err := json.Unmarshal([]byte(raw), &tools); err != nil || len(tools) == 0 {
				return nil, fmt.Errorf("-mcp-tools: want a non-empty JSON list of {name, arguments}: %v", err)
			}
			for _, t := range tools {
				if t.Name == "" {
					return nil, errors.New("-mcp-tools: a tool has no name")
				}
			}
			if o.mcpProtocol != ops.MCPStateless && o.mcpProtocol != ops.MCPSession {
				return nil, fmt.Errorf("-mcp-protocol %q, want %s or %s", o.mcpProtocol, ops.MCPStateless, ops.MCPSession)
			}
			op = &ops.MCPCall{Client: client, URL: o.mcpURL, Key: getenv("AUTHZBENCH_MCP_KEY"), Tools: tools, Protocol: o.mcpProtocol}
		default:
			return nil, fmt.Errorf("mix: unknown operation %q", name)
		}
		mix = append(mix, load.Weighted{Op: op, Weight: weights[i]})
	}
	return mix, nil
}

// Summary is a histogram's headline figures, in nanoseconds.
type Summary struct {
	P50   int64          `json:"p50_ns"`
	P90   int64          `json:"p90_ns"`
	P99   int64          `json:"p99_ns"`
	P999  int64          `json:"p999_ns"`
	Max   int64          `json:"max_ns"`
	Mean  int64          `json:"mean_ns"`
	Count int64          `json:"count"`
	Hist  *hdr.Histogram `json:"histogram"`
}

func summarize(h *hdr.Histogram) Summary {
	return Summary{P50: int64(h.Quantile(0.50)), P90: int64(h.Quantile(0.90)), P99: int64(h.Quantile(0.99)),
		P999: int64(h.Quantile(0.999)), Max: int64(h.Max()), Mean: int64(h.Mean()), Count: h.Count(), Hist: h}
}

// OpReport is one operation in the result file.
type OpReport struct {
	Name         string   `json:"name"`
	Weight       int      `json:"weight"`
	OK           int64    `json:"ok"`
	Errors       int64    `json:"errors"`
	ErrorSamples []string `json:"error_samples,omitempty"`
	Throughput   float64  `json:"throughput_per_s"`
	// Latency counts from when a request was due (corrected for
	// coordinated omission); Service from when it was sent.
	Latency Summary `json:"latency"`
	Service Summary `json:"service"`
}

// Report is the result file.
type Report struct {
	Label     string     `json:"label,omitempty"`
	StartedAt time.Time  `json:"started_at"`
	Config    ReportConf `json:"config"`
	Scheduled int64      `json:"scheduled"`
	Sent      int64      `json:"sent"`
	Unsent    int64      `json:"unsent"`
	MaxLag    int64      `json:"max_lag_ns"`
	Elapsed   int64      `json:"elapsed_ns"`
	Achieved  float64    `json:"achieved_per_s"`
	Ops       []OpReport `json:"ops"`
	Total     OpReport   `json:"total"`
	Pass      bool       `json:"pass"`
}

// ReportConf is the run's settings, enough to repeat it.
type ReportConf struct {
	Args     []string `json:"args"`
	Rate     float64  `json:"rate_per_s"`
	Warmup   string   `json:"warmup"`
	Duration string   `json:"duration"`
	Workers  int      `json:"workers"`
	Arrival  string   `json:"arrival"`
	Seed     uint64   `json:"seed"`
}

func report(o *options, args []string, weights []int, res *load.Result) *Report {
	r := &Report{Label: o.label, StartedAt: res.Start.UTC(), Scheduled: res.Scheduled, Sent: res.Sent, Unsent: res.Unsent,
		MaxLag: int64(res.Lag), Elapsed: int64(res.Elapsed), Achieved: res.Achieved(),
		Config: ReportConf{Args: args, Rate: o.rate, Warmup: o.warmup.String(), Duration: o.duration.String(),
			Workers: o.workers, Arrival: o.arrival, Seed: o.seed}}
	secs := res.Elapsed.Seconds()
	opReport := func(x *load.OpResult, w int) OpReport {
		return OpReport{Name: x.Name, Weight: w, OK: x.OK, Errors: x.Errors, ErrorSamples: x.ErrorSamples,
			Throughput: float64(x.OK+x.Errors) / secs, Latency: summarize(x.Latency), Service: summarize(x.Service)}
	}
	sum := 0
	for i, x := range res.Ops {
		r.Ops = append(r.Ops, opReport(x, weights[i]))
		sum += weights[i]
	}
	r.Total = opReport(res.Total(), sum)
	errRate := 0.0
	if n := r.Total.OK + r.Total.Errors; n > 0 {
		errRate = float64(r.Total.Errors) / float64(n)
	}
	r.Pass = res.Unsent == 0 && r.Total.OK > 0 && errRate <= o.maxErrorRate
	return r
}

func ms(ns int64) string { return strconv.FormatFloat(float64(ns)/1e6, 'f', 3, 64) }

func printReport(w io.Writer, r *Report) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "operation\trequests\terrors\tper s\tp50 ms\tp90 ms\tp99 ms\tp99.9 ms\tmax ms\tservice p99 ms\t")
	for _, o := range append(r.Ops, r.Total) {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%.1f\t%s\t%s\t%s\t%s\t%s\t%s\t\n", o.Name, o.OK+o.Errors, o.Errors, o.Throughput,
			ms(o.Latency.P50), ms(o.Latency.P90), ms(o.Latency.P99), ms(o.Latency.P999), ms(o.Latency.Max), ms(o.Service.P99))
	}
	tw.Flush()
	fmt.Fprintf(w, "offered %.1f/s, achieved %.1f/s; %d due, %d sent, %d unsent; largest send lag %s\n",
		r.Config.Rate, r.Achieved, r.Scheduled, r.Sent, r.Unsent, time.Duration(r.MaxLag))
	for _, o := range r.Ops {
		for _, s := range o.ErrorSamples {
			fmt.Fprintf(w, "%s error: %s\n", o.Name, s)
		}
	}
	if r.Pass {
		fmt.Fprintln(w, "pass")
	} else {
		fmt.Fprintln(w, "FAIL: the run did not keep up or had too many errors")
	}
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	o, err := parse(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "authzbench:", err)
		return 2
	}
	names, weights, err := parseMix(o.mix)
	if err != nil {
		fmt.Fprintln(stderr, "authzbench:", err)
		return 2
	}
	mix, err := build(ctx, o, getenv, names, weights)
	if err != nil {
		fmt.Fprintln(stderr, "authzbench:", err)
		return 2
	}
	res, err := load.Run(ctx, load.Config{Mix: mix, Rate: o.rate, Warmup: o.warmup, Duration: o.duration,
		Workers: o.workers, Backlog: o.backlog, Drain: o.drain, Arrival: load.Arrival(o.arrival),
		Seed: o.seed, Timeout: o.timeout})
	if err != nil {
		fmt.Fprintln(stderr, "authzbench:", err)
		return 2
	}
	r := report(o, args, weights, res)
	printReport(stdout, r)
	if o.out != "" {
		b, err := json.MarshalIndent(r, "", "  ")
		if err == nil {
			err = os.WriteFile(o.out, append(b, '\n'), 0o644)
		}
		if err != nil {
			fmt.Fprintln(stderr, "authzbench:", err)
			return 2
		}
	}
	if !r.Pass {
		return 1
	}
	return 0
}
