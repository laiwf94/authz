// Command authzdata writes the benchmark's seeded datasets (bench/datasets)
// and loads them into a running authz.
//
//	authzdata manifest -size 1m                  counts and authzbench flags, as JSON
//	authzdata schema [-format authz|openfga]     the dataset's schema or OpenFGA model
//	authzdata graph -size 1m [-format tuples|openfga] [-from N -to N] [-o FILE]
//	authzdata load -size 1m -api URL [-target authz|spicedb|openfga] [-schema] [-batch N] [-workers 4] [-from N -to N]
//	authzdata crosscheck -size 1m [-n 1000] -authz URL [-spicedb URL] [-openfga URL]
//	authzdata users -size 1m [-n N] [-format json|credentials] [-o FILE]
//	authzdata import -size 1m -n N -target keycloak -api URL [-workers 4] [-verify 100]
//	authzdata tools [-n 100] [-calls 0] [-o FILE]
//
// Every subcommand takes -seed (default 1); a size and a seed name one
// dataset everywhere. -size is 1m, 10m, 100m or a count such as 250k.
// Keys come from the environment, never a flag: AUTHZBENCH_API_KEY for
// authz, AUTHZBENCH_SPICEDB_KEY and AUTHZBENCH_OPENFGA_KEY for the
// products in bench/products. The exit
// status is 0 on success, 1 when writing or loading failed, 2 for bad
// arguments.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/laiwf94/authz/bench/datasets"
	"github.com/laiwf94/authz/bench/products"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `usage: authzdata COMMAND [flags]

commands:
  manifest  print a graph's counts and the authzbench flags for it, as JSON
  schema    print the dataset's schema (-format authz) or OpenFGA model (-format openfga)
  graph     write a graph's relationships, one per line
  load      write a graph into a running authz, SpiceDB or OpenFGA through its API
  crosscheck ask authz and the products the same sampled checks; fail on a disagreement
  users     write the sign-in population of a graph's users
  import    set up an identity provider and import the sign-in population into it
  tools     write an MCP tool catalog, or with -calls, calls of it for authzbench

run authzdata COMMAND -h for a command's flags
`

// usageError is a bad argument: exit status 2.
type usageError struct{ error }

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	err := command(ctx, args[0], args[1:], getenv, stdout, stderr)
	var ue usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &ue):
		fmt.Fprintln(stderr, "authzdata:", err)
		return 2
	default:
		fmt.Fprintln(stderr, "authzdata:", err)
		return 1
	}
}

type flags struct {
	fs       *flag.FlagSet
	size     string
	seed     uint64
	out      string
	format   string
	from, to int64
}

func newFlags(name string, stderr io.Writer, size bool, format string) *flags {
	f := &flags{fs: flag.NewFlagSet("authzdata "+name, flag.ContinueOnError), to: -1}
	f.fs.SetOutput(stderr)
	f.fs.Uint64Var(&f.seed, "seed", 1, "dataset seed")
	if size {
		f.fs.StringVar(&f.size, "size", "1m", "relationships: 1m, 10m, 100m or a count such as 250k")
	}
	if format != "" {
		f.fs.StringVar(&f.format, "format", format, "output format")
	}
	return f
}

func (f *flags) output() {
	f.fs.StringVar(&f.out, "o", "", "write to this file instead of standard output")
}

func (f *flags) ranges() {
	f.fs.Int64Var(&f.from, "from", 0, "first relationship number")
	f.fs.Int64Var(&f.to, "to", -1, "relationship number to stop before (-1: the end)")
}

func (f *flags) parse(args []string) error {
	if err := f.fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err}
	}
	if f.fs.NArg() > 0 {
		return usageError{fmt.Errorf("unexpected argument %q", f.fs.Arg(0))}
	}
	return nil
}

func (f *flags) graph() (datasets.Graph, error) {
	n, err := datasets.ParseSize(f.size)
	if err != nil {
		return datasets.Graph{}, usageError{err}
	}
	g, err := datasets.Size(n, f.seed)
	if err != nil {
		return g, usageError{err}
	}
	if f.to == -1 {
		f.to = g.Count()
	}
	if f.from < 0 || f.to < f.from || f.to > g.Count() {
		return g, usageError{fmt.Errorf("-from %d -to %d: want 0 <= from <= to <= %d", f.from, f.to, g.Count())}
	}
	return g, nil
}

// write runs fn on the output and closes it, keeping the first error.
func (f *flags) write(stdout io.Writer, fn func(io.Writer) error) (err error) {
	w := stdout
	if f.out != "" {
		file, err := os.Create(f.out)
		if err != nil {
			return err
		}
		defer func() {
			if cerr := file.Close(); err == nil {
				err = cerr
			}
		}()
		w = file
	}
	return fn(w)
}

func command(ctx context.Context, name string, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	switch name {
	case "manifest":
		f := newFlags(name, stderr, true, "")
		if err := f.parse(args); err != nil {
			return err
		}
		g, err := f.graph()
		if err != nil {
			return err
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(g.Describe())
	case "schema":
		f := newFlags(name, stderr, false, "authz")
		if err := f.parse(args); err != nil {
			return err
		}
		switch f.format {
		case "authz":
			_, err := io.WriteString(stdout, datasets.Schema)
			return err
		case "openfga":
			_, err := io.WriteString(stdout, datasets.OpenFGAModel)
			return err
		}
		return usageError{fmt.Errorf("-format %q: want authz or openfga", f.format)}
	case "graph":
		f := newFlags(name, stderr, true, datasets.FormatTuples)
		f.output()
		f.ranges()
		if err := f.parse(args); err != nil {
			return err
		}
		g, err := f.graph()
		if err != nil {
			return err
		}
		if f.format != datasets.FormatTuples && f.format != datasets.FormatOpenFGA {
			return usageError{fmt.Errorf("-format %q: want %s or %s", f.format, datasets.FormatTuples, datasets.FormatOpenFGA)}
		}
		return f.write(stdout, func(w io.Writer) error {
			_, err := datasets.WriteGraph(w, g, f.format, f.from, f.to)
			return err
		})
	case "load":
		return load(ctx, args, getenv, stdout, stderr)
	case "crosscheck":
		return crosscheck(ctx, args, getenv, stdout, stderr)
	case "users":
		f := newFlags(name, stderr, true, datasets.FormatUsersJSON)
		f.output()
		n := f.fs.Int("n", -1, "users to write, from u0 (-1: every user of the graph)")
		if err := f.parse(args); err != nil {
			return err
		}
		g, err := f.graph()
		if err != nil {
			return err
		}
		if *n == -1 {
			*n = g.Users
		}
		if *n < 0 || *n > g.Users {
			return usageError{fmt.Errorf("-n %d: the graph has %d users", *n, g.Users)}
		}
		if f.format != datasets.FormatUsersJSON && f.format != datasets.FormatCredentials {
			return usageError{fmt.Errorf("-format %q: want %s or %s", f.format, datasets.FormatUsersJSON, datasets.FormatCredentials)}
		}
		return f.write(stdout, func(w io.Writer) error { return datasets.WriteUsers(w, g, *n, f.format) })
	case "import":
		return importUsers(ctx, args, getenv, stdout, stderr)
	case "tools":
		f := newFlags(name, stderr, false, "")
		f.output()
		n := f.fs.Int("n", 100, "tools in the catalog")
		calls := f.fs.Int("calls", 0, "write this many calls of the catalog (authzbench -mcp-tools) instead of the catalog")
		if err := f.parse(args); err != nil {
			return err
		}
		tools, err := datasets.Catalog(*n, f.seed)
		if err != nil {
			return usageError{err}
		}
		if *calls < 0 {
			return usageError{fmt.Errorf("-calls %d: want 0 or more", *calls)}
		}
		var v any = map[string]any{"tools": tools}
		if *calls > 0 {
			if v, err = datasets.Calls(tools, *calls, f.seed); err != nil {
				return err
			}
		}
		return f.write(stdout, func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", " ")
			return enc.Encode(v)
		})
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usage)
		return nil
	}
	return usageError{fmt.Errorf("unknown command %q", name)}
}

// keyEnv is the variable each target's key is read from.
var keyEnv = map[string]string{"authz": "AUTHZBENCH_API_KEY", "spicedb": "AUTHZBENCH_SPICEDB_KEY", "openfga": "AUTHZBENCH_OPENFGA_KEY"}

// openfgaStore is the store the dataset is loaded into, so that load and
// crosscheck find the same one.
const openfgaStore = "authz-bench"

// target returns the product at url, its key read from the environment.
func target(name, url string, getenv func(string) string) (products.Target, error) {
	env, ok := keyEnv[name]
	if !ok {
		return nil, usageError{fmt.Errorf("target %q: want authz, spicedb or openfga", name)}
	}
	key := getenv(env)
	if url == "" || key == "" {
		return nil, usageError{fmt.Errorf("%s needs its URL and the key in %s", name, env)}
	}
	switch name {
	case "spicedb":
		return products.NewSpiceDB(nil, url, key), nil
	case "openfga":
		return products.NewOpenFGA(nil, url, key, openfgaStore), nil
	}
	return products.NewAuthz(nil, url, key), nil
}

func load(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	f := newFlags("load", stderr, true, "")
	f.ranges()
	api := f.fs.String("api", "", "API base URL, such as http://127.0.0.1:8080")
	name := f.fs.String("target", "authz", "the product at -api: authz, spicedb or openfga")
	schema := f.fs.Bool("schema", false, "write the dataset's schema first (OpenFGA: the store and model, which a load always needs)")
	batch := f.fs.Int("batch", 0, "relationships per write (0: the most the product takes: 1000, or 100 for OpenFGA)")
	workers := f.fs.Int("workers", 4, "writes in flight")
	if err := f.parse(args); err != nil {
		return err
	}
	g, err := f.graph()
	if err != nil {
		return err
	}
	t, err := target(*name, *api, getenv)
	if err != nil {
		return err
	}
	most := datasets.MaxBatch
	if *name == "openfga" {
		most = products.OpenFGAMaxBatch
	}
	if *batch < 0 || *batch > most || *workers < 1 {
		return usageError{fmt.Errorf("-batch %d -workers %d: want 0 to %d and at least 1", *batch, most, *workers)}
	}
	if *schema || *name == "openfga" {
		if err := t.Setup(ctx); err != nil {
			return err
		}
	}
	l := t.Loader()
	l.Batch, l.Workers = *batch, *workers
	res, err := l.Load(ctx, g, f.from, f.to)
	fmt.Fprintf(stdout, "loaded %d relationships in %d writes (%d retried) in %v: %.0f/s\n",
		res.Relationships, res.Writes, res.Retries, res.Elapsed.Round(1e6), res.PerSecond())
	return err
}

// Keycloak's defaults are compose.yaml's: its bootstrap admin, and the
// addresses oauth2-proxy and Keycloak's own account page answer at.
const (
	keycloakAdmin    = "bench-admin"
	keycloakRedirect = "http://127.0.0.1:14180/oauth2/callback,http://127.0.0.1:18180/realms/bench/account/*"
)

func importUsers(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	f := newFlags("import", stderr, true, "")
	n := f.fs.Int("n", 1000, "users to import, from u0 (-1: every user of the graph)")
	name := f.fs.String("target", "keycloak", "the identity provider at -api: keycloak")
	api := f.fs.String("api", "", "base URL, such as http://127.0.0.1:18180")
	admin := f.fs.String("admin", keycloakAdmin, "admin user of the master realm; its password is read from AUTHZBENCH_KEYCLOAK_ADMIN_PASSWORD")
	realm := f.fs.String("realm", "bench", "realm to create or update")
	client := f.fs.String("client", "bench-proxy", "OpenID Connect client to create or update; its secret is read from AUTHZBENCH_KEYCLOAK_CLIENT_SECRET")
	redirects := f.fs.String("redirect-uris", keycloakRedirect, "comma-separated redirect URIs of the client")
	batch := f.fs.Int("batch", products.KeycloakBatch, "users per partial import")
	workers := f.fs.Int("workers", 4, "imports in flight")
	verify := f.fs.Int("verify", 100, "users to read back and compare afterwards (0: none, -1: every one)")
	if err := f.parse(args); err != nil {
		return err
	}
	g, err := f.graph()
	if err != nil {
		return err
	}
	if *n == -1 {
		*n = g.Users
	}
	switch {
	case *name != "keycloak":
		return usageError{fmt.Errorf("-target %q: want keycloak", *name)}
	case *n < 0 || *n > g.Users:
		return usageError{fmt.Errorf("-n %d: the graph has %d users", *n, g.Users)}
	case *batch < 1 || *workers < 1 || *verify < -1:
		return usageError{fmt.Errorf("-batch %d -workers %d -verify %d: want at least 1, 1 and -1", *batch, *workers, *verify)}
	}
	kc := &products.Keycloak{URL: *api, AdminUser: *admin, AdminPassword: getenv("AUTHZBENCH_KEYCLOAK_ADMIN_PASSWORD"),
		Realm: *realm, ClientID: *client, ClientSecret: getenv("AUTHZBENCH_KEYCLOAK_CLIENT_SECRET"),
		RedirectURIs: strings.Split(*redirects, ",")}
	if *api == "" || kc.AdminPassword == "" || kc.ClientSecret == "" {
		return usageError{errors.New("keycloak needs -api, AUTHZBENCH_KEYCLOAK_ADMIN_PASSWORD and AUTHZBENCH_KEYCLOAK_CLIENT_SECRET")}
	}
	if err := kc.Setup(ctx); err != nil {
		return err
	}
	res, err := kc.ImportUsers(ctx, g, *n, *batch, *workers)
	fmt.Fprintf(stdout, "imported %d users in %d groups with %d partial imports (%d retried) in %v: %d added, %d skipped, %.0f users/s\n",
		res.Users, res.Groups, res.Imports, res.Retries, res.Elapsed.Round(1e6), res.Added, res.Skipped,
		float64(res.Users)/max(res.Elapsed.Seconds(), 1e-9))
	if err != nil || *verify == 0 {
		return err
	}
	sample := *verify
	if sample == -1 {
		sample = 0
	}
	checked, err := kc.VerifyUsers(ctx, g, *n, sample)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "verified %d users: email, enabled and groups as in the graph\n", checked)
	return nil
}

func crosscheck(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	f := newFlags("crosscheck", stderr, true, "")
	n := f.fs.Int("n", 1000, "questions to ask every target")
	workers := f.fs.Int("workers", 8, "questions in flight")
	urls := map[string]*string{}
	for _, name := range []string{"authz", "spicedb", "openfga"} {
		urls[name] = f.fs.String(name, "", name+" API base URL; leave empty to skip it")
	}
	if err := f.parse(args); err != nil {
		return err
	}
	g, err := f.graph()
	if err != nil {
		return err
	}
	if *n < 1 || *workers < 1 {
		return usageError{fmt.Errorf("-n %d -workers %d: want at least 1 each", *n, *workers)}
	}
	var targets []products.Target
	for _, name := range []string{"authz", "spicedb", "openfga"} {
		if *urls[name] == "" {
			continue
		}
		t, err := target(name, *urls[name], getenv)
		if err != nil {
			return err
		}
		if o, ok := t.(*products.OpenFGA); ok {
			// Finds the store and model a load made (and makes them if
			// there is none, which answers every question no).
			if err := o.Setup(ctx); err != nil {
				return err
			}
		}
		targets = append(targets, t)
	}
	if len(targets) < 2 {
		return usageError{errors.New("crosscheck needs two of -authz, -spicedb and -openfga")}
	}
	rep, err := products.CrossCheck(ctx, targets, products.Sample(g, *n, f.seed), *workers)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, rep)
	if len(rep.Disagreements) > 0 {
		return fmt.Errorf("%d of %d questions answered differently", len(rep.Disagreements), rep.Questions)
	}
	return nil
}
