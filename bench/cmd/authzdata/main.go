// Command authzdata writes the benchmark's seeded datasets (bench/datasets)
// and loads them into a running authz.
//
//	authzdata manifest -size 1m                  counts and authzbench flags, as JSON
//	authzdata schema [-format authz|openfga]     the dataset's schema or OpenFGA model
//	authzdata graph -size 1m [-format tuples|openfga] [-from N -to N] [-o FILE]
//	authzdata load -size 1m -api URL [-schema] [-batch 1000] [-workers 4] [-from N -to N]
//	authzdata users -size 1m [-n N] [-format json|credentials] [-o FILE]
//	authzdata tools [-n 100] [-calls 0] [-o FILE]
//
// Every subcommand takes -seed (default 1); a size and a seed name one
// dataset everywhere. -size is 1m, 10m, 100m or a count such as 250k. The
// load's API key comes from AUTHZBENCH_API_KEY, never a flag. The exit
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
	"syscall"

	"github.com/laiwf94/authz/bench/datasets"
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
  load      write a graph into a running authz through its API
  users     write the sign-in population of a graph's users
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

func load(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	f := newFlags("load", stderr, true, "")
	f.ranges()
	api := f.fs.String("api", "", "authorization API base URL, such as http://127.0.0.1:8080")
	schema := f.fs.Bool("schema", false, "write the dataset's schema first")
	batch := f.fs.Int("batch", datasets.MaxBatch, "relationships per write")
	workers := f.fs.Int("workers", 4, "writes in flight")
	if err := f.parse(args); err != nil {
		return err
	}
	g, err := f.graph()
	if err != nil {
		return err
	}
	key := getenv("AUTHZBENCH_API_KEY")
	if *api == "" || key == "" {
		return usageError{errors.New("load needs -api and the API key in AUTHZBENCH_API_KEY")}
	}
	if *batch < 1 || *batch > datasets.MaxBatch || *workers < 1 {
		return usageError{fmt.Errorf("-batch %d -workers %d: want 1 to %d and at least 1", *batch, datasets.MaxBatch, *workers)}
	}
	l := &datasets.Loader{URL: *api, Key: key, Batch: *batch, Workers: *workers}
	if *schema {
		if err := l.PutSchema(ctx, datasets.Schema); err != nil {
			return err
		}
	}
	res, err := l.Load(ctx, g, f.from, f.to)
	fmt.Fprintf(stdout, "loaded %d relationships in %d writes (%d retried) in %v: %.0f/s\n",
		res.Relationships, res.Writes, res.Retries, res.Elapsed.Round(1e6), res.PerSecond())
	return err
}
