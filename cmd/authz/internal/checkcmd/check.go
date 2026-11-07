// Package checkcmd implements "authz check": it validates what authz would
// start with, without starting anything, and prints every problem it finds
// rather than stopping at the first.
package checkcmd

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/laiwf94/authz/cmd/authz/internal/serve"
	"github.com/laiwf94/authz/internal/authn/check"
	"github.com/laiwf94/authz/internal/authz/schema"
	"github.com/laiwf94/authz/internal/authz/store"
)

// Summary is the one-line description shown in "authz help".
const Summary = "validate the platform config file, the serve environment, schema files and relationship files"

// Exit codes of "authz check".
const (
	OK       = 0 // everything checked is valid
	Problems = 1 // at least one problem was printed
	Usage    = 2 // bad flags or arguments
)

// maxLine bounds one line of a relationships file. A relationship is at most
// a few hundred bytes; anything longer is reported rather than buffered.
const maxLine = 64 << 10

const usage = `usage: authz check [-config file [-online] [-timeout 10s]] [-serve] [-schema file] [-relationships file]

Validates configuration without starting anything and prints every problem
as "where: error: message". At least one flag is required.

  -config file         the platform configuration file: its serve, gateway and mcp
                       sections with the AUTHZ_* overrides and the secrets they
                       reference, each problem as "file:line:col: severity: path: message"
                       (or "VARIABLE: severity: path: message" for an override)
  -online              with -config, also fetch the gateway's provider metadata
  -timeout d           time limit for each provider's online checks (default 10s)
  -serve               the GRANTD_* environment "authz serve" would start with
  -schema file         a schema file, as PUT /v1/schema would accept it
  -relationships file  one relationship per line (type:id#relation@type:id[#relation]);
                       blank lines and lines starting with // are skipped. With
                       -schema, each one must also be allowed by that schema.

A file of "-" is read from standard input. Exit codes: 0 valid, 1 problems
found, 2 usage error.
`

// Run is the "authz check" subcommand.
func Run(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	env := fs.Bool("serve", false, "validate the GRANTD_* environment of authz serve")
	schemaFile := fs.String("schema", "", "schema `file` to validate")
	relFile := fs.String("relationships", "", "relationships `file` to validate, one per line")
	configFile := fs.String("config", "", "platform configuration `file` to validate")
	online := fs.Bool("online", false, "with -config, also fetch the gateway's provider metadata")
	timeout := fs.Duration("timeout", check.DefaultTimeout, "time limit for each provider's online checks")
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return OK
		}
		return Usage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "authz check: unexpected argument %q\n", fs.Arg(0))
		return Usage
	}
	if !*env && *schemaFile == "" && *relFile == "" && *configFile == "" {
		fmt.Fprint(stderr, "authz check: nothing to check; pass -config, -serve, -schema or -relationships\n")
		return Usage
	}
	if *configFile == "" && (*online || *timeout != check.DefaultTimeout) {
		fmt.Fprint(stderr, "authz check: -online and -timeout apply to -config\n")
		return Usage
	}
	if *timeout <= 0 || *timeout > 5*time.Minute {
		fmt.Fprint(stderr, "authz check: -timeout must be between 1ns and 5m\n")
		return Usage
	}
	if *schemaFile == "-" && *relFile == "-" {
		fmt.Fprint(stderr, "authz check: only one of -schema and -relationships can read standard input\n")
		return Usage
	}
	open := func(name string) (io.ReadCloser, error) {
		if name == "-" {
			return io.NopCloser(stdin), nil
		}
		return os.Open(name)
	}

	r := &report{out: stdout}
	if *configFile != "" {
		checkConfig(ctx, r, *configFile, getenv, check.Options{Getenv: getenv, Online: *online, Timeout: *timeout})
	}
	if *env {
		errs := serve.Check(getenv)
		for _, err := range errs {
			r.problem("env", err.Error())
		}
		if len(errs) == 0 {
			r.ok("env: serve environment is valid")
		}
	}
	var sc *schema.Schema
	if *schemaFile != "" {
		sc = checkSchema(r, *schemaFile, open)
		if sc == nil && *relFile != "" {
			// Relationships are still checked for syntax, but schema rules
			// cannot be applied without a valid schema.
			r.note(*relFile + ": schema is invalid; checking syntax only")
		}
	}
	if *relFile != "" {
		checkRelationships(r, *relFile, open, sc)
	}
	if r.problems > 0 {
		fmt.Fprintf(stdout, "%d %s\n", r.problems, plural(r.problems, "problem", "problems"))
		return Problems
	}
	return OK
}

type report struct {
	out      io.Writer
	problems int
}

func (r *report) problem(where, msg string) {
	r.problems++
	fmt.Fprintf(r.out, "%s: error: %s\n", where, msg)
}

func (r *report) warning(where, msg string) {
	fmt.Fprintf(r.out, "%s: warning: %s\n", where, msg)
}

func (r *report) note(msg string) { fmt.Fprintf(r.out, "%s\n", msg) }
func (r *report) ok(msg string)   { fmt.Fprintf(r.out, "%s\n", msg) }

func checkSchema(r *report, name string, open func(string) (io.ReadCloser, error)) *schema.Schema {
	f, err := open(name)
	if err != nil {
		r.problem(name, err.Error())
		return nil
	}
	defer f.Close()
	// One byte more than the limit lets Parse report the size problem itself.
	src, err := io.ReadAll(io.LimitReader(f, schema.MaxSchemaBytes+1))
	if err != nil {
		r.problem(name, err.Error())
		return nil
	}
	sc, err := schema.Parse(string(src))
	if err != nil {
		var se *schema.Error
		switch {
		case errors.As(err, &se) && se.Line > 0:
			r.problem(fmt.Sprintf("%s:%d:%d", name, se.Line, se.Col), se.Msg)
		case errors.As(err, &se):
			r.problem(name, se.Msg)
		default:
			r.problem(name, err.Error())
		}
		return nil
	}
	r.ok(fmt.Sprintf("%s: schema is valid: %d %s", name, len(sc.Order), plural(len(sc.Order), "definition", "definitions")))
	return sc
}

func checkRelationships(r *report, name string, open func(string) (io.ReadCloser, error), sc *schema.Schema) {
	f, err := open(name)
	if err != nil {
		r.problem(name, err.Error())
		return
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 4096)
	n, count, before := 0, 0, r.problems
	for {
		line, tooLong, err := readLine(br)
		if err == io.EOF {
			break
		}
		n++
		where := fmt.Sprintf("%s:%d", name, n)
		if err != nil {
			r.problem(where, err.Error())
			return
		}
		if tooLong {
			r.problem(where, fmt.Sprintf("line is longer than %d bytes", maxLine))
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		count++
		rel, err := store.ParseRelationship(line)
		if err == nil && sc != nil {
			err = store.CheckAgainst(sc, rel)
		}
		if err != nil {
			r.problem(where, strings.TrimPrefix(err.Error(), store.ErrInvalid.Error()+": "))
		}
	}
	if r.problems == before {
		what := "syntax is valid"
		if sc != nil {
			what = "valid against the schema"
		}
		r.ok(fmt.Sprintf("%s: %d %s, %s", name, count, plural(count, "relationship", "relationships"), what))
	}
}

// readLine returns the next line without its newline. A line longer than
// maxLine is consumed and reported as too long instead of being buffered.
func readLine(br *bufio.Reader) (line string, tooLong bool, err error) {
	var b []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil {
			if err == io.EOF && (b != nil || tooLong) {
				return string(b), tooLong, nil
			}
			return "", false, err
		}
		if !tooLong {
			if len(b)+len(chunk) > maxLine {
				tooLong, b = true, nil
			} else {
				b = append(b, chunk...)
			}
		}
		if !isPrefix {
			if b == nil {
				b = []byte{}
			}
			return string(b), tooLong, nil
		}
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
