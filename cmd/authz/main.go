// Command authz is the one binary of the platform. Each part of it is a
// subcommand with its own flags, help text and exit codes:
//
//	authz serve      the authorization API (formerly grantd)
//	authz check      validate configuration and schema files without starting anything
//	authz ctl        talk to a running authz serve: schema, relationships and checks
//	authz mcp        the MCP gateway for AI agents (formerly toolgate)
//	authz version    print the build's version
//
// authz mcpfake, a small MCP server to try the gateway against, runs but is
// left out of the listing. The sign-on gateway registers itself here as it
// moves in. "authz help <command>" prints a subcommand's help.
//
// The dispatcher only picks the subcommand. Everything after its name is
// passed through untouched, so subcommands can nest their own commands
// ("authz ctl schema write file"). The context given to a subcommand is
// cancelled on SIGINT and SIGTERM; SIGHUP is left alone so subcommands that
// reload on it can subscribe to it themselves.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/laiwf94/authz/cmd/authz/internal/checkcmd"
	"github.com/laiwf94/authz/cmd/authz/internal/ctl"
	"github.com/laiwf94/authz/cmd/authz/internal/mcp"
	"github.com/laiwf94/authz/cmd/authz/internal/mcpfake"
	"github.com/laiwf94/authz/cmd/authz/internal/serve"
)

// runFunc runs one subcommand with the arguments after its name and returns
// the process exit code. Subcommands read nothing from globals, so tests can
// drive them in process.
type runFunc func(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int

type command struct {
	name    string
	summary string
	// hidden commands (test and operator helpers) run but are left out of
	// the help listing.
	hidden bool
	run    runFunc
}

// commands is the registry. A track adds its subcommand with one line here.
var commands = []command{
	{name: "serve", summary: serve.Summary, run: serve.Run},
	{name: "check", summary: checkcmd.Summary, run: checkcmd.Run},
	{name: "ctl", summary: ctl.Summary, run: ctl.Run},
	{name: "mcp", summary: mcp.Summary, run: mcp.Run},
	{name: "mcpfake", summary: mcpfake.Summary, hidden: true, run: mcpfake.Run},
	{name: "version", summary: "print the version, revision and Go toolchain of this build", run: runVersion},
}

// Exit codes of the dispatcher itself. Subcommands document their own.
const (
	exitOK    = 0
	exitUsage = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := dispatch(ctx, commands, os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func lookup(cmds []command, name string) (command, bool) {
	for _, c := range cmds {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// dispatch picks the subcommand named by args[0] and runs it with the rest.
func dispatch(ctx context.Context, cmds []command, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr, cmds)
		return exitUsage
	}
	name, rest := args[0], args[1:]
	switch name {
	case "help", "-h", "-help", "--help":
		if len(rest) == 0 {
			usage(stdout, cmds)
			return exitOK
		}
		c, ok := lookup(cmds, rest[0])
		if !ok {
			return unknown(stderr, rest[0])
		}
		// Every subcommand owns a FlagSet, which prints its help for -h.
		return c.run(ctx, []string{"-h"}, getenv, stdin, stdout, stderr)
	case "-version", "--version":
		name = "version"
	}
	c, ok := lookup(cmds, name)
	if !ok {
		return unknown(stderr, name)
	}
	return c.run(ctx, rest, getenv, stdin, stdout, stderr)
}

func unknown(stderr io.Writer, name string) int {
	if strings.HasPrefix(name, "-") {
		fmt.Fprintf(stderr, "authz: flag %s must follow a command; run \"authz help\" for the list\n", name)
	} else {
		fmt.Fprintf(stderr, "authz: unknown command %q; run \"authz help\" for the list\n", name)
	}
	return exitUsage
}

func usage(w io.Writer, cmds []command) {
	shown := make([]command, 0, len(cmds))
	width := 0
	for _, c := range cmds {
		if !c.hidden {
			shown = append(shown, c)
			width = max(width, len(c.name))
		}
	}
	sort.Slice(shown, func(i, j int) bool { return shown[i].name < shown[j].name })
	fmt.Fprint(w, "usage: authz <command> [arguments]\n\nCommands:\n")
	for _, c := range shown {
		fmt.Fprintf(w, "  %-*s  %s\n", width, c.name, c.summary)
	}
	fmt.Fprint(w, "\nRun \"authz help <command>\" or \"authz <command> -h\" for a command's flags.\n")
}
