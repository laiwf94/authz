package gateway

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/laiwf94/authz/internal/authn/check"
	"github.com/laiwf94/authz/internal/authn/config"
)

// Exit codes of "authz gateway check".
const (
	checkOK       = 0
	checkProblems = 1
	checkUsage    = 2
)

// runCheck is "wicket check" under its old name; see checkCmd.
func runCheck(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	return checkCmd(ctx, LegacyName, args, getenv, stdout, stderr)
}

// checkCmd implements "PROG check [-online] [-timeout d] [file]": it
// validates a configuration without starting the gateway, prints every
// problem as "file:line:col: severity: path: message", and exits 1 when
// there are errors. Warnings alone exit 0.
func checkCmd(ctx context.Context, prog string, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	online := fs.Bool("online", false, "also fetch provider metadata: OpenID discovery and signing keys, SAML metadata URLs")
	timeout := fs.Duration("timeout", check.DefaultTimeout, "time limit for each provider's online checks")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: %s check [-online] [-timeout 10s] [config.json]\n", prog)
		fmt.Fprintln(stderr, "Checks a configuration file (default $WICKET_CONFIG) without starting the gateway.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return checkOK
		}
		return checkUsage
	}
	path := getenv("WICKET_CONFIG")
	switch fs.NArg() {
	case 0:
	case 1:
		path = fs.Arg(0)
	default:
		fs.Usage()
		return checkUsage
	}
	if path == "" {
		fmt.Fprintf(stderr, "%s check: name a config file or set WICKET_CONFIG\n", prog)
		return checkUsage
	}
	if *timeout <= 0 || *timeout > 5*time.Minute {
		fmt.Fprintf(stderr, "%s check: -timeout must be between 1ns and 5m\n", prog)
		return checkUsage
	}
	r := check.File(ctx, path, check.Options{Getenv: getenv, Online: *online, Timeout: *timeout})
	for _, p := range r.Problems {
		loc := path
		if p.Line > 0 {
			loc = fmt.Sprintf("%s:%d:%d", path, p.Line, p.Column)
		}
		fmt.Fprintf(stdout, "%s: %s: %s: %s\n", loc, p.Severity, p.Path, p.Message)
	}
	errs, warns := r.Problems.Count(config.SeverityError), r.Problems.Count(config.SeverityWarning)
	mode := "offline"
	if *online {
		mode = "online"
	}
	if errs > 0 {
		fmt.Fprintf(stdout, "%s: %s, %s (%s checks)\n", path, plural(errs, "error"), plural(warns, "warning"), mode)
		return checkProblems
	}
	fmt.Fprintf(stdout, "%s: ok, %s and %s, %s (%s checks)\n", path, plural(len(r.Config.Providers), "provider"),
		plural(len(r.Config.Apps), "app"), plural(warns, "warning"), mode)
	return checkOK
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
