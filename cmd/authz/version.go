package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// version is set at release time with -ldflags "-X main.version=v1.2.3".
// When it is empty the module version from the build information is used.
var version string

// buildInfo describes the running binary.
type buildInfo struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	Time     string `json:"time,omitempty"`
	Modified bool   `json:"modified,omitempty"`
	Go       string `json:"go"`
	Platform string `json:"platform"`
}

func currentBuild(read func() (*debug.BuildInfo, bool), stamped string) buildInfo {
	b := buildInfo{Version: stamped, Go: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH}
	bi, ok := read()
	if !ok {
		if b.Version == "" {
			b.Version = "unknown"
		}
		return b
	}
	if b.Version == "" {
		b.Version = bi.Main.Version
	}
	if b.Version == "" {
		b.Version = "(devel)"
	}
	if bi.GoVersion != "" {
		b.Go = bi.GoVersion
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			b.Revision = s.Value
		case "vcs.time":
			b.Time = s.Value
		case "vcs.modified":
			b.Modified = s.Value == "true"
		}
	}
	return b
}

func (b buildInfo) String() string {
	s := "authz " + b.Version
	if b.Revision != "" {
		rev := b.Revision
		if len(rev) > 12 {
			rev = rev[:12]
		}
		if b.Modified {
			rev += "+modified"
		}
		s += " (" + rev
		if b.Time != "" {
			s += ", " + b.Time
		}
		s += ")"
	}
	return s + " " + b.Go + " " + b.Platform
}

const versionUsage = `usage: authz version [-json]

Prints the version, source revision and Go toolchain of this build.
`

// runVersion is "authz version". It exits 0, or 2 for a usage error.
func runVersion(_ context.Context, args []string, _ func(string) string, _ io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print the build information as one JSON object")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), versionUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "authz version: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	b := currentBuild(debug.ReadBuildInfo, version)
	if *asJSON {
		out, _ := json.Marshal(b)
		fmt.Fprintf(stdout, "%s\n", out)
		return exitOK
	}
	fmt.Fprintln(stdout, b)
	return exitOK
}
