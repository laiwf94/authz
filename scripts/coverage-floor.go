//go:build ignore

// coverage-floor fails the gate when statement coverage of the whole module
// drops below a floor, and prints the coverage of each tree that went into
// the module so a drop in one of them is visible.
//
//	go run scripts/coverage-floor.go -min PERCENT [-group NAME=PREFIX,...]... [-rest NAME] PROFILE
//
// PROFILE is written by `go test -coverprofile`. The floor in ci.yml is
// 93.5%, the lowest total of the three repositories before the week 1 merge
// (at 41d9bf0: grantd 95.3%, wicket 93.5%, toolgate 96.4%, each measured with
// go test -race -coverprofile ./... in its own module). Statements are
// counted the way go tool cover counts them. Exit status: 0 at or above the
// floor, 1 below it, 2 usage or parse error.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/laiwf94/authz/internal/gate"
)

type groups []gate.Group

func (g *groups) String() string { return fmt.Sprint(*g) }
func (g *groups) Set(s string) error {
	v, err := gate.ParseGroup(s)
	if err == nil {
		*g = append(*g, v)
	}
	return err
}

func main() {
	min := flag.Float64("min", -1, "lowest accepted total coverage, in percent")
	rest := flag.String("rest", "other", "name for files no -group matches")
	var gs groups
	flag.Var(&gs, "group", "NAME=PREFIX[,PREFIX...]: report coverage of these import paths (repeatable)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/coverage-floor.go -min PERCENT [-group NAME=PREFIX,...]... [-rest NAME] PROFILE")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 || *min < 0 || *min > 100 {
		flag.Usage()
		os.Exit(2)
	}
	f, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "coverage-floor:", err)
		os.Exit(2)
	}
	c, err := gate.ParseCoverProfile(f)
	f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "coverage-floor: %s: %v\n", flag.Arg(0), err)
		os.Exit(2)
	}
	if len(gs) > 0 {
		for _, g := range c.ByGroup(gs, *rest) {
			fmt.Printf("%-8s %s\n", g.Name, g.Stat)
		}
	}
	total := c.Total()
	fmt.Printf("%-8s %s (floor %.1f%%)\n", "total", total, *min)
	if total.Percent() < *min {
		fmt.Printf("coverage %.2f%% is below the floor of %.1f%%\n", total.Percent(), *min)
		os.Exit(1)
	}
}
