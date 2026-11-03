//go:build ignore

// image-size measures the authz image and holds it under the limit in a
// baseline file.
//
//	go run scripts/image-size.go [-baseline FILE] [-json] IMAGE
//	go run scripts/image-size.go -archive FILE [-baseline FILE] [-json]
//	go run scripts/image-size.go -record FILE -limit BYTES IMAGE
//
// IMAGE is a local image, which is exported with `docker save`; -archive
// reads an archive docker save already wrote. Two sizes are reported: the
// compressed size, the gzip-compressed layers and config that a registry
// stores and its manifest lists, and the uncompressed size, the layer tar
// streams that a pulled image takes on disk. The limit applies to the
// uncompressed size. ci.yml runs it on every change against
// bench/image-baseline.json, whose limit is the roadmap's 25 MB target.
//
// -record measures IMAGE and writes a new baseline file with the given limit,
// the commit (git describe --always --dirty) and the date; that is how
// bench/image-baseline.json was made.
//
// Exit status: 0 within the limit (or recorded), 1 over it, 2 usage, docker
// or parse error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/laiwf94/authz/internal/gate"
)

func main() {
	archive := flag.String("archive", "", "read this docker save archive instead of exporting IMAGE")
	baseline := flag.String("baseline", "", "compare with this baseline file and fail above its limit")
	asJSON := flag.Bool("json", false, "print the measurement as JSON")
	record := flag.String("record", "", "write a new baseline file for IMAGE")
	limit := flag.Int64("limit", 0, "with -record: the limit in bytes, uncompressed")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/image-size.go [-baseline FILE] [-json] IMAGE | -archive FILE | -record FILE -limit BYTES IMAGE")
		flag.PrintDefaults()
	}
	flag.Parse()
	image := flag.Arg(0)
	switch {
	case flag.NArg() > 1,
		*archive == "" && image == "",
		*archive != "" && image != "",
		*record != "" && (image == "" || *limit <= 0 || *baseline != ""):
		flag.Usage()
		os.Exit(2)
	}

	path := *archive
	if path == "" {
		dir, err := os.MkdirTemp("", "image-size")
		if err != nil {
			fatal(err)
		}
		defer os.RemoveAll(dir)
		path = dir + "/image.tar"
		cmd := exec.Command("docker", "save", "-o", path, image)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fatal(fmt.Errorf("docker save %s: %w", image, err))
		}
	}
	f, err := os.Open(path)
	if err != nil {
		fatal(err)
	}
	size, err := gate.MeasureImage(f)
	f.Close()
	if err != nil {
		fatal(err)
	}

	if *record != "" {
		b := gate.ImageBaseline{Limit: *limit, Baseline: *size, Recorded: map[string]string{
			"date":    time.Now().UTC().Format(time.DateOnly),
			"commit":  output("git", "describe", "--always", "--dirty", "--abbrev=12"),
			"image":   image,
			"docker":  output("docker", "version", "--format", "{{.Server.Version}}"),
			"command": "docker build -t " + image + " . && go run scripts/image-size.go -record " + *record + " -limit " + fmt.Sprint(*limit) + " " + image,
		}}
		var out strings.Builder
		enc := json.NewEncoder(&out)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(b); err != nil {
			fatal(err)
		}
		if _, err := gate.ParseImageBaseline(strings.NewReader(out.String())); err != nil {
			fatal(err)
		}
		if err := os.WriteFile(*record, []byte(out.String()), 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("recorded %s: %d bytes compressed, %d uncompressed\n", *record, size.Compressed, size.Uncompressed)
		return
	}

	if *asJSON {
		out, _ := json.MarshalIndent(size, "", "  ")
		fmt.Printf("%s\n", out)
	}
	if *baseline == "" {
		if !*asJSON {
			fmt.Printf("compressed    %d bytes\nuncompressed  %d bytes\n", size.Compressed, size.Uncompressed)
			for _, f := range size.Largest {
				fmt.Printf("  %-11s %d bytes\n", f.Path, f.Size)
			}
		}
		return
	}
	bf, err := os.Open(*baseline)
	if err != nil {
		fatal(err)
	}
	b, err := gate.ParseImageBaseline(bf)
	bf.Close()
	if err != nil {
		fatal(err)
	}
	report, ok := b.Compare(size)
	fmt.Print(report)
	if !ok {
		os.Exit(1)
	}
}

func output(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		fatal(fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err))
	}
	return strings.TrimSpace(string(out))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "image-size:", err)
	os.Exit(2)
}
