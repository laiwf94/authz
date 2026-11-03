package gate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type tarFile struct {
	name string
	body string
	dir  bool
	link string
}

func makeTar(t *testing.T, files []tarFile) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, f := range files {
		h := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}
		switch {
		case f.dir:
			h = &tar.Header{Name: f.name, Mode: 0o755, Typeflag: tar.TypeDir}
		case f.link != "":
			h = &tar.Header{Name: f.name, Linkname: f.link, Typeflag: tar.TypeSymlink}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// saveArchive builds what `docker save` writes: blobs, then (or first, with
// manifestFirst) manifest.json.
func saveArchive(t *testing.T, manifest string, manifestFirst bool, blobs []tarFile) []byte {
	t.Helper()
	m := tarFile{name: "manifest.json", body: manifest}
	all := append([]tarFile{{name: "blobs/", dir: true}}, blobs...)
	if manifestFirst {
		all = append([]tarFile{m}, all...)
	} else {
		all = append(all, m)
	}
	return makeTar(t, all)
}

func manifestJSON(t *testing.T, config string, layers ...string) string {
	t.Helper()
	b, err := json.Marshal([]map[string]any{{"Config": config, "RepoTags": []string{"x:latest"}, "Layers": layers}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var (
	base = []tarFile{{name: "etc/", dir: true}, {name: "etc/passwd", body: strings.Repeat("root:x:0:0\n", 20)}, {name: "bin", link: "usr/bin"}}
	app  = []tarFile{{name: "./authz", body: strings.Repeat("binary ", 500)}, {name: "wicket", link: "authz"}, {name: "etc/passwd", body: "nonroot\n"}}
)

func TestMeasureImageStoresAgree(t *testing.T) {
	baseTar, appTar := makeTar(t, base), makeTar(t, app)
	baseGz, appGz := gz(t, baseTar), gz(t, appTar)
	config := `{"architecture":"amd64"}`
	want := &ImageSize{
		Compressed:   int64(len(config) + len(baseGz) + len(appGz)),
		Uncompressed: int64(len(baseTar) + len(appTar)),
		Layers: []LayerSize{
			{Compressed: int64(len(baseGz)), Uncompressed: int64(len(baseTar)), Files: 1},
			{Compressed: int64(len(appGz)), Uncompressed: int64(len(appTar)), Files: 2},
		},
		Largest: []ImageFileSize{{Path: "/authz", Size: 3500}, {Path: "/etc/passwd", Size: 8}},
	}
	for _, tc := range []struct {
		name          string
		layers        [2][]byte
		manifestFirst bool
	}{
		{"classic store, plain layers", [2][]byte{baseTar, appTar}, false},
		{"containerd store, gzip layers", [2][]byte{baseGz, appGz}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arch := saveArchive(t, manifestJSON(t, "blobs/sha256/c", "blobs/sha256/l1", "./blobs/sha256/l2"), tc.manifestFirst, []tarFile{
				{name: "blobs/sha256/l1", body: string(tc.layers[0])},
				{name: "blobs/sha256/c", body: config},
				{name: "blobs/sha256/l2", body: string(tc.layers[1])},
				{name: "index.json", body: "{}"},
			})
			got, err := MeasureImage(bytes.NewReader(arch))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got  %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestMeasureImageRepeatedLayer(t *testing.T) {
	l := makeTar(t, []tarFile{{name: "a", body: "aaaa"}})
	arch := saveArchive(t, manifestJSON(t, "c", "l", "l"), false, []tarFile{{name: "c", body: "{}"}, {name: "l", body: string(l)}})
	got, err := MeasureImage(bytes.NewReader(arch))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Layers) != 2 || got.Layers[0] != got.Layers[1] || got.Uncompressed != 2*int64(len(l)) {
		t.Fatalf("got %+v", got)
	}
	if want := []ImageFileSize{{Path: "/a", Size: 4}}; !reflect.DeepEqual(got.Largest, want) {
		t.Fatalf("largest = %+v, want %+v", got.Largest, want)
	}
}

func TestLargestKeepsTheBiggest(t *testing.T) {
	files := []ImageFileSize{{"/b", 1}, {"/a", 1}, {"/big", 9}, {"/c", 3}, {"/d", 4}, {"/e", 5}, {"/f", 0}}
	want := []ImageFileSize{{"/big", 9}, {"/e", 5}, {"/d", 4}, {"/c", 3}, {"/a", 1}}
	if got := largest(files, maxLargest); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestMeasureImageErrors(t *testing.T) {
	layer := makeTar(t, []tarFile{{name: "a", body: "a"}})
	ok := []tarFile{{name: "c", body: "{}"}, {name: "l", body: string(layer)}}
	for _, tc := range []struct {
		name string
		arch []byte
		want string
	}{
		{"not a tar", []byte("hello, this is not a tar archive at all but it needs to be long enough to fill a header block" + strings.Repeat(".", 512)), "image archive"},
		{"no manifest", makeTar(t, ok), "no manifest.json"},
		{"manifest not JSON", saveArchive(t, "[{", false, ok), "manifest.json"},
		{"two images", saveArchive(t, `[{"Config":"c"},{"Config":"c"}]`, false, ok), "lists 2 images"},
		{"no config named", saveArchive(t, `[{"Layers":["l"]}]`, false, ok), "has no config"},
		{"config missing", saveArchive(t, manifestJSON(t, "nope", "l"), false, ok), "config nope not found"},
		{"layer missing", saveArchive(t, manifestJSON(t, "c", "l", "gone"), false, ok), "layer gone not found"},
		{"zstd layer", saveArchive(t, manifestJSON(t, "c", "z"), false, []tarFile{{name: "c", body: "{}"}, {name: "z", body: "\x28\xb5\x2f\xfd rest"}}), "zstd"},
		{"bad gzip header", saveArchive(t, manifestJSON(t, "c", "g"), false, []tarFile{{name: "c", body: "{}"}, {name: "g", body: "\x1f\x8b"}}), "layer g"},
		{"truncated gzip", saveArchive(t, manifestJSON(t, "c", "g"), false, []tarFile{{name: "c", body: "{}"}, {name: "g", body: string(gz(t, layer)[:40])}}), "layer g"},
		{"layer not a tar", saveArchive(t, manifestJSON(t, "c", "p"), false, []tarFile{{name: "c", body: "{}"}, {name: "p", body: strings.Repeat("x", 600)}}), "layer p"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := MeasureImage(bytes.NewReader(tc.arch))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

type failSeeker struct{ *bytes.Reader }

func (f failSeeker) Seek(int64, int) (int64, error) { return 0, errTest }

var errTest = errors.New("seek failed")

func TestMeasureImageSeekError(t *testing.T) {
	arch := saveArchive(t, manifestJSON(t, "c"), true, []tarFile{{name: "c", body: "{}"}})
	if _, err := MeasureImage(failSeeker{bytes.NewReader(arch)}); err != errTest {
		t.Fatalf("err = %v, want the seek error", err)
	}
}

const baselineJSON = `{
  "limit_bytes": 25000000,
  "baseline": {"compressed_bytes": 5000000, "uncompressed_bytes": 12000000, "layers": [], "largest_files": []},
  "recorded": {"commit": "abc"}
}`

func TestParseImageBaseline(t *testing.T) {
	b, err := ParseImageBaseline(strings.NewReader(baselineJSON))
	if err != nil {
		t.Fatal(err)
	}
	if b.Limit != 25e6 || b.Baseline.Uncompressed != 12e6 || b.Recorded["commit"] != "abc" {
		t.Fatalf("got %+v", b)
	}
	for _, tc := range []struct{ in, want string }{
		{`{`, "image baseline"},
		{`{"limit_bytes": 1, "extra": 1}`, "unknown field"},
		{`{"limit_bytes": 0, "baseline": {"compressed_bytes": 1, "uncompressed_bytes": 1}}`, "limit_bytes must be positive"},
		{`{"limit_bytes": 10, "baseline": {"compressed_bytes": 0, "uncompressed_bytes": 1}}`, "must be positive"},
		{`{"limit_bytes": 10, "baseline": {"compressed_bytes": 1, "uncompressed_bytes": 0}}`, "must be positive"},
		{`{"limit_bytes": 10, "baseline": {"compressed_bytes": 1, "uncompressed_bytes": 11}}`, "already over the limit"},
	} {
		if _, err := ParseImageBaseline(strings.NewReader(tc.in)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.in, err, tc.want)
		}
	}
}

func TestImageBaselineCompare(t *testing.T) {
	b, err := ParseImageBaseline(strings.NewReader(baselineJSON))
	if err != nil {
		t.Fatal(err)
	}
	got := &ImageSize{Compressed: 4_500_000, Uncompressed: 13_200_000, Largest: []ImageFileSize{{"/authz", 12_000_000}}}
	report, ok := b.Compare(got)
	want := `compressed    4.50 MB  (baseline 5.00 MB, -0.50 MB, -10.0%)
uncompressed  13.20 MB  (baseline 12.00 MB, +1.20 MB, +10.0%)
  /authz      12.00 MB
limit         25.00 MB uncompressed: within, 11.80 MB to spare
`
	if !ok || report != want {
		t.Fatalf("ok = %v, report:\n%s\nwant:\n%s", ok, report, want)
	}
	got.Uncompressed = 25_000_001
	report, ok = b.Compare(got)
	if ok || !strings.HasSuffix(report, "limit         25.00 MB uncompressed: OVER by 0.00 MB\n") {
		t.Fatalf("ok = %v, report:\n%s", ok, report)
	}
	got.Uncompressed = 25_000_000
	if _, ok := b.Compare(got); !ok {
		t.Fatal("exactly the limit must pass")
	}
}
