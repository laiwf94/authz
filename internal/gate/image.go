package gate

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// ImageSize is the size of a container image, measured from the archive
// `docker save` writes.
type ImageSize struct {
	// Compressed is the sum of the gzip-compressed layers and the config
	// blob: what a registry stores and a pull downloads, and what the
	// registry manifest reports.
	Compressed int64 `json:"compressed_bytes"`
	// Uncompressed is the sum of the layer tar streams: what the image
	// takes on disk once pulled, and what `docker images` shows.
	Uncompressed int64           `json:"uncompressed_bytes"`
	Layers       []LayerSize     `json:"layers"`
	Largest      []ImageFileSize `json:"largest_files"`
}

// LayerSize is one layer of an image, in the order the image applies them.
type LayerSize struct {
	Compressed   int64 `json:"compressed_bytes"`
	Uncompressed int64 `json:"uncompressed_bytes"`
	// Files is the number of regular files in the layer.
	Files int `json:"files"`
}

// ImageFileSize is a regular file in the image and its size.
type ImageFileSize struct {
	Path string `json:"path"`
	Size int64  `json:"size_bytes"`
}

// maxLargest is how many of the biggest files MeasureImage reports.
const maxLargest = 5

// saveManifest is one entry of the manifest.json that `docker save` writes in
// both its legacy layout and its OCI layout.
type saveManifest struct {
	Config string
	Layers []string
}

// MeasureImage measures the single image in a `docker save` archive. The
// archive is read twice, once for manifest.json and once for the blobs, so
// it must be seekable.
//
// Layers that are already gzip-compressed (the containerd image store keeps
// them that way) count their blob size as compressed and are decompressed to
// count the uncompressed size. Plain tar layers (the classic image store)
// are compressed with gzip at the default level, as docker push does, to
// count the compressed size. Either way the uncompressed size of a layer is
// the length of its tar stream, so the two stores give the same Uncompressed
// total; Compressed may differ by a few bytes per layer between gzip
// implementations.
func MeasureImage(r io.ReadSeeker) (*ImageSize, error) {
	m, err := readSaveManifest(r)
	if err != nil {
		return nil, err
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	want := map[string][]int{} // blob path -> layer indexes (a layer may repeat)
	for i, l := range m.Layers {
		p := path.Clean(l)
		want[p] = append(want[p], i)
	}
	cfg := path.Clean(m.Config)
	img := &ImageSize{Layers: make([]LayerSize, len(m.Layers))}
	done := make([]bool, len(m.Layers))
	var files []ImageFileSize
	sawConfig := false
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("image archive: %w", err)
		}
		name := path.Clean(h.Name)
		if name == cfg && h.Typeflag == tar.TypeReg {
			img.Compressed += h.Size
			sawConfig = true
		}
		idx, ok := want[name]
		if !ok || h.Typeflag != tar.TypeReg || done[idx[0]] {
			continue
		}
		l, fs, err := measureLayer(tr, h.Size)
		if err != nil {
			return nil, fmt.Errorf("layer %s: %w", name, err)
		}
		for _, i := range idx {
			img.Layers[i] = l
			done[i] = true
			img.Compressed += l.Compressed
			img.Uncompressed += l.Uncompressed
		}
		files = mergeFiles(files, fs)
	}
	if !sawConfig {
		return nil, fmt.Errorf("image archive: config %s not found", m.Config)
	}
	for i, d := range done {
		if !d {
			return nil, fmt.Errorf("image archive: layer %s not found", m.Layers[i])
		}
	}
	img.Largest = largest(files, maxLargest)
	return img, nil
}

func readSaveManifest(r io.Reader) (*saveManifest, error) {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("image archive: no manifest.json; is this the output of docker save?")
		}
		if err != nil {
			return nil, fmt.Errorf("image archive: %w", err)
		}
		if path.Clean(h.Name) != "manifest.json" {
			continue
		}
		var ms []saveManifest
		if err := json.NewDecoder(tr).Decode(&ms); err != nil {
			return nil, fmt.Errorf("image archive: manifest.json: %w", err)
		}
		if len(ms) != 1 {
			return nil, fmt.Errorf("image archive: manifest.json lists %d images, want 1", len(ms))
		}
		if ms[0].Config == "" {
			return nil, errors.New("image archive: manifest.json has no config")
		}
		return &ms[0], nil
	}
}

// measureLayer reads one layer blob of size n and returns its sizes and the
// regular files in it, path -> size.
func measureLayer(blob io.Reader, n int64) (LayerSize, map[string]int64, error) {
	br := bufio.NewReader(blob)
	magic, _ := br.Peek(4)
	var l LayerSize
	var stream io.Reader
	var flush func() error
	cw := &countWriter{}
	switch {
	case bytes.HasPrefix(magic, []byte{0x1f, 0x8b}):
		l.Compressed = n
		zr, err := gzip.NewReader(br)
		if err != nil {
			return l, nil, err
		}
		stream = zr
		flush = func() error { return nil }
	case bytes.Equal(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return l, nil, errors.New("zstd-compressed layers are not supported")
	default:
		zw := gzip.NewWriter(cw)
		stream = io.TeeReader(br, zw)
		flush = zw.Close
	}
	// Count the whole tar stream, padding and end blocks included, while
	// listing its files.
	cr := &countReader{r: stream}
	files := map[string]int64{}
	tr := tar.NewReader(cr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return l, nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		l.Files++
		files[cleanImagePath(h.Name)] = h.Size
	}
	if _, err := io.Copy(io.Discard, cr); err != nil {
		return l, nil, err
	}
	if err := flush(); err != nil {
		return l, nil, err
	}
	l.Uncompressed = cr.n
	if l.Compressed == 0 {
		l.Compressed = cw.n
	}
	return l, files, nil
}

func cleanImagePath(name string) string {
	return path.Clean("/" + strings.TrimPrefix(name, "./"))
}

// mergeFiles applies a later layer's files over the earlier ones: a file a
// later layer writes again counts once, at its new size.
func mergeFiles(all []ImageFileSize, layer map[string]int64) []ImageFileSize {
	for i := range all {
		if s, ok := layer[all[i].Path]; ok {
			all[i].Size = s
			delete(layer, all[i].Path)
		}
	}
	for p, s := range layer {
		all = append(all, ImageFileSize{Path: p, Size: s})
	}
	return all
}

func largest(files []ImageFileSize, n int) []ImageFileSize {
	sort.Slice(files, func(i, j int) bool {
		if files[i].Size != files[j].Size {
			return files[i].Size > files[j].Size
		}
		return files[i].Path < files[j].Path
	})
	if len(files) > n {
		files = files[:n]
	}
	return append([]ImageFileSize(nil), files...)
}

type countWriter struct{ n int64 }

func (w *countWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ImageBaseline is the recorded size of the authz image and the limit the
// gate holds it to.
type ImageBaseline struct {
	// Limit is the largest accepted uncompressed size, in bytes.
	Limit int64 `json:"limit_bytes"`
	// Baseline is the size measured when the baseline was recorded.
	Baseline ImageSize `json:"baseline"`
	// Recorded says when, from which commit and how.
	Recorded map[string]string `json:"recorded"`
}

// ParseImageBaseline reads an ImageBaseline and checks that it is usable.
func ParseImageBaseline(r io.Reader) (*ImageBaseline, error) {
	var b ImageBaseline
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("image baseline: %w", err)
	}
	if b.Limit <= 0 {
		return nil, errors.New("image baseline: limit_bytes must be positive")
	}
	if b.Baseline.Uncompressed <= 0 || b.Baseline.Compressed <= 0 {
		return nil, errors.New("image baseline: baseline sizes must be positive")
	}
	if b.Baseline.Uncompressed > b.Limit {
		return nil, fmt.Errorf("image baseline: the baseline (%d bytes) is already over the limit (%d bytes)", b.Baseline.Uncompressed, b.Limit)
	}
	return &b, nil
}

// Compare reports the measured size against the baseline and says whether it
// is within the limit. The limit applies to the uncompressed size, the larger
// of the two and the one a pulled image costs on every node.
func (b *ImageBaseline) Compare(got *ImageSize) (report string, ok bool) {
	var s strings.Builder
	row := func(name string, now, base int64) {
		fmt.Fprintf(&s, "%-13s %s  (baseline %s, %s)\n", name, mb(now), mb(base), delta(now, base))
	}
	row("compressed", got.Compressed, b.Baseline.Compressed)
	row("uncompressed", got.Uncompressed, b.Baseline.Uncompressed)
	for _, f := range got.Largest {
		fmt.Fprintf(&s, "  %-11s %s\n", f.Path, mb(f.Size))
	}
	ok = got.Uncompressed <= b.Limit
	if ok {
		fmt.Fprintf(&s, "limit         %s uncompressed: within, %s to spare\n", mb(b.Limit), mb(b.Limit-got.Uncompressed))
	} else {
		fmt.Fprintf(&s, "limit         %s uncompressed: OVER by %s\n", mb(b.Limit), mb(got.Uncompressed-b.Limit))
	}
	return s.String(), ok
}

func mb(n int64) string { return fmt.Sprintf("%.2f MB", float64(n)/1e6) }

func delta(now, base int64) string {
	d := now - base
	sign := "+"
	if d < 0 {
		sign = "-"
		d = -d
	}
	return fmt.Sprintf("%s%s, %s%.1f%%", sign, mb(d), sign, 100*float64(d)/float64(base))
}
