package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/rand/v2"
	"strings"
	"testing"
)

// The leaves and tree heads of the RFC 6962 test vectors published with
// Certificate Transparency's reference implementation (merkle_tree_test.cc)
// and Trillian (merkle/testonly): the root of the first n leaves for n from
// 1 to 8.
var vectorLeaves = []string{
	"",
	"00",
	"10",
	"2021",
	"3031",
	"40414243",
	"5051525354555657",
	"606162636465666768696a6b6c6d6e6f",
}

var vectorRoots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	if got, want := hex.EncodeToString(func() []byte { h := EmptyRoot(); return h[:] }()),
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; got != want {
		t.Fatalf("empty root %s, want %s", got, want)
	}
	var r Range
	if r.Root() != EmptyRoot() || r.Size() != 0 {
		t.Fatal("the zero Range is not the empty tree")
	}
	var leaves []Hash
	for i, l := range vectorLeaves {
		h := LeafHash(unhex(t, l))
		leaves = append(leaves, h)
		r.AppendData(unhex(t, l))
		root := r.Root()
		if got := hex.EncodeToString(root[:]); got != vectorRoots[i] {
			t.Errorf("root of %d leaves: %s, want %s", i+1, got, vectorRoots[i])
		}
		if ref := RootOf(leaves); ref != root {
			t.Errorf("root of %d leaves: Range and RootOf differ", i+1)
		}
		if r.Size() != uint64(i+1) {
			t.Errorf("size %d after %d leaves", r.Size(), i+1)
		}
	}
}

func TestHashes(t *testing.T) {
	// The prefixes of RFC 6962 by hand.
	data := []byte("record")
	if want := sha256.Sum256(append([]byte{0}, data...)); LeafHash(data) != want {
		t.Error("leaf hash is not SHA-256(0x00 || data)")
	}
	a, b := LeafHash([]byte("a")), LeafHash([]byte("b"))
	if want := sha256.Sum256(append(append([]byte{1}, a[:]...), b[:]...)); NodeHash(a, b) != want {
		t.Error("node hash is not SHA-256(0x01 || left || right)")
	}
	// A node is not a leaf of the two hashes it joins.
	if NodeHash(a, b) == LeafHash(append(a[:], b[:]...)) {
		t.Error("node and leaf hashes collide")
	}
}

func leavesFor(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		out[i] = LeafHash([]byte(strings.Repeat("x", i%7) + string(rune('a'+i%26))))
	}
	return out
}

// Every size from 0 to 1100 agrees with the RFC's recursion, and so does
// every compact range's shape: one subtree per set bit, of the sizes those
// bits say, largest first.
func TestRangeMatchesRecursion(t *testing.T) {
	leaves := leavesFor(1100)
	var r Range
	for n := 0; n <= len(leaves); n++ {
		if n > 0 {
			r.Append(leaves[n-1])
		}
		if r.Root() != RootOf(leaves[:n]) {
			t.Fatalf("root of %d leaves differs from the recursion", n)
		}
		start := 0
		hs := r.Hashes()
		for bit, i := 63, 0; bit >= 0; bit-- {
			if n>>bit&1 == 0 {
				continue
			}
			sub := 1 << bit
			if i >= len(hs) || hs[i] != RootOf(leaves[start:start+sub]) {
				t.Fatalf("size %d: subtree %d (leaves %d to %d) is wrong", n, i, start, start+sub-1)
			}
			start += sub
			i++
		}
		if len(hs) != popcount(n) {
			t.Fatalf("size %d: %d subtrees", n, len(hs))
		}
	}
}

func popcount(n int) int {
	c := 0
	for ; n > 0; n &= n - 1 {
		c++
	}
	return c
}

// Random sizes up to 2^17, each grown from a random earlier size through a
// cloned and re-encoded range, so a range restored from disk extends as
// the one that wrote it would.
func TestRangeRandomSizes(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	leaves := leavesFor(1 << 17)
	for range 40 {
		n := rng.IntN(len(leaves) + 1)
		m := rng.IntN(n + 1)
		var r Range
		for _, l := range leaves[:m] {
			r.Append(l)
		}
		enc, _ := r.MarshalBinary()
		var back Range
		if err := back.UnmarshalBinary(enc); err != nil {
			t.Fatal(err)
		}
		c := back.Clone()
		for _, l := range leaves[m:n] {
			c.Append(l)
		}
		if c.Root() != RootOf(leaves[:n]) || c.Size() != uint64(n) {
			t.Fatalf("%d leaves restored at %d: wrong root", n, m)
		}
		// The original is untouched by the clone's appends.
		if back.Root() != RootOf(leaves[:m]) || back.Size() != uint64(m) {
			t.Fatalf("clone changed the range it was taken from (%d, %d)", m, n)
		}
	}
}

func TestEncoding(t *testing.T) {
	leaves := leavesFor(13)
	var r Range
	for _, l := range leaves {
		r.Append(l)
	}
	enc, _ := r.MarshalBinary()
	if len(enc) != 8+3*Size || !bytes.Equal(enc[:8], []byte{0, 0, 0, 0, 0, 0, 0, 13}) {
		t.Fatalf("encoding of 13 leaves: %x", enc)
	}
	nr, err := NewRange(13, r.Hashes())
	if err != nil || nr.Root() != r.Root() {
		t.Fatalf("NewRange: %v", err)
	}
	var empty Range
	e, _ := empty.MarshalBinary()
	var back Range
	if err := back.UnmarshalBinary(e); err != nil || back.Size() != 0 || back.Root() != EmptyRoot() {
		t.Fatalf("empty range: %v", err)
	}
	for _, bad := range [][]byte{nil, enc[:7], enc[:8], enc[:len(enc)-1], append(enc, 0)} {
		if err := back.UnmarshalBinary(bad); err == nil {
			t.Errorf("decoded %d bytes", len(bad))
		}
	}
	if _, err := NewRange(13, r.Hashes()[:2]); err == nil {
		t.Error("NewRange took 2 subtrees for 13 leaves")
	}
}

func TestFullRange(t *testing.T) {
	r, err := NewRange(^uint64(0), make([]Hash, 64))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Error("appending to a full range did not panic")
		}
	}()
	r.Append(Hash{})
}

func FuzzUnmarshal(f *testing.F) {
	var r Range
	for _, l := range leavesFor(5) {
		r.Append(l)
	}
	enc, _ := r.MarshalBinary()
	f.Add(enc)
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		var r Range
		if r.UnmarshalBinary(b) != nil {
			return
		}
		again, _ := r.MarshalBinary()
		if !bytes.Equal(again, b) {
			t.Fatalf("decoded %x, encodes as %x", b, again)
		}
		if r.Size() < ^uint64(0) {
			r.Append(LeafHash(b))
		}
		_ = r.Root()
	})
}

func BenchmarkAppend(b *testing.B) {
	leaf := LeafHash([]byte("record"))
	var r Range
	b.ReportAllocs()
	for b.Loop() {
		r.Append(leaf)
	}
}

func BenchmarkLeafHash(b *testing.B) {
	line := bytes.Repeat([]byte("x"), 300) // a typical record
	b.ReportAllocs()
	b.SetBytes(int64(len(line)))
	for b.Loop() {
		LeafHash(line)
	}
}

func BenchmarkRoot(b *testing.B) {
	var r Range
	for _, l := range leavesFor(1<<20 - 1) { // 20 subtrees
		r.Append(l)
	}
	b.ReportAllocs()
	for b.Loop() {
		r.Root()
	}
}
