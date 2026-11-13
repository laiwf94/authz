package merkle

import (
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"slices"
	"testing"
)

// The inclusion and consistency proofs of the RFC 6962 test vectors
// published with Certificate Transparency's reference implementation
// (merkle_tree_test.cc) and Trillian (merkle/testonly), over vectorLeaves.
// The vectors number leaves from 1; index is from 0 here.
var inclusionVectors = []struct {
	index, size uint64
	proof       []string
}{
	{0, 1, nil},
	{0, 8, []string{
		"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
		"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
		"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
	}},
	{5, 8, []string{
		"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
		"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	}},
	{2, 3, []string{
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	}},
	{1, 5, []string{
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
		"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
	}},
}

var consistencyVectors = []struct {
	from, size uint64
	proof      []string
}{
	{1, 1, nil},
	{1, 8, []string{
		"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
		"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
		"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
	}},
	{6, 8, []string{
		"0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
		"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	}},
	{2, 5, []string{
		"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
		"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
	}},
}

func vectorLeafHashes(t *testing.T) []Hash {
	var out []Hash
	for _, l := range vectorLeaves {
		out = append(out, LeafHash(unhex(t, l)))
	}
	return out
}

func hexes(hs []Hash) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = hex.EncodeToString(h[:])
	}
	return out
}

func rootHash(t *testing.T, size uint64) Hash {
	var h Hash
	copy(h[:], unhex(t, vectorRoots[size-1]))
	return h
}

func TestInclusionVectors(t *testing.T) {
	leaves := vectorLeafHashes(t)
	for _, v := range inclusionVectors {
		got, err := InclusionProof(v.index, leaves[:v.size])
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(hexes(got), v.proof) && !(len(got) == 0 && len(v.proof) == 0) {
			t.Errorf("inclusion of leaf %d in %d: %v, want %v", v.index, v.size, hexes(got), v.proof)
		}
		if err := VerifyInclusion(v.index, v.size, leaves[v.index], got, rootHash(t, v.size)); err != nil {
			t.Errorf("inclusion of leaf %d in %d does not verify: %v", v.index, v.size, err)
		}
	}
}

func TestConsistencyVectors(t *testing.T) {
	leaves := vectorLeafHashes(t)
	for _, v := range consistencyVectors {
		got, err := ConsistencyProof(v.from, leaves[:v.size])
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(hexes(got), v.proof) && !(len(got) == 0 && len(v.proof) == 0) {
			t.Errorf("consistency from %d to %d: %v, want %v", v.from, v.size, hexes(got), v.proof)
		}
		if err := VerifyConsistency(v.from, v.size, got, rootHash(t, v.from), rootHash(t, v.size)); err != nil {
			t.Errorf("consistency from %d to %d does not verify: %v", v.from, v.size, err)
		}
	}
}

// refPath and refSubproof are PATH and SUBPROOF of RFC 6962 section 2.1.1
// and 2.1.2 as written, over the leaves in memory.
func refPath(m int, d []Hash) []Hash {
	n := len(d)
	if n == 1 {
		return nil
	}
	k := int(split(uint64(n)))
	if m < k {
		return append(refPath(m, d[:k]), RootOf(d[k:]))
	}
	return append(refPath(m-k, d[k:]), RootOf(d[:k]))
}

func refSubproof(m int, d []Hash, b bool) []Hash {
	n := len(d)
	if m == n {
		if b {
			return nil
		}
		return []Hash{RootOf(d)}
	}
	k := int(split(uint64(n)))
	if m <= k {
		return append(refSubproof(m, d[:k], b), RootOf(d[k:]))
	}
	return append(refSubproof(m-k, d[k:], false), RootOf(d[:k]))
}

func refConsistency(m int, d []Hash) []Hash {
	if m == 0 || m == len(d) {
		return nil
	}
	return refSubproof(m, d, true)
}

// Every leaf of every tree up to 70 leaves, and every pair of sizes up to
// 70, gets the proof the RFC's recursion gives, and it verifies.
func TestProofsMatchRecursion(t *testing.T) {
	all := leavesFor(70)
	for n := 1; n <= len(all); n++ {
		d := all[:n]
		root := RootOf(d)
		for m := range n {
			got, err := InclusionProof(uint64(m), d)
			if err != nil {
				t.Fatal(err)
			}
			if want := refPath(m, d); !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
				t.Fatalf("inclusion of %d in %d differs from PATH", m, n)
			}
			if err := VerifyInclusion(uint64(m), uint64(n), d[m], got, root); err != nil {
				t.Fatalf("inclusion of %d in %d: %v", m, n, err)
			}
		}
		for m := 0; m <= n; m++ {
			got, err := ConsistencyProof(uint64(m), d)
			if err != nil {
				t.Fatal(err)
			}
			if want := refConsistency(m, d); !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
				t.Fatalf("consistency from %d to %d differs from PROOF", m, n)
			}
			if err := VerifyConsistency(uint64(m), uint64(n), got, RootOf(d[:m]), root); err != nil {
				t.Fatalf("consistency from %d to %d: %v", m, n, err)
			}
		}
	}
}

// tamper returns a copy of proof with one bit of hash i flipped.
func tamper(proof []Hash, i int) []Hash {
	out := slices.Clone(proof)
	out[i][i%Size] ^= 1 << (i % 8)
	return out
}

// Random sizes up to 2^17 leaves: proofs from a Prover verify, and any
// changed hash, index, size, leaf or root, a proof cut short or one hash
// too many, fails.
func TestProofsRandomSizes(t *testing.T) {
	rng := rand.New(rand.NewPCG(6962, 9162))
	all := leavesFor(1 << 12)
	leafAt := func(i uint64) Hash { return all[i%uint64(len(all))] }
	for range 40 {
		size := 1 + rng.Uint64N(1<<17)
		if rng.IntN(4) == 0 {
			size = 1 + rng.Uint64N(300)
		}
		index := rng.Uint64N(size)
		from := rng.Uint64N(size + 1)
		ip, err := NewInclusionProver(index, size)
		if err != nil {
			t.Fatal(err)
		}
		cp, err := NewConsistencyProver(from, size)
		if err != nil {
			t.Fatal(err)
		}
		for i := range size {
			ip.Add(leafAt(i))
			cp.Add(leafAt(i))
		}
		incl, err := ip.Proof()
		if err != nil {
			t.Fatal(err)
		}
		cons, err := cp.Proof()
		if err != nil {
			t.Fatal(err)
		}
		root, old := ip.Root(), cp.PrefixRoot()
		if cp.Root() != root || ip.Leaf() != leafAt(index) {
			t.Fatal("the provers disagree on the tree")
		}
		if err := VerifyInclusion(index, size, leafAt(index), incl, root); err != nil {
			t.Fatalf("inclusion of %d in %d: %v", index, size, err)
		}
		if err := VerifyConsistency(from, size, cons, old, root); err != nil {
			t.Fatalf("consistency from %d to %d: %v", from, size, err)
		}
		if len(incl) > 64 || len(cons) > 64 {
			t.Fatalf("proofs of %d and %d hashes for %d leaves", len(incl), len(cons), size)
		}

		bad := LeafHash([]byte("not a leaf"))
		for i := range incl {
			if VerifyInclusion(index, size, leafAt(index), tamper(incl, i), root) == nil {
				t.Fatalf("inclusion of %d in %d verifies with hash %d changed", index, size, i)
			}
		}
		if VerifyInclusion(index, size, bad, incl, root) == nil {
			t.Fatalf("inclusion of %d in %d verifies for another leaf", index, size)
		}
		if VerifyInclusion(index, size, leafAt(index), incl, bad) == nil {
			t.Fatalf("inclusion of %d in %d verifies against another root", index, size)
		}
		if size > 1 {
			other := (index + 1 + rng.Uint64N(size-1)) % size
			if leafAt(other) != leafAt(index) && VerifyInclusion(other, size, leafAt(index), incl, root) == nil {
				t.Fatalf("inclusion of %d in %d verifies as leaf %d", index, size, other)
			}
			if VerifyInclusion(index, size, leafAt(index), incl[:len(incl)-1], root) == nil {
				t.Fatalf("inclusion of %d in %d verifies cut short", index, size)
			}
		}
		if VerifyInclusion(index, size, leafAt(index), append(slices.Clone(incl), bad), root) == nil {
			t.Fatalf("inclusion of %d in %d verifies with a hash added", index, size)
		}

		if from == 0 || from == size {
			if len(cons) != 0 {
				t.Fatalf("consistency from %d to %d has %d hashes", from, size, len(cons))
			}
			continue
		}
		for i := range cons {
			if VerifyConsistency(from, size, tamper(cons, i), old, root) == nil {
				t.Fatalf("consistency from %d to %d verifies with hash %d changed", from, size, i)
			}
		}
		if VerifyConsistency(from, size, cons, bad, root) == nil || VerifyConsistency(from, size, cons, old, bad) == nil {
			t.Fatalf("consistency from %d to %d verifies against another root", from, size)
		}
		if VerifyConsistency(from, size, cons[:len(cons)-1], old, root) == nil {
			t.Fatalf("consistency from %d to %d verifies cut short", from, size)
		}
		if VerifyConsistency(from, size, append(slices.Clone(cons), bad), old, root) == nil {
			t.Fatalf("consistency from %d to %d verifies with a hash added", from, size)
		}
	}
}

func TestProofErrors(t *testing.T) {
	leaves := vectorLeafHashes(t)
	if _, err := InclusionProof(8, leaves); err == nil {
		t.Error("an inclusion proof of a leaf past the end")
	}
	if _, err := InclusionProof(0, nil); err == nil {
		t.Error("an inclusion proof in the empty tree")
	}
	if _, err := NewConsistencyProver(9, 8); err == nil {
		t.Error("a consistency proof from a larger tree")
	}
	p, _ := NewInclusionProver(3, 8)
	for _, l := range leaves[:5] {
		p.Add(l)
	}
	if _, err := p.Proof(); err == nil {
		t.Error("a proof before every leaf was added")
	}
	if p.Added() != 5 || p.Size() != 8 {
		t.Errorf("added %d of %d", p.Added(), p.Size())
	}
	for range 3 {
		p.AddData(nil) // the leaf data does not matter for the shape
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("no panic adding a ninth leaf to a proof of eight")
			}
		}()
		p.Add(leaves[0])
	}()

	root8, root6 := rootHash(t, 8), rootHash(t, 6)
	if err := VerifyInclusion(8, 8, leaves[0], nil, root8); err == nil {
		t.Error("verified a leaf past the end")
	}
	if err := VerifyConsistency(9, 8, nil, root8, root8); err == nil {
		t.Error("verified consistency from a larger tree")
	}
	if err := VerifyConsistency(8, 8, nil, root8, root8); err != nil {
		t.Errorf("a tree is consistent with itself: %v", err)
	}
	if err := VerifyConsistency(8, 8, nil, root6, root8); !errors.Is(err, ErrProof) {
		t.Errorf("the same size with two roots: %v", err)
	}
	if err := VerifyConsistency(8, 8, []Hash{root6}, root8, root8); err == nil {
		t.Error("a proof of the same size with hashes")
	}
	if err := VerifyConsistency(0, 8, nil, EmptyRoot(), root8); err != nil {
		t.Errorf("every tree extends the empty one: %v", err)
	}
	if err := VerifyConsistency(0, 8, nil, root6, root8); !errors.Is(err, ErrProof) {
		t.Errorf("the empty tree with another root: %v", err)
	}
	// A consistency proof is not an inclusion proof, nor the other way.
	cons, _ := ConsistencyProof(6, leaves)
	if VerifyInclusion(5, 8, leaves[5], cons, root8) == nil {
		t.Error("a consistency proof verified as an inclusion proof")
	}
}

func BenchmarkInclusionProver(b *testing.B) {
	leaves := leavesFor(1 << 16)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := InclusionProof(12345, leaves); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(leaves)), "ns/leaf")
}

func BenchmarkVerifyInclusion(b *testing.B) {
	leaves := leavesFor(1 << 16)
	proof, _ := InclusionProof(12345, leaves)
	root := RootOf(leaves)
	b.ReportAllocs()
	for b.Loop() {
		if err := VerifyInclusion(12345, uint64(len(leaves)), leaves[12345], proof, root); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyConsistency(b *testing.B) {
	leaves := leavesFor(1 << 16)
	proof, _ := ConsistencyProof(40000, leaves)
	old, root := RootOf(leaves[:40000]), RootOf(leaves)
	b.ReportAllocs()
	for b.Loop() {
		if err := VerifyConsistency(40000, uint64(len(leaves)), proof, old, root); err != nil {
			b.Fatal(err)
		}
	}
}
