package merkle

import (
	"errors"
	"math/rand/v2"
	"slices"
	"testing"
)

// skipped runs a prover made by mk over leaves, skipping the first n with
// their compact range.
func skipped(t *testing.T, mk func() (*Prover, error), leaves []Hash, n uint64) (*Prover, error) {
	t.Helper()
	p, err := mk()
	if err != nil {
		t.Fatal(err)
	}
	var base Range
	for _, l := range leaves[:n] {
		base.Append(l)
	}
	if err := p.Skip(&base); err != nil {
		return nil, err
	}
	for _, l := range leaves[n:] {
		p.Add(l)
	}
	return p, nil
}

// Every leaf, every earlier tree and every skip point up to 40 leaves: a
// prover that skipped the first leaves with their compact range gives the
// proof a prover of every leaf gives, whenever the leaf it proves (or the
// tree it proves consistency from) was not skipped. Then the RFC recursion
// never needs a hash inside a skipped subtree.
func TestSkipMatchesFullProver(t *testing.T) {
	all := leavesFor(40)
	for size := uint64(1); size <= 40; size++ {
		leaves := all[:size]
		for n := uint64(0); n <= size; n++ {
			for index := range size {
				p, err := skipped(t, func() (*Prover, error) { return NewInclusionProver(index, size) }, leaves, n)
				if index < n {
					if !errors.Is(err, ErrPruned) {
						t.Fatalf("inclusion of %d in %d after skipping %d: %v, want ErrPruned", index, size, n, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("inclusion of %d in %d after skipping %d: %v", index, size, n, err)
				}
				got, err := p.Proof()
				if err != nil {
					t.Fatal(err)
				}
				want, _ := InclusionProof(index, leaves)
				if !slices.Equal(got, want) || p.Leaf() != leaves[index] || p.Root() != RootOf(leaves) {
					t.Fatalf("inclusion of %d in %d after skipping %d differs", index, size, n)
				}
			}
			for from := uint64(0); from <= size; from++ {
				p, err := skipped(t, func() (*Prover, error) { return NewConsistencyProver(from, size) }, leaves, n)
				if from != 0 && from < n {
					if !errors.Is(err, ErrPruned) {
						t.Fatalf("consistency from %d to %d after skipping %d: %v, want ErrPruned", from, size, n, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("consistency from %d to %d after skipping %d: %v", from, size, n, err)
				}
				got, err := p.Proof()
				if err != nil {
					t.Fatal(err)
				}
				want, _ := ConsistencyProof(from, leaves)
				if !slices.Equal(got, want) || p.PrefixRoot() != RootOf(leaves[:from]) {
					t.Fatalf("consistency from %d to %d after skipping %d differs", from, size, n)
				}
			}
		}
	}
}

// At random sizes up to 2^16, proofs after a skip verify.
func TestSkipRandomSizes(t *testing.T) {
	rng := rand.New(rand.NewPCG(9162, 6962))
	all := leavesFor(1 << 12)
	leafAt := func(i uint64) Hash { return all[i%uint64(len(all))] }
	for range 30 {
		size := 2 + rng.Uint64N(1<<16)
		n := rng.Uint64N(size)
		index := n + rng.Uint64N(size-n)
		from := n + rng.Uint64N(size-n+1)
		var base Range
		for i := range n {
			base.Append(leafAt(i))
		}
		ip, _ := NewInclusionProver(index, size)
		cp, _ := NewConsistencyProver(from, size)
		if err := ip.Skip(&base); err != nil {
			t.Fatalf("inclusion of %d in %d after skipping %d: %v", index, size, n, err)
		}
		if err := cp.Skip(&base); err != nil {
			t.Fatalf("consistency from %d to %d after skipping %d: %v", from, size, n, err)
		}
		for i := n; i < size; i++ {
			ip.Add(leafAt(i))
			cp.Add(leafAt(i))
		}
		incl, err := ip.Proof()
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyInclusion(index, size, leafAt(index), incl, ip.Root()); err != nil {
			t.Fatalf("inclusion of %d in %d after skipping %d: %v", index, size, n, err)
		}
		cons, err := cp.Proof()
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyConsistency(from, size, cons, cp.PrefixRoot(), cp.Root()); err != nil {
			t.Fatalf("consistency from %d to %d after skipping %d: %v", from, size, n, err)
		}
	}
}

func TestSkipErrors(t *testing.T) {
	leaves := leavesFor(8)
	var base Range
	for _, l := range leaves[:5] {
		base.Append(l)
	}
	p, _ := NewInclusionProver(6, 8)
	p.Add(leaves[0])
	if err := p.Skip(&base); err == nil {
		t.Fatal("Skip after Add succeeded")
	}
	p, _ = NewInclusionProver(2, 4)
	if err := p.Skip(&base); err == nil || errors.Is(err, ErrPruned) {
		t.Fatalf("skipping 5 leaves of 4: %v", err)
	}
	// Skipping nothing changes nothing.
	p, _ = NewInclusionProver(3, 8)
	if err := p.Skip(&Range{}); err != nil {
		t.Fatal(err)
	}
	for _, l := range leaves {
		p.Add(l)
	}
	got, _ := p.Proof()
	want, _ := InclusionProof(3, leaves)
	if !slices.Equal(got, want) {
		t.Fatal("skipping no leaves changed the proof")
	}
}
