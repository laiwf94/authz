package merkle

import (
	"errors"
	"fmt"
	"math/bits"
	"slices"
)

// Proofs
//
// An inclusion proof (RFC 6962 section 2.1.1, RFC 9162 section 2.1.3) shows
// that a leaf is the one at an index of the tree of a size, given only that
// tree's root: it is the hashes of the subtrees beside the path from the
// leaf to the root, deepest first. A consistency proof (RFC 6962 section
// 2.1.2, RFC 9162 section 2.1.4) shows that the tree of an earlier size is a
// prefix of the tree of a later one, given only the two roots: it is the
// hashes of the subtrees that build both roots.
//
// Either proof is a list of the roots of disjoint ranges of leaves, which
// Spans names. A Prover computes them in one pass over the leaves in order,
// holding a compact range for the subtree being read and one for the whole
// tree, so a log on disk is proved without keeping its leaves in memory or
// storing interior nodes.

// Span is the range of leaves [Start, End) whose root is one proof hash.
type Span struct{ Start, End uint64 }

// ErrProof means a proof does not lead to the root it was checked against.
var ErrProof = errors.New("merkle: the proof does not verify")

// split is the largest power of two smaller than n, for n > 1: where the
// tree of n leaves divides.
func split(n uint64) uint64 { return 1 << (bits.Len64(n-1) - 1) }

// InclusionSpans names the subtrees an inclusion proof of leaf index in the
// tree of size leaves is made of, deepest first: PATH(m, D[n]) of RFC 6962.
func InclusionSpans(index, size uint64) ([]Span, error) {
	if index >= size {
		return nil, fmt.Errorf("merkle: leaf %d is not in a tree of %d leaves", index, size)
	}
	var out []Span
	// Walk down from the root, then reverse: the RFC lists the deepest
	// sibling first.
	for lo, n, m := uint64(0), size, index; n > 1; {
		k := split(n)
		if m < k {
			out = append(out, Span{lo + k, lo + n})
			n = k
		} else {
			out = append(out, Span{lo, lo + k})
			lo, n, m = lo+k, n-k, m-k
		}
	}
	slices.Reverse(out)
	return out, nil
}

// ConsistencySpans names the subtrees a consistency proof from the tree of
// from leaves to the tree of size leaves is made of: PROOF(m, D[n]) of RFC
// 6962, empty when from is 0 or size.
func ConsistencySpans(from, size uint64) ([]Span, error) {
	if from > size {
		return nil, fmt.Errorf("merkle: a tree of %d leaves cannot extend one of %d", size, from)
	}
	if from == 0 || from == size {
		return nil, nil
	}
	var out []Span
	// SUBPROOF(m, D[lo:lo+n], b), unrolled; the hashes it appends after
	// the recursion are collected on the way down and reversed.
	lo, n, m, whole := uint64(0), size, from, true
	for m != n {
		k := split(n)
		if m <= k {
			out = append(out, Span{lo + k, lo + n})
			n = k
		} else {
			out = append(out, Span{lo, lo + k})
			lo, n, m, whole = lo+k, n-k, m-k, false
		}
	}
	if !whole {
		out = append(out, Span{lo, lo + n})
	}
	slices.Reverse(out)
	return out, nil
}

// Prover computes a proof's hashes from the leaves of the tree, added in
// order with Add.
type Prover struct {
	size  uint64
	spans []Span
	order []int // indexes into spans, by Start
	next  int   // the first span in order not yet complete
	sub   Range // the leaves of the span being read
	all   Range // every leaf so far
	out   []Hash

	at       uint64 // a leaf whose hash to keep (inclusion); size if none
	leaf     Hash
	prefix   uint64 // a size whose root to keep (consistency); 0 if none
	prefixAt Hash
}

func newProver(size uint64, spans []Span) *Prover {
	p := &Prover{size: size, spans: spans, at: size, out: make([]Hash, len(spans))}
	p.order = make([]int, len(spans))
	for i := range p.order {
		p.order[i] = i
	}
	slices.SortFunc(p.order, func(a, b int) int {
		switch {
		case spans[a].Start < spans[b].Start:
			return -1
		case spans[a].Start > spans[b].Start:
			return 1
		}
		return 0
	})
	return p
}

// NewInclusionProver proves that leaf index is in the tree of size leaves.
func NewInclusionProver(index, size uint64) (*Prover, error) {
	spans, err := InclusionSpans(index, size)
	if err != nil {
		return nil, err
	}
	p := newProver(size, spans)
	p.at = index
	return p, nil
}

// NewConsistencyProver proves that the tree of size leaves extends the tree
// of from leaves.
func NewConsistencyProver(from, size uint64) (*Prover, error) {
	spans, err := ConsistencySpans(from, size)
	if err != nil {
		return nil, err
	}
	p := newProver(size, spans)
	p.prefix = from
	if from == 0 {
		p.prefixAt = EmptyRoot()
	}
	return p, nil
}

// Size is the number of leaves the prover needs: every leaf of the tree
// the proof is for.
func (p *Prover) Size() uint64 { return p.size }

// Added is the number of leaves added so far.
func (p *Prover) Added() uint64 { return p.all.Size() }

// Add adds the next leaf by its hash. It panics past Size leaves.
func (p *Prover) Add(leaf Hash) {
	i := p.all.Size()
	if i >= p.size {
		panic("merkle: more leaves than the proof's tree holds")
	}
	if i == p.at {
		p.leaf = leaf
	}
	p.all.Append(leaf)
	if p.all.Size() == p.prefix {
		p.prefixAt = p.all.Root()
	}
	if p.next == len(p.order) {
		return
	}
	s := p.spans[p.order[p.next]]
	if i < s.Start {
		return
	}
	p.sub.Append(leaf)
	if i+1 == s.End {
		p.out[p.order[p.next]] = p.sub.Root()
		p.sub = Range{hashes: p.sub.hashes[:0]}
		p.next++
	}
}

// AddData adds the next leaf holding data.
func (p *Prover) AddData(data []byte) { p.Add(LeafHash(data)) }

// Proof returns the proof's hashes, once every leaf was added.
func (p *Prover) Proof() ([]Hash, error) {
	if p.all.Size() != p.size {
		return nil, fmt.Errorf("merkle: the proof needs %d leaves, but %d were added", p.size, p.all.Size())
	}
	return p.out, nil
}

// Root is the root of the leaves added so far: the tree head the proof
// leads to, once every leaf was added.
func (p *Prover) Root() Hash { return p.all.Root() }

// Leaf is the hash of the leaf an inclusion proof is for, once it was
// added.
func (p *Prover) Leaf() Hash { return p.leaf }

// PrefixRoot is the root of the earlier tree a consistency proof starts
// from, once its leaves were added.
func (p *Prover) PrefixRoot() Hash { return p.prefixAt }

// InclusionProof is the inclusion proof of leaf index in the tree of the
// given leaves.
func InclusionProof(index uint64, leaves []Hash) ([]Hash, error) {
	p, err := NewInclusionProver(index, uint64(len(leaves)))
	if err != nil {
		return nil, err
	}
	for _, l := range leaves {
		p.Add(l)
	}
	return p.Proof()
}

// ConsistencyProof is the consistency proof from the tree of the first from
// leaves to the tree of all of them.
func ConsistencyProof(from uint64, leaves []Hash) ([]Hash, error) {
	p, err := NewConsistencyProver(from, uint64(len(leaves)))
	if err != nil {
		return nil, err
	}
	for _, l := range leaves {
		p.Add(l)
	}
	return p.Proof()
}

// VerifyInclusion checks that leaf is leaf index of the tree of size leaves
// with root root, by proof: the algorithm of RFC 9162 section 2.1.3.2.
func VerifyInclusion(index, size uint64, leaf Hash, proof []Hash, root Hash) error {
	if index >= size {
		return fmt.Errorf("merkle: leaf %d is not in a tree of %d leaves", index, size)
	}
	if want := inclusionLen(index, size); len(proof) != want {
		return fmt.Errorf("merkle: an inclusion proof of leaf %d in %d leaves has %d hashes, not %d", index, size, want, len(proof))
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return ErrProof
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn, sn = fn>>1, sn>>1
				}
			}
		} else {
			r = NodeHash(r, p)
		}
		fn, sn = fn>>1, sn>>1
	}
	if sn != 0 || r != root {
		return ErrProof
	}
	return nil
}

// VerifyConsistency checks that the tree of size leaves with root root
// extends the tree of from leaves with root fromRoot, by proof: the
// algorithm of RFC 9162 section 2.1.4.2, with the trivial cases of a tree
// that did not grow (an empty proof and equal roots) and of the empty tree
// (an empty proof) allowed.
func VerifyConsistency(from, size uint64, proof []Hash, fromRoot, root Hash) error {
	switch {
	case from > size:
		return fmt.Errorf("merkle: a tree of %d leaves cannot extend one of %d", size, from)
	case from == size || from == 0:
		if len(proof) != 0 {
			return fmt.Errorf("merkle: a consistency proof from %d to %d leaves has no hashes, not %d", from, size, len(proof))
		}
		if from == 0 && fromRoot != EmptyRoot() || from == size && fromRoot != root {
			return ErrProof
		}
		return nil
	}
	if want := consistencyLen(from, size); len(proof) != want {
		return fmt.Errorf("merkle: a consistency proof from %d to %d leaves has %d hashes, not %d", from, size, want, len(proof))
	}
	path := proof
	if from&(from-1) == 0 {
		// The old tree is a perfect subtree of the new: its root starts
		// the path.
		path = append([]Hash{fromRoot}, proof...)
	}
	fn, sn := from-1, size-1
	for fn&1 == 1 {
		fn, sn = fn>>1, sn>>1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return ErrProof
		}
		if fn&1 == 1 || fn == sn {
			fr, sr = NodeHash(c, fr), NodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn, sn = fn>>1, sn>>1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn, sn = fn>>1, sn>>1
	}
	if sn != 0 || fr != fromRoot || sr != root {
		return ErrProof
	}
	return nil
}

func inclusionLen(index, size uint64) int {
	s, _ := InclusionSpans(index, size)
	return len(s)
}

func consistencyLen(from, size uint64) int {
	s, _ := ConsistencySpans(from, size)
	return len(s)
}
