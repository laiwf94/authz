// Package merkle is the Merkle tree of RFC 6962 (Certificate Transparency),
// section 2.1, as an append-only log keeps it: a compact range of at most
// 64 subtree hashes from which the tree head of every record so far is
// computed, extended one leaf at a time.
//
// A leaf's hash is SHA-256(0x00 || data) and an interior node's
// SHA-256(0x01 || left || right); the tree of no leaves has the hash of the
// empty string. The tree of n > 1 leaves splits at k, the largest power of
// two smaller than n: its root is the node of the tree of the first k leaves
// and the tree of the rest. The prefixes keep a leaf from passing for a node
// (second preimage resistance), and the split makes the tree of the first n
// leaves of a longer log a fixed set of its subtrees, which is what
// inclusion and consistency proofs rest on.
package merkle

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

// Size is the length of a hash.
const Size = sha256.Size

// Hash is a SHA-256 hash of a leaf, a node or a tree.
type Hash [Size]byte

// The domain separation prefixes of RFC 6962, section 2.1.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// LeafHash is the hash of a leaf holding data: SHA-256(0x00 || data).
func LeafHash(data []byte) Hash {
	d := sha256.New()
	d.Write([]byte{leafPrefix})
	d.Write(data)
	var h Hash
	d.Sum(h[:0])
	return h
}

// NodeHash is the hash of an interior node: SHA-256(0x01 || left || right).
func NodeHash(left, right Hash) Hash {
	var buf [1 + 2*Size]byte
	buf[0] = nodePrefix
	copy(buf[1:], left[:])
	copy(buf[1+Size:], right[:])
	return sha256.Sum256(buf[:])
}

// EmptyRoot is the root of the tree of no leaves: the SHA-256 of nothing.
func EmptyRoot() Hash { return sha256.Sum256(nil) }

// RootOf is the root of the tree of the given leaf hashes, computed by the
// recursion of RFC 6962 as written. It is the reference Range is checked
// against; a log uses Range.
func RootOf(leaves []Hash) Hash {
	switch n := len(leaves); n {
	case 0:
		return EmptyRoot()
	case 1:
		return leaves[0]
	default:
		k := 1 << (bits.Len(uint(n-1)) - 1) // largest power of two < n
		return NodeHash(RootOf(leaves[:k]), RootOf(leaves[k:]))
	}
}

// Range is the compact range of the first Size leaves of a tree: the roots
// of its perfect subtrees, largest first, one for each set bit of the size.
// Leaves 0 to 11, say, are the subtrees of leaves 0 to 7 and 8 to 11. The
// zero Range is the tree of no leaves.
//
// Appending a leaf adds a subtree of one leaf and merges equal subtrees
// from the right, as a binary counter carries, so it costs one node hash on
// average and never more than 64. The root folds the subtrees from the
// right, which is the RFC 6962 split at every level. A Range holds at most
// 64 hashes (2 KiB), whatever the size.
type Range struct {
	size   uint64
	hashes []Hash
}

// NewRange is the compact range of the first size leaves, with the subtree
// hashes largest first. There must be one for each set bit of size.
func NewRange(size uint64, hashes []Hash) (*Range, error) {
	if len(hashes) != bits.OnesCount64(size) {
		return nil, fmt.Errorf("merkle: a range of %d leaves has %d subtrees, not %d", size, bits.OnesCount64(size), len(hashes))
	}
	return &Range{size: size, hashes: append([]Hash(nil), hashes...)}, nil
}

// Size is the number of leaves.
func (r *Range) Size() uint64 { return r.size }

// Hashes returns the subtree hashes, largest first. The caller must not
// change them.
func (r *Range) Hashes() []Hash { return r.hashes }

// Clone returns a copy that appends independently of r.
func (r *Range) Clone() *Range {
	return &Range{size: r.size, hashes: append(make([]Hash, 0, cap(r.hashes)), r.hashes...)}
}

// Append adds a leaf by its hash (LeafHash of its data).
func (r *Range) Append(leaf Hash) {
	if r.size == ^uint64(0) {
		panic("merkle: range is full")
	}
	r.hashes = append(r.hashes, leaf)
	// Each trailing one bit of the old size is a subtree as large as the
	// one just completed: merge them, as a carry ripples.
	for s := r.size; s&1 == 1; s >>= 1 {
		n := len(r.hashes)
		r.hashes[n-2] = NodeHash(r.hashes[n-2], r.hashes[n-1])
		r.hashes = r.hashes[:n-1]
	}
	r.size++
}

// AppendData adds a leaf holding data.
func (r *Range) AppendData(data []byte) { r.Append(LeafHash(data)) }

// Root is the tree head: the root of the tree of the first Size leaves.
func (r *Range) Root() Hash {
	n := len(r.hashes)
	if n == 0 {
		return EmptyRoot()
	}
	h := r.hashes[n-1]
	for i := n - 2; i >= 0; i-- {
		h = NodeHash(r.hashes[i], h)
	}
	return h
}

// MarshalBinary encodes the range: the size as 8 bytes big-endian, then the
// subtree hashes largest first.
func (r *Range) MarshalBinary() ([]byte, error) {
	b := make([]byte, 8, 8+Size*len(r.hashes))
	binary.BigEndian.PutUint64(b, r.size)
	for _, h := range r.hashes {
		b = append(b, h[:]...)
	}
	return b, nil
}

// UnmarshalBinary decodes what MarshalBinary wrote, refusing any other
// length than the size calls for.
func (r *Range) UnmarshalBinary(b []byte) error {
	if len(b) < 8 {
		return errors.New("merkle: an encoded range starts with its size in 8 bytes")
	}
	size := binary.BigEndian.Uint64(b)
	want := bits.OnesCount64(size)
	if len(b)-8 != want*Size {
		return fmt.Errorf("merkle: an encoded range of %d leaves holds %d hashes, %d bytes, not %d", size, want, 8+want*Size, len(b))
	}
	hashes := make([]Hash, want)
	for i := range hashes {
		copy(hashes[i][:], b[8+i*Size:])
	}
	r.size, r.hashes = size, hashes
	return nil
}
