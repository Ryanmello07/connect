// array-based ratchet-tree index arithmetic, per RFC 9420 appendix C and
// section 4.1.
//
// nothing in this file is cryptographic and nothing in it reads a node's
// contents, so it is deterministic, exhaustively testable, and safe to call
// from any goroutine. leaves are even-numbered nodes, with leaf L at node 2*L,
// and intermediate nodes are odd-numbered.
//
// the tree is always full: RFC 9420 section 7.7 states that adding or removing
// leaves doubles or halves the tree, so a valid leaf count is always a power of
// two. every function here that takes a leaf count enforces that, which is
// stricter than the appendix C pseudocode and deliberately so — appendix C with
// a non-power-of-two count silently answers for the enclosing full tree and can
// return an index past the end of the node array.
//
// no group-size policy lives here. the 500-member and 10-device caps are v1
// product rules enforced in commit.go.
package mls

import (
	"errors"
	"math/bits"
)

// the index of a leaf, counted from zero at the left. a member of the group
// occupies exactly one leaf.
type LeafIndex uint32

// the index of any node in the flat array, leaf or parent.
type NodeIndex uint32

// the number of leaves in a tree, always a power of two for a valid tree
// (RFC 9420 section 7.7).
type LeafCount uint32

// the largest representable tree. node width of this count is 2^32-1, the
// largest value a node index can hold, so every index computation in this file
// stays inside uint32 without a carry.
const MaxLeafCount LeafCount = 1 << 31

var (
	ErrLeafCountRange    = errors.New("mls: leaf count out of range")
	ErrLeafCountNotFull  = errors.New("mls: leaf count is not a power of two")
	ErrNodeOutOfRange    = errors.New("mls: node index outside the tree")
	ErrLeafOutOfRange    = errors.New("mls: leaf index outside the tree")
	ErrNodeIsParent      = errors.New("mls: node index is a parent, not a leaf")
	ErrLeafHasNoChildren = errors.New("mls: leaf node has no children")
	ErrRootHasNoParent   = errors.New("mls: root node has no parent")
	ErrRootHasNoSibling  = errors.New("mls: root node has no sibling")
	ErrNodeWidthNotOdd   = errors.New("mls: node array width is not odd")
)

// the exponent of the largest power of two not greater than x. zero for x == 0,
// matching the appendix C special case rather than being undefined there.
func log2(x uint32) uint32 {
	if x == 0 {
		return 0
	}
	return uint32(bits.Len32(x) - 1)
}

// the array position of a leaf: leaf L sits at node 2*L.
//
// total, and so wraps rather than refusing: a leaf index of 2^31 or above sits
// in no representable tree, and 2*L for it is taken modulo 2^32 — leaf 2^31
// answers node 0, indistinguishable from leaf 0. every caller range-checks its
// leaf count against MaxLeafCount before converting, so no reachable path holds
// an index that large, but a zero from this function is not an error signal.
func (self LeafIndex) NodeIndex() NodeIndex {
	return NodeIndex(2 * uint32(self))
}

// even node indices are leaves, odd ones are parents.
func (self NodeIndex) IsLeaf() bool {
	return self&0x01 == 0
}

// the inverse of LeafIndex.NodeIndex, refused for a parent rather than
// silently truncating.
func (self NodeIndex) LeafIndex() (LeafIndex, error) {
	if !self.IsLeaf() {
		return 0, ErrNodeIsParent
	}
	return LeafIndex(uint32(self) / 2), nil
}

// leaves are level zero, their parents level one, and so on. the level of an
// odd index is its count of trailing one bits.
//
// the only index whose level is 32 is 0xFFFFFFFF, which is one past the last
// node of the largest representable tree and therefore never inside one; the
// value is returned rather than special-cased so this stays a total function.
func (self NodeIndex) Level() uint32 {
	if self.IsLeaf() {
		return 0
	}
	return uint32(bits.TrailingZeros32(^uint32(self)))
}

// the number of nodes in the flat array for a tree with n leaves.
//
// deliberately total and deliberately not restricted to full leaf counts: the
// ratchet_tree extension carries an array with its trailing blank nodes
// stripped, so a width of node_width(6) = 11 is a legal thing to reason about
// even though a tree never has six leaves. a count past MaxLeafCount returns
// zero so that every downstream range check fails closed.
func NodeWidth(n LeafCount) uint32 {
	if n == 0 || n > MaxLeafCount {
		return 0
	}
	return 2*(uint32(n)-1) + 1
}

// whether n is a leaf count a valid tree can actually have: non-zero, in range,
// and a power of two.
func IsFullLeafCount(n LeafCount) bool {
	return n > 0 && n <= MaxLeafCount && n&(n-1) == 0
}

// the depth of the full tree that contains n leaves, which is the length of any
// leaf's direct path in that tree. one leaf is depth zero.
func TreeDepth(n LeafCount) uint32 {
	if n <= 1 {
		return 0
	}
	return uint32(bits.Len32(uint32(n) - 1))
}

// the smallest full leaf count that contains n leaves. zero for n == 0 and for
// n past MaxLeafCount, so an out-of-range count fails closed.
func FullLeafCount(n LeafCount) LeafCount {
	if n == 0 || n > MaxLeafCount {
		return 0
	}
	return LeafCount(1) << TreeDepth(n)
}

// the leaf count an array of w nodes describes. every node array has an odd
// width, and a truncated ratchet_tree array yields a count that is not a power
// of two — pass the result through FullLeafCount to get the tree it belongs to.
func LeafCountFromNodeWidth(w uint32) (LeafCount, error) {
	if w == 0 || w%2 == 0 {
		return 0, ErrNodeWidthNotOdd
	}
	return LeafCount((uint64(w) + 1) / 2), nil
}

// the leaf count after adding a blank root whose left subtree is the existing
// tree (RFC 9420 section 7.7). an empty tree extends to one leaf.
func ExtendedLeafCount(n LeafCount) (LeafCount, error) {
	if n == 0 {
		return 1, nil
	}
	if !IsFullLeafCount(n) {
		return 0, ErrLeafCountNotFull
	}
	if n == MaxLeafCount {
		return 0, ErrLeafCountRange
	}
	return n * 2, nil
}

// the leaf count after removing right subtrees until one holds a non-blank leaf
// (RFC 9420 section 12.1.3): 2^d for the smallest d with 2^d greater than the
// index of the rightmost non-blank leaf.
//
// which leaf that is depends on node contents and is decided by the caller;
// only the arithmetic lives here.
func TruncatedLeafCount(rightmostNonBlankLeaf LeafIndex) (LeafCount, error) {
	if LeafCount(rightmostNonBlankLeaf) >= MaxLeafCount {
		return 0, ErrLeafOutOfRange
	}
	return LeafCount(1) << TreeDepth(LeafCount(rightmostNonBlankLeaf)+1), nil
}

// the shared entry check for every function that takes a leaf count and answers
// about a real tree.
func checkLeafCount(n LeafCount) error {
	if n == 0 || n > MaxLeafCount {
		return ErrLeafCountRange
	}
	if !IsFullLeafCount(n) {
		return ErrLeafCountNotFull
	}
	return nil
}
