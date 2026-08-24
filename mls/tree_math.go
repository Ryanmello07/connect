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
	// range is tested before fullness, matching checkLeafCount, because a count
	// past MaxLeafCount is both out of range and not a power of two and the
	// order alone decides which sentinel the caller sees. Testing fullness
	// first reported MaxLeafCount+1 as ErrLeafCountNotFull here while the shared
	// check called the same value ErrLeafCountRange, so a caller switching on the
	// sentinel would have had to know which function produced it.
	if n > MaxLeafCount {
		return 0, ErrLeafCountRange
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

// the index of the root of a tree with n leaves.
//
// the root sits at 2^d - 1 for a tree of depth d, so it is the one index that
// is the same for every count in a doubling band — which is exactly why a
// non-power-of-two count is refused here rather than quietly answered.
func Root(n LeafCount) (NodeIndex, error) {
	if err := checkLeafCount(n); err != nil {
		return 0, err
	}
	w := NodeWidth(n)
	return NodeIndex((uint32(1) << log2(w)) - 1), nil
}

// the left child of a parent node. children are computed from the index alone,
// so no leaf count is needed and the answer is the same in every tree that
// contains x.
func Left(x NodeIndex) (NodeIndex, error) {
	k := x.Level()
	if k == 0 {
		return 0, ErrLeafHasNoChildren
	}
	if k > 31 {
		return 0, ErrNodeOutOfRange
	}
	return x ^ NodeIndex(uint32(0x01)<<(k-1)), nil
}

// the right child of a parent node.
func Right(x NodeIndex) (NodeIndex, error) {
	k := x.Level()
	if k == 0 {
		return 0, ErrLeafHasNoChildren
	}
	if k > 31 {
		return 0, ErrNodeOutOfRange
	}
	return x ^ NodeIndex(uint32(0x03)<<(k-1)), nil
}

// the parent of a node in a tree with n leaves.
//
// the leaf count is used only to locate the root, exactly as in appendix C; the
// arithmetic itself is index-only. it is done in uint64 so the shift by k+1 is
// obviously in range without an argument about the maximum level of a non-root
// node.
func Parent(x NodeIndex, n LeafCount) (NodeIndex, error) {
	r, err := Root(n)
	if err != nil {
		return 0, err
	}
	if uint32(x) >= NodeWidth(n) {
		return 0, ErrNodeOutOfRange
	}
	if x == r {
		return 0, ErrRootHasNoParent
	}
	k := uint64(x.Level())
	b := (uint64(x) >> (k + 1)) & 0x01
	return NodeIndex((uint64(x) | (uint64(1) << k)) ^ (b << (k + 1))), nil
}

// the other child of the node's parent.
func Sibling(x NodeIndex, n LeafCount) (NodeIndex, error) {
	p, err := Parent(x, n)
	if err != nil {
		if errors.Is(err, ErrRootHasNoParent) {
			return 0, ErrRootHasNoSibling
		}
		return 0, err
	}
	if x < p {
		return Right(p)
	}
	return Left(p)
}

// the path from x to the root, ordered leaf to root, excluding x and including
// the root. the root's direct path is empty (RFC 9420 section 4.1.2).
//
// the result is always a slice and never nil, empty root included, so a caller
// can range over it without a nil check. a refusal carries no slice at all, so
// a caller that reads the value and drops the error walks nothing rather than
// walking a partly built path.
//
// the loop is bounded explicitly. it cannot run away for a validated index —
// every step moves to a strictly higher level and the root holds the highest —
// but a structural bound makes that a property of the code rather than of an
// argument about the code. the bound is pinned from below and not from above:
// the deepest tree walks a path of 31 nodes, so a bound of 29 or less truncates
// a real answer and the tests catch it, while every value from 30 up is
// indistinguishable from every other. measured, one version per value from 0 to
// 32: 0 through 29 fail, 30, 31 and 32 pass.
//
// the range check is a second line rather than the only one. Parent refuses an
// index past the end of the tree with the same sentinel and the same absent
// slice, so weakening this check, or skipping it at any one depth, changes
// nothing a caller can observe — measured, thirty-nine versions of it, every
// one indistinguishable from this one. it is kept because a function should
// enforce its own precondition rather than inherit it from the one it happens
// to call, and because a rewrite that walked ancestors by arithmetic instead of
// by Parent would leave nothing else guarding the entry.
func DirectPath(x NodeIndex, n LeafCount) ([]NodeIndex, error) {
	r, err := Root(n)
	if err != nil {
		return nil, err
	}
	if uint32(x) >= NodeWidth(n) {
		return nil, ErrNodeOutOfRange
	}

	pathNodes := make([]NodeIndex, 0, TreeDepth(n))
	for steps := uint32(0); x != r; steps += 1 {
		if steps > 32 {
			return nil, ErrNodeOutOfRange
		}
		x, err = Parent(x, n)
		if err != nil {
			return nil, err
		}
		pathNodes = append(pathNodes, x)
	}
	return pathNodes, nil
}

// the sibling of x followed by the sibling of every node on x's direct path
// except the root, ordered leaf to root (RFC 9420 section 4.1.2).
//
// always the same length as the direct path, and every entry is the child of
// the direct-path entry at the same position that x does not descend from. the
// root has an empty copath, and as with the direct path the empty result is a
// slice rather than nil and a refusal carries no slice.
//
// the range check here stands to DirectPath's as DirectPath's stands to
// Parent's, and is unobservable for the same reason and by the same
// measurement: thirty-nine versions of it, none of them distinguishable. the
// root case below is a shortcut rather than a correction — an empty direct path
// would yield an empty copath through the loop anyway — and is likewise
// indistinguishable from its own absence.
func Copath(x NodeIndex, n LeafCount) ([]NodeIndex, error) {
	r, err := Root(n)
	if err != nil {
		return nil, err
	}
	if uint32(x) >= NodeWidth(n) {
		return nil, ErrNodeOutOfRange
	}
	if x == r {
		return []NodeIndex{}, nil
	}

	pathNodes, err := DirectPath(x, n)
	if err != nil {
		return nil, err
	}

	// the siblings wanted are those of x and of every direct-path node below
	// the root, which is the direct path shifted down by one with x in front.
	// the root is never the argument to Sibling, which is why no refusal from
	// it can reach a caller here.
	copathNodes := make([]NodeIndex, 0, len(pathNodes))
	child := x
	for _, pathNode := range pathNodes {
		sibling, err := Sibling(child, n)
		if err != nil {
			return nil, err
		}
		copathNodes = append(copathNodes, sibling)
		child = pathNode
	}
	return copathNodes, nil
}
