// unit tests for the array-based ratchet-tree arithmetic.
//
// the mlswg tree-math vector family covers six of this file's twenty-four
// exported callables and only at power-of-two sizes, so the tests here carry
// the rest: the two worked examples RFC 9420 publishes, a differential against
// the RFC's own second definition of the common ancestor, and an exhaustive
// sweep of every node of every tree size up to 512 leaves.
package mls

import (
	"errors"
	"testing"
)

func TestNodeIndexLevelAndLeafMapping(t *testing.T) {
	// RFC 9420 figure 32, the eight-leaf tree drawn as an array.
	levelCases := []struct {
		nodeIndex NodeIndex
		level     uint32
	}{
		{nodeIndex: 0, level: 0},
		{nodeIndex: 1, level: 1},
		{nodeIndex: 2, level: 0},
		{nodeIndex: 3, level: 2},
		{nodeIndex: 4, level: 0},
		{nodeIndex: 5, level: 1},
		{nodeIndex: 6, level: 0},
		{nodeIndex: 7, level: 3},
		{nodeIndex: 8, level: 0},
		{nodeIndex: 9, level: 1},
		{nodeIndex: 10, level: 0},
		{nodeIndex: 11, level: 2},
		{nodeIndex: 12, level: 0},
		{nodeIndex: 13, level: 1},
		{nodeIndex: 14, level: 0},
	}
	for _, c := range levelCases {
		if got := c.nodeIndex.Level(); got != c.level {
			t.Errorf("node %d level: %d, want %d", c.nodeIndex, got, c.level)
		}
		wantLeaf := c.level == 0
		if got := c.nodeIndex.IsLeaf(); got != wantLeaf {
			t.Errorf("node %d is leaf: %v, want %v", c.nodeIndex, got, wantLeaf)
		}
	}

	for leaf := LeafIndex(0); leaf < 8; leaf += 1 {
		nodeIndex := leaf.NodeIndex()
		if nodeIndex != NodeIndex(2*leaf) {
			t.Errorf("leaf %d node index: %d, want %d", leaf, nodeIndex, 2*leaf)
		}
		back, err := nodeIndex.LeafIndex()
		if err != nil {
			t.Errorf("node %d leaf index: %v", nodeIndex, err)
			continue
		}
		if back != leaf {
			t.Errorf("node %d leaf index: %d, want %d", nodeIndex, back, leaf)
		}
	}

	if _, err := NodeIndex(1).LeafIndex(); !errors.Is(err, ErrNodeIsParent) {
		t.Errorf("node 1 leaf index error: %v, want %v", err, ErrNodeIsParent)
	}

	// the eight-leaf fixture above stops at node 14 and leaf 7, so nothing in
	// it reaches the top of the index range. measured, not assumed: with only
	// the rows above, three wrong versions pass — one that clamps the level to
	// 31, and one on each direction of the leaf mapping that returns zero near
	// 2^31. the range is not decoration. the file's own comment says
	// 0xFFFFFFFF is the single index of level 32, and the out-of-range refusal
	// in the children functions is built on that being true, so it is asserted
	// here rather than left to a downstream task to depend on.
	//
	// that argument applies to the middle of the range too, and this table at
	// first did not carry it there: it jumped from the fixture's level 3
	// straight to 31. also measured — with only the fixture and the two
	// endpoints, a Level wrong by one across an interior band passes, and
	// nothing else in these tests covers that band either. the invariant sweep
	// stops at 512 leaves, so it reaches level 9; the fuzz target asserts only
	// that the level is at most 32. levels 5, 16 and 30 are asserted below,
	// which cuts the widest unasserted run from twenty-seven levels (4 to 30)
	// to thirteen (17 to 29).
	//
	// no live group reaches any of this. the v1 product cap is 500 members, so
	// a real tree stops at level 9. these rows are gate strength, not a bug.
	boundaryLevelCases := []struct {
		nodeIndex NodeIndex
		level     uint32
	}{
		// the last node of the largest representable tree, holding its last leaf.
		{nodeIndex: 0xFFFFFFFE, level: 0},
		// three interior levels: 2^5-1, 2^16-1 and 2^30-1, each the root of a
		// subtree that a tree of that depth would actually contain.
		{nodeIndex: 0x0000001F, level: 5},
		{nodeIndex: 0x0000FFFF, level: 16},
		{nodeIndex: 0x3FFFFFFF, level: 30},
		// the root of that tree, 2^31-1, every bit below bit 31 set.
		{nodeIndex: 0x7FFFFFFF, level: 31},
		// one past the end of that tree, and so inside no tree at all.
		{nodeIndex: 0xFFFFFFFF, level: 32},
	}
	for _, c := range boundaryLevelCases {
		if got := c.nodeIndex.Level(); got != c.level {
			t.Errorf("node %d level: %d, want %d", c.nodeIndex, got, c.level)
		}
		wantLeaf := c.level == 0
		if got := c.nodeIndex.IsLeaf(); got != wantLeaf {
			t.Errorf("node %d is leaf: %v, want %v", c.nodeIndex, got, wantLeaf)
		}
	}

	lastLeaf := LeafIndex(MaxLeafCount - 1)
	if got := lastLeaf.NodeIndex(); got != NodeIndex(0xFFFFFFFE) {
		t.Errorf("leaf %d node index: %d, want %d", lastLeaf, got, uint32(0xFFFFFFFE))
	}
	lastBack, err := NodeIndex(0xFFFFFFFE).LeafIndex()
	if err != nil {
		t.Fatalf("node 0xFFFFFFFE leaf index: %v", err)
	}
	if lastBack != lastLeaf {
		t.Errorf("node 0xFFFFFFFE leaf index: %d, want %d", lastBack, lastLeaf)
	}
	if _, err := NodeIndex(0xFFFFFFFF).LeafIndex(); !errors.Is(err, ErrNodeIsParent) {
		t.Errorf("node 0xFFFFFFFF leaf index error: %v, want %v", err, ErrNodeIsParent)
	}
}

func TestNodeWidth(t *testing.T) {
	// NodeWidth is the one sizing function deliberately not restricted to full
	// leaf counts, because the ratchet_tree extension carries a stripped array
	// — so the non-power-of-two counts are the reason the function is written
	// the way it is, and they are the rows worth having. the table originally
	// tested exactly two of them, 3 and 6, and no other test in the plan covers
	// any: the vector family and the invariant sweep are powers of two, and the
	// Task 3 round trip adds only 3 and 6 again. measured — with 3 and 6 alone,
	// a NodeWidth that conflates counts above six with the enclosing full tree
	// passes, as does one wrong at 5 only. 5, 7 and 11 are added below.
	widthCases := []struct {
		leafCount LeafCount
		nodeWidth uint32
	}{
		{leafCount: 0, nodeWidth: 0},
		{leafCount: 1, nodeWidth: 1},
		{leafCount: 2, nodeWidth: 3},
		{leafCount: 3, nodeWidth: 5},
		{leafCount: 4, nodeWidth: 7},
		{leafCount: 5, nodeWidth: 9},
		{leafCount: 6, nodeWidth: 11},
		{leafCount: 7, nodeWidth: 13},
		{leafCount: 8, nodeWidth: 15},
		{leafCount: 11, nodeWidth: 21},
		{leafCount: 512, nodeWidth: 1023},
		{leafCount: MaxLeafCount, nodeWidth: 0xFFFFFFFF},
		{leafCount: MaxLeafCount + 1, nodeWidth: 0},
	}
	for _, c := range widthCases {
		if got := NodeWidth(c.leafCount); got != c.nodeWidth {
			t.Errorf("node width of %d leaves: %d, want %d", c.leafCount, got, c.nodeWidth)
		}
	}
}

// log2 has no caller until Task 4's Root, so without this test nothing in this
// package reaches it: coverage reports it at 0.0% while every other callable in
// tree_math.go is at 100.0%. that is a plan sequencing artifact rather than a
// decision, and shipping an untested shift-amount source for a later task to
// pick up is the shape that produced p1's unfailable tests. measured — five
// distinct wrong versions pass the rest of this file.
//
// dropping the zero guard is the one worth naming. bits.Len32(0)-1 is -1, which
// converts to 0xFFFFFFFF, and Root computes (1 << log2(w)) - 1 from whatever it
// gets. Go defines a shift past the width of the type as zero rather than a
// panic, so that version does not crash — it silently answers 0xFFFFFFFF for
// every root. Root's checkLeafCount refuses a zero leaf count before NodeWidth
// can return zero, so no in-plan path reaches log2(0) today; the guard is
// asserted here because the doc comment promises it, not because a caller
// currently depends on it.
func TestLog2(t *testing.T) {
	log2Cases := []struct {
		value uint32
		want  uint32
	}{
		// the zero special case, which appendix C leaves undefined and this
		// file promises. the only row that can tell a wrong zero guard from a
		// right one, or a dropped one from either.
		{value: 0, want: 0},
		// exact powers of two, where the answer is the exponent.
		{value: 1, want: 0},
		{value: 2, want: 1},
		{value: 4, want: 2},
		{value: 1024, want: 10},
		{value: 0x80000000, want: 31},
		// non-powers of two, where it floors. these separate a leading-bit
		// count from a trailing-zero count, which agree on every power of two.
		{value: 3, want: 1},
		{value: 7, want: 2},
		{value: 1023, want: 9},
		{value: 0x7FFFFFFF, want: 30},
		// the largest input it can be handed: NodeWidth(MaxLeafCount).
		{value: 0xFFFFFFFF, want: 31},
	}
	for _, c := range log2Cases {
		if got := log2(c.value); got != c.want {
			t.Errorf("log2(%d): %d, want %d", c.value, got, c.want)
		}
	}
}
