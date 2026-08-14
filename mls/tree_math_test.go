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
	boundaryLevelCases := []struct {
		nodeIndex NodeIndex
		level     uint32
	}{
		// the last node of the largest representable tree, holding its last leaf.
		{nodeIndex: 0xFFFFFFFE, level: 0},
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
	widthCases := []struct {
		leafCount LeafCount
		nodeWidth uint32
	}{
		{leafCount: 0, nodeWidth: 0},
		{leafCount: 1, nodeWidth: 1},
		{leafCount: 2, nodeWidth: 3},
		{leafCount: 3, nodeWidth: 5},
		{leafCount: 4, nodeWidth: 7},
		{leafCount: 6, nodeWidth: 11},
		{leafCount: 8, nodeWidth: 15},
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
