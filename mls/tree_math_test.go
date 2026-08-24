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

// the sizing trio, asserted as absolute values against the RFC's own
// definition: a full leaf count is a power of two, its depth is that exponent,
// and any count between two powers of two rounds up to the enclosing tree.
//
// the plan's table for this ran 0 to 8 and then jumped to 512 and the top of
// the range. that is the shape Task 2's review rejected — a version wrong only
// across an interior band passes a table that never enters one. the literal
// rows carry hand-computed values at every boundary that matters, and the sweep
// after them walks all thirty-two full counts with the count on either side, so
// no band is unasserted.
func TestFullLeafCountAndDepth(t *testing.T) {
	sizeCases := []struct {
		leafCount     LeafCount
		full          bool
		depth         uint32
		fullLeafCount LeafCount
	}{
		// the empty tree, which is not a tree: no depth, and no enclosing full
		// count to round up to.
		{leafCount: 0, full: false, depth: 0, fullLeafCount: 0},
		// the bottom of the range, where a power of two and its neighbours are
		// the same handful of values.
		{leafCount: 1, full: true, depth: 0, fullLeafCount: 1},
		{leafCount: 2, full: true, depth: 1, fullLeafCount: 2},
		{leafCount: 3, full: false, depth: 2, fullLeafCount: 4},
		{leafCount: 4, full: true, depth: 2, fullLeafCount: 4},
		{leafCount: 5, full: false, depth: 3, fullLeafCount: 8},
		{leafCount: 6, full: false, depth: 3, fullLeafCount: 8},
		{leafCount: 7, full: false, depth: 3, fullLeafCount: 8},
		{leafCount: 8, full: true, depth: 3, fullLeafCount: 8},
		{leafCount: 9, full: false, depth: 4, fullLeafCount: 16},
		{leafCount: 15, full: false, depth: 4, fullLeafCount: 16},
		{leafCount: 16, full: true, depth: 4, fullLeafCount: 16},
		{leafCount: 17, full: false, depth: 5, fullLeafCount: 32},
		// the middle, which the plan's table skipped from 8 to 512 to the top.
		{leafCount: 511, full: false, depth: 9, fullLeafCount: 512},
		{leafCount: 512, full: true, depth: 9, fullLeafCount: 512},
		{leafCount: 513, full: false, depth: 10, fullLeafCount: 1024},
		{leafCount: 1024, full: true, depth: 10, fullLeafCount: 1024},
		{leafCount: 1025, full: false, depth: 11, fullLeafCount: 2048},
		{leafCount: 65535, full: false, depth: 16, fullLeafCount: 65536},
		{leafCount: 65536, full: true, depth: 16, fullLeafCount: 65536},
		{leafCount: 65537, full: false, depth: 17, fullLeafCount: 131072},
		{leafCount: 1<<30 - 1, full: false, depth: 30, fullLeafCount: 1 << 30},
		{leafCount: 1 << 30, full: true, depth: 30, fullLeafCount: 1 << 30},
		{leafCount: 1<<30 + 1, full: false, depth: 31, fullLeafCount: MaxLeafCount},
		// the top of the range. one leaf below MaxLeafCount still rounds up to
		// it; one above has no enclosing tree at all.
		{leafCount: MaxLeafCount - 1, full: false, depth: 31, fullLeafCount: MaxLeafCount},
		{leafCount: MaxLeafCount, full: true, depth: 31, fullLeafCount: MaxLeafCount},
		// the plan carried the first of the two rows below and wrote depth 31 for
		// it, while its own implementation answers 32: the plan's test failed the
		// plan's code, which is how this was found.
		// 32 is the value to keep. bits.Len32 of anything from 2^31 up is 32,
		// LeafCount is a uint32, and Go defines a shift past the width of the
		// type as zero rather than a panic — so a depth of 32 makes 1 << depth
		// collapse to zero and an out-of-range count fail closed, where 31 would
		// hand back MaxLeafCount, an in-range and entirely plausible wrong tree.
		// both halves of that were verified by running.
		{leafCount: MaxLeafCount + 1, full: false, depth: 32, fullLeafCount: 0},
		{leafCount: 0xFFFFFFFF, full: false, depth: 32, fullLeafCount: 0},
	}
	for _, c := range sizeCases {
		if got := IsFullLeafCount(c.leafCount); got != c.full {
			t.Errorf("%d leaves full: %v, want %v", c.leafCount, got, c.full)
		}
		if got := TreeDepth(c.leafCount); got != c.depth {
			t.Errorf("%d leaves depth: %d, want %d", c.leafCount, got, c.depth)
		}
		if got := FullLeafCount(c.leafCount); got != c.fullLeafCount {
			t.Errorf("%d leaves full count: %d, want %d", c.leafCount, got, c.fullLeafCount)
		}
	}

	// every full leaf count the type can hold, each with the count one below and
	// one above it. the expectation is the loop's own exponent rather than a
	// recomputation of the implementation's formula, so it cannot agree with a
	// wrong version by construction.
	for depth := uint32(0); depth <= 31; depth += 1 {
		leafCount := LeafCount(1) << depth
		if !IsFullLeafCount(leafCount) {
			t.Errorf("%d leaves full: false, want true", leafCount)
		}
		if got := TreeDepth(leafCount); got != depth {
			t.Errorf("%d leaves depth: %d, want %d", leafCount, got, depth)
		}
		if got := FullLeafCount(leafCount); got != leafCount {
			t.Errorf("%d leaves full count: %d, want %d", leafCount, got, leafCount)
		}

		// from depth 2 up. below a tree of one or two leaves the neighbour is
		// itself a full count, and the literal rows above carry those.
		if depth >= 2 {
			below := leafCount - 1
			if IsFullLeafCount(below) {
				t.Errorf("%d leaves full: true, want false", below)
			}
			if got := TreeDepth(below); got != depth {
				t.Errorf("%d leaves depth: %d, want %d", below, got, depth)
			}
			if got := FullLeafCount(below); got != leafCount {
				t.Errorf("%d leaves full count: %d, want %d", below, got, leafCount)
			}
		}

		// up to depth 30. one leaf above a tree of one is two, which is full,
		// and one above MaxLeafCount has no enclosing tree — the literal rows
		// carry both.
		if 1 <= depth && depth <= 30 {
			above := leafCount + 1
			if IsFullLeafCount(above) {
				t.Errorf("%d leaves full: true, want false", above)
			}
			if got := TreeDepth(above); got != depth+1 {
				t.Errorf("%d leaves depth: %d, want %d", above, got, depth+1)
			}
			if got := FullLeafCount(above); got != leafCount*2 {
				t.Errorf("%d leaves full count: %d, want %d", above, got, leafCount*2)
			}
		}
	}

	// everything above asserts edges: a power of two, the count either side of
	// it, and the ends of the range. a version wrong strictly inside a doubling
	// band and right at both of its ends passes all of it, and measured, one
	// wrong across 600 to 1000 did — no row and no sweep above enters that band.
	//
	// so the low range is checked exhaustively against an independent oracle.
	// the oracle is the RFC's own statement, that the tree doubles until it
	// holds the count, rather than a second bit trick, so it agrees with the
	// implementation only if both are right. it stops at 2^22 to keep this test
	// in the tens of milliseconds; above that the power-of-two sweep and the
	// literal rows are what hold.
	//
	// this does make most of the literal rows redundant against a wrong
	// implementation, which is worth stating plainly rather than claiming every
	// row is load-bearing. they are not redundant against a wrong test: their
	// expectations are constants and the two sweeps compute theirs, so a bug in
	// an oracle is caught by the rows and never by itself.
	wantDepth := uint32(0)
	wantFullLeafCount := LeafCount(1)
	for leafCount := LeafCount(1); leafCount <= 1<<22; leafCount += 1 {
		if leafCount > wantFullLeafCount {
			wantFullLeafCount *= 2
			wantDepth += 1
		}
		if got := TreeDepth(leafCount); got != wantDepth {
			t.Fatalf("%d leaves depth: %d, want %d", leafCount, got, wantDepth)
		}
		if got := FullLeafCount(leafCount); got != wantFullLeafCount {
			t.Fatalf("%d leaves full count: %d, want %d", leafCount, got, wantFullLeafCount)
		}
		if want := leafCount == wantFullLeafCount; IsFullLeafCount(leafCount) != want {
			t.Fatalf("%d leaves full: %v, want %v", leafCount, !want, want)
		}
	}
}

// the node-array width and the leaf count it describes, in both directions.
//
// this pair is deliberately total over counts that are not powers of two,
// because the ratchet_tree extension carries an array with its trailing blank
// nodes stripped: six non-blank leaves encode as eleven nodes, and the receiver
// extends that to the enclosing full tree of eight (RFC 9420 section 12.4.3.1).
// the plan's table jumped from width 11 to width 1023, and the odd widths in
// between are exactly the ones a stripped array actually has.
func TestLeafCountFromNodeWidth(t *testing.T) {
	widthCases := []struct {
		nodeWidth uint32
		leafCount LeafCount
	}{
		{nodeWidth: 1, leafCount: 1},
		{nodeWidth: 3, leafCount: 2},
		{nodeWidth: 5, leafCount: 3},
		{nodeWidth: 7, leafCount: 4},
		{nodeWidth: 9, leafCount: 5},
		{nodeWidth: 11, leafCount: 6},
		{nodeWidth: 13, leafCount: 7},
		{nodeWidth: 15, leafCount: 8},
		{nodeWidth: 21, leafCount: 11},
		{nodeWidth: 1021, leafCount: 511},
		{nodeWidth: 1023, leafCount: 512},
		{nodeWidth: 1025, leafCount: 513},
		{nodeWidth: 0x0000FFFF, leafCount: 32768},
		{nodeWidth: 0x7FFFFFFF, leafCount: 1 << 30},
		// the widest array the type can hold, which is the full tree of
		// MaxLeafCount leaves, and the one below it, which is not full.
		{nodeWidth: 0xFFFFFFFD, leafCount: MaxLeafCount - 1},
		{nodeWidth: 0xFFFFFFFF, leafCount: MaxLeafCount},
	}
	for _, c := range widthCases {
		got, err := LeafCountFromNodeWidth(c.nodeWidth)
		if err != nil {
			t.Errorf("width %d: %v", c.nodeWidth, err)
			continue
		}
		if got != c.leafCount {
			t.Errorf("width %d: %d leaves, want %d", c.nodeWidth, got, c.leafCount)
		}
		if roundTrip := NodeWidth(got); roundTrip != c.nodeWidth {
			t.Errorf("width %d round trip: %d", c.nodeWidth, roundTrip)
		}
	}

	// an even width, and zero, describe no node array at all. the returned count
	// is checked alongside the error: a version that answers and refuses at the
	// same time hands a wrong tree to any caller that reads only the value.
	badWidths := []uint32{0, 2, 10, 1022, 0xFFFFFFFE}
	for _, badWidth := range badWidths {
		got, err := LeafCountFromNodeWidth(badWidth)
		if !errors.Is(err, ErrNodeWidthNotOdd) {
			t.Errorf("width %d: %v, want %v", badWidth, err, ErrNodeWidthNotOdd)
		}
		if got != 0 {
			t.Errorf("width %d: %d leaves alongside the refusal, want 0", badWidth, got)
		}
	}

	// the other direction at every full count: the width is what NodeWidth says
	// it is, and decoding it returns the count it came from.
	for depth := uint32(0); depth <= 31; depth += 1 {
		leafCount := LeafCount(1) << depth
		nodeWidth := NodeWidth(leafCount)
		if want := 2*uint32(leafCount) - 1; nodeWidth != want {
			t.Errorf("%d leaves width: %d, want %d", leafCount, nodeWidth, want)
		}
		got, err := LeafCountFromNodeWidth(nodeWidth)
		if err != nil {
			t.Errorf("width %d: %v", nodeWidth, err)
			continue
		}
		if got != leafCount {
			t.Errorf("width %d: %d leaves, want %d", nodeWidth, got, leafCount)
		}
	}

	if got := FullLeafCount(6); got != 8 {
		t.Errorf("full count containing 6 leaves: %d, want 8", got)
	}
}

// extension and truncation, as absolute sizes.
//
// a test that only checks that extending and then truncating returns the
// original is satisfied by two functions wrong in mirror-image ways, so every
// case here pins the size itself against the RFC's definition. the sweep at the
// end then reaches the same size by three independent routes — the extension of
// a tree, the enclosing full count of one leaf past it, and the truncation to
// that leaf — which no mirror-image pair satisfies.
func TestExtendAndTruncate(t *testing.T) {
	// RFC 9420 section 7.7: extending doubles the tree.
	extendCases := []struct {
		leafCount LeafCount
		extended  LeafCount
	}{
		{leafCount: 0, extended: 1},
		{leafCount: 1, extended: 2},
		{leafCount: 2, extended: 4},
		{leafCount: 4, extended: 8},
		{leafCount: 8, extended: 16},
		{leafCount: 512, extended: 1024},
		{leafCount: 65536, extended: 131072},
		{leafCount: 1 << 29, extended: 1 << 30},
		// the last count that can be extended at all: doubling it is exactly
		// MaxLeafCount.
		{leafCount: 1 << 30, extended: MaxLeafCount},
	}
	for _, c := range extendCases {
		got, err := ExtendedLeafCount(c.leafCount)
		if err != nil {
			t.Errorf("extend %d: %v", c.leafCount, err)
			continue
		}
		if got != c.extended {
			t.Errorf("extend %d: %d, want %d", c.leafCount, got, c.extended)
		}
	}

	extendErrorCases := []struct {
		leafCount LeafCount
		err       error
	}{
		// a count that is not a power of two names no tree, so there is nothing
		// to double.
		{leafCount: 3, err: ErrLeafCountNotFull},
		{leafCount: 5, err: ErrLeafCountNotFull},
		{leafCount: 1<<30 + 1, err: ErrLeafCountNotFull},
		// MaxLeafCount is a tree and cannot be doubled inside a uint32.
		{leafCount: MaxLeafCount, err: ErrLeafCountRange},
		// past MaxLeafCount the refusal is ErrLeafCountRange, matching
		// checkLeafCount on the same input. these values are both out of range
		// and not powers of two, so the order of the two tests alone decided
		// which sentinel came back, and the two functions disagreed. settled in
		// favour of range by the argument TestCheckLeafCount already makes below:
		// a caller told ErrLeafCountNotFull may round up with FullLeafCount and
		// retry, and for a count past the maximum that retry is exactly how it
		// ends up holding a tree of MaxLeafCount leaves. ErrLeafCountRange
		// forbids the retry, so it is the safe classification here.
		{leafCount: MaxLeafCount + 1, err: ErrLeafCountRange},
		{leafCount: 0xFFFFFFFF, err: ErrLeafCountRange},
	}
	for _, c := range extendErrorCases {
		got, err := ExtendedLeafCount(c.leafCount)
		if !errors.Is(err, c.err) {
			t.Errorf("extend %d: %v, want %v", c.leafCount, err, c.err)
		}
		if got != 0 {
			t.Errorf("extend %d: %d leaves alongside the refusal, want 0", c.leafCount, got)
		}
	}

	// RFC 9420 section 12.1.3: after a remove, the tree is truncated to 2^d
	// leaves where d is the smallest value with 2^d greater than the index of
	// the rightmost non-blank leaf.
	truncateCases := []struct {
		rightmostNonBlankLeaf LeafIndex
		leafCount             LeafCount
	}{
		{rightmostNonBlankLeaf: 0, leafCount: 1},
		{rightmostNonBlankLeaf: 1, leafCount: 2},
		{rightmostNonBlankLeaf: 2, leafCount: 4},
		{rightmostNonBlankLeaf: 3, leafCount: 4},
		{rightmostNonBlankLeaf: 4, leafCount: 8},
		{rightmostNonBlankLeaf: 7, leafCount: 8},
		{rightmostNonBlankLeaf: 8, leafCount: 16},
		{rightmostNonBlankLeaf: 15, leafCount: 16},
		{rightmostNonBlankLeaf: 16, leafCount: 32},
		{rightmostNonBlankLeaf: 499, leafCount: 512},
		{rightmostNonBlankLeaf: 511, leafCount: 512},
		{rightmostNonBlankLeaf: 512, leafCount: 1024},
		{rightmostNonBlankLeaf: 65535, leafCount: 65536},
		{rightmostNonBlankLeaf: 65536, leafCount: 131072},
		{rightmostNonBlankLeaf: 1<<30 - 1, leafCount: 1 << 30},
		{rightmostNonBlankLeaf: 1 << 30, leafCount: MaxLeafCount},
		// the last leaf of the largest representable tree, which truncates to
		// that whole tree.
		{rightmostNonBlankLeaf: LeafIndex(MaxLeafCount - 1), leafCount: MaxLeafCount},
	}
	for _, c := range truncateCases {
		got, err := TruncatedLeafCount(c.rightmostNonBlankLeaf)
		if err != nil {
			t.Errorf("truncate to leaf %d: %v", c.rightmostNonBlankLeaf, err)
			continue
		}
		if got != c.leafCount {
			t.Errorf("truncate to leaf %d: %d leaves, want %d", c.rightmostNonBlankLeaf, got, c.leafCount)
		}
	}

	// a leaf index at or past MaxLeafCount sits in no representable tree. the
	// plan asserted none of these, so nothing in it reached the refusal at all.
	// measured, with the guard deleted: the two just past MaxLeafCount answer a
	// tree of zero leaves, and 0xFFFFFFFF answers a tree of one — the largest
	// leaf index the type can hold, silently naming the smallest tree there is,
	// because the count wraps to zero before the depth is taken.
	badLeaves := []LeafIndex{LeafIndex(MaxLeafCount), LeafIndex(MaxLeafCount) + 1, 0xFFFFFFFF}
	for _, badLeaf := range badLeaves {
		got, err := TruncatedLeafCount(badLeaf)
		if !errors.Is(err, ErrLeafOutOfRange) {
			t.Errorf("truncate to leaf %d: %v, want %v", badLeaf, err, ErrLeafOutOfRange)
		}
		if got != 0 {
			t.Errorf("truncate to leaf %d: %d leaves alongside the refusal, want 0", badLeaf, got)
		}
	}

	// the two functions against each other and against the sizing trio, at
	// every full count. the rightmost leaf of a full tree truncates back to that
	// same tree, and one leaf past it names the extended tree by both the
	// rounding route and the truncation route.
	for depth := uint32(0); depth <= 31; depth += 1 {
		leafCount := LeafCount(1) << depth

		lastLeaf := LeafIndex(leafCount - 1)
		kept, err := TruncatedLeafCount(lastLeaf)
		if err != nil {
			t.Errorf("truncate to leaf %d: %v", lastLeaf, err)
		} else if kept != leafCount {
			t.Errorf("truncate to leaf %d: %d leaves, want %d", lastLeaf, kept, leafCount)
		}

		// MaxLeafCount cannot be extended, and its own refusal is a row above.
		if depth == 31 {
			continue
		}
		extended, err := ExtendedLeafCount(leafCount)
		if err != nil {
			t.Errorf("extend %d: %v", leafCount, err)
			continue
		}
		if want := LeafCount(1) << (depth + 1); extended != want {
			t.Errorf("extend %d: %d, want %d", leafCount, extended, want)
		}
		if got := FullLeafCount(leafCount + 1); got != extended {
			t.Errorf("full count containing %d leaves: %d, want the extension of %d, %d", leafCount+1, got, leafCount, extended)
		}
		firstNewLeaf := LeafIndex(leafCount)
		grown, err := TruncatedLeafCount(firstNewLeaf)
		if err != nil {
			t.Errorf("truncate to leaf %d: %v", firstNewLeaf, err)
			continue
		}
		if grown != extended {
			t.Errorf("truncate to leaf %d: %d leaves, want the extension of %d, %d", firstNewLeaf, grown, leafCount, extended)
		}
	}

	// truncation, exhaustively, against the same independent oracle the sizing
	// test uses: the smallest tree that still holds the leaf, reached by
	// doubling rather than by a bit trick. every case above sits at a power of
	// two or next to one, and a version wrong only in the middle of a band
	// passes all of them.
	wantLeafCount := LeafCount(1)
	for leaf := LeafIndex(0); leaf < 1<<22; leaf += 1 {
		if LeafCount(leaf) >= wantLeafCount {
			wantLeafCount *= 2
		}
		got, err := TruncatedLeafCount(leaf)
		if err != nil {
			t.Fatalf("truncate to leaf %d: %v", leaf, err)
		}
		if got != wantLeafCount {
			t.Fatalf("truncate to leaf %d: %d leaves, want %d", leaf, got, wantLeafCount)
		}
	}
}

// checkLeafCount is the shared entry check every later leaf-count function is
// built on, and this task introduces it with no caller: Root, the first one,
// lands in Task 4. shipping an unexercised gate for a later task to pick up is
// the shape that produced p1's nine unfailable tests, and log2 was already
// shipped that way once in this file, so it is asserted here.
//
// the classification matters as much as the refusal. a caller told
// ErrLeafCountNotFull can round the count up with FullLeafCount and retry; a
// caller told ErrLeafCountRange cannot, and folding the two together is how a
// count past the range becomes a tree of MaxLeafCount leaves.
func TestCheckLeafCount(t *testing.T) {
	checkCases := []struct {
		leafCount LeafCount
		err       error
	}{
		{leafCount: 0, err: ErrLeafCountRange},
		{leafCount: 1, err: nil},
		{leafCount: 2, err: nil},
		{leafCount: 3, err: ErrLeafCountNotFull},
		{leafCount: 4, err: nil},
		{leafCount: 6, err: ErrLeafCountNotFull},
		{leafCount: 512, err: nil},
		{leafCount: 513, err: ErrLeafCountNotFull},
		{leafCount: 65536, err: nil},
		{leafCount: 1 << 30, err: nil},
		{leafCount: MaxLeafCount - 1, err: ErrLeafCountNotFull},
		{leafCount: MaxLeafCount, err: nil},
		{leafCount: MaxLeafCount + 1, err: ErrLeafCountRange},
		{leafCount: 0xFFFFFFFF, err: ErrLeafCountRange},
	}
	for _, c := range checkCases {
		err := checkLeafCount(c.leafCount)
		if c.err == nil {
			if err != nil {
				t.Errorf("%d leaves: %v, want no error", c.leafCount, err)
			}
			continue
		}
		if !errors.Is(err, c.err) {
			t.Errorf("%d leaves: %v, want %v", c.leafCount, err, c.err)
		}
	}
}

// the root index at every tree size the type can hold, which vector family 1
// cannot reach.
//
// the family's ladder is 1 to 512 leaves, so it pins depths 0 to 9, and the one
// other size the plan names is MaxLeafCount at depth 31. depths 10 to 30 are
// asserted nowhere else in this plan. measured, against the family runner
// alone: a version wrong across exactly that band passes, and so does one wrong
// at depth 20 alone, or at depth 10 alone. depths 0, 9 and 31 were measured too
// and are already held, so the ladder's ends and the plan's MaxLeafCount row
// are load-bearing rather than decoration.
//
// the sweeps take their expectation from the loop's own exponent, never from
// log2 or NodeWidth, so they cannot agree with a wrong version by construction.
func TestRoot(t *testing.T) {
	// hand-computed from 2^d - 1, one per octave the family stops short of.
	rootCases := []struct {
		leafCount LeafCount
		root      NodeIndex
	}{
		{leafCount: 1, root: 0},
		{leafCount: 2, root: 1},
		{leafCount: 4, root: 3},
		{leafCount: 8, root: 7},
		{leafCount: 512, root: 511},
		{leafCount: 1024, root: 1023},
		{leafCount: 65536, root: 65535},
		{leafCount: 1 << 20, root: 1<<20 - 1},
		{leafCount: 1 << 25, root: 1<<25 - 1},
		{leafCount: 1 << 30, root: 1<<30 - 1},
		{leafCount: MaxLeafCount, root: 0x7FFFFFFF},
	}
	for _, c := range rootCases {
		got, err := Root(c.leafCount)
		if err != nil {
			t.Errorf("root of %d leaves: %v", c.leafCount, err)
			continue
		}
		if got != c.root {
			t.Errorf("root of %d leaves: %d, want %d", c.leafCount, got, c.root)
		}
	}

	// every full count the type can hold, and the counts either side of it. a
	// count one off a power of two is not a tree, so it is refused, and the
	// refusal is read with its index: a version that answers and refuses at the
	// same time hands a real in-tree node to a caller that reads only the value.
	//
	// the mid-band probe is what stops this being an ends-only table. a version
	// that enforces fullness at the edges of a doubling band and rounds up
	// inside it is refused here at every depth from two up, which no row above
	// and no ladder in the family reaches.
	for depth := uint32(0); depth <= 31; depth += 1 {
		leafCount := LeafCount(1) << depth
		wantRoot := NodeIndex(1)<<depth - 1

		got, err := Root(leafCount)
		if err != nil {
			t.Errorf("root of %d leaves: %v", leafCount, err)
		} else if got != wantRoot {
			t.Errorf("root of %d leaves: %d, want %d", leafCount, got, wantRoot)
		}

		notTrees := []LeafCount{}
		if depth >= 2 {
			notTrees = append(notTrees, leafCount-1)
		}
		// one above and half again are both past MaxLeafCount at depth 31,
		// where the refusal is range rather than fullness; the out-of-range
		// rows below carry that end.
		if 1 <= depth && depth <= 30 {
			notTrees = append(notTrees, leafCount+1)
		}
		if 2 <= depth && depth <= 30 {
			notTrees = append(notTrees, leafCount+leafCount/2)
		}
		for _, notTree := range notTrees {
			refused, err := Root(notTree)
			if !errors.Is(err, ErrLeafCountNotFull) {
				t.Errorf("root of %d leaves: %v, want %v", notTree, err, ErrLeafCountNotFull)
			}
			if refused != 0 {
				t.Errorf("root of %d leaves: %d alongside the refusal, want 0", notTree, refused)
			}
		}
	}

	// past the top of the range there is no tree to have a root, and the
	// sentinel says range rather than fullness so that a caller cannot round the
	// count up with FullLeafCount and retry into a tree of MaxLeafCount leaves.
	outOfRange := []LeafCount{0, MaxLeafCount + 1, 0xFFFFFFFF}
	for _, leafCount := range outOfRange {
		refused, err := Root(leafCount)
		if !errors.Is(err, ErrLeafCountRange) {
			t.Errorf("root of %d leaves: %v, want %v", leafCount, err, ErrLeafCountRange)
		}
		if refused != 0 {
			t.Errorf("root of %d leaves: %d alongside the refusal, want 0", leafCount, refused)
		}
	}

	// the low range exhaustively, against the same doubling oracle the sizing
	// test uses rather than against a second bit trick, so the two agree only if
	// both are right. every count is either a tree, whose root is one below it,
	// or no tree at all. this is what closes the single-count holes the sweeps
	// above leave: measured, a version that skips the guard for exactly one
	// interior count passes everything else in this file.
	//
	// it stops at 2^22 to keep the test in the tens of milliseconds, so a
	// version wrong at one count above that and right everywhere else survives
	// this file — measured, not assumed. closing that needs a walk of all 2^31
	// counts, and the same ceiling is what TestFullLeafCountAndDepth settles for.
	wantFullLeafCount := LeafCount(1)
	for leafCount := LeafCount(1); leafCount <= 1<<22; leafCount += 1 {
		if leafCount > wantFullLeafCount {
			wantFullLeafCount *= 2
		}
		got, err := Root(leafCount)
		if leafCount != wantFullLeafCount {
			if !errors.Is(err, ErrLeafCountNotFull) {
				t.Fatalf("root of %d leaves: %v, want %v", leafCount, err, ErrLeafCountNotFull)
			}
			if got != 0 {
				t.Fatalf("root of %d leaves: %d alongside the refusal, want 0", leafCount, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("root of %d leaves: %v", leafCount, err)
		}
		if want := NodeIndex(leafCount) - 1; got != want {
			t.Fatalf("root of %d leaves: %d, want %d", leafCount, got, want)
		}
	}
}

// compares two node slices and reports the whole slice on a mismatch, because
// a path bug is almost never at the element the first difference lands on.
//
// Task 11's resolution fixtures call this as well, so the signature is the one
// the plan declares here rather than the predicate below, which the sweeps use
// because they report a node index and a leaf count beside the two slices.
func assertNodeIndexes(t *testing.T, label string, got []NodeIndex, want []NodeIndex) {
	t.Helper()
	if !sameNodeIndexes(got, want) {
		t.Errorf("%s: %v, want %v", label, got, want)
	}
}

// reports whether two node slices hold the same indices in the same order.
func sameNodeIndexes(got []NodeIndex, want []NodeIndex) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// the node at the given level spanning the given block of 2^level leaves, so
// leaf L is the node at level zero and block L.
//
// RFC 9420 appendix C figure 32 lays a level-k node at the centre of the
// 2^(k+1)-1 array slots it spans, which puts the b-th of them at
// b*2^(k+1) + 2^k - 1. the arithmetic runs in uint64 so the last leaf of the
// largest tree, node 2^32-2, is built without a wrap.
func nodeAt(level uint32, block uint64) NodeIndex {
	return NodeIndex(block<<(level+1) + uint64(1)<<level - 1)
}

// the direct path and copath of the node at (level, block) in a tree of the
// given depth, from the array layout alone.
//
// no function of this package is called here, so the expectation cannot agree
// with a wrong DirectPath or Copath by construction — which a table derived
// from the functions under test would, and which is the shape this project has
// rejected four times.
//
// the ancestor of a node at level k is the node covering the block of leaves
// that contains it, at (k, block >> (k-level)); the copath entry beside that
// ancestor is the ancestor's other child, one level down and in the sibling
// block, at (k-1, (block >> (k-1-level)) ^ 1). neither form is argued for:
// TestDirectPathAndCopathRfcTable2 runs both against all five rows RFC 9420
// table 2 publishes and against the ten further nodes figure 11 draws, so a
// wrong form fails there, against published data, before any sweep uses it.
func pathOracle(level uint32, block uint64, depth uint32) ([]NodeIndex, []NodeIndex) {
	directPath := []NodeIndex{}
	copathNodes := []NodeIndex{}
	for k := level + 1; k <= depth; k += 1 {
		directPath = append(directPath, nodeAt(k, block>>(k-level)))
		copathNodes = append(copathNodes, nodeAt(k-1, (block>>(k-1-level))^1))
	}
	return directPath, copathNodes
}

// RFC 9420 figure 11 and table 2: an eight-leaf tree with members at leaves
// 0, 1, 4, 5 and 6. the figure labels the blank parents U, V, Z and the blank
// leaf H, and table 2 publishes the direct path and copath of every member.
//
// table 2 is read out of the RFC text at
// https://www.rfc-editor.org/rfc/rfc9420.txt section 4.1.2, and cross-read
// against the copy at mls_measure/mls-go/rfc9420.txt, sha256
// 467d709b7cea19d278204daca1af01910add522cd8e3325cb406f339efbb0d92. the two
// readings agree. the published rows are:
//
//	Node | Direct path | Copath  | Filtered Direct Path
//	A    | T, U, W     | B, V, Y | T, W
//	B    | T, U, W     | A, V, Y | T, W
//	E    | X, Y, W     | F, Z, U | X, Y, W
//	F    | X, Y, W     | E, Z, U | X, Y, W
//	G    | Z, Y, W     | H, X, U | Y, W
//
// the filtered column belongs to Task 12 and is not asserted here.
//
// node indices for the figure's labels:
//
//	A = 0   B = 2   E = 8   F = 10  G = 12  H = 14 (blank leaf 7)
//	T = 1   V = 5 (blank)   X = 9   Z = 13 (blank)
//	U = 3 (blank)           Y = 11
//	W = 7 (root)
//
// table 2 publishes five of the tree's fifteen nodes, all of them leaves and
// none of them the last leaf. the other ten are read off the tree figure 11
// draws, which is published too and is what the RFC derives table 2 from; the
// rows say which they are so a reviewer can see where the oracle ends and the
// figure continued begins. all fifteen are here because the five published rows
// leave two of the eight leaves, every parent and the root unasserted, and a
// path that is right for a leaf and wrong for a parent is exactly what Task 12
// and the TreeKEM plan go on to call.
//
// this tree is one depth of thirty-two, so it is the start of the coverage and
// not the whole of it. measured against the same enumeration the sweep below
// describes: the five published rows and the two edge arms the plan wrote for
// this task fail 37 of 279 versions and let 240 through. the sweeps carry the
// rest.
func TestDirectPathAndCopathRfcTable2(t *testing.T) {
	pathCases := []struct {
		label      string
		published  bool
		nodeIndex  NodeIndex
		level      uint32
		block      uint64
		directPath []NodeIndex
		copath     []NodeIndex
	}{
		{label: "A", published: true, nodeIndex: 0, level: 0, block: 0, directPath: []NodeIndex{1, 3, 7}, copath: []NodeIndex{2, 5, 11}},
		{label: "B", published: true, nodeIndex: 2, level: 0, block: 1, directPath: []NodeIndex{1, 3, 7}, copath: []NodeIndex{0, 5, 11}},
		{label: "E", published: true, nodeIndex: 8, level: 0, block: 4, directPath: []NodeIndex{9, 11, 7}, copath: []NodeIndex{10, 13, 3}},
		{label: "F", published: true, nodeIndex: 10, level: 0, block: 5, directPath: []NodeIndex{9, 11, 7}, copath: []NodeIndex{8, 13, 3}},
		{label: "G", published: true, nodeIndex: 12, level: 0, block: 6, directPath: []NodeIndex{13, 11, 7}, copath: []NodeIndex{14, 9, 3}},

		// the two blank leaves figure 11 leaves unlabelled, at 2 and 3. they
		// are the only nodes whose level 1 ancestor is V, and no published row
		// reaches V from below.
		{label: "leaf 2", nodeIndex: 4, level: 0, block: 2, directPath: []NodeIndex{5, 3, 7}, copath: []NodeIndex{6, 1, 11}},
		{label: "leaf 3", nodeIndex: 6, level: 0, block: 3, directPath: []NodeIndex{5, 3, 7}, copath: []NodeIndex{4, 1, 11}},
		// H, the blank leaf at 7 and the last leaf of the tree. its direct path
		// is G's published one, the two being siblings, and its copath differs
		// from G's only in the first entry, which figure 11 draws as G.
		{label: "H", nodeIndex: 14, level: 0, block: 7, directPath: []NodeIndex{13, 11, 7}, copath: []NodeIndex{12, 9, 3}},

		// the four level 1 parents.
		{label: "T", nodeIndex: 1, level: 1, block: 0, directPath: []NodeIndex{3, 7}, copath: []NodeIndex{5, 11}},
		{label: "V", nodeIndex: 5, level: 1, block: 1, directPath: []NodeIndex{3, 7}, copath: []NodeIndex{1, 11}},
		{label: "X", nodeIndex: 9, level: 1, block: 2, directPath: []NodeIndex{11, 7}, copath: []NodeIndex{13, 3}},
		{label: "Z", nodeIndex: 13, level: 1, block: 3, directPath: []NodeIndex{11, 7}, copath: []NodeIndex{9, 3}},

		// the two level 2 parents, whose paths are one node long. that is the
		// shortest non-empty path either function returns and the one length at
		// which a copath built by shifting the direct path the wrong way still
		// comes out the right length.
		{label: "U", nodeIndex: 3, level: 2, block: 0, directPath: []NodeIndex{7}, copath: []NodeIndex{11}},
		{label: "Y", nodeIndex: 11, level: 2, block: 1, directPath: []NodeIndex{7}, copath: []NodeIndex{3}},

		// and the root, whose direct path RFC 9420 section 4.1.2 defines as the
		// empty list before it defines any other.
		{label: "W", nodeIndex: 7, level: 3, block: 0, directPath: []NodeIndex{}, copath: []NodeIndex{}},
	}

	// both arms are counted, as in Tasks 5 and 6. the empty arm is one row of
	// fifteen here, so a loop that reached only the fourteen rows with a path
	// on them would look like full coverage of this tree while asserting
	// nothing whatever about the definition the RFC states first.
	emptyPaths, definedPaths, publishedRows := 0, 0, 0

	for _, c := range pathCases {
		if c.published {
			publishedRows += 1
		}
		if len(c.directPath) == 0 {
			emptyPaths += 1
		} else {
			definedPaths += 1
		}

		// the row names its node twice, once as an index and once as a level
		// and a block, and every sweep below reaches a node only through the
		// second. a mistyped pair would leave those sweeps walking a different
		// node from the one this row pins.
		if got := nodeAt(c.level, c.block); got != c.nodeIndex {
			t.Errorf("%s: node at level %d block %d: %d, want %d", c.label, c.level, c.block, got, c.nodeIndex)
		}

		// the layout oracle every sweep below takes its expectation from,
		// against the published values. this is the anchor: two wrong closed
		// forms fail here, against table 2, rather than agreeing quietly with a
		// wrong implementation at a depth the RFC publishes nothing for.
		oracleDirect, oracleCopath := pathOracle(c.level, c.block, 3)
		if !sameNodeIndexes(oracleDirect, c.directPath) {
			t.Errorf("%s: oracle direct path: %v, want %v", c.label, oracleDirect, c.directPath)
		}
		if !sameNodeIndexes(oracleCopath, c.copath) {
			t.Errorf("%s: oracle copath: %v, want %v", c.label, oracleCopath, c.copath)
		}

		gotDirect, err := DirectPath(c.nodeIndex, 8)
		if err != nil {
			t.Errorf("%s direct path: %v", c.label, err)
			continue
		}
		assertNodeIndexes(t, c.label+" direct path", gotDirect, c.directPath)

		gotCopath, err := Copath(c.nodeIndex, 8)
		if err != nil {
			t.Errorf("%s copath: %v", c.label, err)
			continue
		}
		assertNodeIndexes(t, c.label+" copath", gotCopath, c.copath)
	}

	countCases := []struct {
		label string
		got   int
		want  int
	}{
		// the eight-leaf tree holds fifteen nodes and exactly one of them, the
		// root, has an empty path.
		{label: "empty paths", got: emptyPaths, want: 1},
		{label: "paths with nodes on them", got: definedPaths, want: 14},
		// table 2 publishes five rows. deleting one would otherwise leave this
		// test passing on the figure rows alone, with no published oracle in it
		// at all.
		{label: "published rows", got: publishedRows, want: 5},
	}
	for _, c := range countCases {
		if c.got != c.want {
			t.Errorf("confirmed %s: %d, want %d", c.label, c.got, c.want)
		}
	}
}

// the two arms neither table 2 nor any sweep of nodes inside a tree reaches:
// the node that has no path at all, and the index that has no node.
//
// both arms are counted and both counts are asserted, as in Tasks 5 and 6. a
// runner that exercised only the arm with an answer in it looks like full
// coverage and is not, and here the empty arm is the one the RFC defines first
// and the one a caller ranges over without checking.
//
// the two read-backs of the value beside the error are what this test adds over
// the shape of the refusal, and one of them is the sole holder of its class:
// measured, with the nil read-back below removed and every other row of this
// file kept, a version that hands back an empty slice alongside
// ErrNodeOutOfRange passes the whole package. a caller that reads the value and
// drops the error then walks a path that was never computed.
func TestDirectPathAndCopathEdges(t *testing.T) {
	emptyPaths, outOfRangeRefusals, invalidCountRefusals := 0, 0, 0

	// the root has an empty direct path and an empty copath, at every depth the
	// index type can hold rather than at the one depth table 2 covers, and the
	// empty slice is not nil: the doc comments promise a caller can range over
	// the result with no nil check, and a promise nothing asserts is what p2
	// task 9 shipped.
	//
	// depth zero is the one-leaf tree, whose only node is both its sole leaf
	// and its root. it is called out again below because it is the arm a caller
	// creating a group reaches first.
	for depth := uint32(0); depth <= 31; depth += 1 {
		leafCount := LeafCount(1) << depth
		root, err := Root(leafCount)
		if err != nil {
			t.Fatalf("%d leaves: root: %v", leafCount, err)
		}

		rootPath, err := DirectPath(root, leafCount)
		if err != nil {
			t.Errorf("%d leaves: direct path of the root: %v", leafCount, err)
		} else if len(rootPath) != 0 {
			t.Errorf("%d leaves: direct path of the root: %v, want empty", leafCount, rootPath)
		} else if rootPath == nil {
			t.Errorf("%d leaves: direct path of the root is nil, want an empty slice", leafCount)
		} else {
			emptyPaths += 1
		}

		rootCopath, err := Copath(root, leafCount)
		if err != nil {
			t.Errorf("%d leaves: copath of the root: %v", leafCount, err)
		} else if len(rootCopath) != 0 {
			t.Errorf("%d leaves: copath of the root: %v, want empty", leafCount, rootCopath)
		} else if rootCopath == nil {
			t.Errorf("%d leaves: copath of the root is nil, want an empty slice", leafCount)
		} else {
			emptyPaths += 1
		}

		// an index past the end of this tree is refused rather than answered,
		// and the refusal comes with no slice: a partly built path handed back
		// beside an error is a path a caller reading only the value walks.
		//
		// three indices, for the reasons Task 6's runner gives. the width
		// itself separates a guard reading at least the width from one reading
		// more than it; one past the width stops a guard holed at exactly that
		// index; and the top of the type stops a guard that refuses the first
		// indices outside the tree and answers beyond them. the largest tree's
		// width fills the index type, so one past it is not representable and
		// is skipped rather than wrapped round to node 0, which is in range.
		width := uint64(NodeWidth(leafCount))
		for _, probe := range []uint64{width, width + 1, 0xFFFFFFFF} {
			if probe > 0xFFFFFFFF {
				continue
			}
			nodeIndex := NodeIndex(probe)
			if got, err := DirectPath(nodeIndex, leafCount); !errors.Is(err, ErrNodeOutOfRange) {
				t.Errorf("%d leaves: direct path of node %d: %v, want %v", leafCount, nodeIndex, err, ErrNodeOutOfRange)
			} else if got != nil {
				t.Errorf("%d leaves: direct path of node %d: %v alongside the refusal, want no slice", leafCount, nodeIndex, got)
			} else {
				outOfRangeRefusals += 1
			}
			if got, err := Copath(nodeIndex, leafCount); !errors.Is(err, ErrNodeOutOfRange) {
				t.Errorf("%d leaves: copath of node %d: %v, want %v", leafCount, nodeIndex, err, ErrNodeOutOfRange)
			} else if got != nil {
				t.Errorf("%d leaves: copath of node %d: %v alongside the refusal, want no slice", leafCount, nodeIndex, got)
			} else {
				outOfRangeRefusals += 1
			}
		}
	}

	// the one-leaf tree on its own, because it is the shape a caller creating a
	// group holds and the only tree whose sole leaf is also its root.
	solePath, solePathErr := DirectPath(0, 1)
	soleCopath, soleCopathErr := Copath(0, 1)
	soleLeafCases := []struct {
		label string
		path  []NodeIndex
		err   error
	}{
		{label: "direct path", path: solePath, err: solePathErr},
		{label: "copath", path: soleCopath, err: soleCopathErr},
	}
	soleLeafEmpties := 0
	for _, c := range soleLeafCases {
		if c.err != nil {
			t.Errorf("sole leaf %s: %v", c.label, c.err)
		} else if len(c.path) != 0 {
			t.Errorf("sole leaf %s: %v, want empty", c.label, c.path)
		} else if c.path == nil {
			t.Errorf("sole leaf %s is nil, want an empty slice", c.label)
		} else {
			soleLeafEmpties += 1
		}
	}

	// a leaf count no tree can have is refused before any index arithmetic
	// runs, and the sentinel says which kind of refusal it is: a caller told the
	// count is not full can round it up with FullLeafCount and retry, and one
	// told it is out of range cannot.
	//
	// two node indices per count, for the reason Task 6's runner gives. a
	// version that discarded the error from Root would read a root of node 0,
	// answer an empty path for node 0 and refuse for node 1, so the two indices
	// separate it where either alone does not. the same pair separates a width
	// check hoisted above the count check, which at zero leaves calls every
	// index out of range instead.
	invalidCountCases := []struct {
		nodeIndex NodeIndex
		leafCount LeafCount
		err       error
	}{
		{nodeIndex: 0, leafCount: 3, err: ErrLeafCountNotFull},
		{nodeIndex: 1, leafCount: 3, err: ErrLeafCountNotFull},
		{nodeIndex: 0, leafCount: 6, err: ErrLeafCountNotFull},
		{nodeIndex: 1, leafCount: 6, err: ErrLeafCountNotFull},
		{nodeIndex: 0, leafCount: MaxLeafCount - 1, err: ErrLeafCountNotFull},
		{nodeIndex: 1, leafCount: MaxLeafCount - 1, err: ErrLeafCountNotFull},
		{nodeIndex: 0, leafCount: 0, err: ErrLeafCountRange},
		{nodeIndex: 1, leafCount: 0, err: ErrLeafCountRange},
		{nodeIndex: 0, leafCount: MaxLeafCount + 1, err: ErrLeafCountRange},
		{nodeIndex: 1, leafCount: MaxLeafCount + 1, err: ErrLeafCountRange},
		{nodeIndex: 0, leafCount: 0xFFFFFFFF, err: ErrLeafCountRange},
		{nodeIndex: 1, leafCount: 0xFFFFFFFF, err: ErrLeafCountRange},
	}
	for _, c := range invalidCountCases {
		if got, err := DirectPath(c.nodeIndex, c.leafCount); !errors.Is(err, c.err) {
			t.Errorf("direct path of node %d in %d leaves: %v, want %v", c.nodeIndex, c.leafCount, err, c.err)
		} else if got != nil {
			t.Errorf("direct path of node %d in %d leaves: %v alongside the refusal, want no slice", c.nodeIndex, c.leafCount, got)
		} else {
			invalidCountRefusals += 1
		}
		if got, err := Copath(c.nodeIndex, c.leafCount); !errors.Is(err, c.err) {
			t.Errorf("copath of node %d in %d leaves: %v, want %v", c.nodeIndex, c.leafCount, err, c.err)
		} else if got != nil {
			t.Errorf("copath of node %d in %d leaves: %v alongside the refusal, want no slice", c.nodeIndex, c.leafCount, got)
		} else {
			invalidCountRefusals += 1
		}
	}

	countCases := []struct {
		label string
		got   int
		want  int
	}{
		// thirty-two depths, two functions, one empty answer each.
		{label: "empty paths", got: emptyPaths, want: 64},
		{label: "sole leaf empty paths", got: soleLeafEmpties, want: 2},
		// thirty-one depths probe three indices past the end of their tree and
		// the largest probes two, since one past its width is not
		// representable, and each probe is put to both functions.
		{label: "out of range refusals", got: outOfRangeRefusals, want: 190},
		// twelve rows, both functions.
		{label: "invalid leaf count refusals", got: invalidCountRefusals, want: 24},
	}
	for _, c := range countCases {
		if c.got != c.want {
			t.Errorf("confirmed %s: %d, want %d", c.label, c.got, c.want)
		}
	}
}

// one node's direct path and copath against the layout oracle, returning the
// length the oracle predicts so the caller can count the empty arm from the
// oracle rather than from the answer under test.
func checkPathsAgainstOracle(t *testing.T, level uint32, block uint64, depth uint32, n LeafCount) int {
	t.Helper()
	nodeIndex := nodeAt(level, block)
	wantDirect, wantCopath := pathOracle(level, block, depth)

	gotDirect, err := DirectPath(nodeIndex, n)
	if err != nil {
		t.Fatalf("%d leaves: direct path of node %d: %v", n, nodeIndex, err)
	}
	if !sameNodeIndexes(gotDirect, wantDirect) {
		t.Fatalf("%d leaves: direct path of node %d: %v, want %v", n, nodeIndex, gotDirect, wantDirect)
	}

	gotCopath, err := Copath(nodeIndex, n)
	if err != nil {
		t.Fatalf("%d leaves: copath of node %d: %v", n, nodeIndex, err)
	}
	if !sameNodeIndexes(gotCopath, wantCopath) {
		t.Fatalf("%d leaves: copath of node %d: %v, want %v", n, nodeIndex, gotCopath, wantCopath)
	}
	return len(wantDirect)
}

// the absolute contents of both paths at every depth a tree can have, against
// the layout oracle table 2 anchors.
//
// table 2 covers one depth. the vector family covers none of these two
// functions at all, Task 13's sweep stops at depth 9 and asserts laws rather
// than values, and the fuzz target asserts only that an answer is inside the
// tree, so depths 10 to 31 are covered by nothing else in this package —
// the same hole Tasks 5 and 6 each had to fill for their own functions.
//
// measured rather than argued, in a scratch copy. a grammar over the two
// bodies — the leaf count check, the range guard and its depth bands, what the
// path holds, its length, one level or one position missing, the step bound,
// and for the copath the chain the siblings are taken from — enumerates 279
// versions. this file fails 195 of them and the 82 it does not are
// indistinguishable from the shipped one for every input, which the shipped
// doc comments say where it matters. cut this file back to the family's ladder,
// depth 9 and below, with every other row kept and the arm counts adjusted so
// it is still green, and 200 pass: the band from depth 10 to 31 is the only
// thing killing 118 of the 279. they are every level from 10 to 31 dropped from
// the direct path, every position from 10 to 30 dropped, every truncation to a
// length in that range, the matching two bands of the copath, and the step
// bound anywhere from 10 to 29.
//
// the independence of the oracle is measured too, not asserted. with pathOracle
// rewritten to call DirectPath and Copath and nothing else changed, a version
// that swaps the first node of every path above depth 9 for its sibling — the
// same length, the wrong nodes — passes this test. with the layout oracle it
// fails. that is the circular table this project has rejected four times, and
// the only thing standing between the two is that pathOracle calls nothing.
func TestDirectPathAndCopathAcrossEveryDepth(t *testing.T) {
	emptyPaths, definedPaths := 0, 0

	// depths 0 to 9 exhaustively. walking (level, block) rather than the node
	// index reaches every node exactly once — level k holds 2^(depth-k) nodes
	// and the widths sum to 2^(depth+1)-1 — and it is the pair the oracle takes,
	// so no node index is ever handed back to the oracle to be taken apart.
	for depth := uint32(0); depth <= 9; depth += 1 {
		leafCount := LeafCount(1) << depth
		for level := uint32(0); level <= depth; level += 1 {
			for block := uint64(0); block < uint64(1)<<(depth-level); block += 1 {
				if checkPathsAgainstOracle(t, level, block, depth, leafCount) == 0 {
					emptyPaths += 1
				} else {
					definedPaths += 1
				}
			}
		}
	}

	// depths 10 to 31, where a tree has too many nodes to walk. five blocks at
	// every level of every depth: the first and second block, the last and
	// second to last, and one with alternating bits, which is what separates a
	// version right for an all-left or all-right ancestor chain from one right
	// for a chain that turns. the mask keeps the count the same at every level,
	// so a level holding a single block simply repeats it rather than dropping
	// out of the total below.
	blockProbes := []uint64{0, 1, 0xFFFFFFFF, 0xFFFFFFFE, 0xA5A5A5A5}
	highDepthEmpty, highDepthDefined := 0, 0
	for depth := uint32(10); depth <= 31; depth += 1 {
		leafCount := LeafCount(1) << depth
		for level := uint32(0); level <= depth; level += 1 {
			blockMask := uint64(1)<<(depth-level) - 1
			for _, probe := range blockProbes {
				if checkPathsAgainstOracle(t, level, probe&blockMask, depth, leafCount) == 0 {
					highDepthEmpty += 1
				} else {
					highDepthDefined += 1
				}
			}
		}
	}

	countCases := []struct {
		label string
		got   int
		want  int
	}{
		// the ten trees from one to 512 leaves hold 2^(d+1)-1 nodes each,
		// 2036 in all, which is the node total the corpus tripwire pins for
		// the same ladder. one node of each is its root.
		{label: "empty paths up to 512 leaves", got: emptyPaths, want: 10},
		{label: "paths with nodes on them up to 512 leaves", got: definedPaths, want: 2026},
		// twenty-two depths, depth+1 levels each, five blocks a level:
		// 5 * (11 + 12 + ... + 32) = 5 * 473 = 2365. the five at the top level
		// of each depth are the root, whose blocks all mask to zero.
		{label: "empty paths above 512 leaves", got: highDepthEmpty, want: 110},
		{label: "paths with nodes on them above 512 leaves", got: highDepthDefined, want: 2255},
	}
	for _, c := range countCases {
		if c.got != c.want {
			t.Errorf("confirmed %s: %d, want %d", c.label, c.got, c.want)
		}
	}
}

// the relationship the two functions are defined by, asserted on its own.
//
// RFC 9420 section 4.1.2 defines the copath of a node as the node's sibling
// followed by the siblings of its direct path excluding the root, so the two
// results are the pair a mirror-image bug hides in: a copath built by shifting
// a wrong direct path agrees with it at every length, and a test that only
// compared their lengths, or derived one from the other, would pass on both.
// the absolute contents are pinned against table 2 and the layout oracle above
// and are not restated here; what is asserted here is the relation, against the
// Parent and Sibling the vector family and Task 6's boundary rows already pin
// at every level and every leaf count.
func TestCopathIsTheSiblingOfTheDirectPath(t *testing.T) {
	checkedPositions, emptyPathNodes := 0, 0

	// the same two bands the absolute sweep walks, for the same reason: the
	// relation has to hold at depth 31 as well as at depth 3, and nothing else
	// in this package puts either function into a tree that deep.
	blockProbes := []uint64{0, 1, 0xFFFFFFFF, 0xFFFFFFFE, 0xA5A5A5A5}
	for depth := uint32(0); depth <= 31; depth += 1 {
		leafCount := LeafCount(1) << depth
		root, err := Root(leafCount)
		if err != nil {
			t.Fatalf("%d leaves: root: %v", leafCount, err)
		}
		for level := uint32(0); level <= depth; level += 1 {
			blocks := []uint64{}
			if depth <= 9 {
				for block := uint64(0); block < uint64(1)<<(depth-level); block += 1 {
					blocks = append(blocks, block)
				}
			} else {
				blockMask := uint64(1)<<(depth-level) - 1
				for _, probe := range blockProbes {
					blocks = append(blocks, probe&blockMask)
				}
			}

			for _, block := range blocks {
				nodeIndex := nodeAt(level, block)
				directPath, err := DirectPath(nodeIndex, leafCount)
				if err != nil {
					t.Fatalf("%d leaves: direct path of node %d: %v", leafCount, nodeIndex, err)
				}
				copathNodes, err := Copath(nodeIndex, leafCount)
				if err != nil {
					t.Fatalf("%d leaves: copath of node %d: %v", leafCount, nodeIndex, err)
				}
				if len(copathNodes) != len(directPath) {
					t.Fatalf("%d leaves: node %d has a copath of %d beside a direct path of %d", leafCount, nodeIndex, len(copathNodes), len(directPath))
				}
				if len(directPath) == 0 {
					if nodeIndex != root {
						t.Fatalf("%d leaves: node %d has an empty direct path but is not the root %d", leafCount, nodeIndex, root)
					}
					emptyPathNodes += 1
					continue
				}
				if last := directPath[len(directPath)-1]; last != root {
					t.Fatalf("%d leaves: direct path of node %d ends at %d, want the root %d", leafCount, nodeIndex, last, root)
				}

				child := nodeIndex
				for i := range directPath {
					// the direct path is the chain of parents from the node up.
					if got, err := Parent(child, leafCount); err != nil {
						t.Fatalf("%d leaves: parent of node %d: %v", leafCount, child, err)
					} else if got != directPath[i] {
						t.Fatalf("%d leaves: direct path of node %d has %d at position %d, but the parent of %d is %d", leafCount, nodeIndex, directPath[i], i, child, got)
					}
					// and the copath is that chain's siblings, which is the
					// half of the relation a mirror-image pair gets wrong in
					// step with the other half.
					if got, err := Sibling(child, leafCount); err != nil {
						t.Fatalf("%d leaves: sibling of node %d: %v", leafCount, child, err)
					} else if got != copathNodes[i] {
						t.Fatalf("%d leaves: copath of node %d has %d at position %d, but the sibling of %d is %d", leafCount, nodeIndex, copathNodes[i], i, child, got)
					}
					// read the other way as well: the copath entry hangs off
					// the direct path entry beside it, and is the child of it
					// the node does not descend from. a copath shifted by a
					// position satisfies one of these two and not both.
					if got, err := Parent(copathNodes[i], leafCount); err != nil {
						t.Fatalf("%d leaves: parent of copath node %d: %v", leafCount, copathNodes[i], err)
					} else if got != directPath[i] {
						t.Fatalf("%d leaves: copath node %d at position %d has parent %d, want the direct path node %d", leafCount, copathNodes[i], i, got, directPath[i])
					}
					if copathNodes[i] == child {
						t.Fatalf("%d leaves: copath of node %d repeats %d at position %d, want the other child", leafCount, nodeIndex, child, i)
					}
					if copathNodes[i] == root {
						t.Fatalf("%d leaves: copath of node %d holds the root %d at position %d", leafCount, nodeIndex, root, i)
					}
					checkedPositions += 1
					child = directPath[i]
				}
			}
		}
	}

	countCases := []struct {
		label string
		got   int
		want  int
	}{
		// one root per depth, thirty-two depths. the top level of a depth above
		// 9 is probed five times and every probe masks to the root, so those
		// twenty-two depths contribute five each.
		{label: "nodes with an empty path", got: emptyPathNodes, want: 10 + 110},
		// a node at level k of a depth d tree has d-k positions on its path.
		// summed over every node of depths 0 to 9 that is
		// sum(d=0..9) sum(j=0..d) j*2^j = 14362, and over the five blocks a
		// level of depths 10 to 31 it is 5/2 * sum(d=10..31) d*(d+1) = 26455.
		{label: "checked positions", got: checkedPositions, want: 40817},
	}
	for _, c := range countCases {
		if c.got != c.want {
			t.Errorf("confirmed %s: %d, want %d", c.label, c.got, c.want)
		}
	}
}

// the ancestors of one node, each mapped to its own level: the node itself and
// every node above it on the way to the root of a tree of the given depth.
//
// the node is named by its level and by the block of 2^level leaves it spans
// rather than by its index, which is what makes the level of every ancestor
// known without asking for it — the i-th node of a direct path leaving level k
// sits at level k+1+i. no function of this package is called here or by what
// this calls, so nothing in the answer can move with a bug in the package.
func ancestorLevels(level uint32, block uint64, depth uint32) map[NodeIndex]uint32 {
	ancestors := map[NodeIndex]uint32{nodeAt(level, block): level}
	directPath, _ := pathOracle(level, block, depth)
	for i, node := range directPath {
		ancestors[node] = level + 1 + uint32(i)
	}
	return ancestors
}

// the second of the two definitions RFC 9420 gives for the common ancestor,
// which is the only reason a differential is possible here at all.
//
// ported from the appendix C listing, published as
//
//	# The common ancestor of two nodes is the lowest node that is in the
//	# direct paths of both leaves.
//	def common_ancestor_semantic(x, y, n):
//	    dx = set([x]) | set(direct_path(x, n))
//	    dy = set([y]) | set(direct_path(y, n))
//	    dxy = dx & dy
//	    if len(dxy) == 0:
//	        raise Exception('failed to find common ancestor')
//	    return min(dxy, key=level)
//
// read from https://www.rfc-editor.org/rfc/rfc9420.txt appendix C and from the
// local copy at mls_measure/mls-go/rfc9420.txt lines 6843 to 6851, sha256
// 467d709b7cea19d278204daca1af01910add522cd8e3325cb406f339efbb0d92. the two
// readings agree, and the same appendix publishes the arithmetic form on lines
// 6854 to 6867, which is what the shipped function implements.
//
// the port departs from the listing in exactly one place, and deliberately.
// the listing's direct_path and level are this package's DirectPath and
// NodeIndex.Level, and CommonAncestor calls NodeIndex.Level itself, so a port
// written that way would share a dependency with the function it exists to
// disagree with. the ancestor chains come from pathOracle instead, the array
// layout in closed form, anchored against RFC 9420 table 2 by the direct-path
// tests above; each level is carried down from the loop that built the chain.
// measured, and not merely argued: with the two chains taken from DirectPath
// and the minimum taken by NodeIndex.Level, a Level answering one too high for
// every parent leaves this differential green.
//
// the intersection of two ancestor chains holds no two nodes at one level, so
// the minimum is unique and this returns the same node whatever order the map
// is walked in.
func commonAncestorSemantic(t *testing.T, level uint32, block uint64, otherLevel uint32, otherBlock uint64, depth uint32) NodeIndex {
	t.Helper()
	ancestorsOfX := ancestorLevels(level, block, depth)
	ancestorsOfY := ancestorLevels(otherLevel, otherBlock, depth)

	lowest, lowestLevel, found := NodeIndex(0), uint32(0), false
	for node, nodeLevel := range ancestorsOfX {
		if _, shared := ancestorsOfY[node]; !shared {
			continue
		}
		if !found || nodeLevel < lowestLevel {
			lowest, lowestLevel, found = node, nodeLevel, true
		}
	}
	if !found {
		t.Fatalf("depth %d: no common ancestor of the node at level %d block %d and the node at level %d block %d", depth, level, block, otherLevel, otherBlock)
	}
	return lowest
}

// how many pairs of each shape a common-ancestor sweep reached.
//
// the implementation answers in three ways — the second operand is an ancestor
// of the first, the first is an ancestor of the second, or the answer is
// neither — and a sweep that reaches only one of them looks complete and is
// not. the leaf-pair band below reaches no ancestor pair at all, which is why
// its two ancestor arms are asserted to be empty rather than left unsaid.
type ancestorArms struct {
	pairsOfANodeWithItself int
	pairsAnsweredByX       int
	pairsAnsweredByY       int
	pairsAnsweredByNeither int
}

// one pair of nodes against the semantic definition, absolutely and in both
// orders, tallying the shape of the pair.
//
// both orders are checked against the same absolute answer rather than against
// each other, because two answers that agree with each other can both be
// wrong: a version that always returns the root is perfectly symmetric.
//
// the pair is named by level and block for the same reason the oracle is. no
// node index is ever handed back to be taken apart, so nothing here needs a
// second reading of NodeIndex.Level.
func checkCommonAncestorAgainstSemantic(t *testing.T, level uint32, block uint64, otherLevel uint32, otherBlock uint64, depth uint32, arms *ancestorArms) {
	t.Helper()
	x, y := nodeAt(level, block), nodeAt(otherLevel, otherBlock)
	want := commonAncestorSemantic(t, level, block, otherLevel, otherBlock, depth)

	if got := CommonAncestor(x, y); got != want {
		t.Fatalf("depth %d: common ancestor of %d and %d: %d, want %d", depth, x, y, got, want)
	}
	if got := CommonAncestor(y, x); got != want {
		t.Fatalf("depth %d: common ancestor of %d and %d: %d, want %d", depth, y, x, got, want)
	}

	switch {
	case x == y:
		arms.pairsOfANodeWithItself += 1
	case want == x:
		arms.pairsAnsweredByX += 1
	case want == y:
		arms.pairsAnsweredByY += 1
	default:
		arms.pairsAnsweredByNeither += 1
	}
}

// reports the four arms of a sweep against the totals derived from its own loop
// structure, so a band that silently stopped short fails as loudly as a wrong
// answer would.
func assertAncestorArms(t *testing.T, band string, arms ancestorArms, want ancestorArms) {
	t.Helper()
	armCases := []struct {
		label string
		got   int
		want  int
	}{
		{label: "pairs of a node with itself", got: arms.pairsOfANodeWithItself, want: want.pairsOfANodeWithItself},
		{label: "pairs answered by the first node", got: arms.pairsAnsweredByX, want: want.pairsAnsweredByX},
		{label: "pairs answered by the second node", got: arms.pairsAnsweredByY, want: want.pairsAnsweredByY},
		{label: "pairs answered by neither node", got: arms.pairsAnsweredByNeither, want: want.pairsAnsweredByNeither},
	}
	for _, c := range armCases {
		if c.got != c.want {
			t.Errorf("%s: %s: %d, want %d", band, c.label, c.got, c.want)
		}
	}
}

// the absolute answer for pairs whose common ancestor was worked out by hand
// from the array layout, before anything was run.
//
// RFC 9420 publishes no table of common ancestors, so unlike the direct-path
// fixtures above these rows are not quoted from the document; they are read off
// appendix C figure 32's layout, in which the level-k node covering the b-th
// block of 2^k leaves sits at array position b*2^(k+1) + 2^k - 1. the first
// nine rows are the eight-leaf tree the plan named and can be checked against
// figure 11's drawing node by node. the rest reach levels the eight-leaf tree
// does not have: a tree has up to 32 levels and a fixture that stops at level
// three pins one of them.
//
// symmetry is checked on every row, but the load-bearing assertion is the
// absolute one beside it. symmetry, reflexivity and "the answer is an ancestor
// of both" are each satisfied by a version that always returns the root, so a
// fixture built out of them alone would be green on one.
func TestCommonAncestorKnownValues(t *testing.T) {
	ancestorCases := []struct {
		x        NodeIndex
		y        NodeIndex
		ancestor NodeIndex
	}{
		// the eight-leaf tree of figure 11: leaves at 0, 2, 4, 6, 8, 10, 12 and
		// 14, parents at 1, 5, 9 and 13, grandparents at 3 and 11, root at 7.
		{x: 0, y: 0, ancestor: 0},
		{x: 0, y: 2, ancestor: 1},
		{x: 0, y: 4, ancestor: 3},
		{x: 2, y: 6, ancestor: 3},
		{x: 0, y: 14, ancestor: 7},
		{x: 1, y: 0, ancestor: 1},
		{x: 0, y: 1, ancestor: 1},
		{x: 3, y: 11, ancestor: 7},
		{x: 9, y: 13, ancestor: 11},
		// two level-ten nodes side by side, joining at level eleven:
		// 2^10-1 = 1023 and 2^11 + 2^10 - 1 = 3071 under 2^11-1 = 2047.
		{x: 1023, y: 3071, ancestor: 2047},
		// leaf 0 and leaf 2^20, the first leaf of the right half of the
		// leftmost level-21 node: 2*2^20 = 2097152 under 2^21-1 = 2097151.
		{x: 0, y: 2097152, ancestor: 2097151},
		// the level-20 node covering leaves 0 to 2^20-1, and the leaf just past
		// the end of it, which join one level up.
		{x: 1048575, y: 2097152, ancestor: 2097151},
		// a level-five node at the far left and the level-20 node covering
		// leaves 2^20 to 2^21-1, which also join at level 21.
		{x: 31, y: 3145727, ancestor: 2097151},
		// the two level-30 halves of the largest tree, joining at its root
		// 2^31-1 = 2147483647.
		{x: 1073741823, y: 3221225471, ancestor: 2147483647},
		// the first and last leaves of the largest tree, 0 and 2^32-2.
		{x: 0, y: 4294967294, ancestor: 2147483647},
		// the root of the largest tree is an ancestor of every node in it,
		// including the last leaf and including itself.
		{x: 2147483647, y: 0, ancestor: 2147483647},
		{x: 2147483647, y: 4294967294, ancestor: 2147483647},
		{x: 2147483647, y: 2147483647, ancestor: 2147483647},
	}
	// the same arms the sweeps count, so a table that drifted into rows of one
	// shape fails rather than quietly narrowing.
	arms := ancestorArms{}
	for _, c := range ancestorCases {
		if got := CommonAncestor(c.x, c.y); got != c.ancestor {
			t.Errorf("common ancestor of %d and %d: %d, want %d", c.x, c.y, got, c.ancestor)
		}
		// the relation is symmetric.
		if got := CommonAncestor(c.y, c.x); got != c.ancestor {
			t.Errorf("common ancestor of %d and %d: %d, want %d", c.y, c.x, got, c.ancestor)
		}
		switch {
		case c.x == c.y:
			arms.pairsOfANodeWithItself += 1
		case c.ancestor == c.x:
			arms.pairsAnsweredByX += 1
		case c.ancestor == c.y:
			arms.pairsAnsweredByY += 1
		default:
			arms.pairsAnsweredByNeither += 1
		}
	}
	assertAncestorArms(t, "the known-value table", arms, ancestorArms{
		pairsOfANodeWithItself: 2,
		pairsAnsweredByX:       3,
		pairsAnsweredByY:       1,
		pairsAnsweredByNeither: 12,
	})
}

// the absolute answer at every level a node can have, from the layout and not
// from the semantic oracle.
//
// the differential below is only as good as the oracle it runs against, so the
// levels above the eight-leaf tree are anchored here as well, by three ladders
// whose answers are closed forms rather than searches. every row is a triple
// the layout fixes: two nodes side by side under one parent answer that parent;
// a node and anything beneath it answer the node; and two nodes taken from
// opposite halves of a level-k node answer that node whatever levels they
// themselves sit at.
//
// this is where the boundary lives. the vector family stops at 512 leaves, the
// plan's own differential stops at depth 9, and the invariant sweep of Task 13
// stops there too, so levels 10 to 31 are reached by nothing else in this
// package. the ladders run to level 31 because that is the highest level the
// largest representable tree has.
func TestCommonAncestorAtEveryLevel(t *testing.T) {
	siblingRows, containedRows, joinRows := 0, 0, 0

	// two nodes side by side at the same level answer their parent, at every
	// level a parent can sit at.
	for level := uint32(0); level <= 30; level += 1 {
		x, y, want := nodeAt(level, 0), nodeAt(level, 1), nodeAt(level+1, 0)
		if got := CommonAncestor(x, y); got != want {
			t.Fatalf("level %d: common ancestor of %d and %d: %d, want %d", level, x, y, got, want)
		}
		if got := CommonAncestor(y, x); got != want {
			t.Fatalf("level %d: common ancestor of %d and %d: %d, want %d", level, y, x, got, want)
		}
		siblingRows += 1
	}

	// a node and a node beneath it answer the higher node, at every pair of
	// levels. the leftmost and the rightmost descendant at the lower level are
	// both taken, because a version that shifted by the wrong operand's level
	// is right for one of them and wrong for the other.
	for level := uint32(1); level <= 31; level += 1 {
		head := nodeAt(level, 0)
		for inner := uint32(0); inner < level; inner += 1 {
			for _, block := range []uint64{0, uint64(1)<<(level-inner) - 1} {
				inside := nodeAt(inner, block)
				if got := CommonAncestor(head, inside); got != head {
					t.Fatalf("level %d: common ancestor of %d and %d beneath it: %d, want %d", level, head, inside, got, head)
				}
				if got := CommonAncestor(inside, head); got != head {
					t.Fatalf("level %d: common ancestor of %d and %d above it: %d, want %d", level, inside, head, got, head)
				}
				containedRows += 1
			}
		}
	}

	// one node from each half of a level-k node answers that node, whatever
	// levels the two are at. the left one is the leftmost node of its level and
	// the right one the rightmost of its own, so the two are always in opposite
	// halves of the level-k node at block zero.
	for level := uint32(1); level <= 31; level += 1 {
		want := nodeAt(level, 0)
		for leftLevel := uint32(0); leftLevel < level; leftLevel += 1 {
			for rightLevel := uint32(0); rightLevel < level; rightLevel += 1 {
				x := nodeAt(leftLevel, 0)
				y := nodeAt(rightLevel, uint64(1)<<(level-rightLevel)-1)
				if got := CommonAncestor(x, y); got != want {
					t.Fatalf("level %d: common ancestor of %d at level %d and %d at level %d: %d, want %d", level, x, leftLevel, y, rightLevel, got, want)
				}
				if got := CommonAncestor(y, x); got != want {
					t.Fatalf("level %d: common ancestor of %d at level %d and %d at level %d: %d, want %d", level, y, rightLevel, x, leftLevel, got, want)
				}
				joinRows += 1
			}
		}
	}

	countCases := []struct {
		label string
		got   int
		want  int
	}{
		// one parent per level from 1 to 31.
		{label: "sibling pairs", got: siblingRows, want: 31},
		// two descendants at each pair of levels (k, j) with j < k, which is
		// 2 * sum(k=1..31) k.
		{label: "containment pairs", got: containedRows, want: 992},
		// every ordered pair of levels below each join level, sum(k=1..31) k*k.
		{label: "join pairs", got: joinRows, want: 10416},
	}
	for _, c := range countCases {
		if c.got != c.want {
			t.Errorf("confirmed %s: %d, want %d", c.label, c.got, c.want)
		}
	}
}

// RFC 9420 gives two independent definitions and the whole value of having both
// is that they can be run against each other.
//
// three bands. every ordered pair of nodes of every tree up to 128 leaves; then
// every ordered pair of leaves of the 256 and 512 leaf trees, which is the band
// the plan named; then designed pairs at every level of every depth from 10 to
// 31, which is where the boundary is and which nothing else in this package
// reaches. the arms of each band are counted and pinned, and the leaf band's
// two ancestor arms are pinned at zero: a band of leaves alone can never put
// one operand inside the other, so a differential built only from leaf pairs
// never runs either of the two shortcuts the implementation opens with.
func TestCommonAncestorMatchesSemanticDefinition(t *testing.T) {
	// depths 0 to 7 exhaustively. walking (level, block) reaches every node of
	// the tree exactly once and is the pair the oracle takes, so no node index
	// is ever handed back to the oracle to be taken apart.
	exhaustiveArms := ancestorArms{}
	for depth := uint32(0); depth <= 7; depth += 1 {
		for level := uint32(0); level <= depth; level += 1 {
			for block := uint64(0); block < uint64(1)<<(depth-level); block += 1 {
				for otherLevel := uint32(0); otherLevel <= depth; otherLevel += 1 {
					for otherBlock := uint64(0); otherBlock < uint64(1)<<(depth-otherLevel); otherBlock += 1 {
						checkCommonAncestorAgainstSemantic(t, level, block, otherLevel, otherBlock, depth, &exhaustiveArms)
					}
				}
			}
		}
	}
	// a tree of depth d holds 2^(d+1)-1 nodes, so the eight trees hold 502
	// between them and that many pairs are a node with itself. a level-k node
	// has 2^(k+1)-2 nodes strictly beneath it, and summed over a whole tree
	// that is (d-1)*2^(d+1)+2, which over the eight depths is 2582; the
	// mirrored arm is the same size, and the rest answer neither operand.
	assertAncestorArms(t, "every node pair up to 128 leaves", exhaustiveArms, ancestorArms{
		pairsOfANodeWithItself: 502,
		pairsAnsweredByX:       2582,
		pairsAnsweredByY:       2582,
		pairsAnsweredByNeither: 80702,
	})

	// the 256 and 512 leaf trees, leaf pairs only, which is the band the plan
	// wrote and is kept because a leaf pair is what every caller of this
	// function in the rest of the slice actually holds.
	leafArms := ancestorArms{}
	for depth := uint32(8); depth <= 9; depth += 1 {
		for block := uint64(0); block < uint64(1)<<depth; block += 1 {
			for otherBlock := uint64(0); otherBlock < uint64(1)<<depth; otherBlock += 1 {
				checkCommonAncestorAgainstSemantic(t, 0, block, 0, otherBlock, depth, &leafArms)
			}
		}
	}
	// 256^2 + 512^2 pairs, of which 256 + 512 are a leaf with itself and no
	// leaf is ever inside another.
	assertAncestorArms(t, "every leaf pair at 256 and 512 leaves", leafArms, ancestorArms{
		pairsOfANodeWithItself: 768,
		pairsAnsweredByX:       0,
		pairsAnsweredByY:       0,
		pairsAnsweredByNeither: 326912,
	})

	// depths 10 to 31, where a tree has too many nodes to walk. every ordered
	// pair of levels, and five blocks at each: the first and second block, the
	// last and second to last, and one with alternating bits, which is what
	// separates a version right for an all-left or all-right chain from one
	// right for a chain that turns. the mask keeps the count the same at every
	// level, so a level holding a single block repeats it rather than dropping
	// out of the totals below.
	blockProbes := []uint64{0, 1, 0xFFFFFFFF, 0xFFFFFFFE, 0xA5A5A5A5}
	deepArms := ancestorArms{}
	for depth := uint32(10); depth <= 31; depth += 1 {
		for level := uint32(0); level <= depth; level += 1 {
			blockMask := uint64(1)<<(depth-level) - 1
			for otherLevel := uint32(0); otherLevel <= depth; otherLevel += 1 {
				otherMask := uint64(1)<<(depth-otherLevel) - 1
				for _, probe := range blockProbes {
					for _, otherProbe := range blockProbes {
						checkCommonAncestorAgainstSemantic(t, level, probe&blockMask, otherLevel, otherProbe&otherMask, depth, &deepArms)
					}
				}
			}
		}
	}
	// twenty-two depths, (d+1)^2 ordered level pairs each, twenty-five block
	// pairs a level pair: 25 * sum(d=10..31) (d+1)^2 = 276375. the split
	// between the four arms was derived from the same masks outside Go, not
	// read off a run.
	assertAncestorArms(t, "designed pairs from depth 10 to 31", deepArms, ancestorArms{
		pairsOfANodeWithItself: 3025,
		pairsAnsweredByX:       35308,
		pairsAnsweredByY:       35308,
		pairsAnsweredByNeither: 202734,
	})
}

// the properties of the relation, asserted apart from the absolute answers
// above because on their own they are nearly free.
//
// a version that always returns the root of the tree satisfies symmetry, "the
// answer is an ancestor of both" and "the answer is at least as high as both
// operands"; only reflexivity refuses it, and only at the pairs where the two
// operands are equal. these rows pin the shape of the relation rather than
// establish it, and that sentence is measurable rather than rhetorical: with
// the three absolute tests above deleted and only this one and the rest of the
// package kept, the enumeration this task ran leaves far more versions alive
// than it does with them.
//
// the last row is the one that is not free. the answer has to be inside the
// smallest tree that contains both operands, which is what makes the missing
// leaf count in the signature sound, and it is the row a version returning the
// root of the largest representable tree fails.
func TestCommonAncestorProperties(t *testing.T) {
	checkedPairs, reflexivePairs := 0, 0

	check := func(depth uint32, level uint32, block uint64, otherLevel uint32, otherBlock uint64) {
		t.Helper()
		leafCount := LeafCount(1) << depth
		x, y := nodeAt(level, block), nodeAt(otherLevel, otherBlock)
		ancestor := CommonAncestor(x, y)

		if got := CommonAncestor(y, x); got != ancestor {
			t.Fatalf("%d leaves: common ancestor of %d and %d is %d one way and %d the other", leafCount, x, y, ancestor, got)
		}
		if x == y {
			if ancestor != x {
				t.Fatalf("%d leaves: common ancestor of %d with itself: %d", leafCount, x, ancestor)
			}
			reflexivePairs += 1
		}
		// idempotent: joining the answer back onto either operand answers the
		// same node, which a version that climbed one level too far fails.
		if got := CommonAncestor(ancestor, x); got != ancestor {
			t.Fatalf("%d leaves: common ancestor of %d and %d beneath it: %d", leafCount, ancestor, x, got)
		}
		if got := CommonAncestor(ancestor, y); got != ancestor {
			t.Fatalf("%d leaves: common ancestor of %d and %d beneath it: %d", leafCount, ancestor, y, got)
		}
		// an ancestor of both, read off the direct paths the rest of this file
		// already pins against RFC 9420 table 2.
		for _, operand := range []NodeIndex{x, y} {
			if ancestor == operand {
				continue
			}
			directPath, err := DirectPath(operand, leafCount)
			if err != nil {
				t.Fatalf("%d leaves: direct path of %d: %v", leafCount, operand, err)
			}
			onPath := false
			for _, node := range directPath {
				if node == ancestor {
					onPath = true
				}
			}
			if !onPath {
				t.Fatalf("%d leaves: common ancestor %d of %d and %d is not on the direct path of %d", leafCount, ancestor, x, y, operand)
			}
		}
		// and no lower than either operand.
		if ancestor.Level() < level || ancestor.Level() < otherLevel {
			t.Fatalf("%d leaves: common ancestor %d of %d and %d is at level %d, below level %d or %d", leafCount, ancestor, x, y, ancestor.Level(), level, otherLevel)
		}
		// inside the smallest tree holding both, which is the claim that makes
		// the absent leaf count sound.
		if uint32(ancestor) >= NodeWidth(leafCount) {
			t.Fatalf("%d leaves: common ancestor %d of %d and %d is outside a tree that holds them both, of width %d", leafCount, ancestor, x, y, NodeWidth(leafCount))
		}
		checkedPairs += 1
	}

	// every ordered node pair of every tree up to 32 leaves.
	for depth := uint32(0); depth <= 5; depth += 1 {
		for level := uint32(0); level <= depth; level += 1 {
			for block := uint64(0); block < uint64(1)<<(depth-level); block += 1 {
				for otherLevel := uint32(0); otherLevel <= depth; otherLevel += 1 {
					for otherBlock := uint64(0); otherBlock < uint64(1)<<(depth-otherLevel); otherBlock += 1 {
						check(depth, level, block, otherLevel, otherBlock)
					}
				}
			}
		}
	}

	// and every ordered pair of levels in the largest tree there is, so the
	// properties are pinned where the sweeps of this package otherwise stop.
	for level := uint32(0); level <= 31; level += 1 {
		for otherLevel := uint32(0); otherLevel <= 31; otherLevel += 1 {
			check(31, level, 0, otherLevel, uint64(1)<<(31-otherLevel)-1)
			check(31, level, uint64(1)<<(31-level)-1, otherLevel, 0)
		}
	}

	countCases := []struct {
		label string
		got   int
		want  int
	}{
		// 1 + 9 + 49 + 225 + 961 + 3969 pairs from the six trees, then two per
		// ordered pair of the 32 levels.
		{label: "checked pairs", got: checkedPairs, want: 5214 + 2048},
		// one per node of the six trees, which is sum(d=0..5) 2^(d+1)-1, and in
		// the deep band the pairs where both sides name one node: the only pair
		// of levels at which they do is 31 against 31, once in each order.
		{label: "pairs of a node with itself", got: reflexivePairs, want: 120 + 2},
	}
	for _, c := range countCases {
		if c.got != c.want {
			t.Errorf("confirmed %s: %d, want %d", c.label, c.got, c.want)
		}
	}
}

// the claim the missing leaf count rests on: any tree containing both nodes
// contains their common ancestor, at the same index.
//
// the shipped doc comment states it and the plan's test block never looks at
// it. it is checked here by asking the semantic definition the same question in
// every tree that holds the pair, from the smallest up to the largest there is,
// requiring one answer throughout, and requiring the count-free answer of the
// shipped function to be that one.
func TestCommonAncestorDoesNotDependOnTheLeafCount(t *testing.T) {
	// pairs named by level and block, across the shapes: two leaves, a node and
	// a leaf beneath it, two nodes at unequal levels, a node with itself.
	pairCases := []struct {
		level      uint32
		block      uint64
		otherLevel uint32
		otherBlock uint64
	}{
		{level: 0, block: 0, otherLevel: 0, otherBlock: 1},
		{level: 0, block: 0, otherLevel: 0, otherBlock: 5},
		{level: 0, block: 3, otherLevel: 0, otherBlock: 4},
		{level: 2, block: 0, otherLevel: 0, otherBlock: 3},
		{level: 2, block: 0, otherLevel: 0, otherBlock: 4},
		{level: 3, block: 1, otherLevel: 1, otherBlock: 0},
		{level: 4, block: 0, otherLevel: 4, otherBlock: 1},
		{level: 5, block: 2, otherLevel: 5, otherBlock: 2},
		{level: 9, block: 1, otherLevel: 0, otherBlock: 0},
		{level: 10, block: 0, otherLevel: 10, otherBlock: 1},
	}
	checkedTrees := 0
	for _, c := range pairCases {
		// the smallest tree holding both: deep enough for the higher of the two
		// levels and for the higher of the two blocks.
		smallestDepth := c.level
		if smallestDepth < c.otherLevel {
			smallestDepth = c.otherLevel
		}
		for c.block>>(smallestDepth-c.level) != 0 || c.otherBlock>>(smallestDepth-c.otherLevel) != 0 {
			smallestDepth += 1
		}

		x, y := nodeAt(c.level, c.block), nodeAt(c.otherLevel, c.otherBlock)
		ancestor := CommonAncestor(x, y)
		for depth := smallestDepth; depth <= 31; depth += 1 {
			want := commonAncestorSemantic(t, c.level, c.block, c.otherLevel, c.otherBlock, depth)
			if want != ancestor {
				t.Fatalf("%d leaves: common ancestor of %d and %d is %d there and %d in the smallest tree that holds them", LeafCount(1)<<depth, x, y, want, ancestor)
			}
			if uint32(ancestor) >= NodeWidth(LeafCount(1)<<depth) {
				t.Fatalf("%d leaves: common ancestor %d of %d and %d is outside the tree", LeafCount(1)<<depth, ancestor, x, y)
			}
			checkedTrees += 1
		}
	}

	// the smallest tree holding each pair is at depth 1, 3, 3, 2, 3, 4, 5, 7,
	// 10 and 11, and each is carried up to depth 31, which is the sum of 32-d
	// over those ten depths.
	if want := 31 + 29 + 29 + 30 + 29 + 28 + 27 + 25 + 22 + 21; checkedTrees != want {
		t.Errorf("confirmed trees checked: %d, want %d", checkedTrees, want)
	}
}
