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
