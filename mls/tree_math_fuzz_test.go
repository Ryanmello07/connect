// a fuzz target over the index arithmetic of tree_math.go: the structural laws
// that hold in every well-formed tree, and the refusals that have to hold for
// every input that is not one.
//
// the sweeps in tree_math_test.go walk trees. this walks the argument space,
// which is a different set and deliberately so: a sweep only ever forms an
// argument some tree really holds, so the whole out-of-range half of every
// signature — a leaf count that is no tree, a node index past the end of the
// array, a leaf index past the last member — is reached there only where a test
// was written to reach it, one arm at a time. that half is where a wrong answer
// is worst: a function that answers a plausible index for a node outside the
// tree hands its caller a node of some other tree, and nothing downstream can
// tell that apart from a real one. so the target takes four raw uint32 words
// and interprets none of them: every input is legal to hand over, and what the
// laws below say is which of them is an answer and which is a refusal.
//
// every expectation here is built from the array layout — the level and block
// of a node, and the node at a level and block — and never from the function
// being asked. that is the discipline the sweeps hold to and it is the reason a
// fuzz target of this shape is worth having at all: a target that asserted
// Parent against Parent's own arithmetic would pass every rewrite of it, which
// is exactly the class of test this project has rejected before. the layout
// helpers are tree_math_test.go's, anchored there against RFC 9420 table 2 and
// figure 11 before any sweep or any fuzz execution uses them.
//
// the corpus is seeded from the ladder the vendored mlswg tree-math vectors
// publish, read off the corpus rather than typed out here, together with the
// boundaries of the leaf-count space computed from the width of the type. the
// seeds alone are a test: go test -run FuzzTreeMath executes every one of them,
// so the laws below are enforced on every run of this package and not only when
// someone passes -fuzz.
package mls

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// the largest leaf count a tree can have, derived here from the width of a node
// index rather than read from the package: a count of 2^31 has node width
// 2^32-1, the largest value a NodeIndex holds, and one leaf more does not fit.
// tree_math.go states the same bound as MaxLeafCount, and the two are asserted
// against each other in TestTreeMathFuzzSeedCorpus rather than assumed equal,
// so a change to either is a failure and not a silent agreement.
const fuzzMaxLeafCount = uint64(1) << 31

// the deepest tree one fuzz execution builds a blank-node shape over.
//
// a resolution descends the blank part of a subtree, so the root of a tree with
// every parent blank costs a node visit per leaf: at 512 leaves that is about a
// thousand visits an execution and at 2^31 leaves it is an hour of them. above
// the cap the shape is the tree with nothing blank, whose resolution is one node
// whatever the depth, so every depth is still asked about — what the cap bounds
// is how much of a shape's blank space a single execution explores, not which
// trees the target reaches.
const fuzzBlankShapeDepth = 9

// the refusal checkLeafCount owes a leaf count, worked out from what a valid
// tree is rather than from IsFullLeafCount: non-zero, in range, and equal to two
// to some power — asked by comparing against every power there is rather than by
// the n&(n-1) trick the package uses, so the two derivations cannot be wrong in
// the same direction.
//
// the order of the two refusals is part of the contract and not an accident of
// this body: a count past MaxLeafCount is both out of range and not a power of
// two, and ExtendedLeafCount carries a comment saying which sentinel a caller
// switching on it sees. asserted here means asserted for every function that
// takes a leaf count at once.
func leafCountRefusalOracle(n LeafCount) error {
	if n == 0 || uint64(n) > fuzzMaxLeafCount {
		return ErrLeafCountRange
	}
	for depth := uint32(0); depth <= 31; depth += 1 {
		if uint64(n) == uint64(1)<<depth {
			return nil
		}
	}
	return ErrLeafCountNotFull
}

// the depth of the full tree that holds n leaves: the smallest d with 2^d at
// least n, counted up to rather than read off a bit length, so a bit-length
// mistake in the package cannot be agreed with here.
func treeDepthOracle(n LeafCount) uint32 {
	for depth := uint32(0); depth < 32; depth += 1 {
		if uint64(1)<<depth >= uint64(n) {
			return depth
		}
	}
	return 32
}

// the number of array slots a tree of n leaves occupies, zero where no tree has
// that many leaves so that every range test below fails closed.
func nodeWidthOracle(n LeafCount) uint64 {
	if n == 0 || uint64(n) > fuzzMaxLeafCount {
		return 0
	}
	return 2*uint64(n) - 1
}

// whether the node at (headLevel, headBlock) is an ancestor of the node at
// (level, block), a node counting as its own ancestor (RFC 9420 appendix C).
//
// stated over the layout and not over the array: the head is at or above the
// node and covers the block of leaves the node sits in. the same relation read
// off the array is a range test on a span, which is what InSubtree does, so
// deriving it that way here would be asserting that function against itself.
func ancestorOracle(headLevel uint32, headBlock uint64, level uint32, block uint64) bool {
	return headLevel >= level && block>>(headLevel-level) == headBlock
}

// the lowest node that is an ancestor of both x and y.
//
// found by climbing rather than by shifting the two indices together: the answer
// is at the first level, at or above both, where the two nodes sit in the same
// block. the loop reaches level 32 only when one of the two is 0xFFFFFFFF, the
// one index no tree holds, which tree_math.go documents as reading like a
// level-32 node and being its own answer against anything.
func commonAncestorOracle(x NodeIndex, y NodeIndex) NodeIndex {
	levelOfX, blockOfX := nodeLevelAndBlock(x)
	levelOfY, blockOfY := nodeLevelAndBlock(y)
	for level := max(levelOfX, levelOfY); level <= 32; level += 1 {
		if blockOfX>>(level-levelOfX) == blockOfY>>(level-levelOfY) {
			return nodeAt(level, blockOfX>>(level-levelOfX))
		}
	}
	// two 32-bit indices sit in the same block by level 32 at the latest, so
	// this is unreachable. it is a value and not a panic so that a fuzz failure
	// is reported by the law that follows rather than by this helper.
	return 0
}

// whether head is x or an ancestor of x.
//
// the level-32 index is the exception tree_math.go names: a level-32 subtree is
// 2^33 slots and is not representable, so that index heads nothing but itself.
// the climbing relation above would call it the head of every node there is,
// which is the answer the package deliberately does not give.
func inSubtreeOracle(head NodeIndex, x NodeIndex) bool {
	headLevel, headBlock := nodeLevelAndBlock(head)
	level, block := nodeLevelAndBlock(x)
	if headLevel > 31 {
		return head == x
	}
	return ancestorOracle(headLevel, headBlock, level, block)
}

// the span of any index, including the one no tree holds, whose span
// tree_math.go documents as itself alone and whose leaf pair is therefore the
// truncating halving of that single odd slot.
func subtreeSpanOracle(x NodeIndex) (NodeIndex, NodeIndex, LeafIndex, LeafIndex) {
	level, block := nodeLevelAndBlock(x)
	if level > 31 {
		return x, x, LeafIndex(uint32(x) / 2), LeafIndex(uint32(x) / 2)
	}
	return spanOracle(level, block)
}

// the resolution of x under a shape, written as the recursive definition of
// RFC 9420 section 4.1 rather than as the explicit-stack walk the package runs:
// a non-blank node resolves to itself followed by its unmerged leaves, a blank
// leaf to nothing, and a blank parent to its left child's resolution followed by
// its right child's.
//
// the shape is the caller's, so this is independent of Resolution and not of the
// fixture: what a fuzz execution varies is which nodes are blank and what they
// carry, and both bodies are asked the same question about the same tree.
//
// the out-of-range refusal is raised where the walk reaches it and not before,
// because that is where the package raises it and because an unmerged list is
// only read on a node the walk actually resolves — a list hung behind a blank
// parent's non-blank sibling is never looked at by either body.
func resolutionOracle(shape NodeShape, x NodeIndex, n LeafCount) ([]NodeIndex, error) {
	if !shape.IsBlank(x) {
		resolvedNodes := []NodeIndex{x}
		for _, leaf := range shape.UnmergedLeaves(x) {
			if LeafCount(leaf) >= n {
				return nil, ErrLeafOutOfRange
			}
			resolvedNodes = append(resolvedNodes, leaf.NodeIndex())
		}
		return resolvedNodes, nil
	}
	level, block := nodeLevelAndBlock(x)
	if level == 0 {
		return []NodeIndex{}, nil
	}
	leftResolution, err := resolutionOracle(shape, nodeAt(level-1, 2*block), n)
	if err != nil {
		return nil, err
	}
	rightResolution, err := resolutionOracle(shape, nodeAt(level-1, 2*block+1), n)
	if err != nil {
		return nil, err
	}
	return append(leftResolution, rightResolution...), nil
}

// the filtered direct path of a leaf: its direct path with every step dropped
// whose copath child resolves to nothing, each surviving node paired with that
// copath child.
//
// both columns come from the layout and the decision comes from the resolution
// definition above, so nothing here reads FilteredDirectPath's own reasoning.
func filteredDirectPathOracle(shape NodeShape, leaf LeafIndex, n LeafCount) ([]PathStep, error) {
	pathNodes, copathNodes := pathOracle(0, uint64(leaf), treeDepthOracle(n))
	pathSteps := []PathStep{}
	for i, pathNode := range pathNodes {
		copathResolution, err := resolutionOracle(shape, copathNodes[i], n)
		if err != nil {
			return nil, err
		}
		if len(copathResolution) > 0 {
			pathSteps = append(pathSteps, PathStep{Node: pathNode, CopathChild: copathNodes[i]})
		}
	}
	return pathSteps, nil
}

// the tree a fuzz execution asks the two shape rules about.
//
// the blank set is the fuzzer's own thirty-two bits indexed by the low five bits
// of the node, so an execution names a shape rather than drawing one from a
// generator this file would then have to be trusted about, and the fuzzer can
// walk the whole family by walking one word. the unmerged lists are switched on
// by two more bits: one hangs the first two leaves of a parent's own block on
// it, which is a list a real tree can hold, and the other hangs a leaf past the
// end of the tree, which is a malformed shape both bodies have to refuse at the
// node the walk reaches it on.
//
// the first leaf of a node comes from the layout and not from SubtreeLeaves. a
// fixture built out of the function under test moves with it, so a defect there
// would change the shape and the oracle together and be observed by neither.
func fuzzShape(n LeafCount, pattern uint32) *functionShape {
	return &functionShape{
		shapeLeafCount: n,
		blankNode: func(x NodeIndex) bool {
			return (pattern>>(uint32(x)&0x1F))&0x01 == 1
		},
		unmergedOfNode: func(x NodeIndex) []LeafIndex {
			level, block := nodeLevelAndBlock(x)
			if level == 0 || pattern&0x03 == 0 {
				return nil
			}
			unmergedLeaves := []LeafIndex{}
			if pattern&0x01 != 0 {
				firstLeaf := block << level
				unmergedLeaves = append(unmergedLeaves, LeafIndex(firstLeaf), LeafIndex(firstLeaf+1))
			}
			if pattern&0x02 != 0 {
				unmergedLeaves = append(unmergedLeaves, LeafIndex(uint64(n)+uint64(uint32(x)&0x0F)))
			}
			return unmergedLeaves
		},
	}
}

// one exported function that takes a node index and a leaf count, wrapped so the
// two refusals every one of them owes can be asserted over the whole class at
// once. the boolean says whether the refused call handed back nothing — the zero
// index for the two that answer an index, no slice at all for the two that
// answer a list, which is the promise DirectPath and Copath both document.
//
// the names in this table are checked against the class derived from the source
// by TestTreeMathFuzzRefusalTableIsEveryNodeAndCountFunction, so a function
// added to tree_math.go with this signature and not added here is a failure and
// not a quiet gap.
type treeFunctionCase struct {
	name string
	call func(x NodeIndex, n LeafCount) (err error, handedBackNothing bool)
}

var treeFunctionCases = []treeFunctionCase{
	{
		name: "Parent",
		call: func(x NodeIndex, n LeafCount) (error, bool) {
			parent, err := Parent(x, n)
			return err, parent == 0
		},
	},
	{
		name: "Sibling",
		call: func(x NodeIndex, n LeafCount) (error, bool) {
			sibling, err := Sibling(x, n)
			return err, sibling == 0
		},
	},
	{
		name: "DirectPath",
		call: func(x NodeIndex, n LeafCount) (error, bool) {
			pathNodes, err := DirectPath(x, n)
			return err, pathNodes == nil
		},
	},
	{
		name: "Copath",
		call: func(x NodeIndex, n LeafCount) (error, bool) {
			copathNodes, err := Copath(x, n)
			return err, copathNodes == nil
		},
	},
}

// the laws that hold of a node index on its own, in no tree at all.
//
// every function asked here is total by contract, so the whole 2^32 index space
// is in range for them and the interesting inputs are exactly the ones no tree
// holds. a panic is a failure by construction; what the rows below add is that a
// plausible wrong answer is a failure too.
func checkNodeLawsOutsideAnyTree(t *testing.T, x NodeIndex, y NodeIndex) {
	t.Helper()
	level, block := nodeLevelAndBlock(x)
	if nodeAt(level, block) != x {
		t.Fatalf("node %d reads as level %d block %d, which is node %d", x, level, block, nodeAt(level, block))
	}
	if x.Level() != level {
		t.Fatalf("node %d level %d, want %d", x, x.Level(), level)
	}
	if x.IsLeaf() != (level == 0) {
		t.Fatalf("node %d at level %d reports leaf %v", x, level, x.IsLeaf())
	}
	if x.IsLeaf() != (uint32(x)%2 == 0) {
		t.Fatalf("node %d reports leaf %v against its parity", x, x.IsLeaf())
	}

	leftChild, leftErr := Left(x)
	rightChild, rightErr := Right(x)
	switch {
	case level == 0:
		if !errors.Is(leftErr, ErrLeafHasNoChildren) || leftChild != 0 {
			t.Fatalf("left of leaf %d: %d, %v", x, leftChild, leftErr)
		}
		if !errors.Is(rightErr, ErrLeafHasNoChildren) || rightChild != 0 {
			t.Fatalf("right of leaf %d: %d, %v", x, rightChild, rightErr)
		}
	case level > 31:
		if !errors.Is(leftErr, ErrNodeOutOfRange) || leftChild != 0 {
			t.Fatalf("left of the index no tree holds, %d: %d, %v", x, leftChild, leftErr)
		}
		if !errors.Is(rightErr, ErrNodeOutOfRange) || rightChild != 0 {
			t.Fatalf("right of the index no tree holds, %d: %d, %v", x, rightChild, rightErr)
		}
	default:
		if leftErr != nil || rightErr != nil {
			t.Fatalf("children of %d at level %d: %v, %v", x, level, leftErr, rightErr)
		}
		if leftChild != nodeAt(level-1, 2*block) || rightChild != nodeAt(level-1, 2*block+1) {
			t.Fatalf("children of %d: %d and %d, want %d and %d", x, leftChild, rightChild,
				nodeAt(level-1, 2*block), nodeAt(level-1, 2*block+1))
		}
		if !(leftChild < x && x < rightChild) {
			t.Fatalf("children of %d, %d and %d, do not straddle it", x, leftChild, rightChild)
		}
		if leftChild.Level() != level-1 || rightChild.Level() != level-1 {
			t.Fatalf("children of %d are at levels %d and %d, want %d", x, leftChild.Level(), rightChild.Level(), level-1)
		}
	}

	leaf, leafErr := x.LeafIndex()
	if level == 0 {
		if leafErr != nil || uint64(leaf) != block {
			t.Fatalf("leaf index of %d: %d, %v, want %d", x, leaf, leafErr, block)
		}
		if leaf.NodeIndex() != x {
			t.Fatalf("leaf %d sits at node %d, want %d", leaf, leaf.NodeIndex(), x)
		}
	} else if !errors.Is(leafErr, ErrNodeIsParent) || leaf != 0 {
		t.Fatalf("leaf index of the parent %d: %d, %v", x, leaf, leafErr)
	}

	firstNode, lastNode := SubtreeSpan(x)
	firstLeaf, lastLeaf := SubtreeLeaves(x)
	wantFirstNode, wantLastNode, wantFirstLeaf, wantLastLeaf := subtreeSpanOracle(x)
	if firstNode != wantFirstNode || lastNode != wantLastNode {
		t.Fatalf("span of %d is [%d, %d], want [%d, %d]", x, firstNode, lastNode, wantFirstNode, wantLastNode)
	}
	if firstLeaf != wantFirstLeaf || lastLeaf != wantLastLeaf {
		t.Fatalf("node %d covers leaves %d..%d, want %d..%d", x, firstLeaf, lastLeaf, wantFirstLeaf, wantLastLeaf)
	}
	if firstNode > x || lastNode < x {
		t.Fatalf("span of %d is [%d, %d] and does not contain it", x, firstNode, lastNode)
	}

	if InSubtree(x, y) != inSubtreeOracle(x, y) {
		t.Fatalf("%d in the subtree of %d: %v, want %v", y, x, InSubtree(x, y), inSubtreeOracle(x, y))
	}
	if !InSubtree(x, x) {
		t.Fatalf("node %d is not in its own subtree", x)
	}

	ancestor := CommonAncestor(x, y)
	if ancestor != commonAncestorOracle(x, y) {
		t.Fatalf("common ancestor of %d and %d: %d, want %d", x, y, ancestor, commonAncestorOracle(x, y))
	}
	if CommonAncestor(y, x) != ancestor {
		t.Fatalf("common ancestor of %d and %d is %d one way and %d the other", x, y, ancestor, CommonAncestor(y, x))
	}
	if CommonAncestor(x, x) != x {
		t.Fatalf("common ancestor of %d with itself: %d", x, CommonAncestor(x, x))
	}

	// the common ancestor of two indices contains them both, which is the law
	// that ties the two relations together — and the one index no tree holds is
	// where the two documented answers part company, so it is pinned here rather
	// than carved out of the law.
	//
	// tree_math.go makes 0xFFFFFFFF its own common ancestor against anything,
	// because that relation is defined on indices and not inside a tree, and at
	// the same time makes it the head of nothing but itself, because a level-32
	// subtree is 2^33 slots and is not representable. so the ancestor of 0 and
	// 0xFFFFFFFF is an index that does not contain 0. that is a disagreement
	// between two deliberate answers at an index every caller in this package
	// range checks away before asking, and not a defect in either: the fuzzer
	// found it on the first run, which is what the two rows below are for.
	levelOfY, _ := nodeLevelAndBlock(y)
	outsideEveryTree := NodeIndex(0xFFFFFFFF)
	if level <= 31 && levelOfY <= 31 {
		if !InSubtree(ancestor, x) || !InSubtree(ancestor, y) {
			t.Fatalf("common ancestor %d of %d and %d does not contain both", ancestor, x, y)
		}
		return
	}
	if ancestor != outsideEveryTree {
		t.Fatalf("common ancestor of %d and %d, one of them the index no tree holds: %d, want %d", x, y, ancestor, outsideEveryTree)
	}
	if InSubtree(outsideEveryTree, x) != (x == outsideEveryTree) || InSubtree(outsideEveryTree, y) != (y == outsideEveryTree) {
		t.Fatalf("the index no tree holds heads more than itself: it holds %d and %d", x, y)
	}
}

// the laws that hold of a leaf count on its own, and of a raw word read as a
// node-array width and as a leaf index.
//
// the whole space is legal to hand over here too, and the refusals are the point
// of it: three of these functions answer a count for an argument no tree has and
// have to answer zero rather than something plausible, and the other three have
// to name the right sentinel.
func checkLeafCountLaws(t *testing.T, n LeafCount, probe uint32) {
	t.Helper()
	wantErr := leafCountRefusalOracle(n)
	depth := treeDepthOracle(n)

	if uint64(NodeWidth(n)) != nodeWidthOracle(n) {
		t.Fatalf("%d leaves: node width %d, want %d", n, NodeWidth(n), nodeWidthOracle(n))
	}
	if IsFullLeafCount(n) != (wantErr == nil) {
		t.Fatalf("%d leaves: full %v, want %v", n, IsFullLeafCount(n), wantErr == nil)
	}
	if TreeDepth(n) != depth {
		t.Fatalf("%d leaves: depth %d, want %d", n, TreeDepth(n), depth)
	}
	wantFullCount := LeafCount(0)
	if nodeWidthOracle(n) != 0 {
		wantFullCount = LeafCount(uint64(1) << depth)
	}
	if FullLeafCount(n) != wantFullCount {
		t.Fatalf("%d leaves: full leaf count %d, want %d", n, FullLeafCount(n), wantFullCount)
	}

	root, rootErr := Root(n)
	if !errors.Is(rootErr, wantErr) {
		t.Fatalf("%d leaves: root: %v, want %v", n, rootErr, wantErr)
	}
	if wantErr != nil {
		if root != 0 {
			t.Fatalf("%d leaves: refused root handed back %d", n, root)
		}
	} else if root != nodeAt(depth, 0) {
		t.Fatalf("%d leaves: root %d, want %d", n, root, nodeAt(depth, 0))
	}

	// the count after a doubling. zero extends to one leaf rather than refusing,
	// and the largest count there is refuses as out of range rather than wrapping
	// to zero, which is the pair of answers no other function here gives.
	extended, extendedErr := ExtendedLeafCount(n)
	wantExtended, wantExtendedErr := LeafCount(0), error(nil)
	switch {
	case n == 0:
		wantExtended = 1
	case uint64(n) > fuzzMaxLeafCount:
		wantExtendedErr = ErrLeafCountRange
	case wantErr != nil:
		wantExtendedErr = wantErr
	case uint64(n) == fuzzMaxLeafCount:
		wantExtendedErr = ErrLeafCountRange
	default:
		wantExtended = n * 2
	}
	if !errors.Is(extendedErr, wantExtendedErr) || extended != wantExtended {
		t.Fatalf("%d leaves: extended to %d, %v, want %d, %v", n, extended, extendedErr, wantExtended, wantExtendedErr)
	}

	truncated, truncatedErr := TruncatedLeafCount(LeafIndex(probe))
	if uint64(probe) >= fuzzMaxLeafCount {
		if !errors.Is(truncatedErr, ErrLeafOutOfRange) || truncated != 0 {
			t.Fatalf("truncated to hold leaf %d: %d, %v", probe, truncated, truncatedErr)
		}
	} else {
		wantTruncated := LeafCount(uint64(1) << treeDepthOracle(LeafCount(probe)+1))
		if truncatedErr != nil || truncated != wantTruncated {
			t.Fatalf("truncated to hold leaf %d: %d, %v, want %d", probe, truncated, truncatedErr, wantTruncated)
		}
	}

	countFromWidth, countFromWidthErr := LeafCountFromNodeWidth(probe)
	if probe == 0 || probe%2 == 0 {
		if !errors.Is(countFromWidthErr, ErrNodeWidthNotOdd) || countFromWidth != 0 {
			t.Fatalf("leaf count of a %d-node array: %d, %v", probe, countFromWidth, countFromWidthErr)
		}
	} else {
		wantCount := LeafCount((uint64(probe) + 1) / 2)
		if countFromWidthErr != nil || countFromWidth != wantCount {
			t.Fatalf("leaf count of a %d-node array: %d, %v, want %d", probe, countFromWidth, countFromWidthErr, wantCount)
		}
	}
	if wantErr == nil {
		roundTrip, err := LeafCountFromNodeWidth(NodeWidth(n))
		if err != nil || roundTrip != n {
			t.Fatalf("%d leaves: width %d reads back as %d, %v", n, NodeWidth(n), roundTrip, err)
		}
	}
}

// the laws that hold of a node inside a tree, and the two refusals that hold of
// one outside it.
func checkTreeLaws(t *testing.T, n LeafCount, x NodeIndex, y NodeIndex) {
	t.Helper()
	wantErr := leafCountRefusalOracle(n)
	width := nodeWidthOracle(n)

	// the class first, so that the two refusals are asserted of every function
	// that owes them rather than of whichever one a later row happens to call.
	for _, treeFunction := range treeFunctionCases {
		err, handedBackNothing := treeFunction.call(x, n)
		switch {
		case wantErr != nil:
			if !errors.Is(err, wantErr) {
				t.Fatalf("%s of %d in a tree of %d leaves: %v, want %v", treeFunction.name, x, n, err, wantErr)
			}
		case uint64(x) >= width:
			if !errors.Is(err, ErrNodeOutOfRange) {
				t.Fatalf("%s of %d, past the %d-node array of %d leaves: %v", treeFunction.name, x, width, n, err)
			}
		default:
			continue
		}
		if !handedBackNothing {
			t.Fatalf("%s of %d in a tree of %d leaves refused and handed back an answer", treeFunction.name, x, n)
		}
	}
	if wantErr != nil || uint64(x) >= width {
		return
	}

	depth := treeDepthOracle(n)
	level, block := nodeLevelAndBlock(x)
	root := nodeAt(depth, 0)

	parent, parentErr := Parent(x, n)
	sibling, siblingErr := Sibling(x, n)
	if x == root {
		if !errors.Is(parentErr, ErrRootHasNoParent) {
			t.Fatalf("%d leaves: parent of the root %d: %d, %v", n, x, parent, parentErr)
		}
		if !errors.Is(siblingErr, ErrRootHasNoSibling) {
			t.Fatalf("%d leaves: sibling of the root %d: %d, %v", n, x, sibling, siblingErr)
		}
		if level != depth {
			t.Fatalf("%d leaves: the root %d is at level %d, want %d", n, x, level, depth)
		}
	} else {
		if parentErr != nil || parent != nodeAt(level+1, block>>1) {
			t.Fatalf("%d leaves: parent of %d: %d, %v, want %d", n, x, parent, parentErr, nodeAt(level+1, block>>1))
		}
		if parent.Level() != level+1 {
			t.Fatalf("%d leaves: parent of %d is at level %d, want %d", n, x, parent.Level(), level+1)
		}
		if uint64(parent) >= width {
			t.Fatalf("%d leaves: parent of %d is %d, past the %d-node array", n, x, parent, width)
		}
		if siblingErr != nil || sibling != nodeAt(level, block^1) {
			t.Fatalf("%d leaves: sibling of %d: %d, %v, want %d", n, x, sibling, siblingErr, nodeAt(level, block^1))
		}
		// the sibling relation is its own inverse wherever it is defined, which
		// is the one law a sibling that answered the parent, or a child, still
		// looks plausible against until it is asked twice.
		back, backErr := Sibling(sibling, n)
		if backErr != nil || back != x {
			t.Fatalf("%d leaves: sibling of the sibling of %d: %d, %v", n, x, back, backErr)
		}
		if sibling.Level() != level {
			t.Fatalf("%d leaves: sibling of %d is at level %d, want %d", n, x, sibling.Level(), level)
		}
		if CommonAncestor(x, sibling) != parent {
			t.Fatalf("%d leaves: common ancestor of %d and its sibling %d: %d, want %d", n, x, sibling, CommonAncestor(x, sibling), parent)
		}
		// the child a parent names is the node itself, asked from above so that
		// a parent and a child that agree with each other but not with the
		// layout are both caught rather than neither.
		leftChild, err := Left(parent)
		if err != nil {
			t.Fatalf("%d leaves: left of %d: %v", n, parent, err)
		}
		rightChild, err := Right(parent)
		if err != nil {
			t.Fatalf("%d leaves: right of %d: %v", n, parent, err)
		}
		if leftChild != x && rightChild != x {
			t.Fatalf("%d leaves: the children of the parent of %d are %d and %d, neither of them it", n, x, leftChild, rightChild)
		}
		if leftChild != x && leftChild != sibling {
			t.Fatalf("%d leaves: the children of the parent of %d are %d and %d, and its sibling is %d", n, x, leftChild, rightChild, sibling)
		}
	}

	wantPath, wantCopath := pathOracle(level, block, depth)
	pathNodes, pathErr := DirectPath(x, n)
	if pathErr != nil || pathNodes == nil {
		t.Fatalf("%d leaves: direct path of %d: %v, %v", n, x, pathNodes, pathErr)
	}
	if !sameNodeIndexes(pathNodes, wantPath) {
		t.Fatalf("%d leaves: direct path of %d: %v, want %v", n, x, pathNodes, wantPath)
	}
	if uint32(len(pathNodes)) != depth-level {
		t.Fatalf("%d leaves: direct path of %d has %d nodes, want %d", n, x, len(pathNodes), depth-level)
	}
	previousLevel := level
	for _, pathNode := range pathNodes {
		if pathNode.Level() != previousLevel+1 {
			t.Fatalf("%d leaves: direct path of %d does not ascend one level a step: %v", n, x, pathNodes)
		}
		previousLevel = pathNode.Level()
		if uint64(pathNode) >= width {
			t.Fatalf("%d leaves: direct path of %d holds %d, past the %d-node array", n, x, pathNode, width)
		}
		if !InSubtree(pathNode, x) {
			t.Fatalf("%d leaves: %d is on the direct path of %d and does not contain it", n, pathNode, x)
		}
	}
	// the path ends at the root, and the root's own path is the empty one. this
	// is the law a path that stopped one short of the top still satisfies
	// everywhere else: every node on it is a real ancestor and the levels still
	// ascend.
	if len(pathNodes) == 0 {
		if x != root {
			t.Fatalf("%d leaves: direct path of %d is empty and it is not the root %d", n, x, root)
		}
	} else if pathNodes[len(pathNodes)-1] != root {
		t.Fatalf("%d leaves: direct path of %d ends at %d, want the root %d", n, x, pathNodes[len(pathNodes)-1], root)
	}

	copathNodes, copathErr := Copath(x, n)
	if copathErr != nil || copathNodes == nil {
		t.Fatalf("%d leaves: copath of %d: %v, %v", n, x, copathNodes, copathErr)
	}
	if !sameNodeIndexes(copathNodes, wantCopath) {
		t.Fatalf("%d leaves: copath of %d: %v, want %v", n, x, copathNodes, wantCopath)
	}
	if len(copathNodes) != len(pathNodes) {
		t.Fatalf("%d leaves: copath of %d has %d nodes and its direct path has %d", n, x, len(copathNodes), len(pathNodes))
	}
	for i, copathNode := range copathNodes {
		if copathNode == x {
			t.Fatalf("%d leaves: copath of %d holds the node itself", n, x)
		}
		for _, pathNode := range pathNodes {
			if copathNode == pathNode {
				t.Fatalf("%d leaves: copath of %d meets its direct path at %d", n, x, copathNode)
			}
		}
		if InSubtree(copathNode, x) {
			t.Fatalf("%d leaves: copath node %d contains %d", n, copathNode, x)
		}
		copathParent, err := Parent(copathNode, n)
		if err != nil || copathParent != pathNodes[i] {
			t.Fatalf("%d leaves: copath node %d has parent %d, %v, want the direct-path node %d", n, copathNode, copathParent, err, pathNodes[i])
		}
	}

	// a pair of nodes of one tree: their common ancestor is a node of that same
	// tree and holds them both. the relation takes no leaf count, so this is the
	// only place the count is what makes the law sayable.
	if uint64(y) < width {
		ancestor := CommonAncestor(x, y)
		if uint64(ancestor) >= width {
			t.Fatalf("%d leaves: common ancestor of %d and %d is %d, past the %d-node array", n, x, y, ancestor, width)
		}
		if !InSubtree(ancestor, x) || !InSubtree(ancestor, y) {
			t.Fatalf("%d leaves: common ancestor %d of %d and %d does not contain both", n, ancestor, x, y)
		}
	}
}

// the two rules that read node contents, over a shape the fuzzer names.
//
// the leaf count and the node index reach these through a NodeShape rather than
// as arguments, so their refusals are ordered — a shape that is no tree is
// refused as that whatever node it was asked about — and the order is asserted
// here because a caller switching on the sentinel depends on it.
func checkShapeLaws(t *testing.T, n LeafCount, x NodeIndex, leaf LeafIndex, pattern uint32) {
	t.Helper()
	wantErr := leafCountRefusalOracle(n)
	width := nodeWidthOracle(n)

	shape := populatedShape(n)
	if wantErr == nil && treeDepthOracle(n) <= fuzzBlankShapeDepth {
		shape = fuzzShape(n, pattern)
	}

	resolvedNodes, resolveErr := Resolution(shape, x)
	switch {
	case wantErr != nil:
		if !errors.Is(resolveErr, wantErr) || resolvedNodes != nil {
			t.Fatalf("resolution of %d under a shape of %d leaves: %v, %v, want %v", x, n, resolvedNodes, resolveErr, wantErr)
		}
	case uint64(x) >= width:
		if !errors.Is(resolveErr, ErrNodeOutOfRange) || resolvedNodes != nil {
			t.Fatalf("%d leaves: resolution of %d, past the %d-node array: %v, %v", n, x, width, resolvedNodes, resolveErr)
		}
	default:
		wantResolved, wantResolveErr := resolutionOracle(shape, x, n)
		if wantResolveErr != nil {
			if !errors.Is(resolveErr, wantResolveErr) || resolvedNodes != nil {
				t.Fatalf("%d leaves: resolution of %d under a shape carrying a leaf past the end: %v, %v, want %v",
					n, x, resolvedNodes, resolveErr, wantResolveErr)
			}
			break
		}
		if resolveErr != nil || resolvedNodes == nil {
			t.Fatalf("%d leaves: resolution of %d: %v, %v", n, x, resolvedNodes, resolveErr)
		}
		if !sameNodeIndexes(resolvedNodes, wantResolved) {
			t.Fatalf("%d leaves: resolution of %d: %v, want %v", n, x, resolvedNodes, wantResolved)
		}
	}

	pathSteps, pathErr := FilteredDirectPath(shape, leaf)
	switch {
	case wantErr != nil:
		if !errors.Is(pathErr, wantErr) || pathSteps != nil {
			t.Fatalf("filtered direct path of leaf %d under a shape of %d leaves: %v, %v, want %v", leaf, n, pathSteps, pathErr, wantErr)
		}
	case LeafCount(leaf) >= n:
		if !errors.Is(pathErr, ErrLeafOutOfRange) || pathSteps != nil {
			t.Fatalf("%d leaves: filtered direct path of leaf %d, past the last one: %v, %v", n, leaf, pathSteps, pathErr)
		}
	default:
		wantSteps, wantStepsErr := filteredDirectPathOracle(shape, leaf, n)
		if wantStepsErr != nil {
			if !errors.Is(pathErr, wantStepsErr) || pathSteps != nil {
				t.Fatalf("%d leaves: filtered direct path of leaf %d under a shape carrying a leaf past the end: %v, %v, want %v",
					n, leaf, pathSteps, pathErr, wantStepsErr)
			}
			break
		}
		if pathErr != nil || pathSteps == nil {
			t.Fatalf("%d leaves: filtered direct path of leaf %d: %v, %v", n, leaf, pathSteps, pathErr)
		}
		if len(pathSteps) != len(wantSteps) {
			t.Fatalf("%d leaves: filtered direct path of leaf %d has %d steps, want %d", n, leaf, len(pathSteps), len(wantSteps))
		}
		for i, pathStep := range pathSteps {
			if pathStep != wantSteps[i] {
				t.Fatalf("%d leaves: filtered direct path of leaf %d step %d is {%d, %d}, want {%d, %d}",
					n, leaf, i, pathStep.Node, pathStep.CopathChild, wantSteps[i].Node, wantSteps[i].CopathChild)
			}
		}
	}
}

// the leaf counts a seed is built for: the ladder the vendored mlswg tree-math
// vectors publish, read off the corpus, and the boundaries of the count space,
// computed from the width of the type.
//
// read and not listed. the ladder is ten entries today and the corpus is the
// thing that says so, and a file that typed those ten out would keep asserting
// them after a bump that changed the corpus — which is the shape of gap this
// project has closed eleven times. the loader raises the corpus count itself, so
// a short or absent corpus is a failure here and not an empty seed set.
func treeMathSeedLeafCounts(t testing.TB) []uint32 {
	t.Helper()
	counts := map[uint32]bool{}
	for _, vector := range loadTreeMathVectors(t) {
		counts[vector.NLeaves] = true
	}
	for _, boundary := range treeMathSeedBoundaries() {
		counts[boundary] = true
	}
	return sortedWords(counts)
}

// the boundaries of the leaf-count space.
//
// every power of two the type holds, since those are the only counts a tree can
// have; each one's two neighbours at the small end and at the large end, since a
// count one either side of a power is the pair of inputs that separates a range
// test from an off-by-one in it; and the end of the type, which is past every
// tree and past MaxLeafCount both. the exponents are walked rather than named so
// that the set moves with the width of the type and not with this comment.
func treeMathSeedBoundaries() []uint32 {
	boundaries := map[uint32]bool{0: true, 0xFFFFFFFF: true, 0xFFFFFFFE: true}
	for exponent := uint32(0); exponent <= 31; exponent += 1 {
		power := uint32(1) << exponent
		boundaries[power] = true
		if exponent <= 5 || exponent >= 30 {
			boundaries[power-1] = true
			boundaries[power+1] = true
		}
	}
	return sortedWords(boundaries)
}

// the node indices a seed asks about in a tree of the given leaf count: every
// index of an array small enough to write down, and otherwise the two ends of
// the array, the root, the ends of the type and the first few slots.
//
// the out-of-range probes are the point. a seed that only ever named a node some
// tree holds would leave the whole refusing half of these signatures to the
// fuzzer to stumble into, and the seeds are what runs on every ordinary test
// invocation.
func treeMathSeedNodes(n uint32) []uint32 {
	nodes := map[uint32]bool{0: true, 1: true, 2: true, 0x80000000: true, 0xFFFFFFFE: true, 0xFFFFFFFF: true}
	width := nodeWidthOracle(LeafCount(n))
	if width != 0 {
		if width <= 63 {
			for node := uint64(0); node < width; node += 1 {
				nodes[uint32(node)] = true
			}
		}
		nodes[uint32(width-1)] = true
		nodes[uint32(width)] = true
		nodes[uint32(width/2)] = true
	}
	return sortedWords(nodes)
}

// a set of raw words in order, so a seed corpus does not depend on map iteration
// order and a failing seed is the same seed on the next run.
func sortedWords(words map[uint32]bool) []uint32 {
	sorted := make([]uint32, 0, len(words))
	for word := range words {
		sorted = append(sorted, word)
	}
	sort.Slice(sorted, func(i int, j int) bool { return sorted[i] < sorted[j] })
	return sorted
}

// the shape words a seed is built for: nothing blank, everything blank and
// carrying a list that runs past the end of the tree, and an alternating pattern
// carrying a well-formed list. three words is not a sample of the 2^32 there
// are; it is the three the laws behave differently under, and the fuzzer walks
// out from them.
func treeMathSeedPatterns() []uint32 {
	return []uint32{0x00000000, 0xFFFFFFFF, 0xAAAAAAA9}
}

// the second word of a seed, read by the laws as another node of the same tree
// and as the leaf a filtered direct path is asked about: the first leaf, the
// last one, and one past the end of the type so that the refusing half is seeded
// there too.
func treeMathSeedOthers(n uint32) []uint32 {
	others := map[uint32]bool{0: true, 0xFFFFFFFF: true}
	if n != 0 {
		others[n-1] = true
	}
	return sortedWords(others)
}

func seedTreeMathCorpus(f *testing.F) {
	f.Helper()
	for _, leafCount := range treeMathSeedLeafCounts(f) {
		for _, node := range treeMathSeedNodes(leafCount) {
			for _, other := range treeMathSeedOthers(leafCount) {
				for _, pattern := range treeMathSeedPatterns() {
					f.Add(leafCount, node, other, pattern)
				}
			}
		}
	}
}

// the target.
//
// four raw words, none of them interpreted: a leaf count, a node index, a second
// word read both as another node of the same tree and as a leaf index, and a
// word naming a shape. the laws decide which inputs are answers and which are
// refusals, so no input is rejected before the package under test has seen it.
func FuzzTreeMath(f *testing.F) {
	seedTreeMathCorpus(f)
	f.Fuzz(func(t *testing.T, rawLeafCount uint32, rawNode uint32, rawOther uint32, rawPattern uint32) {
		leafCount := LeafCount(rawLeafCount)
		node := NodeIndex(rawNode)
		other := NodeIndex(rawOther)

		checkNodeLawsOutsideAnyTree(t, node, other)
		checkLeafCountLaws(t, leafCount, rawOther)
		checkTreeLaws(t, leafCount, node, other)
		checkShapeLaws(t, leafCount, node, LeafIndex(rawOther), rawPattern)
	})
}

// this file and the file it is a target for, named so a failing scan can say
// where the code it is asking about lives.
const (
	treeMathSourceFile = "tree_math.go"
	treeMathFuzzFile   = "tree_math_fuzz_test.go"
)

// the exported functions one parsed file declares, split by whether they hang
// off a receiver.
//
// the split is what makes the scan below say anything. a conversion to a named
// type is a call of an identifier, so NodeIndex(x) and LeafIndex(x) are calls of
// the two names that are also methods of this package, and a scan that pooled
// the two kinds would report the method LeafIndex.NodeIndex as exercised by
// every conversion in the file. asked as a selector it is the method and nothing
// else.
func exportedFunctionsOf(parsed *ast.File) (functions map[string]bool, methods map[string]bool) {
	functions, methods = map[string]bool{}, map[string]bool{}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || !function.Name.IsExported() {
			continue
		}
		if function.Recv == nil {
			functions[function.Name.Name] = true
			continue
		}
		methods[function.Name.Name] = true
	}
	return functions, methods
}

// the names one parsed file calls, split the same way: a bare identifier and the
// selected half of a selector.
func calledNamesOf(parsed *ast.File) (identCalls map[string]bool, selectorCalls map[string]bool) {
	identCalls, selectorCalls = map[string]bool{}, map[string]bool{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch called := call.Fun.(type) {
		case *ast.Ident:
			identCalls[called.Name] = true
		case *ast.SelectorExpr:
			selectorCalls[called.Sel.Name] = true
		}
		return true
	})
	return identCalls, selectorCalls
}

// the exported functions of one parsed file that take a node index and a leaf
// count and answer an error.
//
// this is the class the two refusals in checkTreeLaws are owed by: a leaf count
// that is no tree, refused as such whatever the node, and a node past the end of
// the array, refused as that. a function of this shape that answered either of
// them with a plausible index would be handing its caller a node of some other
// tree, which is the failure the class exists to make unmissable.
func nodeAndCountFunctionsOf(parsed *ast.File) map[string]bool {
	functions := map[string]bool{}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv != nil || !function.Name.IsExported() {
			continue
		}
		if !parameterTypesAre(function.Type.Params, "NodeIndex", "LeafCount") {
			continue
		}
		results := function.Type.Results
		if results == nil || len(results.List) == 0 {
			continue
		}
		if !isNamedType(results.List[len(results.List)-1].Type, "error") {
			continue
		}
		functions[function.Name.Name] = true
	}
	return functions
}

// whether a parameter list is exactly the named types in order, counting a
// grouped declaration as the parameters it declares rather than as one.
func parameterTypesAre(parameters *ast.FieldList, want ...string) bool {
	if parameters == nil {
		return false
	}
	declared := []ast.Expr{}
	for _, field := range parameters.List {
		repeats := len(field.Names)
		if repeats == 0 {
			repeats = 1
		}
		for i := 0; i < repeats; i += 1 {
			declared = append(declared, field.Type)
		}
	}
	if len(declared) != len(want) {
		return false
	}
	for i, wanted := range want {
		if !isNamedType(declared[i], wanted) {
			return false
		}
	}
	return true
}

func isNamedType(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

// one file of this package, parsed.
//
// an unreadable or unparsable file is fatal rather than an empty answer, for the
// reason parsePackageSources gives about its own glob: every question asked of a
// scan like this is answered "found nothing" somewhere, and a scan that read no
// source at all agrees with any package there is.
func parseSourceFile(t *testing.T, fileSet *token.FileSet, name string) *ast.File {
	t.Helper()
	parsed, err := parser.ParseFile(fileSet, name, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return parsed
}

// a package holding both shapes each scan above has to tell apart. it is parsed
// and never compiled, so the names in it are the scan's own rather than this
// package's.
//
// the controls are not decoration. every claim these scans make is of the form
// "this name is called", and the way that claim goes wrong is by being true of
// everything: a scan that pooled identifier calls with selector calls would
// report the method NodeIndex as called by every conversion, and a class that
// read a grouped parameter list as one parameter would report every function
// here as taking the wrong number of them and so demand nothing of anybody.
const fuzzScanControlSource = `package mls

func Called(x NodeIndex, n LeafCount) error { return nil }

func NeverCalled(x NodeIndex, n LeafCount) error { return nil }

func CalledGrouped(x, y NodeIndex) error { return nil }

func TakesOnlyACount(n LeafCount) (NodeIndex, error) { return 0, nil }

func TakesThePairAndAnswersNoError(x NodeIndex, n LeafCount) bool { return false }

func unexportedTakingThePair(x NodeIndex, n LeafCount) error { return nil }

func (self NodeIndex) CalledMethod() bool { return false }

func (self NodeIndex) NeverCalledMethod() bool { return false }

func control() {
	_ = Called(0, 1)
	_ = CalledGrouped(0, 1)
	_, _ = TakesOnlyACount(1)
	_ = TakesThePairAndAnswersNoError(0, 1)
	_ = NodeIndex(0).CalledMethod()
}
`

// every exported function of tree_math.go is asked about by this file.
//
// the class is read out of the source rather than listed here, so a function
// added to that file and never fuzzed is a failure in the same commit. a fuzz
// target that named its own coverage would be a list that understated the API
// the moment the API grew, and on this project a hand-written class has
// understated the real one every single time.
func TestTreeMathFuzzAsksAboutEveryExportedFunction(t *testing.T) {
	fileSet := token.NewFileSet()

	// the controls first: the scans are trusted about this package only after
	// they have separated a called name from an uncalled one, and a method from
	// a conversion, in a source whose answer is known.
	controlSet := token.NewFileSet()
	control, err := parser.ParseFile(controlSet, "control.go", fuzzScanControlSource, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse the control source: %v", err)
	}
	controlFunctions, controlMethods := exportedFunctionsOf(control)
	controlIdentCalls, controlSelectorCalls := calledNamesOf(control)
	controlCases := []struct {
		label string
		got   bool
		want  bool
	}{
		{label: "an exported function is a function", got: controlFunctions["Called"], want: true},
		{label: "an exported method is not a function", got: controlFunctions["CalledMethod"], want: false},
		{label: "an exported method is a method", got: controlMethods["CalledMethod"], want: true},
		{label: "an exported function is not a method", got: controlFunctions["Called"] && controlMethods["Called"], want: false},
		{label: "a called function is called", got: controlIdentCalls["Called"], want: true},
		{label: "an uncalled function is not", got: controlIdentCalls["NeverCalled"], want: false},
		{label: "a called method is called as a selector", got: controlSelectorCalls["CalledMethod"], want: true},
		{label: "an uncalled method is not", got: controlSelectorCalls["NeverCalledMethod"], want: false},
		{label: "a conversion is not a call of the method of that name", got: controlSelectorCalls["NodeIndex"], want: false},
	}
	for _, c := range controlCases {
		if c.got != c.want {
			t.Fatalf("control: %s: %t, want %t: the scan is broken, not the package", c.label, c.got, c.want)
		}
	}

	exportedFunctions, exportedMethods := exportedFunctionsOf(parseSourceFile(t, fileSet, treeMathSourceFile))
	if len(exportedFunctions) == 0 || len(exportedMethods) == 0 {
		t.Fatalf("%s declares %d exported functions and %d exported methods: the scan is broken, not the package",
			treeMathSourceFile, len(exportedFunctions), len(exportedMethods))
	}
	identCalls, selectorCalls := calledNamesOf(parseSourceFile(t, fileSet, treeMathFuzzFile))

	missing := []string{}
	for _, name := range sortedNames(exportedFunctions) {
		if !identCalls[name] {
			missing = append(missing, name)
		}
	}
	for _, name := range sortedNames(exportedMethods) {
		if !selectorCalls[name] {
			missing = append(missing, name+" (a method, so call it on a value)")
		}
	}
	if len(missing) != 0 {
		t.Fatalf("%s exports %d functions and %d methods and %s never calls %v.\n"+
			"a fuzz target that leaves one of them out is a target for a smaller package than the one that ships:\n"+
			"give each of them a law in this file, or move it out of %s.",
			treeMathSourceFile, len(exportedFunctions), len(exportedMethods), treeMathFuzzFile, missing, treeMathSourceFile)
	}
}

// the refusal table is exactly the class of functions that owe those refusals.
//
// derived and compared both ways. a table with a name the source no longer
// declares asserts nothing, and a source with a function the table does not name
// is a function whose out-of-range behaviour nobody checks — which is the half
// of a signature this whole file exists for.
func TestTreeMathFuzzRefusalTableIsEveryNodeAndCountFunction(t *testing.T) {
	controlSet := token.NewFileSet()
	control, err := parser.ParseFile(controlSet, "control.go", fuzzScanControlSource, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse the control source: %v", err)
	}
	controlClass := nodeAndCountFunctionsOf(control)
	controlCases := []struct {
		label string
		got   bool
		want  bool
	}{
		{label: "the pair and an error is in the class", got: controlClass["Called"], want: true},
		{label: "being uncalled does not leave the class", got: controlClass["NeverCalled"], want: true},
		{label: "a count alone is not in the class", got: controlClass["TakesOnlyACount"], want: false},
		{label: "the pair without an error is not", got: controlClass["TakesThePairAndAnswersNoError"], want: false},
		{label: "an unexported function is not", got: controlClass["unexportedTakingThePair"], want: false},
		{label: "two node indices are not the pair", got: controlClass["CalledGrouped"], want: false},
	}
	for _, c := range controlCases {
		if c.got != c.want {
			t.Fatalf("control: %s: %t, want %t: the scan is broken, not the package", c.label, c.got, c.want)
		}
	}

	fileSet := token.NewFileSet()
	declared := nodeAndCountFunctionsOf(parseSourceFile(t, fileSet, treeMathSourceFile))
	if len(declared) == 0 {
		t.Fatalf("%s declares no exported function taking a node index and a leaf count: the scan is broken, not the package", treeMathSourceFile)
	}
	tabled := map[string]bool{}
	for _, treeFunction := range treeFunctionCases {
		tabled[treeFunction.name] = true
	}

	for _, name := range sortedNames(declared) {
		if !tabled[name] {
			t.Fatalf("%s exports %s(x NodeIndex, n LeafCount) and treeFunctionCases does not name it.\n"+
				"every function of that shape owes the same two refusals — the leaf count that is no tree, and the\n"+
				"node past the end of the array — and this table is what asks all of them at once. add it.",
				treeMathSourceFile, name)
		}
	}
	for _, name := range sortedNames(tabled) {
		if !declared[name] {
			t.Fatalf("treeFunctionCases names %s and %s no longer exports it with that signature: the row asserts nothing", name, treeMathSourceFile)
		}
	}
	if len(tabled) != len(declared) {
		t.Fatalf("treeFunctionCases holds %d rows for a class of %d: a name is tabled twice", len(tabled), len(declared))
	}
}

// the seed corpus covers the published ladder, the boundaries of the count
// space, and both halves of every signature.
//
// the seeds are what runs on an ordinary go test invocation, so what they reach
// is what this file asserts when nobody passes -fuzz. the four classes below are
// counted rather than assumed: a seed builder that quietly stopped producing
// out-of-range nodes would leave every refusal in this file unasked while the
// test count went up.
func TestTreeMathFuzzSeedCorpus(t *testing.T) {
	if uint64(MaxLeafCount) != fuzzMaxLeafCount {
		t.Fatalf("MaxLeafCount is %d and this file works from %d: the oracles here are for a different tree", MaxLeafCount, fuzzMaxLeafCount)
	}

	seedCounts := treeMathSeedLeafCounts(t)
	seeded := map[uint32]bool{}
	for _, count := range seedCounts {
		seeded[count] = true
	}
	for _, vector := range loadTreeMathVectors(t) {
		if !seeded[vector.NLeaves] {
			t.Fatalf("the published ladder holds %d leaves and no seed does", vector.NLeaves)
		}
	}
	for _, boundary := range treeMathSeedBoundaries() {
		if !seeded[boundary] {
			t.Fatalf("the boundary %d is not seeded", boundary)
		}
	}

	seeds, treesReached, nodesInTree, nodesOutOfTree, countsThatAreNoTree := 0, map[uint32]bool{}, 0, 0, 0
	for _, leafCount := range seedCounts {
		refusal := leafCountRefusalOracle(LeafCount(leafCount))
		width := nodeWidthOracle(LeafCount(leafCount))
		for _, node := range treeMathSeedNodes(leafCount) {
			for range treeMathSeedOthers(leafCount) {
				for range treeMathSeedPatterns() {
					seeds += 1
					switch {
					case refusal != nil:
						countsThatAreNoTree += 1
					case uint64(node) >= width:
						nodesOutOfTree += 1
					default:
						nodesInTree += 1
						treesReached[leafCount] = true
					}
				}
			}
		}
	}

	// pinned rather than recomputed from the sets above, which would agree with
	// any seed builder whatsoever. the numbers move when the corpus or the
	// boundary derivation moves, and moving them is the commit that says so.
	countCases := []struct {
		label string
		got   int
		want  int
	}{
		{label: "seeds", got: seeds, want: 5643},
		{label: "seeds naming a node of a real tree", got: nodesInTree, want: 2256},
		{label: "seeds naming a node past the end of a real tree", got: nodesOutOfTree, want: 1119},
		{label: "seeds naming a leaf count that is no tree", got: countsThatAreNoTree, want: 2268},
		{label: "trees a seed names a node of", got: len(treesReached), want: 32},
	}
	for _, c := range countCases {
		if c.got != c.want {
			t.Errorf("seeded %s: %d, want %d", c.label, c.got, c.want)
		}
	}
}

// a set of names in order, so a failure names the same one on every run.
func sortedNames(names map[string]bool) []string {
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	return sorted
}
