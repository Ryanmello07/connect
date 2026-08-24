// the RFC 9420 tree-math test-vector family, family 1 of the sixteen the
// validation and interop harness plan vendors into testdata/vectors.
//
// the entries are plain integers, so this file decodes them itself, but the
// bytes come from the shared loader: one reader of the vendored corpus, one
// place a vendoring mistake surfaces. families whose fields are hex-encoded
// also call MustHex; this one has no hex field.
package mls

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// the directory the validation and interop harness plan vendors the mlswg
// corpus into, named relative to this package so the loader is independent of
// where the test binary is invoked from.
const vectorDir = "testdata/vectors"

// LoadVectorFile reads one vendored mlswg corpus file and splits it into its
// top-level entries without decoding them, so each family owns its own entry
// type while exactly one function reads the corpus off disk.
//
// This is a temporary in-package stand-in. The validation and interop harness
// plan owns this symbol and declares it in mls/vectors_test.go; that file does
// not exist yet, and family 1 cannot wait for it. When it lands the duplicate
// declaration is a build failure by design: delete this one, keep the callers.
//
// It fails the test rather than returning an error because every failure it can
// report — the corpus is absent, the corpus is not a JSON array — is a broken
// checkout rather than a condition any caller could handle.
func LoadVectorFile(t *testing.T, file string) []json.RawMessage {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(filepath.FromSlash(vectorDir), file))
	if err != nil {
		t.Fatalf("read %s/%s: %v", vectorDir, file, err)
	}
	entries := []json.RawMessage{}
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("parse %s/%s as a vector array: %v", vectorDir, file, err)
	}
	return entries
}

// one entry of the family. every relation column is optional: null means the
// function is undefined at that node, which is as much a part of the vector as
// an index is.
type treeMathVector struct {
	NLeaves uint32    `json:"n_leaves"`
	NNodes  uint32    `json:"n_nodes"`
	Root    uint32    `json:"root"`
	Left    []*uint32 `json:"left"`
	Right   []*uint32 `json:"right"`
	Parent  []*uint32 `json:"parent"`
	Sibling []*uint32 `json:"sibling"`
}

// the family file, named relative to testdata/vectors exactly as
// VectorFamily.File is.
const treeMathVectorFile = "tree-math.json"

// the entry count upstream publishes for this family, one per leaf count on
// the ladder. It lives here rather than inside a single test because the
// loader below checks it on every call.
const treeMathVectorCount = 10

// decodes the vendored family through the shared loader, failing the test
// rather than returning an error so every caller is a one-liner.
//
// The count is checked here, in the loader, rather than only in the corpus
// tripwire below. A loader that silently returns nothing passes every caller
// that ranges over its result, and plan p1 shipped exactly that shape before
// needing the same guard. It matters here because every command the plan
// prescribes for the tasks that follow names one test with -run, so none of
// them runs the tripwire: with the guard only there, emptying the corpus
// leaves those vector tests passing over zero entries and asserting nothing.
func loadTreeMathVectors(t *testing.T) []treeMathVector {
	t.Helper()
	rawEntries := LoadVectorFile(t, treeMathVectorFile)
	vectors := make([]treeMathVector, 0, len(rawEntries))
	for i, rawEntry := range rawEntries {
		var vector treeMathVector
		if err := json.Unmarshal(rawEntry, &vector); err != nil {
			t.Fatalf("decode %s entry %d: %v", treeMathVectorFile, i, err)
		}
		vectors = append(vectors, vector)
	}
	// checked on what is handed back, not on what was read. guarding the input
	// count instead looks equivalent and is not: it passes for a loader whose
	// body is later reduced to returning nil, which is the exact regression this
	// guard exists to catch. the first version of this check made that mistake
	// and survived the mutation it was written for.
	if len(vectors) != treeMathVectorCount {
		t.Fatalf("returning %d entries for %s, want %d: a vector test over a short corpus asserts nothing", len(vectors), treeMathVectorFile, treeMathVectorCount)
	}
	return vectors
}

// a tripwire on the corpus itself. the mlswg format is not versioned in the
// file, so a field added upstream would otherwise be vendored and silently
// ignored, and a bump that dropped entries would shrink the gate without
// failing anything.
func TestTreeMathVectorFileShape(t *testing.T) {
	rawEntries := LoadVectorFile(t, treeMathVectorFile)
	if len(rawEntries) != 10 {
		t.Fatalf("entries: %d, want 10", len(rawEntries))
	}

	wantFields := []string{"n_leaves", "n_nodes", "root", "left", "right", "parent", "sibling"}
	for i, rawEntry := range rawEntries {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(rawEntry, &entry); err != nil {
			t.Fatalf("decode %s entry %d: %v", treeMathVectorFile, i, err)
		}
		if len(entry) != len(wantFields) {
			t.Fatalf("entry %d: %d fields, want %d — the upstream format changed and the runner must be extended", i, len(entry), len(wantFields))
		}
		for _, field := range wantFields {
			if _, ok := entry[field]; !ok {
				t.Fatalf("entry %d: missing field %s", i, field)
			}
		}
	}

	vectors := loadTreeMathVectors(t)
	wantLeaves := []uint32{1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
	totalNodes := uint32(0)
	for i, v := range vectors {
		if v.NLeaves != wantLeaves[i] {
			t.Fatalf("entry %d: n_leaves %d, want %d", i, v.NLeaves, wantLeaves[i])
		}
		// kept for the reader, not for coverage: the row above pins n_leaves to
		// an exact power of two, so nothing that reaches here can fail this. it
		// states the property the ladder exists to express, and goes live the
		// day the ladder is relaxed to a range.
		if v.NLeaves&(v.NLeaves-1) != 0 {
			t.Fatalf("entry %d: n_leaves %d is not a power of two", i, v.NLeaves)
		}
		// n_nodes is otherwise pinned only in aggregate, by the family total
		// below, and self-consistently, by the column lengths. neither notices
		// node counts moved from one entry to another, so the relation that
		// defines a full tree is asserted per entry.
		if v.NNodes != 2*v.NLeaves-1 {
			t.Fatalf("entry %d: n_nodes %d, want 2*%d-1 = %d", i, v.NNodes, v.NLeaves, 2*v.NLeaves-1)
		}
		columns := map[string]int{
			"left":    len(v.Left),
			"right":   len(v.Right),
			"parent":  len(v.Parent),
			"sibling": len(v.Sibling),
		}
		for name, length := range columns {
			if uint32(length) != v.NNodes {
				t.Fatalf("entry %d: %s has %d entries, want n_nodes %d", i, name, length, v.NNodes)
			}
		}
		totalNodes += v.NNodes
	}
	// do not delete this line. it is the only caller-side statement of the
	// corpus size, and it catches something the loader's own guard structurally
	// cannot: a loader whose body still builds ten entries but hands back
	// something else. that guard runs before the return, so a return statement
	// reduced to nil walks straight past it, and the sum here is what fails.
	// measured, not assumed - with this line removed, that mutation passes the
	// whole file while the loader's guard is still in place.
	//
	// an earlier revision of this comment said the opposite: "kept for the
	// reader rather than for coverage", reasoning that reaching here meant all
	// ten entries had matched. reaching here means the ladder walked whatever
	// was returned, however much that was. a reader who believed the comment
	// would have deleted the one assertion holding that down.
	if totalNodes != 2036 {
		t.Fatalf("nodes across the family: %d, want 2036", totalNodes)
	}
}

func TestTreeMathVectorRoot(t *testing.T) {
	vectors := loadTreeMathVectors(t)
	for _, v := range vectors {
		leafCount := LeafCount(v.NLeaves)
		if got := NodeWidth(leafCount); got != v.NNodes {
			t.Errorf("n_leaves %d: node width %d, want %d", v.NLeaves, got, v.NNodes)
		}
		root, err := Root(leafCount)
		if err != nil {
			t.Errorf("n_leaves %d: root: %v", v.NLeaves, err)
			continue
		}
		if uint32(root) != v.Root {
			t.Errorf("n_leaves %d: root %d, want %d", v.NLeaves, root, v.Root)
		}
	}

	// a leaf count that is not a power of two is refused rather than answered
	// for the enclosing full tree, which is what the appendix C pseudocode
	// silently does. the ladder above is powers of two only, so these three are
	// the whole of what the runner says about a count no tree can have.
	//
	// the index is read back alongside every refusal, which the rest of this
	// package already does and the plan's form of these three checks did not.
	// measured: a version that hands back the enclosing full tree's root and the
	// error together passes when the value is discarded, and a caller reading
	// only the value then gets node 3, a real node of the four-leaf tree.
	refusalCases := []struct {
		leafCount LeafCount
		err       error
	}{
		{leafCount: 3, err: ErrLeafCountNotFull},
		{leafCount: 0, err: ErrLeafCountRange},
		{leafCount: MaxLeafCount + 1, err: ErrLeafCountRange},
	}
	for _, c := range refusalCases {
		root, err := Root(c.leafCount)
		if !errors.Is(err, c.err) {
			t.Errorf("root of %d leaves: %v, want %v", c.leafCount, err, c.err)
		}
		if root != 0 {
			t.Errorf("root of %d leaves: %d alongside the refusal, want 0", c.leafCount, root)
		}
	}

	root, err := Root(MaxLeafCount)
	if err != nil {
		t.Fatalf("root of MaxLeafCount: %v", err)
	}
	if root != NodeIndex(1<<31)-1 {
		t.Errorf("root of MaxLeafCount: %d, want %d", root, NodeIndex(1<<31)-1)
	}
}

// asserts one relation column of one node against one function and reports
// which of the two arms it confirmed, so the caller can prove it exercised
// both.
//
// all four relation columns carry identical rules and differ only in which
// sentinel marks the undefined arm, so the rules are stated once here rather
// than four times at the call sites: separate copies is how one column
// acquires an assertion the others lack, and a reader has to diff forty lines
// to notice.
func checkRelationColumn(t *testing.T, label string, undefined error, nLeaves uint32, node uint32, got NodeIndex, err error, want *uint32) (refused bool, matched bool) {
	t.Helper()
	if want == nil {
		if err == nil {
			t.Errorf("n_leaves %d node %d: %s %d, want undefined", nLeaves, node, label, got)
			return false, false
		}
		if !errors.Is(err, undefined) {
			t.Errorf("n_leaves %d node %d: %s: %v, want %v", nLeaves, node, label, err, undefined)
			return false, false
		}
		// the index is read back alongside the refusal, as the root runner above
		// already does. measured: a version that hands back x with the error
		// satisfies both checks above, and a caller that reads only the value
		// then has a leaf as its own child, or the root as its own parent.
		if got != 0 {
			t.Errorf("n_leaves %d node %d: %s %d alongside the refusal, want 0", nLeaves, node, label, got)
			return false, false
		}
		return true, false
	}
	if err != nil {
		t.Errorf("n_leaves %d node %d: %s: %v, want %d", nLeaves, node, label, err, *want)
		return false, false
	}
	if uint32(got) != *want {
		t.Errorf("n_leaves %d node %d: %s %d, want %d", nLeaves, node, label, got, *want)
		return false, false
	}
	return false, true
}

func TestTreeMathVectorChildren(t *testing.T) {
	vectors := loadTreeMathVectors(t)

	// both arms of every column are counted, and what is counted is a confirmed
	// assertion rather than a column entry seen. counting entries seen would
	// sit at the same number while every assertion beneath it was skipped,
	// which is the shape a guard in this package already had to be rewritten
	// out of.
	//
	// the counting exists because null is the majority of these columns at
	// every size, and a runner that reads null as "nothing to check here" tests
	// the parent half of the family and silently drops the leaf refusal
	// entirely. measured: with the null arm made unreachable, a version of Left
	// and Right with no leaf guard at all passes the whole of this test.
	leftRefusals, leftMatches := 0, 0
	rightRefusals, rightMatches := 0, 0

	for _, v := range vectors {
		for i := uint32(0); i < v.NNodes; i += 1 {
			nodeIndex := NodeIndex(i)

			gotLeft, leftErr := Left(nodeIndex)
			refused, matched := checkRelationColumn(t, "left", ErrLeafHasNoChildren, v.NLeaves, i, gotLeft, leftErr, v.Left[i])
			if refused {
				leftRefusals += 1
			}
			if matched {
				leftMatches += 1
			}

			gotRight, rightErr := Right(nodeIndex)
			refused, matched = checkRelationColumn(t, "right", ErrLeafHasNoChildren, v.NLeaves, i, gotRight, rightErr, v.Right[i])
			if refused {
				rightRefusals += 1
			}
			if matched {
				rightMatches += 1
			}
		}
	}

	// the leaf counts on the family's ladder sum to 1023, and every entry holds
	// one fewer parent than it holds leaves, so the family publishes 1023
	// undefined children and 1013 defined ones per column — 2036 in all, the
	// node total the corpus tripwire pins. the totals are asserted rather than
	// only "more than none" so that a runner which skipped part of the ladder,
	// or part of an entry, fails here too.
	countCases := []struct {
		label string
		got   int
		want  int
	}{
		{label: "left refusals", got: leftRefusals, want: 1023},
		{label: "left matches", got: leftMatches, want: 1013},
		{label: "right refusals", got: rightRefusals, want: 1023},
		{label: "right matches", got: rightMatches, want: 1013},
	}
	for _, c := range countCases {
		if c.got != c.want {
			t.Errorf("confirmed %s: %d, want %d", c.label, c.got, c.want)
		}
	}

	// the family stops at 512 leaves, so its deepest parent is that entry's
	// root at level 9 and it says nothing at all about levels 10 and above.
	// nothing later in this package covers them either: the structural sweep
	// also stops at 512 leaves, and the fuzz target asserts only that an
	// answer is inside the tree.
	//
	// measured, not assumed: against the family plus the two refusal probes
	// below, every range guard from k > 9 through k >= 31 passes. each of them
	// refuses only nodes the family never asks about, and 0xFFFFFFFF is
	// expected to be refused anyway. the level 31 row is what brackets the
	// guard from below; 0xFFFFFFFF brackets it from above.
	//
	// the expected values are not the operation under test. in the array layout
	// a node at level k spans the 2^(k+1)-1 nodes centred on itself, so its
	// children are the centres of the two halves, at x-2^(k-1) and x+2^(k-1).
	// that derivation reproduces all 2036 published entries of this family
	// exactly, and the level 5 row is itself published — it is the root of the
	// 32-leaf entry — so the table is anchored to vendored data at one row
	// rather than resting on arithmetic alone.
	boundaryCases := []struct {
		nodeIndex NodeIndex
		left      NodeIndex
		right     NodeIndex
	}{
		// level 5, the root of the family's 32-leaf entry.
		{nodeIndex: 0x0000001F, left: 0x0000000F, right: 0x0000002F},
		// level 16 and level 30, two subtree roots no published entry reaches.
		{nodeIndex: 0x0000FFFF, left: 0x00007FFF, right: 0x00017FFF},
		{nodeIndex: 0x3FFFFFFF, left: 0x1FFFFFFF, right: 0x5FFFFFFF},
		// level 31, the root of the largest representable tree and the deepest
		// node that has children at all.
		{nodeIndex: 0x7FFFFFFF, left: 0x3FFFFFFF, right: 0xBFFFFFFF},
	}
	for _, c := range boundaryCases {
		gotLeft, err := Left(c.nodeIndex)
		if err != nil {
			t.Errorf("left of %d: %v, want %d", c.nodeIndex, err, c.left)
		} else if gotLeft != c.left {
			t.Errorf("left of %d: %d, want %d", c.nodeIndex, gotLeft, c.left)
		}
		gotRight, err := Right(c.nodeIndex)
		if err != nil {
			t.Errorf("right of %d: %v, want %d", c.nodeIndex, err, c.right)
		} else if gotRight != c.right {
			t.Errorf("right of %d: %d, want %d", c.nodeIndex, gotRight, c.right)
		}
	}

	// the refusal below is reachable at exactly one index, and only because
	// Level is total and answers 32 there. this line is the diagnosis rather
	// than the coverage: a Level clamped to 31 already fails the two checks
	// after it, because the clamped version answers 0x7FFFFFFF instead of
	// refusing. it is here so that failure names its cause instead of looking
	// like a broken guard.
	if got := NodeIndex(0xFFFFFFFF).Level(); got != 32 {
		t.Fatalf("level of 0xFFFFFFFF: %d, want 32: no index reaches the range refusal below at any other level", got)
	}

	// 0xFFFFFFFF is one past the last node of the largest representable tree,
	// and its level of 32 would shift a child computation off the end of a
	// uint32. it is refused rather than answered with a truncated index, and
	// the index is read back alongside the refusal for the same reason as in
	// the column checker above.
	if gotLeft, err := Left(NodeIndex(0xFFFFFFFF)); !errors.Is(err, ErrNodeOutOfRange) {
		t.Errorf("left of 0xFFFFFFFF: %v, want %v", err, ErrNodeOutOfRange)
	} else if gotLeft != 0 {
		t.Errorf("left of 0xFFFFFFFF: %d alongside the refusal, want 0", gotLeft)
	}
	if gotRight, err := Right(NodeIndex(0xFFFFFFFF)); !errors.Is(err, ErrNodeOutOfRange) {
		t.Errorf("right of 0xFFFFFFFF: %v, want %v", err, ErrNodeOutOfRange)
	} else if gotRight != 0 {
		t.Errorf("right of 0xFFFFFFFF: %d alongside the refusal, want 0", gotRight)
	}
}

func TestTreeMathVectorParentAndSibling(t *testing.T) {
	vectors := loadTreeMathVectors(t)

	// both arms of both columns are counted, for the reason the children runner
	// above gives, and the argument is stronger here rather than weaker. null is
	// half of each child column; it is ten of the 2036 entries in each of these
	// two, one root per size. a runner that reads null as nothing to check here
	// therefore still walks 99.5% of the family and looks like full coverage
	// while asserting nothing whatever about either refusal. measured: with the
	// family runner's null arm made unreachable, a Parent carrying no root
	// guard at all and a Sibling that never translates the sentinel both pass
	// it, and only the rows below this loop catch either of them.
	parentRefusals, parentMatches := 0, 0
	siblingRefusals, siblingMatches := 0, 0

	for _, v := range vectors {
		leafCount := LeafCount(v.NLeaves)
		for i := uint32(0); i < v.NNodes; i += 1 {
			nodeIndex := NodeIndex(i)

			gotParent, parentErr := Parent(nodeIndex, leafCount)
			refused, matched := checkRelationColumn(t, "parent", ErrRootHasNoParent, v.NLeaves, i, gotParent, parentErr, v.Parent[i])
			if refused {
				parentRefusals += 1
			}
			if matched {
				parentMatches += 1
			}

			gotSibling, siblingErr := Sibling(nodeIndex, leafCount)
			refused, matched = checkRelationColumn(t, "sibling", ErrRootHasNoSibling, v.NLeaves, i, gotSibling, siblingErr, v.Sibling[i])
			if refused {
				siblingRefusals += 1
			}
			if matched {
				siblingMatches += 1
			}
		}

		// a node past the end of the array is refused, not answered. the
		// appendix C pseudocode answers, which is how an index decoded from a
		// message reaches arithmetic it has no business reaching.
		//
		// three indices, not one. the width itself is what separates a guard
		// reading at least the width from one reading more than it, and the
		// family pins the node one below, which every correct guard admits.
		// one past the width and the top of the type are what stop the guard
		// from being an equality or a narrow band that refuses the first index
		// outside the tree and answers for every one after it. measured: with
		// only the width probed, a guard reading exactly equal to the width
		// survives the whole of this test, and it hands a caller node 17 of a
		// fifteen-node tree.
		outOfRangeCases := []NodeIndex{
			NodeIndex(v.NNodes),
			NodeIndex(v.NNodes + 1),
			NodeIndex(0xFFFFFFFF),
		}
		for _, nodeIndex := range outOfRangeCases {
			if got, err := Parent(nodeIndex, leafCount); !errors.Is(err, ErrNodeOutOfRange) {
				t.Errorf("n_leaves %d: parent of node %d: %v, want %v", v.NLeaves, nodeIndex, err, ErrNodeOutOfRange)
			} else if got != 0 {
				t.Errorf("n_leaves %d: parent of node %d: %d alongside the refusal, want 0", v.NLeaves, nodeIndex, got)
			}
			if got, err := Sibling(nodeIndex, leafCount); !errors.Is(err, ErrNodeOutOfRange) {
				t.Errorf("n_leaves %d: sibling of node %d: %v, want %v", v.NLeaves, nodeIndex, err, ErrNodeOutOfRange)
			} else if got != 0 {
				t.Errorf("n_leaves %d: sibling of node %d: %d alongside the refusal, want 0", v.NLeaves, nodeIndex, got)
			}
		}
	}

	// every entry publishes one root, and the root is the only node in an entry
	// with neither a parent nor a sibling, so across the ten entries each of the
	// two columns holds ten undefined and 2026 defined entries - 2036 in all,
	// the node total the corpus tripwire pins. the totals are asserted rather
	// than only "more than none" so that a runner which skipped part of the
	// ladder, or part of an entry, fails here too.
	countCases := []struct {
		label string
		got   int
		want  int
	}{
		{label: "parent refusals", got: parentRefusals, want: 10},
		{label: "parent matches", got: parentMatches, want: 2026},
		{label: "sibling refusals", got: siblingRefusals, want: 10},
		{label: "sibling matches", got: siblingMatches, want: 2026},
	}
	for _, c := range countCases {
		if c.got != c.want {
			t.Errorf("confirmed %s: %d, want %d", c.label, c.got, c.want)
		}
	}

	// the family's ladder is powers of two only, so nothing above says what
	// either function does with a leaf count no tree can have. both take the
	// count only to locate the root, and both have to refuse before the index
	// arithmetic runs rather than answering for the enclosing full tree.
	//
	// measured: with these rows removed and every other row kept, a Parent that
	// discards the error from Root passes. Root hands back zero alongside its
	// refusal, so the discarding version reads a root of node 0, then reports
	// leaf 0 of a three-leaf tree as a root with no parent and node 1 as an
	// ordinary node with parent 3. two node indices are used per count for that
	// reason: one the wrong root swallows into a refusal and one it answers
	// for. the same pair also separates a width check hoisted above the count
	// check, which at zero leaves calls every index out of range instead.
	invalidCountCases := []struct {
		nodeIndex NodeIndex
		leafCount LeafCount
		err       error
	}{
		{nodeIndex: 0, leafCount: 3, err: ErrLeafCountNotFull},
		{nodeIndex: 1, leafCount: 3, err: ErrLeafCountNotFull},
		{nodeIndex: 0, leafCount: 0, err: ErrLeafCountRange},
		{nodeIndex: 1, leafCount: 0, err: ErrLeafCountRange},
		{nodeIndex: 0, leafCount: MaxLeafCount + 1, err: ErrLeafCountRange},
		{nodeIndex: 1, leafCount: MaxLeafCount + 1, err: ErrLeafCountRange},
	}
	for _, c := range invalidCountCases {
		parent, err := Parent(c.nodeIndex, c.leafCount)
		if !errors.Is(err, c.err) {
			t.Errorf("parent of node %d in %d leaves: %v, want %v", c.nodeIndex, c.leafCount, err, c.err)
		}
		if parent != 0 {
			t.Errorf("parent of node %d in %d leaves: %d alongside the refusal, want 0", c.nodeIndex, c.leafCount, parent)
		}
		sibling, err := Sibling(c.nodeIndex, c.leafCount)
		if !errors.Is(err, c.err) {
			t.Errorf("sibling of node %d in %d leaves: %v, want %v", c.nodeIndex, c.leafCount, err, c.err)
		}
		if sibling != 0 {
			t.Errorf("sibling of node %d in %d leaves: %d alongside the refusal, want 0", c.nodeIndex, c.leafCount, sibling)
		}
	}

	// the family's deepest node is the root of its 512-leaf entry, at level 9,
	// and that node is a refusal in both columns: the deepest node it publishes
	// a parent or a sibling for is at level 8. so the family says nothing about
	// levels 9 through 31, and nothing later in this package covers them
	// either - the structural sweep also stops at 512 leaves and the fuzz
	// target asserts only that an answer is inside the tree. it says nothing
	// about leaf counts above 512 either, and the count is what locates the
	// root both functions refuse at.
	//
	// measured, not assumed: with these rows removed and every other row of
	// this test kept, two versions pass — a Parent whose index arithmetic is
	// correct only up to level 8, and a Parent whose root guard fires only at
	// the leaf counts the family publishes and answers a parent for the root of
	// every larger tree.
	//
	// the expected values are not the operation under test. in the array layout
	// a node at level k is the centre of the 2^(k+1)-1 nodes it spans, so the
	// leftmost node of level k sits at 2^k-1; the parent spanning it and its
	// neighbour is the centre of a 2^(k+2)-1 span based at zero, at 2^(k+1)-1;
	// and that parent's other child is the centre of the upper half, at
	// 3*2^k-1. in a tree of 2^(k+1) leaves that parent is the root, so each row
	// pins a refusal at level k+1 as well. the same three closed forms
	// reproduce all nine levels the family does publish, defined rows and root
	// refusal alike - the level 8 row below is the 512-leaf entry itself,
	// vendored - so the table is anchored to published data and every row above
	// it is the same three forms continued.
	//
	// with these rows the two functions are asserted at every level a node can
	// have: 0 through 8 by the family, 8 through 30 here, level 31 as the root
	// refusal of the largest tree (its only node, 0x7FFFFFFF, is that root, and
	// is out of range in every smaller tree, so it has no defined arm to
	// assert), and level 32 as the out-of-range probe below. all thirty-two
	// valid leaf counts are covered too: 2^0 through 2^9 by the family and 2^9
	// through 2^31 here.
	boundaryCases := []struct {
		level      uint32
		leafCount  LeafCount
		leftChild  NodeIndex
		parent     NodeIndex
		rightChild NodeIndex
	}{
		{level: 8, leafCount: 1 << 9, leftChild: 0x000000FF, parent: 0x000001FF, rightChild: 0x000002FF},
		{level: 9, leafCount: 1 << 10, leftChild: 0x000001FF, parent: 0x000003FF, rightChild: 0x000005FF},
		{level: 10, leafCount: 1 << 11, leftChild: 0x000003FF, parent: 0x000007FF, rightChild: 0x00000BFF},
		{level: 11, leafCount: 1 << 12, leftChild: 0x000007FF, parent: 0x00000FFF, rightChild: 0x000017FF},
		{level: 12, leafCount: 1 << 13, leftChild: 0x00000FFF, parent: 0x00001FFF, rightChild: 0x00002FFF},
		{level: 13, leafCount: 1 << 14, leftChild: 0x00001FFF, parent: 0x00003FFF, rightChild: 0x00005FFF},
		{level: 14, leafCount: 1 << 15, leftChild: 0x00003FFF, parent: 0x00007FFF, rightChild: 0x0000BFFF},
		{level: 15, leafCount: 1 << 16, leftChild: 0x00007FFF, parent: 0x0000FFFF, rightChild: 0x00017FFF},
		{level: 16, leafCount: 1 << 17, leftChild: 0x0000FFFF, parent: 0x0001FFFF, rightChild: 0x0002FFFF},
		{level: 17, leafCount: 1 << 18, leftChild: 0x0001FFFF, parent: 0x0003FFFF, rightChild: 0x0005FFFF},
		{level: 18, leafCount: 1 << 19, leftChild: 0x0003FFFF, parent: 0x0007FFFF, rightChild: 0x000BFFFF},
		{level: 19, leafCount: 1 << 20, leftChild: 0x0007FFFF, parent: 0x000FFFFF, rightChild: 0x0017FFFF},
		{level: 20, leafCount: 1 << 21, leftChild: 0x000FFFFF, parent: 0x001FFFFF, rightChild: 0x002FFFFF},
		{level: 21, leafCount: 1 << 22, leftChild: 0x001FFFFF, parent: 0x003FFFFF, rightChild: 0x005FFFFF},
		{level: 22, leafCount: 1 << 23, leftChild: 0x003FFFFF, parent: 0x007FFFFF, rightChild: 0x00BFFFFF},
		{level: 23, leafCount: 1 << 24, leftChild: 0x007FFFFF, parent: 0x00FFFFFF, rightChild: 0x017FFFFF},
		{level: 24, leafCount: 1 << 25, leftChild: 0x00FFFFFF, parent: 0x01FFFFFF, rightChild: 0x02FFFFFF},
		{level: 25, leafCount: 1 << 26, leftChild: 0x01FFFFFF, parent: 0x03FFFFFF, rightChild: 0x05FFFFFF},
		{level: 26, leafCount: 1 << 27, leftChild: 0x03FFFFFF, parent: 0x07FFFFFF, rightChild: 0x0BFFFFFF},
		{level: 27, leafCount: 1 << 28, leftChild: 0x07FFFFFF, parent: 0x0FFFFFFF, rightChild: 0x17FFFFFF},
		{level: 28, leafCount: 1 << 29, leftChild: 0x0FFFFFFF, parent: 0x1FFFFFFF, rightChild: 0x2FFFFFFF},
		{level: 29, leafCount: 1 << 30, leftChild: 0x1FFFFFFF, parent: 0x3FFFFFFF, rightChild: 0x5FFFFFFF},
		{level: 30, leafCount: 1 << 31, leftChild: 0x3FFFFFFF, parent: 0x7FFFFFFF, rightChild: 0xBFFFFFFF},
	}
	for _, c := range boundaryCases {
		// the row states which level it exercises, and the claim above about
		// which levels are covered rests on that being true, so it is asserted
		// rather than trusted: a mistyped index would otherwise cover one level
		// twice and leave another with nothing.
		levelCases := []struct {
			nodeIndex NodeIndex
			level     uint32
		}{
			{nodeIndex: c.leftChild, level: c.level},
			{nodeIndex: c.rightChild, level: c.level},
			{nodeIndex: c.parent, level: c.level + 1},
		}
		for _, l := range levelCases {
			if got := l.nodeIndex.Level(); got != l.level {
				t.Errorf("node %d level: %d, want %d", l.nodeIndex, got, l.level)
			}
		}

		// the left child, whose parent lies above it.
		if got, err := Parent(c.leftChild, c.leafCount); err != nil {
			t.Errorf("parent of node %d in %d leaves: %v, want %d", c.leftChild, c.leafCount, err, c.parent)
		} else if got != c.parent {
			t.Errorf("parent of node %d in %d leaves: %d, want %d", c.leftChild, c.leafCount, got, c.parent)
		}
		if got, err := Sibling(c.leftChild, c.leafCount); err != nil {
			t.Errorf("sibling of node %d in %d leaves: %v, want %d", c.leftChild, c.leafCount, err, c.rightChild)
		} else if got != c.rightChild {
			t.Errorf("sibling of node %d in %d leaves: %d, want %d", c.leftChild, c.leafCount, got, c.rightChild)
		}

		// the right child, whose parent lies below it. the two rows together are
		// what separates the term that reads the bit above the level from a
		// constant: a version that always adds passes the row above and fails
		// this one.
		if got, err := Parent(c.rightChild, c.leafCount); err != nil {
			t.Errorf("parent of node %d in %d leaves: %v, want %d", c.rightChild, c.leafCount, err, c.parent)
		} else if got != c.parent {
			t.Errorf("parent of node %d in %d leaves: %d, want %d", c.rightChild, c.leafCount, got, c.parent)
		}
		if got, err := Sibling(c.rightChild, c.leafCount); err != nil {
			t.Errorf("sibling of node %d in %d leaves: %v, want %d", c.rightChild, c.leafCount, err, c.leftChild)
		} else if got != c.leftChild {
			t.Errorf("sibling of node %d in %d leaves: %d, want %d", c.rightChild, c.leafCount, got, c.leftChild)
		}

		// and the parent, which at this leaf count is the root and so has
		// neither. these are the only assertions in the package on a root
		// refusal above level 9.
		if got, err := Parent(c.parent, c.leafCount); !errors.Is(err, ErrRootHasNoParent) {
			t.Errorf("parent of node %d in %d leaves: %v, want %v", c.parent, c.leafCount, err, ErrRootHasNoParent)
		} else if got != 0 {
			t.Errorf("parent of node %d in %d leaves: %d alongside the refusal, want 0", c.parent, c.leafCount, got)
		}
		if got, err := Sibling(c.parent, c.leafCount); !errors.Is(err, ErrRootHasNoSibling) {
			t.Errorf("sibling of node %d in %d leaves: %v, want %v", c.parent, c.leafCount, err, ErrRootHasNoSibling)
		} else if got != 0 {
			t.Errorf("sibling of node %d in %d leaves: %d alongside the refusal, want 0", c.parent, c.leafCount, got)
		}
	}

	// the top of the index range at the largest representable leaf count, which
	// no entry of the family reaches. 0xFFFFFFFE is the last leaf of that tree,
	// 0xFFFFFFFD is its parent and 0xFFFFFFFC its sibling; those are the
	// deepest-indexed defined answers either function has, and they are the one
	// place the parent of a level 0 node is asserted with the bit above the
	// level set at the very top of the type. 0xFFFFFFFF is one past the end of
	// the tree and so inside no tree at all, and it is the one index the width
	// guard has to refuse here, where every smaller index is in range - the
	// per-entry probe above brackets that guard at ten small sizes and this
	// brackets it at the only size where the width fills the type.
	topOfRangeCases := []struct {
		nodeIndex NodeIndex
		parent    NodeIndex
		sibling   NodeIndex
	}{
		{nodeIndex: 0xFFFFFFFE, parent: 0xFFFFFFFD, sibling: 0xFFFFFFFC},
	}
	for _, c := range topOfRangeCases {
		if got, err := Parent(c.nodeIndex, MaxLeafCount); err != nil {
			t.Errorf("parent of node %d in MaxLeafCount leaves: %v, want %d", c.nodeIndex, err, c.parent)
		} else if got != c.parent {
			t.Errorf("parent of node %d in MaxLeafCount leaves: %d, want %d", c.nodeIndex, got, c.parent)
		}
		if got, err := Sibling(c.nodeIndex, MaxLeafCount); err != nil {
			t.Errorf("sibling of node %d in MaxLeafCount leaves: %v, want %d", c.nodeIndex, err, c.sibling)
		} else if got != c.sibling {
			t.Errorf("sibling of node %d in MaxLeafCount leaves: %d, want %d", c.nodeIndex, got, c.sibling)
		}
	}

	if got, err := Parent(NodeIndex(0xFFFFFFFF), MaxLeafCount); !errors.Is(err, ErrNodeOutOfRange) {
		t.Errorf("parent of 0xFFFFFFFF in MaxLeafCount leaves: %v, want %v", err, ErrNodeOutOfRange)
	} else if got != 0 {
		t.Errorf("parent of 0xFFFFFFFF in MaxLeafCount leaves: %d alongside the refusal, want 0", got)
	}
	if got, err := Sibling(NodeIndex(0xFFFFFFFF), MaxLeafCount); !errors.Is(err, ErrNodeOutOfRange) {
		t.Errorf("sibling of 0xFFFFFFFF in MaxLeafCount leaves: %v, want %v", err, ErrNodeOutOfRange)
	} else if got != 0 {
		t.Errorf("sibling of 0xFFFFFFFF in MaxLeafCount leaves: %d alongside the refusal, want 0", got)
	}
}
