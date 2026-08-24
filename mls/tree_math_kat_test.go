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
	"go/ast"
	"go/parser"
	"go/token"
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

// this file, named so a failure can say where the code it is asking for goes.
const treeMathVectorRunnerFile = "mls/tree_math_kat_test.go"

// every field an entry of this family carries, in the order upstream writes
// them. stated once: the corpus tripwire reads it off the vendored bytes and
// the generate direction reads it off the bytes this file produces, and two
// copies is how the generated side ends up checked against a list that was
// updated on the vendored side only.
var treeMathVectorFields = []string{"n_leaves", "n_nodes", "root", "left", "right", "parent", "sibling"}

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

	for i, rawEntry := range rawEntries {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(rawEntry, &entry); err != nil {
			t.Fatalf("decode %s entry %d: %v", treeMathVectorFile, i, err)
		}
		if len(entry) != len(treeMathVectorFields) {
			t.Fatalf("entry %d: %d fields, want %d — the upstream format changed and the runner must be extended", i, len(entry), len(treeMathVectorFields))
		}
		for _, field := range treeMathVectorFields {
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

// the columns an entry publishes are as long as the entry says the tree is.
//
// checked in each of the three runners that indexes one, and not only in the
// corpus tripwire above, because a short column is a panic at v.Left[i] rather
// than a failure and a panic takes the whole test binary down with it. measured
// against a corpus with one entry's sibling column one short: the package
// reported 16 of its 32 tests, and the three that name the truncated column
// were among the sixteen that never ran.
func checkColumnLengths(t *testing.T, v treeMathVector) {
	t.Helper()
	columns := []struct {
		label     string
		published []*uint32
	}{
		{label: "left", published: v.Left},
		{label: "right", published: v.Right},
		{label: "parent", published: v.Parent},
		{label: "sibling", published: v.Sibling},
	}
	for _, column := range columns {
		if uint32(len(column.published)) != v.NNodes {
			t.Fatalf("n_leaves %d: %s has %d entries, want n_nodes %d", v.NLeaves, column.label, len(column.published), v.NNodes)
		}
	}
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
		checkColumnLengths(t, v)
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
		checkColumnLengths(t, v)
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
		//
		// all three earn their place, by ablation rather than by argument: drop
		// one past the width and a guard holed at exactly that index survives at
		// every leaf count this loop covers, and drop the top of the type and a
		// guard that refuses only the first two indices outside the tree and
		// answers beyond them survives at every one of them. each of the two is
		// the sole killer of its own class, ten counts apiece.
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
	// valid leaf counts are covered too, and in each of the three arms both
	// functions have - a defined answer, the root refusal, and the refusal of
	// an index past the end: 2^0 through 2^9 by the family and 2^9 through 2^31
	// here. the third arm is named separately because the leaf count is as much
	// an input to the range guard as it is to the root check, and a table that
	// probes only inside each tree says nothing whatever about it.
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
	// the probe loop inside this one skips an index the type cannot hold, and a
	// skip is invisible: a mistyped width would leave every one of those rows
	// vacuous with the test still passing. the executed count is asserted after
	// the loop for that reason.
	outOfRangeProbes := 0
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

		// and an index past the end of this tree, which nothing else in the
		// package reaches at this leaf count. the per-entry probe above brackets
		// the range guard at the ten counts the family publishes and the probe
		// below it at the one count whose width fills the index type, so without
		// these rows the guard is unasserted at the twenty-one counts in
		// between.
		//
		// the same three indices the per-entry probe uses, for the same reasons:
		// the width itself separates a guard reading at least the width from one
		// reading more than it, one past the width stops a guard holed at
		// exactly that index, and the top of the type stops a guard that refuses
		// the first two indices outside the tree and answers beyond them. the
		// largest tree's width is the top of the type, so one past it is not
		// representable and is dropped rather than wrapped round to node 0,
		// which is in range.
		//
		// measured: with these rows removed and every other row of this test
		// kept, a mechanical enumeration of the guard as a function of leaf
		// count leaves a hundred and six versions passing - skipped at one
		// count, off by one at one count, holed at one index of one count,
		// refusing only the first two indices outside one count's tree, and
		// banded to the family's counts plus the largest. with them, the only
		// versions still passing are four rewrites of the guard into itself.
		width := uint64(NodeWidth(c.leafCount))
		for _, probe := range []uint64{width, width + 1, 0xFFFFFFFF} {
			if probe > 0xFFFFFFFF {
				continue
			}
			outOfRangeProbes += 1
			nodeIndex := NodeIndex(probe)
			if got, err := Parent(nodeIndex, c.leafCount); !errors.Is(err, ErrNodeOutOfRange) {
				t.Errorf("parent of node %d in %d leaves: %v, want %v", nodeIndex, c.leafCount, err, ErrNodeOutOfRange)
			} else if got != 0 {
				t.Errorf("parent of node %d in %d leaves: %d alongside the refusal, want 0", nodeIndex, c.leafCount, got)
			}
			if got, err := Sibling(nodeIndex, c.leafCount); !errors.Is(err, ErrNodeOutOfRange) {
				t.Errorf("sibling of node %d in %d leaves: %v, want %v", nodeIndex, c.leafCount, err, ErrNodeOutOfRange)
			} else if got != 0 {
				t.Errorf("sibling of node %d in %d leaves: %d alongside the refusal, want 0", nodeIndex, c.leafCount, got)
			}
		}
	}

	// twenty-two of the twenty-three rows probe three indices past the end of
	// their tree. the largest tree's width is the top of the index type, so one
	// past it is not representable and that row probes two.
	if outOfRangeProbes != 68 {
		t.Errorf("boundary out-of-range probes: %d, want 68", outOfRangeProbes)
	}

	// the top of the index range at the largest representable leaf count, which
	// no entry of the family reaches. 0xFFFFFFFE is the last leaf of that tree,
	// 0xFFFFFFFD is its parent and 0xFFFFFFFC its sibling; those are the
	// deepest-indexed defined answers either function has, and they are the one
	// place the parent of a level 0 node is asserted with the bit above the
	// level set at the very top of the type. 0xFFFFFFFF is one past the end of
	// the tree and so inside no tree at all, and it is the one index the width
	// guard has to refuse here, where every smaller index is in range - the
	// per-entry probe brackets that guard at the ten sizes the family publishes
	// and the boundary rows at the twenty-three above them, this size included.
	// the row is kept anyway: 0xFFFFFFFF is the one index in the whole type that
	// is outside every tree, and it reads here beside the defined answers it
	// borders.
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

// checks every relation one entry publishes, against the functions this plan
// produces, and reports how many assertions were confirmed in each arm.
//
// what is counted is a confirmed assertion, not a column entry visited, for the
// reason the two per-function runners above give: a count of entries visited
// sits at the same number while every assertion beneath it is reported and
// skipped. the checking itself is checkRelationColumn, unchanged, so the gate
// inherits its sentinel and its read-back of the index alongside a refusal
// rather than restating a weaker version of either.
func checkTreeMathEntry(t *testing.T, v treeMathVector) (refusals int, matches int) {
	t.Helper()
	leafCount := LeafCount(v.NLeaves)

	if got := NodeWidth(leafCount); got != v.NNodes {
		t.Fatalf("n_leaves %d: node width %d, want %d", v.NLeaves, got, v.NNodes)
	}
	root, err := Root(leafCount)
	if err != nil {
		t.Fatalf("n_leaves %d: root: %v", v.NLeaves, err)
	}
	if uint32(root) != v.Root {
		t.Fatalf("n_leaves %d: root %d, want %d", v.NLeaves, root, v.Root)
	}

	// the four columns, each paired with the function that answers it and the
	// sentinel its undefined arm has to carry. stated once, walked once: the
	// per-function runners above pair them at four separate call sites because
	// each landed in its own task, and a gate that repeated that shape is where
	// one column would quietly lose a check.
	relations := []struct {
		label     string
		undefined error
		answer    func(x NodeIndex) (NodeIndex, error)
		published []*uint32
	}{
		{label: "left", undefined: ErrLeafHasNoChildren, answer: Left, published: v.Left},
		{label: "right", undefined: ErrLeafHasNoChildren, answer: Right, published: v.Right},
		{
			label:     "parent",
			undefined: ErrRootHasNoParent,
			answer:    func(x NodeIndex) (NodeIndex, error) { return Parent(x, leafCount) },
			published: v.Parent,
		},
		{
			label:     "sibling",
			undefined: ErrRootHasNoSibling,
			answer:    func(x NodeIndex) (NodeIndex, error) { return Sibling(x, leafCount) },
			published: v.Sibling,
		},
	}

	// before any column is indexed, and by the same helper the two per-function
	// runners call: this runner is also where an entry that was never read off
	// disk arrives, and naming the truncated column says which one it was.
	checkColumnLengths(t, v)

	for i := uint32(0); i < v.NNodes; i += 1 {
		for _, relation := range relations {
			got, err := relation.answer(NodeIndex(i))
			refused, matched := checkRelationColumn(t, relation.label, relation.undefined, v.NLeaves, i, got, err, relation.published[i])
			if refused {
				refusals += 1
			}
			if matched {
				matches += 1
			}
		}
	}
	return refusals, matches
}

// one entry of family 1, decoded and checked, in the arity the shared vector
// harness calls its families with. the registration that would hand this
// function to that harness is deferred; see the note above TestTreeMathVectors.
//
// the count guard is not "did the loop run". it states which arm each of the
// entry's assertions had to land in, and both numbers come from the shape of a
// full tree rather than from this package: a full tree refuses both children at
// each of its n_leaves leaves and refuses a parent and a sibling at its one
// root, and defines every other relation. an entry whose nulls were dropped
// therefore fails here even though every assertion it did make passed, which is
// the failure a truncated or a naively regenerated entry produces.
//
// n_leaves of zero cannot reach the arithmetic below: no tree has zero leaves,
// so the root lookup in checkTreeMathEntry has already failed the test.
func verifyTreeMathVector(t *testing.T, raw json.RawMessage) {
	t.Helper()
	var v treeMathVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode tree-math entry: %v", err)
	}
	refusals, matches := checkTreeMathEntry(t, v)

	// 2*n_leaves for the two child columns plus 2 for the root's parent and
	// sibling; the rest of the 4*n_nodes assertions are defined relations.
	wantRefusals := int(2*v.NLeaves + 2)
	wantMatches := int(4*v.NNodes) - wantRefusals
	if refusals != wantRefusals {
		t.Fatalf("n_leaves %d: confirmed %d refusals, want %d", v.NLeaves, refusals, wantRefusals)
	}
	if matches != wantMatches {
		t.Fatalf("n_leaves %d: confirmed %d matches, want %d", v.NLeaves, matches, wantMatches)
	}
}

// the whole of family 1 recomputed from this file's arithmetic, at the ten
// sizes upstream publishes, in the upstream field order and with null for every
// undefined relation. the arity is the shared harness's generate direction: one
// json.RawMessage holding the array the corpus file is.
//
// generated vectors are circular on their own — they are this package's answers
// read back as this package's expectations — so nothing here is a gate by
// itself. what makes it worth having is the comparison against the vendored
// bytes in TestTreeMathVectorGenerateThenVerify.
func generateTreeMathVectors(t *testing.T) json.RawMessage {
	t.Helper()

	// the corpus writes an undefined relation as null, so a refusal becomes a
	// nil pointer and the error is deliberately not distinguished here: which
	// sentinel a refusal carries is checked on the way back in, against the
	// vendored column, not asserted on the way out against itself.
	optional := func(x NodeIndex, err error) *uint32 {
		if err != nil {
			return nil
		}
		value := uint32(x)
		return &value
	}

	vectors := make([]treeMathVector, 0, treeMathVectorCount)
	for depth := uint32(0); depth < treeMathVectorCount; depth += 1 {
		leafCount := LeafCount(1) << depth
		nodeWidth := NodeWidth(leafCount)
		root, err := Root(leafCount)
		if err != nil {
			t.Fatalf("%d leaves: root: %v", leafCount, err)
		}

		v := treeMathVector{
			NLeaves: uint32(leafCount),
			NNodes:  nodeWidth,
			Root:    uint32(root),
			Left:    make([]*uint32, 0, nodeWidth),
			Right:   make([]*uint32, 0, nodeWidth),
			Parent:  make([]*uint32, 0, nodeWidth),
			Sibling: make([]*uint32, 0, nodeWidth),
		}
		for i := uint32(0); i < nodeWidth; i += 1 {
			nodeIndex := NodeIndex(i)
			v.Left = append(v.Left, optional(Left(nodeIndex)))
			v.Right = append(v.Right, optional(Right(nodeIndex)))
			v.Parent = append(v.Parent, optional(Parent(nodeIndex, leafCount)))
			v.Sibling = append(v.Sibling, optional(Sibling(nodeIndex, leafCount)))
		}
		vectors = append(vectors, v)
	}

	generated, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("encode tree-math family: %v", err)
	}
	return json.RawMessage(generated)
}

// vector family 1, the gate spec A section 4.2.1 names for this plan.
//
// what it holds that nothing above it does is the first loop: the vendored
// bytes walked through verifyTreeMathVector, which is the function the shared
// harness will call, in the arity it will call it with, over the corpus it will
// hand it. everywhere else in this file that function is run against entries
// this package generated, and a verifier checked only against its own
// generator's output is this package's arithmetic read back as this package's
// expectation - its per-entry arm counts would never meet a published number at
// all.
//
// the totals below are not that. they are the family sums of the eight the two
// per-function runners already assert - 1023 + 1023 + 10 + 10 refusals and
// 1013 + 1013 + 2026 + 2026 matches - so no production mutant fails here and
// passes there, and this row is a restatement rather than a second opinion.
// stated plainly because the first version of this comment called the totals
// "the whole point of it", and a reader who believed that would take this test
// for independent evidence it is not. they are kept because 8144 is the number
// spec A's family-1 row publishes and the row a reader comes to a gate to find,
// and because they are what a runner that walked a short corpus, skipped an
// entry, or read null as nothing to check here lands wrong on.
//
// the registration this task was to land with it is deferred and is not
// silently missing: mls/vectors_test.go, where the validation and interop
// harness plan declares VectorFamily, RegisterVectorFamily and
// expectedPendingFamilies, does not exist in this tree, and inventing that
// registry here would put a second, guessed copy of another plan's contract in
// the package. verifyTreeMathVector and generateTreeMathVectors above already
// carry the arities that contract publishes, so registering is an init() and a
// one-line deletion once the file lands, and
// TestTreeMathVectorRegistrationFollowsTheHarness below fails the day it does.
func TestTreeMathVectors(t *testing.T) {
	// the count is pinned here as well as inside loadTreeMathVectors because
	// this loop does not go through it: a raw corpus that decoded to nothing
	// would leave the harness's own entry point run zero times, and the loop
	// beneath would still be the only thing that noticed.
	rawEntries := LoadVectorFile(t, treeMathVectorFile)
	if len(rawEntries) != treeMathVectorCount {
		t.Fatalf("%s holds %d entries, want %d: a gate over a short corpus asserts nothing", treeMathVectorFile, len(rawEntries), treeMathVectorCount)
	}
	for _, rawEntry := range rawEntries {
		verifyTreeMathVector(t, rawEntry)
	}

	vectors := loadTreeMathVectors(t)

	refusals, matches := 0, 0
	for _, v := range vectors {
		entryRefusals, entryMatches := checkTreeMathEntry(t, v)
		refusals += entryRefusals
		matches += entryMatches
	}

	countCases := []struct {
		label string
		got   int
		want  int
	}{
		{label: "refusals", got: refusals, want: 2066},
		{label: "matches", got: matches, want: 6078},
		// implied by the two rows above rather than independent of them, and
		// kept because 8144 is the number spec A's family-1 row publishes and
		// the one a reader comes here to find.
		{label: "assertions", got: refusals + matches, want: 8144},
	}
	for _, c := range countCases {
		if c.got != c.want {
			t.Errorf("confirmed %s across the family: %d, want %d", c.label, c.got, c.want)
		}
	}
}

// the generate direction against the verify direction, and then both against
// the vendored bytes.
//
// the first half composes this file with itself and can only catch a generator
// that disagrees with its own reader. the second half is the assertion that
// makes generating worth doing at all: the family this package computes from
// nothing but a leaf count has to equal, field for field and null for null, the
// family the mlswg published. that is the same evidence the runner above gets,
// arrived at from the other side.
func TestTreeMathVectorGenerateThenVerify(t *testing.T) {
	var generated []json.RawMessage
	if err := json.Unmarshal(generateTreeMathVectors(t), &generated); err != nil {
		t.Fatalf("decode the generated family: %v", err)
	}
	if len(generated) != treeMathVectorCount {
		t.Fatalf("generated %d entries, want %d", len(generated), treeMathVectorCount)
	}

	for i, rawEntry := range generated {
		verifyTreeMathVector(t, rawEntry)

		// the field names are read off the generated bytes rather than through
		// the entry type, because a struct round trip structurally cannot fail
		// on them: a generator that wrote the wrong names would be read back
		// through the same tags and agree with itself at every value.
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(rawEntry, &fields); err != nil {
			t.Fatalf("decode generated entry %d as fields: %v", i, err)
		}
		if len(fields) != len(treeMathVectorFields) {
			t.Fatalf("generated entry %d: %d fields, want %d", i, len(fields), len(treeMathVectorFields))
		}
		for _, field := range treeMathVectorFields {
			if _, ok := fields[field]; !ok {
				t.Fatalf("generated entry %d: missing field %s", i, field)
			}
		}
	}

	vendored := loadTreeMathVectors(t)
	compared := 0
	for i := range vendored {
		var got treeMathVector
		if err := json.Unmarshal(generated[i], &got); err != nil {
			t.Fatalf("decode generated entry %d: %v", i, err)
		}
		want := vendored[i]
		if got.NLeaves != want.NLeaves || got.NNodes != want.NNodes || got.Root != want.Root {
			t.Fatalf("entry %d: generated (%d, %d, %d), vendored (%d, %d, %d)", i,
				got.NLeaves, got.NNodes, got.Root, want.NLeaves, want.NNodes, want.Root)
		}
		columns := []struct {
			name string
			got  []*uint32
			want []*uint32
		}{
			{name: "left", got: got.Left, want: want.Left},
			{name: "right", got: got.Right, want: want.Right},
			{name: "parent", got: got.Parent, want: want.Parent},
			{name: "sibling", got: got.Sibling, want: want.Sibling},
		}
		for _, column := range columns {
			if len(column.got) != len(column.want) {
				t.Fatalf("entry %d %s: %d entries, want %d", i, column.name, len(column.got), len(column.want))
			}
			for j := range column.want {
				if (column.got[j] == nil) != (column.want[j] == nil) {
					t.Errorf("entry %d %s node %d: presence differs", i, column.name, j)
					continue
				}
				if column.got[j] != nil && *column.got[j] != *column.want[j] {
					t.Errorf("entry %d %s node %d: %d, want %d", i, column.name, j, *column.got[j], *column.want[j])
					continue
				}
				compared += 1
			}
		}
	}

	// cells that agreed with the vendored column, counted rather than taken
	// from the loop bounds: every length above is compared generated against
	// vendored, so two empty columns satisfy all of them, and 8144 is what says
	// the corpus was really on the other side of the comparison.
	if compared != 8144 {
		t.Errorf("generated cells agreeing with the vendored family: %d, want 8144", compared)
	}
}

// every go file of this package, parsed.
//
// the package is read as syntax rather than as text, which is the one thing
// crypto_forbidden_test.go's line-based scanner deliberately does not do. its
// tradeoff does not carry here. it over-reports, and a ban list that
// over-reports is merely noisy; this one under-reports, because the failure
// messages below have to quote the call they are asking for and a text scan
// then finds that quotation and concludes the call is already there. measured:
// the text version of this check passed with the registry present and nothing
// registered, matching its own error message. a call expression is not a string
// literal to a parser.
//
// an empty glob is fatal rather than an empty answer. every question asked of
// this scan is answered "found nothing" today, so a scan that read no file at
// all would agree with the package it is checking.
func parsePackageSources(t *testing.T, fileSet *token.FileSet) []*ast.File {
	t.Helper()
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob the package sources: %v", err)
	}
	parsedFiles := make([]*ast.File, 0, len(sources))
	for _, source := range sources {
		parsed, err := parser.ParseFile(fileSet, source, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", source, err)
		}
		parsedFiles = append(parsedFiles, parsed)
	}
	if len(parsedFiles) == 0 {
		t.Fatal("the glob read no go file in this package: the scan is broken, not the package")
	}
	return parsedFiles
}

// the package-level names one parsed file declares, added to names.
//
// a var counts alongside a func because the registry is a name, not a keyword:
// a var holding a func value declares RegisterVectorFamily as surely as a func
// declaration does, and a scan that recognised only func declarations would
// read the registry as absent while its call sites were being counted. that
// reads as "no harness yet" for as long as the harness is written that way,
// which is silence in the one direction this file exists to break.
func packageDeclarations(parsed *ast.File, names map[string]int) {
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			// a method is a name on its receiver, not on the package.
			if typed.Recv == nil {
				names[typed.Name.Name] += 1
			}
		case *ast.GenDecl:
			for _, spec := range typed.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range valueSpec.Names {
					names[name.Name] += 1
				}
			}
		}
	}
}

// where callee is called with carried named somewhere inside its arguments.
//
// the pairing is the whole of it. counting calls of the registry by its own
// name answers "did anything register", not "did family 1 register", and those
// two answers part company the moment a second family lands - which, for a
// harness that vendors sixteen of them, is the normal case and not the edge
// one. what makes a registration this family's is the function it hands over,
// so that is what is looked for, and it is looked for anywhere in the argument
// rather than at one field of one literal: through the composite literal the
// message below prescribes, and equally through a wrapper or a literal built
// under a different field name.
func callsCarrying(fileSet *token.FileSet, parsed *ast.File, callee string, carried string) []token.Position {
	positions := []token.Position{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok || name.Name != callee {
			return true
		}
		for _, argument := range call.Args {
			if mentionsIdent(argument, carried) {
				positions = append(positions, fileSet.Position(call.Pos()))
				break
			}
		}
		return true
	})
	return positions
}

// whether name appears in the subtree as an identifier.
//
// as an identifier and not as text, for the reason the parse above gives: both
// names this scan looks for are quoted in the failure messages below, and a
// matcher that read string literals would find the test's own instructions.
func mentionsIdent(node ast.Node, name string) bool {
	found := false
	ast.Inspect(node, func(inner ast.Node) bool {
		if ident, ok := inner.(*ast.Ident); ok && ident.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// where name is handed over as a value rather than called or declared.
//
// this does not decide whether family 1 is registered - the scan above does
// that, and it claims only a registration it can watch reach the registry,
// which is the precision that keeps a second family's registration from
// counting as this one's. this is the other side of that trade, and it is here
// so that the trade is paid in an accurate message rather than in a misleading
// one: a verifier handed to something this scan did not recognise is not an
// unregistered family, and telling a reader it is sends them looking for a
// registration that is already written. enumerated, the shapes that land here
// are a family built into a variable first and a family returned by a
// constructor.
func identValueUses(fileSet *token.FileSet, parsed *ast.File, name string) []token.Position {
	positions := []token.Position{}
	// the positions an identifier of this name can occupy without being a value
	// handed over: the callee of a call, the name of a declaration, the field
	// half of a selector. marked on the way down, which reaches each of them
	// before the identifier itself.
	notAValue := map[*ast.Ident]bool{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.CallExpr:
			if ident, ok := typed.Fun.(*ast.Ident); ok {
				notAValue[ident] = true
			}
		case *ast.FuncDecl:
			notAValue[typed.Name] = true
		case *ast.ValueSpec:
			for _, ident := range typed.Names {
				notAValue[ident] = true
			}
		case *ast.SelectorExpr:
			notAValue[typed.Sel] = true
		case *ast.Ident:
			if typed.Name == name && !notAValue[typed] {
				positions = append(positions, fileSet.Position(typed.Pos()))
			}
		}
		return true
	})
	return positions
}

// whether a package-level declaration of name still lists the integer literal
// want.
//
// this is the second half of the change the message below asks for, and it is
// the half no build failure and no other test could observe: a family whose
// number is still in expectedPendingFamilies is one the harness's own runner
// skips, so a family 1 that is registered and still listed is executed by
// nobody while both the registration and the vectors job look done. the value
// is read as a subtree rather than as a slice of elements, so that a list which
// lands as a map keyed by number is read the same way.
func declarationLists(parsed *ast.File, name string, want string) bool {
	listed := false
	for _, declaration := range parsed.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range general.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, declared := range valueSpec.Names {
				if declared.Name != name || i >= len(valueSpec.Values) {
					continue
				}
				ast.Inspect(valueSpec.Values[i], func(node ast.Node) bool {
					literal, ok := node.(*ast.BasicLit)
					if ok && literal.Kind == token.INT && literal.Value == want {
						listed = true
					}
					return !listed
				})
			}
		}
	}
	return listed
}

// the registration the messages below ask for, in the shape the scan above
// reads without being taught anything. it is a string literal and so is not a
// call: the scan looks for call expressions, which is what lets this test quote
// the code it wants without finding its own quotation and concluding the code
// is already there.
const treeMathVectorRegistration = `func init() {
	RegisterVectorFamily(VectorFamily{
		Number:   1,
		Name:     "tree-math",
		File:     treeMathVectorFile,
		Slice:    "A1",
		Verify:   verifyTreeMathVector,
		Generate: generateTreeMathVectors,
	})
}`

// a package holding both shapes each detector above has to tell apart: one it
// must find and one it must not. it is parsed and never compiled, so the names
// in it are the harness's rather than this package's.
//
// this is the control the first version of this test did not have, and the
// registration pair is the finding that produced it. counted by the name of the
// registry, this source scores two calls, and family 1 is one of them only
// because family 2 is also there - so the same count with family 1's line
// deleted is still two, and the test reports the package registered.
const vectorHarnessControlSource = `package mls

var RegisterVectorFamily = func(family VectorFamily) {}

func init() {
	RegisterVectorFamily(VectorFamily{Number: 2, Verify: verifyCryptoBasicsVector})
	RegisterVectorFamily(VectorFamily{Number: 1, Verify: verifyTreeMathVector})
}

var expectedPendingFamilies = []int{1, 2}
var expectedSettledFamilies = []int{2}
`

// the deferred half of this task, recorded where it will be executed rather
// than only in a plan.
//
// registering family 1 needs the shared vector harness, which owns
// VectorFamily, RegisterVectorFamily and expectedPendingFamilies in
// mls/vectors_test.go. that file is not in this tree, so this plan neither
// registers nor declares a guessed copy of it. the day it lands, the stand-in
// LoadVectorFile above is a duplicate declaration and the package stops
// building, which is the signal to delete the stand-in; nothing in that signal
// mentions family 1, and a package that builds again looks finished. this is
// what says it is not: it fails from the moment the registry exists until the
// registration is written, and then it passes and stays passed.
//
// what it looks for is family 1's own verifier reaching the registry, and not a
// call of the registry by name. the first version asked the second question and
// could not fail in the case it was written for: with the registry present,
// family 2 registered and family 1 not, it passed. so did the shape a registry
// file usually carries all by itself, a test of its own registry - one call of
// RegisterVectorFamily anywhere in the package was enough for it to report
// family 1 registered. both are the state named above, reported green.
func TestTreeMathVectorRegistrationFollowsTheHarness(t *testing.T) {
	fileSet := token.NewFileSet()
	parsedFiles := parsePackageSources(t, fileSet)

	declarations := map[string]int{}
	registrations := []token.Position{}
	loaderCalls := []token.Position{}
	valueUses := []token.Position{}
	stillPending := false
	for _, parsed := range parsedFiles {
		packageDeclarations(parsed, declarations)
		registrations = append(registrations, callsCarrying(fileSet, parsed, "RegisterVectorFamily", "verifyTreeMathVector")...)
		loaderCalls = append(loaderCalls, callsCarrying(fileSet, parsed, "LoadVectorFile", "treeMathVectorFile")...)
		valueUses = append(valueUses, identValueUses(fileSet, parsed, "verifyTreeMathVector")...)
		if declarationLists(parsed, "expectedPendingFamilies", "1") {
			stillPending = true
		}
	}

	// the positive control against this package. every answer the scan gives
	// below is "found nothing", and "found nothing" is also what a broken scan
	// reports, so none of them is trusted until the same two detectors are run
	// against a symbol this package certainly declares once and certainly calls.
	// that stays true after the harness lands: the stand-in is deleted and the
	// same declaration arrives from vectors_test.go, with the callers untouched.
	if declarations["LoadVectorFile"] != 1 {
		t.Fatalf("the declaration scan found %d declarations of LoadVectorFile, want 1: the scan is broken, not the package", declarations["LoadVectorFile"])
	}
	if len(loaderCalls) == 0 {
		t.Fatal("the call scan found no call of LoadVectorFile carrying treeMathVectorFile: the scan is broken, not the package")
	}

	// the control above says the scan finds something. this says it finds the
	// right thing, which is the harder half and the one that was wrong: the
	// source holds a registration this scan must claim and one it must not, in a
	// package that declares its registry in the shape the declaration scan above
	// would otherwise miss.
	controlSet := token.NewFileSet()
	control, err := parser.ParseFile(controlSet, "control.go", vectorHarnessControlSource, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse the control source: %v", err)
	}
	controlDeclarations := map[string]int{}
	packageDeclarations(control, controlDeclarations)
	controlRegistrations := callsCarrying(controlSet, control, "RegisterVectorFamily", "verifyTreeMathVector")
	if len(controlRegistrations) != 1 {
		t.Fatalf("the registration scan found %d family-1 registrations in a control holding that one and family 2's, want 1: the scan is broken, not the package", len(controlRegistrations))
	}
	controlCases := []struct {
		label string
		got   bool
		want  bool
	}{
		{label: "a registry declared as a var is a declaration", got: controlDeclarations["RegisterVectorFamily"] == 1, want: true},
		{label: "a verifier handed to a literal is handed over", got: len(identValueUses(controlSet, control, "verifyTreeMathVector")) == 1, want: true},
		{label: "a registry declared and called is not handed over", got: len(identValueUses(controlSet, control, "RegisterVectorFamily")) > 0, want: false},
		{label: "a pending list holding 1 is read as pending", got: declarationLists(control, "expectedPendingFamilies", "1"), want: true},
		{label: "a neighbouring list without 1 is not", got: declarationLists(control, "expectedSettledFamilies", "1"), want: false},
	}
	for _, c := range controlCases {
		if c.got != c.want {
			t.Fatalf("control: %s: %t, want %t: the scan is broken, not the package", c.label, c.got, c.want)
		}
	}

	declared := declarations["RegisterVectorFamily"] > 0

	// the accurate half of the answer first. this scan claims a registration
	// only where it can watch verifyTreeMathVector reach the registry, so a
	// family built into a variable first, or returned by a constructor, is one
	// it declines to claim rather than one it refuses. the verdict is the same
	// and deliberately so - a shape this test cannot read is not a shape it
	// should pass - but the reason a reader is given has to be the true one, or
	// the obvious repair is to delete the test.
	if declared && len(registrations) == 0 && len(valueUses) > 0 {
		t.Fatalf("family 1's verifier is handed over at %s, and this scan cannot see it reach\n"+
			"RegisterVectorFamily. it claims only a registration that carries\n"+
			"verifyTreeMathVector into the call, so that another family's registration cannot\n"+
			"count as this one's - which is the failure it was rewritten for. write the\n"+
			"registration in the shape below, or teach this scan the shape you used. do not\n"+
			"delete the check.\n\n"+
			"%s\n\n"+
			"and delete 1 from expectedPendingFamilies in the same commit: registered while\n"+
			"still pending is the state where the vectors job skips family 1 and reports green.",
			valueUses[0], treeMathVectorRegistration)
	}
	if declared && len(registrations) == 0 {
		t.Fatalf("the vector harness registry has landed and family 1 is still unregistered.\n"+
			"add to %s:\n\n"+
			"%s\n\n"+
			"and delete 1 from expectedPendingFamilies in the same commit: registered while\n"+
			"still pending is the state where the vectors job skips family 1 and reports green.",
			treeMathVectorRunnerFile, treeMathVectorRegistration)
	}
	if len(registrations) > 0 && stillPending {
		t.Fatalf("family 1 is registered at %s and expectedPendingFamilies still lists 1.\n"+
			"delete 1 from that list in this commit: registered while still pending is the\n"+
			"state the registration above was written to leave behind, and the vectors job\n"+
			"reports green from it with family 1 never executed.",
			registrations[0])
	}

	// a call of an unqualified name this package does not declare does not
	// compile, so this arm cannot fire on a package that builds. it is the two
	// halves of the scan disagreeing - the call half seeing a name the
	// declaration half cannot find - which is what the var-declared registry
	// produced before the declaration half learned to read vars. it is kept for
	// that reason and reports the position of the call rather than a file named
	// in advance, because the call it is describing need not be in this file.
	if len(registrations) > 0 && !declared {
		t.Fatalf("%s registers family 1 with a harness this package does not declare", registrations[0])
	}
}
