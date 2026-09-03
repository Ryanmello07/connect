// The commit fixture corpus, and the gate that measures it.
//
// THREE CONSECUTIVE ROUNDS OF THIS DOOR HAD ONE ROOT CAUSE AND IT WAS NOT IN THE DOOR. "Every
// fixture carries exactly one Update" made every loop narrowable to element zero; "every fixture
// makes PostTree a Clone of PreTree" made three tree reads swappable; "every fixture puts the
// committer at leaf 0" made `Sender: self.Committer` indistinguishable from the constant
// `LeafIndex(0)`. Each round repaired the comparison it was handed and left the corpus that hid it,
// so the next round found the next constant.
//
// A CORPUS THAT DRIFTS BACK TO CONSTANTS IS THE DEFECT, so it is measured here rather than
// remembered. What the gate below asserts is one property stated once: no dimension of a commit
// validation input is the SAME VALUE across the whole corpus. A dimension that is constant is a
// dimension on which the production code and that constant are the same program, which is what
// "the fixtures cannot see it" means and is the only thing all three rounds had in common.
//
// AND THE DIMENSIONS ARE DERIVED RATHER THAN LISTED. A list of three properties is the enumeration
// this project has been caught by fourteen times; what is enumerated here is the CORPUS -- one row
// per fixture, held to the set of fixtures the package declares in both directions -- while the
// dimensions are read off the values those fixtures produce, by walking a CommitValidationInput
// for every LeafIndex it carries and keying each by the path that reached it. A leaf index is the
// right class because it is what this door's rules and the apply door decide off: which leaf
// commits, which leaf is judging, which leaf a proposal is attributed to, which leaf it removes.
// A fifth leaf-index-valued field added anywhere under the input is measured here without anybody
// editing this file.
package mls

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"math"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// the two fixtures the corpus was missing
// ---------------------------------------------------------------------------

// testCommitInputOverTheTreeItsProposalsBuild is the fixture whose two trees are not one tree.
//
// testCommitInput hands PostTree a CLONE of PreTree, which is what every fixture in this package
// took, and a clone is equal to what it was cloned from: a rule reading either answers the same
// thing, so three tree reads of validate_commit.go could be pointed at the other tree with the
// whole suite green. Here the post tree is what ApplyProposals actually builds from the list, so
// the two answer differently -- the removes truncate the group -- and a rule stated over the wrong
// one is a rule that reports on an epoch this commit is not in.
func testCommitInputOverTheTreeItsProposalsBuild(t *testing.T,
	crypto CryptoProvider) *CommitValidationInput {

	t.Helper()
	in, members := testFullCommitInput(t, crypto)
	testCommitProposals(t, in, testRemoveOf(LeafIndex(3)), testRemoveOf(LeafIndex(2)))
	applied, err := ApplyProposals(in.PreTree, in.Context, in.Own, in.List)
	if err != nil {
		t.Fatalf("ApplyProposals to build the post tree: %v", err)
	}
	in.PostTree = applied.Tree
	// the path is fitted against the POST tree, which is the tree ValSem202 is stated over, so it
	// has to be re-fitted once the removes have shortened the committer's filtered direct path
	testFitCommitPath(t, crypto, in, members[in.Committer])
	if in.PostTree.LeafCount() >= in.PreTree.LeafCount() {
		t.Fatalf("the post tree is %d leaves wide and the pre tree %d; this fixture exists to make the two answer differently",
			in.PostTree.LeafCount(), in.PreTree.LeafCount())
	}
	return in
}

// testWideCommitterLeaf is the leaf the wide fixture commits from, and testWideOwnLeaf is the leaf
// judging it. Both are above what one octet holds, which is the whole point of them.
//
// A COMPARISON NARROWER THAN A LeafIndex IS EXACT OVER EVERY GROUP WHOSE LEAVES FIT IN ONE OCTET,
// and every group in this package's fixtures did: measured, the corpus held exactly one leaf index
// above 255 and it was a value a probe wrote by hand. So the Sender comparator could be truncated
// to its low octet with the entire suite green. A group whose members really do sit above 255 is
// what makes that truncation a wrong answer rather than an unexercised one.
const (
	testWideCommitterLeaf = LeafIndex(258)
	testWideOwnLeaf       = LeafIndex(257)
)

// testWideGroupLeaves is the group's width, and it is a POWER OF TWO on purpose: a ratchet tree
// grows by doubling, so a group of any other size ends in blank nodes and ValSem300 refuses the
// post tree it exports.
const testWideGroupLeaves = 512

// testWideCommitInput is testFullCommitInput over a group wide enough that its leaf indices do not
// fit in one octet.
func testWideCommitInput(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
	t.Helper()
	names := make([]string, 0, testWideGroupLeaves)
	for i := 0; i < testWideGroupLeaves; i += 1 {
		names = append(names, fmt.Sprintf("wide%d", i))
	}
	tree, members := testTreeWith(t, crypto, names...)
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
	in.Committer = testWideCommitterLeaf
	in.Own = testWideOwnLeaf
	// the inline entries are attributed to THIS fixture's committer rather than to
	// testCommitterLeaf, which is (*ProposalCache).Resolve's rule: a by-value entry of a commit's
	// vector resolves to whoever sent the commit.
	removes := []CachedProposal{testRemoveOf(LeafIndex(1)), testRemoveOf(testWideOwnLeaf - 1)}
	for i := range removes {
		removes[i].Sender = in.Committer
	}
	testCommitProposals(t, in, removes...)
	testFitCommitPath(t, crypto, in, members[in.Committer])
	if failure := ValidateCommit(in); failure != nil {
		t.Fatalf("ValidateCommit refused the wide fixture: %v; a fixture no door accepts measures nothing about the doors",
			failure)
	}
	return in
}

// ---------------------------------------------------------------------------
// the corpus
// ---------------------------------------------------------------------------

// commitFixtureCorpus is every fixture of this package that answers a commit validation input,
// keyed by the name it is declared under.
//
// KEYED BY THE DECLARED NAME because that is what the derivation below can read. Several of these
// builders take arguments -- a tree, a list, an input to lead -- and the row supplies the ordinary
// ones, so what is measured is the fixture as its callers use it rather than a zero value of it.
func commitFixtureCorpus() map[string]func(*testing.T, CryptoProvider) *CommitValidationInput {
	return map[string]func(*testing.T, CryptoProvider) *CommitValidationInput{
		"testCommitInput": func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
			tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
			in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
			testCommitProposals(t, in, testRemoveOf(LeafIndex(2)))
			return in
		},
		"testFullCommitInput": func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
			in, _ := testFullCommitInput(t, crypto)
			return in
		},
		"testCommitCarryingOneOfEveryBucket": testCommitCarryingOneOfEveryBucket,
		"testCommitCarryingOneOfEveryBucketAndItsMembers": func(t *testing.T,
			crypto CryptoProvider) *CommitValidationInput {
			in, _ := testCommitCarryingOneOfEveryBucketAndItsMembers(t, crypto)
			return in
		},
		"testCommitCarryingAnInnocentRemoveFirst": testCommitCarryingAnInnocentRemoveFirst,
		"testCommitNamingACachedProposal":         testCommitNamingACachedProposal,
		"testCommitNamingACachedRemove": func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
			in, _, _ := testCommitNamingACachedRemove(t, crypto, LeafIndex(2))
			return in
		},
		"testCommitWideEnoughToPrice": testCommitWideEnoughToPrice,
		"testCommitLedBy": func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
			return testCommitLedBy(t, testCommitCarryingOneOfEveryBucket(t, crypto),
				testRemoveOf(LeafIndex(3)))
		},
		"testCommitInputOverTheTreeItsProposalsBuild": testCommitInputOverTheTreeItsProposalsBuild,
		"testWideCommitInput":                        testWideCommitInput,
	}
}

// commitFixtureBuildersInSource is every function this package's test files declare that ANSWERS a
// commit validation input.
//
// THE DERIVATION IS OVER THE RESULT TYPE and not over a naming convention, because the result type
// is what makes a function a fixture for this door: a helper that takes an input and edits it --
// testCommitProposals, testFitCommitPath, testRestoreCachedEntries -- is not a corpus entry, it is
// something a corpus entry is built out of, and none of those answers one.
//
// WHAT IT BUYS is the direction the three rounds kept losing: a NEW fixture is in the corpus the
// moment it is declared, so the next person who adds one that puts the committer back on leaf 0
// finds out here rather than three rounds later. The reverse direction is worth as much -- a row
// naming a builder the package no longer declares is a row measuring nothing.
func commitFixtureBuildersInSource(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read this package's own directory: %v", err)
	}
	fileSet := token.NewFileSet()
	found := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, declared := range file.Decls {
			function, isFunction := declared.(*ast.FuncDecl)
			if !isFunction || function.Recv != nil || function.Type.Results == nil {
				continue
			}
			for _, result := range function.Type.Results.List {
				pointer, isPointer := result.Type.(*ast.StarExpr)
				if !isPointer {
					continue
				}
				named, isNamed := pointer.X.(*ast.Ident)
				if isNamed && named.Name == "CommitValidationInput" {
					found = append(found, function.Name.Name)
					break
				}
			}
		}
	}
	slices.Sort(found)
	return found
}

// TestEveryCommitFixtureThisPackageDeclaresIsInTheCorpus holds the corpus to the package, in both
// directions.
func TestEveryCommitFixtureThisPackageDeclaresIsInTheCorpus(t *testing.T) {
	declared := commitFixtureBuildersInSource(t)
	if len(declared) == 0 {
		t.Fatal("no function in this package's test files answers a *CommitValidationInput, so the derivation read something other than the package and the corpus below is a list of names")
	}
	corpus := commitFixtureCorpus()
	held := []string{}
	for name := range corpus {
		held = append(held, name)
	}
	slices.Sort(held)
	if !slices.Equal(declared, held) {
		t.Errorf("this package declares the commit fixtures %v and the corpus measures %v; a fixture with no row is one nothing holds to being able to separate a value from a constant, and a row naming a fixture the package no longer declares is a row measuring nothing",
			declared, held)
	}
}

// ---------------------------------------------------------------------------
// what a fixture is measured on
// ---------------------------------------------------------------------------

// commitCorpusLeafDimensions answers every LeafIndex a commit validation input carries, keyed by
// the PATH that reached it.
//
// WALKED RATHER THAN LISTED, which is this file's whole argument: the fields a fixture can be
// degenerate in are whatever fields exist, and a walk over the value finds a leaf index moved one
// level down or added to a type nobody edited this file for.
//
// SLICES AGGREGATE UNDER ONE PATH -- "List[].Sender" and not "List[2].Sender" -- because the
// dimension is the FIELD and not the position. A corpus in which every list's second entry is sent
// from leaf 1 while its first varies is not degenerate in the sender; a corpus in which no entry
// anywhere carries a second value is.
//
// TWO THINGS ARE DELIBERATELY NOT WALKED. An interface field is skipped, because what hangs off
// Crypto is a provider rather than part of this commit's geometry. A *RatchetTree is skipped
// because a tree carries a leaf index for every member it has, so walking one would swamp every
// other dimension with the group's own arithmetic -- and what matters about the two trees is
// whether they DIFFER, which the gate asserts separately and directly.
func commitCorpusLeafDimensions(in *CommitValidationInput) map[string][]LeafIndex {
	out := map[string][]LeafIndex{}
	leafIndex := reflect.TypeFor[LeafIndex]()
	tree := reflect.TypeFor[*RatchetTree]()
	var walk func(value reflect.Value, path string, depth int)
	walk = func(value reflect.Value, path string, depth int) {
		// a bound rather than a visited set: nothing under a commit validation input is
		// self referential, and a bound cannot silently drop a path a pointer set would
		if depth > 12 || !value.IsValid() || value.Type() == tree {
			return
		}
		if value.Type() == leafIndex {
			out[path] = append(out[path], LeafIndex(value.Uint()))
			return
		}
		switch value.Kind() {
		case reflect.Pointer:
			if !value.IsNil() {
				walk(value.Elem(), path, depth+1)
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < value.Len(); i += 1 {
				walk(value.Index(i), path+"[]", depth+1)
			}
		case reflect.Struct:
			for i := 0; i < value.NumField(); i += 1 {
				field := value.Type().Field(i)
				if !field.IsExported() {
					continue
				}
				under := field.Name
				if path != "" {
					under = path + "." + field.Name
				}
				walk(value.Field(i), under, depth+1)
			}
		}
	}
	walk(reflect.ValueOf(in), "", 0)
	// the commit order is behind an unexported field with one accessor, which is what makes a
	// ProposalList hold one representation -- so it is walked through the accessor
	if in != nil && in.List != nil {
		walk(reflect.ValueOf(in.List.All()), "List", 0)
	}
	return out
}

// TestTheCommitFixtureCorpusSeparatesEveryLeafItDecidesOff is the gate the three rounds needed.
//
// FOUR CLAIMS, and the first is the class while the other three are the three shapes that class
// took on this door.
//
//	no leaf-index dimension is one value across the corpus  -- the class itself
//	the widest leaf index does not fit in one octet         -- the Sender comparator's width
//	a commit order longer than one entry exists             -- a loop against a read of its head
//	one fixture's two trees answer differently              -- PreTree against PostTree
//
// THE LAST THREE ARE NOT INSTANCES OF THE FIRST and are stated separately rather than folded into
// it. A list's length and a tree's hash are not leaf indices, so a walk for leaf indices cannot see
// them; each is named here with the mutation it exists to make fail, which is what the first claim
// gives every other dimension for free.
func TestTheCommitFixtureCorpusSeparatesEveryLeafItDecidesOff(t *testing.T) {
	crypto := testCrypto(t)
	corpus := commitFixtureCorpus()
	if len(corpus) == 0 {
		t.Fatal("the corpus is empty, so every claim below holds vacuously")
	}

	dimensions := map[string]map[LeafIndex][]string{}
	lengths := map[int][]string{}
	widest := LeafIndex(0)
	widestIn := ""
	treesDiffer := []string{}
	built := 0
	for _, name := range slices.Sorted(maps.Keys(corpus)) {
		// EACH FIXTURE IS BUILT INSIDE ITS OWN SUBTEST, and that is not tidiness. A builder
		// answers t.Fatalf when its own precondition stops holding, and a Fatalf in the middle
		// of this loop takes the whole test with it -- so the four claims below would report
		// nothing about the other ten fixtures, and the claim a corpus regression actually
		// broke would never be printed. One red row per fixture, and the measurement carries on
		// over the ones that built.
		var in *CommitValidationInput
		t.Run(name, func(t *testing.T) { in = corpus[name](t, crypto) })
		if in == nil {
			continue
		}
		built += 1
		for path, values := range commitCorpusLeafDimensions(in) {
			if dimensions[path] == nil {
				dimensions[path] = map[LeafIndex][]string{}
			}
			for _, at := range values {
				dimensions[path][at] = append(dimensions[path][at], name)
				if at > widest {
					widest, widestIn = at, name
				}
			}
		}
		lengths[len(in.List.All())] = append(lengths[len(in.List.All())], name)
		same, err := testTreesHashAlike(t, crypto, in.PreTree, in.PostTree)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !same {
			treesDiffer = append(treesDiffer, name)
		}
	}

	if built < len(corpus) {
		t.Errorf("%d of the %d fixtures in this corpus could not be built, so the claims below are stated over the rest of it",
			len(corpus)-built, len(corpus))
	}
	if len(dimensions) == 0 {
		t.Fatal("the walk found no leaf index anywhere in the corpus, so it read something other than these inputs")
	}
	for _, path := range slices.Sorted(maps.Keys(dimensions)) {
		if len(dimensions[path]) > 1 {
			continue
		}
		only := slices.Sorted(maps.Keys(dimensions[path]))[0]
		t.Errorf("every fixture in this corpus carries %s = %d, so that field and the constant %d are the same program and no test here can tell a rule reading the field from a rule reading the constant. Give one fixture a different value for it",
			path, only, only)
	}
	t.Logf("%d fixtures, %d leaf dimensions, widest leaf index %d (in %s), commit orders of %v",
		len(corpus), len(dimensions), widest, widestIn, slices.Sorted(maps.Keys(lengths)))

	// the narrowest integer width there is, which is what a truncated comparator collapses to
	if octet := LeafIndex(math.MaxUint8); widest <= octet {
		t.Errorf("the widest leaf index in this corpus is %d and one octet holds %d, so a comparison of leaf indices one octet wide is exact over every input here. Measured: the join's Sender comparator truncated to its low octet left the whole suite green",
			widest, octet)
	}
	if !slices.ContainsFunc(slices.Sorted(maps.Keys(lengths)), func(at int) bool { return at > 1 }) {
		t.Errorf("no fixture in this corpus carries more than one proposal -- the lengths are %v -- so a loop over the commit order and a read of its head answer alike, which is the shape four bypasses of this door took",
			slices.Sorted(maps.Keys(lengths)))
	}
	if len(treesDiffer) == 0 {
		t.Errorf("every fixture in this corpus hands PostTree a tree that hashes the same as PreTree, so a rule stated over either answers the same thing and the two fields are one. Measured: three tree reads of validate_commit.go could be swapped with the whole suite green")
	}
}

// testTreesHashAlike answers whether two trees are the same tree by the one identity a ratchet tree
// has, which is its tree hash -- the value a GroupContext carries and a transcript covers.
func testTreesHashAlike(t *testing.T, crypto CryptoProvider, first *RatchetTree,
	second *RatchetTree) (bool, error) {

	t.Helper()
	if first == nil || second == nil {
		return false, fmt.Errorf("a fixture carries no tree in one of its two tree fields")
	}
	before, err := first.TreeHash(crypto)
	if err != nil {
		return false, fmt.Errorf("the pre tree's hash: %w", err)
	}
	after, err := second.TreeHash(crypto)
	if err != nil {
		return false, fmt.Errorf("the post tree's hash: %w", err)
	}
	return slices.Equal(before, after), nil
}
