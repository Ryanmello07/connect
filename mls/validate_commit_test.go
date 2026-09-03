// The gate over RFC 9420 section 12.4.2 commit validation.
//
// Two properties run through every test here and neither is the plan's.
//
// EACH RULE OWES A FIXTURE WHOSE FAULT IS NOT AT ELEMENT ZERO. Five of the rules in
// validate_commit.go loop -- ValSem200 over the removes, ValSem203 over the path's nodes,
// ValSem206 over the adds and the updates, ValSem209 over the installed extensions and over the
// members, CheckErrata8815 over the ProposalOrRef vector -- and a fixture carrying one entry
// cannot tell a loop from a read of its head. p7 tasks 7 and 8 shipped two rules narrowed to
// updates[0] with the whole suite green for exactly that reason, so every loop below is driven
// with the offender behind at least one innocent entry.
//
// AND EACH RULE OWES A NEGATIVE ON EVERY OTHER SENTINEL. errors.Is cannot tell two rules apart
// when they answer one value, so TestEachCommitRuleAnswersOnlyItsOwnSentinel builds the input for
// each code and requires the whole roster except that code's own value -- and the one sanctioned
// wrap -- not to answer.
package mls

import (
	"crypto/subtle"
	"errors"
	"go/ast"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const commitValidationFile = "validate_commit.go"

// commitValidationOwnedErrors is every sentinel validate_commit.go declares.
//
// Held against the file's own declarations in BOTH directions by
// TestCommitValidationOwnedErrorsIsEveryErrorItsFileDeclares, so a tenth sentinel added there with
// no row here fails rather than sitting outside every sweep below, and a row here for a name the
// file no longer declares fails too.
var commitValidationOwnedErrors = map[string]error{
	"errNilCommitValidationInput":   errNilCommitValidationInput,
	"errNilCommit":                  errNilCommit,
	"errCommitProposalsNotResolved": errCommitProposalsNotResolved,
	"errCommitExtensionsNotApplied": errCommitExtensionsNotApplied,
	"errMissingPath":                errMissingPath,
	"errPathLeafKeyUnchanged":       errPathLeafKeyUnchanged,
	"errBadConfirmationTag":         errBadConfirmationTag,
	"errCommitterNotMember":         errCommitterNotMember,
	"errProfileExternalSender":      errProfileExternalSender,
	"errProfileGroupExtension":      errProfileGroupExtension,
	"errUnregisteredGroupExtension": errUnregisteredGroupExtension,
}

// commitValidationBorrowedErrors is every sentinel a rule of validate_commit.go can answer that
// some other file declares.
//
// It is here because the exclusivity sweep has to run over the WHOLE class a commit refusal can
// come from, and half of that class is deliberately not this file's: ValSem200 delegates to
// section 12.2's body, ValSem207 to the tree's walk, CheckErrata8815 to the cache's value, and
// ValSem202 wraps whatever the tree math answered. A sweep bounded to one file's declarations
// would report clean over exactly the rules this file was careful not to give values of their own.
//
// IT WAS A LIST OF TWELVE NAMES HELD BY NOTHING, which is rule 5 inside the gate written to
// enforce rule 5. It understated the class by more than half -- ErrMalformedExtension,
// ErrTreeMalformed, ErrNodeTypeMismatch, ErrNilCryptoProvider, errNilProposalList,
// errNilRatchetTree, ErrNilGroupContext and errNilUpdatePath were all reachable and all outside
// every sweep, and ValSem205's nil-provider refusal rewritten to answer ErrTreeMalformed left the
// whole suite green. The class is now DERIVED by
// TestCommitValidationBorrowedErrorsIsEveryErrorItsRulesCanReach, which walks this package's own
// call graph out of validate_commit.go's declarations, and this map is held to it in BOTH
// directions. What the map is FOR is the one thing a source scan cannot do: Go has no reflection
// over package level variables, so the name a derivation produces has to be bound to the value a
// sweep compares with somewhere, and here it is, failing the moment the two disagree.
var commitValidationBorrowedErrors = map[string]error{
	"ErrContentArmMismatch":             ErrContentArmMismatch,
	"ErrLeafCountNotFull":               ErrLeafCountNotFull,
	"ErrLeafCountRange":                 ErrLeafCountRange,
	"ErrLeafHasNoChildren":              ErrLeafHasNoChildren,
	"ErrLeafIndexOutOfRange":            ErrLeafIndexOutOfRange,
	"ErrLeafNodeSourceMismatch":         ErrLeafNodeSourceMismatch,
	"ErrLeafOutOfRange":                 ErrLeafOutOfRange,
	"ErrMalformedExtension":             ErrMalformedExtension,
	"ErrNilCryptoProvider":              ErrNilCryptoProvider,
	"ErrNilGroupContext":                ErrNilGroupContext,
	"ErrNodeIsParent":                   ErrNodeIsParent,
	"ErrNodeOutOfRange":                 ErrNodeOutOfRange,
	"ErrNodeTypeMismatch":               ErrNodeTypeMismatch,
	"ErrProposalListBucketsDisagree":    ErrProposalListBucketsDisagree,
	"ErrProposalListMisbucketed":        ErrProposalListMisbucketed,
	"ErrRatchetExhausted":               ErrRatchetExhausted,
	"ErrRemoveCommitter":                ErrRemoveCommitter,
	"ErrRootHasNoParent":                ErrRootHasNoParent,
	"ErrRootHasNoSibling":               ErrRootHasNoSibling,
	"ErrTreeMalformed":                  ErrTreeMalformed,
	"ErrUnknownProposalOrRefType":       ErrUnknownProposalOrRefType,
	"errDuplicateEncryptionKey":         errDuplicateEncryptionKey,
	"errForgedProposalDiscriminant":     errForgedProposalDiscriminant,
	"errGroupContextExtensionNotListed": errGroupContextExtensionNotListed,
	"errMissingConfirmationTag":         errMissingConfirmationTag,
	"errMissingRequiredCapability":      errMissingRequiredCapability,
	"errMultipleGroupContextExtensions": errMultipleGroupContextExtensions,
	"errNilProposal":                    errNilProposal,
	"errNilProposalList":                errNilProposalList,
	"errNilProposalValidationInput":     errNilProposalValidationInput,
	"errNilRatchetTree":                 errNilRatchetTree,
	"errNilUpdatePath":                  errNilUpdatePath,
	"errPathDecrypt":                    errPathDecrypt,
	"errPathLength":                     errPathLength,
	"errProfileExternalCommit":          errProfileExternalCommit,
	"errProfilePsk":                     errProfilePsk,
	"errProfileReInit":                  errProfileReInit,
	"errProposalNotCached":              errProposalNotCached,
	"errReservedProposalType":           errReservedProposalType,
	"errTrailingBlankNodes":             errTrailingBlankNodes,
	"errUnregisteredProposalType":       errUnregisteredProposalType,
}

// commitValidationSanctionedWraps is the one place a refusal of this class answers a SECOND member
// of it, with the reason.
//
// leaf_node.go declares errGroupContextExtensionNotListed as a wrap of errMissingRequiredCapability
// -- section 13.4's rule is a narrowing of section 7.3's -- so the erratum 8745 refusal answers
// both by construction. Written down rather than filtered out by shape, on treeIndexWraps' terms:
// a second wrap has to be argued for here before the sweep will pass over it.
var commitValidationSanctionedWraps = map[string]string{
	"errGroupContextExtensionNotListed": "errMissingRequiredCapability",
	// tree_errors.go declares ErrLeafIndexOutOfRange as a wrap of ErrLeafOutOfRange -- the index
	// rule is the range rule with the offending index named -- and the derived roster now reaches
	// both of them, through the filtered direct path ValSem202 and ValSem203 read.
	"ErrLeafIndexOutOfRange": "ErrLeafOutOfRange",
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// testCommitInput is the shape every rule below is driven through: one tree standing in for both
// sides of the proposals, one epoch, and the committer at leaf 0.
//
// PostTree is a CLONE and not the same pointer. Several rules write nothing but several tests do,
// and a fixture that handed one tree to both fields would make an edit meant for the post-proposal
// tree land in the pre-commit one -- which is the difference ValSem204 and ValSem207 are stated
// across.
func testCommitInput(t *testing.T, crypto CryptoProvider, tree *RatchetTree,
	list *ProposalList, commit *Commit) *CommitValidationInput {

	t.Helper()
	// the commit's own ProposalOrRef vector IS the list, which is what
	// (*CommitValidationInput).check joins and what section 12.4's rule is written over. A fixture
	// that left the vector empty beside a non-empty list would be a commit no sender could have
	// produced -- and that pair is exactly what made ValSem201 decidable off a field the RFC does
	// not name, so it is built here rather than left to each test to remember. A test that means
	// to drive the join fills Proposals itself and this leaves it alone.
	if commit != nil && commit.Proposals == nil && list != nil {
		commit.Proposals = list.Refs()
	}
	return &CommitValidationInput{
		Crypto:  crypto,
		PreTree: tree,
		// deliberately the same node array in both fields for the rules that do not edit
		// either, and replaced by the tests that need them to differ
		PostTree:  tree.Clone(),
		Context:   testResolveContext(),
		Committer: LeafIndex(0),
		Own:       LeafIndex(0),
		List:      list,
		Commit:    commit,
		Now:       time.Now(),
	}
}

// testCommitProposals sets the list and the commit's own vector from one set of entries, so a
// fixture cannot make them disagree by accident.
func testCommitProposals(t *testing.T, in *CommitValidationInput, entries ...CachedProposal) {
	t.Helper()
	in.List = testProposalList(t, entries...)
	in.Commit.Proposals = in.List.Refs()
}

// testFitCommitPath rebuilds the commit's update path to the length of the committer's filtered
// direct path IN THE POST TREE, carrying the committer's own signature key.
//
// The POST tree, because that is the tree ValSem202 is stated over, and every row below that edits
// the post tree has to re-fit the path afterwards or be refused by the length rule for a reason
// that is not the rule it is about.
func testFitCommitPath(t *testing.T, crypto CryptoProvider, in *CommitValidationInput, m *testMember) {
	t.Helper()
	filtered, err := in.PostTree.FilteredDirectPath(in.Committer)
	if err != nil {
		t.Fatalf("FilteredDirectPath(%d) over the post tree: %v", in.Committer, err)
	}
	path := testCommitPath(t, crypto, m, len(filtered))
	current := in.PreTree.Leaf(in.Committer)
	if current == nil {
		t.Fatalf("leaf %d of the pre tree is blank, so the fixture has no committer", in.Committer)
	}
	// the committer's own signature key, so CheckUpdatePathKeyUniqueness exempts the position the
	// path is replacing rather than reporting the commit as a duplicate
	path.LeafNode.SignatureKey = current.SignatureKey
	in.Commit.Path = path
}

// testFullCommitInput is the input every aggregate row starts from: a four member group, a commit
// from leaf 0 carrying no proposals and a full path, which ValidateCommit accepts.
//
// Four members and not two, because a two member group's filtered direct path is one node long and
// half the rules below need an offender that is not at element zero.
func testFullCommitInput(t *testing.T, crypto CryptoProvider) (*CommitValidationInput, []*testMember) {
	t.Helper()
	tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
	testFitCommitPath(t, crypto, in, members[0])
	return in, members
}

// testCommitPathLeaf is a leaf in the shape an UpdatePath publishes: commit source, a parent hash,
// and a fresh encryption key.
//
// It is not signed, because no rule in validate_commit.go verifies a signature -- that is
// treekem.go's ValidateUpdatePathLeafNode and p7 task 18's call. A fixture that signed it would
// state that these rules check something they do not.
func testCommitPathLeaf(t *testing.T, crypto CryptoProvider, m *testMember) *LeafNode {
	t.Helper()
	leaf, _ := testLeafNode(t, crypto, m)
	leaf = leaf.Clone()
	leaf.LeafNodeSource = LeafNodeSourceCommit
	leaf.ParentHash = []byte("parent-hash")
	return leaf
}

// testCommitPath is an UpdatePath of n nodes, each addressing one ciphertext, over a commit leaf.
func testCommitPath(t *testing.T, crypto CryptoProvider, m *testMember, nodes int) *UpdatePath {
	t.Helper()
	path := &UpdatePath{LeafNode: *testCommitPathLeaf(t, crypto, m)}
	for i := 0; i < nodes; i += 1 {
		_, pub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
		if err != nil {
			t.Fatalf("DeriveKeyPair for path node %d: %v", i, err)
		}
		path.Nodes = append(path.Nodes, UpdatePathNode{
			EncryptionKey:       pub,
			EncryptedPathSecret: []HpkeCiphertext{{KemOutput: []byte("kem"), Ciphertext: []byte("ct")}},
		})
	}
	return path
}

// testNarrowedCapabilities is testCapabilities with urmessage_owner_successor taken out.
//
// One member of the group that does not list a non-default extension type is the whole subject of
// section 13.4 and of erratum 8745, and there is no other way to build one: every fixture leaf in
// this package lists all three private-use types.
func testNarrowedCapabilities() Capabilities {
	narrowed := testCapabilities()
	narrowed.Extensions = []ExtensionType{
		ExtensionTypeUrmessageGroupPolicy,
		ExtensionTypeUrmessageLeafKeys,
	}
	return narrowed
}

// testNarrowLeafCapabilities replaces one leaf of a tree with the same leaf under narrowed
// capabilities.
//
// The signature no longer covers the capabilities afterwards, and that is fine here for
// testCommitPathLeaf's reason: nothing in validate_commit.go verifies one. A test that needs a
// valid signature has to go through treekem.go's door instead.
func testNarrowLeafCapabilities(t *testing.T, tree *RatchetTree, at LeafIndex) {
	t.Helper()
	leaf := tree.Leaf(at)
	if leaf == nil {
		t.Fatalf("leaf %d is blank, so there is nothing to narrow", at)
	}
	narrowed := leaf.Clone()
	narrowed.Capabilities = testNarrowedCapabilities()
	if err := tree.SetLeaf(at, narrowed); err != nil {
		t.Fatalf("SetLeaf(%d): %v", at, err)
	}
}

// ---------------------------------------------------------------------------
// ValSem200 to ValSem209, ValSem300 and the two errata
// ---------------------------------------------------------------------------

// TestValSem200SelfRemoveInCommit puts the committer's own remove at removes[1].
//
// The plan's fixture carries ONE remove, which is the committer's, so a rule reading Removes[0]
// passes it. Behind an innocent remove of leaf 1 the two are told apart.
func TestValSem200SelfRemoveInCommit(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
	someoneElse := CachedProposal{ByValue: true,
		Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}}}
	theCommitter := CachedProposal{ByValue: true,
		Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 0}}}
	list := testProposalList(t, someoneElse, theCommitter)
	in := testCommitInput(t, crypto, tree, list, &Commit{})
	if err := ValSem200NoSelfRemove(in); !errors.Is(err, ErrRemoveCommitter) {
		t.Fatalf("ValSem200 error = %v, want ErrRemoveCommitter", err)
	}
	// and the accepting half, so the rule is not "any list of two removes"
	onlyOthers := testProposalList(t, someoneElse, CachedProposal{ByValue: true,
		Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}})
	if err := ValSem200NoSelfRemove(testCommitInput(t, crypto, tree, onlyOthers, &Commit{})); err != nil {
		t.Fatalf("ValSem200 refused a list that removes nobody's committer: %v", err)
	}
}

func TestValSem201MissingPath(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	cached := CachedProposal{ByValue: true,
		Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}}
	list := testProposalList(t, cached)
	in := testCommitInput(t, crypto, tree, list, &Commit{Path: nil})
	if err := ValSem201PathPresentWhenRequired(in); !errors.Is(err, errMissingPath) {
		t.Fatalf("ValSem201 error = %v, want errMissingPath", err)
	}
}

func TestValSem201EmptyProposalListRequiresPath(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{Path: nil})
	if err := ValSem201PathPresentWhenRequired(in); !errors.Is(err, errMissingPath) {
		t.Fatalf("ValSem201 error = %v, want errMissingPath for an empty proposal list", err)
	}
}

// TestValSem201AcceptsAPathlessAddOnlyCommit is the half that stops the rule from being "every
// commit needs a path".
func TestValSem201AcceptsAPathlessAddOnlyCommit(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	joiner := testIdentity(t, crypto, "dave")
	kp, _, _ := testKeyPackage(t, crypto, joiner)
	_ = members
	list := testProposalList(t, CachedProposal{ByValue: true,
		Proposal: Proposal{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}})
	in := testCommitInput(t, crypto, tree, list, &Commit{Path: nil})
	if err := ValSem201PathPresentWhenRequired(in); err != nil {
		t.Fatalf("ValSem201 refused a pathless add-only commit: %v", err)
	}
}

func TestValSem202PathLength(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
	filtered, err := tree.FilteredDirectPath(LeafIndex(0))
	if err != nil {
		t.Fatalf("FilteredDirectPath: %v", err)
	}
	if len(filtered) < 2 {
		t.Fatalf("the fixture's filtered direct path is %d long, so a one node path is not short",
			len(filtered))
	}
	short := testCommitPath(t, crypto, members[0], 1)
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{Path: short})
	if err := ValSem202PathLength(in); !errors.Is(err, errPathLength) {
		t.Fatalf("ValSem202 error = %v, want errPathLength", err)
	}
	exact := testCommitPath(t, crypto, members[0], len(filtered))
	in = testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{Path: exact})
	if err := ValSem202PathLength(in); err != nil {
		t.Fatalf("ValSem202 refused a path of the filtered direct path's own length: %v", err)
	}
}

// TestTheCommitPathLeafMustBeCommitSourced drives section 12.4.2's own bullet.
func TestTheCommitPathLeafMustBeCommitSourced(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	keyPackageLeaf, _ := testLeafNode(t, crypto, members[0])
	in := testCommitInput(t, crypto, tree, &ProposalList{},
		&Commit{Path: &UpdatePath{LeafNode: *keyPackageLeaf}})
	if err := validateCommitPathLeafSource(in); !errors.Is(err, ErrLeafNodeSourceMismatch) {
		t.Fatalf("the path leaf source rule = %v, want ErrLeafNodeSourceMismatch", err)
	}
	commitLeaf := testCommitPathLeaf(t, crypto, members[0])
	in = testCommitInput(t, crypto, tree, &ProposalList{},
		&Commit{Path: &UpdatePath{LeafNode: *commitLeaf}})
	if err := validateCommitPathLeafSource(in); err != nil {
		t.Fatalf("the path leaf source rule refused a commit sourced leaf: %v", err)
	}
}

// TestValSem203PathEncryptsToNobody puts the empty ciphertext vector at node 1.
//
// The plan's fixture is a path of one node, so a rule reading Nodes[0] passes it. A path whose
// first rung addresses somebody and whose second addresses nobody is the input that separates
// them, and it is the input a sender would actually produce by truncating.
func TestValSem203PathEncryptsToNobody(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
	path := testCommitPath(t, crypto, members[0], 2)
	path.Nodes[1].EncryptedPathSecret = nil
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{Path: path})
	in.Committer = LeafIndex(0)
	in.Own = LeafIndex(1)
	failure := ValSem203PathDecrypt(in)
	if !errors.Is(failure, errPathDecrypt) {
		t.Fatalf("ValSem203 error = %v, want errPathDecrypt", failure)
	}
	// the index the refusal names is the whole of what separates a rule over the vector from one
	// over its head: a rule reading Nodes[0] cannot refuse this input at all
	if !strings.Contains(failure.Error(), "node 1") {
		t.Errorf("ValSem203 refused the path without naming which node encrypts to nobody: %v", failure)
	}
	whole := testCommitPath(t, crypto, members[0], 2)
	in = testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{Path: whole})
	in.Committer = LeafIndex(0)
	in.Own = LeafIndex(1)
	if failure := ValSem203PathDecrypt(in); failure != nil {
		t.Fatalf("ValSem203 refused a path whose every node addresses somebody: %v", failure)
	}
}

// TestValSem203RefusesAReceiverOutsideTheTree drives the second half of the rule: the receiver's
// own filtered direct path is what says a secret exists for it.
func TestValSem203RefusesAReceiverOutsideTheTree(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
	in := testCommitInput(t, crypto, tree, &ProposalList{},
		&Commit{Path: testCommitPath(t, crypto, members[0], 2)})
	in.Committer = LeafIndex(0)
	in.Own = LeafIndex(97)
	if failure := ValSem203PathDecrypt(in); !errors.Is(failure, errPathDecrypt) {
		t.Fatalf("ValSem203 over a receiver outside the tree = %v, want errPathDecrypt", failure)
	}
}

func TestValSem204PathLeafReusesTheCommittersKey(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	current := tree.Leaf(LeafIndex(0))
	if current == nil {
		t.Fatal("leaf 0 is blank")
	}
	reused := testCommitPathLeaf(t, crypto, members[0])
	reused.EncryptionKey = current.EncryptionKey
	in := testCommitInput(t, crypto, tree, &ProposalList{},
		&Commit{Path: &UpdatePath{LeafNode: *reused}})
	if failure := ValSem204PathKeyMismatch(in); !errors.Is(failure, errPathLeafKeyUnchanged) {
		t.Fatalf("ValSem204 error = %v, want errPathLeafKeyUnchanged", failure)
	}
	fresh := testCommitPathLeaf(t, crypto, members[0])
	in = testCommitInput(t, crypto, tree, &ProposalList{},
		&Commit{Path: &UpdatePath{LeafNode: *fresh}})
	if failure := ValSem204PathKeyMismatch(in); failure != nil {
		t.Fatalf("ValSem204 refused a path leaf carrying a fresh key: %v", failure)
	}
}

// TestValSem204RefusesACommitterThatOccupiesNoLeaf is the precondition, with its own value.
func TestValSem204RefusesACommitterThatOccupiesNoLeaf(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	in := testCommitInput(t, crypto, tree, &ProposalList{},
		&Commit{Path: &UpdatePath{LeafNode: *testCommitPathLeaf(t, crypto, members[0])}})
	in.Committer = LeafIndex(41)
	if failure := ValSem204PathKeyMismatch(in); !errors.Is(failure, errCommitterNotMember) {
		t.Fatalf("ValSem204 over a committer outside the tree = %v, want errCommitterNotMember", failure)
	}
}

func TestValSem205ConfirmationTagMismatch(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
	in.ConfirmationKey = make([]byte, crypto.HashSize())
	in.ConfirmedHash = []byte("confirmed")
	if failure := ValSem205ConfirmationTag(in); !errors.Is(failure, errMissingConfirmationTag) {
		t.Fatalf("ValSem205 over a commit with no tag = %v, want errMissingConfirmationTag", failure)
	}
	in.ConfirmationTag = []byte("not the tag")
	if failure := ValSem205ConfirmationTag(in); !errors.Is(failure, errBadConfirmationTag) {
		t.Fatalf("ValSem205 error = %v, want errBadConfirmationTag", failure)
	}
	in.ConfirmationTag = crypto.Mac(in.ConfirmationKey, in.ConfirmedHash)
	if failure := ValSem205ConfirmationTag(in); failure != nil {
		t.Fatalf("ValSem205 rejected the correct tag: %v", failure)
	}
	// the tag is over the confirmed transcript hash and not over nothing: a tag correct for a
	// different hash must not verify
	in.ConfirmedHash = []byte("some other transcript")
	if failure := ValSem205ConfirmationTag(in); !errors.Is(failure, errBadConfirmationTag) {
		t.Fatalf("ValSem205 accepted a tag computed over another transcript hash: %v", failure)
	}
}

// TestValSem206PathLeafKeyIsPublishedByAProposal drives the axis CheckUpdatePathKeyUniqueness
// cannot see, with the offending proposal SECOND in each of the two buckets.
func TestValSem206PathLeafKeyIsPublishedByAProposal(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	innocent, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "erin"))
	colliding, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "frank"))

	adds := testProposalList(t,
		CachedProposal{ByValue: true, Proposal: Proposal{ProposalType: ProposalTypeAdd,
			Add: &Add{KeyPackage: *innocent}}},
		CachedProposal{ByValue: true, Proposal: Proposal{ProposalType: ProposalTypeAdd,
			Add: &Add{KeyPackage: *colliding}}})

	leaf := testCommitPathLeaf(t, crypto, members[0])
	leaf.EncryptionKey = colliding.LeafNode.EncryptionKey
	in := testCommitInput(t, crypto, tree, adds, &Commit{Path: &UpdatePath{LeafNode: *leaf}})
	if failure := ValSem206PathLeafEncryptionKeyUnique(in); !errors.Is(failure, errDuplicateEncryptionKey) {
		t.Fatalf("ValSem206 over an add at index 1 = %v, want errDuplicateEncryptionKey", failure)
	}

	// the init key of the same add, which is a different field of the same joiner
	leaf = testCommitPathLeaf(t, crypto, members[0])
	leaf.EncryptionKey = colliding.InitKey
	in = testCommitInput(t, crypto, tree, adds, &Commit{Path: &UpdatePath{LeafNode: *leaf}})
	if failure := ValSem206PathLeafEncryptionKeyUnique(in); !errors.Is(failure, errDuplicateEncryptionKey) {
		t.Fatalf("ValSem206 over the init key of the add at index 1 = %v, want errDuplicateEncryptionKey",
			failure)
	}

	// and the updates bucket, offender second again
	innocentUpdate, _ := testUpdateLeafNode(t, crypto, members[0], []byte("group"), LeafIndex(0))
	collidingUpdate, _ := testUpdateLeafNode(t, crypto, members[1], []byte("group"), LeafIndex(1))
	updates := testProposalList(t,
		CachedProposal{ByValue: true, Proposal: Proposal{ProposalType: ProposalTypeUpdate,
			Update: &Update{LeafNode: *innocentUpdate}}},
		CachedProposal{ByValue: true, Proposal: Proposal{ProposalType: ProposalTypeUpdate,
			Update: &Update{LeafNode: *collidingUpdate}}})
	leaf = testCommitPathLeaf(t, crypto, members[0])
	leaf.EncryptionKey = collidingUpdate.EncryptionKey
	in = testCommitInput(t, crypto, tree, updates, &Commit{Path: &UpdatePath{LeafNode: *leaf}})
	if failure := ValSem206PathLeafEncryptionKeyUnique(in); !errors.Is(failure, errDuplicateEncryptionKey) {
		t.Fatalf("ValSem206 over an update at index 1 = %v, want errDuplicateEncryptionKey", failure)
	}

	// the accepting half over the same lists, so the rule is not "any list with two proposals"
	fresh := testCommitPathLeaf(t, crypto, members[0])
	in = testCommitInput(t, crypto, tree, adds, &Commit{Path: &UpdatePath{LeafNode: *fresh}})
	if failure := ValSem206PathLeafEncryptionKeyUnique(in); failure != nil {
		t.Fatalf("ValSem206 refused a path leaf whose key no proposal publishes: %v", failure)
	}
}

// TestValSem207PathKeysAreNewToTheTree drives the funnel onto CheckUpdatePathKeyUniqueness, with
// the collision at path node 1.
func TestValSem207PathKeysAreNewToTheTree(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
	stranger := testIdentity(t, crypto, "mallory")
	path := testCommitPath(t, crypto, stranger, 2)
	occupied := tree.Leaf(LeafIndex(2))
	if occupied == nil {
		t.Fatal("leaf 2 is blank, so there is no key to collide with")
	}
	path.Nodes[1].EncryptionKey = occupied.EncryptionKey
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{Path: path})
	if failure := ValSem207PathEncryptionKeysUnique(in); !errors.Is(failure, errDuplicateEncryptionKey) {
		t.Fatalf("ValSem207 over a path node reusing leaf 2's key = %v, want errDuplicateEncryptionKey",
			failure)
	}
	clean := testCommitPath(t, crypto, stranger, 2)
	in = testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{Path: clean})
	if failure := ValSem207PathEncryptionKeysUnique(in); failure != nil {
		t.Fatalf("ValSem207 refused a path publishing only fresh keys: %v", failure)
	}
}

// TestValSem207DoesNotFlattenTheTreesOwnRefusals is the half the plan's %v wrap loses.
//
// CheckUpdatePathKeyUniqueness answers ErrTreeMalformed for a missing tree, and its own header
// says a funnel that flattens the chain reports that to the group as a commit that duplicated a
// key -- which names the committer for a fault that is the receiver's own state.
func TestValSem207DoesNotFlattenTheTreesOwnRefusals(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	in := testCommitInput(t, crypto, tree, &ProposalList{},
		&Commit{Path: testCommitPath(t, crypto, members[0], 1)})
	// an OCCUPIED node holding neither a leaf nor a parent, which is the fault
	// CheckUpdatePathKeyUniqueness answers ErrNodeTypeMismatch for. A nil tree cannot be used for
	// this: the argument rule at the door answers it first, so that position is unreachable
	// through this funnel and a test written against it would state nothing.
	in.PostTree.nodes[1] = &Node{}
	failure := ValSem207PathEncryptionKeysUnique(in)
	if !errors.Is(failure, ErrNodeTypeMismatch) {
		t.Fatalf("ValSem207 over a malformed post tree = %v, want ErrNodeTypeMismatch to survive the funnel",
			failure)
	}
	if errors.Is(failure, errDuplicateEncryptionKey) {
		t.Fatal("ValSem207 reported a malformed tree as a duplicated encryption key, which names the committer for a fault that is the receiver's own state")
	}
}

func TestValSem208MultipleGroupContextExtensions(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	one := testGceOf()
	list := testProposalList(t, one, one)
	in := testCommitInput(t, crypto, tree, list, &Commit{})
	if failure := ValSem208SingleGroupContextExtensions(in); !errors.Is(failure, errMultipleGroupContextExtensions) {
		t.Fatalf("ValSem208 error = %v, want errMultipleGroupContextExtensions", failure)
	}
	if failure := ValSem208SingleGroupContextExtensions(
		testCommitInput(t, crypto, tree, testProposalList(t, one), &Commit{})); failure != nil {
		t.Fatalf("ValSem208 refused a list carrying one group_context_extensions proposal: %v", failure)
	}
}

// TestValSem209RefusesAnExtensionTypeOutsideTheV1Profile puts the offending type at entry 1.
func TestValSem209RefusesAnExtensionTypeOutsideTheV1Profile(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	admitted := Extension{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: []byte{}}
	for _, row := range []struct {
		name     string
		ext      Extension
		sentinel error
	}{
		{"external_senders", Extension{ExtensionType: ExtensionTypeExternalSenders}, errProfileExternalSender},
		{"external_pub", Extension{ExtensionType: ExtensionTypeExternalPub}, errProfileExternalCommit},
		{"urmessage_leaf_keys", Extension{ExtensionType: ExtensionTypeUrmessageLeafKeys}, errProfileGroupExtension},
		{"application_id", Extension{ExtensionType: ExtensionTypeApplicationId}, errProfileGroupExtension},
		{"an unregistered code point", Extension{ExtensionType: ExtensionType(0xABCD)}, errUnregisteredGroupExtension},
	} {
		list := testProposalList(t, testGceOf(admitted, row.ext))
		in := testCommitInput(t, crypto, tree, list, &Commit{})
		failure := ValSem209GroupExtensionsSupported(in)
		if !errors.Is(failure, row.sentinel) {
			t.Errorf("ValSem209 over %s at entry 1 = %v, want %v", row.name, failure, row.sentinel)
			continue
		}
		if !strings.Contains(failure.Error(), "entry 1") {
			t.Errorf("ValSem209 over %s refused without naming the entry: %v", row.name, failure)
		}
	}
}

// TestValSem209RefusesAGroupExtensionAMemberDoesNotSupport is section 13.4 as erratum 8745
// corrects it, which is the condition the plan omits entirely.
//
// The offending member is leaf 1 and the offending extension is entry 1, so neither loop can be
// narrowed to its head and still fail this.
func TestValSem209RefusesAGroupExtensionAMemberDoesNotSupport(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	testNarrowLeafCapabilities(t, tree, LeafIndex(1))
	list := testProposalList(t, testGceOf(
		Extension{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: []byte{}},
		Extension{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor, ExtensionData: []byte{}},
	))
	in := testCommitInput(t, crypto, tree, list, &Commit{})
	in.PostTree = tree.Clone()
	failure := ValSem209GroupExtensionsSupported(in)
	if !errors.Is(failure, errGroupContextExtensionNotListed) {
		t.Fatalf("ValSem209 over a member that does not list urmessage_owner_successor = %v, want errGroupContextExtensionNotListed",
			failure)
	}
	if !strings.Contains(failure.Error(), "leaf 1") {
		t.Errorf("ValSem209 refused without naming the member: %v", failure)
	}
	// and the same commit is accepted once every member lists it, so the rule is not "any
	// group_context_extensions proposal"
	whole, _ := testTreeWith(t, crypto, "alice", "bob")
	if failure := ValSem209GroupExtensionsSupported(
		testCommitInput(t, crypto, whole, list, &Commit{})); failure != nil {
		t.Fatalf("ValSem209 refused a commit every member supports: %v", failure)
	}
}

// TestValSem209ExemptsTheMembersTheCommitRemoves states the scope of the two member loops.
func TestValSem209ExemptsTheMembersTheCommitRemoves(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	testNarrowLeafCapabilities(t, tree, LeafIndex(1))
	list := testProposalList(t,
		testGceOf(Extension{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor}),
		CachedProposal{ByValue: true,
			Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}})
	in := testCommitInput(t, crypto, tree, list, &Commit{})
	in.PostTree = tree.Clone()
	if failure := ValSem209GroupExtensionsSupported(in); failure != nil {
		t.Fatalf("ValSem209 held a commit to the capabilities of the member it removes: %v", failure)
	}
}

// TestValSem209RefusesARequiredCapabilityAMemberDoesNotHold is section 7.3's own clause, which is
// the one the plan states.
func TestValSem209RefusesARequiredCapabilityAMemberDoesNotHold(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	testNarrowLeafCapabilities(t, tree, LeafIndex(1))
	// required_capabilities is a section 7.2 DEFAULT type, so installing it trips no section
	// 13.4 rule of its own; what it asks for is what leaf 1 does not list
	list := testProposalList(t, testGceOf(
		testRequiredCapabilitiesNaming(t, ExtensionTypeUrmessageOwnerSuccessor)))
	in := testCommitInput(t, crypto, tree, list, &Commit{})
	in.PostTree = tree.Clone()
	failure := ValSem209GroupExtensionsSupported(in)
	if !errors.Is(failure, errMissingRequiredCapability) {
		t.Fatalf("ValSem209 over a required capability leaf 1 does not hold = %v, want errMissingRequiredCapability",
			failure)
	}
	if errors.Is(failure, errGroupContextExtensionNotListed) {
		t.Fatal("ValSem209 reported the required_capabilities clause as the section 13.4 clause; the two are separate rules and a caller cannot tell them apart if they answer one value")
	}
}

func TestValSem300TrailingBlankNodes(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	if failure := ValSem300NoTrailingBlankNodes(tree); failure != nil {
		t.Fatalf("ValSem300 rejected a full tree: %v", failure)
	}
	// the rightmost node of any tree is a leaf, so blanking it is the whole of what section
	// 12.4.3.3 forbids of an exported tree. RemoveLeaf truncates, so a tree that still reports
	// trailing blanks is one assembled some other way -- which is what a tree off the wire is.
	padded := tree.Clone()
	last := NodeIndex(padded.NodeWidth() - 1)
	if err := padded.Blank(last); err != nil {
		t.Fatalf("Blank(%d): %v", last, err)
	}
	if failure := ValSem300NoTrailingBlankNodes(padded); !errors.Is(failure, errTrailingBlankNodes) {
		t.Fatalf("ValSem300 over a tree ending in a blank = %v, want errTrailingBlankNodes", failure)
	}
	if failure := ValSem300NoTrailingBlankNodes(nil); !errors.Is(failure, ErrTreeMalformed) {
		t.Fatalf("ValSem300(nil) = %v, want ErrTreeMalformed", failure)
	}
}

// TestUnmarshalRatchetTreeStillRefusesATrailingBlank is the other door on the same rule, kept here
// because ValSem300's whole account is that a tree with trailing blanks is one off the wire.
func TestUnmarshalRatchetTreeStillRefusesATrailingBlank(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	encoded, err := marshalRatchetTree(tree)
	if err != nil {
		t.Fatalf("marshalRatchetTree: %v", err)
	}
	if _, err := UnmarshalRatchetTree(append(append([]byte(nil), encoded...), 0x00)); err == nil {
		t.Fatal("UnmarshalRatchetTree accepted a tree with a trailing blank node")
	}
}

// TestErrata8745RefusesAPathLeafThatDropsAGroupExtension puts the offending extension at index 1 of
// the group context's vector.
//
// Index 1 is not a convenience. A real GroupContext is led by the section 7.2 default types, which
// this rule exempts, so a loop that answered element zero steps over the exempt entry and never
// reaches the one the erratum is about -- and ERRATA.md records that this exact narrowing once
// passed the whole suite inside (*LeafNode).Validate.
func TestErrata8745RefusesAPathLeafThatDropsAGroupExtension(t *testing.T) {
	crypto := testCrypto(t)
	member := testIdentity(t, crypto, "alice")
	leaf := testCommitPathLeaf(t, crypto, member)
	leaf.Capabilities = testNarrowedCapabilities()
	context := &GroupContext{
		Version: ProtocolVersionMls10, CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId: []byte("group"), Epoch: 2,
		Extensions: []Extension{
			{ExtensionType: ExtensionTypeRequiredCapabilities, ExtensionData: []byte{}},
			{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor, ExtensionData: []byte{}},
		},
	}
	failure := CheckErrata8745(&UpdatePath{LeafNode: *leaf}, context)
	if !errors.Is(failure, errGroupContextExtensionNotListed) {
		t.Fatalf("CheckErrata8745 over a path leaf that drops urmessage_owner_successor = %v, want errGroupContextExtensionNotListed",
			failure)
	}
	if !strings.Contains(failure.Error(), "8745") {
		t.Errorf("CheckErrata8745 refused without naming the erratum it is applying: %v", failure)
	}
	whole := testCommitPathLeaf(t, crypto, member)
	if failure := CheckErrata8745(&UpdatePath{LeafNode: *whole}, context); failure != nil {
		t.Fatalf("CheckErrata8745 rejected a path leaf that lists every group extension: %v", failure)
	}
	if failure := CheckErrata8745(nil, context); failure != nil {
		t.Fatalf("CheckErrata8745 over an absent path = %v, want nil; whether the path was allowed to be absent is ValSem201's rule",
			failure)
	}
	if failure := CheckErrata8745(&UpdatePath{LeafNode: *whole}, nil); !errors.Is(failure, ErrNilGroupContext) {
		t.Fatalf("CheckErrata8745 with no context = %v, want ErrNilGroupContext", failure)
	}
}

// TestErrata8745IsTheErratumTheErrataFileRecords is the check the plan's prose fails.
//
// The plan describes erratum 8745 as a leaf_node_source and parent_hash rule. ERRATA.md carries the
// erratum verbatim and it is section 13.4's group-extension compatibility rule extended to update
// paths. A path leaf that IS commit sourced and DOES carry a parent hash, and that drops a group
// extension, is the input the two readings disagree about: the plan's version accepts it.
func TestErrata8745IsTheErratumTheErrataFileRecords(t *testing.T) {
	crypto := testCrypto(t)
	leaf := testCommitPathLeaf(t, crypto, testIdentity(t, crypto, "alice"))
	if leaf.LeafNodeSource != LeafNodeSourceCommit || len(leaf.ParentHash) == 0 {
		t.Fatal("the fixture is not the leaf the plan's version accepts, so this states nothing")
	}
	leaf.Capabilities = testNarrowedCapabilities()
	context := &GroupContext{GroupId: []byte("group"), Extensions: []Extension{
		{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor},
	}}
	if failure := CheckErrata8745(&UpdatePath{LeafNode: *leaf}, context); failure == nil {
		t.Fatal("CheckErrata8745 accepted a commit sourced path leaf, carrying a parent hash, that does not support an extension the group is using -- which is the leaf erratum 8745 is about and the one the plan's leaf_node_source reading admits")
	}
}

// TestErrata8815RefusesAReferenceThisMemberNeverReceived puts the uncached reference at entry 1.
func TestErrata8815RefusesAReferenceThisMemberNeverReceived(t *testing.T) {
	crypto := testCrypto(t)
	cache := testCacheAt(t, testResolveContext())
	ref, err := cache.Store(crypto, testResolveContext(), testProposalContent(t, crypto, LeafIndex(1),
		&Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 4}}))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	stranger := ProposalRef(append(append([]byte(nil), ref...), 0x5a))
	commit := &Commit{Proposals: []ProposalOrRef{
		{Type: ProposalOrRefTypeReference, Reference: ref},
		{Type: ProposalOrRefTypeReference, Reference: stranger},
	}}
	failure := CheckErrata8815(commit, cache)
	if !errors.Is(failure, errProposalNotCached) {
		t.Fatalf("CheckErrata8815 over a reference this member never received = %v, want errProposalNotCached",
			failure)
	}
	if !strings.Contains(failure.Error(), "entry 1") {
		t.Errorf("CheckErrata8815 refused without naming which entry: %v", failure)
	}
	held := &Commit{Proposals: []ProposalOrRef{{Type: ProposalOrRefTypeReference, Reference: ref}}}
	if failure := CheckErrata8815(held, cache); failure != nil {
		t.Fatalf("CheckErrata8815 rejected a commit naming a proposal this member holds: %v", failure)
	}
	// a by-value proposal is delivered by the commit itself, so "previously received" is not a
	// question about it and a nil cache is the right cache for it
	inline := &Commit{Proposals: []ProposalOrRef{{Type: ProposalOrRefTypeProposal,
		Proposal: &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}}}}
	if failure := CheckErrata8815(inline, nil); failure != nil {
		t.Fatalf("CheckErrata8815 refused a by-value only commit under no cache: %v", failure)
	}
	// and the fail-closed direction: no record of what this member received is not a pass
	if failure := CheckErrata8815(held, nil); !errors.Is(failure, errProposalNotCached) {
		t.Fatalf("CheckErrata8815 with no cache = %v, want errProposalNotCached; a validator handed no record of what this member received has not checked the erratum",
			failure)
	}
}

// ---------------------------------------------------------------------------
// the derived gates
// ---------------------------------------------------------------------------

// commitValidationSource is validate_commit.go, parsed.
func commitValidationSource(t *testing.T) parsedSource {
	t.Helper()
	for _, path := range packageSourcePaths(t) {
		if filepath.Base(path) == commitValidationFile {
			return mustParseSource(t, path)
		}
	}
	t.Fatalf("this package holds no %s, so every derivation below has no subject", commitValidationFile)
	return parsedSource{}
}

// commitRuleNamesDeclared is every function of validate_commit.go whose whole signature is
// `func(*CommitValidationInput) error`.
//
// The SIGNATURE and not a prefix, so the rules carrying no ValSem code are in the class too. A gate
// keyed on the ValSem spelling would let the next rule spelled validateSomething out of it, which
// is the enumeration the aggregate below exists to be held against.
func commitRuleNamesDeclared(t *testing.T) []string {
	t.Helper()
	source := commitValidationSource(t)
	names := []string{}
	for _, declaration := range source.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Recv != nil || function.Type.Params == nil {
			continue
		}
		if len(function.Type.Params.List) != 1 || function.Type.Results == nil ||
			len(function.Type.Results.List) != 1 {
			continue
		}
		if source.render(function.Type.Params.List[0].Type) != "*CommitValidationInput" {
			continue
		}
		if source.render(function.Type.Results.List[0].Type) != "error" {
			continue
		}
		names = append(names, function.Name.Name)
	}
	slices.Sort(names)
	return names
}

// commitRulesDeliberatelyNotInTheAggregate is every rule of the class ValidateCommit does not run,
// with the reason.
//
// Held in BOTH directions below, so the excuse expires by failing: a rule that appears here and is
// then wired fails, and a rule left out of the aggregate with no entry here fails too.
var commitRulesDeliberatelyNotInTheAggregate = map[string]string{
	"ValidateCommit": "is the aggregate itself; a rule that ran itself would be a loop rather than a check",
	"ValSem205ConfirmationTag": "verifies a MAC under the confirmation key of the epoch this commit OPENS, " +
		"which does not exist until the new key schedule has been derived -- a step RFC 9420 section 12.4.2 " +
		"puts after every rule the aggregate runs. The caller that has one runs it.",
}

// TestValidateCommitRunsEveryRuleThisFileDeclares holds the aggregate to the class derived from the
// file's own source.
func TestValidateCommitRunsEveryRuleThisFileDeclares(t *testing.T) {
	declared := commitRuleNamesDeclared(t)
	if len(declared) == 0 {
		t.Fatalf("no function of %s takes a *CommitValidationInput and answers an error, so this gate read something other than that file",
			commitValidationFile)
	}
	// the positive control: a derivation that resolved nothing reports the clean bill a complete
	// one reports, and this file certainly declares ValSem201PathPresentWhenRequired
	if !slices.Contains(declared, "ValSem201PathPresentWhenRequired") {
		t.Fatalf("the derivation found %v and %s certainly declares ValSem201PathPresentWhenRequired",
			declared, commitValidationFile)
	}
	source := commitValidationSource(t)
	run := map[string]bool{}
	for _, declaration := range source.file.Decls {
		generic, isGeneric := declaration.(*ast.GenDecl)
		if !isGeneric {
			continue
		}
		for _, spec := range generic.Specs {
			value, isValue := spec.(*ast.ValueSpec)
			if !isValue || len(value.Names) != 1 || value.Names[0].Name != "commitValidationChecks" {
				continue
			}
			for name := range identifiersIn(value) {
				run[name] = true
			}
		}
	}
	if len(run) == 0 {
		t.Fatal("commitValidationChecks named nothing, so the gate below cannot tell a run rule from an unrun one")
	}
	for _, name := range declared {
		reason, excused := commitRulesDeliberatelyNotInTheAggregate[name]
		switch {
		case run[name] && excused:
			t.Errorf("%s is in commitValidationChecks and is also written down as deliberately left out, with the reason %q; one of the two is stale",
				name, reason)
		case !run[name] && !excused:
			t.Errorf("%s takes a *CommitValidationInput and answers an error and ValidateCommit does not run it. A rule the aggregate does not run refuses nothing on any path that calls the aggregate: put it in commitValidationChecks, or write down why it is not there",
				name)
		case run[name]:
			t.Logf("%s runs in the aggregate", name)
		default:
			t.Logf("%s is deliberately not in the aggregate: %s", name, reason)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(commitRulesDeliberatelyNotInTheAggregate)) {
		if !slices.Contains(declared, name) {
			t.Errorf("a reason is written down for %s and %s declares no rule of that name; the excuse has outlived what it excused",
				name, commitValidationFile)
		}
	}
}

// TestCommitValidationOwnedErrorsIsEveryErrorItsFileDeclares is the derivation the other error
// classes of this package get, over this one.
func TestCommitValidationOwnedErrorsIsEveryErrorItsFileDeclares(t *testing.T) {
	declared := packageLevelDeclarations(t, ".")
	fromFile := map[string]bool{}
	for name, file := range declared {
		if file == commitValidationFile && strings.HasPrefix(name, "err") {
			fromFile[name] = true
		}
	}
	if !fromFile["errMissingPath"] {
		t.Fatalf("the scan did not find errMissingPath among the err declarations of %s, which certainly declares it, so it is reading something other than that file",
			commitValidationFile)
	}
	if got, want := slices.Sorted(maps.Keys(fromFile)), slices.Sorted(maps.Keys(commitValidationOwnedErrors)); !slices.Equal(got, want) {
		t.Fatalf("%s declares %v and commitValidationOwnedErrors holds %v; the sweeps below run over the second, so a sentinel missing from it is one no rule of this file is held against",
			commitValidationFile, got, want)
	}
}

// commitRefusalRoster is the whole class a commit refusal can come from: this file's sentinels and
// the ones its rules can reach through the bodies they delegate to.
func commitRefusalRoster() map[string]error {
	roster := map[string]error{}
	maps.Copy(roster, commitValidationOwnedErrors)
	maps.Copy(roster, commitValidationBorrowedErrors)
	return roster
}

// commitRefusalClosure is every package level sentinel a rule of validate_commit.go can answer,
// derived by walking this package's own call graph from that file's declarations.
//
// WHY A CLOSURE AND NOT A SCAN OF ONE FILE. Half the refusals a commit rule answers are not
// written in the file that states the rule and that is deliberate -- ValSem200 delegates to
// section 12.2's body and answers ErrRemoveCommitter, a name validate_commit.go mentions only in a
// comment; ValSem209 reaches errMissingRequiredCapability through Capabilities.Supports and
// ErrMalformedExtension through requiredCapabilitiesOf; ValSem202 wraps whatever the tree math
// answered with %w. A derivation that read one file's identifiers would find the twelve easy ones
// and miss exactly the delegated half, which is the half the roster was already missing.
//
// THE EDGES. A declaration reaches another when it MENTIONS it and that other is either a function
// answering an error or a package level value. The mention half is packageLevelMentionsIn, which
// counts data as well as code, and both halves of the target rule are load bearing: the profile
// gates are MAPS from a code point to the refusal it earns, so checkProposalType's eight answers
// and checkGroupExtension's three are named by a table and by no statement at all, and a walk that
// followed only functions would lose every one of them. What is left out is a mention of a type or
// of a field, which cannot carry a refusal anywhere.
//
// IT OVER-REACHES AND THAT IS THE SAFE DIRECTION, said plainly. A mention is resolved by BARE
// NAME, because Go's method sets are not recoverable from an unresolved AST -- so a rule that
// mentions Update reaches TranscriptHashes.Update, and a handful of tree math sentinels ride in
// behind FilteredDirectPath that no commit fixture will ever produce. A sentinel in the roster
// that no rule can answer costs one pairwise comparison; a sentinel missing from it is a rule no
// sweep in this file runs over, which is the defect this replaced.
func commitRefusalClosure(t *testing.T) map[string]bool {
	t.Helper()
	mentions := map[string]map[string]bool{}
	sentinels := map[string]bool{}
	answersAnError := map[string]bool{}
	isATable := map[string]bool{}
	byBareName := map[string][]string{}
	read := 0
	for _, path := range packageSourcePaths(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		read += 1
		source := mustParseSource(t, path)
		packageLevelMentionsIn(source, mentions)
		for _, declaration := range source.file.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				name := typed.Name.Name
				if typed.Recv != nil && len(typed.Recv.List) == 1 {
					name = receiverTypeName(typed.Recv.List[0].Type) + "." + name
				}
				byBareName[typed.Name.Name] = append(byBareName[typed.Name.Name], name)
				if typed.Type.Results == nil {
					continue
				}
				for _, result := range typed.Type.Results.List {
					if source.render(result.Type) == "error" {
						answersAnError[name] = true
					}
				}
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					value, isValue := spec.(*ast.ValueSpec)
					if !isValue {
						continue
					}
					for _, ident := range value.Names {
						byBareName[ident.Name] = append(byBareName[ident.Name], ident.Name)
						isATable[ident.Name] = true
						if strings.HasPrefix(ident.Name, "err") || strings.HasPrefix(ident.Name, "Err") {
							sentinels[ident.Name] = true
						}
					}
				}
			}
		}
	}
	if read < 2 || len(sentinels) == 0 {
		t.Fatalf("the scan read %d non test files and found %d sentinels, so the closure below walked nothing",
			read, len(sentinels))
	}
	roots := map[string]map[string]bool{}
	packageLevelMentionsIn(mustParseSource(t, commitValidationFile), roots)
	if len(roots) == 0 {
		t.Fatalf("%s declares nothing, so the closure has no root", commitValidationFile)
	}
	queue := slices.Sorted(maps.Keys(roots))
	walked := map[string]bool{}
	reached := map[string]bool{}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if walked[name] {
			continue
		}
		walked[name] = true
		for ident := range mentions[name] {
			if sentinels[ident] {
				reached[ident] = true
				continue
			}
			for _, qualified := range byBareName[ident] {
				if (answersAnError[qualified] || isATable[qualified]) && !walked[qualified] {
					queue = append(queue, qualified)
				}
			}
		}
	}
	// the two controls. errMissingPath is named in the file itself, so a walk that resolved
	// nothing still finds it; ErrRemoveCommitter is named NOWHERE in that file except a comment
	// and is reachable only through the body ValSem200 delegates to, so it is the one that says
	// the graph was walked rather than the file scanned.
	if !reached["errMissingPath"] || !reached["ErrRemoveCommitter"] {
		t.Fatalf("the closure reached errMissingPath=%v and ErrRemoveCommitter=%v; both are answerable by a rule of %s and the second is answerable only through a delegation, so a walk missing it read the file rather than the graph",
			reached["errMissingPath"], reached["ErrRemoveCommitter"], commitValidationFile)
	}
	// and the control on the other side: a closure that reached every sentinel this package
	// declares is a walk with no edges rather than a class
	if len(reached) >= len(sentinels) {
		t.Fatalf("the closure reached %d of this package's %d sentinels, which is all of them; a class with no outside is not a class",
			len(reached), len(sentinels))
	}
	return reached
}

// TestCommitValidationBorrowedErrorsIsEveryErrorItsRulesCanReach holds the borrowed half of the
// roster to the derived class in both directions.
//
// This is the gate the borrowed half never had. It was twelve names held by nothing while the
// rules could reach thirty four, and the eight the reviewer happened to name -- ErrMalformedExtension,
// ErrTreeMalformed, ErrNodeTypeMismatch, ErrNilCryptoProvider, errNilProposalList, errNilRatchetTree,
// ErrNilGroupContext, errNilUpdatePath -- were every one of them outside both exclusivity sweeps.
func TestCommitValidationBorrowedErrorsIsEveryErrorItsRulesCanReach(t *testing.T) {
	reached := commitRefusalClosure(t)
	borrowed := []string{}
	for _, name := range slices.Sorted(maps.Keys(reached)) {
		if _, owned := commitValidationOwnedErrors[name]; owned {
			continue
		}
		borrowed = append(borrowed, name)
	}
	if got, want := slices.Sorted(maps.Keys(commitValidationBorrowedErrors)), borrowed; !slices.Equal(got, want) {
		t.Fatalf("the rules of %s can reach %v and commitValidationBorrowedErrors holds %v; every sweep in this file runs over the second, so a name missing from it is a value no rule here is held against and a name that is only in it is a sweep over a refusal nothing can produce",
			commitValidationFile, want, got)
	}
	// and every owned name is inside the closure too, or the file declares a value nothing it
	// states can answer
	for _, name := range slices.Sorted(maps.Keys(commitValidationOwnedErrors)) {
		if !reached[name] {
			t.Errorf("%s declares %s and no rule of it can answer that value", commitValidationFile, name)
		}
	}
}

// TestEveryCommitValidationRefusalIsDistinctFromEveryOther holds the roster pairwise apart.
//
// Both directions of every ordered pair, because errors.Is is not symmetric: a wrap holds one way
// only, and the sanctioned one is exactly such a pair.
func TestEveryCommitValidationRefusalIsDistinctFromEveryOther(t *testing.T) {
	roster := commitRefusalRoster()
	names := slices.Sorted(maps.Keys(roster))
	if len(names) < len(commitValidationOwnedErrors) {
		t.Fatal("the roster is smaller than this file's own class, so it read nothing")
	}
	pairs := 0
	for _, first := range names {
		for _, second := range names {
			if first == second {
				continue
			}
			if !errors.Is(roster[first], roster[second]) {
				pairs += 1
				continue
			}
			if commitValidationSanctionedWraps[first] == second {
				t.Logf("%s answers %s, which is the sanctioned wrap", first, second)
				continue
			}
			t.Errorf("%s answers %s and no wrap is sanctioned between them; errors.Is cannot tell two rules apart when one answers the other, so a negative test asserting either passes over a rule that fired for the wrong reason",
				first, second)
		}
	}
	if pairs == 0 {
		t.Fatal("no ordered pair of the roster was distinct, which cannot be true, so the sweep compared nothing")
	}
	for _, wrapped := range slices.Sorted(maps.Keys(commitValidationSanctionedWraps)) {
		outer, held := roster[wrapped]
		inner, alsoHeld := roster[commitValidationSanctionedWraps[wrapped]]
		if !held || !alsoHeld {
			t.Errorf("a wrap is sanctioned between %s and %s and one of them is not in the roster",
				wrapped, commitValidationSanctionedWraps[wrapped])
			continue
		}
		if !errors.Is(outer, inner) {
			t.Errorf("a wrap is sanctioned between %s and %s and it does not hold; the sanction has outlived the wrap",
				wrapped, commitValidationSanctionedWraps[wrapped])
		}
	}
}

// commitRuleCase is one refusal a rule of validate_commit.go can answer, the input that produces
// it, and the sentinel it owes.
//
// A SLICE AND NOT A MAP KEYED BY RULE, because a rule answers more than one value and a map keyed
// by rule admits exactly one row for each. That is how ValSem205's missing provider, ValSem205's
// absent tag, ValSem204's non-member committer, three of ValSem209's four profile refusals,
// ValSem300's missing tree, CheckErrata8745's missing context and every value the argument rule
// answers came to be outside this sweep -- and it is why ValSem205's nil-provider refusal could be
// rewritten to report a MALFORMED TREE with the whole suite green. A rule with one row is a rule
// whose other refusals are asserted by nothing.
type commitRuleCase struct {
	rule     string
	sentinel string
	run      func(t *testing.T) error
}

// commitRuleCases is one row per refusal this file's rules can answer, each building the input
// that produces exactly that refusal.
//
// This is the table ledger 17 asks for -- every code owes a test that names it -- and it is also
// the exclusivity sweep: TestEachCommitRuleAnswersOnlyItsOwnSentinel runs each row and requires
// every other member of the roster not to answer.
func commitRuleCases() []commitRuleCase {
	return []commitRuleCase{
		// the argument rule at the door, which is five conditions with five values plus the join
		// and the structural precondition. Driven through ValidateCommit rather than through
		// check, because check is not a door a caller can reach.
		{"CommitValidationInput.check", "errNilCommitValidationInput", func(t *testing.T) error {
			return ValidateCommit(nil)
		}},
		{"CommitValidationInput.check", "errNilCommit", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice")
			in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
			in.Commit = nil
			return ValidateCommit(in)
		}},
		{"CommitValidationInput.check", "errNilProposalList", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice")
			in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
			in.List = nil
			return ValidateCommit(in)
		}},
		{"CommitValidationInput.check", "errNilRatchetTree", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice")
			in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
			in.PostTree = nil
			return ValidateCommit(in)
		}},
		{"CommitValidationInput.check", "ErrNilGroupContext", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice")
			in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
			in.Context = nil
			return ValidateCommit(in)
		}},
		// the join, over the exact input RFC 9420 section 12.4's empty clause asserts against: a
		// commit naming no proposals and carrying no path. It was ACCEPTED, because the rule was
		// decided off a list the commit did not name.
		{"CommitValidationInput.check", "errCommitProposalsNotResolved", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob")
			kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "dave"))
			list := testProposalList(t, testAddOf(kp))
			return ValidateCommit(testCommitInput(t, crypto, tree, list,
				&Commit{Proposals: []ProposalOrRef{}}))
		}},
		// the bucket join, over the input the owner verified against the unmutated door: a list
		// whose All IS the faithful resolution of the commit's vector and whose Removes bucket is
		// empty. ValSem200 reads the bucket, so this commit -- which removes its own committer,
		// RFC 9420 section 12.2's own rule -- was accepted by the whole aggregate.
		{"CommitValidationInput.check", "ErrProposalListBucketsDisagree", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
			innocent := testRemoveOf(LeafIndex(2))
			list := &ProposalList{
				All:     []CachedProposal{innocent, testRemoveOf(LeafIndex(0))},
				Removes: []CachedProposal{innocent},
			}
			return ValidateCommit(testCommitInput(t, crypto, tree, list, &Commit{}))
		}},
		// the extension join, with the disagreement in the MIDDLE of the installed vector
		{"CommitValidationInput.check", "errCommitExtensionsNotApplied", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
			installed := testCommitInstalledExtensions()
			in := testCommitInput(t, crypto, tree,
				testProposalList(t, testGceOf(installed...)), &Commit{})
			announced := slices.Clone(installed)
			announced[1] = Extension{ExtensionType: announced[1].ExtensionType,
				ExtensionData: []byte{0xaa}}
			in.Extensions = announced
			return ValidateCommit(in)
		}},
		// the structural precondition, with the armless proposal behind an innocent one
		{"CommitValidationInput.check", "ErrContentArmMismatch", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
			armless := CachedProposal{ByValue: true,
				Proposal: Proposal{ProposalType: ProposalTypeRemove}}
			return ValidateCommit(testCommitInput(t, crypto, tree,
				testProposalList(t, testRemoveOf(2), armless), &Commit{}))
		}},
		{"ValSem200NoSelfRemove", "ErrRemoveCommitter", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
			list := testProposalList(t, testRemoveOf(2), testRemoveOf(0))
			return ValSem200NoSelfRemove(testCommitInput(t, crypto, tree, list, &Commit{}))
		}},
		{"ValSem201PathPresentWhenRequired", "errMissingPath", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob")
			return ValSem201PathPresentWhenRequired(
				testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{}))
		}},
		{"ValSem202PathLength", "errPathLength", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
			return ValSem202PathLength(testCommitInput(t, crypto, tree, &ProposalList{},
				&Commit{Path: testCommitPath(t, crypto, members[0], 1)}))
		}},
		{"validateCommitPathLeafSource", "ErrLeafNodeSourceMismatch", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, members := testTreeWith(t, crypto, "alice", "bob")
			leaf, _ := testLeafNode(t, crypto, members[0])
			return validateCommitPathLeafSource(testCommitInput(t, crypto, tree, &ProposalList{},
				&Commit{Path: &UpdatePath{LeafNode: *leaf}}))
		}},
		{"ValSem203PathDecrypt", "errPathDecrypt", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
			path := testCommitPath(t, crypto, members[0], 2)
			path.Nodes[1].EncryptedPathSecret = nil
			return ValSem203PathDecrypt(testCommitInput(t, crypto, tree, &ProposalList{},
				&Commit{Path: path}))
		}},
		{"ValSem204PathKeyMismatch", "errPathLeafKeyUnchanged", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, members := testTreeWith(t, crypto, "alice", "bob")
			leaf := testCommitPathLeaf(t, crypto, members[0])
			leaf.EncryptionKey = tree.Leaf(LeafIndex(0)).EncryptionKey
			return ValSem204PathKeyMismatch(testCommitInput(t, crypto, tree, &ProposalList{},
				&Commit{Path: &UpdatePath{LeafNode: *leaf}}))
		}},
		// ValSem204's precondition, which is a second value of the same rule and had no row
		{"ValSem204PathKeyMismatch", "errCommitterNotMember", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, members := testTreeWith(t, crypto, "alice", "bob")
			in := testCommitInput(t, crypto, tree, &ProposalList{},
				&Commit{Path: &UpdatePath{LeafNode: *testCommitPathLeaf(t, crypto, members[0])}})
			in.Committer = LeafIndex(41)
			return ValSem204PathKeyMismatch(in)
		}},
		// the refusal the reviewer's mutation rewrote: a rule about a missing provider reporting
		// a malformed tree was invisible to every sweep this file ran
		{"ValSem205ConfirmationTag", "ErrNilCryptoProvider", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice")
			in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
			in.Crypto = nil
			return ValSem205ConfirmationTag(in)
		}},
		{"ValSem205ConfirmationTag", "errMissingConfirmationTag", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice")
			in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
			in.ConfirmationKey = make([]byte, crypto.HashSize())
			in.ConfirmedHash = []byte("confirmed")
			return ValSem205ConfirmationTag(in)
		}},
		{"ValSem205ConfirmationTag", "errBadConfirmationTag", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice")
			in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
			in.ConfirmationKey = make([]byte, crypto.HashSize())
			in.ConfirmedHash = []byte("confirmed")
			in.ConfirmationTag = []byte("not the tag")
			return ValSem205ConfirmationTag(in)
		}},
		{"ValSem206PathLeafEncryptionKeyUnique", "errDuplicateEncryptionKey", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, members := testTreeWith(t, crypto, "alice", "bob")
			innocent, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "erin"))
			colliding, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "frank"))
			list := testProposalList(t, testAddOf(innocent), testAddOf(colliding))
			leaf := testCommitPathLeaf(t, crypto, members[0])
			leaf.EncryptionKey = colliding.LeafNode.EncryptionKey
			return ValSem206PathLeafEncryptionKeyUnique(testCommitInput(t, crypto, tree, list,
				&Commit{Path: &UpdatePath{LeafNode: *leaf}}))
		}},
		{"ValSem207PathEncryptionKeysUnique", "errDuplicateEncryptionKey", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
			path := testCommitPath(t, crypto, testIdentity(t, crypto, "mallory"), 2)
			path.Nodes[1].EncryptionKey = tree.Leaf(LeafIndex(2)).EncryptionKey
			return ValSem207PathEncryptionKeysUnique(testCommitInput(t, crypto, tree,
				&ProposalList{}, &Commit{Path: path}))
		}},
		{"ValSem208SingleGroupContextExtensions", "errMultipleGroupContextExtensions", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice")
			one := testGceOf()
			return ValSem208SingleGroupContextExtensions(
				testCommitInput(t, crypto, tree, testProposalList(t, one, one), &Commit{}))
		}},
		// ValSem209's four refusals, each with the offending entry at index 1. Three of the four
		// had no row at all: the profile half of the rule was asserted by the one sentinel that
		// happened to be first in the table.
		{"ValSem209GroupExtensionsSupported", "errProfileExternalSender", func(t *testing.T) error {
			return testValSem209Refusal(t, Extension{ExtensionType: ExtensionTypeExternalSenders})
		}},
		{"ValSem209GroupExtensionsSupported", "errProfileGroupExtension", func(t *testing.T) error {
			return testValSem209Refusal(t, Extension{ExtensionType: ExtensionTypeUrmessageLeafKeys})
		}},
		{"ValSem209GroupExtensionsSupported", "errUnregisteredGroupExtension", func(t *testing.T) error {
			return testValSem209Refusal(t, Extension{ExtensionType: ExtensionType(0xABCD)})
		}},
		{"ValSem209GroupExtensionsSupported", "errProfileExternalCommit", func(t *testing.T) error {
			return testValSem209Refusal(t, Extension{ExtensionType: ExtensionTypeExternalPub})
		}},
		// and the two member clauses, which are section 13.4's and section 7.3's and are two
		// values because they are two rules
		{"ValSem209GroupExtensionsSupported", "errGroupContextExtensionNotListed", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob")
			testNarrowLeafCapabilities(t, tree, LeafIndex(1))
			list := testProposalList(t, testGceOf(
				Extension{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: []byte{}},
				Extension{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor, ExtensionData: []byte{}}))
			return ValSem209GroupExtensionsSupported(testCommitInput(t, crypto, tree, list, &Commit{}))
		}},
		{"ValSem209GroupExtensionsSupported", "errMissingRequiredCapability", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob")
			testNarrowLeafCapabilities(t, tree, LeafIndex(1))
			list := testProposalList(t, testGceOf(
				testRequiredCapabilitiesNaming(t, ExtensionTypeUrmessageOwnerSuccessor)))
			return ValSem209GroupExtensionsSupported(testCommitInput(t, crypto, tree, list, &Commit{}))
		}},
		{"ValSem300NoTrailingBlankNodes", "errTrailingBlankNodes", func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob")
			padded := tree.Clone()
			if failure := padded.Blank(NodeIndex(padded.NodeWidth() - 1)); failure != nil {
				t.Fatalf("Blank: %v", failure)
			}
			return ValSem300NoTrailingBlankNodes(padded)
		}},
		{"ValSem300NoTrailingBlankNodes", "ErrTreeMalformed", func(t *testing.T) error {
			return ValSem300NoTrailingBlankNodes(nil)
		}},
		{"CheckErrata8745", "errGroupContextExtensionNotListed", func(t *testing.T) error {
			crypto := testCrypto(t)
			leaf := testCommitPathLeaf(t, crypto, testIdentity(t, crypto, "alice"))
			leaf.Capabilities = testNarrowedCapabilities()
			return CheckErrata8745(&UpdatePath{LeafNode: *leaf}, &GroupContext{
				GroupId: []byte("group"),
				Extensions: []Extension{
					{ExtensionType: ExtensionTypeRequiredCapabilities},
					{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor},
				}})
		}},
		{"CheckErrata8745", "ErrNilGroupContext", func(t *testing.T) error {
			crypto := testCrypto(t)
			leaf := testCommitPathLeaf(t, crypto, testIdentity(t, crypto, "alice"))
			return CheckErrata8745(&UpdatePath{LeafNode: *leaf}, nil)
		}},
		{"CheckErrata8815", "errProposalNotCached", func(t *testing.T) error {
			crypto := testCrypto(t)
			cache := testCacheAt(t, testResolveContext())
			ref, failure := cache.Store(crypto, testResolveContext(),
				testProposalContent(t, crypto, LeafIndex(1),
					&Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 4}}))
			if failure != nil {
				t.Fatalf("Store: %v", failure)
			}
			return CheckErrata8815(&Commit{Proposals: []ProposalOrRef{
				{Type: ProposalOrRefTypeReference, Reference: ref},
				{Type: ProposalOrRefTypeReference,
					Reference: ProposalRef(append(append([]byte(nil), ref...), 0x5a))},
			}}, cache)
		}},
	}
}

// testValSem209Refusal drives ValSem209's profile half over one extension type, with the offending
// entry SECOND: a rule narrowed to entry zero steps over the admitted type in front of it.
func testValSem209Refusal(t *testing.T, offending Extension) error {
	t.Helper()
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	list := testProposalList(t, testGceOf(
		Extension{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: []byte{}}, offending))
	failure := ValSem209GroupExtensionsSupported(testCommitInput(t, crypto, tree, list, &Commit{}))
	if failure != nil && !strings.Contains(failure.Error(), "entry 1") {
		t.Errorf("ValSem209 over %#04x refused without naming which entry: %v",
			uint16(offending.ExtensionType), failure)
	}
	return failure
}

// TestEachCommitRuleAnswersOnlyItsOwnSentinel is ledger 17's obligation and the exclusivity sweep
// in one: every refusal this file's rules can answer has a row, the row's refusal answers the
// sentinel it owes, and no other member of the roster answers it.
func TestEachCommitRuleAnswersOnlyItsOwnSentinel(t *testing.T) {
	roster := commitRefusalRoster()
	for _, row := range commitRuleCases() {
		t.Run(row.rule+"/"+row.sentinel, func(t *testing.T) {
			owed, held := roster[row.sentinel]
			if !held {
				t.Fatalf("%s owes %s and that name is not in the roster", row.rule, row.sentinel)
			}
			failure := row.run(t)
			if failure == nil {
				t.Fatalf("%s did not refuse the input built for it, so this row states nothing about %s",
					row.rule, row.sentinel)
			}
			if !errors.Is(failure, owed) {
				t.Fatalf("%s answered %v, want %s", row.rule, failure, row.sentinel)
			}
			for _, other := range slices.Sorted(maps.Keys(roster)) {
				if other == row.sentinel || commitValidationSanctionedWraps[row.sentinel] == other {
					continue
				}
				if errors.Is(failure, roster[other]) {
					t.Errorf("%s refused with %v, which also answers %s; a caller cannot tell which rule fired and a negative test asserting %s would pass over this one",
						row.rule, failure, other, other)
				}
			}
		})
	}
}

// commitRuleCaseRulesStatedOverSomethingElse is the four names a row may carry that
// commitRuleNamesDeclared cannot produce, with the reason each is outside that class.
//
// Held in both directions by the gate below, so an entry that stops being true fails.
var commitRuleCaseRulesStatedOverSomethingElse = map[string]string{
	"ValSem300NoTrailingBlankNodes": "is stated over a ratchet tree, because task 16's welcome path asks it of a tree that arrived in a GroupInfo and holds no commit at all",
	"CheckErrata8745":               "is stated over an update path and a context, because p7 task 18 calls it with values it holds rather than with a validation input it would have to assemble",
	"CheckErrata8815":               "is stated over a commit and a cache, for CheckErrata8745's reason",
	"CommitValidationInput.check":   "is the argument rule every door runs first and is a method rather than a rule function, so it is reached through ValidateCommit rather than called directly",
}

// TestEveryCommitRuleAndEveryRefusalItNamesHasARow holds the table to two derived classes at once.
//
// THE RULES, so a twelfth rule added to the file with no row is a rule the sweep does not run --
// which is the class check the map keyed by rule name already made. AND THE REFUSALS, which is the
// half that was missing: every sentinel validate_commit.go NAMES owes a row that produces it, so a
// rule answering four values cannot be covered by one. Both directions, so a row for a rule that
// has gone, or a sentinel the file no longer names, fails rather than sitting there.
func TestEveryCommitRuleAndEveryRefusalItNamesHasARow(t *testing.T) {
	cases := commitRuleCases()
	rules := map[string]bool{}
	produced := map[string]bool{}
	roster := commitRefusalRoster()
	for _, row := range cases {
		rules[row.rule] = true
		produced[row.sentinel] = true
		if _, held := roster[row.sentinel]; !held {
			t.Errorf("a row for %s owes %s and the roster does not hold that name", row.rule, row.sentinel)
		}
	}
	declared := commitRuleNamesDeclared(t)
	adapters := map[string]bool{
		"ValidateCommit": true, "validateCommitErrata": true,
		"validateCommitPostTreeIsExportable": true,
	}
	for _, name := range declared {
		if adapters[name] || rules[name] {
			continue
		}
		t.Errorf("%s is a rule of this file and no row of commitRuleCases builds the input that makes it refuse; ledger 17 is that every code owes a test that names it",
			name)
	}
	for _, name := range slices.Sorted(maps.Keys(rules)) {
		if slices.Contains(declared, name) {
			continue
		}
		if _, excused := commitRuleCaseRulesStatedOverSomethingElse[name]; !excused {
			t.Errorf("commitRuleCases holds a row for %s and %s declares no rule of that name",
				name, commitValidationFile)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(commitRuleCaseRulesStatedOverSomethingElse)) {
		if !rules[name] {
			t.Errorf("a reason is written down for %s and no row carries that name; the excuse has outlived what it excused",
				name)
		}
	}
	// the refusals half: every sentinel the file itself names owes a row producing it
	named := commitFileSentinels(t)
	if len(named) < len(commitValidationOwnedErrors) {
		t.Fatalf("%s names %d sentinels and declares %d, so the scan read something other than that file",
			commitValidationFile, len(named), len(commitValidationOwnedErrors))
	}
	for _, name := range slices.Sorted(maps.Keys(named)) {
		if !produced[name] {
			t.Errorf("%s names %s and no row of commitRuleCases produces it. A rule that answers four values with one row is three refusals nothing asserts -- which is how a rule about a missing provider came to report a malformed tree with the whole suite green",
				commitValidationFile, name)
		}
	}
}

// commitFileSentinels is every sentinel of the roster that validate_commit.go's own declarations
// name, read off that file rather than listed.
func commitFileSentinels(t *testing.T) map[string]bool {
	t.Helper()
	mentions := map[string]map[string]bool{}
	packageLevelMentionsIn(mustParseSource(t, commitValidationFile), mentions)
	roster := commitRefusalRoster()
	named := map[string]bool{}
	for _, identifiers := range mentions {
		for identifier := range identifiers {
			if _, held := roster[identifier]; held {
				named[identifier] = true
			}
		}
	}
	return named
}

// TestTheV1ProfileClassifiesEveryRegisteredExtensionTypeAsAGroupContextExtension holds the profile
// table to the registry in both directions.
func TestTheV1ProfileClassifiesEveryRegisteredExtensionTypeAsAGroupContextExtension(t *testing.T) {
	declared := registryConstantsOfType(t, "ExtensionType")
	if len(declared) == 0 {
		t.Fatal("this package declares no ExtensionType constant, so this gate read nothing")
	}
	classified := map[uint64]bool{}
	for code := range groupExtensionProfile {
		classified[uint64(code)] = true
	}
	admitted := 0
	refused := 0
	for _, name := range slices.Sorted(maps.Keys(declared)) {
		code := declared[name]
		if !classified[code] {
			t.Errorf("extension.go declares %s at %#04x and groupExtensionProfile has no row for it; a code point with no row is one ValSem209 answers 'not registered' about, which is a sentence about a registration that is right there",
				name, code)
			continue
		}
		if groupExtensionProfile[ExtensionType(code)] == nil {
			admitted += 1
		} else {
			refused += 1
		}
	}
	byCode := map[uint64]string{}
	for name, code := range declared {
		byCode[code] = name
	}
	for code := range classified {
		if _, isConstant := byCode[code]; !isConstant {
			t.Errorf("groupExtensionProfile holds a row for %#04x and this package declares no ExtensionType constant of that value",
				code)
		}
	}
	// both halves non-empty, or the table is satisfied by one answer
	if admitted == 0 || refused == 0 {
		t.Fatalf("the profile admits %d extension types and refuses %d; a table whose answer is the same for every member states nothing",
			admitted, refused)
	}
	t.Logf("%d registered extension types, %d admitted in a group context and %d refused",
		admitted+refused, admitted, refused)
}

// TestEveryCommitValidationEntryPointRefusesANilInput drives the argument rule at every door.
//
// The class is the DERIVED one, so a rule added to the file is swept without anybody editing this.
// commitValidationDoors is every entry point of validate_commit.go that takes a validation input,
// as a value rather than as a name.
//
// It is a function rather than a literal inside one test because TWO sweeps need the same class:
// the nil argument rule below, and the arm rule that says none of these dereferences a proposal
// whose arm is missing. Both are held to commitRuleNamesDeclared in both directions, so a rule
// added to the file is swept by both without anybody editing either.
func commitValidationDoors() map[string]func(*CommitValidationInput) error {
	return map[string]func(*CommitValidationInput) error{
		"ValidateCommit":                        ValidateCommit,
		"ValSem200NoSelfRemove":                 ValSem200NoSelfRemove,
		"ValSem201PathPresentWhenRequired":      ValSem201PathPresentWhenRequired,
		"ValSem202PathLength":                   ValSem202PathLength,
		"validateCommitPathLeafSource":          validateCommitPathLeafSource,
		"ValSem203PathDecrypt":                  ValSem203PathDecrypt,
		"ValSem204PathKeyMismatch":              ValSem204PathKeyMismatch,
		"ValSem205ConfirmationTag":              ValSem205ConfirmationTag,
		"ValSem206PathLeafEncryptionKeyUnique":  ValSem206PathLeafEncryptionKeyUnique,
		"ValSem207PathEncryptionKeysUnique":     ValSem207PathEncryptionKeysUnique,
		"ValSem208SingleGroupContextExtensions": ValSem208SingleGroupContextExtensions,
		"ValSem209GroupExtensionsSupported":     ValSem209GroupExtensionsSupported,
		"validateCommitErrata":                  validateCommitErrata,
		"validateCommitPostTreeIsExportable":    validateCommitPostTreeIsExportable,
	}
}

func TestEveryCommitValidationEntryPointRefusesANilInput(t *testing.T) {
	doors := commitValidationDoors()
	declared := commitRuleNamesDeclared(t)
	for _, name := range declared {
		if _, driven := doors[name]; !driven {
			t.Errorf("%s takes a *CommitValidationInput and this gate does not drive it with nil; a door with no argument rule dereferences what it was handed and takes the caller's process rather than its call",
				name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(doors)) {
		if !slices.Contains(declared, name) {
			t.Errorf("this gate drives %s and %s declares no rule of that name", name, commitValidationFile)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(doors)) {
		if failure := doors[name](nil); !errors.Is(failure, errNilCommitValidationInput) {
			t.Errorf("%s(nil) = %v, want errNilCommitValidationInput", name, failure)
		}
	}
	// and the three fields the input rule separates, each with its own value
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	for _, row := range []struct {
		name     string
		mutate   func(*CommitValidationInput)
		sentinel error
	}{
		{"no commit", func(in *CommitValidationInput) { in.Commit = nil }, errNilCommit},
		{"no proposal list", func(in *CommitValidationInput) { in.List = nil }, errNilProposalList},
		{"no pre tree", func(in *CommitValidationInput) { in.PreTree = nil }, errNilRatchetTree},
		{"no post tree", func(in *CommitValidationInput) { in.PostTree = nil }, errNilRatchetTree},
		{"no group context", func(in *CommitValidationInput) { in.Context = nil }, ErrNilGroupContext},
	} {
		in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
		row.mutate(in)
		if failure := ValidateCommit(in); !errors.Is(failure, row.sentinel) {
			t.Errorf("ValidateCommit with %s = %v, want %v", row.name, failure, row.sentinel)
		}
	}
}

// TestValidateCommitAcceptsAWellFormedFullCommit is the accepting half of the aggregate, and it is
// the control every row of the table below is measured against.
//
// Without it every rule could be "return the refusal unconditionally" and the whole file would
// still be green. The fixture is a four member group and a full commit from leaf 0 with a fresh
// path of the filtered direct path's own length, which is section 12.4's "empty" configuration and
// the one every row below is one edit away from.
func TestValidateCommitAcceptsAWellFormedFullCommit(t *testing.T) {
	crypto := testCrypto(t)
	in, _ := testFullCommitInput(t, crypto)
	if failure := ValidateCommit(in); failure != nil {
		t.Fatalf("ValidateCommit refused a well formed full commit: %v", failure)
	}
}

// commitRuleName is the declared name of one rule of commitValidationChecks, read off the VALUE
// rather than written beside it, so a row cannot claim to cover a rule it does not hold.
func commitRuleName(rule func(*CommitValidationInput) error) string {
	full := runtime.FuncForPC(reflect.ValueOf(rule).Pointer()).Name()
	return full[strings.LastIndex(full, ".")+1:]
}

// commitRulesTheAggregateRuns is every rule ValidateCommit runs, in the order it runs them, read
// off the production slice rather than listed here.
func commitRulesTheAggregateRuns() []string {
	names := []string{}
	for _, rule := range commitValidationChecks {
		names = append(names, commitRuleName(rule))
	}
	return names
}

// commitRuleFor answers the rule function of that name out of the production slice, so a row is
// joined to a rule the aggregate actually runs.
func commitRuleFor(t *testing.T, name string) func(*CommitValidationInput) error {
	t.Helper()
	for _, rule := range commitValidationChecks {
		if commitRuleName(rule) == name {
			return rule
		}
	}
	t.Fatalf("no rule of ValidateCommit is named %s", name)
	return nil
}

// commitAggregateRow is one rule of commitValidationChecks, an input that only that rule refuses,
// and the value it must answer THROUGH THE AGGREGATE.
type commitAggregateRow struct {
	rule     string
	sentinel error
	build    func(t *testing.T, crypto CryptoProvider) *CommitValidationInput
}

// commitAggregateRows is one row per rule the aggregate runs, each starting from the commit
// ValidateCommit accepts and breaking exactly one thing.
//
// THIS TABLE IS THE WHOLE OF WHAT SAYS THE AGGREGATE RUNS ITS RULES, and the gate it replaced said
// almost nothing. TestValidateCommitRunsEveryRuleThisFileDeclares reads the slice's SOURCE, so it
// says the names appear; the negative half drove one input, chosen to reach the LAST element, and
// a list where only the last element is driven is a list of one. Measured: validateCommitErrata
// neutered to return nil left the full 6961 test suite green, so neither erratum observably ran at
// all -- and the Pending cache the input carries for erratum 8815 was set by no test in the
// package.
//
// The map is keyed by a LABEL rather than by the rule, because one rule of the slice stands for
// two errata and each of them owes a row of its own. What the gate holds is that every rule the
// slice names is some row's rule and every row's rule is one the slice names.
func commitAggregateRows() map[string]commitAggregateRow {
	return map[string]commitAggregateRow{
		"ValSem200 over a commit that removes its own committer": {
			rule: "ValSem200NoSelfRemove", sentinel: ErrRemoveCommitter,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, _ := testFullCommitInput(t, crypto)
				testCommitProposals(t, in, testRemoveOf(2), testRemoveOf(0))
				return in
			}},
		"ValSem201 over a pathless commit that names no proposals": {
			rule: "ValSem201PathPresentWhenRequired", sentinel: errMissingPath,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, _ := testFullCommitInput(t, crypto)
				in.Commit.Path = nil
				return in
			}},
		"ValSem202 over a path one node short of the filtered direct path": {
			rule: "ValSem202PathLength", sentinel: errPathLength,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, _ := testFullCommitInput(t, crypto)
				in.Commit.Path.Nodes = in.Commit.Path.Nodes[:len(in.Commit.Path.Nodes)-1]
				return in
			}},
		"the path leaf source rule over a key_package sourced leaf": {
			rule: "validateCommitPathLeafSource", sentinel: ErrLeafNodeSourceMismatch,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, _ := testFullCommitInput(t, crypto)
				in.Commit.Path.LeafNode.LeafNodeSource = LeafNodeSourceKeyPackage
				return in
			}},
		"ValSem203 over a path whose second node encrypts to nobody": {
			rule: "ValSem203PathDecrypt", sentinel: errPathDecrypt,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, _ := testFullCommitInput(t, crypto)
				if len(in.Commit.Path.Nodes) < 2 {
					t.Fatalf("the fixture's path is %d nodes long, so an offender at node 1 cannot be built",
						len(in.Commit.Path.Nodes))
				}
				in.Commit.Path.Nodes[1].EncryptedPathSecret = nil
				return in
			}},
		"ValSem204 over a path leaf republishing the committer's current key": {
			rule: "ValSem204PathKeyMismatch", sentinel: errPathLeafKeyUnchanged,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, _ := testFullCommitInput(t, crypto)
				in.Commit.Path.LeafNode.EncryptionKey = in.PreTree.Leaf(in.Committer).EncryptionKey
				return in
			}},
		"ValSem206 over a path leaf whose key the second add publishes": {
			rule: "ValSem206PathLeafEncryptionKeyUnique", sentinel: errDuplicateEncryptionKey,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, _ := testFullCommitInput(t, crypto)
				innocent, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "erin"))
				colliding, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "frank"))
				testCommitProposals(t, in, testAddOf(innocent), testAddOf(colliding))
				in.Commit.Path.LeafNode.EncryptionKey = colliding.LeafNode.EncryptionKey
				return in
			}},
		"ValSem207 over a path node reusing a leaf's key": {
			rule: "ValSem207PathEncryptionKeysUnique", sentinel: errDuplicateEncryptionKey,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, _ := testFullCommitInput(t, crypto)
				in.Commit.Path.Nodes[1].EncryptionKey = in.PostTree.Leaf(LeafIndex(2)).EncryptionKey
				return in
			}},
		"ValSem208 over a commit carrying two group_context_extensions proposals": {
			rule: "ValSem208SingleGroupContextExtensions", sentinel: errMultipleGroupContextExtensions,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, _ := testFullCommitInput(t, crypto)
				one := testGceOf()
				testCommitProposals(t, in, one, one)
				return in
			}},
		"ValSem209 over an extension one remaining member does not support": {
			rule: "ValSem209GroupExtensionsSupported", sentinel: errGroupContextExtensionNotListed,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, members := testFullCommitInput(t, crypto)
				testNarrowLeafCapabilities(t, in.PostTree, LeafIndex(1))
				testFitCommitPath(t, crypto, in, members[0])
				testCommitProposals(t, in, testGceOf(
					Extension{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: []byte{}},
					Extension{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor, ExtensionData: []byte{}}))
				return in
			}},
		// erratum 8745 through the aggregate, and it is also the only thing in this package that
		// observes the extension set the COMMIT installs. The path leaf is not in the post tree,
		// so ValSem209's member walk cannot see it -- see
		// TestTheExtensionSetTheCommitInstallsIsWhatItsPathLeafOwesSupportFor next door.
		"validateCommitErrata over a path leaf that drops an extension the commit installs": {
			rule: "validateCommitErrata", sentinel: errGroupContextExtensionNotListed,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, _ := testFullCommitInput(t, crypto)
				testCommitProposals(t, in, testGceOf(
					Extension{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: []byte{}},
					Extension{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor, ExtensionData: []byte{}}))
				in.Commit.Path.LeafNode.Capabilities = testNarrowedCapabilities()
				return in
			}},
		// erratum 8815 through the aggregate, over a Pending cache -- the field the task added and
		// no test set, which is why the erratum could be deleted with the suite green
		"validateCommitErrata over a reference this member never received": {
			rule: "validateCommitErrata", sentinel: errProposalNotCached,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, _ := testFullCommitInput(t, crypto)
				cache := testCacheAt(t, testResolveContext())
				ref, failure := cache.Store(crypto, testResolveContext(),
					testProposalContent(t, crypto, LeafIndex(1),
						&Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}}))
				if failure != nil {
					t.Fatalf("Store: %v", failure)
				}
				in.Pending = cache
				held := CachedProposal{Ref: ref, Sender: LeafIndex(1),
					Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}}}
				never := CachedProposal{
					Ref:      ProposalRef(append(append([]byte(nil), ref...), 0x5a)),
					Sender:   LeafIndex(1),
					Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 3}}}
				testCommitProposals(t, in, held, never)
				return in
			}},
		"ValSem300 over a post tree ending in a blank node": {
			rule: "validateCommitPostTreeIsExportable", sentinel: errTrailingBlankNodes,
			build: func(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
				in, members := testFullCommitInput(t, crypto)
				if failure := in.PostTree.Blank(NodeIndex(in.PostTree.NodeWidth() - 1)); failure != nil {
					t.Fatalf("Blank: %v", failure)
				}
				// blanking the rightmost leaf changes the filtered direct path, so the path is
				// re-fitted against the tree the aggregate reads
				testFitCommitPath(t, crypto, in, members[0])
				return in
			}},
	}
}

// TestValidateCommitReachesEveryRuleItRuns is the aggregate's negative half: for each rule in the
// slice, an input that only that rule refuses comes back with that rule's sentinel out of
// ValidateCommit itself.
//
// TWO CLAIMS PER ROW and they are different claims. The named rule must answer the row's value,
// which says the fixture breaks the rule the row says it breaks. And the AGGREGATE must answer the
// same value, which says the loop reaches this rule with this input -- a rule the loop skipped, or
// a rule neutered to return nil, answers something else or nothing at all.
func TestValidateCommitReachesEveryRuleItRuns(t *testing.T) {
	crypto := testCrypto(t)
	rows := commitAggregateRows()
	for _, label := range slices.Sorted(maps.Keys(rows)) {
		row := rows[label]
		t.Run(label, func(t *testing.T) {
			in := row.build(t, crypto)
			ruled := commitRuleFor(t, row.rule)(in)
			if !errors.Is(ruled, row.sentinel) {
				t.Fatalf("%s over the fixture built for it answered %v, want %v; the row does not break the rule it names",
					row.rule, ruled, row.sentinel)
			}
			aggregated := ValidateCommit(in)
			if !errors.Is(aggregated, row.sentinel) {
				t.Fatalf("ValidateCommit answered %v and %s answers %v; the aggregate is not reaching this rule with this input",
					aggregated, row.rule, row.sentinel)
			}
		})
	}
}

// TestEveryRuleTheCommitAggregateRunsHasARowAndEveryRowIsARuleItRuns holds the table above to the
// production slice in both directions.
//
// Without it the table is a list, and a list is what rule 5 is about: a thirteenth rule appended to
// commitValidationChecks with no row would be run by the aggregate and asserted by nothing, and a
// row naming a rule that had been taken out would go on reporting a clean bill over a rule that no
// longer runs.
func TestEveryRuleTheCommitAggregateRunsHasARowAndEveryRowIsARuleItRuns(t *testing.T) {
	rules := commitRulesTheAggregateRuns()
	if !slices.Contains(rules, "ValSem209GroupExtensionsSupported") {
		t.Fatalf("the slice reads as %v and ValidateCommit certainly runs ValSem209GroupExtensionsSupported, so the names are being read off something else",
			rules)
	}
	rows := commitAggregateRows()
	covered := map[string]bool{}
	for _, label := range slices.Sorted(maps.Keys(rows)) {
		covered[rows[label].rule] = true
		if !slices.Contains(rules, rows[label].rule) {
			t.Errorf("the row %q names %s and ValidateCommit runs no rule under that name",
				label, rows[label].rule)
		}
	}
	for _, name := range rules {
		if !covered[name] {
			t.Errorf("ValidateCommit runs %s and no row builds an input that only it refuses, so nothing says the aggregate reaches it",
				name)
		}
	}
}

// ---------------------------------------------------------------------------
// the two fields that are one commit, and the two trees that are not one tree
// ---------------------------------------------------------------------------

// testCachedRemoveOf stores a remove of one leaf in a cache and answers the reference it is keyed
// by beside the list entry that names it -- the two halves the join holds together.
func testCachedRemoveOf(t *testing.T, crypto CryptoProvider, cache *ProposalCache,
	removed LeafIndex) CachedProposal {

	t.Helper()
	proposal := Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: removed}}
	ref, failure := cache.Store(crypto, testResolveContext(),
		testProposalContent(t, crypto, LeafIndex(1), &proposal))
	if failure != nil {
		t.Fatalf("Store a remove of leaf %d: %v", removed, failure)
	}
	return CachedProposal{Ref: ref, Sender: LeafIndex(1), Proposal: proposal}
}

// TestValidateCommitRefusesAListThatIsNotTheCommitsOwnProposalVector is the join, over the input
// RFC 9420 section 12.4's own pseudocode asserts against.
//
// THE PROBE. Section 12.4 reads "if len(commit.proposals) == 0 || pathRequired: assert(commit.path
// != null)", and ValSem201 decides it off List. A commit carrying Proposals nil and Path nil --
// which the RFC refuses outright -- was ACCEPTED whenever the caller handed over a non-empty list
// that lets the path be omitted, because the rule was reading a field the commit did not name.
//
// THE SIX WAYS TO DISAGREE are the six things the join compares, and each is driven from a commit
// ValidateCommit ACCEPTS -- one whose only proposal is a remove this member has actually received,
// named by reference. That base is what makes each row exact: with the disagreement introduced the
// only rule that can refuse is the join, so a row that stopped being refused would be a clause
// nothing holds. Measured: without it, dropping the by-reference half of the by-value line was
// still "caught", by a path rule that fired on the way past.
func TestValidateCommitRefusesAListThatIsNotTheCommitsOwnProposalVector(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "dave"))

	// an add-only list lets section 12.4 omit the path, and the commit itself names no proposals
	// at all, so section 12.4 requires one
	addOnly := testProposalList(t, testAddOf(kp))
	probe := testCommitInput(t, crypto, tree, addOnly, &Commit{Proposals: []ProposalOrRef{}})
	if CommitPathRequired(probe.List) {
		t.Fatal("the fixture's list requires a path of its own, so it cannot tell the two fields apart")
	}
	if failure := ValidateCommit(probe); !errors.Is(failure, errCommitProposalsNotResolved) {
		t.Fatalf("ValidateCommit over a commit naming no proposals and carrying no path = %v, want errCommitProposalsNotResolved; that commit is the one section 12.4's empty clause asserts against and it was accepted because the rule read a list the commit does not name",
			failure)
	}

	// the base: a commit whose TWO proposals are removes this member holds, both named by
	// reference.
	//
	// TWO AND NOT ONE, and every row below plants its disagreement at entry ONE. The join walks the
	// vector, and over a base carrying a single entry every row of this table was answered by a read
	// of its head: narrowed to i < 1 the whole loop stayed green over all seven rows, which is the
	// element-zero shape this file's own header states the doctrine for. With an agreeing entry in
	// front of the disagreeing one, a loop and a read of the head are told apart.
	base := func(t *testing.T) (*CommitValidationInput, CachedProposal, CachedProposal, CachedProposal) {
		t.Helper()
		in, _ := testFullCommitInput(t, crypto)
		cache := testCacheAt(t, testResolveContext())
		in.Pending = cache
		agreeing := testCachedRemoveOf(t, crypto, cache, LeafIndex(1))
		held := testCachedRemoveOf(t, crypto, cache, LeafIndex(2))
		other := testCachedRemoveOf(t, crypto, cache, LeafIndex(3))
		in.List = testProposalList(t, agreeing, held)
		in.Commit.Proposals = []ProposalOrRef{
			{Type: ProposalOrRefTypeReference, Reference: agreeing.Ref},
			{Type: ProposalOrRefTypeReference, Reference: held.Ref}}
		return in, agreeing, held, other
	}
	// the control. Every row below is this commit with one field of its SECOND entry changed, so a
	// row that is refused is refused by the join and by nothing else.
	control, _, _, _ := base(t)
	if failure := ValidateCommit(control); failure != nil {
		t.Fatalf("ValidateCommit refused the commit every row below is one edit away from: %v", failure)
	}
	if len(control.List.All) < 2 || len(control.Commit.Proposals) < 2 {
		t.Fatalf("the base carries %d list entries and %d vector entries; a base of one cannot tell the join's loop from a read of its head",
			len(control.List.All), len(control.Commit.Proposals))
	}

	// every row names the FIELD of a ProposalOrRef it makes the two disagree over, and the gate
	// below holds those names to the struct: a fourth field added to the type with no row here
	// would be a field of the commit's own vector that the join does not compare and nothing
	// notices. The count is the one row that is not a field, and it is named as such.
	rows := []struct {
		name  string
		field string
		apply func(t *testing.T, in *CommitValidationInput,
			agreeing CachedProposal, held CachedProposal, other CachedProposal)
	}{
		{"a list longer than the commit's own vector", "",
			func(t *testing.T, in *CommitValidationInput,
				agreeing CachedProposal, held CachedProposal, other CachedProposal) {
				in.List = testProposalList(t, agreeing, held, other)
			}},
		{"an entry the list holds by value and the commit names by reference", "Type",
			func(t *testing.T, in *CommitValidationInput,
				agreeing CachedProposal, held CachedProposal, other CachedProposal) {
				inline := held
				inline.ByValue = true
				in.List = testProposalList(t, agreeing, inline)
			}},
		{"an entry the list holds by reference and the commit carries by value", "Type",
			func(t *testing.T, in *CommitValidationInput,
				agreeing CachedProposal, held CachedProposal, other CachedProposal) {
				carried := held.Proposal
				in.Commit.Proposals[1] = ProposalOrRef{
					Type: ProposalOrRefTypeProposal, Proposal: &carried}
			}},
		{"a reference the list does not name, naming a proposal this member does hold", "Reference",
			func(t *testing.T, in *CommitValidationInput,
				agreeing CachedProposal, held CachedProposal, other CachedProposal) {
				in.Commit.Proposals[1] = ProposalOrRef{
					Type: ProposalOrRefTypeReference, Reference: other.Ref}
			}},
		{"a by-value entry of another type", "Proposal",
			func(t *testing.T, in *CommitValidationInput,
				agreeing CachedProposal, held CachedProposal, other CachedProposal) {
				inline := held
				inline.ByValue = true
				in.List = testProposalList(t, agreeing, inline)
				in.Commit.Proposals[1] = ProposalOrRef{Type: ProposalOrRefTypeProposal,
					Proposal: &Proposal{ProposalType: ProposalTypeGroupContextExtensions,
						GroupContextExtensions: &GroupContextExtensions{}}}
			}},
		{"a by-value entry carrying no proposal at all", "Proposal",
			func(t *testing.T, in *CommitValidationInput,
				agreeing CachedProposal, held CachedProposal, other CachedProposal) {
				inline := held
				inline.ByValue = true
				in.List = testProposalList(t, agreeing, inline)
				in.Commit.Proposals[1] = ProposalOrRef{Type: ProposalOrRefTypeProposal}
			}},
		{"a discriminant that names neither a proposal nor a reference", "Type",
			func(t *testing.T, in *CommitValidationInput,
				agreeing CachedProposal, held CachedProposal, other CachedProposal) {
				in.Commit.Proposals[1] = ProposalOrRef{Type: ProposalOrRefTypeReserved}
			}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			in, agreeing, held, other := base(t)
			row.apply(t, in, agreeing, held, other)
			failure := ValidateCommit(in)
			if !errors.Is(failure, errCommitProposalsNotResolved) {
				t.Fatalf("ValidateCommit over %s = %v, want errCommitProposalsNotResolved", row.name, failure)
			}
			// and the refusal names the entry it fired at, which is the whole of what separates a
			// walk of the vector from a read of its head
			if row.name != "a list longer than the commit's own vector" &&
				!strings.Contains(failure.Error(), "entry 1") {
				t.Errorf("ValidateCommit over %s refused with %v without naming entry 1, where the disagreement is; a join that answered element zero cannot refuse this input at all",
					row.name, failure)
			}
		})
	}

	// the field class, off the type
	driven := map[string]bool{}
	for _, row := range rows {
		if row.field != "" {
			driven[row.field] = true
		}
	}
	entry := reflect.TypeOf(ProposalOrRef{})
	if entry.NumField() == 0 {
		t.Fatal("reflection found no field on ProposalOrRef, so the gate below read nothing")
	}
	onTheType := map[string]bool{}
	for i := 0; i < entry.NumField(); i += 1 {
		name := entry.Field(i).Name
		onTheType[name] = true
		if !driven[name] {
			t.Errorf("a ProposalOrRef carries %s and no row makes the list and the vector disagree over it; a field the join does not compare is a field of the commit's own vector that a rule stated over the list is free to contradict",
				name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(driven)) {
		if !onTheType[name] {
			t.Errorf("a row claims to make the two disagree over %s and a ProposalOrRef has no such field",
				name)
		}
	}
}

// TestTheExtensionSetTheCommitInstallsIsWhatItsPathLeafOwesSupportFor is the half of
// effectiveExtensions that nothing observed, and it is the security relevant half.
//
// Deleting the branch that prefers the list's own GroupContextExtensions proposal left the whole
// suite green, and what that branch buys is this commit: one that INSTALLS an extension and, in
// the same commit, publishes a path leaf that does not support it. Section 12.4.2 applies the
// proposals before the path is validated, so the set the path leaf owes support for is the new one.
//
// VALSEM209 CANNOT COVER THIS and the assertion below says so rather than assuming it. That rule
// walks the POST tree's members, and the path leaf is not in the post tree because the merge has
// not happened -- so with the branch gone nothing in ValidateCommit holds the committer's own new
// leaf against the extension set the same commit installs.
func TestTheExtensionSetTheCommitInstallsIsWhatItsPathLeafOwesSupportFor(t *testing.T) {
	crypto := testCrypto(t)
	in, _ := testFullCommitInput(t, crypto)
	testCommitProposals(t, in, testGceOf(
		Extension{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: []byte{}},
		Extension{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor, ExtensionData: []byte{}}))
	in.Commit.Path.LeafNode.Capabilities = testNarrowedCapabilities()

	// the group's own context carries neither extension, so a validator that read it instead of
	// the commit's own set has nothing to hold the leaf against
	if len(in.Context.Extensions) != 0 {
		t.Fatalf("the fixture's group context already carries %d extensions, so the two sources cannot be told apart",
			len(in.Context.Extensions))
	}
	if failure := ValSem209GroupExtensionsSupported(in); failure != nil {
		t.Fatalf("ValSem209 refused this commit: %v. Every member of the post tree supports the extension and the offending leaf is the path's, which ValSem209 cannot see -- if it answers here, the row below is asserting the wrong rule",
			failure)
	}
	failure := ValidateCommit(in)
	if !errors.Is(failure, errGroupContextExtensionNotListed) {
		t.Fatalf("ValidateCommit over a commit that installs urmessage_owner_successor and publishes a path leaf that does not list it = %v, want errGroupContextExtensionNotListed",
			failure)
	}
	// the same commit with a leaf that lists it is accepted, so the rule is not "any commit
	// carrying a group_context_extensions proposal"
	whole, _ := testFullCommitInput(t, crypto)
	testCommitProposals(t, whole, testGceOf(
		Extension{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: []byte{}},
		Extension{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor, ExtensionData: []byte{}}))
	if failure := ValidateCommit(whole); failure != nil {
		t.Fatalf("ValidateCommit refused a commit whose path leaf lists every extension it installs: %v",
			failure)
	}
}

// TestValSem202IsStatedOverThePostProposalTree drives the field choice, over an input where the two
// trees answer differently.
//
// A four member group whose commit removes leaves 3 and 2 has a filtered direct path of a different
// length in each tree, so a rule pointed at the pre-commit tree refuses the honest commit -- which
// is what CommitValidationInput's doc says the two fields exist to prevent, and what nothing
// measured: the rule rewritten to read PreTree left the whole suite green.
func TestValSem202IsStatedOverThePostProposalTree(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
	testCommitProposals(t, in, testRemoveOf(3), testRemoveOf(2))
	for _, leafIndex := range []LeafIndex{3, 2} {
		if failure := in.PostTree.RemoveLeaf(leafIndex); failure != nil {
			t.Fatalf("RemoveLeaf(%d): %v", leafIndex, failure)
		}
	}
	before, failure := in.PreTree.FilteredDirectPath(in.Committer)
	if failure != nil {
		t.Fatalf("FilteredDirectPath over the pre tree: %v", failure)
	}
	after, failure := in.PostTree.FilteredDirectPath(in.Committer)
	if failure != nil {
		t.Fatalf("FilteredDirectPath over the post tree: %v", failure)
	}
	if len(before) == len(after) {
		t.Fatalf("both trees answer a filtered direct path of %d nodes, so this fixture cannot tell the two fields apart",
			len(before))
	}
	in.Commit.Path = testCommitPath(t, crypto, members[0], len(after))
	if failure := ValSem202PathLength(in); failure != nil {
		t.Fatalf("ValSem202 refused a path of the POST tree's own filtered direct path length: %v. The proposals are applied before the path is validated, so a rule reading the pre-commit tree refuses every honest commit that removes anybody",
			failure)
	}
	in.Commit.Path = testCommitPath(t, crypto, members[0], len(before))
	if failure := ValSem202PathLength(in); !errors.Is(failure, errPathLength) {
		t.Fatalf("ValSem202 accepted a path of the PRE tree's filtered direct path length = %v, want errPathLength",
			failure)
	}
}

// TestValSem204IsStatedOverThePreCommitTree is the same property for the other field, and the two
// together are why CommitValidationInput carries two trees.
//
// The input is a commit whose list carries an UPDATE from the committer itself. Section 12.2's
// ValSem111 refuses that list -- at the PROPOSAL door, which ValidateCommit does not run -- so a
// caller that applied the proposals before judging the commit holds a post tree whose committer
// leaf carries a key the pre tree does not. Over that pair the two readings disagree, and the
// dangerous direction is the accepting one: a path that republishes the committer's RETIRED key
// advances the epoch while leaving that leaf decryptable by whoever holds the old one, which is the
// whole of what a path exists to prevent.
func TestValSem204IsStatedOverThePreCommitTree(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
	update, updated := testUpdateProposalOf(t, crypto, members[0], LeafIndex(0))
	testCommitProposals(t, in, update)
	if failure := in.PostTree.UpdateLeaf(LeafIndex(0), updated); failure != nil {
		t.Fatalf("UpdateLeaf(0): %v", failure)
	}
	retired := in.PreTree.Leaf(LeafIndex(0))
	fresh := in.PostTree.Leaf(LeafIndex(0))
	if retired == nil || fresh == nil {
		t.Fatal("one of the two trees has no leaf 0, so the fixture states nothing")
	}
	if subtle.ConstantTimeCompare(retired.EncryptionKey, fresh.EncryptionKey) == 1 {
		t.Fatal("both trees carry the same key at leaf 0, so this fixture cannot tell the two fields apart")
	}

	republished := testCommitPathLeaf(t, crypto, members[0])
	republished.EncryptionKey = retired.EncryptionKey
	in.Commit.Path = &UpdatePath{LeafNode: *republished}
	if failure := ValSem204PathKeyMismatch(in); !errors.Is(failure, errPathLeafKeyUnchanged) {
		t.Fatalf("ValSem204 over a path leaf republishing the key the PRE tree holds = %v, want errPathLeafKeyUnchanged; the rule is stated over the committer's current leaf and the current leaf is the one the commit arrived on",
			failure)
	}

	// the post tree's key is a different rule's business: ValSem204 is about the key the path
	// retires, and the key an Update in the same commit published is ValSem206's axis
	carried := testCommitPathLeaf(t, crypto, members[0])
	carried.EncryptionKey = fresh.EncryptionKey
	in.Commit.Path = &UpdatePath{LeafNode: *carried}
	if failure := ValSem204PathKeyMismatch(in); failure != nil {
		t.Fatalf("ValSem204 refused a path leaf carrying a key the committer's current leaf does not hold: %v",
			failure)
	}
	if failure := ValSem206PathLeafEncryptionKeyUnique(in); !errors.Is(failure, errDuplicateEncryptionKey) {
		t.Fatalf("ValSem206 over a path leaf republishing an update's key = %v, want errDuplicateEncryptionKey; if nothing refuses this input the split between the two rules is not the split this test claims",
			failure)
	}
}

// TestTheCommitValidationErrataMatchWhatTheErrataFileRecords holds the two errata functions to the
// document rather than to the plan.
//
// ERRATA.md is the transcription this package checks itself against, and both functions were
// written from a plan that described a different rule for each. What is asserted here is the pair
// of properties that separate the two readings, stated over ERRATA.md's own subject matter: 8745 is
// about a leaf's capabilities against the group's extensions, and 8815 is about a reference naming
// a proposal this member received.
func TestTheCommitValidationErrataMatchWhatTheErrataFileRecords(t *testing.T) {
	raw, failure := os.ReadFile("ERRATA.md")
	if failure != nil {
		t.Fatalf("read ERRATA.md: %v", failure)
	}
	body := string(raw)
	for _, needed := range []string{
		"Erratum 8745",
		"This applies both to Update proposals and LeafNode",
		"Erratum 8815",
		"contains a reference to a proposal that was not previously received",
	} {
		if !strings.Contains(body, needed) {
			t.Errorf("ERRATA.md does not carry %q; the two errata functions are written against that transcription and a reader has to be able to diff it against the errata page",
				needed)
		}
	}
}

// ---------------------------------------------------------------------------
// no door that is handed a proposal list dereferences an arm it was not handed
// ---------------------------------------------------------------------------

// proposalListDoor is one exported entry point that is handed a proposal list, wrapped so that
// every shape -- a rule over a validation input, a function taking a list, a method on the list --
// is driven by one sweep.
//
// refuses is false for the doors whose whole answer is a bool or a value. What those owe is only
// that they do not dereference; a method with no error to answer cannot report anything else.
type proposalListDoor struct {
	run     func(t *testing.T, crypto CryptoProvider, tree *RatchetTree, list *ProposalList) error
	refuses bool
}

// proposalListReaders is every exported entry point handed a proposal list that is NOT one of the
// two validators' rules: the functions that take one, and the methods on the type itself.
//
// Held in both directions by the sweep below -- by AST for the functions, by reflection over
// *ProposalList for the methods -- because this is the class rule 5 is about. The reviewer reached
// three unguarded arm reads; the class is every read reachable from an exported door, and a list of
// the three would have left (*ProposalList).Extensions, which is a door of its own with no error to
// answer, exactly where it was.
func proposalListReaders() map[string]proposalListDoor {
	return map[string]proposalListDoor{
		"ApplyProposals": {refuses: true,
			run: func(t *testing.T, crypto CryptoProvider, tree *RatchetTree, list *ProposalList) error {
				_, failure := ApplyProposals(tree, testResolveContext(), LeafIndex(0), list)
				return failure
			}},
		"CommitPathRequired": {
			run: func(t *testing.T, crypto CryptoProvider, tree *RatchetTree, list *ProposalList) error {
				CommitPathRequired(list)
				return nil
			}},
		"ProposalList.Len": {
			run: func(t *testing.T, crypto CryptoProvider, tree *RatchetTree, list *ProposalList) error {
				list.Len()
				return nil
			}},
		"ProposalList.PathRequired": {
			run: func(t *testing.T, crypto CryptoProvider, tree *RatchetTree, list *ProposalList) error {
				list.PathRequired()
				return nil
			}},
		"ProposalList.Extensions": {
			run: func(t *testing.T, crypto CryptoProvider, tree *RatchetTree, list *ProposalList) error {
				list.Extensions()
				return nil
			}},
		"ProposalList.Refs": {
			run: func(t *testing.T, crypto CryptoProvider, tree *RatchetTree, list *ProposalList) error {
				list.Refs()
				return nil
			}},
	}
}

// proposalListDoors is every door of this package that judges or reads a proposal list: the two
// validators' rules, read off the production slices, and the readers above.
func proposalListDoors(t *testing.T) map[string]proposalListDoor {
	t.Helper()
	doors := map[string]proposalListDoor{}
	for name, rule := range commitValidationDoors() {
		commitRule := rule
		doors[name] = proposalListDoor{refuses: true,
			run: func(t *testing.T, crypto CryptoProvider, tree *RatchetTree, list *ProposalList) error {
				return commitRule(testCommitInput(t, crypto, tree, list, &Commit{}))
			}}
	}
	proposalDoors := map[string]func(*ProposalValidationInput) error{
		"ValidateProposalList": ValidateProposalList,
	}
	for _, name := range proposalListRules() {
		proposalDoors[name] = proposalListRuleFor(t, name)
	}
	for name, rule := range proposalDoors {
		proposalRule := rule
		doors[name] = proposalListDoor{refuses: true,
			run: func(t *testing.T, crypto CryptoProvider, tree *RatchetTree, list *ProposalList) error {
				return proposalRule(testValidationInput(t, crypto, tree, LeafIndex(0), list))
			}}
	}
	maps.Copy(doors, proposalListReaders())
	return doors
}

// TestProposalListReadersIsEveryExportedDoorHandedAProposalList holds the reader half of the class
// to the two derivations that produce it.
func TestProposalListReadersIsEveryExportedDoorHandedAProposalList(t *testing.T) {
	readers := proposalListReaders()
	functions := []string{}
	methods := []string{}
	for name := range readers {
		if strings.HasPrefix(name, "ProposalList.") {
			methods = append(methods, strings.TrimPrefix(name, "ProposalList."))
			continue
		}
		functions = append(functions, name)
	}
	slices.Sort(functions)
	slices.Sort(methods)

	// the functions, off the source: every exported function of the non test files that takes a
	// *ProposalList anywhere in its parameters
	declared := []string{}
	for _, path := range packageSourcePaths(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source := mustParseSource(t, path)
		for _, declaration := range source.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Recv != nil || !ast.IsExported(function.Name.Name) ||
				function.Type.Params == nil {
				continue
			}
			for _, parameter := range function.Type.Params.List {
				if source.render(parameter.Type) == "*ProposalList" {
					declared = append(declared, function.Name.Name)
					break
				}
			}
		}
	}
	slices.Sort(declared)
	if !slices.Equal(functions, declared) {
		t.Errorf("this package's non test source exports %v taking a *ProposalList and proposalListReaders drives %v; a door outside the sweep is a door whose arm reads nothing here holds",
			declared, functions)
	}

	// the methods, off the type: every exported method of *ProposalList
	listType := reflect.TypeOf((*ProposalList)(nil))
	onTheType := []string{}
	for i := 0; i < listType.NumMethod(); i += 1 {
		onTheType = append(onTheType, listType.Method(i).Name)
	}
	slices.Sort(onTheType)
	if len(onTheType) == 0 {
		t.Fatal("reflection found no exported method on *ProposalList, so that half of the class read nothing")
	}
	if !slices.Equal(methods, onTheType) {
		t.Errorf("*ProposalList exports %v and proposalListReaders drives %v", onTheType, methods)
	}
}

// testArmlessList is a list carrying an innocent remove and then one proposal of the named type
// with NO arm at all.
//
// SECOND AND NOT FIRST, which is this file's rule for every loop, and it matters twice here: a
// guard written over element zero passes this, and so does a guard that stopped at the first entry
// it could read.
//
// The entry goes in its own bucket when the type has one, because a bucketed rule reads the arm the
// BUCKET names -- `list.Removes[i].Proposal.Remove.Removed` never looks at the entry's own type --
// and which types have buckets is read off proposalBucketsOf rather than written here.
func testArmlessList(t *testing.T, code ProposalType) *ProposalList {
	t.Helper()
	innocent := testRemoveOf(1)
	armless := CachedProposal{ByValue: true, Proposal: Proposal{ProposalType: code}}
	for _, bucket := range proposalBucketsOf(&ProposalList{}) {
		if bucket.carries == code {
			return testProposalList(t, innocent, armless)
		}
	}
	// a type with no bucket of its own is carried in the commit order alone, which is what a list
	// assembled around a type this build does not implement looks like
	return &ProposalList{
		All:     []CachedProposal{innocent, armless},
		Removes: []CachedProposal{innocent},
	}
}

// testBucketOnlyArmlessList is a list whose BUCKET carries an armless proposal the commit order
// does not.
//
// THE SHAPE testArmlessList CANNOT PRODUCE, and the reason it is here. That fixture places its
// offender in All and in the matching bucket at once, so the All sweep of checkProposalListStructure
// answers every case and the bucket sweep never fires: two mutations of the bucket half survived,
// and the two that were caught were caught by an error-roster reachability gate rather than by
// anything driving the behaviour. A list whose bucket carries an entry All does not is exactly what
// re-opens the nil-arm dereference at in.List.Removes[i].Proposal.Remove.Removed, because every
// bucketed rule reads the arm the BUCKET names.
//
// A type with no bucket cannot be carried by one, so the second answer is false rather than an
// empty list: a fixture that reported clean over a shape it never built is the thing this exists to
// not be. Which types have buckets is read off proposalBucketsOf, and the bucket is filled through
// reflection, so a fifth bucket is driven without being named here.
func testBucketOnlyArmlessList(t *testing.T, code ProposalType) (*ProposalList, bool) {
	t.Helper()
	innocent := testRemoveOf(1)
	armless := CachedProposal{ByValue: true, Proposal: Proposal{ProposalType: code}}
	for _, bucket := range proposalBucketsOf(&ProposalList{}) {
		if bucket.carries != code {
			continue
		}
		list := &ProposalList{
			All:     []CachedProposal{innocent},
			Removes: []CachedProposal{innocent},
		}
		held := reflect.ValueOf(list).Elem().FieldByName(bucket.field)
		held.Set(reflect.Append(held, reflect.ValueOf(armless)))
		return list, true
	}
	return nil, false
}

// TestNoDoorHandedAProposalListDereferencesAMissingArm is finding 2's class, derived on both axes.
//
// THE DOORS are every rule the two aggregates run, read off the production slices, plus every
// exported function and method handed a list, and the aggregates themselves. THE INPUTS are one
// list per REGISTERED proposal type, read off the registry, plus a code point outside it.
//
// What each door owes is what this package's own doctrine says a door owes: a refusal rather than a
// dereference, so that a missing argument cannot read as "nothing collided". A panic out of a
// library takes the caller's process rather than its call, and ValidateCommit -- newly exported and
// reachable by a caller that has resolved nothing -- was three of them.
func TestNoDoorHandedAProposalListDereferencesAMissingArm(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
	doors := proposalListDoors(t)
	if len(doors) < 20 {
		t.Fatalf("the sweep found %d doors, and this package declares two aggregates and more than twenty rules between them",
			len(doors))
	}
	registered := registryConstantsOfType(t, "ProposalType")
	if len(registered) == 0 {
		t.Fatal("this package declares no ProposalType constant, so the sweep drove nothing")
	}
	inputs := map[string]ProposalType{}
	for name, code := range registered {
		inputs[name] = ProposalType(code)
	}
	// and one outside the registry, which is the member of the class the registry cannot supply
	inputs["an unregistered code point"] = ProposalType(0x1A1A)
	bucketOnlyShapes := 0

	for _, typeName := range slices.Sorted(maps.Keys(inputs)) {
		code := inputs[typeName]
		wanted := ErrContentArmMismatch
		refusal, isRegistered := proposalTypeProfile[code]
		switch {
		case !isRegistered:
			wanted = errUnregisteredProposalType
		case refusal != nil:
			// a type this profile refuses is refused for its TYPE, whatever it carries, which is
			// checkProposalProfile's own stated order
			wanted = refusal
		}
		// TWO SHAPES per type, and the second is the one nothing drove. The first carries the
		// armless entry in the commit order and in its bucket, which the All sweep answers; the
		// second carries it in the BUCKET ALONE, which only the bucket sweep can answer.
		shapes := map[string]*ProposalList{
			"in the commit order and in its bucket": testArmlessList(t, code),
		}
		if bucketOnly, bucketed := testBucketOnlyArmlessList(t, code); bucketed {
			shapes["in its bucket alone"] = bucketOnly
			bucketOnlyShapes += 1
		}
		for _, shape := range slices.Sorted(maps.Keys(shapes)) {
			for _, name := range slices.Sorted(maps.Keys(doors)) {
				door := doors[name]
				answered := proposalListDoorAnswer(t,
					name+" over an armless "+typeName+" "+shape, door, crypto, tree, shapes[shape])
				if !door.refuses {
					continue
				}
				if !errors.Is(answered, wanted) {
					t.Errorf("%s over a list carrying a %s with no arm %s answered %v, want %v",
						name, typeName, shape, answered, wanted)
				}
			}
		}
	}
	if bucketOnlyShapes != len(proposalBucketsOf(&ProposalList{})) {
		t.Errorf("the sweep drove %d bucket-only shapes and a ProposalList has %d buckets; the half of the structural rule that reads the buckets is then driven by nothing for the rest",
			bucketOnlyShapes, len(proposalBucketsOf(&ProposalList{})))
	}
}

// proposalListDoorAnswer runs one door and turns a panic into the failure it should have been, so
// one door dereferencing its list is a failure of its own case rather than the end of the sweep.
func proposalListDoorAnswer(t *testing.T, what string, door proposalListDoor,
	crypto CryptoProvider, tree *RatchetTree, list *ProposalList) (answered error) {

	t.Helper()
	defer func() {
		if panicked := recover(); panicked != nil {
			t.Errorf("%s panicked with %v; a panic out of a library takes the caller's process rather than its call, and a missing arm is an argument to refuse rather than a state to crash in",
				what, panicked)
			answered = nil
		}
	}()
	return door.run(t, crypto, tree, list)
}


// ---------------------------------------------------------------------------
// which source each rule decides off, and the door that establishes it
// ---------------------------------------------------------------------------

// THE DEFECT CLASS THIS SECTION EXISTS FOR is a rule decided off a field the door has not
// established, and it has been the finding three commits running: ValSem201 stated over List while
// the door held only Commit.Proposals; then four rules stated over a BUCKET while the door held
// only All -- which accepted a commit that removes its own committer, RFC 9420 section 12.2's own
// rule, at the validation door. Enumerating "the four bucket rules" would have been the fourth
// instance, so what is written down here is not the four: it is a DERIVATION of which source every
// rule of commitValidationChecks reads, and a table saying what the door establishes about each.
//
// A rule that comes to read a source with no establishment fails on the commit that writes it,
// whether that source is a fifth bucket, a field added to CommitValidationInput, or one of the
// eighteen already here that a later rule starts reading.

// commitDoorMethod is the name of the argument rule every entry point of validate_commit.go and
// validate_proposals.go runs first. It is what the derivation below excludes, and the
// establishment table is a description of it.
const commitDoorMethod = "check"

// commitSourceValue is one value the reader below tracks: either a SOURCE PATH rooted at
// CommitValidationInput -- "List", "List.Removes", "Commit.Path" -- or a STRUCT BINDING, which is
// what a delegate's input is.
//
// The binding half is what makes the derivation exact across proposalValidationInput. That method
// builds a *ProposalValidationInput out of this input's own fields and the rule reading
// in.List.Removes is on the far side of it, so a reader that stopped at the call would attribute
// nothing at all to ValSem200, and one that followed it without the mapping would report the
// section 12.2 input's field names, which are not this input's.
type commitSourceValue struct {
	path   string
	fields map[string]string
}

// commitSourceCallee is one resolved call: the declaration, and the bindings its receiver and
// parameters take from the call site.
type commitSourceCallee struct {
	declaration *ast.FuncDecl
	bindings    map[string]commitSourceValue
}

// commitSourceReader walks this package's non test source from a named declaration and answers
// every source of a CommitValidationInput that declaration decides off.
type commitSourceReader struct {
	byName map[string][]*ast.FuncDecl
	class  map[string]bool
}

// commitInputSourceClass is every source a rule can decide off, derived from the three types
// rather than listed.
//
// One level of expansion for List and for Commit and no deeper, because that is where the
// granularity stops mattering: the door joins the buckets to All and All to the commit's own
// vector, and a rule reading Removes[i].Proposal.Remove.Removed is deciding off Removes.
// Reflection over the structs and not a list of names, so a fifth bucket on ProposalList, or a
// third field on Commit, is a source the gates below demand an establishment for on the commit
// that adds it.
func commitInputSourceClass() map[string]bool {
	class := map[string]bool{}
	input := reflect.TypeOf(CommitValidationInput{})
	for i := 0; i < input.NumField(); i += 1 {
		class[input.Field(i).Name] = true
	}
	list := reflect.TypeOf(ProposalList{})
	for i := 0; i < list.NumField(); i += 1 {
		class["List."+list.Field(i).Name] = true
	}
	commit := reflect.TypeOf(Commit{})
	for i := 0; i < commit.NumField(); i += 1 {
		class["Commit."+commit.Field(i).Name] = true
	}
	return class
}

// newCommitSourceReader indexes every function and method of this package's non test source by its
// BARE name.
//
// By bare name, which over-reaches, and that is the safe direction for commitRefusalClosure's
// reason: Go's method sets are not recoverable from an unresolved AST, so a call of Extensions
// resolves to every declaration of that name and each is walked. A callee whose bindings carry
// nothing input-derived is dropped, and a selector that does not resolve to a member of the source
// class is dropped, so the over-reach costs work rather than accuracy -- while a derivation that
// MISSED a read would be a rule deciding off a source no gate below asks about.
func newCommitSourceReader(t *testing.T) *commitSourceReader {
	t.Helper()
	reader := &commitSourceReader{byName: map[string][]*ast.FuncDecl{}, class: commitInputSourceClass()}
	for _, path := range packageSourcePaths(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source := mustParseSource(t, path)
		for _, declaration := range source.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			reader.byName[function.Name.Name] = append(reader.byName[function.Name.Name], function)
		}
	}
	if len(reader.byName) == 0 {
		t.Fatal("the reader indexed no declaration of this package, so every derivation below walks nothing")
	}
	return reader
}

// evaluate answers what one expression IS in terms of the input: a source path, a struct binding,
// or nothing.
//
// The selector case is where the granularity is enforced. in.List.Removes[i].Proposal.Remove.Removed
// walks down to "List", then to "List.Removes" because that is in the class, and then answers
// "List.Removes" for every field read past it -- so one dereference chain reports the one source it
// decides off rather than a name per link.
func (self *commitSourceReader) evaluate(expr ast.Expr,
	bindings map[string]commitSourceValue) commitSourceValue {

	switch typed := expr.(type) {
	case *ast.Ident:
		return bindings[typed.Name]
	case *ast.ParenExpr:
		return self.evaluate(typed.X, bindings)
	case *ast.StarExpr:
		return self.evaluate(typed.X, bindings)
	case *ast.UnaryExpr:
		return self.evaluate(typed.X, bindings)
	case *ast.IndexExpr:
		return self.evaluate(typed.X, bindings)
	case *ast.SliceExpr:
		return self.evaluate(typed.X, bindings)
	case *ast.CompositeLit:
		return commitSourceValue{fields: self.fieldsOf(typed, bindings)}
	case *ast.CallExpr:
		return self.answerOf(typed, bindings)
	case *ast.SelectorExpr:
		base := self.evaluate(typed.X, bindings)
		if base.fields != nil {
			if path, mapped := base.fields[typed.Sel.Name]; mapped {
				return commitSourceValue{path: path}
			}
			return commitSourceValue{}
		}
		if base.path == "" {
			return commitSourceValue{}
		}
		if self.class[base.path+"."+typed.Sel.Name] {
			return commitSourceValue{path: base.path + "." + typed.Sel.Name}
		}
		return base
	}
	return commitSourceValue{}
}

// fieldsOf reads a struct literal as a mapping from its own field names to the sources they were
// built out of.
func (self *commitSourceReader) fieldsOf(literal *ast.CompositeLit,
	bindings map[string]commitSourceValue) map[string]string {

	fields := map[string]string{}
	for _, element := range literal.Elts {
		pair, isPair := element.(*ast.KeyValueExpr)
		if !isPair {
			continue
		}
		key, isIdentifier := pair.Key.(*ast.Ident)
		if !isIdentifier {
			continue
		}
		if value := self.evaluate(pair.Value, bindings); value.path != "" {
			fields[key.Name] = value.path
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// calleesOf resolves one call to the declarations it can reach, with each declaration's receiver
// and parameters bound to what the call site handed them.
//
// A callee whose every binding is empty is dropped rather than walked: nothing it reads can be a
// source of this input, and walking it anyway would be a walk of the whole package from every rule.
func (self *commitSourceReader) calleesOf(call *ast.CallExpr,
	bindings map[string]commitSourceValue) []commitSourceCallee {

	name := ""
	receiver := commitSourceValue{}
	switch function := call.Fun.(type) {
	case *ast.Ident:
		name = function.Name
	case *ast.SelectorExpr:
		name = function.Sel.Name
		receiver = self.evaluate(function.X, bindings)
	default:
		return nil
	}
	callees := []commitSourceCallee{}
	for _, declaration := range self.byName[name] {
		inner := map[string]commitSourceValue{}
		if declaration.Recv != nil && len(declaration.Recv.List) == 1 &&
			len(declaration.Recv.List[0].Names) == 1 {
			inner[declaration.Recv.List[0].Names[0].Name] = receiver
		}
		if declaration.Type.Params != nil {
			at := 0
			for _, parameter := range declaration.Type.Params.List {
				for _, identifier := range parameter.Names {
					if at < len(call.Args) {
						inner[identifier.Name] = self.evaluate(call.Args[at], bindings)
					}
					at += 1
				}
			}
		}
		carries := false
		for _, value := range inner {
			if value.path != "" || value.fields != nil {
				carries = true
			}
		}
		if carries {
			callees = append(callees, commitSourceCallee{declaration, inner})
		}
	}
	return callees
}

// answerOf is what a call ANSWERS, which for proposalValidationInput is the delegate input's own
// field mapping and for FilteredDirectPath is nothing.
func (self *commitSourceReader) answerOf(call *ast.CallExpr,
	bindings map[string]commitSourceValue) commitSourceValue {

	for _, callee := range self.calleesOf(call, bindings) {
		answered := commitSourceValue{}
		ast.Inspect(callee.declaration.Body, func(node ast.Node) bool {
			returned, isReturn := node.(*ast.ReturnStmt)
			if !isReturn || len(returned.Results) != 1 {
				return true
			}
			result := returned.Results[0]
			if unary, isUnary := result.(*ast.UnaryExpr); isUnary {
				result = unary.X
			}
			if value := self.evaluate(result, callee.bindings); value.path != "" || value.fields != nil {
				answered = value
			}
			return false
		})
		if answered.path != "" || answered.fields != nil {
			return answered
		}
	}
	return commitSourceValue{}
}

// read collects every source one declaration decides off, following the calls it makes.
//
// EVERY CALL OF A DOOR'S OWN check IS SKIPPED, at every depth, and that is the whole point of the
// derivation. Every rule of this file opens with in.check(), and the door reads the list, the
// buckets, the commit's vector and both trees while ESTABLISHING them -- so a reader that counted
// those would report that every rule decides off everything, and the gate below would be an
// identity. What is left is what the rule decides off on top of what the door established, which
// is exactly the thing that has to have an establishment behind it.
func (self *commitSourceReader) read(declaration *ast.FuncDecl,
	bindings map[string]commitSourceValue, into map[string]bool, walked map[string]bool) {

	key := declaration.Name.Name + "|"
	for _, name := range slices.Sorted(maps.Keys(bindings)) {
		key += name + "=" + bindings[name].path + ";"
		for _, field := range slices.Sorted(maps.Keys(bindings[name].fields)) {
			key += field + ">" + bindings[name].fields[field] + ","
		}
	}
	if walked[key] {
		return
	}
	walked[key] = true
	ast.Inspect(declaration.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.CallExpr:
			if selector, isSelector := typed.Fun.(*ast.SelectorExpr); isSelector &&
				selector.Sel.Name == commitDoorMethod {
				return true
			}
			for _, callee := range self.calleesOf(typed, bindings) {
				self.read(callee.declaration, callee.bindings, into, walked)
			}
			return true
		case *ast.SelectorExpr:
			if value := self.evaluate(typed, bindings); value.path != "" {
				into[value.path] = true
				return false
			}
		}
		return true
	})
}

// sourcesRead is every source of a CommitValidationInput the named declaration decides off.
func (self *commitSourceReader) sourcesRead(name string) []string {
	identity := map[string]string{}
	input := reflect.TypeOf(CommitValidationInput{})
	for i := 0; i < input.NumField(); i += 1 {
		identity[input.Field(i).Name] = input.Field(i).Name
	}
	found := map[string]bool{}
	for _, declaration := range self.byName[name] {
		bindings := map[string]commitSourceValue{}
		if declaration.Recv != nil && len(declaration.Recv.List) == 1 &&
			len(declaration.Recv.List[0].Names) == 1 &&
			receiverTypeName(declaration.Recv.List[0].Type) == "CommitValidationInput" {
			bindings[declaration.Recv.List[0].Names[0].Name] = commitSourceValue{fields: identity}
		}
		if declaration.Type.Params != nil {
			for _, parameter := range declaration.Type.Params.List {
				for _, identifier := range parameter.Names {
					bindings[identifier.Name] = commitSourceValue{fields: identity}
				}
			}
		}
		self.read(declaration, bindings, found, map[string]bool{})
	}
	return slices.Sorted(maps.Keys(found))
}

// commitRuleSources is the derivation itself: for every rule ValidateCommit runs, the sources it
// decides off.
//
// THREE CONTROLS, each ruling out a different way for this to report a clean bill over a walk that
// resolved nothing. ValSem200 reaches List.Removes only through a delegate another method builds,
// so a reader that does not follow that mapping finds nothing there. ValSem207 names in.PostTree in
// its own body, so a reader that resolved no selector at all finds nothing there. And the class
// must have an OUTSIDE: ValSem205's three confirmation tag fields are read by no rule the aggregate
// runs, so a derivation reporting every field of the struct is a walk with no edges.
func commitRuleSources(t *testing.T) map[string][]string {
	t.Helper()
	reader := newCommitSourceReader(t)
	sources := map[string][]string{}
	union := map[string]bool{}
	for _, name := range commitRulesTheAggregateRuns() {
		sources[name] = reader.sourcesRead(name)
		for _, source := range sources[name] {
			union[source] = true
		}
	}
	if len(sources) == 0 {
		t.Fatal("ValidateCommit runs no rule, so the derivation had nothing to read")
	}
	if !slices.Contains(sources["ValSem200NoSelfRemove"], "List.Removes") {
		t.Fatalf("the derivation says ValSem200NoSelfRemove decides off %v, and it decides off the Removes bucket through the section 12.2 input this file builds for it; a reader that does not follow that mapping attributes nothing to either delegating rule",
			sources["ValSem200NoSelfRemove"])
	}
	if !slices.Contains(sources["ValSem207PathEncryptionKeysUnique"], "PostTree") {
		t.Fatalf("the derivation says ValSem207PathEncryptionKeysUnique decides off %v, and it names in.PostTree in its own body",
			sources["ValSem207PathEncryptionKeysUnique"])
	}
	for _, outside := range []string{"ConfirmationKey", "ConfirmedHash", "ConfirmationTag"} {
		if union[outside] {
			t.Fatalf("the derivation says a rule the aggregate runs decides off %s; the only rule that reads the confirmation tag is ValSem205, which the aggregate deliberately does not run, so a class holding it has no outside",
				outside)
		}
	}
	class := commitInputSourceClass()
	for _, source := range slices.Sorted(maps.Keys(union)) {
		if !class[source] {
			t.Errorf("the derivation reports %s, which is not a field of CommitValidationInput, of a ProposalList or of a Commit",
				source)
		}
	}
	return sources
}

// commitSourceEstablishment is what the door establishes about one source, and an input that
// breaks it.
//
// EVERY ROW IS DRIVEN and none of them is a label. The row starts from a commit ValidateCommit
// ACCEPTS, breaks the one thing it claims the door establishes, and states what the aggregate must
// answer -- so a row whose establishment is a fiction fails, and so does one whose establishment
// was real and has since been deleted.
//
// refuses nil is a row of the other kind, and it is the honest way to write "the door establishes
// nothing about this, because no rule it runs decides anything off it": the break is applied and
// the aggregate must go on ACCEPTING. Crypto and Now are those two, and the day a rule reaches the
// provider or the clock without the door growing a guard, the row fails -- by a panic or by a
// changed answer.
type commitSourceEstablishment struct {
	establishes string
	build       func(t *testing.T, crypto CryptoProvider) *CommitValidationInput
	breaks      func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput)
	refuses     error
}

// testCommitInstalledExtensions is the group context extension set the fixture below installs.
//
// THREE ENTRIES, so the extension join's fault can be planted in the middle: a comparison narrowed
// to entry zero, or one that stops at the first agreement, is told apart from the whole walk only
// by a vector that has a middle. ratchet_tree is a default type and is exempt from section 13.4's
// listing rule; the other two are private use types every fixture leaf of this package lists, so
// the set is one an honest commit could install into this group.
func testCommitInstalledExtensions() []Extension {
	return []Extension{
		{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: []byte{}},
		{ExtensionType: ExtensionTypeUrmessageGroupPolicy, ExtensionData: []byte{0x01}},
		{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor, ExtensionData: []byte{0x02}},
	}
}

// testCommitCarryingOneOfEveryBucket is the commit nearly every establishment row starts from: a
// four member group, a full update path, and ONE PROPOSAL OF EVERY BUCKETED TYPE.
//
// One of each and not one, because the bucket rows are generated off proposalBucketsOf and each of
// them empties its own bucket: over a list carrying only removes, emptying the Adds bucket is a
// break that breaks nothing. It also puts each bucket's own entry at a different position of the
// commit order, so the count sweep the join runs cannot be narrowed to element zero without three
// of the four rows failing.
func testCommitCarryingOneOfEveryBucket(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
	t.Helper()
	in, members := testFullCommitInput(t, crypto)
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "erin"))
	update, _ := testUpdateProposalOf(t, crypto, members[1], LeafIndex(1))
	testCommitProposals(t, in,
		testRemoveOf(LeafIndex(3)), testAddOf(kp), update,
		testGceOf(testCommitInstalledExtensions()...))
	return in
}

// testCommitNamingACachedProposal is the base for the Pending row: a commit whose FIRST proposal is
// carried inline and whose SECOND names a proposal this member has received.
//
// The order is the point. Erratum 8815 is stated over references and skips by-value entries, so a
// commit whose only reference is its second is exactly the input a rule written over entry zero
// admits -- and the row's break, a validator handed no record of what this member received, has to
// reach entry one to refuse.
func testCommitNamingACachedProposal(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
	t.Helper()
	in, _ := testFullCommitInput(t, crypto)
	cache := testCacheAt(t, testResolveContext())
	in.Pending = cache
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "erin"))
	inline := testAddOf(kp)
	held := testCachedRemoveOf(t, crypto, cache, LeafIndex(2))
	in.List = testProposalList(t, inline, held)
	carried := inline.Proposal
	in.Commit.Proposals = []ProposalOrRef{
		{Type: ProposalOrRefTypeProposal, Proposal: &carried},
		{Type: ProposalOrRefTypeReference, Reference: held.Ref},
	}
	return in
}

// commitSetBucket replaces one named bucket of a list through reflection, so the rows generated off
// proposalBucketsOf do not have to name the four fields a second time.
func commitSetBucket(t *testing.T, list *ProposalList, field string, entries []CachedProposal) {
	t.Helper()
	held := reflect.ValueOf(list).Elem().FieldByName(field)
	if !held.IsValid() || held.Type() != reflect.TypeOf([]CachedProposal{}) {
		t.Fatalf("proposalBucketsOf names a bucket %s and a ProposalList has no []CachedProposal field of that name",
			field)
	}
	held.Set(reflect.ValueOf(entries))
}

// commitDoorEstablishments is one row per source a rule of the aggregate decides off.
//
// The four bucket rows are GENERATED off proposalBucketsOf rather than written, which is the whole
// difference between this and the enumeration it replaces: a fifth bucket added to ProposalList
// gets a row, a drive and a refusal without anybody remembering to write one, and it fails
// immediately if the door does not in fact hold it to the commit order.
func commitDoorEstablishments() map[string]commitSourceEstablishment {
	rows := map[string]commitSourceEstablishment{
		"List": {
			establishes: "there IS a proposal list, which every rule below reads an arm off",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				in.List = nil
			},
			refuses: errNilProposalList,
		},
		"List.All": {
			establishes: "the commit order carries exactly the proposals the buckets do, so a rule stated over " +
				"All and a rule stated over a bucket are two rules about one commit",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				// the THIRD entry and not the first: the join counts the commit order by type, and a
				// count narrowed to element zero cannot see an entry dropped from the middle
				in.List.All = slices.Concat(in.List.All[:2], in.List.All[3:])
				in.Commit.Proposals = in.List.Refs()
			},
			refuses: ErrProposalListBucketsDisagree,
		},
		"Commit": {
			establishes: "there IS a commit; the update path and the proposal vector are its",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				in.Commit = nil
			},
			refuses: errNilCommit,
		},
		"Commit.Proposals": {
			establishes: "the list is the resolution of the commit's own ProposalOrRef vector -- same length, " +
				"same order, each entry naming what the entry beside it names",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				// entries one and two swapped, so the disagreement is not at element zero
				in.Commit.Proposals[1], in.Commit.Proposals[2] =
					in.Commit.Proposals[2], in.Commit.Proposals[1]
			},
			refuses: errCommitProposalsNotResolved,
		},
		"Commit.Path": {
			establishes: "there is an update path whenever RFC 9420 section 12.4 requires one, which is what " +
				"every rule reading the path stands on when it answers nil for an absent one",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				in.Commit.Path = nil
			},
			refuses: errMissingPath,
		},
		"Extensions": {
			establishes: "the extension set the caller announces is the one this commit installs, so ValSem209 " +
				"and erratum 8745 judge the members and the path leaf against one vector",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				announced := slices.Clone(testCommitInstalledExtensions())
				announced[1] = Extension{ExtensionType: announced[1].ExtensionType,
					ExtensionData: []byte{0xaa}}
				in.Extensions = announced
			},
			refuses: errCommitExtensionsNotApplied,
		},
		"PreTree": {
			establishes: "there IS a pre-commit tree, which is the group the proposals arrived in and what " +
				"section 12.2's membership rules are stated over",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				in.PreTree = nil
			},
			refuses: errNilRatchetTree,
		},
		"PostTree": {
			establishes: "there IS a post-proposal tree, which is the tree the update path was built against",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				in.PostTree = nil
			},
			refuses: errNilRatchetTree,
		},
		"Context": {
			establishes: "there IS a group context; the version, the suite and the group's own extensions are its",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				in.Context = nil
			},
			refuses: ErrNilGroupContext,
		},
		"Pending": {
			establishes: "every proposal the commit names by reference is one this member has received, which is " +
				"erratum 8815 -- and a validator handed no record of what was received has not checked it",
			build: testCommitNamingACachedProposal,
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				in.Pending = nil
			},
			refuses: errProposalNotCached,
		},
		"Committer": {
			establishes: "the commit is attributed to a leaf of this group, which every comparison against the " +
				"committer's current leaf and every filtered direct path stands on",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				in.Committer = LeafIndex(97)
			},
			refuses: ErrLeafOutOfRange,
		},
		"Own": {
			establishes: "this receiver occupies a leaf of the tree the path was built against; a path secret is " +
				"addressed to a position, and a receiver that has none can open nothing",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				in.Own = LeafIndex(97)
			},
			refuses: errPathDecrypt,
		},
		"Crypto": {
			establishes: "NOTHING, and nothing is owed: no rule the aggregate runs calls a method on the provider. " +
				"The two delegating rules copy the field into the section 12.2 input and neither body they reach " +
				"verifies anything, and ValSem205 -- which does, and which refuses a nil one itself -- is the rule " +
				"the aggregate deliberately does not run. The day that stops being true this row fails, by a panic " +
				"or by a changed answer",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				in.Crypto = nil
			},
			refuses: nil,
		},
		"Now": {
			establishes: "NOTHING, for the Crypto row's reason one field over: no rule the aggregate runs reads a " +
				"clock. A lifetime is carried only under a key_package sourced leaf and section 12.4.2's path leaf " +
				"is commit sourced, so the field is copied into the section 12.2 input and read by nothing this " +
				"door reaches",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				in.Now = time.Time{}
			},
			refuses: nil,
		},
	}
	for _, bucket := range proposalBucketsOf(&ProposalList{}) {
		field := bucket.field
		carries := bucket.carries
		rows["List."+field] = commitSourceEstablishment{
			establishes: "the " + field + " bucket holds exactly the " + proposalTypeName(carries) +
				" proposals of the commit order, so a rule stated over the bucket is a rule about the commit " +
				"the sender signed rather than about a field a caller filled in beside it",
			breaks: func(t *testing.T, crypto CryptoProvider, in *CommitValidationInput) {
				commitSetBucket(t, in.List, field, nil)
			},
			refuses: ErrProposalListBucketsDisagree,
		}
	}
	return rows
}

// TestEveryRuleTheCommitAggregateRunsDecidesOffASourceTheDoorEstablishes is this task's gate, and
// it is the derivation rather than a list of the four rules that happened to be wrong.
//
// BOTH DIRECTIONS. A source some rule decides off with no row is a rule standing on nothing --
// which is what ValSem200 was doing off the Removes bucket while the door held only All, and what a
// thirteenth rule reading a fifth source would be doing on the commit that adds it. A row for a
// source no rule reads is an establishment nothing needs, and it goes.
func TestEveryRuleTheCommitAggregateRunsDecidesOffASourceTheDoorEstablishes(t *testing.T) {
	sources := commitRuleSources(t)
	rows := commitDoorEstablishments()
	needed := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(sources)) {
		for _, source := range sources[name] {
			needed[source] = true
			if _, established := rows[source]; established {
				continue
			}
			t.Errorf("%s decides off %s and the door establishes nothing about it. A rule stated over a field the door has not joined to the commit is a rule about a commit that was never sent: write down what the door establishes about %s and drive it, or stop reading it",
				name, source, source)
		}
		t.Logf("%s decides off %v", name, sources[name])
	}
	for _, source := range slices.Sorted(maps.Keys(rows)) {
		if !needed[source] {
			t.Errorf("the door is said to establish %s and no rule the aggregate runs decides off it; an establishment nothing needs goes on reporting a clean bill after the rule it was written for has gone",
				source)
		}
	}
}

// TestEveryEstablishmentTheCommitDoorClaimsIsOneItMakes drives every row, so the table above is a
// set of assertions rather than a set of labels.
//
// The control per row is what makes the break exact: the commit each row starts from is accepted by
// ValidateCommit, so the refusal that follows is the break's and not something the fixture was
// already carrying.
func TestEveryEstablishmentTheCommitDoorClaimsIsOneItMakes(t *testing.T) {
	crypto := testCrypto(t)
	rows := commitDoorEstablishments()
	if len(rows) == 0 {
		t.Fatal("no establishment is written down, so this drives nothing")
	}
	for _, source := range slices.Sorted(maps.Keys(rows)) {
		row := rows[source]
		t.Run(source, func(t *testing.T) {
			if row.establishes == "" || row.breaks == nil {
				t.Fatalf("%s is classified with no account of what the door establishes or no input that breaks it",
					source)
			}
			build := row.build
			if build == nil {
				build = testCommitCarryingOneOfEveryBucket
			}
			in := build(t, crypto)
			if failure := ValidateCommit(in); failure != nil {
				t.Fatalf("ValidateCommit refused the commit this row is one break away from: %v; every refusal below would then be that one",
					failure)
			}
			row.breaks(t, crypto, in)
			answered := ValidateCommit(in)
			if row.refuses == nil {
				if answered != nil {
					t.Fatalf("the row says the door establishes nothing about %s and ValidateCommit answered %v once it was broken; a rule the aggregate runs has come to decide off it, so the door owes it an establishment",
						source, answered)
				}
				return
			}
			if !errors.Is(answered, row.refuses) {
				t.Fatalf("ValidateCommit over a commit whose %s the door was said to establish answered %v, want %v",
					source, answered, row.refuses)
			}
		})
	}
}

// commitRuleTrees is which of the two trees each rule of the aggregate is stated over, with the
// reason.
//
// THE TWO ARE INTERCHANGEABLE IN EVERY FIXTURE THAT CLONES ONE INTO THE OTHER, which is what every
// fixture in this file does by default, and that is why this is written down: three tree reads of
// validate_commit.go could be swapped to the other tree with the whole suite green. It is derived
// off the same walk the establishment gate uses, so a rule that starts reading a tree, stops
// reading one, or comes to read BOTH fails here rather than passing quietly -- and reading both is
// its own failure, because a rule whose two halves are judged in two different epochs is two rules.
var commitRuleTrees = map[string]string{
	"ValSem200NoSelfRemove": "PreTree: section 12.2 is stated over the group the proposals ARRIVED in, and " +
		"proposalValidationInput is the one place this file decides that",
	"ValSem208SingleGroupContextExtensions": "PreTree: the same delegate input, for ValSem200's reason",
	"ValSem202PathLength": "PostTree: the proposals are applied before the path is validated and a remove " +
		"blanks nodes the filter steps over, so against the pre tree an honest commit that removes anybody " +
		"would be refused",
	"ValSem203PathDecrypt": "PostTree: the path addresses positions in the tree it was BUILT against, so a " +
		"receiver the commit's own proposals moved or evicted is judged where the path put it",
	"ValSem204PathKeyMismatch": "PreTree: section 12.4.2 states it over the committer's CURRENT leaf, which is " +
		"the leaf the path is replacing",
	"ValSem207PathEncryptionKeysUnique": "PostTree: the keys the path is about to install must be new to the " +
		"tree the merge happens in",
	"ValSem209GroupExtensionsSupported": "PostTree: the members the new extensions take effect for are the ones " +
		"this commit LEAVES in the group, the ones it adds included",
	"validateCommitPostTreeIsExportable": "PostTree: ValSem300 is stated over the tree a GroupInfo published " +
		"from this commit carries",
}

// TestEveryTreeReadOfTheCommitRulesIsTheTreeItsRuleIsStatedOver holds each rule to one tree.
func TestEveryTreeReadOfTheCommitRulesIsTheTreeItsRuleIsStatedOver(t *testing.T) {
	sources := commitRuleSources(t)
	read := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(sources)) {
		trees := []string{}
		for _, source := range sources[name] {
			if source == "PreTree" || source == "PostTree" {
				trees = append(trees, source)
			}
		}
		if len(trees) == 0 {
			continue
		}
		if len(trees) > 1 {
			t.Errorf("%s decides off %v; a rule stated over both trees is a rule whose two halves are judged in two different epochs, and the table below can say only one thing about it",
				name, trees)
			continue
		}
		read[name] = trees[0]
	}
	if len(read) < 2 {
		t.Fatalf("the derivation found %d rules reading a tree and this file states more than that, so it read something other than the rules",
			len(read))
	}
	for _, name := range slices.Sorted(maps.Keys(read)) {
		reason, written := commitRuleTrees[name]
		if !written {
			t.Errorf("%s decides off %s and nothing says which tree it is stated over; the two are interchangeable in every fixture that clones one into the other, so a rule with no row here is one whose tree can be swapped with the suite green",
				name, read[name])
			continue
		}
		if !strings.HasPrefix(reason, read[name]+":") {
			t.Errorf("%s decides off %s and it is written down as %q; one of the two has moved",
				name, read[name], reason)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(commitRuleTrees)) {
		if _, reads := read[name]; !reads {
			t.Errorf("a tree is written down for %s and the aggregate runs no rule of that name that reads one; the row has outlived what it classified",
				name)
		}
	}
}

// TestTheSectionTwelveTwoInputThisFileBuildsIsThisCommitsOwnFields holds every field of the
// delegate input to the field of this input it is built from.
//
// proposalValidationInput is the one place this file decides what section 12.2 is asked ABOUT, and
// its Tree is the one field whose value does not carry the same name on both sides: PreTree,
// because section 12.2's membership rules are about the group the proposals arrived in. Swapping it
// to PostTree leaves the behaviour of both delegating rules unchanged -- neither reads the tree at
// all -- so the mapping is asserted here rather than left to a rule to notice.
//
// Held to the delegate type in BOTH directions, so a field added to ProposalValidationInput that
// this builder leaves at its zero value fails here rather than being handed over empty.
func TestTheSectionTwelveTwoInputThisFileBuildsIsThisCommitsOwnFields(t *testing.T) {
	crypto := testCrypto(t)
	in := testCommitCarryingOneOfEveryBucket(t, crypto)
	// the two trees must be distinguishable, or every claim below about which one was handed over
	// is a comparison of one pointer with itself
	if in.PreTree == in.PostTree {
		t.Fatal("the fixture hands one tree to both fields, so nothing below can tell them apart")
	}
	in.Extensions = slices.Clone(testCommitInstalledExtensions())
	in.Now = time.Now().Add(time.Hour)
	built := in.proposalValidationInput()
	if built == nil {
		t.Fatal("proposalValidationInput answered nothing")
	}
	expected := map[string]any{
		"Crypto":     in.Crypto,
		"Tree":       in.PreTree,
		"Context":    in.Context,
		"Extensions": in.Extensions,
		"Committer":  in.Committer,
		"List":       in.List,
		"Now":        in.Now,
	}
	delegate := reflect.TypeOf(ProposalValidationInput{})
	if delegate.NumField() == 0 {
		t.Fatal("reflection found no field on ProposalValidationInput, so this gate read nothing")
	}
	held := reflect.ValueOf(built).Elem()
	for i := 0; i < delegate.NumField(); i += 1 {
		name := delegate.Field(i).Name
		want, written := expected[name]
		if !written {
			t.Errorf("a ProposalValidationInput carries %s and nothing says which field of a commit validation input it is built from; a field left at its zero value is section 12.2 asked about something the commit does not carry",
				name)
			continue
		}
		if got := held.Field(i).Interface(); !reflect.DeepEqual(got, want) {
			t.Errorf("the section 12.2 input's %s is %v and this commit's own value is %v", name, got, want)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(expected)) {
		if _, onTheType := delegate.FieldByName(name); !onTheType {
			t.Errorf("this gate claims the delegate carries %s and a ProposalValidationInput has no such field",
				name)
		}
	}
}

// TestValSem209IsStatedOverTheTreeTheProposalsBuild is finding 3's behavioural half for the member
// walk, and it is the security relevant direction.
//
// A MEMBER THIS COMMIT ADDS is in the post-proposal tree and in no other, so it is the member the
// distinction is visible on: section 12.4.2 applies the proposals before the extensions are judged,
// so a joiner who does not support an extension the same commit installs is exactly the state
// section 13.4 says cannot happen. Over the pre-commit tree that joiner is not there to be asked
// and the whole rule reports clean.
//
// The removed-member direction cannot tell the two trees apart, which is why it is not the fixture:
// ValSem209 skips the leaves the list removes, so a narrow member the commit evicts is exempt in
// both trees.
//
// The offender is at the LAST leaf of the post tree and behind the exempt extension in the
// installed vector, so neither loop can be narrowed to element zero and still refuse it.
func TestValSem209IsStatedOverTheTreeTheProposalsBuild(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "erin"))
	kp.LeafNode.Capabilities = testNarrowedCapabilities()

	list := testProposalList(t, testGceOf(
		Extension{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: []byte{}},
		Extension{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor, ExtensionData: []byte{}}),
		testAddOf(kp))
	in := testCommitInput(t, crypto, tree, list, &Commit{})
	applied, err := ApplyProposals(in.PreTree, in.Context, in.Committer, in.List)
	if err != nil {
		t.Fatalf("ApplyProposals to build the post tree: %v", err)
	}
	in.PostTree = applied.Tree
	if len(in.PostTree.NonBlankLeaves()) <= len(in.PreTree.NonBlankLeaves()) {
		t.Fatalf("the post tree holds %d members and the pre tree %d; the add must put one there or the two trees are one",
			len(in.PostTree.NonBlankLeaves()), len(in.PreTree.NonBlankLeaves()))
	}
	if failure := ValSem209GroupExtensionsSupported(in); !errors.Is(failure, errGroupContextExtensionNotListed) {
		t.Fatalf("ValSem209 over a commit installing urmessage_owner_successor while ADDING a member that does not list it = %v, want errGroupContextExtensionNotListed",
			failure)
	}
	// and over the pre-commit tree the joiner is not a member yet, so the rule has nobody to
	// refuse -- which is what makes the tree this rule reads a decision rather than a spelling
	overThePreTree := *in
	overThePreTree.PostTree = in.PreTree
	if failure := ValSem209GroupExtensionsSupported(&overThePreTree); failure != nil {
		t.Fatalf("ValSem209 over the pre-commit tree refused %v; the fixture is then not telling the two trees apart",
			failure)
	}
}

// TestValSem203ReadsTheFilteredDirectPathsOfTheTreeThePathWasBuiltAgainst is finding 3's
// behavioural half for the receiver's own filtered direct path.
//
// A COMMIT THAT EVICTS THIS MEMBER is the input the distinction is visible on. Removing the right
// hand half of the group truncates the tree, so the evicted member's leaf is not a position of the
// post-proposal tree at all and the path, which was built against that tree, addresses nothing to
// it. Over the pre-commit tree the same member's filtered direct path meets the committer's at the
// root, and the rule reports that a secret exists for a member the commit has removed.
//
// WHICH READ FIRED IS ASSERTED and not only that something did. Both halves of this rule answer
// errPathDecrypt, so the sentinel alone cannot tell the receiver's own path read from the
// intersection that follows it: with the read swapped to the pre tree this input is still refused,
// by the clause below it. The committer's half of the same swap is held by
// TestEveryTreeReadOfTheCommitRulesIsTheTreeItsRuleIsStatedOver, which fails on a rule that comes
// to read both trees.
func TestValSem203ReadsTheFilteredDirectPathsOfTheTreeThePathWasBuiltAgainst(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
	list := testProposalList(t, testRemoveOf(LeafIndex(2)), testRemoveOf(LeafIndex(3)))
	in := testCommitInput(t, crypto, tree, list, &Commit{})
	applied, err := ApplyProposals(in.PreTree, in.Context, in.Committer, in.List)
	if err != nil {
		t.Fatalf("ApplyProposals to build the post tree: %v", err)
	}
	in.PostTree = applied.Tree
	if in.PostTree.LeafCount() >= in.PreTree.LeafCount() {
		t.Fatalf("the post tree is %d leaves wide and the pre tree %d; the removals must truncate or the two trees are one",
			in.PostTree.LeafCount(), in.PreTree.LeafCount())
	}
	in.Commit.Path = testCommitPath(t, crypto, members[0], 1)
	in.Committer = LeafIndex(0)
	in.Own = LeafIndex(3)

	failure := ValSem203PathDecrypt(in)
	if !errors.Is(failure, errPathDecrypt) {
		t.Fatalf("ValSem203 over a receiver this commit removes = %v, want errPathDecrypt", failure)
	}
	if !strings.Contains(failure.Error(), "this member's filtered direct path") {
		t.Errorf("ValSem203 refused with %v; over a receiver whose leaf the post-proposal tree no longer has, the refusal that says the tree was read is the one about this member's own filtered direct path",
			failure)
	}
	overThePreTree := *in
	overThePreTree.PostTree = in.PreTree
	if answered := ValSem203PathDecrypt(&overThePreTree); answered != nil {
		t.Fatalf("ValSem203 over the pre-commit tree answered %v and must accept; the fixture is then not telling the two trees apart",
			answered)
	}
}
