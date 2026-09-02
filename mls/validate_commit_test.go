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
	"errors"
	"go/ast"
	"maps"
	"os"
	"path/filepath"
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
	"errMissingPath":                errMissingPath,
	"errPathLeafKeyUnchanged":       errPathLeafKeyUnchanged,
	"errBadConfirmationTag":         errBadConfirmationTag,
	"errCommitterNotMember":         errCommitterNotMember,
	"errProfileExternalSender":      errProfileExternalSender,
	"errProfileGroupExtension":      errProfileGroupExtension,
	"errUnregisteredGroupExtension": errUnregisteredGroupExtension,
}

// commitValidationBorrowedErrors is every sentinel a rule of validate_commit.go answers that some
// other file declares.
//
// It is written down because the exclusivity sweep has to run over the WHOLE class a commit
// refusal can come from, and half of that class is deliberately not this file's: ValSem200
// delegates to section 12.2's body, ValSem207 to the tree's walk, CheckErrata8815 to the cache's
// value. A sweep bounded to one file's declarations would report clean over exactly the rules this
// file was careful not to give values of their own.
var commitValidationBorrowedErrors = map[string]error{
	"ErrRemoveCommitter":                ErrRemoveCommitter,
	"ErrLeafNodeSourceMismatch":         ErrLeafNodeSourceMismatch,
	"errPathLength":                     errPathLength,
	"errPathDecrypt":                    errPathDecrypt,
	"errMissingConfirmationTag":         errMissingConfirmationTag,
	"errDuplicateEncryptionKey":         errDuplicateEncryptionKey,
	"errMultipleGroupContextExtensions": errMultipleGroupContextExtensions,
	"errGroupContextExtensionNotListed": errGroupContextExtensionNotListed,
	"errMissingRequiredCapability":      errMissingRequiredCapability,
	"errTrailingBlankNodes":             errTrailingBlankNodes,
	"errProposalNotCached":              errProposalNotCached,
	"errProfileExternalCommit":          errProfileExternalCommit,
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
// the ones its rules deliberately borrow.
func commitRefusalRoster() map[string]error {
	roster := map[string]error{}
	maps.Copy(roster, commitValidationOwnedErrors)
	maps.Copy(roster, commitValidationBorrowedErrors)
	return roster
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

// commitRuleCase is one rule, the input that makes it refuse, and the sentinel it owes.
type commitRuleCase struct {
	sentinel string
	run      func(t *testing.T) error
}

// commitRuleCases is one row per rule this file states, each building the input that produces that
// rule's refusal.
//
// This is the table ledger 17 asks for -- every code owes a test that names it -- and it is also
// the exclusivity sweep: TestEachCommitRuleAnswersOnlyItsOwnSentinel runs each row and requires
// every other member of the roster not to answer.
func commitRuleCases() map[string]commitRuleCase {
	return map[string]commitRuleCase{
		"ValSem200NoSelfRemove": {sentinel: "ErrRemoveCommitter", run: func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
			list := testProposalList(t,
				CachedProposal{ByValue: true, Proposal: Proposal{ProposalType: ProposalTypeRemove,
					Remove: &Remove{Removed: 2}}},
				CachedProposal{ByValue: true, Proposal: Proposal{ProposalType: ProposalTypeRemove,
					Remove: &Remove{Removed: 0}}})
			return ValSem200NoSelfRemove(testCommitInput(t, crypto, tree, list, &Commit{}))
		}},
		"ValSem201PathPresentWhenRequired": {sentinel: "errMissingPath", run: func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob")
			return ValSem201PathPresentWhenRequired(
				testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{}))
		}},
		"ValSem202PathLength": {sentinel: "errPathLength", run: func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
			return ValSem202PathLength(testCommitInput(t, crypto, tree, &ProposalList{},
				&Commit{Path: testCommitPath(t, crypto, members[0], 1)}))
		}},
		"validateCommitPathLeafSource": {sentinel: "ErrLeafNodeSourceMismatch", run: func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, members := testTreeWith(t, crypto, "alice", "bob")
			leaf, _ := testLeafNode(t, crypto, members[0])
			return validateCommitPathLeafSource(testCommitInput(t, crypto, tree, &ProposalList{},
				&Commit{Path: &UpdatePath{LeafNode: *leaf}}))
		}},
		"ValSem203PathDecrypt": {sentinel: "errPathDecrypt", run: func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
			path := testCommitPath(t, crypto, members[0], 2)
			path.Nodes[1].EncryptedPathSecret = nil
			return ValSem203PathDecrypt(testCommitInput(t, crypto, tree, &ProposalList{},
				&Commit{Path: path}))
		}},
		"ValSem204PathKeyMismatch": {sentinel: "errPathLeafKeyUnchanged", run: func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, members := testTreeWith(t, crypto, "alice", "bob")
			leaf := testCommitPathLeaf(t, crypto, members[0])
			leaf.EncryptionKey = tree.Leaf(LeafIndex(0)).EncryptionKey
			return ValSem204PathKeyMismatch(testCommitInput(t, crypto, tree, &ProposalList{},
				&Commit{Path: &UpdatePath{LeafNode: *leaf}}))
		}},
		"ValSem205ConfirmationTag": {sentinel: "errBadConfirmationTag", run: func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice")
			in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
			in.ConfirmationKey = make([]byte, crypto.HashSize())
			in.ConfirmedHash = []byte("confirmed")
			in.ConfirmationTag = []byte("not the tag")
			return ValSem205ConfirmationTag(in)
		}},
		"ValSem206PathLeafEncryptionKeyUnique": {sentinel: "errDuplicateEncryptionKey", run: func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, members := testTreeWith(t, crypto, "alice", "bob")
			innocent, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "erin"))
			colliding, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "frank"))
			list := testProposalList(t,
				CachedProposal{ByValue: true, Proposal: Proposal{ProposalType: ProposalTypeAdd,
					Add: &Add{KeyPackage: *innocent}}},
				CachedProposal{ByValue: true, Proposal: Proposal{ProposalType: ProposalTypeAdd,
					Add: &Add{KeyPackage: *colliding}}})
			leaf := testCommitPathLeaf(t, crypto, members[0])
			leaf.EncryptionKey = colliding.LeafNode.EncryptionKey
			return ValSem206PathLeafEncryptionKeyUnique(testCommitInput(t, crypto, tree, list,
				&Commit{Path: &UpdatePath{LeafNode: *leaf}}))
		}},
		"ValSem207PathEncryptionKeysUnique": {sentinel: "errDuplicateEncryptionKey", run: func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
			path := testCommitPath(t, crypto, testIdentity(t, crypto, "mallory"), 2)
			path.Nodes[1].EncryptionKey = tree.Leaf(LeafIndex(2)).EncryptionKey
			return ValSem207PathEncryptionKeysUnique(testCommitInput(t, crypto, tree,
				&ProposalList{}, &Commit{Path: path}))
		}},
		"ValSem208SingleGroupContextExtensions": {sentinel: "errMultipleGroupContextExtensions", run: func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice")
			one := testGceOf()
			return ValSem208SingleGroupContextExtensions(
				testCommitInput(t, crypto, tree, testProposalList(t, one, one), &Commit{}))
		}},
		"ValSem209GroupExtensionsSupported": {sentinel: "errProfileExternalSender", run: func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice")
			list := testProposalList(t, testGceOf(
				Extension{ExtensionType: ExtensionTypeRatchetTree},
				Extension{ExtensionType: ExtensionTypeExternalSenders}))
			return ValSem209GroupExtensionsSupported(testCommitInput(t, crypto, tree, list, &Commit{}))
		}},
		"ValSem300NoTrailingBlankNodes": {sentinel: "errTrailingBlankNodes", run: func(t *testing.T) error {
			crypto := testCrypto(t)
			tree, _ := testTreeWith(t, crypto, "alice", "bob")
			padded := tree.Clone()
			if failure := padded.Blank(NodeIndex(padded.NodeWidth() - 1)); failure != nil {
				t.Fatalf("Blank: %v", failure)
			}
			return ValSem300NoTrailingBlankNodes(padded)
		}},
		"CheckErrata8745": {sentinel: "errGroupContextExtensionNotListed", run: func(t *testing.T) error {
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
		"CheckErrata8815": {sentinel: "errProposalNotCached", run: func(t *testing.T) error {
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

// TestEachCommitRuleAnswersOnlyItsOwnSentinel is ledger 17's obligation and the exclusivity sweep
// in one: every rule this file states has a row, the row's refusal answers the sentinel the rule
// owes, and no other member of the roster answers it.
//
// The rows are held against the DERIVED rule class in both directions, so a twelfth rule added to
// the file with no row fails rather than being left out of the sweep, and a row for a rule that has
// gone fails too. The two rules that take something other than a validation input -- ValSem300 and
// the two errata -- are in the class by name because the aggregate reaches them through adapters,
// and those adapters are the members of the derived class that stand for them.
func TestEachCommitRuleAnswersOnlyItsOwnSentinel(t *testing.T) {
	roster := commitRefusalRoster()
	cases := commitRuleCases()
	for _, name := range slices.Sorted(maps.Keys(cases)) {
		row := cases[name]
		owed, held := roster[row.sentinel]
		if !held {
			t.Errorf("%s owes %s and that name is not in the roster", name, row.sentinel)
			continue
		}
		failure := row.run(t)
		if failure == nil {
			t.Errorf("%s did not refuse the input built for it, so this row states nothing about %s",
				name, row.sentinel)
			continue
		}
		if !errors.Is(failure, owed) {
			t.Errorf("%s answered %v, want %s", name, failure, row.sentinel)
			continue
		}
		for _, other := range slices.Sorted(maps.Keys(roster)) {
			if other == row.sentinel || commitValidationSanctionedWraps[row.sentinel] == other {
				continue
			}
			if errors.Is(failure, roster[other]) {
				t.Errorf("%s refused with %v, which also answers %s; a caller cannot tell which rule fired and a negative test asserting %s would pass over this one",
					name, failure, other, other)
			}
		}
	}
	// both directions against the rule class the aggregate is derived from, minus the adapters,
	// so a rule with no row cannot hide
	declared := commitRuleNamesDeclared(t)
	adapters := map[string]bool{
		"ValidateCommit": true, "validateCommitErrata": true,
		"validateCommitPostTreeIsExportable": true,
	}
	for _, name := range declared {
		if adapters[name] {
			continue
		}
		if _, hasRow := cases[name]; !hasRow {
			t.Errorf("%s is a rule of this file and no row of commitRuleCases builds the input that makes it refuse; ledger 17 is that every code owes a test that names it",
				name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(cases)) {
		if slices.Contains(declared, name) {
			continue
		}
		// the three rules stated over something other than a validation input
		if name == "ValSem300NoTrailingBlankNodes" || name == "CheckErrata8745" || name == "CheckErrata8815" {
			continue
		}
		t.Errorf("commitRuleCases holds a row for %s and %s declares no rule of that name",
			name, commitValidationFile)
	}
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
func TestEveryCommitValidationEntryPointRefusesANilInput(t *testing.T) {
	doors := map[string]func(*CommitValidationInput) error{
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

// TestValidateCommitAcceptsAWellFormedFullCommit is the accepting half of the aggregate.
//
// Without it every rule above could be "return the refusal unconditionally" and the whole file
// would still be green. The fixture is a four member group, a full commit from leaf 0 with a fresh
// path of the filtered direct path's own length, and no proposals -- which is section 12.4's
// "empty" configuration and the one every other configuration is a narrowing of.
func TestValidateCommitAcceptsAWellFormedFullCommit(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
	filtered, failure := tree.FilteredDirectPath(LeafIndex(0))
	if failure != nil {
		t.Fatalf("FilteredDirectPath: %v", failure)
	}
	path := testCommitPath(t, crypto, members[0], len(filtered))
	// a fresh key at the leaf, which is what ValSem204 is about, and a signature key that is
	// leaf 0's so CheckUpdatePathKeyUniqueness exempts the right position
	path.LeafNode.SignatureKey = tree.Leaf(LeafIndex(0)).SignatureKey
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{Path: path})
	if failure := ValidateCommit(in); failure != nil {
		t.Fatalf("ValidateCommit refused a well formed full commit: %v", failure)
	}
}

// TestValidateCommitReachesEveryRuleItRuns is the aggregate's negative half: for each rule in the
// slice, an input that only that rule refuses comes back with that rule's sentinel.
//
// The gate above says the slice NAMES every rule; this says the loop that walks it actually calls
// them, which a `for range checks[:1]` would pass the first of and fail here.
func TestValidateCommitReachesEveryRuleItRuns(t *testing.T) {
	crypto := testCrypto(t)
	// the LAST rule of the slice, reached only if the loop walks the whole of it: a post tree
	// ending in a blank node, with every earlier rule satisfied
	tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
	filtered, failure := tree.FilteredDirectPath(LeafIndex(0))
	if failure != nil {
		t.Fatalf("FilteredDirectPath: %v", failure)
	}
	path := testCommitPath(t, crypto, members[0], len(filtered))
	path.LeafNode.SignatureKey = tree.Leaf(LeafIndex(0)).SignatureKey
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{Path: path})
	if failure := in.PostTree.Blank(NodeIndex(in.PostTree.NodeWidth() - 1)); failure != nil {
		t.Fatalf("Blank: %v", failure)
	}
	// blanking the rightmost leaf changes the filtered direct path, so the path length rule would
	// answer first; the check is re-lengthened against the post tree the aggregate reads
	refiltered, failure := in.PostTree.FilteredDirectPath(LeafIndex(0))
	if failure != nil {
		t.Fatalf("FilteredDirectPath over the padded tree: %v", failure)
	}
	in.Commit.Path = testCommitPath(t, crypto, members[0], len(refiltered))
	in.Commit.Path.LeafNode.SignatureKey = tree.Leaf(LeafIndex(0)).SignatureKey
	if failure := ValidateCommit(in); !errors.Is(failure, errTrailingBlankNodes) {
		t.Fatalf("ValidateCommit over a post tree ending in a blank = %v, want errTrailingBlankNodes; the last rule of commitValidationChecks is reached only if the loop walks the whole slice",
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
