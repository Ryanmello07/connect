// The commit and proposal fixture corpora, and the gate that measures BOTH of them.
//
// THREE CONSECUTIVE ROUNDS OF THE COMMIT DOOR HAD ONE ROOT CAUSE AND IT WAS NOT IN THE DOOR. "Every
// fixture carries exactly one Update" made every loop narrowable to element zero; "every fixture
// makes PostTree a Clone of PreTree" made three tree reads swappable; "every fixture puts the
// committer at leaf 0" made `Sender: self.Committer` indistinguishable from the constant
// `LeafIndex(0)`. Each round repaired the comparison it was handed and left the corpus that hid it,
// so the next round found the next constant.
//
// A CORPUS THAT DRIFTS BACK TO CONSTANTS IS THE DEFECT, so it is measured here rather than
// remembered. What the gate below asserts is one property stated once: no dimension of a validation
// input is the SAME VALUE across the whole corpus. A dimension that is constant is a dimension on
// which the production code and that constant are the same program, which is what "the fixtures
// cannot see it" means and is the only thing all three rounds had in common.
//
// THE FOURTH ROUND WAS THIS FILE'S OWN. The gate derived its walk and NAMED ITS SCOPE -- it walked
// for values of two types, LeafIndex and *RatchetTree, and was blind to every other type an input
// carries. Owner-verified: a collapsed `Generation uint32` added to CommitValidationInput left the
// gate passing and logging "11 fixtures, 5 leaf dimensions"; the identical field typed LeafIndex
// fired. That is ledger 21 applied to types -- derive the walk, enumerate the scope -- and the
// scope was where the survivors were. Five reads of the proposal door were measured as
// indistinguishable from build-time constants through it: `in.Context.GroupId`, both halves of
// ValSem105's suite-and-version comparison, the ciphersuite ValSem105 hands KeyPackage.Validate,
// and the clock it hands with it. So the walk below carries NO type at all. It records whatever it
// reaches, by the path that reached it, rendered canonically.
//
// AND IT MEASURES BOTH DOORS. There was no corpus for ProposalValidationInput -- zero references to
// the type in this file, across fifty call sites of testValidationInput, forty-eight of which
// passed LeafIndex(0) -- so the door that reads the group id, the ciphersuite, the version and the
// clock was the one door nothing held to being able to see them. All five survivors lived there.
// The corpora are a REGISTRY keyed by the input type and joined to the types the package's own
// source declares, in both directions, because "two tests, one of which gets deleted" is the shape
// that defect takes next.
//
// WHY THE WALK STOPS WHERE IT DOES, because a bound that is not argued for is the next round's
// finding. It descends through containers -- pointers, interfaces, slices, arrays and maps cost
// nothing -- and spends one HOP per struct field, to a depth of corpusDimensionHops. That is the
// granularity commitInputSourceClass already derives the door's own source class at ("one level of
// expansion for List and for Commit and no deeper, because that is where the granularity stops
// mattering"), and it is where the input's own fields end and the CONTENTS of the messages it
// carries begin. Measured, unbounded is not the stronger choice but an unsatisfiable one: at full
// depth the corpus is asked to separate `List[].Proposal.ExternalInit`, `.PreSharedKey`, `.ReInit`
// and the unknown-type pair, which this profile refuses to populate at all -- checkProposalProfile
// rejects every one of those types before any rule sees the list -- so the claim could never go
// green whatever anybody wrote. A constant deeper than the bound is not invisible; it is folded
// into the rendering of its ancestor, so it is caught whenever that ancestor is constant too. What
// is given up is the ability to demand a DEEP field vary while its parent already does, and for
// the one type these doors decide off -- a leaf index -- that is bought back by the unbounded scan
// the octet claim runs.
package mls

import (
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"math"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// the second value of every dimension the corpus used to hold at one
// ---------------------------------------------------------------------------

// testSecondGroupId is the group id the fixtures that are NOT in testValidationGroupId's group
// announce.
//
// A SECOND SPELLING IS THE WHOLE POINT OF IT. An update leaf's LeafNodeTBS covers the group id, so
// validate_proposals.go hands in.Context.GroupId to the leaf validator to rebuild the preimage the
// leaf signed; over a corpus that runs in one group that read and the literal []byte("group") are
// the same program, and the cross-group replay the function's own header exists to close is
// untested. A fixture in this group signs its update leaves under THIS id, so the literal rebuilds
// the wrong preimage and the signature stops verifying.
func testSecondGroupId() []byte {
	return []byte("second-group")
}

// testSecondEpoch is the epoch those fixtures run in, and it is neither the default 1 nor 0.
const testSecondEpoch = uint64(9)

// testUnimplementedProtocolVersion is a protocol version this build does not implement.
//
// PRIVATE USE RATHER THAN INVENTED. RFC 9420's protocol version registry reserves the top of the
// range for private use, so this is a code point a deployment may legitimately carry and this build
// legitimately refuses -- unlike the zero value, which is "the caller forgot" and would make every
// refusal below ambiguous between a version rule and a missing field.
//
// It exists because ProtocolVersionMls10 is the only version this build accepts, so a corpus that
// announces only that cannot tell ValSem105's `kp.Version != in.Context.Version` from
// `kp.Version != ProtocolVersionMls10`. A group context announcing this one, with an Add carrying
// an ordinary mls10 key package, tells them apart in the only direction that is decidable: the
// honest comparison refuses the Add and the literal accepts it.
const testUnimplementedProtocolVersion = ProtocolVersion(0xFFFF)

// testFixedClock is a clock that is not the wall clock, and it is far enough from it that a
// lifetime decided under one is decided the other way under the other.
//
// THE CORPUS USED TO HOLD ONE CLOCK AND IT WAS time.Now(). in.Now is read in exactly two production
// places, and validate_commit_test.go says outright that the commit aggregate reads it by nothing
// -- so the only two tests that moved the clock were on the door that ignores it, and the door that
// reads it, ValSem105's `kp.Validate(in.Crypto, in.Context.CipherSuite, in.Now)`, saw one clock
// that was always approximately time.Now(). Substituting time.Now() for the field was therefore
// invisible. A key package this package mints is valid for about ninety days from the moment it is
// built, so a clock years past that decides its lifetime the other way.
func testFixedClock() time.Time {
	return time.Date(2031, time.March, 4, 5, 6, 7, 0, time.UTC)
}

// testOtherSuite is the registered ciphersuite this provider does NOT run, read off the registry
// rather than written down.
//
// READ OFF Suites() so that a third registered suite does not leave this pointing at a code point
// that is no longer "the other one", and so that a build with one registered suite says so here
// rather than silently measuring nothing.
func testOtherSuite(t *testing.T, crypto CryptoProvider) CipherSuite {
	t.Helper()
	for _, suite := range Suites() {
		if suite != crypto.Suite() {
			return suite
		}
	}
	t.Fatalf("only %d ciphersuite is registered, so no fixture can announce a second one and every ciphersuite read of these doors is the same program as that constant",
		len(Suites()))
	return CipherSuite(0)
}

// testOtherSuiteCrypto is a provider for that suite.
//
// A SECOND PROVIDER AND NOT A SECOND CODE POINT ON THE FIRST ONE'S INPUTS. NewKeyPackage refuses to
// mint a key package for a suite its provider does not run, and (*LeafNode).Validate judges a
// leaf's capabilities against the ciphersuite it is handed, so a fixture that merely relabelled its
// context would be a group whose members cannot do its crypto -- refused for a reason that is the
// relabelling rather than the rule under test.
func testOtherSuiteCrypto(t *testing.T, crypto CryptoProvider) CryptoProvider {
	t.Helper()
	other, err := NewCryptoProvider(testOtherSuite(t, crypto))
	if err != nil {
		t.Fatalf("NewCryptoProvider for the second registered suite: %v", err)
	}
	return other
}

// testCapabilitiesNaming is testCapabilities with the ciphersuite vector named by the caller.
func testCapabilitiesNaming(suites ...CipherSuite) Capabilities {
	named := testCapabilities()
	named.CipherSuites = slices.Clone(suites)
	return named
}

// ---------------------------------------------------------------------------
// the commit fixtures the corpus was missing
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

// testWideGroupNames is that group's membership, one name per leaf.
func testWideGroupNames() []string {
	names := make([]string, 0, testWideGroupLeaves)
	for i := 0; i < testWideGroupLeaves; i += 1 {
		names = append(names, fmt.Sprintf("wide%d", i))
	}
	return names
}

// testWideCommitInput is testFullCommitInput over a group wide enough that its leaf indices do not
// fit in one octet.
func testWideCommitInput(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
	t.Helper()
	tree, members := testTreeWith(t, crypto, testWideGroupNames()...)
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

// testCommitInputInASecondGroupAtALaterEpoch is the fixture that is not in the default group, not
// in the default epoch, not on the wall clock, and not empty in the fields the default leaves nil.
//
// ONE FIXTURE FOR SEVERAL DIMENSIONS, and that is deliberate rather than lazy. The claim the gate
// states is that no dimension is ONE VALUE across the corpus, which one differing fixture settles
// for each; what a fixture per dimension would buy is a smaller blast radius when a door starts
// refusing, and what it would cost is ten near-identical commits somebody has to keep in step. The
// dimensions bundled here are the ones the commit door reads by NOTHING -- validate_commit_test.go's
// establishment table says so for the clock, and the group id, the epoch and the confirmation
// triple are read only by rules the aggregate does not run -- so a refusal here can only come from
// the two that ARE read, the group extensions.
//
// THE CONFIRMATION TRIPLE IS CONSISTENT rather than three unrelated slices. ValSem205 is the one
// rule of this file the aggregate deliberately does not run, and until this fixture existed there
// was no input in the corpus it could even be asked of: every fixture left all three fields nil, so
// "the tag verifies" and "the tag is missing" were the same input.
func testCommitInputInASecondGroupAtALaterEpoch(t *testing.T,
	crypto CryptoProvider) *CommitValidationInput {

	t.Helper()
	tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
	in.Context = &GroupContext{
		Version:                 ProtocolVersionMls10,
		CipherSuite:             crypto.Suite(),
		GroupId:                 testSecondGroupId(),
		Epoch:                   testSecondEpoch,
		ConfirmedTranscriptHash: crypto.Hash([]byte("the second group's confirmed transcript")),
		Extensions:              testCommitInstalledExtensions(),
	}
	in.Extensions = slices.Clone(testCommitInstalledExtensions())
	in.Now = testFixedClock()
	in.ConfirmationKey = crypto.Random(crypto.HashSize())
	in.ConfirmedHash = crypto.Hash([]byte("the second group's confirmed hash"))
	in.ConfirmationTag = crypto.Mac(in.ConfirmationKey, in.ConfirmedHash)
	testCommitProposals(t, in, testRemoveOf(LeafIndex(3)), testRemoveOf(LeafIndex(2)))
	testFitCommitPath(t, crypto, in, members[in.Committer])
	if failure := ValidateCommit(in); failure != nil {
		t.Fatalf("ValidateCommit refused the second group's commit: %v", failure)
	}
	// the triple is a triple and not three fields, so the rule the aggregate does not run has an
	// input it accepts
	if failure := ValSem205ConfirmationTag(in); failure != nil {
		t.Fatalf("ValSem205 refused this fixture's own confirmation tag: %v", failure)
	}
	return in
}

// testCommitInputUnderTheOtherSuite is a commit in a group that runs the registry's OTHER suite.
//
// THE PROVIDER IS THE OTHER SUITE'S TOO, which is what makes this a group rather than a relabelled
// context: every key in the tree, in the path and in the proposals is drawn through it. Until it
// existed the whole corpus ran one suite, so `in.Context.CipherSuite` and the default code point
// were the same program at every door that reads one.
func testCommitInputUnderTheOtherSuite(t *testing.T, crypto CryptoProvider) *CommitValidationInput {
	t.Helper()
	other := testOtherSuiteCrypto(t, crypto)
	tree, members := testTreeWith(t, other, "alice", "bob", "carol", "dave")
	in := testCommitInput(t, other, tree, &ProposalList{}, &Commit{})
	in.Context.CipherSuite = other.Suite()
	testFitCommitPath(t, other, in, members[in.Committer])
	if failure := ValidateCommit(in); failure != nil {
		t.Fatalf("ValidateCommit refused the other suite's commit: %v", failure)
	}
	return in
}

// testCommitInputAnnouncingAnUnimplementedVersion is a commit whose group context announces a
// protocol version this build does not implement.
//
// AND THE COMMIT DOOR ACCEPTS IT, which is asserted here rather than left as a surprise. That is a
// finding about the door and not about this fixture: no rule ValidateCommit runs reads
// Context.Version at all, and neither does any rule of section 12.2 except ValSem105's comparison
// against an Add's key package -- so a commit arriving in a group whose context claims a version
// this build cannot speak is judged in full and accepted. welcome.go refuses exactly that shape at
// the join door (`self.GroupContext.Version != ProtocolVersionMls10`); the commit door has no
// equivalent. The day one is added this fixture fails, and the answer is to move it to a refusal
// rather than to soften the claim.
func testCommitInputAnnouncingAnUnimplementedVersion(t *testing.T,
	crypto CryptoProvider) *CommitValidationInput {

	t.Helper()
	in, _ := testFullCommitInput(t, crypto)
	in.Context.Version = testUnimplementedProtocolVersion
	if failure := ValidateCommit(in); failure != nil {
		t.Fatalf("ValidateCommit refused a commit whose context announces version %#04x: %v. That is a rule this door did not have when this fixture was written; move the fixture to the refusing side rather than narrowing the corpus",
			uint16(testUnimplementedProtocolVersion), failure)
	}
	return in
}

// ---------------------------------------------------------------------------
// the proposal fixtures, which is a corpus that did not exist
// ---------------------------------------------------------------------------

// testValidationInputInASecondGroupAtALaterEpoch is the section 12.2 input that is not in
// testValidationGroupId's group.
//
// ITS UPDATE LEAF IS SIGNED UNDER THIS GROUP'S ID, which is the whole of what it measures.
// validateUpdateLeafNodeIsValidForAnUpdate hands in.Context.GroupId to the leaf validator, which
// rebuilds the LeafNodeTBS the leaf signed; over a corpus in one group that read is the literal
// []byte("group"), and a leaf signed in another group -- a replayed update, which is the fault the
// binding exists to refuse -- would be admitted by the literal and is refused by the read.
//
// IT ALSO CARRIES THE INPUT'S OWN Extensions AND A TREE HASH, because the corpus held both at one
// value: nil. effectiveExtensions prefers the explicit vector over the group's own, so a corpus
// that never sets it drives only two of that function's three arms.
func testValidationInputInASecondGroupAtALaterEpoch(t *testing.T,
	crypto CryptoProvider) *ProposalValidationInput {

	t.Helper()
	tree, members := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
	treeHash, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("the second group's tree hash: %v", err)
	}
	leaf, _ := testUpdateLeafNode(t, crypto, members[2], testSecondGroupId(), LeafIndex(2))
	return &ProposalValidationInput{
		Crypto: crypto,
		Tree:   tree,
		Context: &GroupContext{
			Version:                 ProtocolVersionMls10,
			CipherSuite:             crypto.Suite(),
			GroupId:                 testSecondGroupId(),
			Epoch:                   testSecondEpoch,
			TreeHash:                treeHash,
			ConfirmedTranscriptHash: crypto.Hash([]byte("the second group's confirmed transcript")),
		},
		Extensions: slices.Clone(testCommitInstalledExtensions()),
		Committer:  testCommitterLeaf,
		List: testProposalList(t, testUpdateOf(LeafIndex(2), leaf),
			testRemoveOf(LeafIndex(3))),
		Now: time.Now(),
	}
}

// testValidationInputUnderTheOtherSuite is a section 12.2 input for a group running the registry's
// OTHER suite, and it is what tells three ciphersuite reads of validate_proposals.go from the
// default code point.
//
// THREE, and each needs a different half of this fixture. ValSem105 compares an Add's key package
// ciphersuite against the group's, so the Add is minted under the other suite. ValSem105 then hands
// that same field to KeyPackage.Validate, which compares it again. And
// validateUpdateLeafNodeIsValidForAnUpdate hands it to the leaf validator, which asks whether the
// UPDATE leaf's capabilities list it -- so this fixture's update leaf advertises the group's suite
// and only that one. Every other fixture leaf in this package advertises Suites(), which is both
// registered code points, and a vector that lists both answers "supported" for either constant.
func testValidationInputUnderTheOtherSuite(t *testing.T,
	crypto CryptoProvider) *ProposalValidationInput {

	t.Helper()
	other := testOtherSuiteCrypto(t, crypto)
	tree, members := testTreeWith(t, other, "alice", "bob", "carol", "dave")
	kp, _, _ := testKeyPackage(t, other, testIdentity(t, other, "erin"))
	leaf, _ := testUpdateLeafNodeNaming(t, other, members[2], testValidationGroupId(), LeafIndex(2),
		testCapabilitiesNaming(other.Suite()))
	return &ProposalValidationInput{
		Crypto: other,
		Tree:   tree,
		Context: &GroupContext{
			Version:     ProtocolVersionMls10,
			CipherSuite: other.Suite(),
			GroupId:     testValidationGroupId(),
			Epoch:       1,
			Extensions:  testCommitInstalledExtensions(),
		},
		Committer: testCommitterLeaf,
		List:      testProposalList(t, testAddOf(kp), testUpdateOf(LeafIndex(2), leaf)),
		Now:       time.Now(),
	}
}

// testValidationInputAnnouncingAnUnimplementedVersion is the input ValSem105's VERSION clause is
// decidable over, and it is a refusal.
//
// The suite clause of that comparison is separable by an accepted input -- a group running the
// other registered suite, with an Add that names it -- but the version clause is not, because
// KeyPackage.Validate refuses every version but mls10 outright. So the only input that tells
// `kp.Version != in.Context.Version` from `kp.Version != ProtocolVersionMls10` is one where the
// GROUP announces the other version and the key package is ordinary: the read refuses it and the
// literal admits it.
func testValidationInputAnnouncingAnUnimplementedVersion(t *testing.T,
	crypto CryptoProvider) *ProposalValidationInput {

	t.Helper()
	tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "erin"))
	return &ProposalValidationInput{
		Crypto: crypto,
		Tree:   tree,
		Context: &GroupContext{
			Version:     testUnimplementedProtocolVersion,
			CipherSuite: crypto.Suite(),
			GroupId:     testValidationGroupId(),
			Epoch:       1,
		},
		Committer: testCommitterLeaf,
		List:      testProposalList(t, testAddOf(kp)),
		Now:       time.Now(),
	}
}

// testValidationInputOnAClockPastTheAddsLifetime is the input in.Now is decidable over.
//
// ValSem105 hands in.Now to KeyPackage.Validate, which clamps it to milliseconds and checks the
// added leaf's lifetime against it. Every other input of this package carries time.Now(), so the
// field and a call to time.Now() answer the same verdict for every key package the fixtures mint --
// which is what made substituting the call for the field invisible. This one is years past the
// lifetime this package's key packages carry, so the field refuses and the call accepts.
func testValidationInputOnAClockPastTheAddsLifetime(t *testing.T,
	crypto CryptoProvider) *ProposalValidationInput {

	t.Helper()
	tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "erin"))
	in := testValidationInput(t, crypto, tree, testCommitterLeaf,
		testProposalList(t, testAddOf(kp)))
	in.Now = testFixedClock()
	if expires := time.Unix(int64(kp.LeafNode.Lifetime.NotAfter), 0); !in.Now.After(expires) {
		t.Fatalf("this fixture's clock is %s and the added leaf is valid until %s; the fixture exists to be past it",
			in.Now, expires)
	}
	return in
}

// testWideValidationInput is the section 12.2 input over a group whose leaf indices do not fit in
// one octet, and it is also the one that carries an entry BY REFERENCE.
//
// The width is testWideCommitInput's argument, restated at the door next to it: every leaf index
// comparison of validate_proposals.go -- a remove's target, an update's sender, the committer --
// is exact over every group that fits in one octet, and every proposal fixture of this package
// fitted. The reference is a second dimension the corpus held at one value: every entry of every
// proposal list here was carried by value, so `ByValue` was the constant true and `Ref` the
// constant nil.
func testWideValidationInput(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
	t.Helper()
	tree, members := testTreeWith(t, crypto, testWideGroupNames()...)
	update, _ := testUpdateProposalOf(t, crypto, members[testWideOwnLeaf], testWideOwnLeaf)
	held := testCachedRemoveOf(t, crypto, testCache(t), testWideOwnLeaf-1)
	in := testValidationInput(t, crypto, tree, testWideCommitterLeaf,
		testProposalList(t, update, held))
	if failure := ValidateProposalList(in); failure != nil {
		t.Fatalf("ValidateProposalList refused the wide fixture: %v; a fixture no door accepts measures nothing about the doors",
			failure)
	}
	return in
}

// ---------------------------------------------------------------------------
// the corpora
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
		"testCommitInputOverTheTreeItsProposalsBuild":     testCommitInputOverTheTreeItsProposalsBuild,
		"testWideCommitInput":                             testWideCommitInput,
		"testCommitInputInASecondGroupAtALaterEpoch":      testCommitInputInASecondGroupAtALaterEpoch,
		"testCommitInputUnderTheOtherSuite":               testCommitInputUnderTheOtherSuite,
		"testCommitInputAnnouncingAnUnimplementedVersion": testCommitInputAnnouncingAnUnimplementedVersion,
	}
}

// proposalFixtureRow is one entry of the section 12.2 corpus: the fixture, and the verdict the door
// it is a fixture FOR must give it.
//
// THE VERDICT IS THE HALF THAT KILLS THE SURVIVORS. Separating a dimension in the corpus makes a
// production read distinguishable from a constant; it does not by itself make any test NOTICE the
// difference, and the commit corpus is measured by a gate that never calls ValidateCommit. All five
// of the reads this round was sent to close are reached only from ValidateProposalList, so the
// corpus is driven through it and each row says what must come back. A row that expects a refusal
// names the sentinel, so a fixture that starts being refused for a different reason is a failure
// rather than a pass.
type proposalFixtureRow struct {
	build func(*testing.T, CryptoProvider) *ProposalValidationInput
	// refuses is the value ValidateProposalList must answer, or nil where it must accept.
	refuses error
}

// proposalFixtureCorpus is every fixture of this package that answers a section 12.2 validation
// input, keyed by the name it is declared under.
func proposalFixtureCorpus() map[string]proposalFixtureRow {
	return map[string]proposalFixtureRow{
		"testValidationInput": {build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
			tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
			return testValidationInput(t, crypto, tree, LeafIndex(0),
				testProposalList(t, testRemoveOf(LeafIndex(2))))
		}},
		"updateSweepFixture": {build: updateSweepFixture},
		"testFullValidationInput": {build: func(t *testing.T, crypto CryptoProvider) *ProposalValidationInput {
			return testFullValidationInput(t, crypto, 9)
		}},
		"testValidationInputInASecondGroupAtALaterEpoch": {
			build: testValidationInputInASecondGroupAtALaterEpoch},
		"testValidationInputUnderTheOtherSuite": {build: testValidationInputUnderTheOtherSuite},
		"testWideValidationInput":               {build: testWideValidationInput},
		"testValidationInputAnnouncingAnUnimplementedVersion": {
			build:   testValidationInputAnnouncingAnUnimplementedVersion,
			refuses: ErrSuiteMismatch},
		"testValidationInputOnAClockPastTheAddsLifetime": {
			build:   testValidationInputOnAClockPastTheAddsLifetime,
			refuses: ErrLeafNodeLifetime},
	}
}

// ---------------------------------------------------------------------------
// the corpora, held to the package that declares the fixtures
// ---------------------------------------------------------------------------

// validationFixtureBuildersInSource is every function this package's test files declare that
// ANSWERS a validation input of the named type.
//
// THE DERIVATION IS OVER THE RESULT TYPE and not over a naming convention, because the result type
// is what makes a function a fixture for a door: a helper that takes an input and edits it --
// testCommitProposals, testFitCommitPath, testRestoreCachedEntries -- is not a corpus entry, it is
// something a corpus entry is built out of, and none of those answers one.
//
// WHAT IT BUYS is the direction the three rounds kept losing: a NEW fixture is in the corpus the
// moment it is declared, so the next person who adds one that puts the committer back on leaf 0
// finds out here rather than three rounds later. The reverse direction is worth as much -- a row
// naming a builder the package no longer declares is a row measuring nothing.
//
// PARAMETERISED BY THE TYPE NAME rather than written twice, so that the second door's corpus is
// held to the package by the same walk as the first one's and cannot come to be held by a weaker.
func validationFixtureBuildersInSource(t *testing.T, named string) []string {
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
				identifier, isNamed := pointer.X.(*ast.Ident)
				if isNamed && identifier.Name == named {
					found = append(found, function.Name.Name)
					break
				}
			}
		}
	}
	slices.Sort(found)
	return found
}

// validationInputTypesInSource is every validation input type this package's own source declares.
//
// DERIVED SO THAT A THIRD DOOR CANNOT ARRIVE WITHOUT A CORPUS, and so that the gate cannot be
// pointed at one door and left there. This file used to measure CommitValidationInput and nothing
// else while ProposalValidationInput -- the door that reads the group id, the ciphersuite, the
// version and the clock -- had no corpus at all, and nothing anywhere said so.
func validationInputTypesInSource(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read this package's own directory: %v", err)
	}
	fileSet := token.NewFileSet()
	found := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, declared := range file.Decls {
			general, isGeneral := declared.(*ast.GenDecl)
			if !isGeneral || general.Tok != token.TYPE {
				continue
			}
			for _, spec := range general.Specs {
				typed, isTyped := spec.(*ast.TypeSpec)
				if !isTyped || !strings.HasSuffix(typed.Name.Name, "ValidationInput") {
					continue
				}
				if _, isStruct := typed.Type.(*ast.StructType); isStruct {
					found = append(found, typed.Name.Name)
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
	assertFixtureCorpusIsThePackages(t, "CommitValidationInput",
		slices.Sorted(maps.Keys(commitFixtureCorpus())))
}

// TestEveryProposalFixtureThisPackageDeclaresIsInTheCorpus is the same claim at the other door.
func TestEveryProposalFixtureThisPackageDeclaresIsInTheCorpus(t *testing.T) {
	assertFixtureCorpusIsThePackages(t, "ProposalValidationInput",
		slices.Sorted(maps.Keys(proposalFixtureCorpus())))
}

// assertFixtureCorpusIsThePackages is that claim written once.
func assertFixtureCorpusIsThePackages(t *testing.T, named string, held []string) {
	t.Helper()
	declared := validationFixtureBuildersInSource(t, named)
	if len(declared) == 0 {
		t.Fatalf("no function in this package's test files answers a *%s, so the derivation read something other than the package and the corpus is a list of names",
			named)
	}
	if !slices.Equal(declared, held) {
		t.Errorf("this package declares the %s fixtures %v and the corpus measures %v; a fixture with no row is one nothing holds to being able to separate a value from a constant, and a row naming a fixture the package no longer declares is a row measuring nothing",
			named, declared, held)
	}
}

// ---------------------------------------------------------------------------
// what a fixture is measured on
// ---------------------------------------------------------------------------

// corpusDimensionHops is how many STRUCT FIELDS deep a dimension is. See this file's header for
// why it is a bound at all and why it is this one.
const corpusDimensionHops = 2

// corpusRenderBudget bounds the canonical rendering below, which follows pointers and would
// otherwise be as deep as the value it is handed.
const corpusRenderBudget = 24

// corpusDimensionsOf answers every dimension one validation input carries, keyed by the PATH that
// reached it and holding the canonical rendering of what was there.
//
// WALKED RATHER THAN LISTED, which is this file's whole argument, and CARRYING NO TYPE, which is
// the correction this round made: the fields a fixture can be degenerate in are whatever fields
// exist, of whatever type, and a walk that names its types is blind to every dimension outside them.
//
// SLICES AGGREGATE UNDER ONE PATH -- "List[].Sender" and not "List[2].Sender" -- because the
// dimension is the FIELD and not the position. A corpus in which every list's second entry is sent
// from leaf 1 while its first varies is not degenerate in the sender; a corpus in which no entry
// anywhere carries a second value is. The slice ITSELF is also recorded, at its own path, so a
// vector that is nil in every fixture is caught rather than answered by its absent elements.
//
// A *RatchetTree IS RENDERED AS ITS TREE HASH. A tree carries a value for every member it has, so
// rendering one literally would make the group's own arithmetic the dimension; its hash is the one
// identity a ratchet tree has -- the value a GroupContext carries and a transcript covers -- and it
// changes if anything in the tree does. Nothing else is special cased and nothing at all is skipped.
func corpusDimensionsOf(crypto CryptoProvider, root any) map[string][]string {
	return corpusDimensionsFrom(crypto, root, "", 0)
}

// corpusDimensionsFrom is that walk started somewhere other than the root, which is what the
// accessor below needs: a value reached through a method rather than a field still sits at the
// depth its field sits at, and a walk that restarted the count there would demand separation one
// level deeper on that branch than on every other -- which is how the five proposal arms this
// profile refuses to populate came to be asked for.
func corpusDimensionsFrom(crypto CryptoProvider, root any, from string, at int) map[string][]string {
	out := map[string][]string{}
	record := func(path string, value string) {
		if path == "" {
			return
		}
		out[path] = append(out[path], value)
	}
	var walk func(value reflect.Value, path string, hops int)
	walk = func(value reflect.Value, path string, hops int) {
		if !value.IsValid() {
			record(path, "nil")
			return
		}
		record(path, corpusRenderOf(crypto, value, corpusRenderBudget))
		if hops >= corpusDimensionHops {
			return
		}
		switch value.Kind() {
		case reflect.Pointer, reflect.Interface:
			if !value.IsNil() {
				walk(value.Elem(), path, hops)
			}
		case reflect.Slice, reflect.Array:
			if value.Kind() == reflect.Slice && value.IsNil() {
				return
			}
			// an octet string is ONE dimension, recorded whole a moment ago. Walked byte
			// by byte it would answer a value per octet under "GroupId[]" and pass the
			// claim vacuously, which is the exact shape this gate exists to refuse
			if value.Type().Elem().Kind() == reflect.Uint8 {
				return
			}
			for i := 0; i < value.Len(); i += 1 {
				walk(value.Index(i), path+"[]", hops)
			}
		case reflect.Map:
			if value.IsNil() {
				return
			}
			iterator := value.MapRange()
			for iterator.Next() {
				walk(iterator.Key(), path+"{}key", hops)
				walk(iterator.Value(), path+"{}", hops)
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
				walk(value.Field(i), under, hops+1)
			}
		}
	}
	walk(reflect.ValueOf(root), from, at)
	return out
}

// corpusListDimensionsInto adds the commit order's own dimensions to a fixture's map.
//
// The order is behind an unexported field with one accessor, which is what makes a ProposalList
// hold ONE representation -- so it is walked through the accessor. The list itself is already
// recorded by the walk above, under "List"; this adds the per-entry paths beneath it, ENTERED AT
// THE DEPTH THE LIST SITS AT so that an entry's own fields are the same distance from the root as
// any other field's.
func corpusListDimensionsInto(crypto CryptoProvider, into map[string][]string, list *ProposalList) {
	if list == nil {
		return
	}
	order := list.All()
	for i := range order {
		for path, values := range corpusDimensionsFrom(crypto, order[i], corpusOrderPath, 1) {
			into[path] = append(into[path], values...)
		}
	}
}

// corpusOrderPath is the path this accessor writes its entries under, and it is a constant because
// the gate reads it back: a corpus whose lists carry entries and whose measurement holds no
// dimension beneath them is one where this call has been dropped, and dropping it would take the
// per-entry dimensions -- the sender the last round fought for among them -- with nothing else
// noticing. See the claim in assertCorpusSeparatesItsDimensions.
const corpusOrderPath = "List[]"

// corpusRenderOf is the canonical rendering of one value.
//
// IT NEVER PRINTS AN ADDRESS, which is why it is written out rather than left to %v. A pointer
// formatted by the fmt package prints where it points, which differs between two fixtures holding
// equal values and between two runs holding the same one -- so a dimension rendered that way is
// separated by construction and measures nothing. This follows pointers instead. It also reads
// UNEXPORTED fields, through the kind specific accessors reflect allows without Interface(), so a
// type whose whole state is unexported -- a ProposalCache, a crypto provider -- is a value this can
// tell two of apart rather than an opaque one every fixture shares.
func corpusRenderOf(crypto CryptoProvider, value reflect.Value, budget int) string {
	if !value.IsValid() {
		return "nil"
	}
	if budget <= 0 {
		return "..."
	}
	if tree, isTree := corpusTreeIdentity(crypto, value); isTree {
		return tree
	}
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		if value.IsNil() {
			return "nil"
		}
		return corpusRenderOf(crypto, value.Elem(), budget-1)
	case reflect.Bool:
		return strconv.FormatBool(value.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(value.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(value.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(value.Float(), 'g', -1, 64)
	case reflect.Complex64, reflect.Complex128:
		return fmt.Sprint(value.Complex())
	case reflect.String:
		return strconv.Quote(value.String())
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return "nil"
		}
		// an octet string is ONE value and not a value per byte, for the walk's own reason
		if value.Type().Elem().Kind() == reflect.Uint8 {
			raw := make([]byte, value.Len())
			for i := 0; i < value.Len(); i += 1 {
				raw[i] = byte(value.Index(i).Uint())
			}
			return hex.EncodeToString(raw)
		}
		parts := make([]string, 0, value.Len())
		for i := 0; i < value.Len(); i += 1 {
			parts = append(parts, corpusRenderOf(crypto, value.Index(i), budget-1))
		}
		return "[" + strings.Join(parts, " ") + "]"
	case reflect.Map:
		if value.IsNil() {
			return "nil"
		}
		// sorted, because map iteration order is randomised and an unsorted rendering would
		// separate a dimension from itself
		parts := make([]string, 0, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			parts = append(parts, corpusRenderOf(crypto, iterator.Key(), budget-1)+"="+
				corpusRenderOf(crypto, iterator.Value(), budget-1))
		}
		sort.Strings(parts)
		return "{" + strings.Join(parts, " ") + "}"
	case reflect.Struct:
		if value.Type() == reflect.TypeFor[time.Time]() && value.CanInterface() {
			// an instant, in one spelling, rather than the wall clock and monotonic halves
			// the struct keeps it in
			return value.Interface().(time.Time).UTC().Format(time.RFC3339Nano)
		}
		parts := make([]string, 0, value.NumField())
		for i := 0; i < value.NumField(); i += 1 {
			parts = append(parts, value.Type().Field(i).Name+":"+
				corpusRenderOf(crypto, value.Field(i), budget-1))
		}
		return "{" + strings.Join(parts, " ") + "}"
	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		// a behaviour rather than a value: two of these are distinguishable by nothing a
		// fixture could vary on purpose
		if value.IsNil() {
			return "nil"
		}
		return "set:" + value.Type().String()
	}
	return "?" + value.Type().String()
}

// corpusTreeIdentity answers a ratchet tree's identity, and whether the value was one.
func corpusTreeIdentity(crypto CryptoProvider, value reflect.Value) (string, bool) {
	if value.Type() != reflect.TypeFor[*RatchetTree]() || !value.CanInterface() {
		return "", false
	}
	tree, isTree := value.Interface().(*RatchetTree)
	if !isTree || tree == nil {
		return "nil", true
	}
	hash, err := tree.TreeHash(crypto)
	if err != nil {
		return "unhashable:" + err.Error(), true
	}
	return "tree:" + hex.EncodeToString(hash), true
}

// corpusLeafIndicesOf answers every LeafIndex a value carries, at any depth.
//
// UNBOUNDED, unlike the dimension walk, and that is the one thing this adds to it. The octet claim
// below is about the WIDEST leaf index anywhere in the corpus, so it has to see the ones a
// proposal's own body carries; a leaf index deeper than corpusDimensionHops is folded into an
// ancestor's rendering for the purpose of the constancy claim, which is the right answer there and
// the wrong one here.
//
// A tree is skipped, because a tree carries a leaf index for every member it has and the claim is
// about what the INPUT names.
func corpusLeafIndicesOf(value any) []LeafIndex {
	found := []LeafIndex{}
	leafIndex := reflect.TypeFor[LeafIndex]()
	tree := reflect.TypeFor[*RatchetTree]()
	var walk func(value reflect.Value, depth int)
	walk = func(value reflect.Value, depth int) {
		// a bound rather than a visited set: nothing under a validation input is self
		// referential, and a bound cannot silently drop a path a pointer set would
		if depth > 12 || !value.IsValid() || value.Type() == tree {
			return
		}
		if value.Type() == leafIndex {
			found = append(found, LeafIndex(value.Uint()))
			return
		}
		switch value.Kind() {
		case reflect.Pointer, reflect.Interface:
			if !value.IsNil() {
				walk(value.Elem(), depth+1)
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < value.Len(); i += 1 {
				walk(value.Index(i), depth+1)
			}
		case reflect.Map:
			iterator := value.MapRange()
			for iterator.Next() {
				walk(iterator.Key(), depth+1)
				walk(iterator.Value(), depth+1)
			}
		case reflect.Struct:
			for i := 0; i < value.NumField(); i += 1 {
				if !value.Type().Field(i).IsExported() {
					continue
				}
				walk(value.Field(i), depth+1)
			}
		}
	}
	walk(reflect.ValueOf(value), 0)
	return found
}

// ---------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------

// corpusClockSeparation is how far from the wall clock a fixture's clock has to be before it
// separates the field from a call. A key package this package mints is valid for about ninety days,
// so anything inside that window decides every lifetime the same way whichever of the two is read.
const corpusClockSeparation = 365 * 24 * time.Hour

// corpusFixtureUnderTest is one built fixture reduced to what the claims below are stated over.
type corpusFixtureUnderTest struct {
	name       string
	dimensions map[string][]string
	leaves     []LeafIndex
	order      []CachedProposal
	now        time.Time
}

// fixtureCorporaUnderMeasurement is the corpus of every door, keyed by the validation input it is a
// corpus of, each reduced to what the claims are stated over.
//
// A REGISTRY AND NOT TWO TESTS, because "the gate is pointed at one door" is the defect this round
// was sent to close and two tests is exactly the shape it takes: deleting one of them is a silent
// weakening that nothing else notices. Here the set of keys is joined to the set of validation
// input types the package's own source declares, in both directions, so a door with no entry fails
// and an entry naming no door fails.
//
// EACH ANSWERS WHAT IT ATTEMPTED as well as what it built, so a corpus half of which failed its own
// preconditions reports that rather than quietly stating every claim below over the remainder.
func fixtureCorporaUnderMeasurement() map[string]func(*testing.T,
	CryptoProvider) ([]corpusFixtureUnderTest, int) {

	return map[string]func(*testing.T, CryptoProvider) ([]corpusFixtureUnderTest, int){
		"CommitValidationInput": func(t *testing.T,
			crypto CryptoProvider) ([]corpusFixtureUnderTest, int) {

			measured := measureCommitCorpus(t, crypto)
			return measured.fixtures, measured.expected
		},
		"ProposalValidationInput": func(t *testing.T,
			crypto CryptoProvider) ([]corpusFixtureUnderTest, int) {

			corpus := proposalFixtureCorpus()
			built := []corpusFixtureUnderTest{}
			for _, name := range slices.Sorted(maps.Keys(corpus)) {
				// EACH FIXTURE IS BUILT INSIDE ITS OWN SUBTEST, and that is not
				// tidiness. A builder answers t.Fatalf when its own precondition
				// stops holding, and a Fatalf in the middle of this loop takes the
				// whole test with it -- so the claims would report nothing about the
				// other fixtures, and the claim a corpus regression actually broke
				// would never be printed. One red row per fixture, and the
				// measurement carries on over the ones that built.
				var in *ProposalValidationInput
				t.Run(name, func(t *testing.T) { in = corpus[name].build(t, crypto) })
				if in == nil {
					continue
				}
				dimensions := corpusDimensionsOf(crypto, in)
				corpusListDimensionsInto(crypto, dimensions, in.List)
				built = append(built, corpusFixtureUnderTest{name: name,
					dimensions: dimensions, leaves: corpusLeafIndicesOf(in),
					order: in.List.All(), now: in.Now})
			}
			return built, len(corpus)
		},
	}
}

// commitCorpusMeasurement is the commit corpus built once and reduced to what the two claims over
// it read.
//
// ONE PASS FOR BOTH CLAIMS, and the reason is the derivation next door rather than the cost: a
// helper that answered a *CommitValidationInput would BE a fixture builder as far as
// validationFixtureBuildersInSource is concerned -- that walk is over the result type, which is the
// whole of what makes it unfoolable -- and the corpus would then owe itself a row. So the built
// inputs never leave this function.
type commitCorpusMeasurement struct {
	fixtures    []corpusFixtureUnderTest
	treesDiffer []string
	expected    int
}

// measureCommitCorpus builds every commit fixture, each INSIDE ITS OWN SUBTEST for the reason the
// proposal loop above gives, and reduces it.
func measureCommitCorpus(t *testing.T, crypto CryptoProvider) commitCorpusMeasurement {
	t.Helper()
	corpus := commitFixtureCorpus()
	measured := commitCorpusMeasurement{expected: len(corpus)}
	for _, name := range slices.Sorted(maps.Keys(corpus)) {
		var in *CommitValidationInput
		t.Run(name, func(t *testing.T) { in = corpus[name](t, crypto) })
		if in == nil {
			continue
		}
		dimensions := corpusDimensionsOf(crypto, in)
		corpusListDimensionsInto(crypto, dimensions, in.List)
		measured.fixtures = append(measured.fixtures, corpusFixtureUnderTest{name: name,
			dimensions: dimensions, leaves: corpusLeafIndicesOf(in),
			order: in.List.All(), now: in.Now})
		same, err := testTreesHashAlike(t, crypto, in.PreTree, in.PostTree)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !same {
			measured.treesDiffer = append(measured.treesDiffer, name)
		}
	}
	return measured
}

// assertCorpusSeparatesItsDimensions is the gate, written once and stated at both doors.
//
// FIVE CLAIMS, and the first is the class while the other four are shapes that class cannot see.
//
//	no dimension is one value across the corpus     -- the class itself
//	the widest leaf index does not fit in one octet -- a comparator truncated to its low octet
//	a commit order longer than one entry exists     -- a loop against a read of its head
//	one fixture's clock is not the wall clock       -- in.Now against a call to time.Now()
//	the commit order is measured at all             -- the accessor call being dropped
//
// THE LAST FOUR ARE NOT INSTANCES OF THE FIRST. A list's length is not a value at any path, the
// widest leaf index lives below the hop bound, and a corpus whose clocks are eleven distinct calls
// to time.Now() separates the Now dimension while leaving the field and the call the same program.
// Each is named with the mutation it exists to make fail, which is what the first claim gives every
// other dimension for free.
func assertCorpusSeparatesItsDimensions(t *testing.T, label string, expected int,
	fixtures []corpusFixtureUnderTest) {

	t.Helper()
	if len(fixtures) < expected {
		t.Errorf("%d of the %d fixtures in the %s corpus could not be built, so the claims below are stated over the rest of it",
			expected-len(fixtures), expected, label)
	}
	if len(fixtures) == 0 {
		t.Fatalf("the %s corpus is empty, so every claim below holds vacuously", label)
	}

	dimensions := map[string]map[string][]string{}
	lengths := map[int][]string{}
	widest, widestIn := LeafIndex(0), ""
	offTheWallClock := []string{}
	carriesEntries := false
	for _, fixture := range fixtures {
		for path, values := range fixture.dimensions {
			if dimensions[path] == nil {
				dimensions[path] = map[string][]string{}
			}
			for _, value := range values {
				dimensions[path][value] = append(dimensions[path][value], fixture.name)
			}
		}
		for _, at := range fixture.leaves {
			if at > widest {
				widest, widestIn = at, fixture.name
			}
		}
		lengths[len(fixture.order)] = append(lengths[len(fixture.order)], fixture.name)
		carriesEntries = carriesEntries || len(fixture.order) > 0
		if time.Since(fixture.now).Abs() > corpusClockSeparation {
			offTheWallClock = append(offTheWallClock, fixture.name)
		}
	}

	if len(dimensions) == 0 {
		t.Fatalf("the walk found no dimension anywhere in the %s corpus, so it read something other than these inputs",
			label)
	}
	for _, path := range slices.Sorted(maps.Keys(dimensions)) {
		if len(dimensions[path]) > 1 {
			continue
		}
		only := slices.Sorted(maps.Keys(dimensions[path]))[0]
		if len(only) > 160 {
			only = only[:160] + "..."
		}
		t.Errorf("every fixture in the %s corpus carries %s = %s, so that field and that constant are the same program and no test here can tell a rule reading the field from a rule reading the constant. Give one fixture a different value for it",
			label, path, only)
	}
	t.Logf("%s: %d fixtures, %d dimensions, widest leaf index %d (in %s), commit orders of %v, %d fixture(s) off the wall clock",
		label, len(fixtures), len(dimensions), widest, widestIn,
		slices.Sorted(maps.Keys(lengths)), len(offTheWallClock))

	// the narrowest integer width there is, which is what a truncated comparator collapses to
	if octet := LeafIndex(math.MaxUint8); widest <= octet {
		t.Errorf("the widest leaf index in the %s corpus is %d and one octet holds %d, so a comparison of leaf indices one octet wide is exact over every input here. Measured: the join's Sender comparator truncated to its low octet left the whole suite green",
			label, widest, octet)
	}
	if !slices.ContainsFunc(slices.Sorted(maps.Keys(lengths)), func(at int) bool { return at > 1 }) {
		t.Errorf("no fixture in the %s corpus carries more than one proposal -- the lengths are %v -- so a loop over the commit order and a read of its head answer alike, which is the shape four bypasses of the commit door took",
			label, slices.Sorted(maps.Keys(lengths)))
	}
	measuresEntries := false
	for path := range dimensions {
		measuresEntries = measuresEntries || strings.HasPrefix(path, corpusOrderPath)
	}
	if carriesEntries && !measuresEntries {
		t.Errorf("fixtures in the %s corpus carry proposals and the measurement holds no dimension beneath %s, so the commit order is reached by nothing here. Its entries are behind an unexported field with one accessor, so losing that call loses every per-entry dimension -- the sender among them -- and no other claim would notice",
			label, corpusOrderPath)
	}
	if len(offTheWallClock) == 0 {
		t.Errorf("every fixture in the %s corpus carries a clock within %s of now, so in.Now and a call to time.Now() answer every lifetime alike and the field is the call. Give one fixture a clock a lifetime is decided differently under",
			label, corpusClockSeparation)
	}
}

// TestEveryValidationInputCorpusSeparatesEveryDimensionItDecidesOff is the gate the four rounds
// needed, stated over every door this package has rather than over the one it was first written
// for.
func TestEveryValidationInputCorpusSeparatesEveryDimensionItDecidesOff(t *testing.T) {
	crypto := testCrypto(t)
	declared := validationInputTypesInSource(t)
	if len(declared) < 2 {
		t.Fatalf("this package's source declares %v validation input types; the derivation read something other than the package, and a gate that measures one door is what this round was sent to close",
			declared)
	}
	corpora := fixtureCorporaUnderMeasurement()
	for _, name := range declared {
		measure, measured := corpora[name]
		if !measured {
			t.Errorf("this package declares %s and no corpus in this file measures one, so every field of that input is a field nothing holds to being separable from a constant",
				name)
			continue
		}
		fixtures, expected := measure(t, crypto)
		assertCorpusSeparatesItsDimensions(t, name, expected, fixtures)
	}
	for _, name := range slices.Sorted(maps.Keys(corpora)) {
		if !slices.Contains(declared, name) {
			t.Errorf("this file measures a corpus of %s and this package declares no such type", name)
		}
	}
}

// TestTheCommitCorpusIsJudgedBetweenTwoTreesThatDiffer is the one claim only the commit door can
// make: a commit is judged BETWEEN two trees, and a corpus in which those two always agree is one
// where a rule stated over either answers the same thing.
func TestTheCommitCorpusIsJudgedBetweenTwoTreesThatDiffer(t *testing.T) {
	crypto := testCrypto(t)
	if len(measureCommitCorpus(t, crypto).treesDiffer) == 0 {
		t.Errorf("every fixture in this corpus hands PostTree a tree that hashes the same as PreTree, so a rule stated over either answers the same thing and the two fields are one. Measured: three tree reads of validate_commit.go could be swapped with the whole suite green")
	}
}

// TestEveryProposalFixtureIsJudgedTheWayItsRowSays drives the corpus through the door it is a
// corpus for.
//
// SEPARATING A DIMENSION DOES NOT BY ITSELF MAKE ANY TEST NOTICE IT. The gate above measures
// fixtures and calls no door; the five reads this round was sent to close are all inside
// ValidateProposalList, and each becomes decidable only when some test drives an input whose value
// differs from the constant AND asserts what comes back. This is that test, and the corpus is
// exactly the set of inputs it is stated over -- so a fixture added to separate a dimension is also
// a fixture the door is held to, and a fixture that quietly stops being accepted is a failure here
// rather than a silent weakening of the corpus.
func TestEveryProposalFixtureIsJudgedTheWayItsRowSays(t *testing.T) {
	crypto := testCrypto(t)
	corpus := proposalFixtureCorpus()
	for _, name := range slices.Sorted(maps.Keys(corpus)) {
		row := corpus[name]
		t.Run(name, func(t *testing.T) {
			in := row.build(t, crypto)
			failure := ValidateProposalList(in)
			switch {
			case row.refuses == nil && failure != nil:
				t.Fatalf("ValidateProposalList refused this fixture: %v. A fixture no door accepts measures nothing about the doors; if the refusal is correct the row owes a sentinel, and if it is not the fixture is wrong",
					failure)
			case row.refuses != nil && failure == nil:
				t.Fatalf("ValidateProposalList accepted this fixture and its row says it must answer %v",
					row.refuses)
			case row.refuses != nil && !errors.Is(failure, row.refuses):
				t.Fatalf("ValidateProposalList answered %v and this fixture's row says %v; a fixture refused for another reason is one that no longer reaches the rule it was built for",
					failure, row.refuses)
			}
		})
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
