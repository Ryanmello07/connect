// The gate over RFC 9420 section 12.4's path-required rule, at the entry point the commit
// lifecycle asks it through.
package mls

import (
	"bytes"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect/mls/syntax"
)

// TestCommitPathRequiredRules is the plan's four cases, plus the two the plan's four cannot see.
//
// The plan states the rule with one path-required proposal in each list and with that proposal at
// index 0 in three of the four. A rule that answered `proposalTypePathRequired(All[0])` passes all
// four of them, because the one case whose offender is not at index zero -- an add followed by an
// update -- is the case the plan happens to write second. That is the p4 ValSem401 shape this
// package has shipped four times, so the offender is walked to the LAST index of a longer list
// here rather than left where a hand written fixture put it.
func TestCommitPathRequiredRules(t *testing.T) {
	empty := &ProposalList{}
	if !CommitPathRequired(empty) {
		t.Fatal("an empty proposal list requires a path")
	}

	addOnly := NewProposalList([]CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
	})
	if CommitPathRequired(addOnly) {
		t.Fatal("an add-only list does not require a path")
	}

	withUpdate := NewProposalList([]CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeUpdate}},
	})
	if !CommitPathRequired(withUpdate) {
		t.Fatal("a list containing an update requires a path")
	}

	withGce := NewProposalList([]CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeGroupContextExtensions}},
	})
	if !CommitPathRequired(withGce) {
		t.Fatal("group_context_extensions is in the RFC 9420 section 12.4 pathRequiredTypes list")
	}

	// the case the plan's four do not hold: the only path-required entry sits at the END of a
	// list of four, behind three that are not.
	trailing := NewProposalList([]CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeRemove}},
	})
	if !CommitPathRequired(trailing) {
		t.Fatal("a remove at the last index of a four entry list requires a path; the rule is over every entry and not over the first")
	}

	// a list with no path-required entry ANYWHERE is the other half of that: a rule that
	// answered true for any non-empty list would pass every case above.
	if CommitPathRequired(NewProposalList([]CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
	})) {
		t.Fatal("four adds require no path")
	}
}

// TestCommitPathRequiredIsThePathRequiredTypeSetOverTheWholeRegistry holds the entry point to the
// RFC's type set rather than to a list written here.
//
// The class is this package's own ProposalType constants, read out of the source, so a ninth code
// point registered later is swept on the commit that declares it. What is asserted is that a
// singleton list of each type agrees with proposalTypePathRequired -- which is where section
// 12.4's four names are transcribed -- so a CommitPathRequired that quietly consulted some other
// set fails here rather than at whichever type the fixtures above happen not to use.
func TestCommitPathRequiredIsThePathRequiredTypeSetOverTheWholeRegistry(t *testing.T) {
	declared := registryConstantsOfType(t, "ProposalType")
	if len(declared) == 0 {
		t.Fatal("this package declares no ProposalType constant, so the sweep below reads nothing")
	}
	agreed := 0
	required := 0
	for _, name := range slices.Sorted(maps.Keys(declared)) {
		proposalType := ProposalType(declared[name])
		list := NewProposalList([]CachedProposal{{Proposal: Proposal{ProposalType: proposalType}}})
		want := proposalTypePathRequired(proposalType)
		if got := CommitPathRequired(list); got != want {
			t.Errorf("CommitPathRequired over a list of one %s = %v, and proposalTypePathRequired says %v",
				name, got, want)
			continue
		}
		agreed += 1
		if want {
			required += 1
		}
	}
	// both halves have to be non empty or the sweep is satisfied by a constant answer
	if required == 0 || agreed-required == 0 {
		t.Fatalf("the registry sweep saw %d agreeing types of which %d require a path; a sweep whose expectation is the same for every member states nothing",
			agreed, required)
	}
	t.Logf("%d registered proposal types swept, %d of them path-required", agreed, required)
}

// TestCommitPathRequiredAnswersTrueForANilList states the fail-closed direction.
//
// A nil list reaches this from a caller that has not resolved a commit's ProposalOrRef vector
// yet, and the answer that costs nothing is "a path is required": section 12.4's empty clause
// already says a commit naming no proposals must carry one. The other answer is a validator that
// lets a pathless commit through because its caller forgot an argument.
func TestCommitPathRequiredAnswersTrueForANilList(t *testing.T) {
	if !CommitPathRequired(nil) {
		t.Fatal("CommitPathRequired(nil) = false; a caller that handed over no list is asking about a commit that names no proposals, and section 12.4 requires a path for one of those")
	}
}

// TestCommitCodecIsTheFramingPlans is the plan's own assertion that this task declares no codec:
// the commit bytes are load bearing for the confirmed transcript hash, so the round trip is
// asserted through the single byte-level entry points rather than through anything here.
//
// commit_wire_test.go holds the same three properties over its own fixtures. This is kept because
// it is the assertion this file makes about OWNERSHIP -- that syntax.Marshal of a Commit built
// here is the framing plan's encoding and not a second one -- and because a task that added a
// codec beside the rule would pass every test in that file.
func TestCommitCodecIsTheFramingPlans(t *testing.T) {
	commit := &Commit{Proposals: []ProposalOrRef{{
		Type:     ProposalOrRefTypeProposal,
		Proposal: &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}},
	}}}
	encoded, err := syntax.Marshal(commit)
	if err != nil {
		t.Fatalf("syntax.Marshal: %v", err)
	}
	if encoded[len(encoded)-1] != 0x00 {
		t.Fatalf("absent path must encode as the 0x00 optional presence byte, got %#x", encoded[len(encoded)-1])
	}
	var parsed Commit
	if err := syntax.Unmarshal(encoded, &parsed); err != nil {
		t.Fatalf("syntax.Unmarshal: %v", err)
	}
	if parsed.Path != nil {
		t.Fatal("Path must be nil when the presence byte is 0")
	}
	reencoded, err := syntax.Marshal(&parsed)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatal("re-encode is not byte identical")
	}

	// 0x02 is not a legal optional presence byte: two encodings of "absent" would be a
	// signature-bypass primitive.
	mutated := append([]byte(nil), encoded...)
	mutated[len(mutated)-1] = 0x02
	if err := syntax.Unmarshal(mutated, &parsed); err == nil {
		t.Fatal("syntax.Unmarshal accepted presence byte 0x02")
	}
	if err := syntax.Unmarshal(append(encoded, 0xFF), &parsed); !errors.Is(err, syntax.ErrTrailingBytes) {
		t.Fatalf("syntax.Unmarshal with a trailing byte = %v, want ErrTrailingBytes", err)
	}
}

// ---------------------------------------------------------------------------
// RFC 9420 section 12.4.1: commit generation
// ---------------------------------------------------------------------------

// stagedForTest exposes the staged commit to tests in this package, and hasPathForTest exposes the
// path decision.
//
// Both live in _test.go rather than beside the code they read, which is pendingProposalsForTest's
// placement one file over and is the same rule framing_group_seams_test.go states for the two
// construction bypass seams: the go tool compiles a _test.go file into `go test`'s binary and into
// nothing else, so a production caller of either does not build at all.
func (self *Group) stagedForTest() *StagedCommit {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pending
}

func (self *StagedCommit) hasPathForTest() bool { return self.hasPath }

// commitTestGroupOfTwo answers a group at epoch 1 holding its owner at leaf 0 and one more member
// at leaf 1, together with both identities.
//
// A REAL COMMIT AND NOT A SPLICED LEAF, which matters for every assertion built on it: a leaf
// pushed straight into the ratchet tree leaves the group context's tree hash naming a tree that no
// longer exists, and every rule below that reads a context against a tree would then be reading a
// group this package could not have produced. The second member cannot process anything -- its
// Welcome is task 15's -- and nothing here asks it to.
func commitTestGroupOfTwo(t *testing.T, crypto CryptoProvider) (*Group, *testMember, *testMember) {
	t.Helper()
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "commit-group")
	other := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, other)
	if _, err := group.CreateCommit(nil,
		[]Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}}, nil); err != nil {
		t.Fatalf("commit the add this fixture is built on: %v", err)
	}
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("merge the add this fixture is built on: %v", err)
	}
	if len(group.Members()) != 2 {
		t.Fatalf("the fixture group holds %d member(s), want 2", len(group.Members()))
	}
	return group, owner, other
}

// commitTestCacheProposal frames, signs and caches one proposal as the member at leaf `at` would
// have sent it, and answers the serialized ProposalRef a commit names it by.
//
// It goes through (*ProposalCache).Store rather than writing the map, because the reference a
// commit names is a hash over the framed, signed content and Store is what computes it: an entry
// filed under anything else is one no commit of this group could name.
func commitTestCacheProposal(t *testing.T, group *Group, m *testMember, at LeafIndex,
	proposal *Proposal) []byte {

	t.Helper()
	context, err := group.GroupContext()
	if err != nil {
		t.Fatalf("the group context this proposal is signed against: %v", err)
	}
	content := &FramedContent{
		GroupId:     group.GroupId(),
		Epoch:       group.Epoch(),
		Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: at},
		ContentType: ContentTypeProposal,
		Proposal:    proposal,
	}
	authenticated, err := SignAuthenticatedContent(group.crypto, m.SigPriv,
		WireFormatPrivateMessage, content, context)
	if err != nil {
		t.Fatalf("sign the proposal this test caches: %v", err)
	}
	ref, err := group.proposals.Store(group.crypto, group.context, authenticated)
	if err != nil {
		t.Fatalf("cache the proposal this test names: %v", err)
	}
	return bytes.Clone(ref)
}

// commitWireSnapshot is everything needed to open a message this group is about to seal, captured
// before the seal.
//
// The encryption secret rather than the group's own secret tree, and that is what makes this work
// at all: the seal consumes a generation of the sender's ratchet, so the live tree can no longer
// answer the key that message was sealed under. A tree rebuilt from the epoch's encryption secret
// starts where the sender started and ratchets to whatever generation the header names, which is
// exactly what a receiver does.
type commitWireSnapshot struct {
	crypto     CryptoProvider
	encryption []byte
	senderData []byte
	leafWidth  LeafCount
	context    []byte
	resolve    SignatureKeyResolver
}

func commitTestSnapshot(t *testing.T, group *Group) commitWireSnapshot {
	t.Helper()
	context, err := group.GroupContext()
	if err != nil {
		t.Fatalf("the group context this message is sealed under: %v", err)
	}
	tree := group.tree
	return commitWireSnapshot{
		crypto:     group.crypto,
		encryption: bytes.Clone(group.schedule.Secrets().Encryption),
		senderData: bytes.Clone(group.schedule.Secrets().SenderData),
		leafWidth:  group.tree.LeafWidth(),
		context:    context,
		resolve: func(sender Sender) (SignaturePublicKey, error) {
			leaf := tree.Leaf(sender.LeafIndex)
			if leaf == nil {
				return nil, errors.New("the sender occupies no leaf of this tree")
			}
			return leaf.SignatureKey, nil
		},
	}
}

// open reads the message off the wire the way a peer would: parse, open under the epoch's own
// keys, and verify the sender's signature against the tree.
func (self commitWireSnapshot) open(t *testing.T, encoded []byte) *AuthenticatedContent {
	t.Helper()
	message, err := ParseMLSMessage(encoded)
	if err != nil {
		t.Fatalf("the commit does not parse as an MLSMessage: %v", err)
	}
	if message.WireFormat != WireFormatPrivateMessage || message.PrivateMessage == nil {
		t.Fatalf("the commit is wire format %d with private arm %v; a handshake message travels as a PrivateMessage",
			message.WireFormat, message.PrivateMessage)
	}
	keys, err := NewSecretTree(self.crypto, self.leafWidth, self.encryption)
	if err != nil {
		t.Fatalf("rebuild the epoch's secret tree: %v", err)
	}
	authenticated, err := OpenPrivateMessage(self.crypto, keys, self.senderData,
		message.PrivateMessage, self.resolve, self.context)
	if err != nil {
		t.Fatalf("open the commit this group sealed: %v", err)
	}
	return authenticated
}

// TestCommitStagesTheEpochItOpensRatherThanEnteringIt is the lifecycle claim: a commit is built,
// the group stays where it was, and the merge is what moves it.
//
// The epoch the committer is in is the epoch every receiver is still in, and the delivery service
// accepts at most one commit per (group, epoch) -- so a committer that advanced here would have
// forked itself off the group the moment somebody else's commit won that race.
func TestCommitStagesTheEpochItOpensRatherThanEnteringIt(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, bob)
	encoded, err := syntax.Marshal(kp)
	if err != nil {
		t.Fatalf("marshal key package: %v", err)
	}
	if _, err := group.ProposeAdd(encoded); err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}

	before := group.EpochAuthenticator()
	result, err := group.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if len(result.Commit) == 0 {
		t.Fatal("Commit returned no commit message")
	}
	if len(result.RatchetTree) == 0 {
		t.Fatal("Commit must return the post-commit tree for out-of-band delivery")
	}
	if group.Epoch() != 0 {
		t.Fatalf("Epoch = %d after Commit; a commit stages and the epoch advances at MergePendingCommit",
			group.Epoch())
	}
	if len(group.Members()) != 1 {
		t.Fatalf("Members = %d before the merge, want 1", len(group.Members()))
	}
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	if group.Epoch() != 1 {
		t.Fatalf("Epoch = %d, want 1 after merge", group.Epoch())
	}
	if bytes.Equal(before, group.EpochAuthenticator()) {
		t.Fatal("the epoch authenticator did not change across the commit")
	}
	if len(group.Members()) != 2 {
		t.Fatalf("Members = %d, want 2", len(group.Members()))
	}
	if group.stagedForTest() != nil {
		t.Fatal("the merge left the commit staged, so a second merge would re-enter the epoch")
	}
	if err := group.MergePendingCommit(); !errors.Is(err, ErrNoPendingCommit) {
		t.Fatalf("a second MergePendingCommit = %v, want ErrNoPendingCommit", err)
	}
	// the tree this commit published is the tree the group now holds, which is what an
	// out-of-band joiner is handed
	live, err := group.RatchetTree()
	if err != nil {
		t.Fatalf("RatchetTree: %v", err)
	}
	if !bytes.Equal(live, result.RatchetTree) {
		t.Fatal("the tree the commit published is not the tree the merge installed")
	}
}

// TestACommitCoveringAnAddCarriesNoWelcomeUntilTask15 is an expiry-by-failure assertion and not a
// property this build wants.
//
// buildWelcomeLocked answers nil, so a member this commit adds has a leaf in the published tree and
// no way to reach the epoch. That is a hole, it is task 15's, and this is what makes it impossible
// to forget: the moment the Welcome is built this test FAILS, and the repair is to replace it with
// the assertion the plan's task 15 writes.
func TestACommitCoveringAnAddCarriesNoWelcomeUntilTask15(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, bob)
	result, err := group.CreateCommit(nil,
		[]Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}}, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if len(result.Commit) == 0 {
		t.Fatal("the commit itself is empty, so this test observed nothing")
	}
	if result.Welcome != nil {
		t.Fatal("a commit covering an Add now answers a Welcome; task 15 has landed, so delete this test and assert what the Welcome carries")
	}
	if staged := group.stagedForTest(); staged == nil || len(staged.AddedLeaves()) != 1 {
		t.Fatal("the commit did not stage an add, so the assertion above is about the wrong shape")
	}
}

// TestCommitWithNoProposalsCarriesAPath is RFC 9420 section 12.4's empty clause.
//
// A commit that names no proposals must carry a path, because the whole of what it does is re-key:
// without one the epoch advances over key material every member of the previous epoch still holds.
func TestCommitWithNoProposalsCarriesAPath(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	result, err := group.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if result.Welcome != nil {
		t.Fatal("a commit that adds nobody must not produce a Welcome")
	}
	staged := group.stagedForTest()
	if staged == nil {
		t.Fatal("no staged commit")
	}
	if !staged.hasPathForTest() {
		t.Fatal("an empty proposal list requires a path: RFC 9420 section 12.4")
	}
	if staged.commit.Path == nil {
		t.Fatal("the commit this group staged carries no path, whatever the decision recorded beside it says")
	}
}

// TestCommitAddOnlyOmitsThePathByDefault is the other half of section 12.4's rule: an add-only
// commit MAY omit the path, and this build does.
func TestCommitAddOnlyOmitsThePathByDefault(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, bob)
	if _, err := group.CreateCommit(nil,
		[]Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}}, nil); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	staged := group.stagedForTest()
	if staged.hasPathForTest() || staged.commit.Path != nil {
		t.Fatal("an add-only commit may omit the path, and this build omits it")
	}
}

// TestCommitForceBuildsAPathForAnAddOnlyList is CommitOptions.Force, which is the committer buying
// post compromise security for itself over a list that does not demand it.
func TestCommitForceBuildsAPathForAnAddOnlyList(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, bob)
	if _, err := group.CreateCommit(nil,
		[]Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}},
		&CommitOptions{Force: true}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	staged := group.stagedForTest()
	if !staged.hasPathForTest() || staged.commit.Path == nil {
		t.Fatal("CommitOptions.Force must populate the path")
	}
	// and the leaf that path publishes is a fresh one, which is the whole of what Force buys
	own := group.OwnLeafNodeCopy()
	if bytes.Equal(own.EncryptionKey, staged.commit.Path.LeafNode.EncryptionKey) {
		t.Fatal("the forced path republished the committer's current leaf key, so it re-keyed nothing")
	}
}

// TestCommitRefusesASecondPendingCommit holds the one-staged-commit rule and the release from it.
func TestCommitRefusesASecondPendingCommit(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	if _, err := group.CreateCommit(nil, nil, nil); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	first := group.stagedForTest()
	if _, err := group.CreateCommit(nil, nil, nil); !errors.Is(err, ErrPendingCommitExists) {
		t.Fatalf("second Commit error = %v, want ErrPendingCommitExists", err)
	}
	if group.stagedForTest() != first {
		t.Fatal("the refused second commit replaced the staged one")
	}
	group.ClearPendingCommit()
	if group.stagedForTest() != nil {
		t.Fatal("ClearPendingCommit left a commit staged")
	}
	if _, err := group.CreateCommit(nil, nil, nil); err != nil {
		t.Fatalf("Commit after ClearPendingCommit: %v", err)
	}
	if group.stagedForTest() == first {
		t.Fatal("the commit built after the clear is the one that was cleared")
	}
}

// TestCommitRefusesItsOwnUpdateProposal is ValSem111 asked at generation time.
//
// nil byReference means "every cached proposal", which here is this member's own update: the rule
// is that a committer must not cover it, because its leaf is reset by the update path instead. A
// generator that silently DROPPED it would be a generator whose commit does not carry what the
// caller asked for, so the refusal is the property rather than the omission.
func TestCommitRefusesItsOwnUpdateProposal(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	if _, err := group.ProposeUpdate(); err != nil {
		t.Fatalf("ProposeUpdate: %v", err)
	}
	if _, err := group.CreateCommit(nil, nil, nil); !errors.Is(err, ErrSelfUpdateInCommit) {
		t.Fatalf("Commit error = %v, want ErrSelfUpdateInCommit", err)
	}
	if group.stagedForTest() != nil {
		t.Fatal("the refused commit was staged anyway")
	}
}

// TestCommitRefusesACommitThatWouldRemoveItsCommitter is ValSem200 asked at generation time.
//
// A commit that removes its own committer is one no receiver accepts, and the committer is the one
// party that cannot discover that from a peer: it would advance into an epoch whose tree has no
// leaf for it.
func TestCommitRefusesACommitThatWouldRemoveItsCommitter(t *testing.T) {
	crypto := testCrypto(t)
	group, _, _ := commitTestGroupOfTwo(t, crypto)
	defer group.Close()

	own := group.OwnLeafIndex()
	if _, err := group.CreateCommit(nil,
		[]Proposal{{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: own}}},
		nil); !errors.Is(err, ErrRemoveCommitter) {

		t.Fatalf("Commit removing leaf %d (the committer) = %v, want ErrRemoveCommitter",
			own, err)
	}
	if group.stagedForTest() != nil {
		t.Fatal("the refused commit was staged anyway")
	}
	// the same removal of the OTHER member is accepted, so the refusal above is about WHO is
	// removed rather than about removes
	if _, err := group.CreateCommit(nil,
		[]Proposal{{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: LeafIndex(1)}}},
		nil); err != nil {
		t.Fatalf("Commit removing the other member: %v", err)
	}
}

// commitShape is one commit this generator can emit, as the arguments (*Group).Commit is called
// with and whatever setup naming them takes.
type commitShape struct {
	name  string
	build func(t *testing.T, crypto CryptoProvider, group *Group, owner *testMember,
		other *testMember) ([][]byte, []Proposal, *CommitOptions)
}

// commitShapes is every shape (*Group).Commit can produce, in both the by-reference and the
// by-value arms and with and without a path.
func commitShapes() []commitShape {
	return []commitShape{
		{name: "empty list, which section 12.4 requires a path for",
			build: func(t *testing.T, crypto CryptoProvider, group *Group, owner *testMember,
				other *testMember) ([][]byte, []Proposal, *CommitOptions) {
				return [][]byte{}, nil, nil
			}},
		{name: "one add by value, path omitted",
			build: func(t *testing.T, crypto CryptoProvider, group *Group, owner *testMember,
				other *testMember) ([][]byte, []Proposal, *CommitOptions) {
				kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "carol"))
				return [][]byte{},
					[]Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}}, nil
			}},
		{name: "one add by value with a forced path",
			build: func(t *testing.T, crypto CryptoProvider, group *Group, owner *testMember,
				other *testMember) ([][]byte, []Proposal, *CommitOptions) {
				kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "carol"))
				return [][]byte{},
					[]Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}},
					&CommitOptions{Force: true}
			}},
		{name: "one add through ExtraProposals",
			build: func(t *testing.T, crypto CryptoProvider, group *Group, owner *testMember,
				other *testMember) ([][]byte, []Proposal, *CommitOptions) {
				kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "carol"))
				return [][]byte{}, nil, &CommitOptions{ExtraProposals: []Proposal{
					{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}}}
			}},
		{name: "one remove by reference, named explicitly",
			build: func(t *testing.T, crypto CryptoProvider, group *Group, owner *testMember,
				other *testMember) ([][]byte, []Proposal, *CommitOptions) {
				encoded, err := group.ProposeRemove(LeafIndex(1))
				if err != nil {
					t.Fatalf("ProposeRemove: %v", err)
				}
				if len(encoded) == 0 {
					t.Fatal("ProposeRemove put nothing on the wire")
				}
				return [][]byte{[]byte(group.proposals.Pending(group.context)[0].Reference)},
					nil, nil
			}},
		{name: "every cached proposal, which is what a nil byReference means",
			build: func(t *testing.T, crypto CryptoProvider, group *Group, owner *testMember,
				other *testMember) ([][]byte, []Proposal, *CommitOptions) {
				leaf, _ := testUpdateLeafNode(t, crypto, other, group.GroupId(), LeafIndex(1))
				commitTestCacheProposal(t, group, other, LeafIndex(1),
					&Proposal{ProposalType: ProposalTypeUpdate, Update: &Update{LeafNode: *leaf}})
				return nil, nil, nil
			}},
		{name: "another member's update by reference beside an add by value",
			build: func(t *testing.T, crypto CryptoProvider, group *Group, owner *testMember,
				other *testMember) ([][]byte, []Proposal, *CommitOptions) {
				leaf, _ := testUpdateLeafNode(t, crypto, other, group.GroupId(), LeafIndex(1))
				ref := commitTestCacheProposal(t, group, other, LeafIndex(1),
					&Proposal{ProposalType: ProposalTypeUpdate, Update: &Update{LeafNode: *leaf}})
				kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "carol"))
				return [][]byte{ref},
					[]Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}}, nil
			}},
		{name: "a group_context_extensions proposal by value",
			build: func(t *testing.T, crypto CryptoProvider, group *Group, owner *testMember,
				other *testMember) ([][]byte, []Proposal, *CommitOptions) {
				exts := testGroupContextOf(t, group).Extensions
				return [][]byte{}, []Proposal{{
					ProposalType:           ProposalTypeGroupContextExtensions,
					GroupContextExtensions: &GroupContextExtensions{Extensions: exts},
				}}, nil
			}},
	}
}

// TestEveryCommitThisGroupGeneratesPassesItsOwnValidateCommit is the counterpart of the commit
// VALIDATION this package already has, and it is the cheapest real check there is on a generator.
//
// A commit this build emits and this build refuses is a client publishing a message its own package
// will not process, and the refusal arrives at a PEER one epoch later with nothing at the point of
// the mistake to point at. The proposal generators had exactly that defect one task ago: ProposeAdd
// signed, sealed and cached an Add that ValidateProposalList refuses.
//
// EVERY INPUT TO THE DOOR IS REBUILT FROM THE WIRE, which is what keeps this from being the
// generator agreeing with itself. The commit is opened out of the sealed PrivateMessage, its
// ProposalOrRef vector is resolved against this member's own cache, the proposals are applied to a
// clone of the pre-commit tree, and the confirmed transcript hash is chained from the interim hash
// the group held BEFORE the call. Only the new epoch's confirmation KEY is taken from the staged
// commit, because deriving it needs the commit secret and the committer is the one party that
// cannot decrypt its own path -- and the key is not what these rules are about.
//
// THE GENERATOR'S OWN DOORS ARE SWITCHED OFF for the run, through skipValidation. With them on, a
// generator that emits a commit its own door refuses answers an error and this test reads a
// refusal; with them off, it emits the commit and this test judges what came out. The second is the
// question being asked.
func TestEveryCommitThisGroupGeneratesPassesItsOwnValidateCommit(t *testing.T) {
	for _, shape := range commitShapes() {
		t.Run(shape.name, func(t *testing.T) {
			crypto := testCrypto(t)
			group, owner, other := commitTestGroupOfTwo(t, crypto)
			defer group.Close()

			refs, byValue, opts := shape.build(t, crypto, group, owner, other)
			if opts == nil {
				opts = &CommitOptions{}
			}
			opts.skipValidation = true

			snapshot := commitTestSnapshot(t, group)
			preTree := group.tree.Clone()
			preContext := group.context.Clone()
			preInterim := bytes.Clone(group.transcript.Interim)
			preConfirmed := bytes.Clone(group.transcript.Confirmed)

			result, err := group.CreateCommit(refs, byValue, opts)
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}
			staged := group.stagedForTest()
			if staged == nil {
				t.Fatal("the commit staged nothing, so there is no epoch to judge")
			}

			authenticated := snapshot.open(t, result.Commit)
			if authenticated.Content.ContentType != ContentTypeCommit ||
				authenticated.Content.Commit == nil {
				t.Fatalf("the message on the wire carries content type %d and commit arm %v",
					authenticated.Content.ContentType, authenticated.Content.Commit)
			}
			wire := authenticated.Content.Commit
			committer := authenticated.Content.Sender.LeafIndex
			if committer != group.OwnLeafIndex() {
				t.Fatalf("the commit names leaf %d as its sender and this member is leaf %d",
					committer, group.OwnLeafIndex())
			}

			// what a receiver does with it: resolve the vector against its own cache, apply the
			// proposals to the tree the commit arrived in, and chain the transcript.
			list, err := group.proposals.Resolve(crypto, preContext, committer, wire.Proposals)
			if err != nil {
				t.Fatalf("the commit's own proposal vector does not resolve against this member's cache: %v", err)
			}
			applied, err := ApplyProposals(preTree, preContext, committer, list)
			if err != nil {
				t.Fatalf("the commit's own proposals do not apply to the tree it was built over: %v", err)
			}
			confirmedInput, err := authenticated.ConfirmedTranscriptHashInput()
			if err != nil {
				t.Fatalf("the confirmed transcript hash input: %v", err)
			}
			confirmedHash := ConfirmedTranscriptHash(crypto, preInterim, confirmedInput)
			if bytes.Equal(confirmedHash, preConfirmed) {
				t.Fatal("the confirmed transcript hash did not move across this commit, so the assertions below compare one epoch with itself")
			}

			in := &CommitValidationInput{
				Crypto:          crypto,
				PreTree:         preTree,
				PostTree:        applied.Tree,
				Context:         preContext,
				Extensions:      applied.Extensions,
				Committer:       committer,
				Own:             committer,
				List:            list,
				Commit:          wire,
				Pending:         group.proposals,
				ConfirmationKey: staged.schedule.Secrets().Confirmation,
				ConfirmedHash:   confirmedHash,
				ConfirmationTag: authenticated.Auth.ConfirmationTag,
				Now:             time.Now(),
			}
			if err := ValidateCommit(in); err != nil {
				t.Fatalf("this group emitted a commit its own ValidateCommit refuses: %v", err)
			}
			if err := ValSem205ConfirmationTag(in); err != nil {
				t.Fatalf("this group emitted a commit whose confirmation tag its own ValSem205 refuses: %v", err)
			}

			// and the epoch the committer staged is the epoch the commit describes
			if staged.Epoch() != preContext.Epoch+1 {
				t.Fatalf("the staged epoch is %d and the commit closes epoch %d",
					staged.Epoch(), preContext.Epoch)
			}
			if !bytes.Equal(staged.context.ConfirmedTranscriptHash, confirmedHash) {
				t.Fatalf("the staged context's confirmed transcript hash is %x and the wire chains to %x",
					staged.context.ConfirmedTranscriptHash, confirmedHash)
			}
			if !bytes.Equal(staged.transcript.Confirmed, confirmedHash) {
				t.Fatalf("the staged transcript's confirmed hash is %x and the wire chains to %x",
					staged.transcript.Confirmed, confirmedHash)
			}
			// the tree the committer keeps is the tree the published path builds
			if wire.Path != nil {
				commitTestPathBuildsTheStagedTree(t, crypto, staged, wire, committer)
			}
			stagedHash, err := staged.tree.TreeHash(crypto)
			if err != nil {
				t.Fatalf("the staged tree's hash: %v", err)
			}
			if !bytes.Equal(stagedHash, staged.context.TreeHash) {
				t.Fatal("the staged group context names a tree hash the staged tree does not have")
			}
		})
	}
}

// commitTestPathBuildsTheStagedTree holds the update path a commit PUBLISHES against the tree its
// committer keeps, position by position.
//
// A path is the only part of a commit that changes the tree without a proposal saying so, and the
// committer is the one member that never decrypts its own -- so a generator that published a path
// built over one tree while staging another would be a member whose epoch agrees with nobody, and
// nothing in a self consistent commit says which tree the path was for.
func commitTestPathBuildsTheStagedTree(t *testing.T, crypto CryptoProvider, staged *StagedCommit,
	wire *Commit, committer LeafIndex) {

	t.Helper()
	leaf := staged.tree.Leaf(committer)
	if leaf == nil {
		t.Fatal("the staged tree holds no leaf for the committer")
	}
	if !bytes.Equal(leaf.EncryptionKey, wire.Path.LeafNode.EncryptionKey) {
		t.Fatalf("the path publishes leaf key %x and the staged tree holds %x",
			wire.Path.LeafNode.EncryptionKey, leaf.EncryptionKey)
	}
	filtered, err := staged.tree.FilteredDirectPath(committer)
	if err != nil {
		t.Fatalf("the committer's filtered direct path: %v", err)
	}
	if len(filtered) != len(wire.Path.Nodes) {
		t.Fatalf("the path publishes %d node(s) and the staged tree's filtered direct path has %d",
			len(wire.Path.Nodes), len(filtered))
	}
	for i, x := range filtered {
		parent := staged.tree.ParentAt(x)
		if parent == nil {
			t.Fatalf("the staged tree holds no parent at node %d, which the path publishes a key for", x)
		}
		if !bytes.Equal(parent.EncryptionKey, wire.Path.Nodes[i].EncryptionKey) {
			t.Fatalf("path node %d publishes %x and the staged tree holds %x at node %d",
				i, wire.Path.Nodes[i].EncryptionKey, parent.EncryptionKey, x)
		}
	}
}

// TestTheCommitTagIsTakenOverTheTranscriptTheCommitItselfAdvances is RFC 9420 section 12.4.1's
// order, stated over the one value an implementation can get wrong while producing 32 well formed
// octets either way.
//
// The confirmation tag is a MAC over the confirmed transcript hash of the epoch the commit OPENS,
// and that hash is a function of this very commit -- so an implementation that took the tag before
// the transcript advanced would tag the epoch it is leaving. Both directions are stated: the tag
// verifies against the new hash and does NOT verify against the old one, because a rule that only
// asked the first would pass over a build where the two hashes are equal.
func TestTheCommitTagIsTakenOverTheTranscriptTheCommitItselfAdvances(t *testing.T) {
	crypto := testCrypto(t)
	group, _, _ := commitTestGroupOfTwo(t, crypto)
	defer group.Close()

	snapshot := commitTestSnapshot(t, group)
	preInterim := bytes.Clone(group.transcript.Interim)
	preConfirmed := bytes.Clone(group.transcript.Confirmed)

	result, err := group.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	staged := group.stagedForTest()
	authenticated := snapshot.open(t, result.Commit)
	confirmedInput, err := authenticated.ConfirmedTranscriptHashInput()
	if err != nil {
		t.Fatalf("the confirmed transcript hash input: %v", err)
	}
	confirmedHash := ConfirmedTranscriptHash(crypto, preInterim, confirmedInput)
	if bytes.Equal(confirmedHash, preConfirmed) {
		t.Fatal("the two transcript hashes this test tells apart are equal, so it tells nothing apart")
	}
	tag := authenticated.Auth.ConfirmationTag
	if len(tag) != crypto.HashSize() {
		t.Fatalf("the commit carries a %d octet confirmation tag, want %d", len(tag), crypto.HashSize())
	}
	if !staged.schedule.VerifyConfirmationTag(confirmedHash, tag) {
		t.Fatal("the confirmation tag on the wire is not the MAC over the confirmed transcript hash this commit advances to")
	}
	if staged.schedule.VerifyConfirmationTag(preConfirmed, tag) {
		t.Fatal("the confirmation tag on the wire is the MAC over the transcript hash of the epoch this commit CLOSES, so it was taken before the transcript advanced")
	}
	// and the seam that makes that mistake on purpose is refused by this package's own door,
	// which is what says the assertion above is the one ValSem205 asks. The seam alone does not
	// put a forged commit on the wire: a caller that wants one has to switch the generator's own
	// doors off as well, which is the right way round -- p8 asks for a bad tag deliberately and
	// nobody reaches one by accident.
	group.ClearPendingCommit()
	if _, err := group.CreateCommit(nil, nil,
		&CommitOptions{confirmationTagOverPreCommitTranscript: true}); !errors.Is(err, errBadConfirmationTag) {

		t.Fatalf("a commit whose tag is taken over the pre-commit transcript = %v, want errBadConfirmationTag from this package's own ValSem205",
			err)
	}
	if group.stagedForTest() != nil {
		t.Fatal("the refused commit was staged anyway")
	}
	// and with the doors off it is emitted, which is what makes the seam usable by p8
	forged, err := group.CreateCommit(nil, nil, &CommitOptions{
		confirmationTagOverPreCommitTranscript: true, skipValidation: true})
	if err != nil {
		t.Fatalf("the seam commit: %v", err)
	}
	if len(forged.Commit) == 0 {
		t.Fatal("the seam put nothing on the wire")
	}
}

// TestCommitDrawsItsPathSecretsAndItsLeafKeyFromTwoDrawsOfItsOwn is the entropy gate over the
// update path, written against what the commit PUBLISHES rather than against the lines that draw.
//
// Three defects it is built to see, each of which leaves the rest of this package green:
//
//  1. a draw replaced by a CONSTANT: the value the commit published is then not one of the draws
//     the provider was asked for, and the search below finds nothing.
//  2. the two draws COLLAPSED into one, so the committer's new leaf key pair is derived from the
//     same 32 octets as path_secret[0]. Everyone who opens the first ciphertext of the path then
//     holds the committer's leaf private key. Both values are still fresh per commit and both
//     still change with the entropy source, so no divergence test can see it; what sees it is the
//     two being found at the same INDEX.
//  3. a draw made and thrown away: every draw of KDF.Nh has to be accounted for by one of the two
//     the commit published.
//
// The path secret seed is recognised by what it DERIVES -- the commit secret it produces rebuilds
// this epoch's key schedule -- because no exported symbol of this package answers a path secret and
// guardrail 6 says none ever may.
func TestCommitDrawsItsPathSecretsAndItsLeafKeyFromTwoDrawsOfItsOwn(t *testing.T) {
	base := testCrypto(t)
	witness := &entropyWitness{CryptoProvider: base}
	group, _, _ := commitTestGroupOfTwo(t, witness)
	defer group.Close()

	before := len(witness.draws)
	beforeIkms := len(witness.ikms)
	if before == 0 || beforeIkms == 0 {
		t.Fatal("the fixture recorded no draws, so the exclusion below excludes nothing")
	}
	preInit := bytes.Clone(group.schedule.Secrets().InitSecret)
	if _, err := group.CreateCommit(nil, nil, nil); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	staged := group.stagedForTest()
	drawn := witness.draws[before:]
	derived := witness.ikms[beforeIkms:]
	if len(derived) == 0 {
		t.Fatal("the commit derived no key pair, so it published no path leaf")
	}

	// the leaf key pair, identified by re-deriving it from the draw it names
	leafDraw := -1
	for _, ikm := range derived {
		at := drawIndexOf(drawn, ikm)
		if at < 0 {
			continue
		}
		_, pub, err := base.DeriveKeyPair(drawn[at])
		if err != nil {
			t.Fatalf("re-derive a key pair this commit made: %v", err)
		}
		if bytes.Equal(pub, staged.commit.Path.LeafNode.EncryptionKey) {
			leafDraw = at
			break
		}
	}
	if leafDraw < 0 {
		t.Fatal("the update path's leaf key was derived from something this commit never drew")
	}

	// the path secret seed, identified by the commit secret it produces: the ladder's last rung
	// is commit_secret, and this epoch's key schedule is the only thing that recognises it
	nodes := len(staged.commit.Path.Nodes)
	seedDraw := -1
	for i, one := range drawn {
		if len(one) != base.HashSize() {
			continue
		}
		ladder := DerivePathSecrets(base, one, nodes)
		rebuilt, err := NewKeySchedule(base, preInit, ladder[len(ladder)-1],
			EmptyPskSecret(base), staged.context)
		if err != nil {
			t.Fatalf("rebuild the key schedule over draw %d: %v", i, err)
		}
		if bytes.Equal(rebuilt.Secrets().EpochAuthenticator, staged.EpochAuthenticator()) {
			if seedDraw >= 0 {
				t.Fatalf("draws %d and %d both rebuild this epoch, so one of them is not the path secret seed",
					seedDraw, i)
			}
			seedDraw = i
		}
		rebuilt.Zeroize()
	}
	if seedDraw < 0 {
		t.Fatal("no value this commit drew produces the commit secret this epoch was derived under; the path secret seed is not one of the draws")
	}
	if seedDraw == leafDraw {
		t.Fatalf("the update path's leaf key and its path secret ladder are both draw %d; a leaf key derived from path_secret[0] is the committer's leaf private key handed to its whole copath",
			leafDraw)
	}
	for i, one := range drawn {
		if i != seedDraw && i != leafDraw && len(one) == base.HashSize() {
			t.Errorf("draw %d is neither the path secret seed nor the leaf key material, and the commit published neither it nor anything derived from it; a draw nothing publishes is entropy this gate cannot follow",
				i)
		}
	}
}

// TestNothingACommitCarriesIsStorageItsCallerStillHolds is the aliasing rule over this method's own
// two argument shapes.
//
// NewGroup retained a live view over its caller's extension bodies and persist handed out the live
// group id, and both were found the same way. A commit is worse than either: what it keeps is the
// vector the confirmed transcript hash was taken over and the signature was made over, so a caller
// writing through its own array afterwards leaves this client holding a commit that no longer says
// what it signed -- with every signature still verifying at the moment it was made.
func TestNothingACommitCarriesIsStorageItsCallerStillHolds(t *testing.T) {
	crypto := testCrypto(t)
	group, _, other := commitTestGroupOfTwo(t, crypto)
	defer group.Close()

	leaf, _ := testUpdateLeafNode(t, crypto, other, group.GroupId(), LeafIndex(1))
	ref := commitTestCacheProposal(t, group, other, LeafIndex(1),
		&Proposal{ProposalType: ProposalTypeUpdate, Update: &Update{LeafNode: *leaf}})
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "carol"))
	byValue := []Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}}
	identity := byValue[0].Add.KeyPackage.LeafNode.Credential.Identity

	if _, err := group.CreateCommit([][]byte{ref}, byValue, nil); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	staged := group.stagedForTest()
	if len(staged.commit.Proposals) != 2 {
		t.Fatalf("the staged commit names %d proposal(s), want 2", len(staged.commit.Proposals))
	}
	named := bytes.Clone(staged.commit.Proposals[0].Reference)
	added := bytes.Clone(staged.commit.Proposals[1].Proposal.Add.KeyPackage.LeafNode.Credential.Identity)
	if len(named) == 0 || len(added) == 0 {
		t.Fatal("the staged commit carries no reference or no identity, so this test scribbled over nothing")
	}

	// the caller writes into the very arrays it handed in
	for i := range ref {
		ref[i] ^= 0xFF
	}
	for i := range identity {
		identity[i] ^= 0xFF
	}

	if !bytes.Equal(named, staged.commit.Proposals[0].Reference) {
		t.Fatalf("the caller's write moved the reference this commit names from %x to %x",
			named, staged.commit.Proposals[0].Reference)
	}
	after := staged.commit.Proposals[1].Proposal.Add.KeyPackage.LeafNode.Credential.Identity
	if !bytes.Equal(added, after) {
		t.Fatalf("the caller's write moved the identity this commit adds from %x to %x", added, after)
	}
}

// TestMergePendingCommitMovesTheProposalCacheToTheEpochItEntered is the epoch boundary's own
// obligation, read through what the cache does afterwards rather than through the call it makes.
//
// A cache left bound to the epoch that closed answers references to proposals the group has already
// applied, and one rebound to that same closing epoch is worse: Store then refuses every proposal of
// the new epoch, Pending answers nothing, and nothing in this package releases it -- so the member
// is wedged for good, by a boundary that looks like it did its job.
func TestMergePendingCommitMovesTheProposalCacheToTheEpochItEntered(t *testing.T) {
	crypto := testCrypto(t)
	group, _, _ := commitTestGroupOfTwo(t, crypto)
	defer group.Close()

	if _, err := group.ProposeRemove(LeafIndex(1)); err != nil {
		t.Fatalf("ProposeRemove: %v", err)
	}
	if len(group.pendingProposalsForTest()) != 1 {
		t.Fatal("the proposal this test commits was not cached")
	}
	if _, err := group.CreateCommit(nil, nil, nil); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	epoch := group.Epoch()
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	if group.Epoch() != epoch+1 {
		t.Fatalf("Epoch = %d after the merge, want %d", group.Epoch(), epoch+1)
	}
	// the closed epoch's entries are gone
	if held := group.pendingProposalsForTest(); len(held) != 0 {
		t.Fatalf("the merge left %d entry/entries of the closed epoch cached; every one of them names a proposal this commit has already applied",
			len(held))
	}
	// and the cache takes proposals of the epoch the group is NOW in, which a cache rebound to
	// the closing epoch would refuse
	if _, err := group.ProposeUpdate(); err != nil {
		t.Fatalf("the cache refuses a proposal of the epoch the group entered: %v", err)
	}
	if len(group.pendingProposalsForTest()) != 1 {
		t.Fatal("the proposal made in the new epoch was not cached, so the cache is bound to another epoch")
	}
	// and a commit built over it names that proposal, which is the whole point of the binding
	if _, err := group.CreateCommit(nil, nil, nil); !errors.Is(err, ErrSelfUpdateInCommit) {
		t.Fatal("the commit built after the merge did not even see this member's own update, so Pending answered nothing")
	}
}
