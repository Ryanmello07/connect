// The round trip: this plan's whole group lifecycle, run over many members and many epochs, with
// every member's view of every epoch compared against every other member's.
//
// WHY THIS FILE IS NOT A LONGER VERSION OF THE OTHERS. Every other file in this package holds one
// piece against its own definition. This one holds the pieces against EACH OTHER, and the four
// defects this package has actually shipped were all agreements rather than pieces: ProposeAdd
// cached an Add its own ValidateProposalList refuses; ApplyCommit accepted another group's staged
// commit and derived byte identical authenticators from it; a restored member restarted its ratchet
// at generation 0 and reused a nonce; the Welcome's joiner pairing was checked by a count its own
// comment ruled out. Not one of the four is visible from inside the piece that holds it, and every
// one of them is visible to a second member reading what the first produced.
//
// SO EVERY CASE HERE HAS THE SAME SHAPE: n views of one group, each a DIFFERENT *Group with its own
// StateStore, its own tree private state and its own key schedule, and the assertion is that all n
// answer one epoch authenticator. That value is DeriveSecret(epoch_secret, "authentication"), so an
// agreement on it is an agreement about the tree, the transcript and the key schedule together --
// a divergence in any one of the three is reported at the commit that caused it rather than at the
// first message somebody could not open. Membership is compared beside it, because two views can
// agree on an epoch secret while disagreeing about who is in the group only if one of them derived
// the secret over a tree it did not publish, and saying both is what tells those apart.
//
// FOUR MEMBERS IS THE FLOOR AND SEVERAL SIZES ARE RUN. four_member_group_test.go measures why: four
// is the smallest size at which EVERY member has a copath node above its own leaf, and at two the
// only node a commit is ever sealed to for a receiver is that receiver's own leaf -- so a whole
// class of structural defect is invisible under a two member fixture. The sizes above four are run
// because the property is the member's POSITION and not the group's size: at five, leaf 4 stands
// alone under the right subtree and behaves exactly as a member of two does, so "four or more" is
// a false way to state any of it.
//
// AND THE UNMERGED LEAF. four_member_group_test.go records, measured, that NO fixture in this
// package puts a member in a resolution reached through an unmerged leaf -- its groups settle, and
// a settled tree carries none. TestACommitReachesTheNewestMemberThroughAnUnmergedLeaf builds one,
// and it asserts the SHAPE off the tree before it sends anything, so a change that stopped
// producing an unmerged leaf makes that case fail rather than quietly turning it into another
// ordinary round trip.
package mls

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"
)

// ---------------------------------------------------------------------------
// the cohort
// ---------------------------------------------------------------------------

// testCohort is n views of ONE group that must stay in lockstep.
//
// It is not testSizedGroup with different field names. That fixture answers a SETTLED group and
// asserts its own invariant as it builds; this one is a live cohort a case drives -- members join,
// leave and are restored while it runs, and the assertions are the case's rather than the
// fixture's, so a case here reports the property it names instead of inheriting somebody else's.
//
// It carries the CONFIG of every member beside the group, for testSizedGroup's reason:
// testGroupConfig mints a fresh StateStore per call, so the only way to reach the states a member
// has persisted is to hold the config that member joined under, and a restore built from a second
// config for the same identity would be asking a store nothing has ever written to.
type testCohort struct {
	crypto  CryptoProvider
	groupId string
	groups  []*Group
	members []*testMember
	configs []*GroupConfig
}

// testNewCohort founds a group and admits size-1 members into it.
//
// The result is NOT settled: a group assembled out of Add commits alone has every parent of every
// added leaf blank, so every resolution walks down to the leaves and a group of n behaves like a
// group of two. A case that needs the tree's interior filled says so by committing from every
// member, which is what settle does below -- named rather than folded in here, because half the
// cases in this file are about what happens on the way to a settled tree.
func testNewCohort(t *testing.T, crypto CryptoProvider, groupId string, size int) *testCohort {
	t.Helper()
	if size < 1 {
		t.Fatalf("a cohort of %d members is not a group", size)
	}
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, groupId)
	group, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	self := &testCohort{
		crypto:  crypto,
		groupId: groupId,
		groups:  []*Group{group},
		members: []*testMember{owner},
		configs: []*GroupConfig{cfg},
	}
	for i := 1; i < size; i += 1 {
		self.addMember(t, group, testMemberName(i))
	}
	return self
}

// closeAll erases every epoch this cohort derived.
func (self *testCohort) closeAll() {
	for _, group := range self.groups {
		group.Close()
	}
}

// deliver hands one message to every view except the author's, applying it when it is a commit and
// merging the author's own last.
//
// THE AUTHOR MERGES AFTER EVERY RECEIVER HAS APPLIED, which is the order the delivery service
// imposes and not a convenience: a committer that merged first would be in the new epoch while the
// message it is about to send is sealed under the old one, and every case in this file that asserts
// an agreement would then be asserting it about a fixture that had already forked.
func (self *testCohort) deliver(t *testing.T, author *Group, message []byte, isCommit bool) {
	t.Helper()
	for _, group := range self.groups {
		if group == author {
			continue
		}
		processed, err := group.ProcessMessage(message)
		if err != nil {
			t.Fatalf("leaf %d could not process a message from leaf %d: %v",
				group.OwnLeafIndex(), author.OwnLeafIndex(), err)
		}
		if isCommit {
			if err := group.ApplyCommit(processed); err != nil {
				t.Fatalf("leaf %d could not apply the commit of leaf %d: %v",
					group.OwnLeafIndex(), author.OwnLeafIndex(), err)
			}
		}
	}
	if isCommit {
		if err := author.MergePendingCommit(); err != nil {
			t.Fatalf("MergePendingCommit at leaf %d: %v", author.OwnLeafIndex(), err)
		}
	}
}

// assertLockstep fails unless every view agrees on the epoch, on the epoch authenticator and on the
// membership.
//
// THE EPOCH AUTHENTICATOR IS THE STRONGEST ASSERTION THIS PLAN HAS. It is
// DeriveSecret(epoch_secret, "authentication"), so a match means the tree, the transcript and the
// key schedule all agree -- an agreement about a secret rather than about some public function of
// the tree, which a member that had reconstructed the tree wrongly could still reproduce.
//
// MEMBERSHIP IS COMPARED ELEMENTWISE AND NOT BY COUNT. A count is satisfied by two views that hold
// the same NUMBER of members at different leaves, which is exactly what an off-by-one in a
// resolution or an add placement produces, and it is the shape of a defect this package has already
// shipped once: the Welcome's joiner pairing was checked by a count its own comment ruled out.
func (self *testCohort) assertLockstep(t *testing.T) {
	t.Helper()
	first := self.groups[0]
	for at, group := range self.groups {
		if at == 0 {
			continue
		}
		if group.Epoch() != first.Epoch() {
			t.Fatalf("leaf %d is at epoch %d and leaf %d at %d",
				group.OwnLeafIndex(), group.Epoch(), first.OwnLeafIndex(), first.Epoch())
		}
		if !bytes.Equal(group.EpochAuthenticator(), first.EpochAuthenticator()) {
			t.Fatalf("leaf %d and leaf %d disagree on the epoch authenticator at epoch %d, so they are not in one epoch of one group",
				group.OwnLeafIndex(), first.OwnLeafIndex(), group.Epoch())
		}
		mine, theirs := group.Members(), first.Members()
		if len(mine) != len(theirs) {
			t.Fatalf("leaf %d holds %d members and leaf %d holds %d",
				group.OwnLeafIndex(), len(mine), first.OwnLeafIndex(), len(theirs))
		}
		for i := range mine {
			if mine[i].LeafIndex != theirs[i].LeafIndex {
				t.Fatalf("member %d is at leaf %d for leaf %d and at leaf %d for leaf %d",
					i, mine[i].LeafIndex, group.OwnLeafIndex(), theirs[i].LeafIndex, first.OwnLeafIndex())
			}
			if !bytes.Equal(mine[i].IdentityPub, theirs[i].IdentityPub) {
				t.Fatalf("leaf %d and leaf %d disagree about who holds leaf %d",
					group.OwnLeafIndex(), first.OwnLeafIndex(), mine[i].LeafIndex)
			}
		}
	}
}

// addMember admits one new identity, committed by the view the caller names, and joins it out of
// the Welcome that commit produced.
//
// The Add proposal is DELIVERED before it is committed, because a commit names its proposals by
// reference and every receiver resolves those references out of its own cache; a cohort that
// skipped the delivery would be asserting about a commit the other members cannot even read.
func (self *testCohort) addMember(t *testing.T, committer *Group, name string) *Group {
	t.Helper()
	member := testIdentity(t, self.crypto, name)
	kp, initPriv, encPriv, encoded := testPublishedKeyPackage(t, self.crypto, member)
	proposal, err := committer.ProposeAdd(encoded)
	if err != nil {
		t.Fatalf("ProposeAdd(%s): %v", name, err)
	}
	self.deliver(t, committer, proposal, false)
	result, err := committer.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateCommit adding %s: %v", name, err)
	}
	if result.Welcome == nil {
		t.Fatalf("the commit adding %s carried no Welcome", name)
	}
	self.deliver(t, committer, result.Commit, true)

	cfg := testGroupConfig(t, self.crypto, member, self.groupId)
	joined, err := JoinFromWelcome(cfg, result.Welcome, result.RatchetTree, &JoinKeyMaterial{
		KeyPackage: *kp, InitPrivate: initPriv, EncryptPrivate: encPriv, SignPrivate: member.SigPriv,
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome(%s): %v", name, err)
	}
	self.groups = append(self.groups, joined)
	self.members = append(self.members, member)
	self.configs = append(self.configs, cfg)
	return joined
}

// commitFrom builds a commit at one view, delivers it to every other and merges the committer's.
func (self *testCohort) commitFrom(t *testing.T, from int) *CommitResult {
	t.Helper()
	author := self.groups[from]
	result, err := author.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateCommit at leaf %d: %v", author.OwnLeafIndex(), err)
	}
	self.deliver(t, author, result.Commit, true)
	return result
}

// settle commits once from every member, in cohort order, so that every parent node of the tree
// carries a key somebody holds the private half of.
func (self *testCohort) settle(t *testing.T) {
	t.Helper()
	for from := range self.groups {
		self.commitFrom(t, from)
	}
}

// exchange has one member seal an application message and requires EVERY other member to open it.
//
// The AAD and the sender leaf are asserted beside the plaintext, because a receive path that opened
// the ciphertext under the wrong sender's ratchet, or that dropped the authenticated data on the
// way through the framing layer, answers the right plaintext and is wrong about the message.
func (self *testCohort) exchange(t *testing.T, from int, plaintext string) {
	t.Helper()
	author := self.groups[from]
	aad := []byte("round trip aad")
	sealed, err := author.Protect(aad, []byte(plaintext))
	if err != nil {
		t.Fatalf("Protect at leaf %d: %v", author.OwnLeafIndex(), err)
	}
	opened := 0
	for at, group := range self.groups {
		if at == from {
			continue
		}
		application, err := group.Unprotect(sealed)
		if err != nil {
			t.Fatalf("leaf %d could not open the message of leaf %d at epoch %d: %v",
				group.OwnLeafIndex(), author.OwnLeafIndex(), group.Epoch(), err)
		}
		if string(application.Plaintext) != plaintext {
			t.Fatalf("leaf %d opened %q from leaf %d, want %q",
				group.OwnLeafIndex(), application.Plaintext, author.OwnLeafIndex(), plaintext)
		}
		if !bytes.Equal(application.AuthenticatedData, aad) {
			t.Fatalf("leaf %d read the authenticated data as %q, want %q",
				group.OwnLeafIndex(), application.AuthenticatedData, aad)
		}
		if application.SenderLeaf != author.OwnLeafIndex() {
			t.Fatalf("leaf %d read the message as coming from leaf %d, want %d",
				group.OwnLeafIndex(), application.SenderLeaf, author.OwnLeafIndex())
		}
		opened += 1
	}
	if opened != len(self.groups)-1 {
		t.Fatalf("%d of %d peers opened the message of leaf %d",
			opened, len(self.groups)-1, author.OwnLeafIndex())
	}
}

// restore reloads one member out of the state it has persisted and PUTS THE RESTORED VIEW IN THE
// LIVE ONE'S PLACE.
//
// The live view is closed and replaced rather than kept beside the restored one, and that is the
// whole point of doing it here: both hold the same leaf, so two views sealing under one leaf's
// ratchet is the nonce reuse the restore path exists to prevent, and a case that kept both would be
// observing whichever of the two it happened to send from. Everything the cohort does afterwards
// goes through the restored view.
func (self *testCohort) restore(t *testing.T, at int) *Group {
	t.Helper()
	live := self.groups[at]
	leaf, epoch := live.OwnLeafIndex(), live.Epoch()
	restored, err := LoadGroup(self.configs[at], epoch, self.members[at].SigPriv)
	if err != nil {
		t.Fatalf("LoadGroup at leaf %d, epoch %d: %v", leaf, epoch, err)
	}
	if restored.OwnLeafIndex() != leaf {
		t.Fatalf("the restored view came back at leaf %d, want %d", restored.OwnLeafIndex(), leaf)
	}
	if restored.Epoch() != epoch {
		t.Fatalf("the restored view of leaf %d came back at epoch %d, want %d",
			leaf, restored.Epoch(), epoch)
	}
	if !bytes.Equal(restored.EpochAuthenticator(), live.EpochAuthenticator()) {
		t.Fatalf("the restored view of leaf %d answers a different epoch authenticator from the live one, so it is not the same epoch of the same group",
			leaf)
	}
	live.Close()
	self.groups[at] = restored
	return restored
}

// testExtensionsWith is the group's own published extension list with one entry replaced.
//
// A group_context_extensions proposal REPLACES the list wholesale (RFC 9420 section 12.1.6), so a
// caller that passes only the entry it changed drops every other extension the group carries -- for
// a group of this profile that is required_capabilities, and dropping it is a different change from
// the one a retention policy case means to make.
func testExtensionsWith(t *testing.T, group *Group, replacement Extension) []Extension {
	t.Helper()
	context := testGroupContextOf(t, group)
	out := make([]Extension, 0, len(context.Extensions)+1)
	replaced := false
	for _, extension := range context.Extensions {
		if extension.ExtensionType == replacement.ExtensionType {
			out = append(out, replacement)
			replaced = true
			continue
		}
		out = append(out, extension)
	}
	if !replaced {
		out = append(out, replacement)
	}
	return out
}

// ---------------------------------------------------------------------------
// the round trips
// ---------------------------------------------------------------------------

// TestGroupLifecycleFullCycle is this plan's gate: one group, four members, and every operation the
// profile has, each one delivered to every other member and each one followed by an agreement.
func TestGroupLifecycleFullCycle(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "roundtrip")
	root, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	cohort := &testCohort{
		crypto:  crypto,
		groupId: "roundtrip",
		groups:  []*Group{root},
		members: []*testMember{owner},
		configs: []*GroupConfig{cfg},
	}
	defer cohort.closeAll()

	cohort.addMember(t, root, "bob")
	cohort.assertLockstep(t)
	cohort.addMember(t, root, "carol")
	cohort.assertLockstep(t)
	cohort.addMember(t, root, "dave")
	cohort.assertLockstep(t)
	if len(root.Members()) != 4 {
		t.Fatalf("Members = %d, want 4", len(root.Members()))
	}

	// a member updates, and SOMEBODY ELSE commits it by reference. The committer never holds the
	// leaf key the update publishes, so a commit path that read the proposer's leaf out of its own
	// tree rather than out of the proposal would produce an epoch only the committer can enter.
	bob := cohort.groups[1]
	update, err := bob.ProposeUpdate()
	if err != nil {
		t.Fatalf("ProposeUpdate: %v", err)
	}
	cohort.deliver(t, bob, update, false)
	cohort.commitFrom(t, 0)
	cohort.assertLockstep(t)

	// application traffic flows in both directions at the new epoch
	cohort.exchange(t, 1, "after the update")
	cohort.exchange(t, 3, "and back the other way")

	// a GroupContextExtensions commit changes the retention policy
	policy, err := root.GroupPolicy()
	if err != nil {
		t.Fatalf("GroupPolicy: %v", err)
	}
	policy.RetentionPolicy = RetentionPolicy{DurableMs: 31536000000, MediaMs: 2592000000}
	ext, err := policy.Encode()
	if err != nil {
		t.Fatalf("Encode policy: %v", err)
	}
	gce, err := root.ProposeGroupContextExtensions(testExtensionsWith(t, root, ext))
	if err != nil {
		t.Fatalf("ProposeGroupContextExtensions: %v", err)
	}
	cohort.deliver(t, root, gce, false)
	cohort.commitFrom(t, 0)
	cohort.assertLockstep(t)
	for at, group := range cohort.groups {
		updated, err := group.GroupPolicy()
		if err != nil {
			t.Fatalf("GroupPolicy at leaf %d: %v", group.OwnLeafIndex(), err)
		}
		if updated.RetentionPolicy.DurableMs != 31536000000 ||
			updated.RetentionPolicy.MediaMs != 2592000000 {
			t.Fatalf("the GCE commit did not reach cohort entry %d: retention is %+v",
				at, updated.RetentionPolicy)
		}
	}

	// a remove: the removed member sees ErrRemovedFromGroup, the rest stay in lockstep
	dave := cohort.groups[3]
	daveLeaf := dave.OwnLeafIndex()
	removal, err := root.ProposeRemove(daveLeaf)
	if err != nil {
		t.Fatalf("ProposeRemove: %v", err)
	}
	cohort.deliver(t, root, removal, false)
	result, err := root.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateCommit with remove: %v", err)
	}
	for _, group := range cohort.groups[1:] {
		processed, err := group.ProcessMessage(result.Commit)
		if err != nil {
			t.Fatalf("leaf %d could not process the removal commit: %v", group.OwnLeafIndex(), err)
		}
		err = group.ApplyCommit(processed)
		if group == dave {
			if !errors.Is(err, ErrRemovedFromGroup) {
				t.Fatalf("removed member error = %v, want ErrRemovedFromGroup", err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("leaf %d could not apply the removal commit: %v", group.OwnLeafIndex(), err)
		}
	}
	if err := root.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	cohort.groups = cohort.groups[:3]
	cohort.members = cohort.members[:3]
	cohort.configs = cohort.configs[:3]
	cohort.assertLockstep(t)
	if len(root.Members()) != 3 {
		t.Fatalf("Members after removal = %d, want 3", len(root.Members()))
	}
	for _, group := range cohort.groups {
		if _, found := group.MemberAt(daveLeaf); found {
			t.Fatalf("leaf %d still holds a member at the removed leaf %d",
				group.OwnLeafIndex(), daveLeaf)
		}
	}
	// the three that remain still talk to each other at the epoch the removal opened
	cohort.exchange(t, 2, "after the removal")

	// and the removed member can no longer read or write the new epoch. THE SENTINEL AND NOT
	// MERELY AN ERROR: a closed group holds a nil secret tree, so a Protect that had lost its own
	// refusal would still fail somewhere below and satisfy an assertion written as "err != nil".
	if _, err := dave.Protect(nil, []byte("still here?")); !errors.Is(err, errGroupClosed) {
		t.Fatalf("the removed member's Protect = %v, want errGroupClosed", err)
	}
}

// TestJoinAtAnAdvancedEpoch is the Welcome at a history the joiner was never sent.
func TestJoinAtAnAdvancedEpoch(t *testing.T) {
	crypto := testCrypto(t)
	cohort := testNewCohort(t, crypto, "advanced", 1)
	defer cohort.closeAll()
	root := cohort.groups[0]

	for i := 0; i < 5; i += 1 {
		cohort.commitFrom(t, 0)
	}
	if root.Epoch() != 5 {
		t.Fatalf("Epoch = %d, want 5", root.Epoch())
	}
	late := cohort.addMember(t, root, "late")
	if late.Epoch() != root.Epoch() {
		t.Fatalf("late joiner epoch = %d, committer = %d", late.Epoch(), root.Epoch())
	}
	cohort.assertLockstep(t)
	// and the epoch it joined at is one it can use, in both directions
	cohort.exchange(t, 1, "the late joiner speaks")
	cohort.commitFrom(t, 1)
	cohort.assertLockstep(t)
}

// TestLosingCommitterRederivesAgainstTheWinner is MASTER section 9.3: the delivery service accepts
// one commit per (group, epoch), so the loser clears its pending commit, applies the winner's, and
// commits again at the epoch that opened.
func TestLosingCommitterRederivesAgainstTheWinner(t *testing.T) {
	crypto := testCrypto(t)
	committer, receiver, _, _ := testTwoMemberGroup(t, crypto)
	defer committer.Close()
	defer receiver.Close()

	winner, err := committer.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("winner CreateCommit: %v", err)
	}
	if _, err := receiver.CreateCommit(nil, nil, nil); err != nil {
		t.Fatalf("loser CreateCommit: %v", err)
	}
	// the loser learns the server accepted the other commit
	receiver.ClearPendingCommit()
	processed, err := receiver.ProcessMessage(winner.Commit)
	if err != nil {
		t.Fatalf("loser ProcessMessage: %v", err)
	}
	if err := receiver.ApplyCommit(processed); err != nil {
		t.Fatalf("loser ApplyCommit: %v", err)
	}
	if err := committer.MergePendingCommit(); err != nil {
		t.Fatalf("winner MergePendingCommit: %v", err)
	}
	if receiver.Epoch() != committer.Epoch() {
		t.Fatalf("the loser is at epoch %d and the winner at %d", receiver.Epoch(), committer.Epoch())
	}
	if !bytes.Equal(receiver.EpochAuthenticator(), committer.EpochAuthenticator()) {
		t.Fatal("the loser did not converge on the winner's epoch")
	}
	// and can commit again at the new epoch, which the winner then follows
	second, err := receiver.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("loser re-commit: %v", err)
	}
	staged, err := committer.ProcessMessage(second.Commit)
	if err != nil {
		t.Fatalf("the winner could not process the loser's next commit: %v", err)
	}
	if err := committer.ApplyCommit(staged); err != nil {
		t.Fatalf("the winner could not apply the loser's next commit: %v", err)
	}
	if err := receiver.MergePendingCommit(); err != nil {
		t.Fatalf("loser MergePendingCommit: %v", err)
	}
	if !bytes.Equal(receiver.EpochAuthenticator(), committer.EpochAuthenticator()) {
		t.Fatal("the two did not agree on the epoch the loser's next commit opened")
	}
}

// TestProfileRefusalsEndToEnd is the v1 profile's three refusals, taken at the doors a message
// actually arrives through rather than at the gate alone.
//
// The codec decodes all seven proposal arms so the messages vector family can round trip them; what
// this plan's profile is, is the refusal of the three v1 does not run.
func TestProfileRefusalsEndToEnd(t *testing.T) {
	crypto := testCrypto(t)
	committer, receiver, _, _ := testTwoMemberGroup(t, crypto)
	defer committer.Close()
	defer receiver.Close()

	psk := &Proposal{ProposalType: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKey{}}
	if err := checkProposalProfile(defaultProfile(), psk); !errors.Is(err, errProfilePsk) {
		t.Fatalf("psk gate = %v, want errProfilePsk", err)
	}
	externalInit := &Proposal{ProposalType: ProposalTypeExternalInit, ExternalInit: &ExternalInit{}}
	if err := checkProposalProfile(defaultProfile(), externalInit); !errors.Is(err, errProfileExternalCommit) {
		t.Fatalf("external_init gate = %v, want errProfileExternalCommit", err)
	}
	// and a psk proposal that arrives on the wire never reaches the cache
	content := testProposalContentAt(t, committer.OwnLeafIndex(), committer.GroupId(),
		committer.Epoch(), psk)
	if _, err := committer.proposals.Store(crypto, committer.context, content); !errors.Is(err, errProfilePsk) {
		t.Fatalf("psk cache Store = %v, want errProfilePsk", err)
	}
	// a group context extension outside the allowed set is refused before it commits
	bad := []Extension{{ExtensionType: ExtensionTypeExternalSenders, ExtensionData: []byte{}}}
	if _, err := committer.ProposeGroupContextExtensions(bad); !errors.Is(err, errProfileExternalSender) {
		t.Fatalf("external_senders = %v, want errProfileExternalSender", err)
	}
}

// TestEveryMemberCommitsInTurnAndEveryOtherMemberFollows is the cross-member half of this file, run
// at three sizes.
//
// EVERY MEMBER COMMITS, IN TURN, AND EVERY OTHER MEMBER PROCESSES IT. A fixture where one member is
// always the committer exercises one sender's filtered direct path and one receiver's entry into
// it, and the entry point is a function of the PAIR: at four members eight of the twelve ordered
// pairs enter above the receiver's own leaf and four do not, so a single committer leaves most of
// the pairs unvisited.
//
// The sizes are 4, 5 and 6 because the property is the member's position. At five, leaf 4 stands
// alone under the right subtree and enters every sender's commit at its own leaf, and at six it no
// longer does -- so a defect that only shows for a member with a copath node above its own leaf is
// present for four of five members at one size and five of six at the next.
func TestEveryMemberCommitsInTurnAndEveryOtherMemberFollows(t *testing.T) {
	crypto := testCrypto(t)
	for _, size := range []int{4, 5, 6} {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			cohort := testNewCohort(t, crypto, fmt.Sprintf("in-turn-%d", size), size)
			defer cohort.closeAll()
			cohort.assertLockstep(t)
			// the adds alone: one commit per admission, so the group stands at size-1
			if cohort.groups[0].Epoch() != uint64(size-1) {
				t.Fatalf("a cohort of %d built out of adds stands at epoch %d, want %d",
					size, cohort.groups[0].Epoch(), size-1)
			}
			for from := range cohort.groups {
				before := cohort.groups[0].Epoch()
				cohort.commitFrom(t, from)
				if cohort.groups[0].Epoch() != before+1 {
					t.Fatalf("the commit of leaf %d moved the epoch from %d to %d",
						cohort.groups[from].OwnLeafIndex(), before, cohort.groups[0].Epoch())
				}
				cohort.assertLockstep(t)
				cohort.exchange(t, from, fmt.Sprintf("epoch %d, from leaf %d",
					cohort.groups[0].Epoch(), cohort.groups[from].OwnLeafIndex()))
			}
			// every view of this cohort holds a distinct leaf, and together they hold 0..size-1
			seen := map[LeafIndex]bool{}
			for _, group := range cohort.groups {
				if seen[group.OwnLeafIndex()] {
					t.Fatalf("two views of this cohort hold leaf %d", group.OwnLeafIndex())
				}
				seen[group.OwnLeafIndex()] = true
			}
			for i := 0; i < size; i += 1 {
				if !seen[LeafIndex(i)] {
					t.Fatalf("no view of this cohort holds leaf %d", i)
				}
			}
			// and the MEMBERSHIP names those same leaves. assertLockstep compares the views
			// against each other, so a build that reported every member at leaf 0 would agree
			// with itself everywhere; this is the absolute statement an agreement cannot make.
			members := cohort.groups[0].Members()
			if len(members) != size {
				t.Fatalf("Members = %d, want %d", len(members), size)
			}
			for i, member := range members {
				if member.LeafIndex != LeafIndex(i) {
					t.Fatalf("Members()[%d] is at leaf %d, want %d", i, member.LeafIndex, i)
				}
			}
		})
	}
}

// TestAMemberThatJoinedMidHistoryFollowsEveryOtherMember is the join at an epoch with a history
// behind it, followed by a commit from each of the members that predate it.
//
// The Welcome is committed by leaf 2 RATHER THAN BY THE GROUP'S FOUNDER, which is the arrangement a
// fixture that always commits from leaf 0 never builds: the joiner's own committer is then not the
// member whose leaf its Welcome's path secret climbs from, and the far side of the tree is a member
// that took no part in admitting it.
func TestAMemberThatJoinedMidHistoryFollowsEveryOtherMember(t *testing.T) {
	crypto := testCrypto(t)
	cohort := testNewCohort(t, crypto, "mid-history", 4)
	defer cohort.closeAll()
	cohort.settle(t)
	cohort.assertLockstep(t)
	cohort.exchange(t, 1, "history the joiner will never see")
	behind := cohort.groups[0].Epoch()

	late := cohort.addMember(t, cohort.groups[2], "late")
	cohort.assertLockstep(t)
	if late.Epoch() != behind+1 {
		t.Fatalf("the late joiner came up at epoch %d, want %d", late.Epoch(), behind+1)
	}
	if len(late.Members()) != 5 {
		t.Fatalf("the late joiner holds %d members, want 5", len(late.Members()))
	}

	// every member that predates the joiner commits, and the joiner follows each one -- leaf 0
	// first, which is the far side of the tree from the leaf the joiner was placed at.
	for from := 0; from < len(cohort.groups)-1; from += 1 {
		cohort.commitFrom(t, from)
		cohort.assertLockstep(t)
		cohort.exchange(t, from, fmt.Sprintf("leaf %d speaks to the joiner",
			cohort.groups[from].OwnLeafIndex()))
	}
	// and the joiner commits, and every member that predates it follows
	joiner := len(cohort.groups) - 1
	cohort.commitFrom(t, joiner)
	cohort.assertLockstep(t)
	cohort.exchange(t, joiner, "the joiner speaks back")
}

// TestARemovedMemberLeavesTheRestInLockstep removes a MIDDLE leaf, committed by that leaf's own
// sibling.
//
// The sibling is the committer because a remove blanks the removed leaf's direct path, which is the
// committer's own path from the parent they share upward -- so the committer is re-keying nodes the
// same commit has just blanked, and it is the arrangement in which a blank-then-fill ordering defect
// is reachable at all.
func TestARemovedMemberLeavesTheRestInLockstep(t *testing.T) {
	crypto := testCrypto(t)
	cohort := testNewCohort(t, crypto, "removal", 5)
	defer cohort.closeAll()
	cohort.settle(t)
	cohort.assertLockstep(t)

	victim := cohort.groups[2]
	victimLeaf := victim.OwnLeafIndex()
	committer := cohort.groups[3]
	removal, err := committer.ProposeRemove(victimLeaf)
	if err != nil {
		t.Fatalf("ProposeRemove(%d): %v", victimLeaf, err)
	}
	cohort.deliver(t, committer, removal, false)
	result, err := committer.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateCommit with the remove: %v", err)
	}
	for _, group := range cohort.groups {
		if group == committer {
			continue
		}
		processed, err := group.ProcessMessage(result.Commit)
		if err != nil {
			t.Fatalf("leaf %d could not process the removal commit: %v", group.OwnLeafIndex(), err)
		}
		err = group.ApplyCommit(processed)
		if group == victim {
			if !errors.Is(err, ErrRemovedFromGroup) {
				t.Fatalf("the removed member's ApplyCommit = %v, want ErrRemovedFromGroup", err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("leaf %d could not apply the removal commit: %v", group.OwnLeafIndex(), err)
		}
	}
	if err := committer.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit at the committer: %v", err)
	}
	cohort.groups = slices.Delete(cohort.groups, 2, 3)
	cohort.members = slices.Delete(cohort.members, 2, 3)
	cohort.configs = slices.Delete(cohort.configs, 2, 3)
	cohort.assertLockstep(t)

	for _, group := range cohort.groups {
		if len(group.Members()) != 4 {
			t.Fatalf("leaf %d holds %d members after the removal, want 4",
				group.OwnLeafIndex(), len(group.Members()))
		}
		if _, found := group.MemberAt(victimLeaf); found {
			t.Fatalf("leaf %d still holds a member at the removed leaf %d",
				group.OwnLeafIndex(), victimLeaf)
		}
	}
	if _, err := victim.Protect(nil, []byte("still here?")); !errors.Is(err, errGroupClosed) {
		t.Fatalf("the removed member's Protect = %v, want errGroupClosed", err)
	}
	// the four that remain go on, from a member on each side of the leaf that left
	cohort.exchange(t, 0, "after the removal, from the left")
	cohort.exchange(t, 2, "after the removal, from the right")
	cohort.commitFrom(t, 2)
	cohort.assertLockstep(t)
	cohort.commitFrom(t, 0)
	cohort.assertLockstep(t)
}

// TestARemovalBlanksTheRemovedLeafsPathTheCommitDoesNotCover is section 12.1.3's blanking, held
// where it is observable.
//
// WHY IT NEEDS ITS OWN CASE, measured rather than argued. Deleting the BlankDirectPath call from
// (*RatchetTree).RemoveLeaf leaves every assertion of every other case in this file green: the
// remaining members all agree about the stale node, so no agreement can see it. And it survived an
// assertion written into TestARemovedMemberLeavesTheRestInLockstep too, for a second reason -- that
// case removes a leaf and commits from its SIBLING, and applying an update path blanks the
// committer's own direct path, which above two siblings is the very same set of nodes. So the
// removal's own blanking is unobservable there whatever assertion is written beside it.
//
// SO THE COMMITTER HERE IS ON THE OTHER SIDE OF THE REMOVED LEAF'S PARENT. The nodes below
// CommonAncestor(removed, committer) are exactly the ones the commit's own path does not touch, and
// they are the ones section 12.1.3 has to blank: each carries a key the removed member holds, so a
// node left standing is one it can go on deriving every path secret sealed to.
//
// THE CLASS IS DERIVED AND THE VACUITY IS GUARDED. The set is the removed leaf's direct path minus
// the committer's, taken off the tree math rather than written down after drawing the tree, and the
// case requires that set to be NON-EMPTY and non-blank BEFORE the removal -- a tree that had blanked
// those nodes already would satisfy the after-assertion by having nothing left in it to look at.
//
// AND WHAT THE FINAL LOOP COULD NOT BE MADE TO FAIL ON ITS OWN, recorded rather than left implied.
// Deleting BlankDirectPath from RemoveLeaf does fail this case -- but in the RECEIVE path, on the
// parent hash, before the loop is reached: the stale node's own parent is re-keyed by the same
// commit, so the leaf that used to claim the stale node no longer chains to it and section 7.9.2
// reports it as claimed by none of its descendants. That is structural and not a gap in the
// mutation. Every node this loop is about sits BELOW CommonAncestor(removed, committer), and that
// ancestor is on the committer's path and therefore always re-keyed, so a node left standing here
// always breaks the parent hash. The loop is a SECOND statement of a rule the parent hash already
// carries -- kept because it says the rule at the level the rule is about, and because it is what
// would report a build whose parent hash validation had been relaxed -- and it is not an
// independent observation of the blanking.
func TestARemovalBlanksTheRemovedLeafsPathTheCommitDoesNotCover(t *testing.T) {
	crypto := testCrypto(t)
	cohort := testNewCohort(t, crypto, "removal-blanking", 4)
	defer cohort.closeAll()
	cohort.settle(t)
	cohort.assertLockstep(t)

	victim := cohort.groups[3]
	victimLeaf := victim.OwnLeafIndex()
	committer := cohort.groups[0]
	committerLeaf := committer.OwnLeafIndex()
	survivor := cohort.groups[1]

	// the class, derived off the tree BEFORE anything is removed
	width := survivor.tree.LeafWidth()
	victimPath, err := directPathOf(victimLeaf.NodeIndex(), width)
	if err != nil {
		t.Fatalf("direct path of leaf %d: %v", victimLeaf, err)
	}
	committerPath, err := directPathOf(committerLeaf.NodeIndex(), width)
	if err != nil {
		t.Fatalf("direct path of leaf %d: %v", committerLeaf, err)
	}
	covered := map[NodeIndex]bool{}
	for _, x := range committerPath {
		covered[x] = true
	}
	owed := []NodeIndex{}
	for _, x := range victimPath {
		if covered[x] {
			continue
		}
		owed = append(owed, x)
	}
	if len(owed) == 0 {
		t.Fatalf("every node above leaf %d is also above leaf %d, so the commit's own path would blank them and the removal's blanking is unobservable here",
			victimLeaf, committerLeaf)
	}
	for _, x := range owed {
		if survivor.tree.ParentAt(x) == nil {
			t.Fatalf("node %d is already blank before the removal, so requiring it blank afterwards observes nothing",
				x)
		}
	}
	t.Logf("removing leaf %d at a commit from leaf %d owes the blanking of %v",
		victimLeaf, committerLeaf, owed)

	removal, err := committer.ProposeRemove(victimLeaf)
	if err != nil {
		t.Fatalf("ProposeRemove(%d): %v", victimLeaf, err)
	}
	cohort.deliver(t, committer, removal, false)
	result, err := committer.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateCommit with the remove: %v", err)
	}
	for _, group := range cohort.groups {
		if group == committer {
			continue
		}
		processed, err := group.ProcessMessage(result.Commit)
		if err != nil {
			t.Fatalf("leaf %d could not process the removal commit: %v", group.OwnLeafIndex(), err)
		}
		err = group.ApplyCommit(processed)
		if group == victim {
			if !errors.Is(err, ErrRemovedFromGroup) {
				t.Fatalf("the removed member's ApplyCommit = %v, want ErrRemovedFromGroup", err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("leaf %d could not apply the removal commit: %v", group.OwnLeafIndex(), err)
		}
	}
	if err := committer.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit at the committer: %v", err)
	}
	cohort.groups = cohort.groups[:3]
	cohort.members = cohort.members[:3]
	cohort.configs = cohort.configs[:3]
	cohort.assertLockstep(t)

	// EVERY view, and not only the one the class was derived from: a member that kept the stale
	// node is a member that seals its next commit to a key the removed member holds, and which of
	// them does that is not something the derivation can say in advance.
	for _, group := range cohort.groups {
		for _, x := range owed {
			if group.tree.ParentAt(x) != nil {
				t.Fatalf("leaf %d still carries node %d, which stands above the removed leaf %d and which this commit's own path never touched: the removed member goes on deriving every path secret sealed to it",
					group.OwnLeafIndex(), x, victimLeaf)
			}
		}
	}
	// and the group goes on from the epoch the removal opened
	cohort.exchange(t, 0, "after the blanking")
	cohort.commitFrom(t, 2)
	cohort.assertLockstep(t)
}

// TestEveryMemberSendsAndReceivesAcrossARestore persists and restores each member in turn and
// requires the restored view to do both halves of being a member.
//
// SENDING IS THE HALF A RESTORE LOSES QUIETLY. A restored member whose sender ratchet restarted at
// generation 0 draws a generation its peers have already consumed: they answer
// ErrRatchetGenerationConsumed and drop the message, and two plaintexts of one epoch have gone out
// under one (key, base nonce) pair for that leaf. So each member SENDS before the restore and sends
// again after it, to a cohort whose receiving heads for that leaf have already moved.
//
// RECEIVING IS THE OTHER HALF, and the commit that follows each restore comes from a DIFFERENT
// member -- so the restored view has to open a path secret sealed to a node above its own leaf out
// of a ladder it rebuilt from storage rather than out of the commit that first gave it to it.
func TestEveryMemberSendsAndReceivesAcrossARestore(t *testing.T) {
	crypto := testCrypto(t)
	cohort := testNewCohort(t, crypto, "restore-round-trip", 4)
	defer cohort.closeAll()
	cohort.settle(t)
	cohort.assertLockstep(t)

	for at := range cohort.groups {
		leaf := cohort.groups[at].OwnLeafIndex()
		cohort.exchange(t, at, fmt.Sprintf("leaf %d before the restore", leaf))
		cohort.restore(t, at)
		cohort.assertLockstep(t)
		cohort.exchange(t, at, fmt.Sprintf("leaf %d after the restore", leaf))
		// and the restored view follows a commit from somebody else
		cohort.commitFrom(t, (at+1)%len(cohort.groups))
		cohort.assertLockstep(t)
		cohort.exchange(t, at, fmt.Sprintf("leaf %d after the next epoch", leaf))
	}
}

// testUnmergedCopathReach answers the copath node through which a commit from sender reaches
// target's leaf AS AN UNMERGED LEAF.
//
// The node it looks for is NOT BLANK -- so RFC 9420 section 7.4's first rule would make its
// resolution itself alone -- and carries target on its unmerged list anyway, which is the second
// rule and the only way a resolution reaches a leaf the node's own key does not cover.
//
// DERIVED OFF THE TREE AND NOT NAMED. A case that wrote the node index down would go on passing over
// a build that stopped producing an unmerged leaf there, which is exactly the failure mode
// four_member_group_test.go records for the fixtures that have none.
func testUnmergedCopathReach(t *testing.T, tree *RatchetTree, sender LeafIndex,
	target LeafIndex) (NodeIndex, bool) {

	t.Helper()
	steps, err := tree.filteredPathSteps(sender)
	if err != nil {
		t.Fatalf("filtered path of leaf %d: %v", sender, err)
	}
	for _, step := range steps {
		if tree.ParentAt(step.CopathChild) == nil {
			continue
		}
		if !slices.Contains(tree.UnmergedLeaves(step.CopathChild), target) {
			continue
		}
		resolution := tree.Resolution(step.CopathChild)
		if !slices.Contains(resolution, target.NodeIndex()) {
			t.Fatalf("node %d lists leaf %d unmerged and its resolution %v does not reach it",
				step.CopathChild, target, resolution)
		}
		if len(resolution) < 2 || resolution[0] != step.CopathChild {
			t.Fatalf("node %d is not blank and resolves to %v, which is not itself followed by its unmerged leaves",
				step.CopathChild, resolution)
		}
		return step.CopathChild, true
	}
	return 0, false
}

// TestACommitReachesTheNewestMemberThroughAnUnmergedLeaf builds the arrangement no fixture in this
// package has: a member a commit reaches through a NON-BLANK copath node's unmerged list.
//
// WHY SEVEN AND THEN AN EIGHTH. An Add lists the new leaf as unmerged at every non-blank node above
// it, and in every other fixture here there are none -- a group assembled out of adds has all those
// parents blank, and one that has settled has had them merged. The node above a new leaf is
// non-blank only when somebody committed through it WHILE the leaf slot was empty, and a filtered
// direct path drops any node whose copath child resolves to nothing, so the empty slot's own parent
// is never it. The nearest node that can be is the GRANDparent, which needs the sibling subtree
// occupied: seven members leaves leaf 7 empty with leaves 4 and 6 in place, node 13 blank because
// leaf 6's filtered path drops it, and node 11 filled because leaf 4's does not.
//
// THE SHAPE IS ASSERTED BEFORE ANYTHING IS SENT. Without that this case is satisfied by a tree with
// no unmerged leaf in it at all -- it would simply be an eight member round trip, green, and
// reported as covering the resolution rule it no longer reaches.
func TestACommitReachesTheNewestMemberThroughAnUnmergedLeaf(t *testing.T) {
	crypto := testCrypto(t)
	cohort := testNewCohort(t, crypto, "unmerged", 7)
	defer cohort.closeAll()
	cohort.settle(t)
	cohort.assertLockstep(t)

	newest := cohort.addMember(t, cohort.groups[0], "newest")
	cohort.assertLockstep(t)

	sender := cohort.groups[0]
	through, held := testUnmergedCopathReach(t, sender.tree, sender.OwnLeafIndex(),
		newest.OwnLeafIndex())
	if !held {
		t.Fatalf("no copath node of leaf %d reaches leaf %d through an unmerged list, so this case is an ordinary round trip and observes nothing about section 7.4's second rule",
			sender.OwnLeafIndex(), newest.OwnLeafIndex())
	}
	t.Logf("leaf %d reaches leaf %d through the unmerged list of node %d, whose resolution is %v",
		sender.OwnLeafIndex(), newest.OwnLeafIndex(), through, sender.tree.Resolution(through))

	// the commit that has to pair its ciphertexts with that resolution. The newest member is not
	// the FIRST entry of it, so a pairing that walked the resolution wrongly hands it the
	// ciphertext sealed to the node itself -- which every other member of that subtree opens.
	cohort.commitFrom(t, 0)
	cohort.assertLockstep(t)
	cohort.exchange(t, len(cohort.groups)-1, "the unmerged member speaks")

	// AND THE ENTRY IS STILL THERE, which is the half that says leaf 0's commit did not merge it.
	// An update path re-keys the COMMITTER'S filtered direct path, and the node this case is about
	// is on leaf 0's COPATH -- so a build that cleared an unmerged list it had only encrypted to
	// would leave every later resolution unable to reach the leaf it dropped.
	if !slices.Contains(sender.tree.UnmergedLeaves(through), newest.OwnLeafIndex()) {
		t.Fatalf("node %d stopped listing leaf %d unmerged after a commit that only sealed to it",
			through, newest.OwnLeafIndex())
	}

	// the merge is the newest member's own commit: that node IS on its own filtered direct path, so
	// this is the commit that re-keys the node and takes the leaf off its unmerged list.
	cohort.commitFrom(t, len(cohort.groups)-1)
	cohort.assertLockstep(t)
	if remaining := sender.tree.UnmergedLeaves(through); len(remaining) != 0 {
		t.Fatalf("node %d still lists %v unmerged after a commit from the leaf it listed",
			through, remaining)
	}
	// and the group goes on from there, with the tree it merged into
	cohort.exchange(t, 0, "after the merge")
	cohort.commitFrom(t, 3)
	cohort.assertLockstep(t)
}
