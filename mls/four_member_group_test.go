// The group of FOUR, and the copath it is the smallest size to make real.
//
// WHY THIS FILE EXISTS. Thirty-two call sites of this package's corpus ran on testTwoMemberGroup and
// nothing larger existed. In a group of two the only node of a sender's filtered direct path that
// covers the receiver is the ROOT, and the receiver's own leaf is the whole of that node's copath
// resolution -- so every path secret any commit ever seals to this member is sealed to the member's
// own leaf key, and (*TreeKEMPrivate).NodePrivateKey's own-leaf arm answers every question the
// receive path asks. A whole class of structural defect is invisible under that: anything that
// loses, mispairs or never stored the rungs ABOVE the leaf.
//
// THREE SEPARATES FOR TWO OF ITS THREE MEMBERS AND NOT FOR THE THIRD, which is MEASURED below and is
// not what the reasoning that opened this work predicted -- that reading said three separated nothing,
// and it is wrong. At three members the third leaf stands alone under the root's right side, so a
// commit from either of the other two is sealed to that leaf itself and leaf 2 never enters above its
// own leaf; but a commit FROM leaf 2 is sealed at the root to the resolution of node 1, the parent
// leaves 0 and 1 share, and both of them enter there. Two of six ordered sender/receiver pairs, two of
// three members. So a three member corpus would have caught the missing ladder -- for two of its
// members, on commits from one of its three senders.
//
// FOUR is the smallest size at which EVERY member has a sender whose commit it must open above its own
// leaf: eight of twelve pairs, four of four members. That is the property this fixture is for, because
// a defect invisible for one member of three is a defect nothing reports when the case happens to
// restore that member.
//
// TestFourIsTheSmallestGroupWhoseMembersEnterTheLadderAboveTheirOwnLeaf holds all of that, over sizes
// two, three and four together and with the counts pinned EXACTLY rather than as floors, so a later
// change that made a two member group seal to a parent -- which would make every case in this file
// vacuous while leaving it green -- is reported there.
package mls

import (
	"bytes"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// testGroupMember is one member of a sized fixture: the group it holds, the CONFIG that built it,
// and the identity behind its leaf.
//
// The config is the field the two member fixture had no reason to keep and every restore needs.
// testGroupConfig mints a fresh StateStore per call, so the only way to reach the states a member
// has persisted is to hold the config that member joined under; a case that built a second config
// for the same identity would be asking a store that has never been written to.
type testGroupMember struct {
	group  *Group
	cfg    *GroupConfig
	member *testMember
	leaf   LeafIndex
}

// testSizedGroup is n members of one group, all at one epoch, indexed by leaf.
type testSizedGroup struct {
	crypto  CryptoProvider
	groupId string
	members []*testGroupMember
}

// testFourMemberGroup is the fixture this file is named for. It is testGroupOfSize(4) and is spelled
// separately because that is the size the tree properties are about, and a case reading
// testGroupOfSize(t, crypto, id, 4) says a number where this says what the number is for.
func testFourMemberGroup(t *testing.T, crypto CryptoProvider, groupId string) *testSizedGroup {
	t.Helper()
	return testGroupOfSize(t, crypto, groupId, 4)
}

// testGroupOfSize builds a group of n members and then SETTLES it: every member commits once, in
// leaf order, so that every parent node of the tree carries a key somebody holds the private half of.
//
// THE SETTLING IS NOT DECORATION. A group assembled out of Add commits alone has every parent of
// every added leaf BLANK -- an Add blanks the direct path of the leaf it lands on, and an Add-only
// commit carries no update path at all -- and in a tree of blank parents every resolution walks down
// to the leaves, so a four member group that was only ever added to behaves exactly like a two member
// one. Measured while writing this: after three Adds the nodes 1, 3 and 5 of a four leaf tree were
// all blank and every member's ladder was empty.
//
// Each commit is delivered to every other member and applied there, so the fixture answers n views of
// ONE epoch rather than n groups that agree by construction. The epoch authenticator is compared
// across all of them at the end, which is DeriveSecret(epoch_secret, "authentication") and therefore
// an agreement about the epoch secret rather than about some public function of the tree.
func testGroupOfSize(t *testing.T, crypto CryptoProvider, groupId string, n int) *testSizedGroup {
	t.Helper()
	if n < 1 {
		t.Fatalf("a group of %d members is not a group", n)
	}
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, groupId)
	group, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	self := &testSizedGroup{crypto: crypto, groupId: groupId}
	self.members = append(self.members, &testGroupMember{group: group, cfg: cfg, member: owner, leaf: 0})
	for i := 1; i < n; i += 1 {
		self.addOne(t, testIdentity(t, crypto, testMemberName(i)))
	}
	for _, one := range self.members {
		self.commitFrom(t, one.leaf)
	}
	return self
}

// testMemberName is one distinct name per leaf. testIdentity mints a fresh key pair per call and the
// name is only what a failure reports, so what this owes is distinctness rather than meaning.
func testMemberName(i int) string {
	return "member-" + string(rune('a'+i))
}

// addOne admits one identity: the Add proposal is published, DELIVERED to every member already in the
// group, and then committed.
//
// The proposal is delivered rather than committed by value because a commit names its proposals by
// reference and every receiver resolves those references out of its own cache -- a fixture that
// skipped the delivery produced "proposal reference is not cached for this epoch" at the second
// member, which is the receive path behaving correctly about a fixture that had sent it nothing.
func (self *testSizedGroup) addOne(t *testing.T, who *testMember) {
	t.Helper()
	owner := self.members[0].group
	kp, initPriv, encPriv, encoded := testPublishedKeyPackage(t, self.crypto, who)
	proposal, err := owner.ProposeAdd(encoded)
	if err != nil {
		t.Fatalf("ProposeAdd(%s): %v", who.Name, err)
	}
	for _, one := range self.members[1:] {
		if _, err := one.group.ProcessMessage(proposal); err != nil {
			t.Fatalf("leaf %d could not cache the Add of %s: %v", one.leaf, who.Name, err)
		}
	}
	result, err := owner.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateCommit adding %s: %v", who.Name, err)
	}
	for _, one := range self.members[1:] {
		self.applyAt(t, one.group, result.Commit)
	}
	if err := owner.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit adding %s: %v", who.Name, err)
	}
	cfg := testGroupConfig(t, self.crypto, who, self.groupId)
	joined, err := JoinFromWelcome(cfg, result.Welcome, result.RatchetTree, &JoinKeyMaterial{
		KeyPackage: *kp, InitPrivate: initPriv, EncryptPrivate: encPriv, SignPrivate: who.SigPriv,
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome(%s): %v", who.Name, err)
	}
	self.members = append(self.members, &testGroupMember{
		group: joined, cfg: cfg, member: who, leaf: joined.OwnLeafIndex(),
	})
}

// applyAt processes one commit at one member and enters the epoch it opens.
func (self *testSizedGroup) applyAt(t *testing.T, at *Group, commit []byte) {
	t.Helper()
	processed, err := at.ProcessMessage(commit)
	if err != nil {
		t.Fatalf("leaf %d could not process the commit: %v", at.OwnLeafIndex(), err)
	}
	if err := at.ApplyCommit(processed); err != nil {
		t.Fatalf("leaf %d could not apply the commit: %v", at.OwnLeafIndex(), err)
	}
}

// commitFrom builds a commit at one leaf, delivers it to every other member of the fixture, merges
// the committer's own, and requires all of them to answer one epoch authenticator.
func (self *testSizedGroup) commitFrom(t *testing.T, from LeafIndex) {
	t.Helper()
	sender := self.at(t, from)
	result, err := sender.group.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateCommit at leaf %d: %v", from, err)
	}
	for _, one := range self.members {
		if one.leaf == from {
			continue
		}
		self.applyAt(t, one.group, result.Commit)
	}
	if err := sender.group.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit at leaf %d: %v", from, err)
	}
	self.requireOneEpoch(t)
}

// requireOneEpoch is the fixture's own invariant: n views of one epoch.
func (self *testSizedGroup) requireOneEpoch(t *testing.T) {
	t.Helper()
	first := self.members[0].group
	for _, one := range self.members[1:] {
		if one.group.Epoch() != first.Epoch() {
			t.Fatalf("leaf %d is at epoch %d and leaf 0 at %d, so this fixture is not one epoch",
				one.leaf, one.group.Epoch(), first.Epoch())
		}
		if !bytes.Equal(one.group.EpochAuthenticator(), first.EpochAuthenticator()) {
			t.Fatalf("leaf %d and leaf 0 disagree on the epoch authenticator, so nothing built on this fixture observes an agreement",
				one.leaf)
		}
	}
}

// at is the member holding one leaf.
func (self *testSizedGroup) at(t *testing.T, leaf LeafIndex) *testGroupMember {
	t.Helper()
	for _, one := range self.members {
		if one.leaf == leaf {
			return one
		}
	}
	t.Fatalf("this fixture holds no member at leaf %d", leaf)
	return nil
}

// closeAll erases every epoch this fixture derived.
func (self *testSizedGroup) closeAll() {
	for _, one := range self.members {
		one.group.Close()
	}
}

// testPublishedKeyPackage is testKeyPackage with the encoding a ProposeAdd is handed, so the two
// never part company at a call site.
func testPublishedKeyPackage(t *testing.T, crypto CryptoProvider, who *testMember) (
	*KeyPackage, HpkePrivateKey, HpkePrivateKey, []byte) {

	t.Helper()
	kp, initPriv, encPriv := testKeyPackage(t, crypto, who)
	encoded, err := syntax.Marshal(kp)
	if err != nil {
		t.Fatalf("marshal the key package of %s: %v", who.Name, err)
	}
	return kp, initPriv, encPriv, encoded
}

// ---------------------------------------------------------------------------
// where a member enters the ladder
// ---------------------------------------------------------------------------

// testLadderEntryPoint is the node whose private key a member has to hold in order to open the commit
// a given sender is about to publish: the first entry of the resolution that sender seals to at their
// common ancestor which this member can answer a key for.
//
// It is the reading (*RatchetTree).DecryptUpdatePath makes, taken off the tree rather than out of the
// decrypt, so a case can say WHERE a member enters before anything has been encrypted. That is the
// whole difference a four member group makes and the one thing a two member group cannot say: at two
// members the answer is always the member's own leaf.
//
// The (value, ok) shape is DecryptUpdatePath's for its reason -- a member the commit does not seal to
// at all is the ordinary condition and not a fault -- and the sender itself is one of those.
func testLadderEntryPoint(t *testing.T, crypto CryptoProvider, tree *RatchetTree,
	priv *TreeKEMPrivate, sender LeafIndex) (NodeIndex, bool) {

	t.Helper()
	steps, err := tree.filteredPathSteps(sender)
	if err != nil {
		t.Fatalf("filtered path of leaf %d: %v", sender, err)
	}
	start, onThePath := indexOfStep(steps, CommonAncestor(sender.NodeIndex(), priv.LeafIndex.NodeIndex()))
	if !onThePath {
		return 0, false
	}
	targets, err := tree.EncryptionTargets(sender, nil)
	if err != nil {
		t.Fatalf("encryption targets of leaf %d: %v", sender, err)
	}
	for _, y := range targets[start] {
		_, held, err := priv.NodePrivateKey(crypto, y)
		if err != nil {
			t.Fatalf("leaf %d asking for the key of node %d: %v", priv.LeafIndex, y, err)
		}
		if held {
			return y, true
		}
	}
	return 0, false
}

// TestFourIsTheSmallestGroupWhoseMembersEnterTheLadderAboveTheirOwnLeaf is the measurement the whole
// of this file rests on.
//
// PINNED EXACTLY AND NOT AS A FLOOR, in both of its counts. A floor is satisfied by a tree that
// separates MORE than this as well as by one that separates the same amount somewhere else, and what
// a reader needs out of this table is which sizes hide a missing ladder and for which members. So the
// row for three carries "2 of 6 pairs, 2 of 3 members" rather than "some", and a move in either
// direction is a change to this table.
//
// The row for three is the one that was WRONG before it was run. The reasoning that opened this work
// said two and three both separated nothing; three separates for two of its three members, because
// the lone leaf under the root's right side has no sibling subtree of its own but IS the far side for
// the pair that shares node 1.
func TestFourIsTheSmallestGroupWhoseMembersEnterTheLadderAboveTheirOwnLeaf(t *testing.T) {
	crypto := testCrypto(t)
	for _, row := range []struct {
		size         int
		pairs        int
		abovePairs   int
		aboveMembers int
	}{
		{size: 2, pairs: 2, abovePairs: 0, aboveMembers: 0},
		{size: 3, pairs: 6, abovePairs: 2, aboveMembers: 2},
		{size: 4, pairs: 12, abovePairs: 8, aboveMembers: 4},
	} {
		fixture := testGroupOfSize(t, crypto, "ladder-entry", row.size)
		abovePairs := 0
		aboveMembers := 0
		pairs := 0
		for _, receiver := range fixture.members {
			separates := false
			for _, sender := range fixture.members {
				if sender.leaf == receiver.leaf {
					continue
				}
				entry, sealed := testLadderEntryPoint(t, crypto, receiver.group.tree,
					receiver.group.ownPriv, sender.leaf)
				if !sealed {
					t.Fatalf("size %d: a commit from leaf %d seals nothing the member at leaf %d can open, so this fixture is not one group",
						row.size, sender.leaf, receiver.leaf)
				}
				pairs += 1
				if entry != receiver.leaf.NodeIndex() {
					abovePairs += 1
					separates = true
				}
			}
			if separates {
				aboveMembers += 1
			}
		}
		if pairs != row.pairs {
			t.Errorf("size %d: %d ordered sender/receiver pairs were read, want %d", row.size, pairs, row.pairs)
		}
		if abovePairs != row.abovePairs {
			t.Errorf("size %d: %d of %d pairs enter the ladder above the receiver's own leaf, want %d; a size that separates more or less than this table says is a size whose cases observe something else",
				row.size, abovePairs, pairs, row.abovePairs)
		}
		if aboveMembers != row.aboveMembers {
			t.Errorf("size %d: %d of %d members enter above their own leaf for at least one sender, want %d",
				row.size, aboveMembers, len(fixture.members), row.aboveMembers)
		}
		t.Logf("size %d: %d of %d pairs and %d of %d members enter the ladder above the receiver's own leaf",
			row.size, abovePairs, pairs, aboveMembers, len(fixture.members))
		fixture.closeAll()
	}
	t.Log("four is the smallest size at which EVERY member enters above its own leaf for some sender; three does it for two of its three, which is why a three member corpus would hide the missing ladder for whichever member a case happened to restore")
}
