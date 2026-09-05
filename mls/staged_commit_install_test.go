// The two doors that install a staged epoch, and the two things they read before they do.
//
// commit_provenance_test.go holds the pair ApplyCommit compares -- the group and the epoch a staged
// commit was staged against -- and this file holds the two properties that file's fixtures could not
// see, both of them measured through the exported API alone:
//
//   - THE ORDER of those two refusals against the RemovesSelf arm. Both provenance fixtures commit
//     without removing anybody, so moving the two comparisons below the removal arm is a four line
//     reorder that leaves the whole suite green -- and lets a FOREIGN staged commit Close a live group
//     and erase its key material.
//   - AN ERASED staged commit. The group id, the prior epoch, the epoch, the committer and the
//     removal flag all survive Zeroize, because none of them is key material, so an erased value
//     walks the whole of the provenance door and installs an erased key schedule, an erased secret
//     tree and an erased leaf private state as the group's live epoch.
package mls

import (
	"bytes"
	"errors"
	"testing"
)

// testRemovingStagedCommit is a Processed one member staged for a commit that removes IT, together
// with the group that staged it.
//
// The Remove proposal is delivered to the receiver before the commit that names it, for
// TestProcessCommitReportsSelfRemoval's stated reason: a commit names its proposals by reference, and
// a member that never received the Remove cannot resolve the reference at all -- so a fixture that
// skipped the delivery would observe errProposalNotCached and report a self-removal that was never
// staged.
func testRemovingStagedCommit(t *testing.T, crypto CryptoProvider, groupId string) (
	*Group, *Group, *Processed) {

	t.Helper()
	committer, receiver, _, _, _ := testTwoMemberGroupNamed(t, crypto, groupId)
	removal, err := committer.ProposeRemove(receiver.OwnLeafIndex())
	if err != nil {
		t.Fatalf("ProposeRemove: %v", err)
	}
	if _, err := receiver.ProcessMessage(removal); err != nil {
		t.Fatalf("the receiver could not cache the Remove naming it: %v", err)
	}
	result, err := committer.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateCommit: %v", err)
	}
	processed, err := receiver.ProcessMessage(result.Commit)
	if err != nil {
		t.Fatalf("ProcessMessage: %v", err)
	}
	if processed.Kind != ProcessedCommit || processed.Commit == nil {
		t.Fatalf("the receiver staged kind %d", processed.Kind)
	}
	if !processed.Commit.RemovesSelf() {
		t.Fatal("this fixture's commit does not remove the member that staged it, so the ordering it exists to observe is not reachable from it")
	}
	return committer, receiver, processed
}

// TestApplyCommitReadsProvenanceBeforeTheRemovalArm is the ordering, and the ordering alone.
//
// A staged commit that removes the member that staged it is a value ApplyCommit responds to by
// CLOSING the group -- erasing its key schedule, its secret tree, its leaf private state and its
// signing key -- and answering ErrRemovedFromGroup. So a door that read the removal flag before it
// read the provenance would let any Processed a caller crossed over from another group destroy this
// one, and there is no recovery from it: the epoch is gone from the process.
//
// BOTH HALVES OF THE PROVENANCE PAIR, because they are two comparisons and a reorder can move either.
// The group arm is a commit another group staged; the epoch arm is a commit of THIS group staged
// against an epoch it has already left.
//
// What each arm asserts is not only the sentinel but that the group is STILL ALIVE, which is the
// thing the sentinel cannot say: a body that closed the group and then returned the provenance
// refusal would answer exactly the error this case wants while having done the damage.
func TestApplyCommitReadsProvenanceBeforeTheRemovalArm(t *testing.T) {
	crypto := testCrypto(t)

	// the group arm.
	committerA, receiverA, removing := testRemovingStagedCommit(t, crypto, "removal-order-a")
	defer committerA.Close()
	defer receiverA.Close()
	committerB, receiverB, _, _, _ := testTwoMemberGroupNamed(t, crypto, "removal-order-b")
	defer committerB.Close()
	defer receiverB.Close()

	epochBefore := receiverB.Epoch()
	authenticatorBefore := bytes.Clone(receiverB.EpochAuthenticator())
	if len(authenticatorBefore) == 0 {
		t.Fatal("the group this case protects answers no epoch authenticator before the call, so a closed group and a live one read the same here")
	}
	if err := receiverB.ApplyCommit(removing); !errors.Is(err, errApplyCommitNotThisGroups) {
		t.Fatalf("group B ApplyCommit over a removing commit group A staged = %v, want errApplyCommitNotThisGroups", err)
	}
	if !bytes.Equal(receiverB.EpochAuthenticator(), authenticatorBefore) {
		t.Fatal("a foreign staged commit that removes its own stager destroyed group B's epoch; the removal arm is being read before the provenance pair")
	}
	if receiverB.Epoch() != epochBefore {
		t.Fatalf("the refused ApplyCommit moved group B from epoch %d to %d", epochBefore, receiverB.Epoch())
	}
	// alive rather than merely unmoved: an epoch authenticator is a read of the schedule, and Protect
	// is a write to the secret tree.
	if _, err := receiverB.Protect(nil, []byte("group B is still here")); err != nil {
		t.Fatalf("group B cannot protect a message after refusing a foreign removing commit: %v", err)
	}

	// the epoch arm, over ONE group id so that the group comparison cannot be what refuses it.
	//
	// The laggard is a SECOND VIEW of the same member at an epoch it has not left -- the join door
	// run again over the same Welcome, which is commit_provenance_test.go's device -- and it holds
	// the leaf the removing commit names. So the removal flag is true of it, the group id agrees, and
	// the epoch comparison is the only thing standing between it and a Close.
	committer, receiver, _, _, material := testTwoMemberGroupNamed(t, crypto, "removal-order-epoch")
	defer committer.Close()
	defer receiver.Close()
	laggard, err := material.join(t, nil)
	if err != nil {
		t.Fatalf("the second view this arm lags with: %v", err)
	}
	defer laggard.Close()

	// one plain commit, so the removing commit below is staged against an epoch the laggard is not in.
	advancing, err := committer.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("the plain CreateCommit: %v", err)
	}
	moved, err := receiver.ProcessMessage(advancing.Commit)
	if err != nil {
		t.Fatalf("ProcessMessage of the plain commit: %v", err)
	}
	if err := receiver.ApplyCommit(moved); err != nil {
		t.Fatalf("ApplyCommit of the plain commit: %v", err)
	}
	if err := committer.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit of the plain commit: %v", err)
	}

	removal, err := committer.ProposeRemove(receiver.OwnLeafIndex())
	if err != nil {
		t.Fatalf("ProposeRemove: %v", err)
	}
	if _, err := receiver.ProcessMessage(removal); err != nil {
		t.Fatalf("the receiver could not cache the Remove naming it: %v", err)
	}
	ejecting, err := committer.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateCommit that removes the receiver: %v", err)
	}
	staged, err := receiver.ProcessMessage(ejecting.Commit)
	if err != nil {
		t.Fatalf("ProcessMessage of the removing commit: %v", err)
	}
	if !staged.Commit.RemovesSelf() {
		t.Fatal("the staged commit of the epoch arm does not remove the member that staged it, so the ordering it exists to observe is not reachable")
	}
	if laggard.Epoch() >= staged.Commit.Epoch() {
		t.Fatalf("the laggard is at epoch %d and the removing commit opens epoch %d, so this arm is not the stale one",
			laggard.Epoch(), staged.Commit.Epoch())
	}

	authenticatorBefore = bytes.Clone(laggard.EpochAuthenticator())
	if len(authenticatorBefore) == 0 {
		t.Fatal("the laggard answers no epoch authenticator before the call, so this arm cannot tell a closed group from a live one")
	}
	if err := laggard.ApplyCommit(staged); !errors.Is(err, errApplyCommitNotThisEpochs) {
		t.Fatalf("ApplyCommit of a removing commit staged against another epoch = %v, want errApplyCommitNotThisEpochs", err)
	}
	if !bytes.Equal(laggard.EpochAuthenticator(), authenticatorBefore) {
		t.Fatal("a removing commit staged against an epoch this group is not in destroyed its epoch; the removal arm is being read before the epoch comparison")
	}
	if _, err := laggard.Protect(nil, []byte("still a member")); err != nil {
		t.Fatalf("the laggard cannot protect a message after refusing a stale removing commit: %v", err)
	}
}

// TestApplyCommitRefusesAStagedCommitWhoseKeyMaterialHasBeenErased is the second measurement, and it
// is reached through the exported API alone: Processed and its Commit field are exported, Zeroize is
// exported, and connect/message is documented as holding Processed values across a policy decision.
//
// WHAT THE ERASED VALUE STILL ANSWERS is the whole reason the door needed a new flag. Zeroize erases
// the key schedule, the secret tree, the leaf private state and the update path plan; the group id,
// the prior epoch, the epoch and the removal flag are not key material and survive it untouched. So
// the provenance pair -- the only thing this door read -- agrees over an erased commit exactly as it
// agrees over a live one.
//
// AND THE SYMPTOM IS THE FORK DETECTOR. Two members that each took this path would install two erased
// key schedules and answer the same 32 zero bytes for the epoch authenticator, which is the value the
// product compares to decide whether two devices are in the same epoch. The second half of this case
// is that comparison, run over two groups that have nothing in common.
func TestApplyCommitRefusesAStagedCommitWhoseKeyMaterialHasBeenErased(t *testing.T) {
	crypto := testCrypto(t)
	committerA, receiverA, _, _, _ := testTwoMemberGroupNamed(t, crypto, "erased-staged-a")
	defer committerA.Close()
	defer receiverA.Close()
	committerB, receiverB, _, _, _ := testTwoMemberGroupNamed(t, crypto, "erased-staged-b")
	defer committerB.Close()
	defer receiverB.Close()

	erasedAt := func(t *testing.T, committer *Group, receiver *Group) *Processed {
		t.Helper()
		result, err := committer.CreateCommit(nil, nil, nil)
		if err != nil {
			t.Fatalf("CreateCommit: %v", err)
		}
		processed, err := receiver.ProcessMessage(result.Commit)
		if err != nil {
			t.Fatalf("ProcessMessage: %v", err)
		}
		// the control: while it is live the staged commit answers the epoch it opens.
		if live := processed.Commit.EpochAuthenticator(); len(live) != crypto.HashSize() {
			t.Fatalf("the live staged commit answers %d octets for its epoch authenticator, want %d",
				len(live), crypto.HashSize())
		}
		processed.Commit.Zeroize()
		return processed
	}

	processedA := erasedAt(t, committerA, receiverA)
	// an erased staged commit answers NOTHING rather than the zero bytes its erased schedule holds.
	// Without that, the two groups below compare equal on a value both of them made up.
	if authenticator := processedA.Commit.EpochAuthenticator(); authenticator != nil {
		t.Errorf("an erased staged commit answers %x for its epoch authenticator, want nothing", authenticator)
	}

	epochBefore := receiverA.Epoch()
	authenticatorBefore := bytes.Clone(receiverA.EpochAuthenticator())
	if err := receiverA.ApplyCommit(processedA); !errors.Is(err, errStagedCommitErased) {
		t.Fatalf("ApplyCommit of an erased staged commit = %v, want errStagedCommitErased", err)
	}
	if receiverA.Epoch() != epochBefore {
		t.Fatalf("the refused ApplyCommit moved the receiver from epoch %d to %d", epochBefore, receiverA.Epoch())
	}
	if !bytes.Equal(receiverA.EpochAuthenticator(), authenticatorBefore) {
		t.Fatal("the refused ApplyCommit changed the receiver's epoch authenticator")
	}
	// and it left no staged commit behind, which is what would block every later commit this member
	// makes with ErrPendingCommitExists.
	if _, err := receiverA.CreateCommit(nil, nil, nil); err != nil {
		t.Fatalf("the receiver cannot commit after refusing an erased staged commit: %v", err)
	}
	receiverA.ClearPendingCommit()

	processedB := erasedAt(t, committerB, receiverB)
	if err := receiverB.ApplyCommit(processedB); !errors.Is(err, errStagedCommitErased) {
		t.Fatalf("group B ApplyCommit of an erased staged commit = %v, want errStagedCommitErased", err)
	}
	// the symptom, stated over the two groups rather than over the door: two members that both took
	// this path used to answer one epoch authenticator, and answering one is what the product reads
	// as "these two devices have not forked".
	if bytes.Equal(receiverA.EpochAuthenticator(), receiverB.EpochAuthenticator()) {
		t.Fatal("two members of two unrelated groups answer one epoch authenticator after each was handed an erased staged commit")
	}
}

// TestMergePendingCommitRefusesAStagedCommitWhoseKeyMaterialHasBeenErased is the SECOND door of the
// same rule, and it is here because the rule is about installing a staged epoch rather than about the
// method a caller happens to call. ApplyCommit reaches live state through this method, so a guard
// written only at ApplyCommit is a guard that holds for the callers somebody enumerated.
//
// The pending commit is reached through the group's own field because no exported API hands a caller
// its own pending StagedCommit today. That is what makes this the door rather than the case: a
// CommitResult that ever carries one -- and the type is exported, with an exported Zeroize -- turns
// this into a caller shape overnight, and the refusal is already standing there.
func TestMergePendingCommitRefusesAStagedCommitWhoseKeyMaterialHasBeenErased(t *testing.T) {
	crypto := testCrypto(t)
	group, joined, _, _, _ := testTwoMemberGroupNamed(t, crypto, "erased-pending")
	defer group.Close()
	defer joined.Close()

	if _, err := group.CreateCommit(nil, nil, nil); err != nil {
		t.Fatalf("CreateCommit: %v", err)
	}
	epochBefore := group.Epoch()
	authenticatorBefore := bytes.Clone(group.EpochAuthenticator())
	group.stateLock.Lock()
	group.pending.Zeroize()
	group.stateLock.Unlock()

	if err := group.MergePendingCommit(); !errors.Is(err, errStagedCommitErased) {
		t.Fatalf("MergePendingCommit over an erased pending commit = %v, want errStagedCommitErased", err)
	}
	if group.Epoch() != epochBefore {
		t.Fatalf("the refused merge moved the group from epoch %d to %d", epochBefore, group.Epoch())
	}
	if !bytes.Equal(group.EpochAuthenticator(), authenticatorBefore) {
		t.Fatal("the refused merge changed the group's epoch authenticator, so an erased epoch was installed")
	}
	// the pending commit is LEFT WHERE IT IS rather than dropped, which is what every other refusal
	// of that method does: what to do with a staged epoch this group could not enter is the caller's
	// decision, through ClearPendingCommit.
	if _, err := group.CreateCommit(nil, nil, nil); !errors.Is(err, ErrPendingCommitExists) {
		t.Fatalf("CreateCommit after the refused merge = %v, want ErrPendingCommitExists", err)
	}
	group.ClearPendingCommit()
}

// TestApplyCommitReadsTheEraseFlagBeforeTheRemovalArm is the ORDERING of the refusal above, and it is
// here because the case above cannot see it: both of its staged commits remove nobody, so an erase
// check moved below the RemovesSelf arm leaves it green.
//
// It is the same defect this file's first case is about, one refusal along, and it was found by
// running that defect's own class over this change. A staged commit that removes this client and has
// then been ERASED is a value whose removal flag is intact -- selfRemoved is not key material and
// survives Zeroize -- so a door that read the flag first would Close the group, erase its schedule,
// its secret tree, its leaf state and its signing key, and answer ErrRemovedFromGroup out of a value
// that carries no key material at all. What the caller learns is that it was removed; what actually
// happened is that it handed back a value it had already erased.
func TestApplyCommitReadsTheEraseFlagBeforeTheRemovalArm(t *testing.T) {
	crypto := testCrypto(t)
	committer, receiver, processed := testRemovingStagedCommit(t, crypto, "erased-removal-order")
	defer committer.Close()
	defer receiver.Close()

	processed.Commit.Zeroize()
	if !processed.Commit.RemovesSelf() {
		t.Fatal("the erase cleared the removal flag, so this case can no longer tell the two arms apart")
	}
	authenticatorBefore := bytes.Clone(receiver.EpochAuthenticator())
	if len(authenticatorBefore) == 0 {
		t.Fatal("the receiver answers no epoch authenticator before the call, so this case cannot tell a closed group from a live one")
	}
	if err := receiver.ApplyCommit(processed); !errors.Is(err, errStagedCommitErased) {
		t.Fatalf("ApplyCommit of an erased removing commit = %v, want errStagedCommitErased", err)
	}
	if !bytes.Equal(receiver.EpochAuthenticator(), authenticatorBefore) {
		t.Fatal("an ERASED staged commit closed the group; the removal arm is being read before the erase flag")
	}
	if _, err := receiver.Protect(nil, []byte("not removed by an erased value")); err != nil {
		t.Fatalf("the receiver cannot protect a message after refusing an erased removing commit: %v", err)
	}
}
