// The provenance a staged commit carries, and the door that reads it.
//
// (*Group).ApplyCommit checked the Kind, the nil, the closed flag and RemovesSelf and NOTHING about
// where the commit it was handed came from. Measured, by deleting the two refusals this file exists
// for and running the first case below: two independent groups A and B, and receiverB.ApplyCommit
// given a Processed receiverA had staged answered nil, moved B out of epoch 1 into the epoch A's
// commit opened, and left the two groups answering one epoch authenticator. Processed and its Commit
// field are exported and connect/message holds Processed values across a policy decision, so two
// groups' results are two values of one type in one caller's hands: this is the expected caller
// shape rather than a contrived one.
package mls

import (
	"bytes"
	"errors"
	"go/ast"
	"slices"
	"testing"
)

// TestApplyCommitRefusesACommitAnotherGroupStaged is the measurement above, run as a test.
//
// TWO GROUPS WITH DIFFERENT IDS, which the fixture has to be asked for: every group this client is
// a member of runs an epoch 1, so two groups sharing an id would let this pass on the epoch check
// and say nothing about the group one.
func TestApplyCommitRefusesACommitAnotherGroupStaged(t *testing.T) {
	crypto := testCrypto(t)
	committerA, receiverA, _, _, _ := testTwoMemberGroupNamed(t, crypto, "provenance-a")
	defer committerA.Close()
	defer receiverA.Close()
	committerB, receiverB, _, _, _ := testTwoMemberGroupNamed(t, crypto, "provenance-b")
	defer committerB.Close()
	defer receiverB.Close()

	result, err := committerA.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("group A CreateCommit: %v", err)
	}
	processed, err := receiverA.ProcessMessage(result.Commit)
	if err != nil {
		t.Fatalf("group A ProcessMessage: %v", err)
	}

	epochBefore := receiverB.Epoch()
	authenticatorBefore := bytes.Clone(receiverB.EpochAuthenticator())
	if err := receiverB.ApplyCommit(processed); !errors.Is(err, errApplyCommitNotThisGroups) {
		t.Fatalf("group B ApplyCommit over group A's staged commit = %v, want errApplyCommitNotThisGroups", err)
	}
	if receiverB.Epoch() != epochBefore {
		t.Fatalf("the refused ApplyCommit moved group B from epoch %d to epoch %d", epochBefore, receiverB.Epoch())
	}
	if !bytes.Equal(receiverB.EpochAuthenticator(), authenticatorBefore) {
		t.Fatal("the refused ApplyCommit changed group B's epoch authenticator")
	}
	// and the two groups still do not agree on an authenticator, which is the symptom itself rather
	// than the refusal: an adopted epoch is one B derived out of A's key schedule.
	if err := receiverA.ApplyCommit(processed); err != nil {
		t.Fatalf("group A's own receiver could not apply its own staged commit: %v", err)
	}
	if bytes.Equal(receiverA.EpochAuthenticator(), receiverB.EpochAuthenticator()) {
		t.Fatal("two independent groups answer one epoch authenticator")
	}
	// B is unharmed rather than merely unmoved: it still ingests its own peer's commits.
	resultB, err := committerB.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("group B CreateCommit after the refusal: %v", err)
	}
	processedB, err := receiverB.ProcessMessage(resultB.Commit)
	if err != nil {
		t.Fatalf("group B ProcessMessage after the refusal: %v", err)
	}
	if err := receiverB.ApplyCommit(processedB); err != nil {
		t.Fatalf("group B ApplyCommit of its own peer's commit after the refusal: %v", err)
	}
}

// TestApplyCommitRefusesACommitStagedAgainstAnotherEpoch is the other half of the binding, in BOTH
// directions -- an epoch this group has already left and an epoch it has not reached -- because a
// rule written as one comparison is one edit away from being written as an inequality, and a case
// for one direction alone cannot tell the two apart.
func TestApplyCommitRefusesACommitStagedAgainstAnotherEpoch(t *testing.T) {
	crypto := testCrypto(t)
	committer, receiver, _, _, material := testTwoMemberGroupNamed(t, crypto, "provenance-epoch")
	defer committer.Close()
	defer receiver.Close()

	// a SECOND view of this same group at the epoch the welcome describes, which is what makes the
	// forward direction observable: it holds the group id the binding compares and sits at an epoch
	// the staged commits below are not staged against.
	laggard, err := material.join(t, nil)
	if err != nil {
		t.Fatalf("the second join this case lags with: %v", err)
	}
	defer laggard.Close()

	first, err := committer.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("the first CreateCommit: %v", err)
	}
	staged, err := receiver.ProcessMessage(first.Commit)
	if err != nil {
		t.Fatalf("the first ProcessMessage: %v", err)
	}
	if err := receiver.ApplyCommit(staged); err != nil {
		t.Fatalf("the first ApplyCommit: %v", err)
	}
	if err := committer.MergePendingCommit(); err != nil {
		t.Fatalf("the first MergePendingCommit: %v", err)
	}

	// BACKWARD: the same value handed back after it was applied. It is the caller shape this whole
	// binding is about -- a Processed held across a policy decision -- and without the binding the
	// second call reinstalls an epoch whose key material this group has already taken ownership of.
	if err := receiver.ApplyCommit(staged); !errors.Is(err, errApplyCommitNotThisEpochs) {
		t.Fatalf("ApplyCommit of an already applied commit = %v, want errApplyCommitNotThisEpochs", err)
	}
	if receiver.Epoch() != committer.Epoch() {
		t.Fatalf("the replayed ApplyCommit moved the receiver to epoch %d, committer at %d",
			receiver.Epoch(), committer.Epoch())
	}

	// FORWARD: a commit staged against an epoch the laggard has not reached.
	second, err := committer.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("the second CreateCommit: %v", err)
	}
	ahead, err := receiver.ProcessMessage(second.Commit)
	if err != nil {
		t.Fatalf("the second ProcessMessage: %v", err)
	}
	if laggard.Epoch() >= ahead.Commit.Epoch() {
		t.Fatalf("the laggard is at epoch %d and the staged commit opens epoch %d, so this arm is not the forward one",
			laggard.Epoch(), ahead.Commit.Epoch())
	}
	authenticatorBefore := bytes.Clone(laggard.EpochAuthenticator())
	if err := laggard.ApplyCommit(ahead); !errors.Is(err, errApplyCommitNotThisEpochs) {
		t.Fatalf("ApplyCommit of a commit staged two epochs on = %v, want errApplyCommitNotThisEpochs", err)
	}
	if !bytes.Equal(laggard.EpochAuthenticator(), authenticatorBefore) {
		t.Fatal("the refused ApplyCommit moved the laggard's epoch")
	}
}

// TestEveryStagedCommitCarriesTheGroupAndEpochThatStagedIt is the gate over the CLASS rather than
// over the two doors this task closed: a staged commit built anywhere in this package without its
// provenance is a value ApplyCommit clears by comparing two zero values, and the site that builds
// one need not be one of the three that exist today.
//
// DERIVED off the source rather than counted: every composite literal of the type in every
// production file, whatever function it stands in. A construction spelled some other way --
// new(StagedCommit), or a positional literal -- is refused outright rather than skipped, because it
// is a construction this rule cannot read and a rule that cannot read a construction clears it.
func TestEveryStagedCommitCarriesTheGroupAndEpochThatStagedIt(t *testing.T) {
	required := []string{"groupId", "priorEpoch"}
	found := 0
	for _, parsed := range parsedProductionSourcesOfThisPackage(t) {
		ast.Inspect(parsed.file, func(node ast.Node) bool {
			if call, isCall := node.(*ast.CallExpr); isCall {
				if name, isIdent := call.Fun.(*ast.Ident); isIdent && name.Name == "new" &&
					len(call.Args) == 1 && parsed.render(call.Args[0]) == "StagedCommit" {
					t.Errorf("%s builds a StagedCommit through new(), which this rule cannot read; build it as a keyed composite literal so its provenance is visible here",
						parsed.fileSet.Position(call.Pos()))
				}
				return true
			}
			literal, isLiteral := node.(*ast.CompositeLit)
			if !isLiteral || literal.Type == nil || parsed.render(literal.Type) != "StagedCommit" {
				return true
			}
			found += 1
			named := []string{}
			for _, element := range literal.Elts {
				pair, isPair := element.(*ast.KeyValueExpr)
				if !isPair {
					t.Errorf("%s builds a StagedCommit positionally, so this rule cannot say which field is which",
						parsed.fileSet.Position(element.Pos()))
					continue
				}
				named = append(named, parsed.render(pair.Key))
			}
			for _, want := range required {
				if !slices.Contains(named, want) {
					t.Errorf("%s stages a commit without %s; ApplyCommit compares that field against the group it is handed to, and a zero one is a commit any group at epoch 0 adopts",
						parsed.fileSet.Position(literal.Pos()), want)
				}
			}
			return true
		})
	}
	if found == 0 {
		t.Fatal("no StagedCommit literal was found in this package's production source, so this rule demanded nothing")
	}
	t.Logf("%d StagedCommit construction site(s), each carrying %v", found, required)
}
