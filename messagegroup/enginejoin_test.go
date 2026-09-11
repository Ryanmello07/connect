// The first standing proof in either tree of "two clients, one group".
//
// It is named enginejoin_test.go and not join_test.go on purpose: another plan's file block
// already claims join_test.go in this package, and two plans creating one file is how a
// dispatched task discovers a merge.
//
// WHAT THIS FILE DOES NOT ESTABLISH IS STATED IN ITS OWN TEST, in three sentences the gate at the
// bottom asserts are present. An absence that is named is safe and an absence that looks like a
// placeholder is not, and a file that proves two clients share a group and does not say those
// three things is a file the next reader will cite as the milestone.
package messagegroup

import (
	"bytes"
	"go/ast"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls"
)

// The exporter label and length the whole claim rests on. It is MASTER section 7's mls_secret:
// the value GroupSession.installEpochOnLoop reads to build every key of the record layer, so two
// members that disagree here disagree about every record either of them will ever seal.
const engineJoinExporterLabel = "URmessage/v1/storage"

const engineJoinExporterLength = 32

// TestTwoEnginesShareOneGroupAndTheirExportersAgree is the whole claim of j1's CP3b prefix.
//
// THE CHAIN: A CreateGroup; B NewKeyPackage; A ProposeAdd(kpB); A Commit(nil) answering a
// non-empty commit, welcome and ratchet tree; A MergePendingCommit; B JoinFromWelcome.
//
// FIVE CLAUSES, AND THE EXPORTER IS THE PROPERTY WHILE THE OTHER FOUR ARE ITS PRECONDITIONS.
// Group id, epoch and member count agree between a joiner that really joined and a joiner that
// built plausible state out of a Welcome it mis-derived; the exported secret does not.
//
// Commit(nil) is what produces the Welcome: connect/mls's nil arm commits every cached proposal,
// and ProposeAdd caches locally, so no new seam method is needed for the founder to answer one.
// An empty non-nil vector commits NOTHING and is a hazard this file names rather than relies on.
func TestTwoEnginesShareOneGroupAndTheirExportersAgree(t *testing.T) {
	a := newTestEngine(t)
	b := newTestEngine(t)

	keyPackage, err := b.engine.NewKeyPackage()
	if err != nil {
		t.Fatalf("B's NewKeyPackage: %v", err)
	}
	founder := a.createGroup(t, "two-clients-one-group")
	defer founder.Close()

	if _, err := founder.ProposeAdd(keyPackage); err != nil {
		t.Fatalf("A's ProposeAdd over B's key package: %v", err)
	}
	commit, welcome, ratchetTree, err := founder.Commit(nil)
	if err != nil {
		t.Fatalf("A's Commit(nil): %v", err)
	}
	t.Logf("the founder's commit answered commit=%d welcome=%d ratchetTree=%d octets",
		len(commit), len(welcome), len(ratchetTree))
	if len(commit) == 0 || len(welcome) == 0 || len(ratchetTree) == 0 {
		t.Fatalf("the commit answered commit=%d welcome=%d ratchetTree=%d and every one of the three has to carry octets",
			len(commit), len(welcome), len(ratchetTree))
	}
	if err := founder.MergePendingCommit(); err != nil {
		t.Fatalf("A's MergePendingCommit: %v", err)
	}

	joined, err := b.engine.JoinFromWelcome(welcome, ratchetTree)
	if err != nil {
		t.Fatalf("B's JoinFromWelcome: %v", err)
	}
	defer joined.Close()

	if !bytes.Equal(joined.GroupId(), founder.GroupId()) {
		t.Errorf("B is in group %x and A is in %x", joined.GroupId(), founder.GroupId())
	}
	if joined.Epoch() != founder.Epoch() {
		t.Errorf("B is at epoch %d and A is at %d", joined.Epoch(), founder.Epoch())
	}
	if count := founder.MemberCount(); count != 2 {
		t.Errorf("A sees %d members, want 2", count)
	}
	if count := joined.MemberCount(); count != 2 {
		t.Errorf("B sees %d members, want 2", count)
	}
	// each finds the OTHER's identity, which is what says the two handles describe one membership
	// rather than two groups that happen to agree on a count
	engineJoinAssertFinds(t, "A", founder, b.identityPub)
	engineJoinAssertFinds(t, "B", joined, a.identityPub)

	// THE CLAUSE THAT IS THE PROPERTY.
	founderSecret, err := founder.Export(engineJoinExporterLabel, nil, engineJoinExporterLength)
	if err != nil {
		t.Fatalf("A's Export: %v", err)
	}
	joinedSecret, err := joined.Export(engineJoinExporterLabel, nil, engineJoinExporterLength)
	if err != nil {
		t.Fatalf("B's Export: %v", err)
	}
	t.Logf("both handles export %x under %q at epoch %d with %d members",
		founderSecret, engineJoinExporterLabel, founder.Epoch(), founder.MemberCount())
	if !bytes.Equal(founderSecret, joinedSecret) {
		t.Errorf("A exports %x and B exports %x under %q; two members that disagree here disagree about every record either of them will ever seal",
			founderSecret, joinedSecret, engineJoinExporterLabel)
	}
	if len(founderSecret) != engineJoinExporterLength {
		t.Errorf("the exporter answered %d octets, want %d", len(founderSecret), engineJoinExporterLength)
	}

	// AND THE DEVICE SURVIVED ITS OWN JOIN, read through the ratchet tree and NEVER through
	// MemberAt: MemberAt answers Credential.Identity, which a destroyed signing key does not
	// touch, and this whole chain is green over an engine B whose identity was erased by its own
	// join. A second key package and a second group are the admissible observation.
	afterJoin, err := b.engine.NewKeyPackage()
	if err != nil {
		t.Fatalf("B's NewKeyPackage after the join: %v", err)
	}
	if named := engineKeyPackageLeafKeyOf(t, afterJoin); !bytes.Equal(named, b.signerPub) {
		t.Errorf("B's key package after the join names %x and B signs with %x; the join destroyed the device's identity",
			named, b.signerPub)
	}
	second := b.createGroup(t, "b-founds-after-joining")
	defer second.Close()
	if named, _ := engineLeafKeyOf(t, second, second.OwnLeafIndex()); !bytes.Equal(named, b.signerPub) {
		t.Errorf("a group B founds after the join names %x at leaf 0 and B signs with %x", named, b.signerPub)
	}
}

// engineJoinAssertFinds walks a handle's membership and requires it to carry one identity.
func engineJoinAssertFinds(t *testing.T, who string, handle GroupHandle, identityPub []byte) {
	t.Helper()
	for at := 0; at < handle.MemberCount(); at += 1 {
		_, found, _, err := handle.MemberAt(at)
		if err != nil {
			t.Fatalf("%s's MemberAt(%d): %v", who, at, err)
		}
		if bytes.Equal(found, identityPub) {
			return
		}
	}
	t.Errorf("%s's membership does not carry the identity %x", who, identityPub)
}

// TestTheTwoEnginesOfAJoinShareNoState is j1 task 6's second property, and the gate PROVES it
// rather than arranging it.
//
// Two providers, two stores, two signers, two credentials, two leaf-keys bodies. THE REASON THIS
// MUTANT IS SOUND IS NOT THE OBVIOUS ONE, and the obvious one is wrong: a shared store does NOT
// make the exporter equality a tautology. Export delegates to the group's epoch key schedule, held
// IN MEMORY by two distinct groups; the store is written by persist and read only by LoadGroup,
// which has zero callers outside connect/mls's own tests. So the first property going on passing
// under one store would prove nothing about the exporter -- and what a shared store DOES break is
// this property's own observation: that B's store holds no group state before the join and A's is
// unchanged by it.
func TestTheTwoEnginesOfAJoinShareNoState(t *testing.T) {
	a := newTestEngine(t)
	b := newTestEngine(t)
	if a.store == b.store {
		t.Fatal("the two engines were built over one store, so every observation below is about one device")
	}
	if bytes.Equal(a.signerPub, b.signerPub) || bytes.Equal(a.identityPub, b.identityPub) ||
		bytes.Equal(a.leafKeys, b.leafKeys) {
		t.Fatal("the two engines share a signer, a credential or a leaf keys body, so they are one device wearing two names")
	}

	keyPackage, err := b.engine.NewKeyPackage()
	if err != nil {
		t.Fatalf("B's NewKeyPackage: %v", err)
	}
	founder := a.createGroup(t, "no-shared-state")
	defer founder.Close()
	if _, err := founder.ProposeAdd(keyPackage); err != nil {
		t.Fatalf("A's ProposeAdd: %v", err)
	}
	_, welcome, ratchetTree, err := founder.Commit(nil)
	if err != nil {
		t.Fatalf("A's Commit(nil): %v", err)
	}
	if err := founder.MergePendingCommit(); err != nil {
		t.Fatalf("A's MergePendingCommit: %v", err)
	}

	if held := len(b.store.groupStates); held != 0 {
		t.Errorf("B's store holds %d group states BEFORE the join; a joiner that read the founder's state would make this whole file a tautology", held)
	}
	founderStates := len(a.store.groupStates)
	if founderStates == 0 {
		t.Fatal("A's store holds no group state after founding and committing, so the comparison below observes nothing")
	}

	joined, err := b.engine.JoinFromWelcome(welcome, ratchetTree)
	if err != nil {
		t.Fatalf("B's JoinFromWelcome: %v", err)
	}
	defer joined.Close()

	if held := len(b.store.groupStates); held != 1 {
		t.Errorf("B's store holds %d group states after the join, want exactly 1", held)
	}
	if held := len(a.store.groupStates); held != founderStates {
		t.Errorf("A's store held %d group states before B joined and %d after; B's join wrote into the founder's store",
			founderStates, held)
	}
}

// TestTheFounderHalfAnswersARealWelcomeThroughTheSeam is j1 task 6's third property, and the
// CONTROL is what keeps its first clause from passing on any non-empty byte slice.
//
// Nothing in this package had ever produced a Welcome before this file: the four GroupHandle.Commit
// sites in these tests all commit a one-member group with no proposals -- the only kind either
// group can make -- and every one of them discards welcome and ratchetTree into _.
//
// THE RELATED OVERLOAD THIS FILE DOES NOT RELY ON AND DOES NOT FIX: Commit with an empty non-nil
// vector commits nothing and silently answers an empty commit with a nil Welcome, and ProposeAdd
// answers the encoded proposal MESSAGE rather than a ref, so there is no way through this seam to
// obtain a value for the by-reference vector at all. This file uses the nil arm and says why.
func TestTheFounderHalfAnswersARealWelcomeThroughTheSeam(t *testing.T) {
	a := newTestEngine(t)
	b := newTestEngine(t)
	founder := a.createGroup(t, "a-real-welcome")
	defer founder.Close()

	// THE CONTROL FIRST: a commit with no pending proposal answers a NIL welcome, which is the
	// documented shape. Without it "the welcome is non-empty" is satisfied by any byte slice this
	// seam happens to answer.
	commit, welcome, ratchetTree, err := founder.Commit(nil)
	if err != nil {
		t.Fatalf("Commit(nil) with no pending proposal: %v", err)
	}
	if len(commit) == 0 {
		t.Error("a commit with no pending proposal answered no commit message")
	}
	if welcome != nil {
		t.Errorf("a commit with no pending proposal answered a %d octet welcome; a group of one admits nobody and there is nothing for a welcome to be addressed to",
			len(welcome))
	}
	if len(ratchetTree) == 0 {
		t.Error("a commit with no pending proposal answered no ratchet tree")
	}
	if err := founder.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}

	// and then the real one
	keyPackage, err := b.engine.NewKeyPackage()
	if err != nil {
		t.Fatalf("B's NewKeyPackage: %v", err)
	}
	if _, err := founder.ProposeAdd(keyPackage); err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	commit, welcome, ratchetTree, err = founder.Commit(nil)
	if err != nil {
		t.Fatalf("Commit(nil) after a ProposeAdd: %v", err)
	}
	if len(commit) == 0 || len(welcome) == 0 || len(ratchetTree) == 0 {
		t.Fatalf("a commit carrying one add answered commit=%d welcome=%d ratchetTree=%d",
			len(commit), len(welcome), len(ratchetTree))
	}
	// and it is a Welcome rather than some octets: it parses, it carries a welcome arm, and the
	// arm is addressed to exactly one joiner
	parsed, err := mls.ParseMLSMessage(welcome)
	if err != nil {
		t.Fatalf("the welcome this seam answered does not parse: %v", err)
	}
	if parsed.Welcome == nil {
		t.Fatal("the message this seam answered carries no welcome arm")
	}
	if addressed := len(parsed.Welcome.Secrets); addressed != 1 {
		t.Errorf("the welcome is addressed to %d joiners, want 1", addressed)
	}
}

// engineJoinImpossibilityPhrases are the sentences a reader would re-derive the wrong fix from.
//
// The class the honesty gate below derives is PRODUCTION SENTENCES THAT SAY A JOIN IS IMPOSSIBLE,
// and "a sentence" is operationalised as a comment or a string literal that names one of the two
// identifiers AND carries one of these phrases. The narrowing is here rather than implied, because
// after j1 task 5 this package's production source names TakeKeyPackage legitimately -- the join
// body CALLS it, and four paragraphs describe what it costs -- so the plan's own published query,
// a grep for those two identifiers over non-test source, no longer answers this class. That query
// returned SIX at a1f8025 and every one of the six was an impossibility sentence; it returns more
// than six now and none of them is.
//
// THE SENTINEL'S SPELLING IS ASSEMBLED AND NEVER WRITTEN, here and below, for the reason the
// framing gate at the bottom of this file gives about its own needles: this package's definition
// of done requires a grep for that identifier over every .go file of the tree to return NOTHING,
// and a gate that searches for a name by writing it down is a gate that answers itself.
var engineJoinImpossibilityPhrases = []string{
	"cannot join",
	"does not carry it",
	"cannot be written over",
	"cannot assemble",
	"does not publish the joiner",
	"is not reachable",
}

// The two identifiers the class is read over.
var engineJoinImpossibilityNames = []string{"TakeKeyPackage", engineJoinSentinelName}

// The sentinel j1 task 5 removed, assembled rather than spelled. See above.
var engineJoinSentinelName = "ErrEngineJoin" + "Unavailable"

// TestNoProductionSentenceOfThisPackageSaysAJoinIsImpossible is j1 task 6's fourth property.
//
// Three statements said so at a1f8025 and the plan named three; the query it published answers SIX,
// every one of them in a file some task of this plan already edits -- so the WORK was scheduled and
// only the NUMBER was wrong, which is exactly how a count that is not a query fails. This gate
// derives its class and PRINTS BOTH SETS, so a seventh written next month fails on the commit that
// adds it.
//
// THE COMPLEMENT IS PRINTED AND IS NOT EMPTY: the production sentences that name TakeKeyPackage and
// say something TRUE about it -- where the ref comes from, what the destructive take costs, what
// its bare error cannot express -- plus the executable call the join body makes. A gate that
// removed the identifier rather than the claim would have taken those with it.
func TestNoProductionSentenceOfThisPackageSaysAJoinIsImpossible(t *testing.T) {
	fileSet, sources := messagegroupProductionSources(t)
	impossible := []string{}
	complement := []string{}
	executable := []string{}
	for _, source := range sources {
		at := func(node ast.Node) string {
			return source.path + ":" + engineJoinLineOf(fileSet, node)
		}
		for _, group := range source.parsed.Comments {
			for _, line := range group.List {
				if !engineJoinNamesOne(line.Text) {
					continue
				}
				if engineJoinAssertsImpossibility(line.Text) {
					impossible = append(impossible, at(line)+" "+strings.TrimSpace(line.Text))
				} else {
					complement = append(complement, at(line))
				}
			}
		}
		ast.Inspect(source.parsed, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.BasicLit:
				if !engineJoinNamesOne(typed.Value) {
					return true
				}
				if engineJoinAssertsImpossibility(typed.Value) {
					impossible = append(impossible, at(typed)+" "+typed.Value)
				} else {
					complement = append(complement, at(typed))
				}
			case *ast.Ident:
				if typed.Name == engineJoinSentinelName {
					impossible = append(impossible, at(typed)+" the sentinel itself")
				}
			case *ast.SelectorExpr:
				if typed.Sel.Name == "TakeKeyPackage" {
					executable = append(executable, at(typed))
				}
			}
			return true
		})
	}
	t.Logf("production sentences asserting a join is impossible: %d %v", len(impossible), impossible)
	t.Logf("the complement, printed: %d production sentence(s) naming %v that assert nothing of the kind, and %d executable call site(s) %v",
		len(complement), engineJoinImpossibilityNames, len(executable), executable)
	if len(impossible) != 0 {
		t.Errorf("%d production statement(s) of this package still say a join is impossible: %v. It is not: this engine mints under its own signer and assembles the material a welcome join takes",
			len(impossible), impossible)
	}
	// fails closed: a gate whose complement is empty is one that removed the identifier rather
	// than the claim, and it would report clean having read nothing
	if len(complement)+len(executable) == 0 {
		t.Error("no production reference to either name survives at all, so this gate cannot tell a package that removed the claim from one that removed the subject")
	}
	if len(executable) == 0 {
		t.Error("no production call site of TakeKeyPackage was found; the join body is what makes the sentences above false, and without it this gate is green over a package that simply deleted its comments")
	}
}

func engineJoinNamesOne(text string) bool {
	for _, name := range engineJoinImpossibilityNames {
		if strings.Contains(text, name) {
			return true
		}
	}
	return false
}

func engineJoinAssertsImpossibility(text string) bool {
	for _, phrase := range engineJoinImpossibilityPhrases {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

func engineJoinLineOf(fileSet *token.FileSet, node ast.Node) string {
	return strconv.Itoa(fileSet.Position(node.Pos()).Line)
}

// The three sentences j1 task 6's fifth property requires this file to carry, each keyed by a
// marker a gate can find. CP3b IS NOT REACHED BY THIS FILE, and that is the first of them.
//
//   - engineJoinDoesNotEstablish1: no record crosses between these two engines. NewGroupSession
//     refuses an empty pq_secret and there is no delivery channel for one. S2-3.
//   - engineJoinDoesNotEstablish2: the joiner cannot compute a sender_handle.
//     installEpochOnLoop refuses a handle at epoch greater than 0 that was given no
//     group_handle_key, and the carrier is deliberately deferred. M1-2.
//   - engineJoinDoesNotEstablish3: the welcome here is handed over as a VALUE IN ONE PROCESS,
//     which is ledger 44a's named, gated, test-only hand-off and not a delivery channel.
const engineJoinDoesNotEstablish1 = "no record crosses between these two engines: NewGroupSession refuses an empty pq_secret and there is no delivery channel for one (S2-3)"

const engineJoinDoesNotEstablish2 = "the joiner cannot compute a sender_handle: installEpochOnLoop refuses a handle at epoch > 0 that was given no group_handle_key, and the carrier is deferred (M1-2)"

const engineJoinDoesNotEstablish3 = "the welcome here is handed over as a value in one process, which is ledger 44a's named, gated, test-only hand-off and not a delivery channel"

// TestThisFileSaysWhatItDoesNotEstablish is j1 task 6's fifth property, held mechanically.
//
// A file that proves two clients share a group and does not say those three things is a file the
// next reader will cite as the milestone. CP3B IS NOT REACHED BY THIS TASK: three filed blockers
// stand after it and none of them is this plan's.
//
// It is a documentation property held by a gate for ledger 44a's own reason: an absence that is
// named is safe and an absence that looks like a placeholder is not.
func TestThisFileSaysWhatItDoesNotEstablish(t *testing.T) {
	source, err := os.ReadFile(engineJoinThisFile)
	if err != nil {
		t.Fatalf("read %s, which is the subject of this gate: %v", engineJoinThisFile, err)
	}
	text := string(source)
	// the gate reads the FILE and not the constants, because a constant this gate compared
	// against itself is a gate no deletion can make red
	// EVERY NEEDLE IS ASSEMBLED AND NOT WRITTEN, for the reason the one below it is: this gate
	// reads the file it is written in, so a literal needle is a needle that MATCHES ITSELF and the
	// gate stays green over a file whose three sentences have all been rewritten. Measured -- a
	// first version of this gate survived exactly that mutation.
	for _, owed := range []struct {
		what   string
		phrase string
	}{
		{what: "(1) no record crosses between these two engines -- S2-3", phrase: "no record " + "crosses between these two engines"},
		{what: "(2) the joiner cannot compute a sender handle -- M1-2", phrase: "cannot compute a " + "sender_handle"},
		{what: "(3) the welcome is handed over as a value in one process -- ledger 44a", phrase: "handed over as a " + "value in one process"},
		{what: "and that CP3b is NOT reached by this task", phrase: "CP3B IS NOT " + "REACHED BY THIS TASK"},
	} {
		if strings.Count(text, owed.phrase) == 0 {
			t.Errorf("%s says %s nowhere. This file proves two clients share a group, and a file that does that without saying what it does not establish is the file the next reader cites as the milestone",
				engineJoinThisFile, owed.what)
		}
	}
	// and the file must not have started trying to establish one of them
	// the needle is ASSEMBLED rather than written, because this gate reads the file it is written
	// in: a literal here would match itself and report the check as the defect.
	if strings.Contains(text, "NewGroupSession"+"(") {
		t.Errorf("%s constructs a GroupSession. It cannot: NewGroupSession refuses an empty pq_secret and installEpochOnLoop refuses a joiner at epoch > 0 that was given no group_handle_key -- and a test that reached for one has stopped saying what it does not establish and started trying to establish it",
			engineJoinThisFile)
	}
	t.Logf("what this file does NOT establish, and CP3b is not reached by it: (1) %s; (2) %s; (3) %s",
		engineJoinDoesNotEstablish1, engineJoinDoesNotEstablish2, engineJoinDoesNotEstablish3)
}

// The file this gate reads, spelled once. It is read off disk rather than embedded, so the gate
// reads what a reviewer will read.
const engineJoinThisFile = "enginejoin_test.go"
