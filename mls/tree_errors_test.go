// The gates over tree_errors.go: that the class judged below is the file's own, that no two
// of its errors answer for each other, and that the two which deliberately wrap a tree math
// sentinel are the only two that do.
//
// The plan's own test for this task is not here in the shape it was written, and the reason
// is a finding rather than a preference. It listed the thirteen names by hand, checked that
// no two carried the same message, and checked that each survived errors.Join. All three
// halves are weaker than they read:
//
//   - a hand written list is not the class. A fourteenth error declared in tree_errors.go and
//     left off the list is judged by nothing at all, and nothing fails. The count has the
//     wrong polarity for that: it fails on adding an error and remembering the list, and
//     stays quiet on adding one and forgetting it. So the class is derived from the file's
//     own declarations here and the list is held to it in both directions, which is what
//     TestKeyScheduleOwnedErrorsIsEveryDeclarationOfItsFile does for the key schedule's file.
//   - comparing MESSAGES does not see aliasing. The mutation this task was asked to survive
//     is a sentinel redeclared so two names wrap one underlying error, and
//     `ErrTreeHashMismatch = fmt.Errorf("...: %w", ErrParentHashMismatch)` carries a message
//     no other name carries while making errors.Is(ErrTreeHashMismatch, ErrParentHashMismatch)
//     true. Every caller branching on the pair then reads the wrong one as the right one, and
//     the plan's test passes. Measured, not supposed. The sweep below is over errors.Is in
//     both directions as well as over the messages.
//   - errors.Join(err, errors.New("context")) followed by errors.Is(joined, err) cannot fail
//     for any non-nil err. It is a property of errors.Join, asserted thirteen times, and it
//     says nothing about this file.
package mls

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
)

// treeErrorsFile is the single file this plan declares its non-ValSem errors in. Every class
// below is derived from that file rather than from the list, which is the difference between
// sweeping the class and sweeping a copy of it.
const treeErrorsFile = "tree_errors.go"

// treeMathErrorsFile is the wave 1 file whose two index sentinels this file's two index
// errors wrap. Its error class is derived from it for the same reason.
const treeMathErrorsFile = "tree_math.go"

// treeOwnedErrors is the thirteen the interface registry names as this plan's, keyed by the
// name each is declared under so the derivation below can compare the two sets by name.
//
// Nothing here is trusted: TestTreeOwnedErrorsIsEveryDeclarationOfItsFile holds this map to
// what tree_errors.go actually declares, in both directions.
var treeOwnedErrors = map[string]error{
	"ErrLeafIndexOutOfRange":      ErrLeafIndexOutOfRange,
	"ErrNodeIndexOutOfRange":      ErrNodeIndexOutOfRange,
	"ErrTreeMalformed":            ErrTreeMalformed,
	"ErrNodeTypeMismatch":         ErrNodeTypeMismatch,
	"ErrUnmergedLeavesNotSorted":  ErrUnmergedLeavesNotSorted,
	"ErrUnmergedLeafInconsistent": ErrUnmergedLeafInconsistent,
	"ErrParentHashMismatch":       ErrParentHashMismatch,
	"ErrTreeHashMismatch":         ErrTreeHashMismatch,
	"ErrLeafNodeSourceMismatch":   ErrLeafNodeSourceMismatch,
	"ErrLeafNodeLifetime":         ErrLeafNodeLifetime,
	"ErrLeafKeysExtensionInvalid": ErrLeafKeysExtensionInvalid,
	"ErrNoPathSecret":             ErrNoPathSecret,
	"ErrPathSecretMismatch":       ErrPathSecretMismatch,
}

// treeMathOwnedErrors is every error tree_math.go declares, which is the class the
// exclusivity sweep runs over.
//
// Held to that file's own Err-prefixed declarations below, so a tenth tree math sentinel
// cannot land outside this sweep: the whole point of the sweep is that a tree error must
// answer to exactly one of these or to none, and a class that stopped growing with the file
// would report a clean bill over the sentinel it had never heard of.
var treeMathOwnedErrors = map[string]error{
	"ErrLeafCountRange":    ErrLeafCountRange,
	"ErrLeafCountNotFull":  ErrLeafCountNotFull,
	"ErrNodeOutOfRange":    ErrNodeOutOfRange,
	"ErrLeafOutOfRange":    ErrLeafOutOfRange,
	"ErrNodeIsParent":      ErrNodeIsParent,
	"ErrLeafHasNoChildren": ErrLeafHasNoChildren,
	"ErrRootHasNoParent":   ErrRootHasNoParent,
	"ErrRootHasNoSibling":  ErrRootHasNoSibling,
	"ErrNodeWidthNotOdd":   ErrNodeWidthNotOdd,
}

// treeIndexWraps is the whole sanctioned wrapping relation between the two files: which of
// this file's errors may answer to which of tree math's, and no other pair may.
//
// Two entries and not a rule, because the sanction is a judgement about a pair rather than a
// property either name has. The file header carries the argument for each.
var treeIndexWraps = map[string]string{
	"ErrLeafIndexOutOfRange": "ErrLeafOutOfRange",
	"ErrNodeIndexOutOfRange": "ErrNodeOutOfRange",
}

// TestTreeOwnedErrorsIsEveryDeclarationOfItsFile derives the class every sweep below runs
// over instead of trusting the transcription of it.
//
// The derivation is every package level name the file declares, not every name that looks
// like an error, because that file holds nothing else by design and a name this gate cannot
// classify should be loud. A helper or a type landing there fails here too, which says either
// move it or widen the rule on purpose.
func TestTreeOwnedErrorsIsEveryDeclarationOfItsFile(t *testing.T) {
	declared := packageLevelDeclarations(t, ".")
	fromFile := map[string]bool{}
	for name, file := range declared {
		if file == treeErrorsFile {
			fromFile[name] = true
		}
	}
	if len(fromFile) == 0 {
		t.Fatalf("the scan found nothing declared in %s, so this gate compared the list against an empty set",
			treeErrorsFile)
	}
	if !fromFile["ErrTreeMalformed"] {
		t.Fatalf("the scan did not find ErrTreeMalformed among the declarations of %s, which certainly declares it, so it is reading something other than that file",
			treeErrorsFile)
	}
	for _, name := range slices.Sorted(maps.Keys(fromFile)) {
		if _, listed := treeOwnedErrors[name]; !listed {
			t.Errorf("%s declares %s and treeOwnedErrors does not list it, so neither the distinctness sweep nor the tree math exclusivity sweep judges it; add it there",
				treeErrorsFile, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(treeOwnedErrors)) {
		if !fromFile[name] {
			t.Errorf("treeOwnedErrors lists %s and %s does not declare it, so the sweeps run over a name this file does not own",
				name, treeErrorsFile)
		}
	}
}

// TestTreeMathOwnedErrorsIsEveryErrorItsFileDeclares is the same derivation over the other
// half of the exclusivity sweep.
//
// Err-prefixed rather than every declaration, because tree_math.go is 789 lines of arithmetic
// and its errors are one block of it. The prefix is the file's own naming convention, and a
// sentinel that broke it would be invisible here -- which is why the positive control below
// names one of the nine explicitly: a scan reading the wrong file, or a prefix filter matching
// nothing, reports the same clean bill as a complete one.
func TestTreeMathOwnedErrorsIsEveryErrorItsFileDeclares(t *testing.T) {
	declared := packageLevelDeclarations(t, ".")
	fromFile := map[string]bool{}
	for name, file := range declared {
		if file == treeMathErrorsFile && strings.HasPrefix(name, "Err") {
			fromFile[name] = true
		}
	}
	if !fromFile["ErrLeafOutOfRange"] {
		t.Fatalf("the scan did not find ErrLeafOutOfRange among the Err declarations of %s, which certainly declares it, so it is reading something other than that file",
			treeMathErrorsFile)
	}
	if got, want := slices.Sorted(maps.Keys(fromFile)), slices.Sorted(maps.Keys(treeMathOwnedErrors)); !slices.Equal(got, want) {
		t.Fatalf("%s declares %v and treeMathOwnedErrors holds %v; the exclusivity sweep below runs over the second, so a sentinel missing from it is one no tree error is held against",
			treeMathErrorsFile, got, want)
	}
}

// TestTreeErrorsAreDistinctAndNamed is the plan's test for this task, rewritten to be able to
// fail at the thing it is named after.
//
// Three properties per pair, and the first is the one the plan's version could not see:
// neither error may answer for the other under errors.Is in either direction, which is what a
// redeclaration or an accidental wrap actually looks like. The messages are compared as well,
// because two distinct values carrying one string are indistinguishable in a log; and each is
// required to be non-nil and non-empty, because a var that was declared and never assigned
// satisfies every comparison below by being nothing.
//
// The count pins the file: a name added to it is a change somebody makes deliberately, in the
// same commit, with a reason. What stops the list shrinking, and what stops it lagging behind
// the file, is TestTreeOwnedErrorsIsEveryDeclarationOfItsFile rather than this number.
func TestTreeErrorsAreDistinctAndNamed(t *testing.T) {
	if len(treeOwnedErrors) != 13 {
		t.Fatalf("this plan owns %d errors and the interface registry's tree_errors.go block names 13; if one landed or left, say so here in the same commit",
			len(treeOwnedErrors))
	}
	names := slices.Sorted(maps.Keys(treeOwnedErrors))
	for i, name := range names {
		first := treeOwnedErrors[name]
		if first == nil {
			t.Fatalf("%s is nil", name)
		}
		if first.Error() == "" {
			t.Fatalf("%s has an empty message", name)
		}
		if !strings.HasPrefix(first.Error(), "mls: ") {
			t.Errorf("%s reads %q; every typed error of this package names the package it came from, so a caller logging one at a distance can tell",
				name, first.Error())
		}
		for j, other := range names {
			if i == j {
				continue
			}
			second := treeOwnedErrors[other]
			if errors.Is(first, second) {
				t.Errorf("%s answers to %s (%v), so a caller branching on the two reads one as the other and nothing reports it",
					name, other, first)
			}
			if first.Error() == second.Error() {
				t.Errorf("%s and %s carry the same message %q, so a log cannot tell them apart",
					name, other, first.Error())
			}
		}
	}
}

// TestTheTwoTreeIndexErrorsWrapTheTreeMathSentinels is the positive half of the wrapping
// argument in the file header: a caller that only knows the arithmetic's sentinel still
// matches the ratchet tree's refusal of the same condition.
//
// Held over treeIndexWraps rather than written twice, so the pair the exclusivity sweep
// exempts and the pair asserted here are one list. A wrap sanctioned there and absent here
// would be an exemption granted to a relationship that does not exist.
func TestTheTwoTreeIndexErrorsWrapTheTreeMathSentinels(t *testing.T) {
	if len(treeIndexWraps) == 0 {
		t.Fatal("no wrap is sanctioned, so the exclusivity sweep below exempts nothing and this test asserts nothing")
	}
	for _, name := range slices.Sorted(maps.Keys(treeIndexWraps)) {
		wrapped := treeIndexWraps[name]
		outer, ok := treeOwnedErrors[name]
		if !ok {
			t.Fatalf("treeIndexWraps names %s and %s does not declare it", name, treeErrorsFile)
		}
		inner, ok := treeMathOwnedErrors[wrapped]
		if !ok {
			t.Fatalf("treeIndexWraps names %s and %s does not declare it", wrapped, treeMathErrorsFile)
		}
		if !errors.Is(outer, inner) {
			t.Errorf("%s does not answer to %s, so a caller that knows only the arithmetic's sentinel stops matching the ratchet tree's refusal of the same condition",
				name, wrapped)
		}
		if errors.Is(inner, outer) {
			t.Errorf("%s answers to %s, so the wrap runs both ways and the two names have stopped being distinguishable",
				wrapped, name)
		}
	}
}

// TestOnlyTheTreeIndexErrorsAnswerToATreeMathSentinel is the half with teeth.
//
// Wrapping is useful only while it stays exclusive. A third error of this file answering to
// ErrLeafOutOfRange would make a caller asking "was this a leaf index problem" get yes for a
// malformed tree, and the answer would be wrong in the direction that reads as working. The
// sweep is over both derived classes, so it judges every pair of the two files rather than the
// pairs somebody remembered, and the number of sanctioned matches is asserted -- a sweep that
// found none at all reports exactly what an exclusive one reports.
func TestOnlyTheTreeIndexErrorsAnswerToATreeMathSentinel(t *testing.T) {
	matched := 0
	for _, name := range slices.Sorted(maps.Keys(treeOwnedErrors)) {
		for _, wrapped := range slices.Sorted(maps.Keys(treeMathOwnedErrors)) {
			if !errors.Is(treeOwnedErrors[name], treeMathOwnedErrors[wrapped]) {
				continue
			}
			matched++
			if treeIndexWraps[name] != wrapped {
				t.Errorf("%s answers to %s and the only sanctioned wraps are %v; two sentinels for one condition is how a caller comes to read the wrong one as the right one",
					name, wrapped, treeIndexWraps)
			}
		}
	}
	if matched != len(treeIndexWraps) {
		t.Fatalf("%d pairs of the two files answer for each other and %d are sanctioned; a sweep that matched nothing reports what an exclusive one reports",
			matched, len(treeIndexWraps))
	}
}

// TestNoTreeErrorAnswersToAKeyScheduleSentinel is the same exclusivity against the other
// error file of this package that carries a maintained, file-derived class.
//
// Nothing is sanctioned here at all, which makes it the cheap half: the key schedule's
// sixteen and this plan's thirteen name conditions from different layers, and an errors.Is
// holding across them would mean one of the two files had grown a wrap nobody argued for.
//
// crypto_errors.go is deliberately NOT swept, and this is the note that says so rather than
// letting the absence look like coverage: it has no map held to its own declarations, and
// adding a written one here would be an eleventh-name-shaped hole of exactly the kind the
// header of this file objects to. Its names share no condition with these thirteen, and a
// wrap onto one of them would have to be written in tree_errors.go, where the file gate above
// makes it a declaration this file's class has to account for.
func TestNoTreeErrorAnswersToAKeyScheduleSentinel(t *testing.T) {
	if len(keyScheduleOwnedErrors) == 0 {
		t.Fatal("the key schedule's error class is empty, so this sweep compares against nothing")
	}
	for _, name := range slices.Sorted(maps.Keys(treeOwnedErrors)) {
		for _, other := range slices.Sorted(maps.Keys(keyScheduleOwnedErrors)) {
			if errors.Is(treeOwnedErrors[name], keyScheduleOwnedErrors[other]) {
				t.Errorf("%s answers to %s, and nothing in either plan argues for a wrap between the two layers",
					name, other)
			}
		}
	}
}
