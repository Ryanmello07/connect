// The file the ratchet tree's mlswg vector runners live in, and the accounting they share.
//
// Two families are this plan's: 10 (tree-validation) and 11 (TreeKEM). Family 9
// (tree-operations) is the group lifecycle plan's, because its vector carries a serialized
// Proposal. Both of this plan's two are INSTALLED here, each in the commit that deletes its
// number from expectedPendingFamilies, and TestTreeVectorFamiliesAreInstalledOrPending holds
// both halves of that at once. The machinery the two runners are built out of came first and
// is still the first half of this file, exercised over the real corpora rather than declared
// and left for a later task to be the first caller of.
//
// What each runner ADDS over the sweeps its own plan already landed, stated plainly because a
// runner that adds no protection of its own is better replaced by a comment. Family 10's four
// answers -- resolutions, tree hashes, the section 7.9 chain, the leaf signatures -- are each
// swept somewhere else in this package already, over the same corpus. What is new is that they
// are asked of ONE case together and reported as one verdict, that the family is offered its
// corpus by TestVectorFamiliesVerify, and that the comparator is held to REFUSING seven
// classes of wrong case, which no sweep over a corpus that agrees with everything can be.
// Family 11 adds the same three plus a generate direction: a sender built here, a receiver
// that is not the sender, and a commit secret re-derived from the RFC text with crypto/hmac.
//
// Wired to the shared registry rather than to a second copy of it. The plan's own text for
// this task is explicit about the corpus half of that -- no second loader, no second hex
// decoder, no second PINS.md, because three parallel hex decoders over one corpus is how two
// of them end up disagreeing about the empty string -- and the same argument reaches the
// accounting. vectors_runner_test.go already holds the run tally, the suite filter, the
// comparator control driver and the probe every control is read through, each of them put
// there because a runner that had rediscovered it independently would have had to learn the
// same lesson at whatever point somebody noticed. So the pieces below are the ones that are
// genuinely this family pair's and nothing else:
//
//   - treeVectorFile, which reads a corpus basename off the shared manifest instead of
//     spelling it, so a family renumbered or repointed in vectors_test.go fails here rather
//     than leaving this file reading a corpus the registry no longer names.
//   - treeVectorsOfSuite, which decodes a corpus into a runner's own struct and partitions it
//     THROUGH the shared tally, so the covered and skipped halves of the run are counted by
//     the same code every other family is counted by.
//   - treeVectorPublishedSuite, the comparator this file owns. It returns the published
//     answer it read as EVIDENCE rather than returning nothing, which is the defect p4
//     shipped twice one task apart: a verifier that returns nothing lets its caller count
//     CALLS, and a call that returned is not a comparison that happened.
//
// The suite filter is the shared implementedSuite and NOT the single code point the plan's
// snippet for this task tests against. A helper that kept only 0x0003 would assume a
// singleton suite, which this slice's global constraints forbid outright, and it would do it
// invisibly: every count below would still add up, over a run that covered one of the two
// registered suites. assertRun holds the matched key set against Suites(), so the singleton
// version fails there.
//
// treeVectorsOfSuite's SIGNATURE departs from the plan's too, in two more ways, and they are
// written down here because the tasks that call it are not written yet and will hit them. The
// plan spells it `func treeVectorsOfSuite[T any](t *testing.T, file string, suiteOf func(v *T)
// CipherSuite) []T`. What is here returns `(*vectorRunTally, []treeVectorCase[T])` and takes a
// suiteOf answering `uint16`.
//
// Both are consequences of routing the partition through the shared tally rather than a second
// copy of it. The tally has to reach the caller, because the counts a family writes down are
// that family's to assert and deriving them inside the helper with the filter under test is
// how a filter matching nothing agrees with itself; and the corpus publishes a code point, not
// a CipherSuite, so a suiteOf returning CipherSuite would have to convert an unregistered code
// point into the registered type before the filter had decided whether it is one. The case
// wrapper carries the raw text alongside the decoded value, which is what lets a runner read
// every answer twice.
//
// The cost is at the call sites: the plan's Task 25 writes `vectors := treeVectorsOfSuite(t,
// "treekem.json", ...)`, a single-value assignment that does not compile against this, and a
// caller reads one.Value where the plan reads the bare T. Tasks 24 and 25 own that edit.
package mls

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// treeVectorRun is one family's whole run: the four counts assertRun holds that family's
// partition of its corpus against.
//
// A named type rather than an anonymous row inside the partition test, because the family
// NUMBERS and the family COUNTS have to be one table. They were two -- a slice of numbers here
// and a row table down in the test -- and a review measured what the second spelling costs:
// shrinking the slice to a single family took the other family out of three of the five tests
// in this file, left the partition test still covering it because its rows were the other
// spelling, and the package reported nothing at all.
type treeVectorRun struct {
	// covered and skipped are the two halves of the suite filter's partition of the file.
	covered int
	skipped int
	// comparisons is how many published answers were compared against and distinct is how
	// many of those answers differed from each other. A corpus read as one repeated value
	// compares the right number of times against the wrong number of answers.
	comparisons int
	distinct    int
}

// treeVectorRuns is the two section 4.2.1 rows this plan gates on, keyed by number.
//
// Numbers and not file names, because the number is what the registry keys on and the file
// name is what treeVectorFile derives from it. A list of two names here and a manifest over
// there is two spellings of one fact, and the second one goes stale silently.
//
// The counts are written down rather than derived, for the reason assertRun records: a count
// derived with the filter that is under test agrees with itself whatever the filter does. 14
// cases per suite over the seven published suites is tree-validation's 98, and 11 per suite is
// TreeKEM's 77; this package registers two of the seven.
var treeVectorRuns = map[int]treeVectorRun{
	10: {covered: 28, skipped: 70, comparisons: 28, distinct: 2},
	11: {covered: 22, skipped: 55, comparisons: 22, distinct: 2},
}

// treeVectorFamilies is the numbers of treeVectorRuns, ascending, and is the only list of them
// this file has.
//
// Derived and not written, so a family can leave this plan's gates only by leaving the table
// above -- and TestTreeVectorFamiliesAreEveryTreeFamilyTheRegistryNames refuses that too, by
// holding the table to the manifest rows that name a tree.
var treeVectorFamilies = slices.Sorted(maps.Keys(treeVectorRuns))

// treeVectorFamiliesElsewhere is every family whose manifest row names a tree and that this
// plan does NOT gate, with the argument for each.
//
// An exemption table and not a filter, for the same reason treeIndexWraps is one: which plan
// owns a family is a judgement about that family and not a property its manifest row carries.
// What makes an exemption table safe is that it is held in both directions --
// TestTreeVectorFamiliesAreEveryTreeFamilyTheRegistryNames refuses an exemption for a family no
// row names, refuses a family that is both exempt and gated, and refuses a tree family that is
// neither -- so the only way a family leaves this file is somebody writing down here who has it
// and why.
var treeVectorFamiliesElsewhere = map[int]string{
	1: "tree math, wave 1's; tree_math_kat_test.go installs it and it is no longer pending",
	3: "the secret tree, p4's; a different tree entirely, the key schedule's ratchets rather than the ratchet tree",
	9: "tree operations, the group lifecycle plan's, because its vector carries a serialized Proposal",
}

// treeVectorFile is one family's corpus basename, read off the shared manifest.
//
// Derived rather than written, so this file cannot name a corpus the registry does not. The
// pin relationship -- every manifest file appears in VECTORS.sha256 -- is
// TestVectorManifestIsComplete's and is deliberately not repeated here; what is checked is
// only that the row exists and names something, since a missing row would otherwise reach
// LoadVectorFile as the empty string and be reported as an unreadable file rather than as the
// registry disagreeing with this plan.
func treeVectorFile(t *testing.T, number int) string {
	t.Helper()
	family, ok := vectorManifest[number]
	if !ok {
		t.Fatalf("family %d is not in the manifest, so this file names a family the registry does not know about", number)
	}
	if family.File == "" {
		t.Fatalf("family %d (%s) names no corpus file", number, family.Name)
	}
	return family.File
}

// treeVectorHeader is the one field families 10 and 11 have in common and the only field this
// task reads: the ciphersuite the case is published at.
//
// Its json key is not typed out a second time in this file. theJsonKeyOf reads it off this
// tag, so the generic decode below and the struct decode above address the same key by
// construction -- two spellings of one key is how the two end up disagreeing about which key
// the corpus uses, and the disagreement is silent in the worst direction.
//
// In this FILE, and the distinction is not pedantry. The shared aCaseAtARegisteredSuite, which
// this file's comparator control gets its accepted case from, carries a literal tag of its
// own, so within the package there are two spellings whatever this file does.
// TestTheSharedCaseFinderAddressesTheSameCiphersuiteKey reads that literal off its source and
// holds it to this tag, which is the difference between the claim being true and the claim
// being checked.
type treeVectorHeader struct {
	CipherSuite uint16 `json:"cipher_suite"`
}

// treeVectorHeaderAsText is treeVectorHeader with the ciphersuite read as a string, so the
// control below can hand treeVectorsOfSuite a struct the vendored corpus cannot decode into.
//
// A struct rather than a corrupted corpus file, because the corpus is pinned by digest and
// the arm under test is "this runner's own struct does not fit the file", which is a property
// of the struct.
type treeVectorHeaderAsText struct {
	CipherSuite string `json:"cipher_suite"`
}

// treeVectorCase is one case of a vendored family file at a ciphersuite this package
// registers.
type treeVectorCase[T any] struct {
	// Index is the case's position in the corpus, for the failure messages.
	Index int
	// Suite is the registered suite the shared filter matched it at.
	Suite CipherSuite
	// Raw is the case's own json text, kept because a runner owes a second decode of every
	// answer it compares: the struct below is the runner's reading of the file and the raw
	// text is the file, and a struct tag pointing at a key the corpus does not publish is
	// visible only where the two are read apart.
	Raw json.RawMessage
	// Value is the case decoded into the runner's own struct.
	Value T
}

// treeVectorsOfSuite decodes every entry of a vendored family file into T, partitions the
// file through the shared run tally, and returns the entries at a ciphersuite this package
// has a provider for.
//
// The tally is returned rather than kept, because the accounting is the caller's to assert:
// the counts a family writes down are that family's, and deriving them here with the same
// filter that is under test is how a filter matching nothing ends up agreeing with itself.
// What this function does is make the partition impossible to do any other way -- every case
// takes exactly one branch of tally.filter, so covered plus skipped is the file and assertRun
// can say so.
//
// An empty in-scope half is fatal here rather than an empty slice returned. A runner handed
// nothing loops zero times, compares nothing and reports a pass, which is the single failure
// the whole vector harness is built to be unable to reach.
func treeVectorsOfSuite[T any](t *testing.T, file string, suiteOf func(v *T) uint16) (*vectorRunTally, []treeVectorCase[T]) {
	t.Helper()
	tally, entries := newVectorRunTally(t, file)
	kept := []treeVectorCase[T]{}
	for index, raw := range entries {
		var value T
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("%s case %d does not decode into this runner's struct: %v", file, index, err)
		}
		suite, inScope := tally.filter(suiteOf(&value))
		if !inScope {
			continue
		}
		kept = append(kept, treeVectorCase[T]{Index: index, Suite: suite, Raw: raw, Value: value})
	}
	if len(kept) == 0 {
		t.Fatalf("%s published no case at a ciphersuite this package registers, so every comparison over the result would be over nothing",
			file)
	}
	return tally, kept
}

// The three refusals treeVectorPublishedSuite makes. Three sentinels and not one, because
// assertComparatorRefuses reports a refusal for the WRONG reason, and a comparator with one
// sentinel cannot produce that report.
var (
	errTreeVectorSuiteUndecodable = errors.New("the vector case is not a json object")
	errTreeVectorSuiteUnpublished = errors.New("the vector case publishes no ciphersuite")
	errTreeVectorSuiteNotANumber  = errors.New("the vector case publishes a ciphersuite that is not a decimal number")
)

// treeVectorPublishedSuite reads a case's ciphersuite out of the case's own json text and
// returns it AS TEXT.
//
// The returned string is the point. A comparator that answers nothing lets its caller count
// the calls it made, and a call that returned is not a comparison that happened -- p4 shipped
// exactly that twice, one task apart, and the shared tally's answer() now takes the published
// value the runner read rather than a tick. This is that value: the corpus's own bytes for
// the field, addressed by the key treeVectorHeader's tag names, decoded by nothing the
// runner's own struct decode touches.
//
// The key is a parameter rather than a literal so the callers can derive it with
// theJsonKeyOf. An error is returned and never reported, because assertComparatorRefuses
// drives this function with cases that are wrong on purpose and a t.Fatalf would end the test
// doing the driving rather than the case being driven.
func treeVectorPublishedSuite(key string, raw json.RawMessage) (string, error) {
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &object); err != nil {
		return "", fmt.Errorf("%w: %v", errTreeVectorSuiteUndecodable, err)
	}
	field, found := object[key]
	if !found {
		return "", fmt.Errorf("%w: no %q", errTreeVectorSuiteUnpublished, key)
	}
	published := strings.TrimSpace(string(field))
	if _, err := strconv.ParseUint(published, 10, 16); err != nil {
		return "", fmt.Errorf("%w: %s", errTreeVectorSuiteNotANumber, published)
	}
	return published, nil
}

// rewriteTreeVectorField replaces one top level field of a corpus case, or deletes it when
// the replacement is nil, and re-encodes the case the way the corpus encodes one.
//
// One field moved and nothing else, so a refusal below is attributable to the thing that was
// made wrong. The absence of the field being rewritten is fatal: a corruption that corrupted
// nothing is a control row that drives the comparator with a case it should accept.
func rewriteTreeVectorField(t *testing.T, raw json.RawMessage, key string, replacement json.RawMessage) json.RawMessage {
	t.Helper()
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatalf("parse the case to corrupt: %v", err)
	}
	if _, found := object[key]; !found {
		t.Fatalf("the case publishes no %q, so rewriting it would corrupt nothing", key)
	}
	if replacement == nil {
		delete(object, key)
	} else {
		object[key] = replacement
	}
	body, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("re-encode the corrupted case: %v", err)
	}
	return body
}

// TestTreeVectorFilesAreVendored holds the two corpora this plan reads to being present and
// parsing to cases, through the harness loader and nothing of this file's own.
//
// Partly redundant, and stated as redundant rather than left to look like coverage:
// TestVectorFilesArePinned already fails when either file is absent or edited, and
// TestVectorManifestIsComplete already fails when a manifest row names a file the pin does
// not cover. What is NOT redundant is the direction -- this reads the files through
// LoadVectorFile, which is the call every runner in this file makes, so a loader that started
// answering an empty corpus for a missing one is a failure here and a green run everywhere a
// runner loops over what it returned.
func TestTreeVectorFilesAreVendored(t *testing.T) {
	if len(treeVectorFamilies) == 0 {
		t.Fatal("this plan claims no vector family, so the loop below reads nothing")
	}
	for _, number := range treeVectorFamilies {
		file := treeVectorFile(t, number)
		if raws := LoadVectorFile(t, file); len(raws) == 0 {
			t.Fatalf("%s decoded to zero entries", file)
		}
	}
}

// requireTreeVectorSuiteAgrees holds one case's two independent decodes of its ciphersuite
// equal: the suite the shared filter kept it at, and the answer read out of the case's own
// json text.
//
// A function rather than four lines inline in the loop below, and the reason is a measurement
// rather than a preference. Inline, this comparison could be DELETED with all five tests of
// this file still reporting green: nothing drove it with a case where the two decodes
// disagree, because every case of both vendored corpora agrees. An assertion no control can
// reach is an assertion whose absence looks exactly like its presence.
// TestTreeVectorSuiteAgreementFlagsADisagreement drives this one now, so deleting it fails
// there.
func requireTreeVectorSuiteAgrees(t *testing.T, file string, index int, kept CipherSuite, published string) {
	t.Helper()
	if published != strconv.Itoa(int(kept)) {
		t.Fatalf("%s case %d was kept at suite %#04x and its own text publishes %s, so the struct this runner decodes with is not reading the field it addresses",
			file, index, uint16(kept), published)
	}
}

// TestTreeVectorCorporaPartitionByTheRegistry is the run this file can hold today, and the
// only comparison it has an answer for before the ratchet tree exists: every case's
// ciphersuite, read twice.
//
// Once through treeVectorHeader, which is how treeVectorsOfSuite decides what is in scope,
// and once out of the case's own json text by treeVectorPublishedSuite, which decodes through
// nothing the first decode touches. The two are held equal per case and the published half is
// what is handed to the tally, so a comparator that answered without reading the corpus moves
// neither the comparison count nor the distinct-answer count.
//
// The families and their counts are read off treeVectorRuns, which is the whole of this
// plan's family class and the same table the other four tests of this file loop over. This
// test used to carry its own row table -- a second spelling of the family numbers -- and a
// review shrank the other spelling to one family and watched this test go on covering both.
func TestTreeVectorCorporaPartitionByTheRegistry(t *testing.T) {
	key := theJsonKeyOf(t, treeVectorHeader{}, "CipherSuite")
	for _, number := range treeVectorFamilies {
		row := treeVectorRuns[number]
		file := treeVectorFile(t, number)
		t.Run(file, func(t *testing.T) {
			tally, kept := treeVectorsOfSuite(t, file, func(v *treeVectorHeader) uint16 {
				return v.CipherSuite
			})
			for _, one := range kept {
				published, err := treeVectorPublishedSuite(key, one.Raw)
				if err != nil {
					t.Errorf("%s case %d: %v", file, one.Index, err)
				}
				// the shared refusal, handed the comparator's OWN verdict and not a tick
				// saying it was called. A comparator that declined a case the filter
				// matched is the filter and the comparator disagreeing about what runs,
				// and the counts below would then read correct over a smaller run.
				tally.requireCompared(t, one.Index, one.Suite, err == nil)
				requireTreeVectorSuiteAgrees(t, file, one.Index, one.Suite, published)
				tally.answer(published)
			}
			tally.assertRun(t, row.covered, row.skipped, row.comparisons, row.distinct)
		})
	}
}

// TestTreeVectorPublishedSuiteRefusesAWrongCase is the control on the comparator this file
// owns.
//
// Every case of both vendored corpora agrees with it, so a comparator that read the field and
// a comparator that returned a constant produce identical runs above; the only way to
// separate them is to hand it an answer that is wrong on purpose, once per defect class, and
// require the matching refusal. The unmodified case is required to be accepted first by
// assertComparatorRefuses, so a comparator that refused everything does not satisfy the table.
//
// Both corpora, not one. The two files are different shapes -- tree-validation publishes a
// tree and its hashes, TreeKEM publishes an epoch and a set of update paths -- and a
// comparator that happened to work on one is worth nothing to the family that reads the other.
func TestTreeVectorPublishedSuiteRefusesAWrongCase(t *testing.T) {
	key := theJsonKeyOf(t, treeVectorHeader{}, "CipherSuite")
	compare := func(_ *testing.T, raw json.RawMessage) error {
		_, err := treeVectorPublishedSuite(key, raw)
		return err
	}
	for _, number := range treeVectorFamilies {
		file := treeVectorFile(t, number)
		accepted, found := aCaseAtARegisteredSuite(t, file)
		if !found {
			t.Fatalf("%s publishes no case at a suite this package registers, so nothing drives the comparator", file)
		}
		assertComparatorRefuses(t, file, compare, accepted, []comparatorRefusal{
			{
				name:   "a case that is not a json object at all",
				vector: json.RawMessage("[]"),
				want:   errTreeVectorSuiteUndecodable,
			},
			{
				name:   "a case that publishes no ciphersuite",
				vector: rewriteTreeVectorField(t, accepted, key, nil),
				want:   errTreeVectorSuiteUnpublished,
			},
			{
				name:   "a case whose ciphersuite is published as a string",
				vector: rewriteTreeVectorField(t, accepted, key, json.RawMessage(`"3"`)),
				want:   errTreeVectorSuiteNotANumber,
			},
		})
	}
}

// TestTreeVectorsOfSuiteFlagsTheControlFixture drives the partition helper instead of
// asserting about it.
//
// Both of its refusals are the kind that look like nothing when they stop firing: a corpus
// this runner's struct cannot decode would otherwise reach the filter as a zero ciphersuite
// and be skipped, and a filter that matched nothing would return an empty slice a runner
// loops over zero times. The rows are bound to the function's own reports, so a third fatal
// cannot land here uncontrolled and a deleted one leaves a row naming nothing.
func TestTreeVectorsOfSuiteFlagsTheControlFixture(t *testing.T) {
	file := treeVectorFile(t, treeVectorFamilies[0])
	suiteOf := func(v *treeVectorHeader) uint16 { return v.CipherSuite }
	if failed, raised := probeAssertion(func(probe *testing.T) {
		treeVectorsOfSuite(probe, file, suiteOf)
	}); failed || raised != nil {
		t.Fatalf("the vendored %s was reported: failed=%v raised=%v; every row below would then pass for the wrong reason",
			file, failed, raised)
	}
	// asserted rather than assumed, because a registry that grew to hold this code point would
	// turn the row below into a run that covers everything and reports nothing.
	if _, ok := implementedSuite(unregisteredControlSuite); ok {
		t.Fatalf("suite %#04x is registered, so the filter row below does not match nothing", unregisteredControlSuite)
	}
	rows := []struct {
		// names is the substring of the report this row must provoke; the bijection against
		// treeVectorsOfSuite's own reports is asserted below.
		names string
		run   func(probe *testing.T)
	}{
		{"does not decode into this runner's struct", func(probe *testing.T) {
			treeVectorsOfSuite(probe, file, func(v *treeVectorHeaderAsText) uint16 { return 0 })
		}},
		{"published no case at a ciphersuite this package registers", func(probe *testing.T) {
			treeVectorsOfSuite(probe, file, func(v *treeVectorHeader) uint16 { return unregisteredControlSuite })
		}},
	}
	keys := []string{}
	for _, row := range rows {
		keys = append(keys, row.names)
	}
	assertEveryReportIsControlled(t, "treeVectorsOfSuite",
		theReportsOf(t, theSourceDeclaring(t, "", "treeVectorsOfSuite"), "", "treeVectorsOfSuite"), keys)
	for _, row := range rows {
		failed, raised := probeAssertion(row.run)
		if raised != nil {
			t.Errorf("%s: the helper panicked: %v", row.names, raised)
			continue
		}
		if !failed {
			t.Errorf("%s: the helper reported nothing, so a corpus it read as empty would reach a runner as a loop over no cases",
				row.names)
		}
	}
}

// TestTreeVectorFamiliesAreEveryTreeFamilyTheRegistryNames derives this plan's family class
// from the registry instead of trusting the table that spells it.
//
// treeVectorRuns is a written list, and a written list of a class is the defect this project
// has paid for fourteen times: it fails when a family is added and the list is remembered, and
// says nothing when a family is dropped. A review dropped one and measured the result -- the
// dropped family lost its vendoring check, lost its comparator control and lost the gate that
// notices it gaining a Verify, and every test in the package still passed.
//
// So the class is derived: every manifest row whose family name or corpus file names a tree.
// That set is {tree math, secret tree, tree operations, tree validation, TreeKEM} today, and
// three of the five are somebody else's -- which is a judgement about those families rather
// than anything their rows carry, so it is written down in treeVectorFamiliesElsewhere with a
// reason each. The two tables together must be exactly the derived set, in both directions.
func TestTreeVectorFamiliesAreEveryTreeFamilyTheRegistryNames(t *testing.T) {
	if len(treeVectorRuns) == 0 {
		t.Fatal("this plan gates no vector family, so every loop of this file reads nothing")
	}
	named := map[int]bool{}
	for number, family := range vectorManifest {
		if strings.Contains(strings.ToLower(family.Name), "tree") || strings.Contains(strings.ToLower(family.File), "tree") {
			named[number] = true
		}
	}
	// the positive control, and TreeKEM specifically: its row spells the word inside a longer
	// one, so a matcher looking for a WORD rather than a substring reports the same clean bill
	// a complete one reports, over a class missing the family this plan reads second.
	if !named[11] {
		t.Fatalf("the scan did not find family 11 (%s), whose row certainly names a tree, so it is matching something other than the manifest's rows",
			vectorManifest[11].Name)
	}
	if len(named) == len(vectorManifest) {
		t.Fatalf("all %d families of the manifest matched, so this rule selects nothing and the two tables below are held against everything",
			len(vectorManifest))
	}
	for _, number := range slices.Sorted(maps.Keys(named)) {
		_, gated := treeVectorRuns[number]
		reason, excused := treeVectorFamiliesElsewhere[number]
		switch {
		case gated && excused:
			t.Errorf("family %d (%s) is gated by this file and also excused to somebody else as %q; one of the two is wrong and a reader cannot tell which",
				number, vectorManifest[number].Name, reason)
		case !gated && !excused:
			t.Errorf("family %d (%s) names a tree and this file neither gates it nor says who has it; a family that left treeVectorRuns silently is a corpus three tests of this file stopped reading",
				number, vectorManifest[number].Name)
		}
	}
	for _, number := range slices.Sorted(maps.Keys(treeVectorFamiliesElsewhere)) {
		if !named[number] {
			t.Errorf("family %d is excused to another plan and no manifest row of that number names a tree, so the exemption covers a family this rule never selected",
				number)
		}
		if strings.TrimSpace(treeVectorFamiliesElsewhere[number]) == "" {
			t.Errorf("family %d is excused with no reason written down, which is the exemption reading as a filter", number)
		}
	}
	for _, number := range treeVectorFamilies {
		if !named[number] {
			t.Errorf("this file gates family %d and its manifest row (%s, %s) names no tree, so the derived class above is not the class this file runs over",
				number, vectorManifest[number].Name, vectorManifest[number].File)
		}
	}
}

// TestTreeVectorSuiteAgreementFlagsADisagreement drives the per case equality the partition
// test makes, rather than asserting about it.
//
// It is the assertion that says the struct this runner filters with and the text the tally is
// answered from are reading one field. Every case of both vendored corpora agrees with it, so
// the real run cannot separate an assertion that holds from an assertion that is not there --
// measured: deleted, all five tests of this file still passed. The row below is the case the
// corpora do not contain.
func TestTreeVectorSuiteAgreementFlagsADisagreement(t *testing.T) {
	suites := Suites()
	if len(suites) == 0 {
		t.Fatal("this package registers no ciphersuite, so the agreement below is over nothing")
	}
	kept := suites[0]
	agreeing := strconv.Itoa(int(kept))
	if failed, raised := probeAssertion(func(probe *testing.T) {
		requireTreeVectorSuiteAgrees(probe, "control.json", 0, kept, agreeing)
	}); failed || raised != nil {
		t.Fatalf("two decodes that agree were reported: failed=%v raised=%v; the row below would then pass for the wrong reason",
			failed, raised)
	}
	rows := []struct {
		// names is the substring of the report this row must provoke; the bijection against
		// the function's own reports is asserted below.
		names     string
		published string
	}{
		{"is not reading the field it addresses", agreeing + "0"},
	}
	keys := []string{}
	for _, row := range rows {
		keys = append(keys, row.names)
	}
	assertEveryReportIsControlled(t, "requireTreeVectorSuiteAgrees",
		theReportsOf(t, theSourceDeclaring(t, "", "requireTreeVectorSuiteAgrees"), "", "requireTreeVectorSuiteAgrees"), keys)
	for _, row := range rows {
		failed, raised := probeAssertion(func(probe *testing.T) {
			requireTreeVectorSuiteAgrees(probe, "control.json", 0, kept, row.published)
		})
		if raised != nil {
			t.Errorf("%s: the assertion panicked: %v", row.names, raised)
			continue
		}
		if !failed {
			t.Errorf("%s: the assertion reported nothing, so it can be deleted with this file's whole run still reading green",
				row.names)
		}
	}
}

// TestTheSharedCaseFinderAddressesTheSameCiphersuiteKey holds the one place outside this file
// that types the corpus's ciphersuite key out to the key this file derives.
//
// The header of this file used to claim the key "is never typed out a second time". Within
// this file that was true; within the package it was not, and the second spelling sits on the
// path this file's own comparator control runs through: aCaseAtARegisteredSuite decodes with a
// literal tag of its own and hands back the case whose key
// TestTreeVectorPublishedSuiteRefusesAWrongCase then derives with theJsonKeyOf. Two spellings
// that disagreed would leave that control driving the comparator with a case selected at a
// field the comparator never reads, and the refusal table would go on passing.
//
// The literal is read out of the shared helper's own source rather than repeated here, so this
// gate cannot become the third spelling.
func TestTheSharedCaseFinderAddressesTheSameCiphersuiteKey(t *testing.T) {
	key := theJsonKeyOf(t, treeVectorHeader{}, "CipherSuite")
	parsed := theSourceDeclaring(t, "", "aCaseAtARegisteredSuite")
	found := []string{}
	ast.Inspect(parsed.declarationOf(t, "", "aCaseAtARegisteredSuite"), func(node ast.Node) bool {
		field, isField := node.(*ast.Field)
		if !isField || field.Tag == nil {
			return true
		}
		text, err := strconv.Unquote(field.Tag.Value)
		if err != nil {
			t.Fatalf("unquote a struct tag of aCaseAtARegisteredSuite: %v", err)
		}
		if tag, _, _ := strings.Cut(reflect.StructTag(text).Get("json"), ","); tag != "" {
			found = append(found, tag)
		}
		return true
	})
	if len(found) != 1 {
		t.Fatalf("aCaseAtARegisteredSuite carries %v json keys and this gate is written for the one it decodes the ciphersuite with", found)
	}
	if found[0] != key {
		t.Errorf("aCaseAtARegisteredSuite decodes %q and %T addresses %q, so the case that drives this file's comparator control is selected at a field the comparator never reads",
			found[0], treeVectorHeader{}, key)
	}
}

// ---------------------------------------------------------------------------
// task 24: family 10, tree-validation
// ---------------------------------------------------------------------------

// The corpus basename family 11 reads, spelled once.
//
// Family 10's is tree_math_test.go's treeValidationVectorFile rather than a second spelling of
// the same string: three readers of that corpus already live in this package and a fourth
// constant naming the same file is how one of them ends up pointed somewhere else. treekem.json
// has no constant yet -- treekem_test.go spells it inline -- so this declares it.
//
// Neither is trusted: treeVectorFamilyFiles below is held to the manifest's own File by
// TestTreeVectorFamilyFilesAreTheRegistrysFiles, so a family renumbered or repointed in
// vectors_test.go fails there rather than leaving this file reading a corpus the registry no
// longer names.
const treekemVectorFile = "treekem.json"

// treeVectorFamilyFiles is the corpus each gated family's runner reads, keyed by family number.
var treeVectorFamilyFiles = map[int]string{
	10: treeValidationVectorFile,
	11: treekemVectorFile,
}

// The accounting that makes family 10's runner unable to pass having compared nothing.
//
// Transcriptions of what testdata/vectors/tree-validation.json holds at the pinned mlswg
// commit, counted off the corpus text with a json reader and not off this implementation: 98
// cases, 14 at each of the seven published ciphersuites, of which the two this package
// registers account for 28. Those 28 trees hold 908 nodes between them and this family compares
// two published answers at every node -- that node's resolution and that node's tree hash --
// which is 1816 comparisons against 790 distinct published answers. The 790 is 717 distinct
// tree hashes plus 73 distinct resolutions with no collision between the halves, since a tree
// hash renders as 64 hex characters and a resolution as a bracketed list of decimals.
//
// treeValidationKatLeaves is the non-blank leaf slots those 28 trees carry, every one of which
// has its signature verified at its own group id and its own index, and treeValidationKatBound
// is how many of those carry a leaf_node_source that BINDS the two. The second is what says the
// wrong-group refusal has something to refuse: over a corpus of key_package leaves alone,
// accepting a signature at another group id is the conforming answer and a control asking for a
// refusal would be asking for a defect. Both agree with leaf_node_test.go's own transcription
// of the same corpus -- 322 signatures of which 288 are context bound -- which is two readers
// of one file arriving at one number rather than a number copied across.
const (
	treeValidationKatCovered     = 28
	treeValidationKatSkipped     = 70
	treeValidationKatNodes       = 908
	treeValidationKatComparisons = 2 * treeValidationKatNodes
	treeValidationKatDistinct    = 790
	treeValidationKatLeaves      = 322
	treeValidationKatBound       = 288
)

// The refusals compareTreeValidationVector makes, as sentinels rather than formatted strings,
// so a control can require a SPECIFIC refusal and a refusal for the wrong reason is reported.
//
// They are the only thing that makes this family's comparison observable at all. Every case of
// the vendored corpus agrees with this implementation, so a comparator that checked everything
// and one that returned an empty struct produce identical runs over it; the only way to
// separate them is to hand it an answer that is wrong on purpose, once per defect class, and
// require the matching refusal.
var (
	errTreeValidationIncomplete  = errors.New("the tree-validation comparison reports answers it cannot have computed")
	errTreeValidationUndecodable = errors.New("the published ratchet tree does not decode")
	errTreeValidationColumnWidth = errors.New("a published column of a tree-validation case is not one entry per node")
	errTreeValidationResolution  = errors.New("a node's resolution is not the published one")
	errTreeValidationTreeHash    = errors.New("a node's tree hash is not the published one")
	errTreeValidationParentHash  = errors.New("the published ratchet tree fails the section 7.9 parent hash check")
	errTreeValidationLeafRefused = errors.New("a published leaf node's signature does not verify at its own group id and index")
	errTreeValidationLeafUnbound = errors.New("a context bound leaf node verified at a group id it was not signed under")
)

// The two answers this family compares at every node, named by what produced them. The order is
// the order the comparator emits them in and incomplete() holds a run to it position by
// position, because a run that emitted two tree hashes for one node and no resolution would
// still emit the right NUMBER of answers.
var treeValidationAnswerNames = []string{"Resolution", "TreeHashes"}

// treeValidationAnswer is one answer this package computed held against one answer the corpus
// published, rendered as text so a resolution and a tree hash are one kind of comparison.
//
// AS TEXT because the two published columns are two json shapes -- tree_hashes is an array of
// hex strings and resolutions an array of arrays of numbers -- and a runner that re-read the
// first through a string and the second through a []uint32 would be re-reading half of its
// answers through its own struct decode, which is the one thing a second read exists not to be.
type treeValidationAnswer struct {
	// name is what produced the computed half and is one of treeValidationAnswerNames.
	name string
	// field is the dotted json path the published half lives at, which the runner re-reads out
	// of a generic decode of the same case.
	field string
	got   string
	want  string
}

// treeValidationComparison is what one run of compareTreeValidationVector PRODUCED, and it is
// the only thing its callers are allowed to judge it by.
//
// A comparator that returns nothing lets its caller count CALLS, and a call that returned is not
// a comparison that happened: p4 shipped exactly that twice, one task apart, with an early
// return leaving the run green over code that was never invoked. Every field here is written at
// the point the work that produces it happens, so a return that skipped the work reports the
// zero value and a caller judging the values sees it.
type treeValidationComparison struct {
	// inScope is true when the case's ciphersuite is one this package registers. False is not a
	// failure and not a skip: it is a case with no provider.
	inScope bool
	// hashSize is the suite's KDF.Nh, read off the provider rather than assumed.
	hashSize int
	// nodeWidth and leafWidth are the decoded tree's own shape, which both published columns
	// are held to.
	nodeWidth uint32
	leafWidth uint32
	// publishesGroupId is whether the case carries the key at all, read off a generic decode
	// with no struct tag in the way: an absent key and an empty value decode identically
	// through the struct, and a signature verified against a group id the corpus never gave is
	// a comparison against nothing.
	publishesGroupId bool
	groupId          []byte
	// answers is every comparison the run made, in node order, two per node.
	answers []treeValidationAnswer
	// leaves is the non-blank leaf slots whose signature was verified, blanks the empty ones,
	// and bound how many of the verified ones carry a source that binds group id and index.
	leaves int
	blanks int
	bound  int
	// parentHashError is what section 7.9's whole-tree check answered, nil where it accepted.
	parentHashError error
	// refusedLeaf is the first published leaf whose signature did not verify at its own group
	// and index, and acceptedLeaf the first CONTEXT BOUND leaf that verified at a group id it
	// was not signed under. The second is the vacuity control on the first: every published
	// signature verifies, so a VerifySignature that answered nil for everything passes the
	// whole sweep and only the wrong question separates it.
	refusedLeaf  error
	acceptedLeaf error
}

// incomplete reports whether the evidence a compared case must carry is missing or
// inconsistent, without looking at whether any answer was right.
//
// The vacuity half, split from the correctness half on purpose: two empty strings compare equal,
// so an answer whose got and want are both empty has compared nothing whatever the comparison
// would say about it.
func (self treeValidationComparison) incomplete() error {
	switch {
	case !self.inScope:
		return fmt.Errorf("%w: the case is out of scope and carries no comparison", errTreeValidationIncomplete)
	case self.hashSize == 0:
		return fmt.Errorf("%w: no KDF.Nh was read from the provider", errTreeValidationIncomplete)
	case self.nodeWidth == 0 || self.leafWidth == 0:
		return fmt.Errorf("%w: the decoded tree is %d nodes over %d leaves, so every column below was held against nothing",
			errTreeValidationIncomplete, self.nodeWidth, self.leafWidth)
	case !self.publishesGroupId:
		return fmt.Errorf("%w: the case publishes no group id key at all, so every leaf signature was verified against a value the corpus never gave",
			errTreeValidationIncomplete)
	case len(self.groupId) == 0:
		return fmt.Errorf("%w: the published group id is the empty octet string, which binds a leaf to nothing",
			errTreeValidationIncomplete)
	case uint32(len(self.answers)) != self.nodeWidth*uint32(len(treeValidationAnswerNames)):
		return fmt.Errorf("%w: the run made %d comparisons over a %d node tree and this family compares %d per node",
			errTreeValidationIncomplete, len(self.answers), self.nodeWidth, len(treeValidationAnswerNames))
	case uint32(self.leaves+self.blanks) != self.leafWidth:
		return fmt.Errorf("%w: %d occupied and %d blank leaf slots over a tree %d leaves wide; a slot took neither branch",
			errTreeValidationIncomplete, self.leaves, self.blanks, self.leafWidth)
	case self.leaves == 0:
		return fmt.Errorf("%w: the published tree carries no occupied leaf, so no signature was verified over it",
			errTreeValidationIncomplete)
	}
	// the emit order, position by position, and the two halves of every comparison non-empty.
	for index, answer := range self.answers {
		want := treeValidationAnswerNames[index%len(treeValidationAnswerNames)]
		if answer.name != want {
			return fmt.Errorf("%w: comparison %d is %s and this family emits %s there",
				errTreeValidationIncomplete, index, answer.name, want)
		}
		if answer.got == "" || answer.want == "" {
			return fmt.Errorf("%w: %s at %s compared %q against %q, and an empty comparison agrees with anything",
				errTreeValidationIncomplete, answer.name, answer.field, answer.got, answer.want)
		}
		if answer.field == "" {
			return fmt.Errorf("%w: %s names no published field, so nothing independent of this comparator's own decode can re-read it",
				errTreeValidationIncomplete, answer.name)
		}
	}
	return nil
}

// verdict is the whole judgement over one compared case: it must be complete, every published
// resolution and every published tree hash must agree, the tree must pass section 7.9's
// whole-tree parent hash check, and every occupied leaf must verify at its own group id and
// index while a context bound one refuses a group id it was not signed under.
//
// The order puts the two columns ahead of the parent hash check on purpose. Section 7.9's check
// is stated over tree hashes of copath subtrees, so a defect in the tree hash breaks BOTH, and
// reporting the parent hash first would send a reader to the condition that is not the one that
// moved.
func (self treeValidationComparison) verdict() error {
	if err := self.incomplete(); err != nil {
		return err
	}
	for _, answer := range self.answers {
		if answer.got == answer.want {
			continue
		}
		sentinel := errTreeValidationTreeHash
		if answer.name == "Resolution" {
			sentinel = errTreeValidationResolution
		}
		return fmt.Errorf("%w: %s answered %s and the corpus publishes %s at %s",
			sentinel, answer.name, answer.got, answer.want, answer.field)
	}
	if self.parentHashError != nil {
		return fmt.Errorf("%w: %v", errTreeValidationParentHash, self.parentHashError)
	}
	if self.refusedLeaf != nil {
		return fmt.Errorf("%w: %v", errTreeValidationLeafRefused, self.refusedLeaf)
	}
	if self.acceptedLeaf != nil {
		return fmt.Errorf("%w: %v", errTreeValidationLeafUnbound, self.acceptedLeaf)
	}
	return nil
}

// verifyTreeValidationVector is the registry's shim: the signature RegisterVectorFamily needs,
// over the comparator that does the work and reports what it produced.
//
// Verify cannot return anything, which is exactly why the work is not done here: a runner
// counting calls to this would count a case it declined to check the same way it counts one it
// compared.
func verifyTreeValidationVector(t *testing.T, raw json.RawMessage) {
	t.Helper()
	evidence, err := compareTreeValidationVector(t, raw)
	if err != nil {
		t.Fatalf("tree-validation: %v", err)
	}
	if !evidence.inScope {
		return
	}
	if err := evidence.verdict(); err != nil {
		t.Fatalf("tree-validation: %v", err)
	}
}

// compareTreeValidationVector runs one case of tree-validation.json and returns what the run
// produced. A case at a ciphersuite this package does not register is not a failure and not a
// skip: it comes back with inScope false and nothing else set.
//
// A corpus that will not parse or will not hex decode is fatal rather than returned, because it
// is not a verdict about this implementation -- it is the evidence itself being unreadable.
// Everything that IS a verdict about this implementation is returned, so a control can require
// a refusal instead of hoping the corpus disagrees with a defect.
func compareTreeValidationVector(t *testing.T, raw json.RawMessage) (treeValidationComparison, error) {
	t.Helper()
	// treeValidationVector is tree_math_test.go's row for this same corpus, reused rather than
	// declared again: a fourth declaration of one corpus row in one package is how two of them
	// end up disagreeing about which json key an answer lives at.
	vector := treeValidationVector{}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("parse tree-validation case: %v", err)
	}
	suite, ok := implementedSuite(vector.CipherSuite)
	if !ok {
		return treeValidationComparison{}, nil
	}
	crypto := mustProvider(t, suite)

	published := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &published); err != nil {
		t.Fatalf("parse tree-validation case as a json object: %v", err)
	}
	_, publishesGroupId := published[theJsonKeyOf(t, treeValidationVector{}, "GroupId")]

	evidence := treeValidationComparison{
		inScope:          true,
		hashSize:         crypto.HashSize(),
		publishesGroupId: publishesGroupId,
		groupId:          MustHex(t, vector.GroupId),
	}
	tree, err := UnmarshalRatchetTree(MustHex(t, vector.Tree))
	if err != nil {
		return evidence, fmt.Errorf("%w: %v", errTreeValidationUndecodable, err)
	}
	evidence.nodeWidth = tree.NodeWidth()
	evidence.leafWidth = uint32(tree.LeafWidth())

	// both columns are held to the tree's own width BEFORE either is read, because a short
	// column would otherwise be a loop that ran fewer times and reported a clean run.
	resolutionKey := theJsonKeyOf(t, treeValidationVector{}, "Resolutions")
	hashKey := theJsonKeyOf(t, treeValidationVector{}, "TreeHashes")
	if uint32(len(vector.Resolutions)) != evidence.nodeWidth {
		return evidence, fmt.Errorf("%w: %d entries in %s for a tree of %d nodes",
			errTreeValidationColumnWidth, len(vector.Resolutions), resolutionKey, evidence.nodeWidth)
	}
	if uint32(len(vector.TreeHashes)) != evidence.nodeWidth {
		return evidence, fmt.Errorf("%w: %d entries in %s for a tree of %d nodes",
			errTreeValidationColumnWidth, len(vector.TreeHashes), hashKey, evidence.nodeWidth)
	}
	hashes, err := tree.TreeHashes(crypto)
	if err != nil {
		return evidence, fmt.Errorf("TreeHashes: %w", err)
	}
	if uint32(len(hashes)) != evidence.nodeWidth {
		return evidence, fmt.Errorf("%w: TreeHashes answered %d hashes for a tree of %d nodes",
			errTreeValidationColumnWidth, len(hashes), evidence.nodeWidth)
	}
	for x := uint32(0); x < evidence.nodeWidth; x += 1 {
		evidence.answers = append(evidence.answers,
			treeValidationAnswer{
				name:  "Resolution",
				field: fmt.Sprintf("%s.%d", resolutionKey, x),
				got:   treeResolutionText(tree.Resolution(NodeIndex(x))),
				want:  publishedNodeIndexListText(vector.Resolutions[x]),
			},
			treeValidationAnswer{
				name:  "TreeHashes",
				field: fmt.Sprintf("%s.%d", hashKey, x),
				got:   HexOf(hashes[x]),
				want:  vector.TreeHashes[x],
			})
	}

	evidence.parentHashError = tree.VerifyParentHashes(crypto)

	for x := uint32(0); x < evidence.leafWidth; x += 1 {
		leaf := tree.Leaf(LeafIndex(x))
		if leaf == nil {
			evidence.blanks += 1
			continue
		}
		evidence.leaves += 1
		if err := leaf.VerifySignature(crypto, evidence.groupId, LeafIndex(x)); err != nil && evidence.refusedLeaf == nil {
			evidence.refusedLeaf = fmt.Errorf("leaf %d: %v", x, err)
		}
		// the vacuity control, and only over the leaves the RFC binds. Section 7.2's select
		// puts the group id and the leaf index inside the LeafNodeTBS for the update and commit
		// sources and leaves them out for key_package, so a key_package leaf verifying at
		// another group is the conforming answer rather than a forgery.
		if !leafNodeSourceBindsItsPosition(leaf.LeafNodeSource) {
			continue
		}
		evidence.bound += 1
		elsewhere := bytes.Clone(evidence.groupId)
		elsewhere[0] ^= 0x01
		if err := leaf.VerifySignature(crypto, elsewhere, LeafIndex(x)); err == nil && evidence.acceptedLeaf == nil {
			evidence.acceptedLeaf = fmt.Errorf("leaf %d, whose source is %v", x, leaf.LeafNodeSource)
		}
	}

	return evidence, evidence.verdict()
}

// leafNodeSourceBindsItsPosition is RFC 9420 section 7.2's select read as the question the
// control above asks of it: does the LeafNodeTBS of a leaf with this source carry the group id
// and the leaf index.
//
// Written as the two sources the RFC names rather than as "not key_package", which is the same
// answer today and the wrong one on the day a fourth source is registered: an unrecognised
// source would inherit the unbound preimage in silence, which is the exact fall-through
// signatureContent refuses outright.
func leafNodeSourceBindsItsPosition(source LeafNodeSource) bool {
	return source == LeafNodeSourceUpdate || source == LeafNodeSourceCommit
}

// treeResolutionText renders a resolution this package computed the way the corpus spells one: a
// bracketed comma separated list of decimal node indices, with the empty resolution as [].
func treeResolutionText(resolution []NodeIndex) string {
	out := strings.Builder{}
	out.WriteByte('[')
	for at, x := range resolution {
		if at > 0 {
			out.WriteByte(',')
		}
		out.WriteString(strconv.FormatUint(uint64(x), 10))
	}
	out.WriteByte(']')
	return out.String()
}

// publishedNodeIndexListText renders a resolution the corpus published, decoded through this
// runner's own struct, in the same spelling.
//
// This is the COMPARATOR's half and is deliberately not the runner's second read: the runner
// re-reads the same answer out of a generic decode of the case text through
// publishedTreeVectorAnswer, which touches no struct tag of this file at all, and the two are
// held equal there. A struct tag pointing at a key the corpus does not publish decodes to an
// empty column here and is a missing key there.
func publishedNodeIndexListText(published []uint32) string {
	indices := make([]NodeIndex, 0, len(published))
	for _, x := range published {
		indices = append(indices, NodeIndex(x))
	}
	return treeResolutionText(indices)
}

// publishedTreeVectorAnswer reads one published answer out of a case decoded as a GENERIC json
// object, addressed by a dotted json path, and renders it as text.
//
// publishedCorpusField next door answers for a json STRING, which is every answer the four
// families before these two compare. Family 10's resolutions column publishes a json ARRAY of
// node indices per node, so the string arm alone would be fatal over half of this family's
// answers. The array arm renders the corpus's own bytes with their whitespace removed rather
// than decoding into anything: a second read that went through a []uint32 would be this
// runner's own struct decode a second time.
//
// The walk into the case is publishedCorpusSegment's, shared with publishedCorpusField, so a
// path that addresses nothing is loud in both places for one reason.
func publishedTreeVectorAnswer(t *testing.T, published map[string]json.RawMessage, path string) string {
	t.Helper()
	key, rest, isNested := strings.Cut(path, ".")
	raw, found := published[key]
	if !found {
		t.Fatalf("the corpus case does not publish %q, so whatever decodes it decodes to nothing and every comparison over it is vacuous", key)
	}
	walked := key
	for isNested {
		var segment string
		segment, rest, isNested = strings.Cut(rest, ".")
		raw = publishedCorpusSegment(t, raw, walked, segment)
		walked += "." + segment
	}
	text := ""
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	compacted := bytes.Buffer{}
	if err := json.Compact(&compacted, raw); err != nil {
		t.Fatalf("the published %s is neither a json string nor well formed json: %v", walked, err)
	}
	return compacted.String()
}

// Family 10 is installed here, and 10 is deleted from expectedPendingFamilies in the same
// commit. Without both halves TestVectorFamiliesVerify runs one fewer family and the manifest
// gate stays green while claiming this family is unimplemented.
//
// Generate is nil, and it is asserted as an absence rather than left unmentioned. A
// tree-validation case is a serialized ratchet tree together with the resolutions and tree
// hashes of every node of it, and this package can produce all three -- but the tree would be
// one this package built, so the generated case would be this implementation's own answers fed
// back to itself, which closes no loop the published corpus does not already close. Family 11
// next door is the one with a generate direction worth having, because there the sender and the
// receiver are two different code paths.
func init() {
	RegisterVectorFamily(VectorFamily{
		Number:   10,
		Name:     "Tree validation",
		File:     treeValidationVectorFile,
		Slice:    "A2",
		Verify:   verifyTreeValidationVector,
		Generate: nil,
	})
}

// TestVectorTreeValidation is vector family 10 over the published corpus.
//
// Every assertion the tally makes after the loop exists because the loop can be made to run zero
// times without anything else in this package noticing: a filter that matched nothing, a filter
// that matched all seven published suites, a corpus that parsed to an empty array and a
// comparator that declined every case are each a green run of this test with the accounting
// removed.
//
// What the loop counts is not calls that returned. It counts comparisons whose computed half is
// re-read here against a GENERIC decode of the corpus text -- no struct tag of this file in the
// way -- so a comparator that answered without computing anything is a failure here rather than
// a number that looks right.
func TestVectorTreeValidation(t *testing.T) {
	file := treeVectorFile(t, 10)
	tally, entries := newVectorRunTally(t, file)
	nodes, leaves, bound := 0, 0, 0
	for index, raw := range entries {
		published := map[string]json.RawMessage{}
		if err := json.Unmarshal(raw, &published); err != nil {
			t.Fatalf("%s case %d: %v", file, index, err)
		}
		header := treeVectorHeader{}
		if err := json.Unmarshal(raw, &header); err != nil {
			t.Fatalf("%s case %d: %v", file, index, err)
		}
		suite, inScope := tally.filter(header.CipherSuite)
		if !inScope {
			continue
		}
		evidence, err := compareTreeValidationVector(t, raw)
		if err != nil {
			t.Fatalf("%s case %d (suite %#04x): %v", file, index, header.CipherSuite, err)
		}
		// the shared refusal, handed the comparator's OWN verdict and not a tick saying it was
		// called. A comparator that declined a case the filter matched is the filter and the
		// comparator disagreeing about what runs, and the counts below would then read correct
		// over a smaller run.
		tally.requireCompared(t, index, suite, evidence.inScope)
		if err := evidence.verdict(); err != nil {
			t.Fatalf("%s case %d (suite %#04x): %v", file, index, header.CipherSuite, err)
		}
		for _, answer := range evidence.answers {
			want := publishedTreeVectorAnswer(t, published, answer.field)
			if answer.got != want {
				t.Fatalf("%s case %d (suite %#04x): %s answered %s and the corpus text publishes %s at %s",
					file, index, header.CipherSuite, answer.name, answer.got, want, answer.field)
			}
			tally.answer(want)
		}
		nodes += int(evidence.nodeWidth)
		leaves += evidence.leaves
		bound += evidence.bound
	}
	tally.assertRun(t, treeValidationKatCovered, treeValidationKatSkipped,
		treeValidationKatComparisons, treeValidationKatDistinct)
	// the shape of the run under the comparison count, which the tally says nothing about: that
	// count is satisfied by 908 nodes spread any way at all, and by a sweep that verified no leaf
	// signature whatever, since a signature is a refusal rather than a published answer.
	if nodes != treeValidationKatNodes {
		t.Fatalf("%s: the covered trees carry %d nodes between them, want %d", file, nodes, treeValidationKatNodes)
	}
	if leaves != treeValidationKatLeaves {
		t.Fatalf("%s: %d published leaf signatures were verified, want %d", file, leaves, treeValidationKatLeaves)
	}
	if bound != treeValidationKatBound {
		t.Fatalf("%s: %d of those leaves bind their group id and index, want %d; without one the wrong-group control ran over nothing",
			file, bound, treeValidationKatBound)
	}
	t.Logf("%s: %d nodes over %d trees, two published answers each; %d leaf signatures verified, %d of them context bound and refused at another group",
		file, nodes, treeValidationKatCovered, leaves, bound)
}

// tvKatBaseCase answers a published tree-validation case every row of the control below can be
// built from, together with the one row that has to be built out of the tree rather than out
// of the json.
//
// Two conditions, and both are searched for rather than assumed of case zero. The tree must
// carry at least one CONTEXT BOUND leaf, because section 7.2 leaves the group id out of a
// key_package leaf's preimage and over a tree of those alone a flipped group id is accepted
// quite correctly -- a row asking for a refusal there would be asking for a defect. And it must
// hold a parent whose parent_hash field, changed in one octet, section 7.9's check refuses; the
// corpus publishes two-leaf trees whose only parent is the root, and the root's parent_hash is
// the zero-length octet string that section 7.9 gives it, so there is nothing there to spoil.
//
// The base is the corpus's own and not a fixture: the whole of what the refusals below mean is
// that this exact case is accepted and a one octet edit of it is not.
func tvKatBaseCase(t *testing.T) (treeValidationVector, json.RawMessage) {
	t.Helper()
	bound, chains := 0, 0
	for _, raw := range LoadVectorFile(t, treeVectorFile(t, 10)) {
		evidence, err := compareTreeValidationVector(t, raw)
		if err != nil {
			t.Fatalf("a published tree-validation case was refused: %v", err)
		}
		if !evidence.inScope || evidence.bound == 0 {
			continue
		}
		bound += 1
		vector := treeValidationVector{}
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("parse a tree-validation case: %v", err)
		}
		broken, found := aTreeValidationCaseWhoseParentHashChainIsBroken(t, vector)
		if !found {
			continue
		}
		chains += 1
		return vector, broken
	}
	t.Fatalf("%d published cases at a registered suite carry a context bound leaf and %d of them a parent hash this check refuses when it is changed; the rows below need one case with both",
		bound, chains)
	return treeValidationVector{}, nil
}

// rewriteTreeValidationCase re-encodes one corpus row with one thing changed.
//
// Through the row's own struct rather than through a hand edit of the json text, which is what
// makes the accepted case below and the refused ones the same shape: assertComparatorRefuses
// requires the unmodified case to be ACCEPTED first, and a base that went through this encoder
// while the corruptions did not would make that acceptance a statement about a different
// encoding.
func rewriteTreeValidationCase(t *testing.T, base treeValidationVector,
	mutate func(corrupted *treeValidationVector)) json.RawMessage {
	t.Helper()
	corrupted := base
	corrupted.Resolutions = slices.Clone(base.Resolutions)
	corrupted.TreeHashes = slices.Clone(base.TreeHashes)
	mutate(&corrupted)
	body, err := json.Marshal(corrupted)
	if err != nil {
		t.Fatalf("re-encode the corrupted tree-validation case: %v", err)
	}
	return body
}

// aTreeValidationCaseWhoseParentHashChainIsBroken is the published tree with one octet of one
// parent's parent_hash field changed, and BOTH published columns recomputed over the result.
//
// The columns are recomputed rather than carried over, and that is what aims this row at the
// class it names. A node's parent_hash field is inside the tree hash preimage of that node, so a
// case that kept the published tree_hashes would be refused as a tree hash mismatch --
// correctly, and for a reason that says nothing about section 7.9.2.
//
// WHICH parent is found rather than chosen: the first whose flipped field the check refuses.
// A tree in which no such node exists answers false and its caller moves to the next published
// case -- a two-leaf tree has only the root, whose parent_hash is the zero-length octet string
// -- and a caller that ran out of cases fails there. A VerifyParentHashes answering nil for
// everything lands in exactly that arm: no tree of the corpus produces a refusal, and the
// search reports having found none.
func aTreeValidationCaseWhoseParentHashChainIsBroken(t *testing.T, base treeValidationVector) (json.RawMessage, bool) {
	t.Helper()
	suite, ok := implementedSuite(base.CipherSuite)
	if !ok {
		t.Fatalf("the base case is at suite %#04x, which this package does not register", base.CipherSuite)
	}
	crypto := mustProvider(t, suite)
	wire := MustHex(t, base.Tree)
	probe, err := UnmarshalRatchetTree(wire)
	if err != nil {
		t.Fatalf("decode the base case's ratchet tree: %v", err)
	}
	for x := uint32(1); x < probe.NodeWidth(); x += 2 {
		tree, err := UnmarshalRatchetTree(wire)
		if err != nil {
			t.Fatalf("decode the base case's ratchet tree: %v", err)
		}
		parent := tree.ParentAt(NodeIndex(x))
		if parent == nil || len(parent.ParentHash) == 0 {
			continue
		}
		parent.ParentHash[0] ^= 0x01
		if tree.VerifyParentHashes(crypto) == nil {
			continue
		}
		encoded, err := syntax.Marshal(tree)
		if err != nil {
			t.Fatalf("re-encode the corrupted ratchet tree: %v", err)
		}
		hashes, err := tree.TreeHashes(crypto)
		if err != nil {
			t.Fatalf("TreeHashes over the corrupted ratchet tree: %v", err)
		}
		return rewriteTreeValidationCase(t, base, func(corrupted *treeValidationVector) {
			corrupted.Tree = HexOf(encoded)
			corrupted.TreeHashes = make([]string, 0, len(hashes))
			for _, hash := range hashes {
				corrupted.TreeHashes = append(corrupted.TreeHashes, HexOf(hash))
			}
			corrupted.Resolutions = make([][]uint32, 0, tree.NodeWidth())
			for y := uint32(0); y < tree.NodeWidth(); y += 1 {
				list := []uint32{}
				for _, index := range tree.Resolution(NodeIndex(y)) {
					list = append(list, uint32(index))
				}
				corrupted.Resolutions = append(corrupted.Resolutions, list)
			}
		}), true
	}
	return nil, false
}

// TestCompareTreeValidationVectorRefusesAnAnswerItShouldNotAccept is the control the runner
// cannot be.
//
// Every case of the vendored corpus agrees with this implementation, so a comparator that
// checked all of its answers and one that returned an empty struct produce identical runs above;
// the only way to separate them is to hand it a case that is wrong on purpose, once per defect
// class, and require the matching refusal. Each row names the sentinel it owes, so a refusal for
// the WRONG reason is reported too, and assertComparatorRefuses requires the unmodified case to
// be accepted first so a comparator that refused everything does not satisfy the table.
func TestCompareTreeValidationVectorRefusesAnAnswerItShouldNotAccept(t *testing.T) {
	base, brokenChain := tvKatBaseCase(t)
	compare := func(t *testing.T, raw json.RawMessage) error {
		evidence, err := compareTreeValidationVector(t, raw)
		if err != nil {
			return err
		}
		return evidence.verdict()
	}
	flipHex := func(text string) string {
		octets := MustHex(t, text)
		if len(octets) == 0 {
			t.Fatalf("nothing to flip in %q", text)
		}
		octets[0] ^= 0x01
		return HexOf(octets)
	}
	if len(base.Resolutions) < 2 || len(base.TreeHashes) < 2 {
		t.Fatalf("the base case publishes %d resolutions and %d tree hashes, and the rows below need two of each",
			len(base.Resolutions), len(base.TreeHashes))
	}
	accepted := rewriteTreeValidationCase(t, base, func(corrupted *treeValidationVector) {})
	assertComparatorRefuses(t, treeVectorFile(t, 10), compare, accepted, []comparatorRefusal{
		{
			name:   "a case whose published ratchet tree does not decode",
			vector: rewriteTreeValidationCase(t, base, func(c *treeValidationVector) { c.Tree = "00" }),
			want:   errTreeValidationUndecodable,
		},
		{
			name: "a case publishing one resolution fewer than the tree has nodes",
			vector: rewriteTreeValidationCase(t, base, func(c *treeValidationVector) {
				c.Resolutions = c.Resolutions[:len(c.Resolutions)-1]
			}),
			want: errTreeValidationColumnWidth,
		},
		{
			name: "a case publishing one tree hash fewer than the tree has nodes",
			vector: rewriteTreeValidationCase(t, base, func(c *treeValidationVector) {
				c.TreeHashes = c.TreeHashes[:len(c.TreeHashes)-1]
			}),
			want: errTreeValidationColumnWidth,
		},
		{
			name: "a case whose first two published resolutions are transposed",
			vector: rewriteTreeValidationCase(t, base, func(c *treeValidationVector) {
				c.Resolutions[0], c.Resolutions[1] = c.Resolutions[1], c.Resolutions[0]
			}),
			want: errTreeValidationResolution,
		},
		{
			name: "a case with one octet of one published tree hash changed",
			vector: rewriteTreeValidationCase(t, base, func(c *treeValidationVector) {
				c.TreeHashes[0] = flipHex(c.TreeHashes[0])
			}),
			want: errTreeValidationTreeHash,
		},
		{
			name:   "a case whose ratchet tree fails the section 7.9 parent hash check",
			vector: brokenChain,
			want:   errTreeValidationParentHash,
		},
		{
			name: "a case whose group id is not the one its leaves were signed under",
			vector: rewriteTreeValidationCase(t, base, func(c *treeValidationVector) {
				c.GroupId = flipHex(c.GroupId)
			}),
			want: errTreeValidationLeafRefused,
		},
	})
}

// treeValidationSentinels is this family's refusals addressed by the identifier they are
// declared under, so a class derived from the source can be turned back into the value a control
// row carries.
//
// A map written out here is a list, and a list is the shape rule 5 is about -- which is why the
// gate below does not read it AS the class. The class is the identifiers the verdict names; this
// only resolves one of those identifiers to its value, and an identifier missing from here is a
// failure rather than a row quietly skipped.
var treeValidationSentinels = map[string]error{
	"errTreeValidationIncomplete":  errTreeValidationIncomplete,
	"errTreeValidationUndecodable": errTreeValidationUndecodable,
	"errTreeValidationColumnWidth": errTreeValidationColumnWidth,
	"errTreeValidationResolution":  errTreeValidationResolution,
	"errTreeValidationTreeHash":    errTreeValidationTreeHash,
	"errTreeValidationParentHash":  errTreeValidationParentHash,
	"errTreeValidationLeafRefused": errTreeValidationLeafRefused,
	"errTreeValidationLeafUnbound": errTreeValidationLeafUnbound,
}

// TestTreeValidationVerdictReportsEveryClassItNames drives the verdict over evidence built here
// rather than over the corpus.
//
// Two of the classes the verdict names cannot be reached from a corpus at all. A comparison that
// is INCOMPLETE is one whose comparator returned early, and no corpus case can ask for that; a
// context bound leaf that verifies at a group id it was not signed under is a DEFECT in
// VerifySignature, and no corpus can publish one. Both are the arms that hold the sweep above
// honest -- without the first a comparator answering an empty struct passes, without the second
// a VerifySignature answering nil for everything passes -- so both are driven here.
//
// The class is DERIVED from the two methods' own source and not listed: every errTreeValidation
// sentinel either of them names owes exactly one row, so an arm added to the verdict without a
// row fails here rather than going unreached. The two the COMPARATOR names and the verdict does
// not -- the undecodable tree and the column widths -- are refused before a comparison exists to
// judge, and are the refusal table's above.
func TestTreeValidationVerdictReportsEveryClassItNames(t *testing.T) {
	complete := func() treeValidationComparison {
		return treeValidationComparison{
			inScope:          true,
			hashSize:         32,
			nodeWidth:        3,
			leafWidth:        2,
			publishesGroupId: true,
			groupId:          []byte{0x01, 0x02},
			answers: []treeValidationAnswer{
				{name: "Resolution", field: "resolutions.0", got: "[0]", want: "[0]"},
				{name: "TreeHashes", field: "tree_hashes.0", got: "aa", want: "aa"},
				{name: "Resolution", field: "resolutions.1", got: "[0,2]", want: "[0,2]"},
				{name: "TreeHashes", field: "tree_hashes.1", got: "bb", want: "bb"},
				{name: "Resolution", field: "resolutions.2", got: "[2]", want: "[2]"},
				{name: "TreeHashes", field: "tree_hashes.2", got: "cc", want: "cc"},
			},
			leaves: 2,
			blanks: 0,
			bound:  2,
		}
	}
	// the baseline, and it is what makes every row below mean anything: a verdict that refused
	// everything would satisfy the whole table.
	if err := complete().verdict(); err != nil {
		t.Fatalf("a complete and agreeing comparison was refused: %v", err)
	}
	rows := []struct {
		// names is the sentinel this row must be refused as.
		names error
		// spoil makes exactly one thing wrong in a comparison that would otherwise pass.
		spoil func(evidence *treeValidationComparison)
	}{
		{errTreeValidationIncomplete, func(e *treeValidationComparison) { e.answers = nil }},
		{errTreeValidationResolution, func(e *treeValidationComparison) { e.answers[2].got = "[2,0]" }},
		{errTreeValidationTreeHash, func(e *treeValidationComparison) { e.answers[3].got = "dd" }},
		{errTreeValidationParentHash, func(e *treeValidationComparison) {
			e.parentHashError = errors.New("a copath child claimed nothing")
		}},
		{errTreeValidationLeafRefused, func(e *treeValidationComparison) { e.refusedLeaf = errors.New("leaf 1") }},
		{errTreeValidationLeafUnbound, func(e *treeValidationComparison) { e.acceptedLeaf = errors.New("leaf 1") }},
	}
	claimed := map[string]bool{}
	for _, row := range rows {
		if row.names == nil {
			t.Fatal("a row names no sentinel, so any refusal at all would satisfy it")
		}
		found := ""
		for name, sentinel := range treeValidationSentinels {
			if sentinel == row.names {
				found = name
			}
		}
		if found == "" {
			t.Fatalf("a row names %v and treeValidationSentinels resolves no identifier to it", row.names)
		}
		if claimed[found] {
			t.Fatalf("%s is claimed by two rows, so some class this verdict names is claimed by none", found)
		}
		claimed[found] = true
	}
	// the class, read off the two methods rather than listed here.
	declared := theSourceDeclaring(t, "treeValidationComparison", "verdict")
	mentioned := map[string]bool{}
	for _, method := range []string{"verdict", "incomplete"} {
		for name := range namesMentionedIn(declared.declarationOf(t, "treeValidationComparison", method)) {
			if strings.HasPrefix(name, "errTreeValidation") {
				mentioned[name] = true
			}
		}
	}
	if len(mentioned) == 0 {
		t.Fatal("the verdict and its completeness check name no errTreeValidation sentinel at all, so the class below was derived from nothing")
	}
	if len(mentioned) != len(rows) {
		t.Fatalf("the verdict names %v and this control offers %d rows for %v",
			slices.Sorted(maps.Keys(mentioned)), len(rows), slices.Sorted(maps.Keys(claimed)))
	}
	for _, name := range slices.Sorted(maps.Keys(mentioned)) {
		if _, known := treeValidationSentinels[name]; !known {
			t.Errorf("%s is a class the verdict reports and treeValidationSentinels does not resolve it", name)
			continue
		}
		if !claimed[name] {
			t.Errorf("%s is a class the verdict reports and no row here drives it", name)
		}
	}
	for _, row := range rows {
		evidence := complete()
		row.spoil(&evidence)
		err := evidence.verdict()
		if err == nil {
			t.Errorf("%v: the spoiled comparison was accepted, so this arm of the verdict reports nothing", row.names)
			continue
		}
		if !errors.Is(err, row.names) {
			t.Errorf("the spoiled comparison was refused as %v, want %v; a refusal for the wrong reason is the verdict checking something else",
				err, row.names)
		}
	}
}

// treeVectorInstalledRunners is the Verify and the Generate this file installs, keyed by family
// number. A family this file gates and has NOT installed yet has no row here.
//
// The identity is the point: assertVectorFamilyIsInstalled holds the registered function to the
// one this table names, so a manifest row that kept its number and picked up some other family's
// runner fails rather than reading as installed. Which families are installed is deliberately
// NOT read off this table -- it is read off the manifest -- so a table that forgot a family and a
// manifest holding a runner nothing here names are two different failures with two different
// messages, rather than one table agreeing with itself.
var treeVectorInstalledRunners = map[int]struct {
	verify   func(t *testing.T, raw json.RawMessage)
	generate func(t *testing.T) json.RawMessage
}{
	10: {verify: verifyTreeValidationVector},
}

// TestTreeVectorFamiliesAreInstalledOrPending is the registration half both of this file's
// families owe, in whichever of the two states each of them is in.
//
// It replaces the earlier assertion that NEITHER family was installed, which could only ever be
// deleted. The two halves of installing a family are two edits -- register the runner, delete the
// number from expectedPendingFamilies -- and either one alone is silent in the worst direction:
// the first without the second leaves the manifest gate failing for a reason nobody wrote down,
// and the second without the first leaves TestVectorFamiliesVerify running one family fewer with
// the gate green.
//
// So both states are held, and which state a family is IN is read off the manifest rather than
// off this file. A runner that stopped being linked -- an init() dropped, a build tag -- takes
// its family back to pending, and this fails there rather than passing over a family nothing
// runs.
func TestTreeVectorFamiliesAreInstalledOrPending(t *testing.T) {
	if len(treeVectorFamilies) == 0 {
		t.Fatal("this plan claims no vector family, so the loop below reads nothing")
	}
	installed := 0
	for _, number := range treeVectorFamilies {
		family, ok := vectorManifest[number]
		if !ok {
			t.Fatalf("family %d is not in the manifest", number)
		}
		runner, named := treeVectorInstalledRunners[number]
		switch {
		case family.Verify == nil && named:
			t.Errorf("this file names a runner for family %d (%s) and the registry holds none, so the init() that registers it is not linked",
				number, family.Name)
		case family.Verify != nil && !named:
			t.Errorf("family %d (%s) is registered with a verifier this file does not name, so nothing holds the installed function to this runner's",
				number, family.Name)
		case family.Verify == nil:
			if !slices.Contains(expectedPendingFamilies, number) {
				t.Errorf("family %d (%s) is no longer listed as pending and this file installs no runner for it",
					number, family.Name)
			}
		default:
			installed += 1
			assertVectorFamilyIsInstalled(t, number, treeVectorFamilyFiles[number], runner.verify, runner.generate)
		}
	}
	if installed != len(treeVectorInstalledRunners) {
		t.Fatalf("%d of the %d runners this file names were held to the registry; the rest were reported above",
			installed, len(treeVectorInstalledRunners))
	}
	t.Logf("%d of this plan's %d families are installed and %d are still pending",
		installed, len(treeVectorFamilies), len(treeVectorFamilies)-installed)
}

// TestTreeVectorFamilyFilesAreTheRegistrysFiles holds the two corpus basenames this file spells
// to the ones the manifest names.
//
// A constant is needed at all because init() runs before any test does and cannot ask a
// *testing.T for the manifest row. That constant is then a second spelling of a fact the
// registry already holds, and the failure a second spelling produces is the quiet one: a family
// repointed at another corpus in vectors_test.go would leave this file's runner reading the old
// file, comparing its answers perfectly, and reporting a clean run for a family that reads
// something else.
func TestTreeVectorFamilyFilesAreTheRegistrysFiles(t *testing.T) {
	if len(treeVectorFamilyFiles) != len(treeVectorFamilies) {
		t.Fatalf("this file spells %d corpus names and gates %d families", len(treeVectorFamilyFiles), len(treeVectorFamilies))
	}
	for _, number := range treeVectorFamilies {
		spelled, named := treeVectorFamilyFiles[number]
		if !named {
			t.Errorf("family %d is gated by this file and no corpus name is spelled for it", number)
			continue
		}
		if got := treeVectorFile(t, number); got != spelled {
			t.Errorf("family %d is registered against %s and this file spells %s", number, got, spelled)
		}
	}
}
