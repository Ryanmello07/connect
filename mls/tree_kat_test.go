// The file the ratchet tree's mlswg vector runners live in, and the accounting they share.
//
// Two families are this plan's: 10 (tree-validation) and 11 (TreeKEM). Family 9
// (tree-operations) is the group lifecycle plan's, because its vector carries a serialized
// Proposal. Neither of this plan's two is INSTALLED yet -- installing a family means a
// Verify that compares a published answer against an implementation, and the ratchet tree is
// written by the tasks after this one -- so both are still named in expectedPendingFamilies
// and nothing here calls RegisterVectorFamily. What this file carries today is the machinery
// those two runners are built out of, exercised over the real corpora rather than declared
// and left for a later task to be the first caller of.
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
package mls

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// treeVectorFamilies is the two section 4.2.1 rows this plan gates on, by number.
//
// Numbers and not file names, because the number is what the registry keys on and the file
// name is what treeVectorFile derives from it. A list of two names here and a manifest over
// there is two spellings of one fact, and the second one goes stale silently.
var treeVectorFamilies = []int{10, 11}

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
// Its json key is never typed out a second time. theJsonKeyOf reads it off this tag, so the
// generic decode below and the struct decode above address the same key by construction --
// two spellings of one key in one package is how the two end up disagreeing about which key
// the corpus uses, and the disagreement is silent in the worst direction.
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
// The four counts are written down rather than derived, for the reason assertRun records: a
// count derived with the filter that is under test agrees with itself whatever the filter
// does. 14 cases per suite over the seven published suites is tree-validation's 98, and 11
// per suite is TreeKEM's 77; this package registers two of the seven.
func TestTreeVectorCorporaPartitionByTheRegistry(t *testing.T) {
	key := theJsonKeyOf(t, treeVectorHeader{}, "CipherSuite")
	for _, row := range []struct {
		number      int
		covered     int
		skipped     int
		comparisons int
		distinct    int
	}{
		{number: 10, covered: 28, skipped: 70, comparisons: 28, distinct: 2},
		{number: 11, covered: 22, skipped: 55, comparisons: 22, distinct: 2},
	} {
		file := treeVectorFile(t, row.number)
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
				if published != strconv.Itoa(int(one.Suite)) {
					t.Fatalf("%s case %d was kept at suite %#04x and its own text publishes %s, so the struct this runner decodes with is not reading the field it addresses",
						file, one.Index, uint16(one.Suite), published)
				}
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

// TestTreeVectorFamiliesAreStillPending is the other half of the note at the top of this
// file, written as an assertion rather than as a sentence.
//
// Neither family is installed, and "not installed" has to keep meaning that: a runner
// registered here without its number leaving expectedPendingFamilies is a family
// TestVectorFamiliesVerify never runs, and a number deleted from that list without a runner
// registered is a manifest gate failing for a reason nobody wrote down. The moment either
// family gains a Verify, this test fails and names it, which is the commit that owes
// assertVectorFamilyIsInstalled instead.
func TestTreeVectorFamiliesAreStillPending(t *testing.T) {
	for _, number := range treeVectorFamilies {
		family, ok := vectorManifest[number]
		if !ok {
			t.Fatalf("family %d is not in the manifest", number)
		}
		if !slices.Contains(expectedPendingFamilies, number) {
			t.Errorf("family %d (%s) is no longer listed as pending and this file still installs no runner for it",
				number, family.Name)
		}
		if family.Verify != nil {
			t.Errorf("family %d (%s) has a Verify; replace this test with assertVectorFamilyIsInstalled for it and delete %d from expectedPendingFamilies",
				number, family.Name, number)
		}
	}
}
