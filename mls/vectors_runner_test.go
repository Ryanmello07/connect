// The machinery every mlswg vector runner in this package shares.
//
// Three families now register against the registry in vectors_test.go -- psk_secret and
// key-schedule from key_schedule_kat_test.go, transcript-hashes from transcript_kat_test.go
// -- and a fourth arrives with every later plan. The parts they have in common are here
// rather than in each of them, because the hardening those runners needed is not the sort
// that gets rediscovered: the first psk_secret runner reported a comparison count of 22
// with the derivation never called, and a second and third independent copy of that
// accounting would each have had to learn the same lesson separately, at whatever point
// somebody noticed.
//
// What is shared, and why each part is a part rather than a line in a runner:
//
//   - the run tally, which partitions a corpus into the cases the suite filter matched and
//     the cases it declined, and refuses a run whose two halves do not add up to the file.
//     A filter that matched nothing and a filter that matched all seven published suites
//     are both green runs without it, and both are runs of a family that proved nothing.
//   - the declined-at-a-registered-suite refusal. A comparator answering "out of scope" for
//     a case at a suite this package registers is the filter and the comparator disagreeing
//     about what runs, and the count then reads correct over a run that is smaller than it.
//   - the comparator control driver. Every case of every vendored corpus agrees with this
//     implementation, so a comparator that checked everything and a comparator that checked
//     nothing produce identical runs over it; the only way to separate them is to hand the
//     comparator an answer that is wrong on purpose and require the matching refusal. The
//     unmodified case is required to be ACCEPTED first, or a comparator that refuses
//     everything satisfies the whole table.
//   - the installed-family assertion, which is two edits in the source -- register the
//     runner, delete the number from expectedPendingFamilies -- and one of them alone
//     leaves a gate green over a family nothing runs.
//   - the opaque<V> tail split, which three files were reading the same published structures
//     with. The tag at the end of a FramedContentAuthData and the tag at the end of a
//     PublicMessage are the same shape, and the width of the length prefix in front of
//     either is the codec's answer and not the literal 1.
//
// The suite filter itself was already shared: implementedSuite in key_schedule_kat_test.go
// reads the ciphersuite registry rather than listing code points, and every family calls it.
//
// Nothing here decides what a family compares. That is each family's own, because the answer
// a family owes is the family's; what is shared is the accounting that makes an answer it
// did not compare impossible to report as one it did.
package mls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// errVectorTagTail is the refusal splitTrailingOpaqueTag makes. A sentinel rather than a
// formatted string, so a family's control can require this refusal specifically and a
// comparator that refused for some other reason is reported.
var errVectorTagTail = errors.New("the tail of this structure is not an opaque<V> of the suite's KDF.Nh")

// vectorLengthPrefix is the length prefix an opaque<V> of n octets carries, spelled by the
// codec rather than written out here.
//
// RFC 9420 section 2.1.2 writes 0..63 as one octet and 64..16383 as two, so a helper that
// assumed a single octet is right for both registered suites -- KDF.Nh is 32 and 32 <= 63 --
// and stops being right at the first suite whose hash is SHA-512, where Nh is 64 and the
// prefix is 0x40 0x40. It would stop being right loudly, which is better than silently, but
// loudly in the helpers that read it rather than in the one line that is actually wrong. So
// the width is derived: the codec is asked to encode a vector of that length and the prefix
// is whatever it wrote in front of the content.
//
// The error is returned rather than reported, so the callers that need a verdict can have
// one and the callers that need a fatal can raise it themselves.
// TestThePublishedVectorPrefixWidensWithTheVector is the control, over both widths and over
// the boundary from both sides.
func vectorLengthPrefix(n int) ([]byte, error) {
	w := syntax.NewWriter()
	w.WriteOpaque(make([]byte, n))
	encoded, err := w.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode the length prefix a %d octet <V> vector carries: %w", n, err)
	}
	prefix := encoded[:len(encoded)-n]
	if len(prefix) == 0 {
		return nil, fmt.Errorf("%w: a %d octet opaque<V> encodes to %d octets and therefore carries no length prefix, so nothing separates a tail from the field in front of it",
			errVectorTagTail, n, len(encoded))
	}
	return prefix, nil
}

// splitTrailingOpaqueTag splits a serialized structure whose last field is an opaque<V> of
// exactly nh octets into everything in front of that field and the tag itself.
//
// Both a FramedContentAuthData's confirmation_tag and a PublicMessage's membership_tag are
// the LAST field of their structure and both are a MAC, which is an opaque<V> of exactly
// KDF.Nh octets, so the tail is the tag and what sits in front of it is that vector's own
// length prefix. For an AuthenticatedContent carrying a Commit the head is precisely the
// serialized ConfirmedTranscriptHashInput, which is what transcript-hashes.json is read
// with.
//
// The prefix is asserted rather than skipped over: if the octets at that offset are not the
// encoded length of the tail being read, then what is being read is not a tag, and a
// comparison against it would be a comparison against the wrong bytes rather than a failure.
// That check plus the caller's own MAC verification is what makes the split self-validating
// rather than assumed -- a split taken one octet out recovers bytes the MAC refuses. When p6
// lands (*AuthenticatedContent).UnmarshalMLS this is replaced by the parse and the MAC check
// stays.
//
// bytes.Equal and not a loop of this file's own. The comparison is over a PUBLIC opaque<V>
// length prefix and not over a tag, so guardrail 8 has nothing to say about it either way --
// but a byte loop spelled out here is a comparator living in this package outside the class
// every derived gate can see, and one edit away from being pointed at a tag. The library call
// is inside that class; the loop was not.
func splitTrailingOpaqueTag(blob []byte, nh int) (head []byte, tag []byte, err error) {
	prefix, err := vectorLengthPrefix(nh)
	if err != nil {
		return nil, nil, err
	}
	if len(blob) <= nh+len(prefix) {
		return nil, nil, fmt.Errorf("%w: the structure is %d octets and a %d octet tag with its %d octet length prefix leaves nothing in front of it",
			errVectorTagTail, len(blob), nh, len(prefix))
	}
	at := len(blob) - nh - len(prefix)
	if found := blob[at : at+len(prefix)]; !bytes.Equal(found, prefix) {
		return nil, nil, fmt.Errorf("%w: the %d octets before its last %d are %x, and a <V> vector of %d octets is written %x",
			errVectorTagTail, len(prefix), nh, found, nh, prefix)
	}
	return blob[:at], blob[len(blob)-nh:], nil
}

// vectorRunTally is the accounting one family's runner does over its corpus: how the suite
// filter partitioned the file, which registered suites it reached, and how many published
// answers were actually compared against.
//
// It exists because a runner that ran nothing reports exactly what a runner that passed
// everything reports. Every field here is written at the point the work that produces it
// happens, and assertRun holds all of them at once against numbers the family wrote down, so
// a filter that matched nothing, a comparator that declined every case and a corpus that
// parsed to an empty array are each a failure rather than a smaller PASS.
type vectorRunTally struct {
	// file is the corpus basename, for the failure messages.
	file string
	// entries is how many cases the corpus parsed to.
	entries int
	// covered and skipped are the two halves of the partition. Their sum must be entries.
	covered int
	skipped int
	// matched counts the covered cases by the registered suite they ran at, so a run that
	// reached one of the two registered suites for every case and the other once is a
	// failure rather than a total that looks right.
	matched map[CipherSuite]int
	// published counts EVERY case by its ciphersuite, in scope or not, so the per suite
	// split is derived from the corpus's own census of itself rather than transcribed.
	published map[uint16]int
	// answers counts each distinct published answer a comparison was made against, and
	// comparisons counts the comparisons. A corpus read as one repeated value -- every
	// field decoding to the same string, every epoch decoding as epoch 0 -- compares the
	// right number of times against the wrong number of answers.
	answers     map[string]int
	comparisons int
}

// newVectorRunTally loads a family's corpus through the harness loader and opens the
// accounting over it.
//
// LoadVectorFile is fatal and never skipping on a corpus it cannot read, which is the
// property TestNoVectorRunnerCanSkip holds structurally; an empty parse is fatal here for
// the same reason, since a corpus truncated to [] would otherwise take a family out of the
// suite and report that as a clean run.
func newVectorRunTally(t *testing.T, file string) (*vectorRunTally, []json.RawMessage) {
	t.Helper()
	entries := LoadVectorFile(t, file)
	if len(entries) == 0 {
		t.Fatalf("%s parsed to no entries, so every comparison below would be against nothing", file)
	}
	return &vectorRunTally{
		file:      file,
		entries:   len(entries),
		matched:   map[CipherSuite]int{},
		published: map[uint16]int{},
		answers:   map[string]int{},
	}, entries
}

// filter records one case against the suite filter and answers whether this package has a
// provider for it.
//
// One call per case, taking both branches itself, so a case cannot be counted twice or take
// neither branch. The filter it consults is implementedSuite, which reads the ciphersuite
// registry rather than a list of code points -- see
// TestImplementedSuiteIsTheRegistryAndNotAList.
func (self *vectorRunTally) filter(code uint16) (CipherSuite, bool) {
	self.published[code]++
	suite, ok := implementedSuite(code)
	if !ok {
		self.skipped++
		return 0, false
	}
	self.covered++
	self.matched[suite]++
	return suite, true
}

// requireCompared refuses a comparator that declined a case the suite filter matched.
//
// The two disagree about what runs when this fires, and the disagreement is silent in the
// worst direction: the tally counts the case as covered because the filter matched it, the
// comparator returned an empty comparison, and the count then reads correct over a run that
// compared one case fewer.
func (self *vectorRunTally) requireCompared(t *testing.T, index int, suite CipherSuite, inScope bool) {
	t.Helper()
	if !inScope {
		t.Fatalf("%s case %d is at suite %#04x, which this package registers, and the comparator declined it",
			self.file, index, uint16(suite))
	}
}

// answer records one comparison made against one published answer.
//
// Called by the runner and not by the comparator, and called with the answer the runner read
// out of the corpus text ITSELF rather than with the comparator's copy of it, so a
// comparator that answered without computing anything moves neither number.
func (self *vectorRunTally) answer(published string) {
	self.answers[published]++
	self.comparisons++
}

// assertRun is every accounting assertion a family runner in this package owes, held at once
// against the counts that family wrote down.
//
// The counts are written down by each family rather than derived here, for the reason task
// 16 gives: deriving an expected count with the same filter that is under test is how a
// filter matching nothing ends up agreeing with itself. What IS derived is the partition --
// covered plus skipped must equal the file -- and the per suite split, which is read off the
// corpus's own census of itself.
func (self *vectorRunTally) assertRun(t *testing.T, wantCovered int, wantSkipped int, wantComparisons int, wantDistinct int) {
	t.Helper()
	if self.covered+self.skipped != self.entries {
		t.Fatalf("%s: %d covered and %d skipped over %d cases; a case took neither branch",
			self.file, self.covered, self.skipped, self.entries)
	}
	if self.covered == 0 {
		t.Fatalf("%s: the suite filter matched no case at all, so this family ran nothing and reported it as a pass", self.file)
	}
	// the floor under the two counts the family writes down for itself, and the reason it is
	// here rather than assumed. Every assertion above is satisfied by a run that partitioned
	// the corpus perfectly and then compared NOTHING: covered and skipped add up, the key set
	// is the registry's, the per suite split matches the corpus census, and comparisons and
	// answers are held only against numbers the family supplied. A family that supplies zero
	// for both therefore passes having verified nothing at all, which is the single outcome
	// this whole accounting exists to be unable to reach -- and it is a two character edit,
	// smaller than deleting the comparison loop it describes. Measured on family 10: deleting
	// the answer() call and writing 0 down produced "0 comparisons against 0 distinct
	// published answers" under a green PASS.
	if wantComparisons < 1 || wantDistinct < 1 {
		t.Fatalf("%s: this family wrote down %d comparisons against %d distinct answers; a run that compares nothing reports what a run that compared everything reports, so neither count may be zero",
			self.file, wantComparisons, wantDistinct)
	}
	if self.covered != wantCovered {
		t.Fatalf("%s: covered %d cases, want %d; the filter matched %v", self.file, self.covered, wantCovered, self.matched)
	}
	if self.skipped != wantSkipped {
		t.Fatalf("%s: skipped %d cases at unimplemented suites, want %d", self.file, self.skipped, wantSkipped)
	}
	if got := slices.Sorted(maps.Keys(self.matched)); !slices.Equal(got, Suites()) {
		t.Fatalf("%s: the corpus answered for %v and this package registers %v", self.file, got, Suites())
	}
	// the per suite split, which the key set above says nothing about: a run that reached
	// one registered suite for every case and the other for one satisfies both the total and
	// the key set, and is a run that covered one suite.
	for _, suite := range Suites() {
		want := self.published[uint16(suite)]
		if want == 0 {
			t.Fatalf("%s: the corpus publishes nothing at suite %#04x, which this package registers",
				self.file, uint16(suite))
		}
		if self.matched[suite] != want {
			t.Fatalf("%s: suite %#04x was covered %d times and the corpus publishes %d cases at it",
				self.file, uint16(suite), self.matched[suite], want)
		}
	}
	if self.comparisons != wantComparisons {
		t.Fatalf("%s: made %d comparisons over %d covered cases, want %d",
			self.file, self.comparisons, self.covered, wantComparisons)
	}
	if len(self.answers) != wantDistinct {
		t.Fatalf("%s: the %d comparisons were made against %d distinct published answers, want %d; a corpus read as one repeated value compares that many times and pins one answer",
			self.file, self.comparisons, len(self.answers), wantDistinct)
	}
	t.Logf("%s: covered %d cases at %v, skipped %d at unimplemented suites, %d comparisons against %d distinct published answers",
		self.file, self.covered, slices.Sorted(maps.Keys(self.matched)), self.skipped,
		self.comparisons, len(self.answers))
}

// publishedCorpusField reads one published answer out of a case decoded as a GENERIC json
// object, addressed by a dotted json path.
//
// Generic on purpose. A family's comparator reads the corpus through its own struct tags and
// this reads the same bytes with no struct involved, so the two are independent decodes of
// one file: a tag misspelled, renamed, or pointed at a key the corpus does not publish
// decodes to the empty string on the comparator's side and is a missing key here, which is a
// failure rather than a comparison of nothing against nothing.
func publishedCorpusField(t *testing.T, published map[string]json.RawMessage, name string) string {
	t.Helper()
	key, rest, isNested := strings.Cut(name, ".")
	raw, found := published[key]
	if !found {
		t.Fatalf("the corpus case does not publish %q, so whatever decodes it decodes to nothing and every comparison over it is vacuous", key)
	}
	// a loop rather than one nesting step, because a family's answers are not all one level
	// down: secret-tree publishes a leaf's generation at leaves[leaf][generation], and a
	// reader that could only take a key would have to decode that array through the
	// comparator's own struct, which is the one decode this function exists to be
	// independent of.
	walked := key
	for isNested {
		var segment string
		segment, rest, isNested = strings.Cut(rest, ".")
		raw = publishedCorpusSegment(t, raw, walked, segment)
		walked += "." + segment
	}
	text := ""
	if err := json.Unmarshal(raw, &text); err != nil {
		t.Fatalf("the published %s is not a json string: %v", name, err)
	}
	return text
}

// publishedCorpusSegment steps one segment of a dotted path into a published value: a json
// object takes a key and a json array takes a decimal index.
//
// The index arm is what lets a family address an answer inside a published array. It is a
// FAILURE and never an empty answer when the segment does not address anything -- an index
// past the end, or a key the case does not carry -- for publishedCorpusField's own reason:
// the whole point of this second decode is that a path which addresses nothing is loud here
// rather than an empty string compared against an empty string somewhere else.
//
// Which arm applies is read off the SHAPE OF THE PUBLISHED VALUE and never off the spelling of
// the segment. The version this replaces asked strconv.Atoi about the segment first, so a
// corpus that published an object key spelled as a decimal -- "0" -- would have had that object
// decoded as a json array and reported as a path that addresses nothing, at a path that is
// exactly right. No vendored corpus publishes such a key today, which is what makes the order a
// defect that arrives with a corpus update rather than with a change to any family: every
// family in this package now walks this one function, so the arm that fires has to be a
// question about the corpus and not about how a family spelled its path.
func publishedCorpusSegment(t *testing.T, raw json.RawMessage, walked string, segment string) json.RawMessage {
	t.Helper()
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &object); err == nil {
		nested, found := object[segment]
		if !found {
			t.Fatalf("the published %s is a json object and does not carry %q", walked, segment)
		}
		return nested
	}
	elements := []json.RawMessage{}
	if err := json.Unmarshal(raw, &elements); err != nil {
		t.Fatalf("the published %s is neither a json object nor a json array, so the segment %q addresses nothing in it: %v",
			walked, segment, err)
	}
	index, err := strconv.Atoi(segment)
	if err != nil {
		t.Fatalf("the published %s is a json array and the segment %q is not a decimal index: %v", walked, segment, err)
	}
	// the canonical spelling, because "00" and "+1" parse to elements 0 and 1 while naming
	// something else. A path that addresses one element and reads as another is the same silent
	// mis-addressing this whole second decode exists to make loud.
	if strconv.Itoa(index) != segment {
		t.Fatalf("the published %s was addressed by the segment %q, which is index %d spelled another way",
			walked, segment, index)
	}
	if index < 0 || index >= len(elements) {
		t.Fatalf("the published %s holds %d elements and index %d was asked for", walked, len(elements), index)
	}
	return elements[index]
}

// theJsonKeyOf is the json key one field of a corpus row is published under, read off that
// field's own struct tag rather than typed out a second time.
//
// Two spellings of one key in one package is how the two end up disagreeing about which key the
// corpus actually uses, and the disagreement is silent in the worst direction: the second
// spelling looks up nothing, the lookup answers "absent", and whatever that absence means is
// then reported about a corpus that publishes the key perfectly well.
func theJsonKeyOf(t *testing.T, row any, field string) string {
	t.Helper()
	found, ok := reflect.TypeOf(row).FieldByName(field)
	if !ok {
		t.Fatalf("%T has no field %s, so nothing names the key it decodes", row, field)
	}
	key, _, _ := strings.Cut(found.Tag.Get("json"), ",")
	if key == "" {
		t.Fatalf("%T.%s carries no json key, so it decodes under its go name and this lookup would miss it", row, field)
	}
	return key
}

// comparatorRefusal is one deliberately wrong case a family's comparator must refuse, and
// the sentinel it must refuse it as.
type comparatorRefusal struct {
	// name is what was made wrong, for the failure message.
	name string
	// vector is the corrupted case, serialized the way the corpus serializes one.
	vector json.RawMessage
	// want is the sentinel the refusal must wrap. A refusal for the wrong reason is a
	// comparator checking something other than what this case corrupts.
	want error
}

// assertComparatorRefuses is the control every family runner in this package owes and cannot
// be.
//
// Every case of every vendored corpus agrees with this implementation, so a comparator that
// accepted everything and a comparator that checked everything produce identical runs over
// it. The only way to see the difference is to disagree with it on purpose, once per defect
// class, and require the matching refusal.
//
// The unmodified case is checked FIRST and is the reason the refusals mean anything: a
// comparator that refused everything would satisfy the whole table. The table is required to
// be non-empty and its names distinct, so a control that corrupted nothing, or that ran one
// case twice under two names, is a failure rather than a shorter table nobody wrote down.
func assertComparatorRefuses(
	t *testing.T,
	family string,
	compare func(t *testing.T, raw json.RawMessage) error,
	accepted json.RawMessage,
	refusals []comparatorRefusal,
) {
	t.Helper()
	if len(refusals) == 0 {
		t.Fatalf("%s: no deliberately wrong case was offered, so this control accepts a comparator that compares nothing", family)
	}
	named := map[string]bool{}
	for _, refusal := range refusals {
		if named[refusal.name] {
			t.Fatalf("%s: %q is offered twice, so this table covers one defect class fewer than it counts", family, refusal.name)
		}
		named[refusal.name] = true
		if refusal.want == nil {
			t.Fatalf("%s: %q names no sentinel, so any refusal at all would satisfy it", family, refusal.name)
		}
	}
	if err := compare(t, accepted); err != nil {
		t.Fatalf("%s: the unmodified published case was refused: %v; a comparator that refuses everything satisfies every case below", family, err)
	}
	for _, refusal := range refusals {
		err := compare(t, refusal.vector)
		if err == nil {
			t.Errorf("%s: %s was accepted; the comparator is not comparing", family, refusal.name)
			continue
		}
		if !errors.Is(err, refusal.want) {
			t.Errorf("%s: %s was refused as %v, want %v; a refusal for the wrong reason is a comparator checking something else",
				family, refusal.name, err, refusal.want)
		}
	}
}

// assertVectorFamilyIsInstalled is the registration half every family owes.
//
// Registering the family and deleting its number from expectedPendingFamilies are two edits,
// and doing only the first leaves TestVectorManifestIsComplete failing while doing only the
// second leaves it passing with the family uninstalled. Both are asserted here, and so is
// the identity of the functions installed, so a row that kept the number and lost the runner
// -- or that picked up some other family's runner -- fails rather than reading as installed.
//
// generate nil means the family has no generate direction, and it is asserted as an absence
// rather than ignored: a family that grew a generator without this call being updated is a
// generator nothing here says anything about.
//
// And the installed Verify is DRIVEN, not merely identified. Pointer identity says the manifest
// holds this function; it says nothing about the function doing anything. Measured rather than
// supposed: the body of each of the three registered verifiers was replaced by a discard of its
// argument and the package still reported 411 passes, with TestVectorFamiliesVerify still logging
// "3 families verified; 91 published cases offered to them" and TestVectorGenerateThenVerify --
// whose whole stated property rests on Verify -- still logging its generated cases as verified.
// assertInstalledVerifierRefusesAWrongCase closes that, once, here, for every family.
func assertVectorFamilyIsInstalled(
	t *testing.T,
	number int,
	file string,
	verify func(t *testing.T, raw json.RawMessage),
	generate func(t *testing.T) json.RawMessage,
) {
	t.Helper()
	family, ok := vectorManifest[number]
	if !ok {
		t.Fatalf("family %d is not in the manifest", number)
	}
	if family.File != file {
		t.Fatalf("family %d names %s, this runner reads %s", number, family.File, file)
	}
	if family.Verify == nil {
		t.Fatalf("family %d has no Verify, so TestVectorFamiliesVerify runs one family fewer and says nothing about it", number)
	}
	if slices.Contains(expectedPendingFamilies, number) {
		t.Fatalf("family %d is installed and expectedPendingFamilies still names it as pending", number)
	}
	if got := reflect.ValueOf(family.Verify).Pointer(); got != reflect.ValueOf(verify).Pointer() {
		t.Fatalf("family %d is installed with a verifier that is not this runner's", number)
	}
	assertInstalledVerifierRefusesAWrongCase(t, number, family)
	if generate == nil {
		if family.Generate != nil {
			t.Fatalf("family %d is installed with a generator and this runner declares none, so nothing holds that generator to anything", number)
		}
		return
	}
	if family.Generate == nil {
		t.Fatalf("family %d has no Generate, so the generate direction of spec A section 4.2.1 is unexercised for it", number)
	}
	if got := reflect.ValueOf(family.Generate).Pointer(); got != reflect.ValueOf(generate).Pointer() {
		t.Fatalf("family %d is installed with a generator that is not this runner's", number)
	}
}

// ---------------------------------------------------------------------------
// driving the shared machinery, rather than asserting about it
// ---------------------------------------------------------------------------

// probeAssertion runs one assertion against a probe *testing.T of its own and reports whether
// that assertion reported a failure.
//
// On its own goroutine because t.Fatalf leaves through runtime.Goexit: called on the caller's
// goroutine it would end the test doing the probing rather than the probe. A panic is recovered
// and returned rather than taken, for the reason recoveringRow in key_schedule_test.go records
// -- a panic here takes the whole test binary down, and the run then reports one failure
// somewhere else and nothing at all about every test declared after it.
//
// The probe has no parent, so what it records is recorded nowhere else and the caller decides
// what it means. mls/syntax/vectors_test.go drives its own family 16 runner the same way.
func probeAssertion(run func(probe *testing.T)) (failed bool, raised any) {
	probe := &testing.T{}
	done := make(chan struct{})
	go func() {
		// LIFO, so the recover runs first and close(done) last: a caller reading raised
		// after <-done reads it after it was written
		defer close(done)
		defer func() { raised = recover() }()
		run(probe)
	}()
	<-done
	return probe.Failed(), raised
}

// aCaseAtARegisteredSuite is the first case of a corpus at a ciphersuite this package has a
// provider for.
//
// The only kind of case a verifier can be driven with. A case at an unimplemented suite is
// DECLINED -- the normal condition for five of the seven suites the mlswg files publish -- and a
// verifier that declined everything is indistinguishable from one that checked everything, which
// is the whole failure this file exists to make impossible.
func aCaseAtARegisteredSuite(t *testing.T, file string) (json.RawMessage, bool) {
	t.Helper()
	for _, raw := range LoadVectorFile(t, file) {
		header := struct {
			CipherSuite uint16 `json:"cipher_suite"`
		}{}
		if err := json.Unmarshal(raw, &header); err != nil {
			t.Fatalf("parse a %s case: %v", file, err)
		}
		if _, ok := implementedSuite(header.CipherSuite); ok {
			return raw, true
		}
	}
	return nil, false
}

// flipEveryPublishedOctet rewrites one corpus case so every hex string it publishes, at any
// depth, differs from the published one in a single bit, and reports how many it changed.
//
// DERIVED and not supplied by the family, which is the point. A per family hand written wrong
// case is a list, and a list is the shape this project has watched understate its own class
// fourteen times: the family that landed without one would be driven by nothing and would still
// read as installed. One flipped bit of every hex field is wrong wherever the family reads,
// without this function knowing what any family reads.
//
// Numbers are decoded as json.Number and written back as they were read, so the ciphersuite the
// case sits at survives untouched: a case rewritten to an unimplemented suite would be declined
// rather than refused, and every verifier alive or dead would satisfy the control by not running.
//
// Only non-empty valid hex is touched. A label or a name is left alone, since corrupting one
// tests a decoder rather than a comparison -- and a label that happens to read as hex being
// flipped anyway is harmless, because the case is meant to be wrong.
func flipEveryPublishedOctet(t *testing.T, raw json.RawMessage) (json.RawMessage, int) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var tree any
	if err := decoder.Decode(&tree); err != nil {
		t.Fatalf("parse the case to corrupt: %v", err)
	}
	flipped := 0
	var walk func(node any) any
	walk = func(node any) any {
		switch value := node.(type) {
		case map[string]any:
			for key, held := range value {
				value[key] = walk(held)
			}
			return value
		case []any:
			for index, held := range value {
				value[index] = walk(held)
			}
			return value
		case string:
			octets, err := hex.DecodeString(value)
			if err != nil || len(octets) == 0 {
				return value
			}
			octets[0] ^= 0x01
			flipped++
			return hex.EncodeToString(octets)
		}
		return node
	}
	body, err := json.Marshal(walk(tree))
	if err != nil {
		t.Fatalf("re-encode the corrupted case: %v", err)
	}
	return body, flipped
}

// assertInstalledVerifierRefusesAWrongCase drives the Verify a family registered instead of
// asserting about it.
//
// The unmodified case is required to be ACCEPTED first, and that is not a formality: a Verify
// that fataled on everything would satisfy the refusal below while comparing nothing, which is
// the same lesson assertComparatorRefuses records one screen up.
func assertInstalledVerifierRefusesAWrongCase(t *testing.T, number int, family VectorFamily) {
	t.Helper()
	accepted, found := aCaseAtARegisteredSuite(t, family.File)
	if !found {
		t.Fatalf("family %d publishes no case at a suite this package registers, so nothing drives the verifier it installed", number)
	}
	refused, flipped := flipEveryPublishedOctet(t, accepted)
	if flipped == 0 {
		t.Fatalf("family %d's case publishes no hex field to corrupt, so the refusal below would be over an unmodified case", number)
	}
	if failed, raised := probeAssertion(func(probe *testing.T) { family.Verify(probe, accepted) }); raised != nil {
		t.Fatalf("family %d's installed verifier panicked over a published case at a registered suite: %v", number, raised)
	} else if failed {
		t.Fatalf("family %d's installed verifier refused a published case at a registered suite; a verifier that refuses everything satisfies the refusal below",
			number)
	}
	if failed, raised := probeAssertion(func(probe *testing.T) { family.Verify(probe, refused) }); raised != nil {
		t.Fatalf("family %d's installed verifier panicked over a case with all %d of its published hex fields changed: %v",
			number, flipped, raised)
	} else if !failed {
		t.Fatalf("family %d's installed verifier accepted a case with all %d of its published hex fields changed, so it is installed and compares nothing",
			number, flipped)
	}
}

// TestProbeAssertionSeesBothOutcomes is the control on the probe every control below is read
// through.
//
// A probe stuck at "did not report" turns every row below into a green run over an assertion
// that reports nothing, and a probe stuck at "reported" turns every baseline into one. Both
// directions are asserted, and so is the panic path, because a probe that took a panic rather
// than returning it would take the binary down instead of reporting one row.
func TestProbeAssertionSeesBothOutcomes(t *testing.T) {
	if failed, raised := probeAssertion(func(probe *testing.T) {}); failed || raised != nil {
		t.Errorf("an assertion that reported nothing came back failed=%v raised=%v", failed, raised)
	}
	if failed, raised := probeAssertion(func(probe *testing.T) { probe.Errorf("reported") }); !failed || raised != nil {
		t.Errorf("an assertion that reported came back failed=%v raised=%v", failed, raised)
	}
	reached := false
	if failed, raised := probeAssertion(func(probe *testing.T) {
		probe.Fatalf("reported and stopped")
		reached = true
	}); !failed || raised != nil {
		t.Errorf("an assertion that raised a fatal came back failed=%v raised=%v", failed, raised)
	}
	if reached {
		t.Error("a probe's t.Fatalf returned to its caller rather than ending it")
	}
	if failed, raised := probeAssertion(func(probe *testing.T) { panic("the assertion panicked") }); raised == nil {
		t.Errorf("an assertion that panicked came back failed=%v with no panic reported", failed)
	} else if raised != "the assertion panicked" {
		t.Errorf("the probe reported %v rather than what was raised", raised)
	}
}

// theSourceDeclaring finds the file of this package that declares one function, or one method on
// a named receiver, rather than being told which file to read.
//
// Found rather than named for the reason sourceDeclaringPackageFunction records: a gate told
// which file to read goes on issuing a clean bill after the thing it guards moves next door. A
// subject in no file, or in two, is fatal rather than clean.
func theSourceDeclaring(t *testing.T, receiver string, name string) parsedSource {
	t.Helper()
	found := []parsedSource{}
	declaring := []string{}
	for _, path := range packageSourcePaths(t) {
		parsed := mustParseSource(t, path)
		for _, declaration := range parsed.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Name.Name != name || parsed.receiverOf(function) != receiver {
				continue
			}
			found = append(found, parsed)
			declaring = append(declaring, path)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%q %s is declared in %v, want exactly one file of this package", receiver, name, declaring)
	}
	return found[0]
}

// theReportsOf is every failure one declaration can raise, read as the format strings it hands
// t.Errorf, t.Error, t.Fatalf and t.Fatal.
//
// Derived from the source rather than listed, for guardrail 5's reason. A control table that
// enumerates the failures somebody remembered understates its class the moment a tenth assertion
// lands beside the nine it was written against, and the table then reports full coverage of a
// function it covers less of than it did yesterday. t.Logf is not a failure and is not collected.
//
// A report whose first argument is not a string literal is fatal rather than skipped: it is a
// report no row can be bound to, and skipping it would silently shrink the class again.
func theReportsOf(t *testing.T, parsed parsedSource, receiver string, name string) []string {
	t.Helper()
	reports := []string{}
	ast.Inspect(parsed.declarationOf(t, receiver, name), func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		selector, isSelector := call.Fun.(*ast.SelectorExpr)
		if !isSelector || !slices.Contains([]string{"Error", "Errorf", "Fatal", "Fatalf"}, selector.Sel.Name) {
			return true
		}
		if len(call.Args) == 0 {
			t.Fatalf("%s reports through %s with no argument at all, so nothing names it", name, selector.Sel.Name)
		}
		literal, isLiteral := call.Args[0].(*ast.BasicLit)
		if !isLiteral || literal.Kind != token.STRING {
			t.Fatalf("%s reports through %s with a first argument that is not a string literal, so no control row can be bound to it",
				name, selector.Sel.Name)
		}
		text, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatalf("unquote a report of %s: %v", name, err)
		}
		reports = append(reports, text)
		return true
	})
	if len(reports) == 0 {
		t.Fatalf("%s raises no report at all, so the control table over it controls nothing", name)
	}
	return reports
}

// assertEveryReportIsControlled binds a control table to the reports of the function it controls:
// one row per report, one report per row, and neither list allowed to be the longer.
//
// This is what makes the tables below a derived class rather than a list. A row keyed on a
// message that has been reworded matches nothing and fails here; an assertion added without a row
// leaves a report unclaimed and fails here; two rows aimed at one report leave another unclaimed
// and fail here.
func assertEveryReportIsControlled(t *testing.T, name string, reports []string, keys []string) {
	t.Helper()
	if len(keys) != len(reports) {
		t.Fatalf("%s can raise %d reports and this control offers %d rows; the rows name %v",
			name, len(reports), len(keys), keys)
	}
	claimed := map[int]string{}
	for _, key := range keys {
		matched := []int{}
		for index, report := range reports {
			if strings.Contains(report, key) {
				matched = append(matched, index)
			}
		}
		if len(matched) != 1 {
			t.Fatalf("%s: the control row %q names %d of its reports, want exactly one", name, key, len(matched))
		}
		if already, taken := claimed[matched[0]]; taken {
			t.Fatalf("%s: %q and %q both name the report %q, so some other report is named by nothing",
				name, already, key, reports[matched[0]])
		}
		claimed[matched[0]] = key
	}
}

// The two sentinels the comparator control refuses with. Two, because a refusal for the wrong
// reason is one of the things assertComparatorRefuses reports, and a control with one sentinel
// cannot produce it.
var (
	errComparatorControl      = errors.New("the control comparator's own refusal")
	errComparatorControlOther = errors.New("some other refusal entirely")
)

// theComparatorControl has the shape every family's comparator has: it accepts the case that
// says it is the right one and refuses every other, naming its own sentinel.
func theComparatorControl(t *testing.T, raw json.RawMessage) error {
	t.Helper()
	entry := struct {
		Right bool `json:"right"`
	}{}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return fmt.Errorf("%w: the case will not parse: %v", errComparatorControl, err)
	}
	if entry.Right {
		return nil
	}
	return fmt.Errorf("%w: the case is not the right one", errComparatorControl)
}

// comparatorControlFixture is one whole call of assertComparatorRefuses: the comparator, the case
// it must accept, and the table of cases it must refuse.
type comparatorControlFixture struct {
	compare  func(t *testing.T, raw json.RawMessage) error
	accepted json.RawMessage
	refusals []comparatorRefusal
}

func (self comparatorControlFixture) run(probe *testing.T) {
	assertComparatorRefuses(probe, "control", self.compare, self.accepted, self.refusals)
}

// aPassingComparatorControl is the fixture assertComparatorRefuses must accept, and it is what
// makes every row below mean anything: a driver that reported everything would satisfy a table of
// failures and say nothing whatever about the driver.
func aPassingComparatorControl() comparatorControlFixture {
	return comparatorControlFixture{
		compare:  theComparatorControl,
		accepted: json.RawMessage("{\"right\":true}"),
		refusals: []comparatorRefusal{
			{"a case that is not the right one", json.RawMessage("{\"right\":false}"), errComparatorControl},
		},
	}
}

// TestAssertComparatorRefusesFlagsTheControlFixture is the control the shared refusal driver owes
// and has never had.
//
// Three families read their refusal tables through this one function now, and the extraction that
// put them there raised the blast radius of a single deletion inside it from one family to three:
// the one t.Errorf that reports a comparator accepting a deliberately wrong case was deleted, all
// three tables stopped meaning anything, and the package reported 411 passes. Measured, not
// supposed. The rows are bound to the function's own reports, so a seventh assertion cannot land
// here uncontrolled.
func TestAssertComparatorRefusesFlagsTheControlFixture(t *testing.T) {
	if failed, raised := probeAssertion(aPassingComparatorControl().run); failed || raised != nil {
		t.Fatalf("a correct comparator was reported: failed=%v raised=%v; every row below would then pass for the wrong reason",
			failed, raised)
	}
	rows := []struct {
		// names is the substring of the report this row must provoke. The bijection
		// against the function's own reports is asserted below.
		names string
		edit  func(*comparatorControlFixture)
	}{
		{"no deliberately wrong case was offered", func(f *comparatorControlFixture) {
			f.refusals = nil
		}},
		{"is offered twice", func(f *comparatorControlFixture) {
			f.refusals = append(f.refusals, f.refusals[0])
		}},
		{"names no sentinel", func(f *comparatorControlFixture) {
			f.refusals[0].want = nil
		}},
		{"the unmodified published case was refused", func(f *comparatorControlFixture) {
			f.compare = func(t *testing.T, raw json.RawMessage) error { return errComparatorControl }
		}},
		{"the comparator is not comparing", func(f *comparatorControlFixture) {
			f.compare = func(t *testing.T, raw json.RawMessage) error { return nil }
		}},
		{"a refusal for the wrong reason", func(f *comparatorControlFixture) {
			f.compare = func(t *testing.T, raw json.RawMessage) error {
				if err := theComparatorControl(t, raw); err != nil {
					return errComparatorControlOther
				}
				return nil
			}
		}},
	}
	keys := []string{}
	for _, row := range rows {
		keys = append(keys, row.names)
	}
	assertEveryReportIsControlled(t, "assertComparatorRefuses",
		theReportsOf(t, theSourceDeclaring(t, "", "assertComparatorRefuses"), "", "assertComparatorRefuses"), keys)
	for _, row := range rows {
		fixture := aPassingComparatorControl()
		fixture.refusals = slices.Clone(fixture.refusals)
		row.edit(&fixture)
		failed, raised := probeAssertion(fixture.run)
		if raised != nil {
			t.Errorf("%s: the driver panicked: %v", row.names, raised)
			continue
		}
		if !failed {
			t.Errorf("%s: the driver reported nothing, so that report can be deleted with all three families' refusal tables still reading green",
				row.names)
		}
	}
}

// vectorRunControlFixture is one whole call of assertRun: the tally, and the four counts the
// family wrote down.
type vectorRunControlFixture struct {
	tally       *vectorRunTally
	covered     int
	skipped     int
	comparisons int
	distinct    int
}

func (self vectorRunControlFixture) run(probe *testing.T) {
	self.tally.assertRun(probe, self.covered, self.skipped, self.comparisons, self.distinct)
}

// aPassingVectorRun is a run assertRun must accept, built over the suites this package actually
// registers rather than over invented ones, so a suite added to the registry cannot leave this
// control asserting over a registry that no longer exists.
func aPassingVectorRun(t *testing.T) vectorRunControlFixture {
	t.Helper()
	suites := Suites()
	if len(suites) == 0 {
		t.Fatal("this package registers no ciphersuite, so assertRun has nothing to be controlled over")
	}
	// a code point outside the registry, so this run has a skipped half as every real run
	// does. Checked rather than assumed: a registry that grew to hold it would turn the
	// skipped case into a covered one and every row below would drift.
	if _, ok := implementedSuite(unregisteredControlSuite); ok {
		t.Fatalf("suite %#04x is registered, so the skipped case of this control is not skipped", unregisteredControlSuite)
	}
	tally := &vectorRunTally{
		file:        "control.json",
		matched:     map[CipherSuite]int{},
		published:   map[uint16]int{unregisteredControlSuite: 1},
		answers:     map[string]int{"00": 1, "01": 1},
		comparisons: 2,
		skipped:     1,
	}
	for _, suite := range suites {
		tally.published[uint16(suite)]++
		tally.matched[suite]++
		tally.covered++
	}
	tally.entries = tally.covered + tally.skipped
	return vectorRunControlFixture{
		tally:       tally,
		covered:     tally.covered,
		skipped:     tally.skipped,
		comparisons: tally.comparisons,
		distinct:    len(tally.answers),
	}
}

// Two code points this package does not register: one for the skipped half of a control run, one
// for the row that widens the covered key set. Both are asserted unregistered where they are used
// rather than assumed, because a registry that grew to hold either would make that row silently
// stop being the edit it is named after.
const (
	unregisteredControlSuite = uint16(0xffff)
	alienControlSuite        = uint16(0xfffe)
)

// TestAssertRunFlagsTheControlFixture is the control the shared accounting owes and has never had.
//
// Every count assertion three families make about their own runs lives in assertRun, and an
// `if true { return }` inserted after its t.Helper() disarmed all three at once with the package
// still reporting 411 passes. Measured, not supposed. Each row below is one minimal edit of a run
// assertRun accepts, and the rows are bound to the function's own reports, so an assertion added
// without a row fails here rather than arriving uncontrolled.
func TestAssertRunFlagsTheControlFixture(t *testing.T) {
	if failed, raised := probeAssertion(aPassingVectorRun(t).run); failed || raised != nil {
		t.Fatalf("a complete and consistent run was reported: failed=%v raised=%v; every row below would then pass for the wrong reason",
			failed, raised)
	}
	first := Suites()[0]
	if _, ok := implementedSuite(alienControlSuite); ok {
		t.Fatalf("suite %#04x is registered, so the row below does not widen the covered key set", alienControlSuite)
	}
	rows := []struct {
		// names is the substring of the report this row must provoke; the bijection
		// against assertRun's own reports is asserted below.
		names string
		edit  func(*vectorRunControlFixture)
	}{
		{"a case took neither branch", func(f *vectorRunControlFixture) {
			f.tally.entries++
		}},
		{"matched no case at all", func(f *vectorRunControlFixture) {
			f.tally.matched = map[CipherSuite]int{}
			f.tally.covered = 0
			f.tally.entries = f.tally.skipped
		}},
		{"covered %d cases, want", func(f *vectorRunControlFixture) {
			f.covered++
		}},
		{"skipped %d cases at unimplemented suites", func(f *vectorRunControlFixture) {
			f.skipped++
		}},
		{"the corpus answered for", func(f *vectorRunControlFixture) {
			f.tally.matched[CipherSuite(alienControlSuite)] = 1
		}},
		{"publishes nothing at suite", func(f *vectorRunControlFixture) {
			delete(f.tally.published, uint16(first))
		}},
		{"was covered %d times", func(f *vectorRunControlFixture) {
			f.tally.published[uint16(first)] = f.tally.matched[first] + 1
		}},
		{"made %d comparisons over", func(f *vectorRunControlFixture) {
			f.comparisons++
		}},
		// the family writing zero down for both, which every other row leaves reachable:
		// nothing above this one looks at the magnitude of the counts a family supplies,
		// only at whether the run matched them, and a run that compared nothing matches
		// zero exactly.
		{"so neither count may be zero", func(f *vectorRunControlFixture) {
			f.comparisons = 0
			f.distinct = 0
		}},
		{"distinct published answers, want", func(f *vectorRunControlFixture) {
			f.distinct++
		}},
	}
	keys := []string{}
	for _, row := range rows {
		keys = append(keys, row.names)
	}
	assertEveryReportIsControlled(t, "assertRun",
		theReportsOf(t, theSourceDeclaring(t, "*vectorRunTally", "assertRun"), "*vectorRunTally", "assertRun"), keys)
	for _, row := range rows {
		fixture := aPassingVectorRun(t)
		row.edit(&fixture)
		failed, raised := probeAssertion(fixture.run)
		if raised != nil {
			t.Errorf("%s: assertRun panicked: %v", row.names, raised)
			continue
		}
		if !failed {
			t.Errorf("%s: assertRun reported nothing, so that assertion can be deleted with all three families' counts still reading green",
				row.names)
		}
	}
}

// publishedCorpusSegmentFixture is one whole call of publishedCorpusSegment: the published value,
// the dotted path already walked to reach it, and the segment to step by.
type publishedCorpusSegmentFixture struct {
	raw     json.RawMessage
	walked  string
	segment string
	// want is the value the step must answer when it answers at all, so a row that reached the
	// wrong element is a failure rather than a step that returned something.
	want string
}

func (self publishedCorpusSegmentFixture) run(probe *testing.T) {
	if got := publishedCorpusSegment(probe, self.raw, self.walked, self.segment); string(got) != self.want {
		probe.Errorf("the step answered %s, want %s", got, self.want)
	}
}

// aPassingCorpusSegment is the step publishedCorpusSegment must take, and the shape every row
// below is one edit of: an array of objects addressed by index, which is what family 3's
// leaves.N.M.field paths walk.
func aPassingCorpusSegment() publishedCorpusSegmentFixture {
	return publishedCorpusSegmentFixture{
		raw:     json.RawMessage(`[{"handshake_key":"00"},{"handshake_key":"01"}]`),
		walked:  "leaves.0",
		segment: "1",
		want:    `{"handshake_key":"01"}`,
	}
}

// TestPublishedCorpusSegmentStepsIntoTheShapeThePublishedValueHas is the control the walk every
// family reads its second decode through has never had.
//
// It was exercised only through family 3's leaves.N.M.field paths, and only in the direction
// where those paths are right: nothing asked it what it does with a segment that addresses
// nothing, and nothing at all pinned WHICH ARM it takes. The arm is the reason this test
// exists. It used to be chosen by asking strconv.Atoi about the segment, so an object key
// spelled as a decimal -- which no vendored corpus publishes today and any corpus update may --
// was decoded as an array and reported as a broken path at a path that is correct. The first
// assertion below is that case, and it is the one that fails against the order this replaces.
//
// The rows are bound to the function's own reports, so a sixth refusal cannot land here
// uncontrolled -- and a refusal deleted from it leaves a row naming nothing and fails here
// rather than turning a path that addresses nothing into an empty string compared against an
// empty string somewhere else.
func TestPublishedCorpusSegmentStepsIntoTheShapeThePublishedValueHas(t *testing.T) {
	if failed, raised := probeAssertion(aPassingCorpusSegment().run); failed || raised != nil {
		t.Fatalf("the step every family's second decode is made of was reported: failed=%v raised=%v; every row below would then pass for the wrong reason",
			failed, raised)
	}
	// the arm itself: a json object whose keys are spelled as decimals takes a KEY. Read off the
	// value's shape, this is an ordinary object lookup; read off the segment's spelling, it is an
	// array index into something that is not an array.
	decimalKeys := publishedCorpusSegmentFixture{
		raw:     json.RawMessage(`{"0":"beef","1":"cafe"}`),
		walked:  "sender_data",
		segment: "1",
		want:    `"cafe"`,
	}
	if failed, raised := probeAssertion(decimalKeys.run); failed || raised != nil {
		t.Errorf("a json object whose keys are spelled as decimals was not walked as an object: failed=%v raised=%v",
			failed, raised)
	}
	rows := []struct {
		// names is the substring of the report this row must provoke; the bijection against
		// publishedCorpusSegment's own reports is asserted below.
		names string
		edit  func(*publishedCorpusSegmentFixture)
	}{
		{"is a json object and does not carry", func(f *publishedCorpusSegmentFixture) {
			f.raw, f.segment = json.RawMessage(`{"handshake_key":"00"}`), "application_key"
		}},
		{"neither a json object nor a json array", func(f *publishedCorpusSegmentFixture) {
			f.raw = json.RawMessage(`"00"`)
		}},
		{"is not a decimal index", func(f *publishedCorpusSegmentFixture) {
			f.segment = "handshake_key"
		}},
		{"spelled another way", func(f *publishedCorpusSegmentFixture) {
			f.segment = "01"
		}},
		{"elements and index", func(f *publishedCorpusSegmentFixture) {
			f.segment = "2"
		}},
	}
	keys := []string{}
	for _, row := range rows {
		keys = append(keys, row.names)
	}
	assertEveryReportIsControlled(t, "publishedCorpusSegment",
		theReportsOf(t, theSourceDeclaring(t, "", "publishedCorpusSegment"), "", "publishedCorpusSegment"), keys)
	for _, row := range rows {
		fixture := aPassingCorpusSegment()
		row.edit(&fixture)
		failed, raised := probeAssertion(fixture.run)
		if raised != nil {
			t.Errorf("%s: the step panicked: %v", row.names, raised)
			continue
		}
		if !failed {
			t.Errorf("%s: the step reported nothing, so a path that addresses nothing comes back as a value every family compares against",
				row.names)
		}
	}
}
