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
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
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
	if found := blob[at : at+len(prefix)]; !equalOctets(found, prefix) {
		return nil, nil, fmt.Errorf("%w: the %d octets before its last %d are %x, and a <V> vector of %d octets is written %x",
			errVectorTagTail, len(prefix), nh, found, nh, prefix)
	}
	return blob[:at], blob[len(blob)-nh:], nil
}

// equalOctets is a length-checked octet comparison for the length prefix above, spelled out
// rather than imported so this file needs no comparator a reader has to check against
// guardrail 8 on the way past. Nothing here compares a tag: the split reads a length prefix,
// and every tag comparison in this package goes through CryptoProvider.MacVerify.
func equalOctets(left []byte, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
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
	key, nested, isNested := strings.Cut(name, ".")
	raw, found := published[key]
	if !found {
		t.Fatalf("the corpus case does not publish %q, so whatever decodes it decodes to nothing and every comparison over it is vacuous", key)
	}
	if isNested {
		inner := map[string]json.RawMessage{}
		if err := json.Unmarshal(raw, &inner); err != nil {
			t.Fatalf("the published %s is not a json object: %v", key, err)
		}
		raw, found = inner[nested]
		if !found {
			t.Fatalf("the published %s does not carry %q", key, nested)
		}
	}
	text := ""
	if err := json.Unmarshal(raw, &text); err != nil {
		t.Fatalf("the published %s is not a json string: %v", name, err)
	}
	return text
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
