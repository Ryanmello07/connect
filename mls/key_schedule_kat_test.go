// Runners for the mlswg key schedule and psk_secret vector families.
//
// This file lands vector family 6, psk_secret.json, and the suite filter every runner in
// this file will share. Family 6 is retained even though PSK proposals are refused by the
// v1 profile: psk_secret is computed on every epoch as the empty case, and the non-empty
// cases are the only check in this system on the PSKLabel encoding and on the argument
// order of the section 8.4 recurrence.
//
// What this file is defending against, stated once because every assertion below is an
// instance of it: a vector runner that ran nothing reports exactly what a vector runner
// that passed everything reports. Five separate things stand in the way.
//
//   - The comparator returns the values it derived rather than a bool, and its callers
//     judge those values. This is the one that had to be rewritten. A bool whose last
//     statement is `return true` reports that control reached the bottom of the function,
//     not that a comparison happened, so an early return anywhere above it left the count
//     reading 22 with PskSecret never called; and moving that bool one stack frame out of
//     the loop, which the first fix did, keeps the shape and only changes where it lies.
//     A value that must be KDF.Nh octets wide, must have moved when the corpus's own psk
//     moved, and must equal the published answer cannot be produced by skipping the work.
//   - The suites the filter matched are compared against the ciphersuite registry rather
//     than against a list written here, so a filter that matched nothing, and a filter
//     that matched all seven published suites, both fail. The per suite split is checked
//     too, against what the corpus itself publishes at each suite, so 21 comparisons at
//     one registered suite and one at the other is a failure rather than a total of 22.
//   - The corpus is loaded through LoadVectorFile, which is fatal and never skipping, and
//     no runner file may name a skip at all; TestNoVectorRunnerCanSkip derives the skip
//     class from the testing package rather than listing it.
//   - Each comparison carries its own vacuity control: the published answer for a
//     non-empty list must differ from the empty answer, and one flipped octet of the
//     corpus's own psk must move the value this package computes. Both fail if the
//     corpus data never reached the derivation.
//   - The comparator is required to REFUSE. Every case in the vendored corpus agrees with
//     this implementation, so a comparator that checked everything and a comparator that
//     checked nothing produce identical runs over it; the only way to tell them apart is
//     to hand the comparator an answer that is wrong on purpose and require the matching
//     refusal, which is what TestComparePskSecretVectorRefusesAnAnswerItShouldNotAccept
//     does over four defect classes.
//
// And the generate direction. The published corpus never passes through our own encoder,
// so verification alone cannot see an encoder and a decoder that are wrong in the same
// direction. Generating a case and verifying it does -- but only if the generator is not
// the verifier under another name, which is the trap: PskSecret generating an answer that
// PskSecret then checks proves nothing about conformance at all. The generator here is
// independentPskSecret, written from RFC 5869 and RFC 9420 with crypto/hmac and nothing
// this package declares, held against the published corpus, and held structurally to
// touching no production function by TestTheGenerateDirectionSharesNoCodePathWithVerify.
// That gate walks the closure over EVERY test file of this package, not the vector runner
// files alone: a function it cannot see is a leaf whose body it never enters, so a narrower
// file class is an escape hatch one hop wide -- route the answer through a helper declared
// in psk_test.go and the whole production closure is laundered.
package mls

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The family, and the accounting that makes its runner unable to pass having compared
// nothing.
//
// The three counts are transcriptions of what testdata/vectors/psk_secret.json holds at
// the pinned mlswg commit: 77 entries, eleven at each of the seven published ciphersuites,
// of which the two this package registers account for 22, and those 22 carry 21 distinct
// answers because the two empty lists both answer the all zero string. They are written
// down rather than derived because deriving the expected count with the same filter under
// test is how a filter that matched nothing ends up agreeing with itself.
//
// What IS derived, and checked alongside them, is that the two counts partition the file:
// compared plus skipped must equal the number of entries read, so an entry silently
// dropped by neither branch fails here rather than shrinking the run.
const (
	pskSecretKatFile            = "psk_secret.json"
	pskSecretKatComparisons     = 22
	pskSecretKatSkipped         = 55
	pskSecretKatDistinctAnswers = 21
)

// implementedSuite maps a vector's cipher_suite field to a provider this package
// implements. The published files cover suites 1 through 7 and v1 registers 0x0001 and
// 0x0003, so five of the seven are skipped.
//
// The answer is read out of the ciphersuite registry rather than written as a switch over
// the two code points. A switch would be a second, private opinion about which suites this
// package implements, and the failure it produces is the quiet one: register a third suite
// and every vector family in this package keeps skipping it, reporting a clean run over a
// corpus it silently stopped covering. TestImplementedSuiteIsTheRegistryAndNotAList sweeps
// the whole uint16 space against the registry, so the two cannot drift.
//
// The signature is the interface registry's, taking a uint16 because that is the type the
// vector files decode into, and returning a CipherSuite because that is what every caller
// needs next. Tasks 17, 18, 20 and 25 consume it.
func implementedSuite(suite uint16) (CipherSuite, bool) {
	candidate := CipherSuite(suite)
	if !IsRegisteredSuite(candidate) {
		return 0, false
	}
	return candidate, true
}

// pskSecretKatVector is one entry of psk_secret.json. Binary fields are hex strings in the
// file and stay strings here: MustHex is the single decoder, HexOf the single encoder, and
// a struct holding []byte would need a second one at the json boundary.
//
// The name carries the Kat prefix because psk_test.go already reads this file for the
// ValSem401 acceptance sweep and declares pskSecretVector for it. Two names for one shape
// in one package is worse than one, but the alternative here is worse still: the two
// structs are read by two different plans for two different reasons, and collapsing them
// would put this task's registry-facing decode inside a file the registry does not know
// about.
type pskSecretKatVector struct {
	CipherSuite uint16 `json:"cipher_suite"`
	Psks        []struct {
		PskId    string `json:"psk_id"`
		Psk      string `json:"psk"`
		PskNonce string `json:"psk_nonce"`
	} `json:"psks"`
	PskSecret string `json:"psk_secret"`
}

// Family 6 is installed here, and 6 is deleted from expectedPendingFamilies in the same
// commit. Without both halves TestVectorFamiliesVerify runs one fewer family and the
// manifest gate stays green while claiming this family is unimplemented.
func init() {
	RegisterVectorFamily(VectorFamily{
		Number:   6,
		Name:     "Pre-shared keys",
		File:     pskSecretKatFile,
		Slice:    "A3",
		Verify:   verifyPskSecretVector,
		Generate: generatePskSecretVectors,
	})
}

// The refusals comparePskSecretVector makes, as sentinels rather than as formatted
// strings, so a test can require a specific refusal rather than "some error".
//
// They are what makes the comparison observable. A comparator that reports its verdict by
// calling t.Fatalf can only be judged by a corpus that happens to disagree with it, and
// the corpus in this tree agrees with everything; a comparator that RETURNS its verdict
// can be handed a deliberately wrong answer and required to refuse it, which is what
// TestComparePskSecretVectorRefusesAnAnswerItShouldNotAccept does.
var (
	errPskSecretPublishedWidth = errors.New("the published psk_secret is not the suite's KDF.Nh")
	errPskSecretIsEmptyAnswer  = errors.New("the published answer for a non-empty list is the empty answer")
	errPskSecretMismatch       = errors.New("psk_secret does not match the published answer")
	errPskSecretDidNotMove     = errors.New("flipping one octet of the published psk left psk_secret unchanged")
	errPskSecretIncomplete     = errors.New("the comparison reports values it cannot have computed")
)

// pskSecretComparison is what one run of comparePskSecretVector PRODUCED, and it is the
// only thing its callers are allowed to judge it by.
//
// This shape is the fix for the defect the first version of this file had. That version
// returned a bool, and the bool was the last statement of the function, so what it
// reported was "control reached the bottom" and not "a comparison happened": an early
// return inserted anywhere above it left the runner counting 22 comparisons that never
// called PskSecret at all, and the run stayed green. A bool cannot be told apart from a
// literal. These fields can: every one of them is written at the point the work that
// produces it happens, so a return that skipped the work reports the zero value, and a
// caller that looks at the values rather than at the fact of returning sees that.
//
// published is decoded by the comparator and computed is produced by PskSecret, and the
// runner re-derives the published half from the corpus text it parsed itself before
// comparing the two. That is deliberate duplication: the comparator's own bytes.Equal and
// the runner's hex string comparison are two expressions of one predicate over two
// independent decodes, and neutralising either one leaves the other standing.
type pskSecretComparison struct {
	// inScope is true when the vector's ciphersuite is one this package registers. A
	// false here is not a failure and not a skip: it is a case with no provider.
	inScope bool
	// psks is how many pre-shared keys reached the derivation, which is what decides
	// whether the two non-empty controls below apply.
	psks int
	// hashSize is the suite's KDF.Nh, read off the provider rather than assumed.
	hashSize int
	// published is the corpus's own answer, decoded.
	published []byte
	// computed is what PskSecret answered for this case.
	computed []byte
	// empty is EmptyPskSecret for this suite: the answer an implementation that ignored
	// the list entirely would give.
	empty []byte
	// perturbed is what PskSecret answers with one octet of the last psk flipped. Nil
	// where there is no non-empty psk to flip, which the two callers both allow for.
	perturbed []byte
}

// incomplete reports whether the fields a compared case must carry are missing or
// inconsistent, without looking at whether the answer was right.
//
// This is the vacuity half, split out from the correctness half on purpose. A comparison
// that produced no computed value, or a computed value of the wrong width, or an empty
// control it never derived, has not compared anything whatever bytes.Equal would say
// about it -- and bytes.Equal over two empty slices says they agree.
func (self pskSecretComparison) incomplete() error {
	switch {
	case !self.inScope:
		return fmt.Errorf("%w: the case is out of scope and carries no comparison", errPskSecretIncomplete)
	case self.hashSize == 0:
		return fmt.Errorf("%w: no KDF.Nh was read from the provider", errPskSecretIncomplete)
	case len(self.computed) != self.hashSize:
		return fmt.Errorf("%w: PskSecret produced %d octets and the suite's KDF.Nh is %d",
			errPskSecretIncomplete, len(self.computed), self.hashSize)
	case len(self.published) != self.hashSize:
		return fmt.Errorf("%w: the published answer is %d octets and the suite's KDF.Nh is %d",
			errPskSecretIncomplete, len(self.published), self.hashSize)
	case len(self.empty) != self.hashSize:
		return fmt.Errorf("%w: the empty answer control was never derived", errPskSecretIncomplete)
	case self.psks > 0 && len(self.perturbed) != self.hashSize:
		return fmt.Errorf("%w: %d psks reached the derivation and the flipped octet control was never run",
			errPskSecretIncomplete, self.psks)
	}
	return nil
}

// verdict is the whole judgement over one compared case: it must be complete, it must
// agree with the corpus, and both vacuity controls must have moved.
//
// Both callers of the comparator run this, and the runner then runs its own comparison
// over the same evidence from the corpus text it decoded itself. One caller would be
// enough for a correct tree and is not enough for this one: the registry shim reaches
// this comparator over all 77 published cases and over every generated case, and the
// runner reaches it over the 22 in scope, so a defect that only the generated cases
// expose has to be refused on the shim's path too.
func (self pskSecretComparison) verdict() error {
	if err := self.incomplete(); err != nil {
		return err
	}
	if self.psks > 0 && bytes.Equal(self.published, self.empty) {
		return fmt.Errorf("%w: a list of %d psks answers %s, which is what an implementation that ignored the list would answer",
			errPskSecretIsEmptyAnswer, self.psks, HexOf(self.empty))
	}
	if !bytes.Equal(self.computed, self.published) {
		return fmt.Errorf("%w: %d psks give %s, the corpus publishes %s",
			errPskSecretMismatch, self.psks, HexOf(self.computed), HexOf(self.published))
	}
	if self.psks > 0 && bytes.Equal(self.perturbed, self.computed) {
		return fmt.Errorf("%w: %d psks, so the corpus data never reached the derivation",
			errPskSecretDidNotMove, self.psks)
	}
	return nil
}

// verifyPskSecretVector is the registry's shim: the signature RegisterVectorFamily needs,
// over the comparator that does the work and reports what it produced.
//
// The split is the whole point. Verify cannot return anything, so a runner that counted
// calls to it would count a case it declined to check exactly as it counts a case it
// compared. comparePskSecretVector returns the values it derived and TestVectorPskSecret
// judges them.
func verifyPskSecretVector(t *testing.T, raw json.RawMessage) {
	t.Helper()
	evidence, err := comparePskSecretVector(t, raw)
	if err != nil {
		t.Fatalf("psk_secret: %v", err)
	}
	if !evidence.inScope {
		return
	}
	if err := evidence.verdict(); err != nil {
		t.Fatalf("psk_secret: %v", err)
	}
}

// comparePskSecretVector runs one entry of psk_secret.json and returns what the run
// produced. A vector at a ciphersuite v1 does not implement is not a failure and not a
// skip: it is a case this package has no provider for, and it comes back with inScope
// false and nothing else set.
//
// A corpus that will not parse or will not hex decode is fatal here rather than returned,
// because it is not a verdict about this implementation -- it is the evidence itself being
// unreadable, and every family in this package treats that as the loudest failure there
// is. Everything that IS a verdict about this implementation is returned, so a caller can
// require a refusal instead of hoping the corpus disagrees with a defect.
//
// The two controls carried per comparison are here rather than in the runner because they
// need the vector's own bytes. A published answer for a non-empty list that equalled the
// empty answer would let an implementation returning KDF.Nh zeroes pass; and if the psk
// list never reached PskSecret -- a renamed json field, a struct tag typo, a decoder
// returning nothing -- then flipping an octet of the corpus's own psk would leave the
// answer where it was. Both are the shape that has caught this before: install the
// corpus's own data and refuse to proceed unless the value moves.
func comparePskSecretVector(t *testing.T, raw json.RawMessage) (pskSecretComparison, error) {
	t.Helper()
	vector := pskSecretKatVector{}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("parse psk_secret entry: %v", err)
	}
	suite, ok := implementedSuite(vector.CipherSuite)
	if !ok {
		return pskSecretComparison{}, nil
	}
	crypto, err := NewCryptoProvider(suite)
	if err != nil {
		t.Fatalf("NewCryptoProvider(%#04x): %v", uint16(suite), err)
	}
	psks := make([]PreSharedKeyInput, 0, len(vector.Psks))
	for _, entry := range vector.Psks {
		psks = append(psks, PreSharedKeyInput{
			Id: PreSharedKeyId{
				PskType:  PskTypeExternal,
				PskId:    MustHex(t, entry.PskId),
				PskNonce: MustHex(t, entry.PskNonce),
			},
			Secret: MustHex(t, entry.Psk),
		})
	}
	if len(psks) != len(vector.Psks) {
		t.Fatalf("the entry carries %d psks and %d reached the derivation", len(vector.Psks), len(psks))
	}
	evidence := pskSecretComparison{
		inScope:   true,
		psks:      len(psks),
		hashSize:  crypto.HashSize(),
		published: MustHex(t, vector.PskSecret),
		empty:     EmptyPskSecret(crypto),
	}
	if len(evidence.published) != evidence.hashSize {
		return evidence, fmt.Errorf("%w: %d octets against a KDF.Nh of %d, so this is not the comparison the corpus intends",
			errPskSecretPublishedWidth, len(evidence.published), evidence.hashSize)
	}
	computed, err := PskSecret(crypto, psks)
	if err != nil {
		return evidence, fmt.Errorf("%d psks: PskSecret: %w", len(psks), err)
	}
	evidence.computed = computed

	// the vacuity control: one octet of the corpus's own psk, flipped, must move the
	// answer. An agreement that survives this was not computed from the corpus.
	if len(psks) > 0 && len(psks[len(psks)-1].Secret) > 0 {
		moved := make([]PreSharedKeyInput, len(psks))
		copy(moved, psks)
		last := moved[len(moved)-1]
		flipped := bytes.Clone(last.Secret)
		flipped[0] ^= 0x01
		last.Secret = flipped
		moved[len(moved)-1] = last
		perturbed, err := PskSecret(crypto, moved)
		if err != nil {
			return evidence, fmt.Errorf("PskSecret over the perturbed list: %w", err)
		}
		evidence.perturbed = perturbed
	}
	return evidence, evidence.verdict()
}

// TestVectorPskSecret is vector family 6 over the published corpus.
//
// Every assertion after the loop exists because the loop can be made to run zero times
// without anything else in this package noticing. A filter that matched nothing, a filter
// that matched all seven published suites, a corpus that parsed to an empty array, a
// comparator that declined every case: each of those is a green run of this test with the
// assertions removed, and a failure with them.
//
// What the loop counts is the part that had to be rewritten. It does not count calls that
// returned; it counts cases whose returned evidence the runner itself checked against the
// corpus text it decoded, so a comparator that answered without computing anything is a
// failure here rather than a number that looks right.
func TestVectorPskSecret(t *testing.T) {
	entries := LoadVectorFile(t, pskSecretKatFile)
	if len(entries) == 0 {
		t.Fatalf("%s parsed to no entries, so every comparison below would be against nothing", pskSecretKatFile)
	}

	compared, skipped := 0, 0
	matched := map[CipherSuite]int{}
	// published counts every entry by its ciphersuite, in scope or not. The per suite
	// split below is derived from it rather than written here: the corpus is a grid of
	// one list length series per published suite, so what each registered suite owes is
	// what the corpus holds for it, and a run that compared all 22 at one suite fails
	// against that without anyone having to transcribe eleven.
	published := map[uint16]int{}
	answers := map[string]int{}
	for index, raw := range entries {
		header := struct {
			CipherSuite uint16 `json:"cipher_suite"`
			PskSecret   string `json:"psk_secret"`
		}{}
		if err := json.Unmarshal(raw, &header); err != nil {
			t.Fatalf("vector %d: %v", index, err)
		}
		published[header.CipherSuite]++
		suite, ok := implementedSuite(header.CipherSuite)
		if !ok {
			skipped++
			continue
		}
		evidence, err := comparePskSecretVector(t, raw)
		if err != nil {
			t.Fatalf("vector %d (suite %#04x): %v", index, header.CipherSuite, err)
		}
		if !evidence.inScope {
			t.Fatalf("vector %d is at suite %#04x, which this package registers, and the comparator declined it",
				index, header.CipherSuite)
		}
		if err := evidence.verdict(); err != nil {
			t.Fatalf("vector %d (suite %#04x): %v", index, header.CipherSuite, err)
		}
		// and the runner's own half of the comparison, against the answer it decoded
		// out of the corpus itself rather than against the comparator's copy of it.
		if got := HexOf(evidence.computed); got != header.PskSecret {
			t.Fatalf("vector %d (suite %#04x, %d psks): this package computes %s, the corpus publishes %s",
				index, header.CipherSuite, evidence.psks, got, header.PskSecret)
		}
		compared++
		matched[suite]++
		answers[header.PskSecret]++
	}

	if compared+skipped != len(entries) {
		t.Fatalf("%d compared and %d skipped over %d entries; an entry took neither branch",
			compared, skipped, len(entries))
	}
	if compared != pskSecretKatComparisons {
		t.Fatalf("compared %d published psk_secrets, want %d; the filter matched %v",
			compared, pskSecretKatComparisons, matched)
	}
	if skipped != pskSecretKatSkipped {
		t.Fatalf("skipped %d entries at unimplemented suites, want %d", skipped, pskSecretKatSkipped)
	}
	if got := slices.Sorted(maps.Keys(matched)); !slices.Equal(got, Suites()) {
		t.Fatalf("the corpus answered for %v and this package registers %v", got, Suites())
	}
	// the per suite split, which the key set above says nothing about: 21 comparisons at
	// one registered suite and 1 at the other satisfies both the count and the key set,
	// and is a run that covered one suite.
	perSuite := map[int]bool{}
	for _, count := range published {
		perSuite[count] = true
	}
	if len(perSuite) != 1 {
		t.Fatalf("the corpus publishes %v cases per suite; this family's file is a grid of one series per suite and the split below assumes it",
			published)
	}
	for _, suite := range Suites() {
		want := published[uint16(suite)]
		if want == 0 {
			t.Fatalf("the corpus publishes nothing at suite %#04x, which this package registers", uint16(suite))
		}
		if matched[suite] != want {
			t.Fatalf("suite %#04x was compared %d times and the corpus publishes %d cases at it",
				uint16(suite), matched[suite], want)
		}
	}
	if len(answers) != pskSecretKatDistinctAnswers {
		t.Fatalf("the %d comparisons were made against %d distinct published answers, want %d; a corpus read as one repeated value would compare that many times and pin one answer",
			compared, len(answers), pskSecretKatDistinctAnswers)
	}
	t.Logf("psk_secret: compared %d over %d distinct published answers, %d at each of the suites %v, skipped %d at unimplemented suites",
		compared, len(answers), published[uint16(Suites()[0])], slices.Sorted(maps.Keys(matched)), skipped)
}

// TestComparePskSecretVectorRefusesAnAnswerItShouldNotAccept is the control the runner
// cannot be: it hands the comparator answers that are wrong in each of the ways the corpus
// is not, and requires the matching refusal.
//
// Why this test rather than more assertions in the runner. Every comparison the runner
// makes is over a corpus that agrees with this implementation, so a comparator that
// accepted everything and a comparator that checked everything produce identical runs
// there. The only way to see the difference is to disagree with it on purpose. Each case
// below is a real defect class -- a wrong answer, an answer of the wrong width, a
// non-empty list published with the empty answer, a psk list that never reached the
// derivation -- and each names the sentinel it owes, so a refusal for the wrong reason is
// a failure too.
//
// The unmodified case is checked first and is the reason the four refusals mean anything:
// a comparator that refused everything would satisfy them all.
func TestComparePskSecretVectorRefusesAnAnswerItShouldNotAccept(t *testing.T) {
	entries := LoadVectorFile(t, pskSecretKatFile)
	base := pskSecretKatVector{}
	found := false
	for _, raw := range entries {
		candidate := pskSecretKatVector{}
		if err := json.Unmarshal(raw, &candidate); err != nil {
			t.Fatalf("parse a psk_secret entry: %v", err)
		}
		// a case with at least two psks, so the flipped octet control has something to
		// flip and the index and count fields of PSKLabel are both exercised.
		if _, ok := implementedSuite(candidate.CipherSuite); ok && len(candidate.Psks) >= 2 {
			base, found = candidate, true
			break
		}
	}
	if !found {
		t.Fatal("no published case at a registered suite carries two or more psks, so this control has nothing to corrupt")
	}

	encode := func(vector pskSecretKatVector) json.RawMessage {
		body, err := json.Marshal(vector)
		if err != nil {
			t.Fatalf("marshal the case under test: %v", err)
		}
		return body
	}

	evidence, err := comparePskSecretVector(t, encode(base))
	if err != nil {
		t.Fatalf("the unmodified published case was refused: %v", err)
	}
	if !evidence.inScope || len(evidence.computed) == 0 {
		t.Fatalf("the unmodified published case produced %+v, which carries no comparison", evidence)
	}
	if HexOf(evidence.computed) != base.PskSecret {
		t.Fatalf("the unmodified published case computed %s against a published %s", HexOf(evidence.computed), base.PskSecret)
	}

	wrongAnswer := base
	flipped := MustHex(t, base.PskSecret)
	flipped[0] ^= 0x01
	wrongAnswer.PskSecret = HexOf(flipped)

	wrongWidth := base
	wrongWidth.PskSecret = base.PskSecret[:len(base.PskSecret)-2]

	emptyAnswer := base
	crypto, err := NewCryptoProvider(CipherSuite(base.CipherSuite))
	if err != nil {
		t.Fatalf("NewCryptoProvider(%#04x): %v", base.CipherSuite, err)
	}
	emptyAnswer.PskSecret = HexOf(EmptyPskSecret(crypto))

	// a psk list that decodes to nothing while the published answer stays the non-empty
	// one: the shape a renamed json field or a struct tag typo produces, and the one the
	// flipped octet control exists for.
	noPsks := base
	noPsks.Psks = nil

	for _, corrupted := range []struct {
		name   string
		vector pskSecretKatVector
		want   error
	}{
		{"one flipped octet of the published answer", wrongAnswer, errPskSecretMismatch},
		{"a published answer one octet short of KDF.Nh", wrongWidth, errPskSecretPublishedWidth},
		{"the empty answer published for a non-empty list", emptyAnswer, errPskSecretIsEmptyAnswer},
		{"the psk list dropped and the answer kept", noPsks, errPskSecretMismatch},
	} {
		_, err := comparePskSecretVector(t, encode(corrupted.vector))
		if err == nil {
			t.Errorf("%s was accepted; the comparator is not comparing", corrupted.name)
			continue
		}
		if !errors.Is(err, corrupted.want) {
			t.Errorf("%s was refused as %v, want %v; a refusal for the wrong reason is a comparator checking something else",
				corrupted.name, err, corrupted.want)
		}
	}
}

// TestPskSecretComparisonCannotReportAComparisonItDidNotMake is the control on the
// evidence struct itself.
//
// The defect this whole shape replaces was a comparator whose "I compared" signal was the
// last statement of the function. The signal is now the values it produced, and this is
// what says those values cannot be faked by omission: a zero comparison, a computed value
// of the wrong width, a missing empty control and a missing flipped octet control are each
// required to be refused as incomplete, so a return that skipped the work is a failure on
// every caller's path rather than a count that still reads 22.
func TestPskSecretComparisonCannotReportAComparisonItDidNotMake(t *testing.T) {
	full := pskSecretComparison{
		inScope:   true,
		psks:      2,
		hashSize:  sha256.Size,
		published: bytes.Repeat([]byte{0xaa}, sha256.Size),
		computed:  bytes.Repeat([]byte{0xaa}, sha256.Size),
		empty:     make([]byte, sha256.Size),
		perturbed: bytes.Repeat([]byte{0xbb}, sha256.Size),
	}
	if err := full.verdict(); err != nil {
		t.Fatalf("a complete and agreeing comparison was refused: %v; every case below would then pass for the wrong reason", err)
	}

	without := func(edit func(*pskSecretComparison)) pskSecretComparison {
		partial := full
		partial.published = bytes.Clone(full.published)
		partial.computed = bytes.Clone(full.computed)
		partial.empty = bytes.Clone(full.empty)
		partial.perturbed = bytes.Clone(full.perturbed)
		edit(&partial)
		return partial
	}
	for _, missing := range []struct {
		name string
		edit func(*pskSecretComparison)
	}{
		{"a comparison that returned before anything was set", func(c *pskSecretComparison) { *c = pskSecretComparison{} }},
		{"in scope and nothing else", func(c *pskSecretComparison) { *c = pskSecretComparison{inScope: true} }},
		{"no computed value", func(c *pskSecretComparison) { c.computed = nil }},
		{"a computed value of the wrong width", func(c *pskSecretComparison) { c.computed = c.computed[:len(c.computed)-1] }},
		{"no published value", func(c *pskSecretComparison) { c.published = nil }},
		{"no empty answer control", func(c *pskSecretComparison) { c.empty = nil }},
		{"no flipped octet control over a non-empty list", func(c *pskSecretComparison) { c.perturbed = nil }},
		{"no KDF.Nh read from the provider", func(c *pskSecretComparison) { c.hashSize = 0 }},
	} {
		partial := without(missing.edit)
		err := partial.verdict()
		if err == nil {
			t.Errorf("%s was accepted as a comparison", missing.name)
			continue
		}
		if !errors.Is(err, errPskSecretIncomplete) {
			t.Errorf("%s was refused as %v, want an incompleteness", missing.name, err)
		}
	}

	// and the correctness half, which incompleteness must not be standing in for.
	disagreeing := without(func(c *pskSecretComparison) { c.computed[0] ^= 0x01 })
	if err := disagreeing.verdict(); !errors.Is(err, errPskSecretMismatch) {
		t.Errorf("a complete comparison whose computed value disagrees was judged %v, want a mismatch", err)
	}
	stuck := without(func(c *pskSecretComparison) { c.perturbed = bytes.Clone(c.computed) })
	if err := stuck.verdict(); !errors.Is(err, errPskSecretDidNotMove) {
		t.Errorf("a comparison whose flipped octet control did not move was judged %v, want that refusal", err)
	}
	// the empty list arm: no flipped octet control is owed, and the empty answer control
	// does not apply, so an agreeing empty case must be accepted.
	empty := without(func(c *pskSecretComparison) {
		c.psks = 0
		c.perturbed = nil
		c.computed = bytes.Clone(c.empty)
		c.published = bytes.Clone(c.empty)
	})
	if err := empty.verdict(); err != nil {
		t.Fatalf("an agreeing empty list case was refused: %v; the 2 empty cases of the corpus would fail for the wrong reason", err)
	}
}

// TestImplementedSuiteIsTheRegistryAndNotAList sweeps every uint16 code point and requires
// implementedSuite to answer exactly what the ciphersuite registry answers.
//
// This is the check that stops the filter becoming a hand written list. Fourteen times on
// this project a hand written list understated the class it was meant to describe, and the
// version of that failure here is silent in the worst way: a third suite registered, every
// vector family still skipping it, and every runner reporting a clean pass over a corpus it
// no longer covers.
//
// The registry read is checked for the two suites it must hold first, so the sweep cannot
// pass by having derived nothing.
func TestImplementedSuiteIsTheRegistryAndNotAList(t *testing.T) {
	registered := Suites()
	if len(registered) != 2 {
		t.Fatalf("the registry holds %v; this test expects the two v1 suites, and a change here means the counts in this file need revisiting", registered)
	}
	for _, suite := range []CipherSuite{
		CipherSuiteX25519AesGcm128Sha256Ed25519,
		CipherSuiteX25519ChaCha20Sha256Ed25519,
	} {
		if !slices.Contains(registered, suite) {
			t.Fatalf("the registry does not hold %#04x, so the sweep below is reading nothing useful", uint16(suite))
		}
	}

	accepted := []CipherSuite{}
	for point := 0; point <= 0xffff; point++ {
		code := uint16(point)
		suite, ok := implementedSuite(code)
		if ok != IsRegisteredSuite(CipherSuite(code)) {
			t.Fatalf("implementedSuite(%#04x) = %v and the registry says %v", code, ok, IsRegisteredSuite(CipherSuite(code)))
		}
		if !ok {
			if suite != 0 {
				t.Fatalf("implementedSuite(%#04x) refused and still answered %#04x", code, uint16(suite))
			}
			continue
		}
		if uint16(suite) != code {
			t.Fatalf("implementedSuite(%#04x) answered %#04x, so the filter renumbers the suite it matched", code, uint16(suite))
		}
		accepted = append(accepted, suite)
	}
	if !slices.Equal(accepted, registered) {
		t.Fatalf("the sweep accepted %v and the registry holds %v", accepted, registered)
	}
}

// TestPskSecretFamilyIsInstalled is the registration half of this task.
//
// Registering the family and deleting its number from expectedPendingFamilies are two
// edits, and doing only the first leaves TestVectorManifestIsComplete failing while doing
// only the second leaves it passing with the family uninstalled. This asserts both, and
// asserts the runner installed is this file's, so a row that kept the number and lost the
// function fails here.
func TestPskSecretFamilyIsInstalled(t *testing.T) {
	family, ok := vectorManifest[6]
	if !ok {
		t.Fatal("family 6 is not in the manifest")
	}
	if family.File != pskSecretKatFile {
		t.Fatalf("family 6 names %s, this runner reads %s", family.File, pskSecretKatFile)
	}
	if family.Verify == nil {
		t.Fatal("family 6 has no Verify, so TestVectorFamiliesVerify runs one family fewer and says nothing about it")
	}
	if family.Generate == nil {
		t.Fatal("family 6 has no Generate, so the generate direction of spec A section 4.2.1 is unexercised for it")
	}
	if slices.Contains(expectedPendingFamilies, 6) {
		t.Fatal("family 6 is installed and expectedPendingFamilies still names it as pending")
	}
	// and the runner really is this file's, not some other row that happens to be non-nil.
	installed := reflect.ValueOf(family.Verify).Pointer()
	if want := reflect.ValueOf(verifyPskSecretVector).Pointer(); installed != want {
		t.Fatal("family 6 is installed with a verifier that is not verifyPskSecretVector")
	}
}

// ---------------------------------------------------------------------------
// the generate direction, written from the RFCs rather than from this package
// ---------------------------------------------------------------------------

// independentPsk is one pre-shared key as the hand written derivation below needs it: the
// three fields section 8.4 folds, and nothing this package declares.
type independentPsk struct {
	id       []byte
	pskNonce []byte
	secret   []byte
}

// independentOpaqueV writes the RFC 9420 section 2.1.2 variable length prefix by hand: one
// octet with prefix bits 0b00 below 64, two with 0b01 up to 16383.
//
// Written out because it is the hazard with no other witness on this side. A one octet
// length on the 71 octet PSKLabel, or a two octet length on a 32 octet psk_id, produces a
// perfectly well formed preimage and a psk_secret that is 32 octets of apparent random.
func independentOpaqueV(t *testing.T, body []byte) []byte {
	t.Helper()
	switch {
	case len(body) < 64:
		return append([]byte{byte(len(body))}, body...)
	case len(body) < 16384:
		return append([]byte{0x40 | byte(len(body)>>8), byte(len(body))}, body...)
	}
	t.Fatalf("a %d octet field needs a four octet varint, which this derivation does not write", len(body))
	return nil
}

// independentExpandWithLabel is RFC 9420 section 5.1's KDF.ExpandWithLabel, written from
// the two RFCs it is made of:
//
//	RFC 9420 section 5.1   ExpandWithLabel(Secret, Label, Context, Length) expands under
//	                       struct { uint16 length; opaque label<V>; opaque context<V> },
//	                       the label carrying the "MLS 1.0 " prefix
//	RFC 5869 section 2.3   HKDF-Expand's first block is HMAC(PRK, info || 0x01), and 32
//	                       octets is exactly that first block under sha256
//
// so for the 19 octet label "MLS 1.0 derived psk" and the 71 octet PSKLabel the info is
//
//	00 20      the requested output length, 32, big endian uint16
//	13         label<V> byte length 19; 19 < 64 so one octet, prefix bits 0b00
//	4d 4c ..   the 19 label octets
//	40 47      context<V> byte length 71; 71 > 63 so two octets: 0x40|(71>>8), 71&0xff
//	01 20 ..   the 71 PSKLabel octets
//
// A length field holding the label's size instead of the output's, a label without the
// prefix, or the two opaque fields transposed all give a well formed 32 octet answer.
func independentExpandWithLabel(t *testing.T, secret []byte, label string, context []byte, length int) []byte {
	t.Helper()
	if length != sha256.Size {
		t.Fatalf("this derivation writes one HKDF-Expand block and was asked for %d octets", length)
	}
	prefixed := []byte("MLS 1.0 " + label)
	info := []byte{byte(length >> 8), byte(length)}
	info = append(info, independentOpaqueV(t, prefixed)...)
	info = append(info, independentOpaqueV(t, context)...)

	expand := hmac.New(sha256.New, secret)
	expand.Write(info)
	expand.Write([]byte{0x01})
	return expand.Sum(nil)
}

// independentPskSecret is the RFC 9420 section 8.4 recurrence, written out with crypto/hmac
// and reaching nothing this package declares:
//
//	RFC 5869 section 2.2   HKDF-Extract(salt, IKM) = HMAC-Hash(key = salt, data = IKM)
//	RFC 9420 section 8.4   psk_extracted_[i] = KDF.Extract(0, psk_[i])
//	                       psk_input_[i]     = ExpandWithLabel(psk_extracted_[i],
//	                                             "derived psk", PSKLabel_[i], KDF.Nh)
//	                       psk_secret_[0]    = 0
//	                       psk_secret_[i]    = KDF.Extract(psk_input_[i-1], psk_secret_[i-1])
//	RFC 9420 section 8.4   PSKLabel = { PreSharedKeyID id; uint16 index; uint16 count; }
//	RFC 9420 section 8.4   an external PreSharedKeyID is the octet 1, then psk_id<V>, then
//	                       psk_nonce<V>
//
// Both Extract calls are written as HMAC with the salt in the key position, which is the
// one place a second opinion is worth having: transposing either compiles, returns 32
// octets, and satisfies every property either side could assert about its own output.
// TestIndependentPskSecretSeesATransposedExtract requires this derivation to disagree with
// its own transposition, so it cannot agree with a transposed implementation by being
// transposed the same way.
//
// sha256 is written in rather than read off a provider on purpose: both registered suites
// are HKDF-SHA256 at KDF.Nh 32, and reading the width off the code under test is how a
// second opinion stops being one. TestBothRegisteredSuitesAreSha256AtThisWidth is what
// fails on the day that stops being true.
func independentPskSecret(t *testing.T, psks []independentPsk) []byte {
	t.Helper()
	if len(psks) > 0xffff {
		t.Fatalf("a list of %d psks cannot be described by the uint16 count field", len(psks))
	}
	// psk_secret_[0], the KDF.Nh all zero string.
	pskSecret := make([]byte, sha256.Size)
	count := len(psks)
	for i, psk := range psks {
		// psk_extracted_[i] = HKDF-Extract(salt = 0, IKM = psk_[i])
		extract := hmac.New(sha256.New, make([]byte, sha256.Size))
		extract.Write(psk.secret)
		extracted := extract.Sum(nil)

		// PSKLabel_[i], the external arm of PreSharedKeyID followed by index and count
		pskLabel := []byte{0x01}
		pskLabel = append(pskLabel, independentOpaqueV(t, psk.id)...)
		pskLabel = append(pskLabel, independentOpaqueV(t, psk.pskNonce)...)
		pskLabel = append(pskLabel, byte(i>>8), byte(i))
		pskLabel = append(pskLabel, byte(count>>8), byte(count))

		pskInput := independentExpandWithLabel(t, extracted, "derived psk", pskLabel, sha256.Size)

		// psk_secret_[i+1] = HKDF-Extract(salt = psk_input_[i], IKM = psk_secret_[i])
		fold := hmac.New(sha256.New, pskInput)
		fold.Write(pskSecret)
		pskSecret = fold.Sum(nil)
	}
	return pskSecret
}

// independentPskSecretTransposed is the same recurrence with both Extract calls the wrong
// way round. It exists only to be disagreed with: a hand written derivation that gave the
// same answer either way could not see the defect guardrail 1 names, and would agree with a
// transposed implementation while looking like a second opinion.
func independentPskSecretTransposed(t *testing.T, psks []independentPsk) []byte {
	t.Helper()
	pskSecret := make([]byte, sha256.Size)
	count := len(psks)
	for i, psk := range psks {
		extract := hmac.New(sha256.New, psk.secret)
		extract.Write(make([]byte, sha256.Size))
		extracted := extract.Sum(nil)

		pskLabel := []byte{0x01}
		pskLabel = append(pskLabel, independentOpaqueV(t, psk.id)...)
		pskLabel = append(pskLabel, independentOpaqueV(t, psk.pskNonce)...)
		pskLabel = append(pskLabel, byte(i>>8), byte(i))
		pskLabel = append(pskLabel, byte(count>>8), byte(count))

		pskInput := independentExpandWithLabel(t, extracted, "derived psk", pskLabel, sha256.Size)

		fold := hmac.New(sha256.New, pskSecret)
		fold.Write(pskInput)
		pskSecret = fold.Sum(nil)
	}
	return pskSecret
}

// generatedPskOctets is deterministic filler for the generate direction. Deterministic
// rather than random so a generated case that fails is the same case on the next run;
// sha256 over a per-field string rather than a counter so no two fields of one psk are
// related in a way a broken PSKLabel encoding could hide behind.
func generatedPskOctets(field string, index int) []byte {
	digest := sha256.Sum256([]byte(fmt.Sprintf("mls slice1 p4 task16 psk_secret generate %s %d", field, index)))
	return digest[:]
}

// generatePskSecretVectors produces fresh psk_secret cases in the published format, with
// every answer computed by independentPskSecret.
//
// This function calls no production function of package mls at all, which is asserted
// rather than described: TestTheGenerateDirectionSharesNoCodePathWithVerify derives the
// production function names from the package's own source and requires this function's
// call closure to be disjoint from them. The ciphersuite code points below are constants,
// not a derivation, and TestGeneratedVectorsCoverEveryRegisteredSuite is what fails on the
// day a third suite is registered and this list stops covering the registry.
//
// List lengths 0, 1 and 2 are all three arms of the recurrence: the empty answer that every
// v1 epoch actually mixes in, the singleton that is the only check on the "derived psk"
// label, and the fold where the accumulator and the index live.
func generatePskSecretVectors(t *testing.T) json.RawMessage {
	t.Helper()
	generated := []pskSecretKatVector{}
	for _, suite := range []uint16{
		uint16(CipherSuiteX25519AesGcm128Sha256Ed25519),
		uint16(CipherSuiteX25519ChaCha20Sha256Ed25519),
	} {
		for _, count := range []int{0, 1, 2, 3} {
			vector := pskSecretKatVector{CipherSuite: suite}
			psks := make([]independentPsk, 0, count)
			for i := 0; i < count; i++ {
				tag := fmt.Sprintf("suite %d count %d", suite, count)
				psk := independentPsk{
					id:       generatedPskOctets(tag+" id", i),
					pskNonce: generatedPskOctets(tag+" nonce", i),
					secret:   generatedPskOctets(tag+" secret", i),
				}
				psks = append(psks, psk)
				vector.Psks = append(vector.Psks, struct {
					PskId    string `json:"psk_id"`
					Psk      string `json:"psk"`
					PskNonce string `json:"psk_nonce"`
				}{
					PskId:    HexOf(psk.id),
					Psk:      HexOf(psk.secret),
					PskNonce: HexOf(psk.pskNonce),
				})
			}
			vector.PskSecret = HexOf(independentPskSecret(t, psks))
			generated = append(generated, vector)
		}
	}
	body, err := json.Marshal(generated)
	if err != nil {
		t.Fatalf("marshal the generated psk_secret cases: %v", err)
	}
	return body
}

// TestIndependentPskSecretMatchesEveryUpstreamVector pins the generator to the published
// corpus.
//
// This is what makes the generate direction worth running. A generator agreeing with the
// verifier proves that two spellings of one algorithm agree; a generator that reproduces
// every answer mlswg published, computed with crypto/hmac from the RFC text, is a second
// implementation, and the round trip through it is then a statement about conformance.
//
// The comparison count is asserted for the same reason it is asserted in the runner.
func TestIndependentPskSecretMatchesEveryUpstreamVector(t *testing.T) {
	compared := 0
	for index, raw := range LoadVectorFile(t, pskSecretKatFile) {
		vector := pskSecretKatVector{}
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("vector %d: %v", index, err)
		}
		if _, ok := implementedSuite(vector.CipherSuite); !ok {
			continue
		}
		psks := make([]independentPsk, 0, len(vector.Psks))
		for _, entry := range vector.Psks {
			psks = append(psks, independentPsk{
				id:       MustHex(t, entry.PskId),
				pskNonce: MustHex(t, entry.PskNonce),
				secret:   MustHex(t, entry.Psk),
			})
		}
		if got := HexOf(independentPskSecret(t, psks)); got != vector.PskSecret {
			t.Errorf("vector %d (suite %#04x, %d psks): the hand written derivation gives %s, the corpus publishes %s",
				index, vector.CipherSuite, len(psks), got, vector.PskSecret)
		}
		compared++
	}
	if compared != pskSecretKatComparisons {
		t.Fatalf("the hand written derivation was compared against %d published answers, want %d",
			compared, pskSecretKatComparisons)
	}
}

// TestIndependentPskSecretSeesATransposedExtract is the control the test above needs. A
// derivation that answers the same with its Extract arguments the wrong way round agrees
// with a transposed implementation and pins nothing about guardrail 1.
//
// The empty list is excluded because it folds nothing and both spellings answer the all
// zero string, which is correct rather than a failure of the control.
func TestIndependentPskSecretSeesATransposedExtract(t *testing.T) {
	checked := 0
	for index, raw := range LoadVectorFile(t, pskSecretKatFile) {
		vector := pskSecretKatVector{}
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("vector %d: %v", index, err)
		}
		if _, ok := implementedSuite(vector.CipherSuite); !ok || len(vector.Psks) == 0 {
			continue
		}
		psks := make([]independentPsk, 0, len(vector.Psks))
		for _, entry := range vector.Psks {
			psks = append(psks, independentPsk{
				id:       MustHex(t, entry.PskId),
				pskNonce: MustHex(t, entry.PskNonce),
				secret:   MustHex(t, entry.Psk),
			})
		}
		if bytes.Equal(independentPskSecretTransposed(t, psks), independentPskSecret(t, psks)) {
			t.Fatalf("vector %d: the hand written derivation gives one answer for both Extract orders, so it cannot see a transposition",
				index)
		}
		checked++
	}
	if checked != pskSecretKatComparisons-2 {
		t.Fatalf("the transposition control ran over %d non-empty lists, want %d",
			checked, pskSecretKatComparisons-2)
	}
}

// TestBothRegisteredSuitesAreSha256AtThisWidth is the assumption independentPskSecret makes
// when it writes sha256 in rather than reading a width off the code under test. It stops
// being true the day a wider suite is registered, and this is where that is said.
func TestBothRegisteredSuitesAreSha256AtThisWidth(t *testing.T) {
	for _, suite := range Suites() {
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("NewCryptoProvider(%#04x): %v", uint16(suite), err)
		}
		if crypto.HashSize() != sha256.Size {
			t.Fatalf("suite %#04x has KDF.Nh %d and the hand written derivation writes %d; it needs widening before it can be a second opinion at that suite",
				uint16(suite), crypto.HashSize(), sha256.Size)
		}
	}
}

// TestGeneratedVectorsCoverEveryRegisteredSuite holds the generator's own list of code
// points to the registry, which is the check the generator cannot make about itself
// without calling into the package it is meant to stay clear of.
func TestGeneratedVectorsCoverEveryRegisteredSuite(t *testing.T) {
	entries := []pskSecretKatVector{}
	if err := json.Unmarshal(generatePskSecretVectors(t), &entries); err != nil {
		t.Fatalf("the generated cases do not parse: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("the generator produced no cases")
	}
	covered := map[CipherSuite]int{}
	counts := map[int]int{}
	for _, entry := range entries {
		covered[CipherSuite(entry.CipherSuite)]++
		counts[len(entry.Psks)]++
	}
	if got := slices.Sorted(maps.Keys(covered)); !slices.Equal(got, Suites()) {
		t.Fatalf("the generator covers %v and the registry holds %v; widen generatePskSecretVectors", got, Suites())
	}
	for _, arm := range []int{0, 1, 2} {
		if counts[arm] == 0 {
			t.Errorf("the generator produced no case with %d psks, so that arm of the recurrence is unexercised in the generate direction", arm)
		}
	}
	t.Logf("%d generated cases over suites %v, list lengths %v", len(entries), slices.Sorted(maps.Keys(covered)), counts)
}

// ---------------------------------------------------------------------------
// the structural gates over the runner files themselves
// ---------------------------------------------------------------------------

// packageTestFiles parses every test file of this package, keyed by base name.
//
// Every test file, and that is the load bearing word. The call graph gate below walks the
// functions these files declare, and a function it cannot see is a leaf: its name is
// collected and its body is never entered, so anything it calls is invisible. Narrowing
// this set to the files that mention the vector harness is therefore not an optimisation,
// it is an escape hatch one hop wide -- a generator routed through a helper declared in
// psk_test.go, crypto_test.go or any other test file would launder the entire production
// closure and the gate would report clean. That is exactly the shape of the first version
// of this file, and it is why the class here is "is a test file of this package" and
// nothing narrower.
//
// The count is asserted against the directory listing so a filter added later cannot
// quietly shrink it.
func packageTestFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	fileSet := token.NewFileSet()
	files := map[string]*ast.File{}
	onDisk := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		onDisk++
		parsed, err := parser.ParseFile(fileSet, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files[name] = parsed
	}
	if onDisk == 0 {
		t.Fatal("no test file was read from the package directory, so every gate over this set would hold vacuously")
	}
	if len(files) != onDisk {
		t.Fatalf("%d test files are on disk and %d were kept; a filter here is an escape hatch for the call graph gate below",
			onDisk, len(files))
	}
	return files
}

// vectorRunnerFiles is every test file of this package that takes part in the vector
// harness, derived rather than listed: a file that installs a family or reads the corpus
// through the harness loader is one, and nothing else is.
//
// Derived because the class grows. Tasks 17, 18, 20 and 25 add runners to this file, and
// p2, p3, p5, p6 and p7 add runner files of their own; a written list would cover the files
// that existed when it was written and silently exempt every one that arrived after.
//
// This is the class for the skip gate, which is a question about a file: may THIS file
// decline to run. It is not the class for the call graph gate, which is a question about a
// closure and needs every test file -- see packageTestFiles.
func vectorRunnerFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	all := packageTestFiles(t)
	runners := map[string]*ast.File{}
	for name, parsed := range all {
		if namesMentionedIn(parsed)["RegisterVectorFamily"] || namesMentionedIn(parsed)["LoadVectorFile"] {
			runners[name] = parsed
		}
	}
	for _, required := range []string{"key_schedule_kat_test.go", "vectors_test.go"} {
		if _, found := runners[required]; !found {
			t.Fatalf("%s takes part in the vector harness and the derivation did not find it, so it is matching nothing useful over %d test files",
				required, len(all))
		}
	}
	return runners
}

// namesMentionedIn returns every identifier a node names, in any position. It answers the
// only question it is asked -- does this test file mention the harness at all -- where a
// mention is exactly the question and over-approximating costs nothing.
func namesMentionedIn(node ast.Node) map[string]bool {
	mentioned := map[string]bool{}
	ast.Inspect(node, func(current ast.Node) bool {
		if ident, isIdent := current.(*ast.Ident); isIdent {
			mentioned[ident.Name] = true
		}
		return true
	})
	return mentioned
}

// namesInvokedBy returns the names a function reaches as code rather than as data: every
// call's callee by bare name, so crypto.Extract(...) contributes Extract; plus every
// identifier used as a value or as a type, so a function passed by name and a parameter
// typed CryptoProvider are both seen.
//
// Three positions are excluded, and each exclusion is the difference between a gate and a
// name collision. The selected half of a selector that is not a call is a field read:
// psk.nonce contributes psk, not nonce, and this package does declare a method called
// nonce. A composite literal key names a field of the type being built. A field
// declaration, which is also how parameter names are spelled, names a local.
func namesInvokedBy(node ast.Node) map[string]bool {
	invoked := map[string]bool{}
	positional := map[*ast.Ident]bool{}
	ast.Inspect(node, func(current ast.Node) bool {
		switch typed := current.(type) {
		case *ast.SelectorExpr:
			positional[typed.Sel] = true
		case *ast.KeyValueExpr:
			if key, isIdent := typed.Key.(*ast.Ident); isIdent {
				positional[key] = true
			}
		case *ast.Field:
			for _, name := range typed.Names {
				positional[name] = true
			}
		case *ast.CallExpr:
			switch callee := typed.Fun.(type) {
			case *ast.Ident:
				invoked[callee.Name] = true
			case *ast.SelectorExpr:
				invoked[callee.Sel.Name] = true
			}
		}
		return true
	})
	ast.Inspect(node, func(current ast.Node) bool {
		if ident, isIdent := current.(*ast.Ident); isIdent && !positional[ident] {
			invoked[ident.Name] = true
		}
		return true
	})
	return invoked
}

// reachableNames returns every identifier a function names, following calls to functions
// declared in the same set of files. A name declared nowhere in that set is a leaf and is
// still collected, so the standard library and this package's production surface both show
// up in the result.
func reachableNames(t *testing.T, declared map[string]*ast.FuncDecl, root string) map[string]bool {
	t.Helper()
	start, ok := declared[root]
	if !ok {
		t.Fatalf("%s is not declared in the files scanned, so its closure would be empty", root)
	}
	reached := map[string]bool{}
	pending := []*ast.FuncDecl{start}
	visited := map[string]bool{root: true}
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		for name := range namesInvokedBy(current) {
			reached[name] = true
			if next, isLocal := declared[name]; isLocal && !visited[name] {
				visited[name] = true
				pending = append(pending, next)
			}
		}
	}
	return reached
}

// testFileFunctions collects the package level functions the given files declare, keyed by
// name, so reachableNames can follow a call into one.
func testFileFunctions(files map[string]*ast.File) map[string]*ast.FuncDecl {
	declared := map[string]*ast.FuncDecl{}
	for _, file := range files {
		for _, decl := range file.Decls {
			function, isFunction := decl.(*ast.FuncDecl)
			if !isFunction || function.Recv != nil {
				continue
			}
			declared[function.Name.Name] = function
		}
	}
	return declared
}

// productionFunctionNames is every function and method this package declares in a non test
// file, by bare name, derived from the package's own syntax tree.
//
// Methods appear under their bare name rather than as Receiver.Name because that is how a
// call reaches them: crypto.Extract names Extract, and a gate keyed on the qualified form
// would not see it.
func productionFunctionNames(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	fileSet := token.NewFileSet()
	names := map[string]bool{}
	read := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		read++
		for _, decl := range parsed.Decls {
			if function, isFunction := decl.(*ast.FuncDecl); isFunction {
				names[function.Name.Name] = true
			}
		}
	}
	if read == 0 {
		t.Fatal("no production file was read, so the class below would be empty and every gate over it vacuous")
	}
	for _, control := range []string{"PskSecret", "EmptyPskSecret", "NewCryptoProvider", "Extract", "ExpandWithLabel"} {
		if !names[control] {
			t.Fatalf("the derivation did not find %s, which this package certainly declares, so it read %d files and nothing useful",
				control, read)
		}
	}
	return names
}

// oneHopLaunderingRoot and oneHopLaunderingHelper are the control on the call graph walk:
// a generator in one file, and the helper it calls declared in another, with the code under
// test reached only from the helper.
//
// This is the exact evasion the first version of this gate was open to. The walk followed
// calls only into functions declared in the vector runner files, so every other test file
// of the package was a leaf, and moving one line -- the answer -- into a helper declared in
// psk_test.go laundered the whole production closure while the gate reported clean. The
// control is written as two sources rather than as two real files because a real one would
// have to be a function nothing calls, and the point is the file boundary, not the code.
var (
	oneHopLaunderingRoot = strings.Join([]string{
		"package control",
		"",
		"func generateControl() []byte {",
		"\treturn launderControl()",
		"}",
		"",
	}, "\n")

	oneHopLaunderingHelper = strings.Join([]string{
		"package control",
		"",
		"func launderControl() []byte {",
		"\tout, _ := PskSecret(nil, nil)",
		"\treturn out",
		"}",
		"",
	}, "\n")
)

// TestTheGenerateDirectionSharesNoCodePathWithVerify is the gate that makes the generate
// direction worth having.
//
// The trap it closes: a generator that computes its answer with PskSecret and a verifier
// that checks it with PskSecret round trip perfectly and say nothing at all about
// conformance. The property asserted is the strongest form of the fix, and BOTH of its
// classes are derived rather than described -- the production function class is read out of
// this package's own non test source, and the closure of the generate direction is walked
// over every test file of the package, so neither a production function added later nor a
// helper hidden in another test file evades it.
//
// Two controls stand in front of the gate. The verify direction is required to reach
// PskSecret, so the disjointness cannot hold by the collector having read nothing; and the
// walk is required to cross a file boundary, so it cannot hold by the walk stopping at the
// first hop.
func TestTheGenerateDirectionSharesNoCodePathWithVerify(t *testing.T) {
	fileSet := token.NewFileSet()
	control := func(name, source string) *ast.File {
		parsed, err := parser.ParseFile(fileSet, name, source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return parsed
	}
	rootOnly := map[string]*ast.File{"root_test.go": control("root_test.go", oneHopLaunderingRoot)}
	if reachableNames(t, testFileFunctions(rootOnly), "generateControl")["PskSecret"] {
		t.Fatal("the walk reports PskSecret from a file that only names launderControl, so it is matching text rather than following calls")
	}
	bothFiles := map[string]*ast.File{
		"root_test.go":   control("root_test.go", oneHopLaunderingRoot),
		"helper_test.go": control("helper_test.go", oneHopLaunderingHelper),
	}
	if !reachableNames(t, testFileFunctions(bothFiles), "generateControl")["PskSecret"] {
		t.Fatal("the walk did not follow a call into a function declared in another file, so the gate below is evadable by one hop through any test file")
	}

	// the class the real walk runs over: every test file, strictly more than the vector
	// runner files, or the control above is describing a walk this gate does not make.
	all := packageTestFiles(t)
	runners := vectorRunnerFiles(t)
	if len(all) <= len(runners) {
		t.Fatalf("the package has %d test files and %d of them are vector runners; the closure below must be walked over every test file and there is nothing here to widen",
			len(all), len(runners))
	}
	declared := testFileFunctions(all)
	if len(declared) <= len(testFileFunctions(runners)) {
		t.Fatalf("the walk sees %d functions over every test file and %d over the runner files alone; it is not reading the wider class",
			len(declared), len(testFileFunctions(runners)))
	}
	production := productionFunctionNames(t)

	verifyReaches := reachableNames(t, declared, "comparePskSecretVector")
	if !verifyReaches["PskSecret"] {
		t.Fatal("the verify direction does not reach PskSecret, so the collector is reading nothing and the disjointness below is vacuous")
	}

	for _, root := range []string{"generatePskSecretVectors", "independentPskSecret", "independentPskSecretTransposed"} {
		shared := []string{}
		for name := range reachableNames(t, declared, root) {
			if production[name] {
				shared = append(shared, name)
			}
		}
		slices.Sort(shared)
		if len(shared) != 0 {
			t.Errorf("%s reaches the production function(s) %v; the generate direction has to answer without the code under test or the round trip only proves that code agrees with itself",
				root, shared)
		}
	}
	t.Logf("the generate direction was walked over %d functions declared across %d test files, against %d production function names",
		len(declared), len(all), len(production))
}

// TestNoVectorRunnerCanSkip holds every vector harness file to failing rather than skipping.
//
// A skipped gate is an absent gate, and the shape that produced this rule is specific: a
// runner that skips when the corpus is missing turns a deleted, renamed or truncated corpus
// into a green run. There is no condition under which any of these files should decline to
// run: the corpus is vendored and pinned in this tree, so it is either there or the build
// is broken.
//
// The skip class is derived from the testing package rather than listed. A list would name
// Skip and Skipf and miss SkipNow, which is exactly the shape of failure this project has
// hit fourteen times.
func TestNoVectorRunnerCanSkip(t *testing.T) {
	skips := map[string]bool{}
	reported := reflect.TypeOf((*testing.T)(nil))
	for index := 0; index < reported.NumMethod(); index++ {
		if name := reported.Method(index).Name; strings.HasPrefix(name, "Skip") {
			skips[name] = true
		}
	}
	for _, required := range []string{"Skip", "Skipf", "SkipNow"} {
		if !skips[required] {
			t.Fatalf("the derived skip class %v does not hold %s, so it is not the testing package's", slices.Sorted(maps.Keys(skips)), required)
		}
	}
	if skips["Fatal"] || skips["Fatalf"] {
		t.Fatalf("the derived skip class %v holds a fatal, so it is matching more than skips", slices.Sorted(maps.Keys(skips)))
	}

	flags := func(source string) []string {
		fileSet := token.NewFileSet()
		parsed, err := parser.ParseFile(fileSet, "control.go", source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse the control: %v", err)
		}
		return skipsNamedIn(parsed, skips)
	}
	if found := flags("package control\nimport \"testing\"\nfunc control(t *testing.T) { t.Skip(\"no corpus\") }\n"); len(found) == 0 {
		t.Fatal("the matcher did not flag a control that skips, so it would report every file below clean having matched nothing")
	}
	if found := flags("package control\nimport \"testing\"\nfunc control(t *testing.T) { t.Fatal(\"no corpus\") }\n"); len(found) != 0 {
		t.Fatalf("the matcher flagged a control that fails rather than skipping: %v", found)
	}

	for name, parsed := range vectorRunnerFiles(t) {
		if found := skipsNamedIn(parsed, skips); len(found) != 0 {
			t.Errorf("%s names %v; a vector runner that skips when the corpus is unreadable turns a deleted corpus into a green run",
				name, found)
		}
	}
}

// skipsNamedIn returns every selector in a file whose selected name is in the skip class.
// The qualifier is not checked: over the vector harness files there is no other kind of
// Skip, and over-approximating is the safe direction for this gate to be wrong in.
func skipsNamedIn(file *ast.File, skips map[string]bool) []string {
	found := map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, isSelector := node.(*ast.SelectorExpr)
		if isSelector && skips[selector.Sel.Name] {
			found[selector.Sel.Name] = true
		}
		return true
	})
	return slices.Sorted(maps.Keys(found))
}
