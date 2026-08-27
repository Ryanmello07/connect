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
// that passed everything reports. Four separate things stand in the way.
//
//   - The number of comparisons is counted where the comparison happens, not where the
//     loop iterates, and the count is asserted against a written number. Counting at the
//     loop is the version of this that does not work: a verifier that returned early for
//     every case would still be counted once per case.
//   - The suites the filter matched are compared against the ciphersuite registry rather
//     than against a list written here, so a filter that matched nothing, and a filter
//     that matched all seven published suites, both fail.
//   - The corpus is loaded through LoadVectorFile, which is fatal and never skipping, and
//     no runner file may name a skip at all; TestNoVectorRunnerCanSkip derives the skip
//     class from the testing package rather than listing it.
//   - Each comparison carries its own vacuity control: the published answer for a
//     non-empty list must differ from the empty answer, and one flipped octet of the
//     corpus's own psk must move the value this package computes. Both fail if the
//     corpus data never reached the derivation.
//
// And the generate direction. The published corpus never passes through our own encoder,
// so verification alone cannot see an encoder and a decoder that are wrong in the same
// direction. Generating a case and verifying it does -- but only if the generator is not
// the verifier under another name, which is the trap: PskSecret generating an answer that
// PskSecret then checks proves nothing about conformance at all. The generator here is
// independentPskSecret, written from RFC 5869 and RFC 9420 with crypto/hmac and nothing
// this package declares, held against the published corpus, and held structurally to
// touching no production function by TestTheGenerateDirectionSharesNoCodePathWithVerify.
package mls

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
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

// verifyPskSecretVector is the registry's shim: the signature RegisterVectorFamily needs,
// over the function that does the work and reports whether it did any.
//
// The split is the whole point. Verify cannot return anything, so a runner that counted
// calls to it would count a case it declined to check exactly as it counts a case it
// compared. comparePskSecretVector returns that fact and TestVectorPskSecret counts it.
func verifyPskSecretVector(t *testing.T, raw json.RawMessage) {
	t.Helper()
	comparePskSecretVector(t, "", raw)
}

// comparePskSecretVector checks one entry of psk_secret.json and reports whether it
// compared anything. A vector at a ciphersuite v1 does not implement is not a failure and
// not a skip: it is a case this package has no provider for, and the accounting in
// TestVectorPskSecret is what makes sure that is not every case.
//
// The two controls carried per comparison are here rather than in the runner because they
// need the vector's own bytes. A published answer for a non-empty list that equalled the
// empty answer would let an implementation returning KDF.Nh zeroes pass; and if the psk
// list never reached PskSecret -- a renamed json field, a struct tag typo, a decoder
// returning nothing -- then flipping an octet of the corpus's own psk would leave the
// answer where it was. Both are the shape that has caught this before: install the
// corpus's own data and refuse to proceed unless the value moves.
func comparePskSecretVector(t *testing.T, at string, raw json.RawMessage) bool {
	t.Helper()
	vector := pskSecretKatVector{}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("%sparse psk_secret entry: %v", at, err)
	}
	suite, ok := implementedSuite(vector.CipherSuite)
	if !ok {
		return false
	}
	crypto, err := NewCryptoProvider(suite)
	if err != nil {
		t.Fatalf("%sNewCryptoProvider(%#04x): %v", at, uint16(suite), err)
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
		t.Fatalf("%sthe entry carries %d psks and %d reached the derivation", at, len(vector.Psks), len(psks))
	}
	want := MustHex(t, vector.PskSecret)
	if len(want) != crypto.HashSize() {
		t.Fatalf("%sthe published psk_secret is %d octets and the suite's KDF.Nh is %d, so this is not the comparison the corpus intends",
			at, len(want), crypto.HashSize())
	}
	if len(psks) > 0 && bytes.Equal(want, EmptyPskSecret(crypto)) {
		t.Fatalf("%sthe published answer for a list of %d psks is the empty answer, so an implementation that ignored the list would match it",
			at, len(psks))
	}
	got, err := PskSecret(crypto, psks)
	if err != nil {
		t.Fatalf("%s%d psks: PskSecret: %v", at, len(psks), err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s%d psks at suite %#04x: psk_secret = %s, want %s",
			at, len(psks), vector.CipherSuite, HexOf(got), vector.PskSecret)
	}
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
			t.Fatalf("%sPskSecret over the perturbed list: %v", at, err)
		}
		if bytes.Equal(perturbed, got) {
			t.Fatalf("%sflipping one octet of the published psk left psk_secret unchanged, so the corpus data never reached the derivation",
				at)
		}
	}
	return true
}

// TestVectorPskSecret is vector family 6 over the published corpus.
//
// Every assertion after the loop exists because the loop can be made to run zero times
// without anything else in this package noticing. A filter that matched nothing, a filter
// that matched all seven suites, a corpus that parsed to an empty array, a verifier that
// declined every case: each of those is a green run of this test with the assertions
// removed, and a failure with them.
func TestVectorPskSecret(t *testing.T) {
	entries := LoadVectorFile(t, pskSecretKatFile)
	if len(entries) == 0 {
		t.Fatalf("%s parsed to no entries, so every comparison below would be against nothing", pskSecretKatFile)
	}

	compared, skipped := 0, 0
	matched := map[CipherSuite]int{}
	answers := map[string]int{}
	for index, raw := range entries {
		header := struct {
			CipherSuite uint16 `json:"cipher_suite"`
			PskSecret   string `json:"psk_secret"`
		}{}
		if err := json.Unmarshal(raw, &header); err != nil {
			t.Fatalf("vector %d: %v", index, err)
		}
		suite, ok := implementedSuite(header.CipherSuite)
		if !ok {
			skipped++
			continue
		}
		if !comparePskSecretVector(t, fmt.Sprintf("vector %d: ", index), raw) {
			t.Fatalf("vector %d is at suite %#04x, which this package registers, and the verifier compared nothing",
				index, header.CipherSuite)
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
	if len(answers) != pskSecretKatDistinctAnswers {
		t.Fatalf("the %d comparisons were made against %d distinct published answers, want %d; a corpus read as one repeated value would compare that many times and pin one answer",
			compared, len(answers), pskSecretKatDistinctAnswers)
	}
	t.Logf("psk_secret: compared %d over %d distinct published answers at suites %v, skipped %d at unimplemented suites",
		compared, len(answers), slices.Sorted(maps.Keys(matched)), skipped)
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

// vectorRunnerFiles is every test file of this package that takes part in the vector
// harness, derived rather than listed: a file that installs a family or reads the corpus
// through the harness loader is one, and nothing else is.
//
// Derived because the class grows. Tasks 17, 18, 20 and 25 add runners to this file, and
// p2, p3, p5, p6 and p7 add runner files of their own; a written list would cover the files
// that existed when it was written and silently exempt every one that arrived after.
func vectorRunnerFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	fileSet := token.NewFileSet()
	runners := map[string]*ast.File{}
	read := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		read++
		if namesMentionedIn(parsed)["RegisterVectorFamily"] || namesMentionedIn(parsed)["LoadVectorFile"] {
			runners[name] = parsed
		}
	}
	if read == 0 {
		t.Fatal("no test file was read from the package directory, so the gates below would hold vacuously")
	}
	for _, required := range []string{"key_schedule_kat_test.go", "vectors_test.go"} {
		if _, found := runners[required]; !found {
			t.Fatalf("%s takes part in the vector harness and the derivation did not find it, so it is matching nothing useful over %d test files",
				required, read)
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

// TestTheGenerateDirectionSharesNoCodePathWithVerify is the gate that makes the generate
// direction worth having.
//
// The trap it closes: a generator that computes its answer with PskSecret and a verifier
// that checks it with PskSecret round trip perfectly and say nothing at all about
// conformance. The property asserted is the strongest form of the fix, and it is derived
// rather than described -- the production function class is read out of this package's own
// non test source, and the closure of the generate direction is read out of its call graph,
// so a call added later to any production function fails here.
//
// The verify direction is required to reach PskSecret, so the disjointness below cannot
// hold by the collector having read nothing.
func TestTheGenerateDirectionSharesNoCodePathWithVerify(t *testing.T) {
	runners := vectorRunnerFiles(t)
	declared := testFileFunctions(runners)
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
