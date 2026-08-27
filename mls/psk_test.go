// Tests for the RFC 9420 section 8.4 pre shared key identifier.
//
// The codec here owes what GroupContext's owes and for the same reason: MLS signs and
// hashes over serialized forms, so byte exactness is the property and round trip
// symmetry cannot see a violation of it. An encoder and a decoder that both write the
// psktype at two octets round trip perfectly against each other and disagree with
// everybody else, and the disagreement surfaces as a psk_secret nobody else derives.
//
// So the goldens below are hand derived from the RFC with their arithmetic written out,
// and the external arm is checked against three hundred encodings the mlswg reference
// implementation produced, which are in this tree already, pinned by digest, and were
// written without reference to this package.
package mls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// pskTestCrypto returns the ciphersuite 0x0003 provider the psk tests are pinned
// against.
func pskTestCrypto(t *testing.T) CryptoProvider {
	t.Helper()
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	return crypto
}

// pskHashSizeProvider is a provider whose KDF output length is whatever the test says,
// and it exists because both registered ciphersuites have Nh = 32. A ValSem401 that
// compared against a literal 32 would pass every test this package can build out of the
// real registry, and would start accepting half length nonces on the day a suite with a
// wider hash is registered — which the still draft post quantum ciphersuites make a near
// certainty. Overriding the one method the rule reads is what makes the derivation
// observable now rather than then.
//
// Everything else is delegated, so this is the real provider in every other respect.
type pskHashSizeProvider struct {
	CryptoProvider
	hashSize int
}

// HashSize reports the length this fixture was built for.
func (self pskHashSizeProvider) HashSize() int { return self.hashSize }

// pskCryptoWithHashSize wraps the suite 0x0003 provider at a chosen KDF.Nh.
func pskCryptoWithHashSize(t *testing.T, hashSize int) CryptoProvider {
	t.Helper()
	return pskHashSizeProvider{CryptoProvider: pskTestCrypto(t), hashSize: hashSize}
}

// clonePreSharedKeyId copies an id so a test that mutates one field cannot reach the
// fixture every other case is built from.
func clonePreSharedKeyId(id *PreSharedKeyId) *PreSharedKeyId {
	clone := *id
	clone.PskId = cloneBytes(id.PskId)
	clone.PskGroupId = cloneBytes(id.PskGroupId)
	clone.PskNonce = cloneBytes(id.PskNonce)
	return &clone
}

// preSharedKeyIdsAgree compares two ids field by field, treating a nil byte slice and an
// empty one as equal because the wire format has one spelling for both and the decoder
// always produces the non nil form.
func preSharedKeyIdsAgree(left *PreSharedKeyId, right *PreSharedKeyId) bool {
	return left.PskType == right.PskType &&
		left.Usage == right.Usage &&
		left.PskEpoch == right.PskEpoch &&
		bytes.Equal(left.PskId, right.PskId) &&
		bytes.Equal(left.PskGroupId, right.PskGroupId) &&
		bytes.Equal(left.PskNonce, right.PskNonce)
}

// describePreSharedKeyId names a corpus case in a failure message, since the cases below
// are generated and there is no table row to point at.
func describePreSharedKeyId(id *PreSharedKeyId) string {
	return fmt.Sprintf("{psktype %d usage %d id %d gid %d epoch %#016x nonce %d}",
		uint8(id.PskType), uint8(id.Usage), len(id.PskId), len(id.PskGroupId),
		id.PskEpoch, len(id.PskNonce))
}

// ---------------------------------------------------------------------------
// the hand derived goldens
// ---------------------------------------------------------------------------

// handDerivedExternalGolden is the external arm written out from RFC 9420 section 8.4
// and the section 2.1 varint, one argument per field:
//
//	psktype           external is code point 1                        -> 01
//	psk_id<V>         two octets, so a one octet prefix of 02          -> 02 aa bb
//	psk_nonce<V>      three octets, so a one octet prefix of 03        -> 03 01 02 03
//
// 1 + (1+2) + (1+3) = 8 octets. There is no usage, no group id and no epoch: the select()
// arm decides which fields exist, and an encoder that wrote a resumption field here would
// be describing a key the receiver cannot look up.
func handDerivedExternalGolden() []byte {
	return joinBytes(
		[]byte{0x01},
		[]byte{0x02, 0xaa, 0xbb},
		[]byte{0x03, 0x01, 0x02, 0x03},
	)
}

// handDerivedExternalGoldenId is the value that golden describes.
func handDerivedExternalGoldenId() *PreSharedKeyId {
	return &PreSharedKeyId{
		PskType:  PskTypeExternal,
		PskId:    []byte{0xaa, 0xbb},
		PskNonce: []byte{0x01, 0x02, 0x03},
	}
}

// handDerivedResumptionGolden is the resumption arm, same derivation:
//
//	psktype           resumption is code point 2                      -> 02
//	usage             application is code point 1                     -> 01
//	psk_group_id<V>   one octet, so a one octet prefix of 01           -> 01 cc
//	psk_epoch         a bare uint64, big endian, no length prefix     -> 00..07
//	psk_nonce<V>      one octet                                        -> 01 09
//
// 1 + 1 + (1+1) + 8 + (1+1) = 14 octets. The epoch is the field a codec is most likely to
// get wrong and least likely to notice: written at four octets it still decodes, still
// round trips against itself, and moves every subsequent field by four.
func handDerivedResumptionGolden() []byte {
	return joinBytes(
		[]byte{0x02},
		[]byte{0x01},
		[]byte{0x01, 0xcc},
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07},
		[]byte{0x01, 0x09},
	)
}

// handDerivedResumptionGoldenId is the value that golden describes.
func handDerivedResumptionGoldenId() *PreSharedKeyId {
	return &PreSharedKeyId{
		PskType:    PskTypeResumption,
		Usage:      ResumptionPskUsageApplication,
		PskGroupId: []byte{0xcc},
		PskEpoch:   7,
		PskNonce:   []byte{0x09},
	}
}

// handDerivedWideExternalGolden pins what the two goldens above and the upstream corpus
// all leave out: a present but empty opaque field, and a field long enough to need the
// two octet varint prefix.
//
//	psktype           external                                         -> 01
//	psk_id<V>         empty, so a one octet prefix of 00 and no body    -> 00
//	psk_nonce<V>      64 octets. 64 is past the 63 a one octet prefix
//	                  can carry, so the two octet form 0b01 000000 |
//	                  0x40 is used                                     -> 40 40 then 64 c1
//
// 1 + 1 + (2+64) = 68 octets.
func handDerivedWideExternalGolden() []byte {
	return joinBytes(
		[]byte{0x01},
		[]byte{0x00},
		[]byte{0x40, 0x40},
		repeatByte(0xc1, 64),
	)
}

// handDerivedWideExternalGoldenId is the value that golden describes.
func handDerivedWideExternalGoldenId() *PreSharedKeyId {
	return &PreSharedKeyId{
		PskType:  PskTypeExternal,
		PskId:    []byte{},
		PskNonce: repeatByte(0xc1, 64),
	}
}

// handDerivedWideResumptionGolden is the resumption arm at the same boundaries, plus an
// epoch whose every octet is distinct — the only shape that catches a uint64 written in
// the wrong byte order, which the epoch 7 golden above cannot see — and a usage value
// this profile refuses, since decoding and accepting are separate questions and the
// codec owes the refusal a decodable value to name.
//
//	psktype           resumption                                       -> 02
//	usage             branch is code point 3                           -> 03
//	psk_group_id<V>   64 octets, two octet prefix                      -> 40 40 then 64 b2
//	psk_epoch         fedcba9876543210, big endian                     -> fe dc ba 98 76 54 32 10
//	psk_nonce<V>      empty                                            -> 00
//
// 1 + 1 + (2+64) + 8 + 1 = 77 octets.
func handDerivedWideResumptionGolden() []byte {
	return joinBytes(
		[]byte{0x02},
		[]byte{0x03},
		[]byte{0x40, 0x40},
		repeatByte(0xb2, 64),
		[]byte{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		[]byte{0x00},
	)
}

// handDerivedWideResumptionGoldenId is the value that golden describes.
func handDerivedWideResumptionGoldenId() *PreSharedKeyId {
	return &PreSharedKeyId{
		PskType:    PskTypeResumption,
		Usage:      ResumptionPskUsageBranch,
		PskGroupId: repeatByte(0xb2, 64),
		PskEpoch:   0xfedcba9876543210,
		PskNonce:   []byte{},
	}
}

// goldenPskIds pairs every hand derived golden with the value it describes, so the
// encode assertions below and the refusal sweeps further down run over one set rather
// than two lists that can drift apart.
func goldenPskIds() map[string]struct {
	id      *PreSharedKeyId
	encoded []byte
	length  int
} {
	return map[string]struct {
		id      *PreSharedKeyId
		encoded []byte
		length  int
	}{
		"external": {handDerivedExternalGoldenId(), handDerivedExternalGolden(), 8},
		"resumption": {
			handDerivedResumptionGoldenId(), handDerivedResumptionGolden(), 14},
		"wide external": {
			handDerivedWideExternalGoldenId(), handDerivedWideExternalGolden(), 68},
		"wide resumption": {
			handDerivedWideResumptionGoldenId(), handDerivedWideResumptionGolden(), 77},
	}
}

// TestPreSharedKeyIdMarshalMatchesEveryHandDerivedGolden is the field order, arm
// selection and varint width pin. A reordered field, a psk_epoch written at four octets,
// a length prefix written at the record layer's fixed 32 bit width instead of the MLS
// varint, or an arm that writes a field belonging to the other one all change every
// psk_secret derived from these bytes, and this is the cheapest place to see it.
//
// Each golden's length is asserted against the arithmetic in its own comment first. A
// derivation whose comment and body disagree is a golden nobody has actually checked.
func TestPreSharedKeyIdMarshalMatchesEveryHandDerivedGolden(t *testing.T) {
	for name, golden := range goldenPskIds() {
		if len(golden.encoded) != golden.length {
			t.Fatalf("%s: the hand derivation is %d octets, the arithmetic in its comment says %d",
				name, len(golden.encoded), golden.length)
		}
		encoded, err := syntax.Marshal(golden.id)
		if err != nil {
			t.Fatalf("%s: syntax.Marshal: %v", name, err)
		}
		if !bytes.Equal(encoded, golden.encoded) {
			t.Fatalf("%s: syntax.Marshal =\n %x\nwant\n %x", name, encoded, golden.encoded)
		}
	}
}

// TestPreSharedKeyIdMarshalExternal is the plan's own external golden, kept because it
// states the same claim in the plan's words.
func TestPreSharedKeyIdMarshalExternal(t *testing.T) {
	id := &PreSharedKeyId{
		PskType:  PskTypeExternal,
		PskId:    []byte{0xaa, 0xbb},
		PskNonce: []byte{0x01, 0x02, 0x03},
	}
	encoded, err := syntax.Marshal(id)
	if err != nil {
		t.Fatalf("syntax.Marshal: %v", err)
	}
	want := []byte{
		0x01,             // psktype = external
		0x02, 0xaa, 0xbb, // psk_id<V>
		0x03, 0x01, 0x02, 0x03, // psk_nonce<V>
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("syntax.Marshal = %x, want %x", encoded, want)
	}
}

// TestPreSharedKeyIdMarshalResumption is the plan's own resumption golden, including the
// usage octet and the uint64 epoch that sit between the type and the nonce.
func TestPreSharedKeyIdMarshalResumption(t *testing.T) {
	id := &PreSharedKeyId{
		PskType:    PskTypeResumption,
		Usage:      ResumptionPskUsageApplication,
		PskGroupId: []byte{0xcc},
		PskEpoch:   7,
		PskNonce:   []byte{0x09},
	}
	encoded, err := syntax.Marshal(id)
	if err != nil {
		t.Fatalf("syntax.Marshal: %v", err)
	}
	want := []byte{
		0x02,       // psktype = resumption
		0x01,       // usage = application
		0x01, 0xcc, // psk_group_id<V>
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, // psk_epoch
		0x01, 0x09, // psk_nonce<V>
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("syntax.Marshal = %x, want %x", encoded, want)
	}
}

// ---------------------------------------------------------------------------
// the upstream corpus
// ---------------------------------------------------------------------------

// pskProposalVector is the part of one mlswg messages.json entry this file reads. The
// PreSharedKey proposal of RFC 9420 section 12.1.4 is a struct of exactly one field, a
// PreSharedKeyID, so its encoding IS the encoding of an id with no framing around it —
// which makes these three hundred hex strings a statement of this structure's wire form
// written by another implementation. The file is pinned by digest in vectors_pin_test.go
// and checked against its upstream git blob in vectors_upstream_test.go, so it cannot
// drift without a visible re-vendoring.
type pskProposalVector struct {
	PreSharedKeyProposal string `json:"pre_shared_key_proposal"`
}

// loadPskProposalVectors reads the pinned corpus. A file that parsed to nothing is fatal:
// the assertions below would then be a comparison against an empty list, which is the
// failure mode that reports green having checked nothing.
func loadPskProposalVectors(t *testing.T) []pskProposalVector {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "vectors", "messages.json"))
	if err != nil {
		t.Fatalf("read messages.json: %v", err)
	}
	vectors := []pskProposalVector{}
	if err := json.Unmarshal(body, &vectors); err != nil {
		t.Fatalf("parse messages.json: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("messages.json parsed to no entries, so every assertion over it would hold vacuously")
	}
	return vectors
}

// TestPreSharedKeyIdMatchesEveryUpstreamPskProposal holds the external arm to bytes this
// encoder did not write.
//
// The fields are cut out of the upstream encoding positionally, under a layout stated
// here from RFC 9420 rather than obtained from this package's decoder: octet zero is the
// psktype, and a vlbytes length below 64 is a single octet whose value is the length
// (section 2.1). Nothing in the slicing consults UnmarshalMLS, so re-encoding those
// fields and getting the upstream bytes back is a statement about this encoder rather
// than a round trip of it against itself. A psktype code point of 2 for external, an
// opaque length written at the record layer's fixed width, or the nonce written before
// the id would all fail here.
//
// The decode direction is asserted on the same bytes, including that the fields the
// external arm does not carry come back as their zero values: a decoder that read a usage
// octet in this arm would consume the first octet of the nonce and everything after it
// would be off by one.
func TestPreSharedKeyIdMatchesEveryUpstreamPskProposal(t *testing.T) {
	checked := 0
	for index, vector := range loadPskProposalVectors(t) {
		raw, err := hex.DecodeString(vector.PreSharedKeyProposal)
		if err != nil {
			t.Fatalf("vector %d: pre_shared_key_proposal is not hex: %v", index, err)
		}
		if len(raw) < 3 {
			t.Fatalf("vector %d: %d octets cannot hold a psktype and two length prefixes", index, len(raw))
		}
		if raw[0] != uint8(PskTypeExternal) {
			t.Fatalf("vector %d: psktype octet is %#02x, want %#02x for external; the corpus carries an arm this test does not cut up",
				index, raw[0], uint8(PskTypeExternal))
		}
		if raw[1] >= 0x40 {
			t.Fatalf("vector %d: psk_id length prefix %#02x is not the single octet form this slicing assumes", index, raw[1])
		}
		idLength := int(raw[1])
		if len(raw) < 2+idLength+1 {
			t.Fatalf("vector %d: %d octets cannot hold a %d octet psk_id and a nonce prefix", index, len(raw), idLength)
		}
		if raw[2+idLength] >= 0x40 {
			t.Fatalf("vector %d: psk_nonce length prefix %#02x is not the single octet form this slicing assumes",
				index, raw[2+idLength])
		}
		nonceLength := int(raw[2+idLength])
		if want := 2 + idLength + 1 + nonceLength; len(raw) != want {
			t.Fatalf("vector %d: the layout accounts for %d octets and the encoding is %d", index, want, len(raw))
		}

		id := &PreSharedKeyId{
			PskType:  PskTypeExternal,
			PskId:    raw[2 : 2+idLength],
			PskNonce: raw[3+idLength : 3+idLength+nonceLength],
		}
		encoded, err := syntax.Marshal(id)
		if err != nil {
			t.Fatalf("vector %d: syntax.Marshal: %v", index, err)
		}
		if !bytes.Equal(encoded, raw) {
			t.Fatalf("vector %d: syntax.Marshal =\n %x\nupstream messages.json =\n %x", index, encoded, raw)
		}

		parsed := &PreSharedKeyId{}
		if err := syntax.Unmarshal(raw, parsed); err != nil {
			t.Fatalf("vector %d: syntax.Unmarshal: %v", index, err)
		}
		if !preSharedKeyIdsAgree(id, parsed) {
			t.Fatalf("vector %d: decoded to %s, want %s", index, describePreSharedKeyId(parsed), describePreSharedKeyId(id))
		}
		if parsed.Usage != 0 || parsed.PskGroupId != nil || parsed.PskEpoch != 0 {
			t.Fatalf("vector %d: the external arm decoded usage %d, a %d octet group id and epoch %d, none of which it carries",
				index, parsed.Usage, len(parsed.PskGroupId), parsed.PskEpoch)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no upstream psk proposal was checked")
	}
	t.Logf("%d upstream psk proposals encoded and decoded byte exact", checked)
}

// ---------------------------------------------------------------------------
// the union: each arm writes its own fields and nobody else's
// ---------------------------------------------------------------------------

// TestPreSharedKeyIdEncodesOnlyTheFieldsOfItsArm asserts the flattened struct behaves as
// the RFC's select() does: the discriminant decides which fields exist, and a field
// belonging to the other arm is not merely ignored on decode but never written.
//
// This is the property the flattening puts at risk and it has a consequence rather than
// being tidiness. A resumption group id leaking into an external id's encoding is extra
// bytes inside a PSKLabel that every member hashes, so the two members who disagree about
// whether to write them derive different psk_secrets and stop being able to talk.
func TestPreSharedKeyIdEncodesOnlyTheFieldsOfItsArm(t *testing.T) {
	for name, pair := range map[string][2]*PreSharedKeyId{
		"external ignores the resumption fields": {
			handDerivedExternalGoldenId(),
			&PreSharedKeyId{
				PskType:    PskTypeExternal,
				PskId:      []byte{0xaa, 0xbb},
				Usage:      ResumptionPskUsageBranch,
				PskGroupId: repeatByte(0x5a, 64),
				PskEpoch:   math.MaxUint64,
				PskNonce:   []byte{0x01, 0x02, 0x03},
			},
		},
		"resumption ignores the external field": {
			handDerivedResumptionGoldenId(),
			&PreSharedKeyId{
				PskType:    PskTypeResumption,
				PskId:      repeatByte(0x5b, 64),
				Usage:      ResumptionPskUsageApplication,
				PskGroupId: []byte{0xcc},
				PskEpoch:   7,
				PskNonce:   []byte{0x09},
			},
		},
	} {
		lean, err := syntax.Marshal(pair[0])
		if err != nil {
			t.Fatalf("%s: syntax.Marshal of the canonical value: %v", name, err)
		}
		loaded, err := syntax.Marshal(pair[1])
		if err != nil {
			t.Fatalf("%s: syntax.Marshal of the loaded value: %v", name, err)
		}
		if !bytes.Equal(lean, loaded) {
			t.Fatalf("%s: setting the other arm's fields changed the encoding\n from %x\n to   %x", name, lean, loaded)
		}
	}
}

// varyPreSharedKeyIdField gives one field of a PreSharedKeyId a different value, in place.
// An unhandled kind is fatal rather than skipped: a field of a new kind that this helper
// quietly ignored would be a field the completeness gate below reports as covered without
// ever having varied it, which is rule 5's failure with the gate's own helper doing it.
func varyPreSharedKeyIdField(t *testing.T, path string, field reflect.Value) {
	t.Helper()
	switch field.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		field.SetUint(field.Uint() + 1)
	case reflect.Slice:
		existing, ok := field.Interface().([]byte)
		if !ok {
			t.Fatalf("%s is a slice of something other than bytes, which this helper cannot vary", path)
		}
		field.Set(reflect.ValueOf(append(append([]byte{}, existing...), 0xff)))
	default:
		t.Fatalf("%s is of kind %s, which this helper does not know how to vary; widen it rather than letting the gate below report the field as covered",
			path, field.Kind())
	}
}

// TestEveryPreSharedKeyIdFieldReachesTheEncodingInSomeArm is the derived completeness gate
// on the codec, and it is the one test here a field added later cannot slip past.
//
// It walks the struct definition with reflection rather than naming the fields, gives each
// one in turn a different value in both arms, and requires that at least one arm noticed —
// either the bytes moved, or the encoder's accept-or-refuse answer moved, which is what
// varying the discriminant off the registry does. A field added to PreSharedKeyId and
// forgotten in MarshalMLS therefore fails on the commit that adds it, rather than in the
// epoch where two members disagree about a field only one of them wrote.
func TestEveryPreSharedKeyIdFieldReachesTheEncodingInSomeArm(t *testing.T) {
	structType := reflect.TypeOf(PreSharedKeyId{})
	if structType.NumField() == 0 {
		t.Fatal("PreSharedKeyId declares no fields, so this gate walked nothing")
	}
	arms := map[string]*PreSharedKeyId{
		"external":   handDerivedExternalGoldenId(),
		"resumption": handDerivedResumptionGoldenId(),
	}
	for i := 0; i < structType.NumField(); i++ {
		name := structType.Field(i).Name
		noticed := []string{}
		for arm, base := range arms {
			before, beforeErr := syntax.Marshal(clonePreSharedKeyId(base))
			if beforeErr != nil {
				t.Fatalf("%s: the %s fixture does not encode: %v", name, arm, beforeErr)
			}
			varied := clonePreSharedKeyId(base)
			varyPreSharedKeyIdField(t, name, reflect.ValueOf(varied).Elem().Field(i))
			after, afterErr := syntax.Marshal(varied)
			if afterErr != nil {
				// an arm the encoder refuses is a change in its answer, which is
				// exactly what varying the discriminant off the registry produces.
				noticed = append(noticed, arm+" (refused)")
				continue
			}
			if !bytes.Equal(before, after) {
				noticed = append(noticed, arm)
			}
		}
		if len(noticed) == 0 {
			t.Errorf("changing %s changed neither arm's encoding, so MarshalMLS does not carry it and two members can disagree about it silently", name)
			continue
		}
		t.Logf("%s reaches the encoding in: %v", name, noticed)
	}
}

// ---------------------------------------------------------------------------
// the generated round trip corpus
// ---------------------------------------------------------------------------

// generatedPreSharedKeyIds is the round trip corpus: the cross product of the two arms
// with the varint width boundaries of every opaque field, the whole octet range of the
// usage discriminant, and the uint64 boundaries of the epoch.
//
// It is generated rather than written out case by case for the reason rule 5 names: a
// hand picked table is a claim about which cases matter, made by whoever also wrote the
// code. The enum axes are read out of the package's own constant declarations, so a
// registry member added later enters this corpus in the commit that declares it rather
// than in the commit somebody remembers to widen a list.
//
// Each entry is in canonical form for its arm — the fields the arm does not encode are
// left at their zero values — so that "decoding reproduces every field" is a statement
// the corpus can actually make. That the encoder ignores the other arm's fields is
// TestPreSharedKeyIdEncodesOnlyTheFieldsOfItsArm, above.
func generatedPreSharedKeyIds(t *testing.T) []*PreSharedKeyId {
	t.Helper()

	pskTypes := registryConstantsOfType(t, "PskType")
	for name, want := range map[string]uint64{"PskTypeExternal": 1, "PskTypeResumption": 2} {
		if got, ok := pskTypes[name]; !ok || got != want {
			t.Fatalf("the derivation read %s = %d (present %v), want %d; it is not reading this package's PskType declarations",
				name, got, ok, want)
		}
	}
	// the usage axis is the derived registry plus the two ends of the octet, because
	// the codec carries usage opaquely: a value outside the registry has to survive a
	// round trip for ValSem402 to be able to refuse it by name.
	usages := map[uint64]bool{0: true, 0xff: true}
	for _, value := range registryConstantsOfType(t, "ResumptionPskUsage") {
		usages[value] = true
	}

	// the opaque field lengths the varint branches on: absent, empty, one octet, the
	// last length a one octet prefix can express, the first that needs two, and one
	// well inside the two octet range.
	opaques := [][]byte{
		nil,
		{},
		repeatByte(0x11, 1),
		repeatByte(0x22, 63),
		repeatByte(0x33, 64),
		repeatByte(0x44, 255),
	}
	// the nonce axis adds KDF.Nh itself, which is the only length ValSem401 accepts and
	// therefore the only one that occurs in production.
	nonces := append(append([][]byte{}, opaques...), repeatByte(0x55, 32))

	// the uint64 boundaries, which are the values a narrower field or a sign would move.
	epochs := []uint64{
		0,
		1,
		math.MaxUint8,
		math.MaxUint16,
		math.MaxUint32 - 1,
		math.MaxUint32,
		uint64(math.MaxUint32) + 1,
		1 << 40,
		1 << 63,
		math.MaxUint64,
	}

	corpus := []*PreSharedKeyId{}
	for _, pskId := range opaques {
		for _, nonce := range nonces {
			corpus = append(corpus, &PreSharedKeyId{
				PskType:  PskTypeExternal,
				PskId:    pskId,
				PskNonce: nonce,
			})
		}
	}
	for usage := range usages {
		for groupIdIndex, groupId := range opaques {
			for epochIndex, epoch := range epochs {
				// the nonce rotates through its own axis rather than being crossed
				// with the group id, which would multiply the corpus to buy nothing:
				// both go through the same opaque encoder, so a length that works in
				// one position works in the other. Rotating puts every length in every
				// position across the product.
				corpus = append(corpus, &PreSharedKeyId{
					PskType:    PskTypeResumption,
					Usage:      ResumptionPskUsage(usage),
					PskGroupId: groupId,
					PskEpoch:   epoch,
					PskNonce:   nonces[(groupIdIndex+epochIndex)%len(nonces)],
				})
			}
		}
	}
	return corpus
}

// TestPreSharedKeyIdRoundTripsByteExactOverTheGeneratedCorpus asserts, for every generated
// id, that it encodes, that decoding recovers every field, and that re-encoding reproduces
// the bytes exactly. syntax.CheckRoundTrip is called on the same input because every later
// fuzz target reaches this codec through it, so a codec that satisfied the property here
// and not there would leave those targets green and empty.
func TestPreSharedKeyIdRoundTripsByteExactOverTheGeneratedCorpus(t *testing.T) {
	corpus := generatedPreSharedKeyIds(t)
	if len(corpus) < 300 {
		t.Fatalf("the generated corpus holds %d ids, far fewer than the product of its axes; the generator produced almost nothing", len(corpus))
	}
	for index, id := range corpus {
		encoded, err := syntax.Marshal(id)
		if err != nil {
			t.Fatalf("case %d %s: syntax.Marshal: %v", index, describePreSharedKeyId(id), err)
		}
		parsed := &PreSharedKeyId{}
		if err := syntax.Unmarshal(encoded, parsed); err != nil {
			t.Fatalf("case %d %s: syntax.Unmarshal: %v", index, describePreSharedKeyId(id), err)
		}
		if !preSharedKeyIdsAgree(id, parsed) {
			t.Fatalf("case %d %s: decoded to %s", index, describePreSharedKeyId(id), describePreSharedKeyId(parsed))
		}
		reencoded, err := syntax.Marshal(parsed)
		if err != nil {
			t.Fatalf("case %d %s: re-encode: %v", index, describePreSharedKeyId(id), err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Fatalf("case %d %s: round trip =\n %x\nwant\n %x", index, describePreSharedKeyId(id), reencoded, encoded)
		}
		if err := syntax.CheckRoundTrip[PreSharedKeyId, *PreSharedKeyId](encoded); err != nil {
			t.Fatalf("case %d %s: CheckRoundTrip: %v", index, describePreSharedKeyId(id), err)
		}
	}
	t.Logf("%d generated ids round tripped byte exact", len(corpus))
}

// TestPreSharedKeyIdRoundTrip is the plan's own round trip case, kept because it states
// the claim in the plan's words over its own two values.
func TestPreSharedKeyIdRoundTrip(t *testing.T) {
	for _, id := range []*PreSharedKeyId{
		{PskType: PskTypeExternal, PskId: []byte{1, 2, 3}, PskNonce: []byte{4, 5}},
		{PskType: PskTypeResumption, Usage: ResumptionPskUsageBranch, PskGroupId: []byte{6}, PskEpoch: 1 << 40, PskNonce: []byte{7}},
	} {
		encoded, err := syntax.Marshal(id)
		if err != nil {
			t.Fatalf("syntax.Marshal: %v", err)
		}
		parsed := &PreSharedKeyId{}
		if err := syntax.Unmarshal(encoded, parsed); err != nil {
			t.Fatalf("syntax.Unmarshal: %v", err)
		}
		if !preSharedKeyIdsAgree(id, parsed) {
			t.Fatalf("decoded %s, want %s", describePreSharedKeyId(parsed), describePreSharedKeyId(id))
		}
		reencoded, err := syntax.Marshal(parsed)
		if err != nil {
			t.Fatalf("syntax.Marshal: %v", err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatalf("round trip = %x, want %x", reencoded, encoded)
		}
	}
}

// TestPreSharedKeyIdRoundTripsAcrossTheFourOctetVarintBoundary covers the lengths the
// corpus above leaves out because carrying them through a cross product would cost
// megabytes per case: the last length the two octet prefix can express and the first that
// needs the four octet one.
func TestPreSharedKeyIdRoundTripsAcrossTheFourOctetVarintBoundary(t *testing.T) {
	for _, length := range []int{16383, 16384, 16385} {
		for name, id := range map[string]*PreSharedKeyId{
			"external": {
				PskType:  PskTypeExternal,
				PskId:    repeatByte(0x99, length),
				PskNonce: repeatByte(0xaa, length),
			},
			"resumption": {
				PskType:    PskTypeResumption,
				Usage:      ResumptionPskUsageApplication,
				PskGroupId: repeatByte(0xbb, length),
				PskEpoch:   math.MaxUint64,
				PskNonce:   repeatByte(0xcc, length),
			},
		} {
			encoded, err := syntax.Marshal(id)
			if err != nil {
				t.Fatalf("%s length %d: syntax.Marshal: %v", name, length, err)
			}
			parsed := &PreSharedKeyId{}
			if err := syntax.Unmarshal(encoded, parsed); err != nil {
				t.Fatalf("%s length %d: syntax.Unmarshal: %v", name, length, err)
			}
			if !preSharedKeyIdsAgree(id, parsed) {
				t.Fatalf("%s length %d did not round trip", name, length)
			}
			reencoded, err := syntax.Marshal(parsed)
			if err != nil {
				t.Fatalf("%s length %d: re-encode: %v", name, length, err)
			}
			if !bytes.Equal(reencoded, encoded) {
				t.Fatalf("%s length %d: re-encoding changed the %d octet encoding", name, length, len(encoded))
			}
		}
	}
}

// TestPreSharedKeyIdRoundTripsAMaximalNonceAndRefusesAnOverlongOne pins the two ends of
// the configured vector length limit. A field of exactly the limit must encode and come
// back; one octet more must be refused by the encoder rather than produce bytes a
// compliant peer would reject.
func TestPreSharedKeyIdRoundTripsAMaximalNonceAndRefusesAnOverlongOne(t *testing.T) {
	maximal := &PreSharedKeyId{
		PskType:  PskTypeExternal,
		PskId:    []byte{0xd0},
		PskNonce: repeatByte(0xd1, syntax.MaxVectorLength),
	}
	encoded, err := syntax.Marshal(maximal)
	if err != nil {
		t.Fatalf("a nonce of exactly MaxVectorLength was refused: %v", err)
	}
	parsed := &PreSharedKeyId{}
	if err := syntax.Unmarshal(encoded, parsed); err != nil {
		t.Fatalf("the maximal encoding did not decode: %v", err)
	}
	if !preSharedKeyIdsAgree(maximal, parsed) {
		t.Fatal("the maximal id did not round trip")
	}

	overlong := clonePreSharedKeyId(maximal)
	overlong.PskNonce = repeatByte(0xd1, syntax.MaxVectorLength+1)
	if _, err := syntax.Marshal(overlong); !errors.Is(err, syntax.ErrLengthExceedsMax) {
		t.Fatalf("a nonce one octet over the limit encoded with err = %v, want syntax.ErrLengthExceedsMax", err)
	}
}

// ---------------------------------------------------------------------------
// decode discipline
// ---------------------------------------------------------------------------

// goldenPskEncodings is the set of valid encodings the refusal properties below are
// stated over: both arms at their narrow widths, both at the two octet varint width, and
// one encoding another implementation wrote.
func goldenPskEncodings(t *testing.T) map[string][]byte {
	t.Helper()
	encodings := map[string][]byte{}
	for name, golden := range goldenPskIds() {
		encodings[name] = golden.encoded
	}
	raw, err := hex.DecodeString(loadPskProposalVectors(t)[0].PreSharedKeyProposal)
	if err != nil {
		t.Fatalf("the first upstream psk proposal is not hex: %v", err)
	}
	encodings["upstream"] = raw
	return encodings
}

// TestPreSharedKeyIdUnmarshalLeavesTheTailAlone asserts UnmarshalMLS consumes exactly one
// id, which is what PSKLabel and GroupSecrets.psks<V> both depend on. Both arms are swept,
// because the resumption arm is where an over consuming decoder is easiest to write: its
// epoch is the one field with no length prefix in front of it.
func TestPreSharedKeyIdUnmarshalLeavesTheTailAlone(t *testing.T) {
	for name, golden := range goldenPskIds() {
		r := syntax.NewReader(append(append([]byte{}, golden.encoded...), 0xde, 0xad))
		parsed := &PreSharedKeyId{}
		if err := parsed.UnmarshalMLS(r); err != nil {
			t.Fatalf("%s: UnmarshalMLS: %v", name, err)
		}
		if !preSharedKeyIdsAgree(golden.id, parsed) {
			t.Fatalf("%s: decoded to %s, want %s", name, describePreSharedKeyId(parsed), describePreSharedKeyId(golden.id))
		}
		tail, err := r.ReadRaw(2)
		if err != nil {
			t.Fatalf("%s: ReadRaw: %v", name, err)
		}
		if !bytes.Equal(tail, []byte{0xde, 0xad}) {
			t.Fatalf("%s: tail = %x, want dead", name, tail)
		}
		if remaining := r.Remaining(); remaining != 0 {
			t.Fatalf("%s: %d octets left after the tail, so the decoder consumed fewer than its own fields", name, remaining)
		}
	}
}

// TestPreSharedKeyIdRejectsTrailingBytes asserts a standalone encoding with anything after
// it is refused. MLS signs over serialized forms, so a decoder tolerating a tail accepts
// two encodings of one object and the signature covers only one of them.
func TestPreSharedKeyIdRejectsTrailingBytes(t *testing.T) {
	for name, full := range goldenPskEncodings(t) {
		if err := syntax.Unmarshal(full, &PreSharedKeyId{}); err != nil {
			t.Fatalf("%s: the untrailed encoding was refused (%v), so the assertion below proves nothing", name, err)
		}
		withTail := append(append([]byte{}, full...), 0x00)
		if err := syntax.Unmarshal(withTail, &PreSharedKeyId{}); !errors.Is(err, syntax.ErrTrailingBytes) {
			t.Errorf("%s: one trailing octet decoded with err = %v, want syntax.ErrTrailingBytes", name, err)
		}
	}
}

// TestPreSharedKeyIdRejectsEverySingleByteTruncation asserts every proper prefix of a
// valid encoding is refused rather than yielding a partly populated id. The set of
// prefixes is derived from each encoding's own length, so a field added to the structure
// widens this test without anybody editing it.
func TestPreSharedKeyIdRejectsEverySingleByteTruncation(t *testing.T) {
	for name, full := range goldenPskEncodings(t) {
		refused := 0
		for n := 0; n < len(full); n++ {
			parsed := &PreSharedKeyId{}
			if err := syntax.Unmarshal(full[:n], parsed); err == nil {
				t.Errorf("%s: the %d octet prefix parsed into %s, want an error", name, n, describePreSharedKeyId(parsed))
				continue
			}
			refused++
		}
		if refused != len(full) {
			t.Errorf("%s: %d of %d prefixes refused", name, refused, len(full))
		}
		if err := syntax.Unmarshal(full, &PreSharedKeyId{}); err != nil {
			t.Errorf("%s: the untruncated encoding was refused too (%v), so the loop above proves nothing", name, err)
		}
	}
}

// TestPreSharedKeyIdEitherRefusesOrExactlyReproducesEverySingleByteCorruption is the
// canonicality property, stated over every one octet change to a valid encoding: the
// decoder may refuse, and if it accepts then re-encoding must give back the corrupted
// bytes exactly. Accepted-and-silently-changed is the outcome that is forbidden, because
// it is a second encoding of a structure whose first encoding somebody signed.
//
// Both outcomes are counted and both are required to occur. A decoder that refused
// everything would satisfy the property vacuously, and so would a corpus that never
// reached the accepting branch.
func TestPreSharedKeyIdEitherRefusesOrExactlyReproducesEverySingleByteCorruption(t *testing.T) {
	for name, full := range goldenPskEncodings(t) {
		accepted, refused := 0, 0
		for position := range full {
			for delta := 1; delta < 256; delta++ {
				corrupted := append([]byte{}, full...)
				corrupted[position] = byte((int(full[position]) + delta) % 256)
				parsed := &PreSharedKeyId{}
				if err := syntax.Unmarshal(corrupted, parsed); err != nil {
					refused++
					continue
				}
				accepted++
				reencoded, err := syntax.Marshal(parsed)
				if err != nil {
					t.Fatalf("%s: octet %d changed to %#02x decoded but would not re-encode: %v",
						name, position, corrupted[position], err)
				}
				if !bytes.Equal(reencoded, corrupted) {
					t.Fatalf("%s: octet %d changed to %#02x was accepted and changed:\n got %x\nwant %x",
						name, position, corrupted[position], reencoded, corrupted)
				}
			}
		}
		if accepted == 0 {
			t.Errorf("%s: every one of the %d corruptions was refused, so the re-encoding half of this property was never evaluated", name, refused)
		}
		if refused == 0 {
			t.Errorf("%s: every one of the %d corruptions was accepted, which cannot be right for a length prefixed format", name, accepted)
		}
		t.Logf("%s: %d corruptions accepted and reproduced byte exact, %d refused", name, accepted, refused)
	}
}

// sentinelPreSharedKeyId is a receiver whose every field holds a value no golden holds, so
// an assignment made before a decode failed is visible whatever it assigned. A zeroed
// receiver would show an early assignment only when the input's value for that field
// happens not to be zero, which makes the observation depend on the fixture rather than on
// the code.
func sentinelPreSharedKeyId() *PreSharedKeyId {
	return &PreSharedKeyId{
		PskType:    PskType(0x7b),
		PskId:      []byte{0x9a, 0x9b},
		Usage:      ResumptionPskUsage(0x7c),
		PskGroupId: []byte{0x9c},
		PskEpoch:   0x0123456789abcdef,
		PskNonce:   []byte{0x9d, 0x9e, 0x9f},
	}
}

// TestPreSharedKeyIdUnmarshalAssignsNothingWhenItRefuses states the all or nothing rule
// UnmarshalMLS documents: a decode that fails leaves the caller's value exactly as it was
// handed over.
//
// The rule earns a test because the value a decode writes into is not always fresh. Under
// C1 the byte level entry point is syntax.Unmarshal(bs, id) into a value the caller owns,
// which invites reuse across a psks<V> vector, and a decoder that assigned as it read
// would leave a refused decode holding some fields from the new input and the rest from
// the old one. That composite is not a mangled struct anybody would notice: it is a well
// formed PreSharedKeyId naming a key nobody sent, and re-encoding it produces bytes that
// go into a psk_input some member will hash.
//
// Two families of refusable input are swept, both derived. Every proper prefix of every
// golden fails somewhere in the field sequence, which reaches the assignments that happen
// before the failing read. Every single octet change to the goldens reaches what a
// truncation cannot — a length prefix that overruns its region, a psktype off the registry
// — and those fail at points a prefix never stops at.
//
// UnmarshalMLS is called directly rather than through syntax.Unmarshal because the trailing
// byte refusal belongs to the outer layer and happens after every field has legitimately
// been assigned, so routing through it would count a correct decode as a refusal.
func TestPreSharedKeyIdUnmarshalAssignsNothingWhenItRefuses(t *testing.T) {
	inputs := map[string][][]byte{}
	for name, full := range goldenPskEncodings(t) {
		prefixes := [][]byte{}
		for n := 0; n < len(full); n++ {
			prefixes = append(prefixes, full[:n])
		}
		inputs[name+" truncated"] = prefixes

		corruptions := [][]byte{}
		for position := range full {
			for delta := 1; delta < 256; delta++ {
				corrupted := append([]byte{}, full...)
				corrupted[position] = byte((int(full[position]) + delta) % 256)
				corruptions = append(corruptions, corrupted)
			}
		}
		inputs[name+" corrupted"] = corruptions
	}

	refused, accepted := 0, 0
	for name, family := range inputs {
		familyRefused := 0
		for _, input := range family {
			untouched := sentinelPreSharedKeyId()
			parsed := sentinelPreSharedKeyId()
			if err := parsed.UnmarshalMLS(syntax.NewReader(input)); err == nil {
				accepted++
				continue
			}
			familyRefused++
			if !reflect.DeepEqual(parsed, untouched) {
				t.Fatalf("%s: a refused %d octet input changed the caller's id\n from %#v\n to   %#v",
					name, len(input), untouched, parsed)
			}
		}
		if familyRefused == 0 {
			t.Errorf("%s: none of its %d inputs was refused, so this family evaluated the property zero times",
				name, len(family))
		}
		refused += familyRefused
	}
	if accepted == 0 {
		t.Fatal("every input was refused, so the corruption sweep produced nothing decodable and is not the sweep it claims to be")
	}
	t.Logf("%d refused inputs left the caller's id untouched, %d were accepted", refused, accepted)
}

// TestPreSharedKeyIdUnmarshalClearsTheFieldsItsArmDoesNotCarry is the other half of the
// assignment rule and the one the flattened union makes possible.
//
// A decoder that assigned only the fields of the arm it read would be correct on a fresh
// receiver and wrong on a reused one: decode a resumption id, then an external one into
// the same value, and PskGroupId and PskEpoch still describe the first. Nothing in the
// re-encoding would show it, because the external arm does not write those fields — it
// shows up in whatever reads them, which for a resumption psk is the lookup that decides
// which group's secret to reach for.
func TestPreSharedKeyIdUnmarshalClearsTheFieldsItsArmDoesNotCarry(t *testing.T) {
	external := handDerivedWideExternalGolden()
	resumption := handDerivedWideResumptionGolden()

	reused := &PreSharedKeyId{}
	if err := syntax.Unmarshal(resumption, reused); err != nil {
		t.Fatalf("the resumption golden did not decode: %v", err)
	}
	if reused.PskGroupId == nil || reused.PskEpoch == 0 || reused.Usage == 0 {
		t.Fatalf("the resumption golden decoded to %s, which carries none of the fields the second decode has to clear",
			describePreSharedKeyId(reused))
	}
	if err := syntax.Unmarshal(external, reused); err != nil {
		t.Fatalf("the external golden did not decode into the reused id: %v", err)
	}
	if reused.Usage != 0 || reused.PskGroupId != nil || reused.PskEpoch != 0 {
		t.Fatalf("after decoding an external id the receiver still holds usage %d, a %d octet group id and epoch %#x from the resumption id before it",
			reused.Usage, len(reused.PskGroupId), reused.PskEpoch)
	}

	if err := syntax.Unmarshal(resumption, reused); err != nil {
		t.Fatalf("the resumption golden did not decode into the reused id: %v", err)
	}
	if reused.PskId != nil {
		t.Fatalf("after decoding a resumption id the receiver still holds a %d octet psk_id from the external id before it", len(reused.PskId))
	}
}

// ---------------------------------------------------------------------------
// the psktype registry, derived
// ---------------------------------------------------------------------------

// registeredPskTypes reads the psktype code points out of this package's own constant
// declarations and checks the reading against the two the RFC names, so a derivation that
// found nothing is separated from one that found something. The sweeps below state their
// property over the complement of this set — every octet that is NOT a registered type —
// which is a class no list can understate.
func registeredPskTypes(t *testing.T) map[uint64]bool {
	t.Helper()
	derived := registryConstantsOfType(t, "PskType")
	for name, want := range map[string]uint64{"PskTypeExternal": 1, "PskTypeResumption": 2} {
		if got, ok := derived[name]; !ok || got != want {
			t.Fatalf("the derivation read %s = %d (present %v), want %d", name, got, ok, want)
		}
	}
	registered := map[uint64]bool{}
	for _, value := range derived {
		registered[value] = true
	}
	return registered
}

// TestPreSharedKeyIdUnmarshalRefusesEveryUnregisteredPskType asserts an unknown psktype is
// a decode error rather than a value carried through, over every octet the registry does
// not claim.
//
// The refusal is not pedantry about unknown code points. The psktype selects the arm, the
// arm decides how many fields follow, and an implementation that does not know the arm does
// not know where the id ends — so a decoder that shrugged and read a nonce would be
// guessing at an offset, and in a psks<V> vector that guess desynchronises every id after it.
func TestPreSharedKeyIdUnmarshalRefusesEveryUnregisteredPskType(t *testing.T) {
	registered := registeredPskTypes(t)
	refused, known := 0, 0
	for value := 0; value <= 0xff; value++ {
		err := (&PreSharedKeyId{}).UnmarshalMLS(syntax.NewReader([]byte{byte(value)}))
		if registered[uint64(value)] {
			known++
			// a registered arm runs out of input here, which is a different failure
			// and must not be reported as the type refusal.
			if errors.Is(err, errPskType) {
				t.Errorf("psktype %#02x is registered and was refused as an unknown type: %v", value, err)
			}
			continue
		}
		if !errors.Is(err, errPskType) {
			t.Errorf("psktype %#02x decoded with err = %v, want the ValSem402 refusal", value, err)
			continue
		}
		refused++
	}
	if known == 0 {
		t.Fatal("no registered psktype was reached, so the control half of this sweep evaluated nothing")
	}
	if refused != 0x100-known {
		t.Fatalf("%d of the %d unregistered psktypes were refused", refused, 0x100-known)
	}
	t.Logf("%d unregistered psktypes refused, %d registered arms reached", refused, known)
}

// TestPreSharedKeyIdMarshalRefusesEveryUnregisteredPskType asserts the encoder refuses the
// same arms it cannot decode. This is the semantic refusal MarshalMLS returns an error for
// (C2): dropping it would emit a psktype octet and a nonce with no arm between them, which
// hashes into psk_input as though it were a whole id.
func TestPreSharedKeyIdMarshalRefusesEveryUnregisteredPskType(t *testing.T) {
	registered := registeredPskTypes(t)
	refused, accepted := 0, 0
	for value := 0; value <= 0xff; value++ {
		id := &PreSharedKeyId{PskType: PskType(value), PskNonce: repeatByte(0x01, 32)}
		encoded, err := syntax.Marshal(id)
		if registered[uint64(value)] {
			if err != nil {
				t.Errorf("psktype %#02x is registered and the encoder refused it: %v", value, err)
				continue
			}
			accepted++
			continue
		}
		if !errors.Is(err, errPskType) {
			t.Errorf("psktype %#02x encoded to %x with err = %v, want the ValSem402 refusal", value, encoded, err)
			continue
		}
		if encoded != nil {
			t.Errorf("psktype %#02x was refused and still produced %x", value, encoded)
		}
		refused++
	}
	if accepted == 0 {
		t.Fatal("no registered psktype encoded, so the control half of this sweep evaluated nothing")
	}
	if refused != 0x100-accepted {
		t.Fatalf("%d of the %d unregistered psktypes were refused", refused, 0x100-accepted)
	}
	t.Logf("%d unregistered psktypes refused by the encoder, %d registered arms encoded", refused, accepted)
}

// TestPreSharedKeyIdCarriesEveryResumptionUsageOctetThroughTheCodec asserts the codec is
// opaque about usage over the whole octet range, which is what lets ValSem402 refuse a
// value by name. A decoder that refused ReInit here would make the validation rule
// unreachable and its test vacuous, and would refuse the vectors besides.
func TestPreSharedKeyIdCarriesEveryResumptionUsageOctetThroughTheCodec(t *testing.T) {
	for value := 0; value <= 0xff; value++ {
		id := &PreSharedKeyId{
			PskType:    PskTypeResumption,
			Usage:      ResumptionPskUsage(value),
			PskGroupId: []byte{0xcc},
			PskEpoch:   9,
			PskNonce:   []byte{0x07},
		}
		encoded, err := syntax.Marshal(id)
		if err != nil {
			t.Fatalf("usage %#02x: syntax.Marshal: %v", value, err)
		}
		if encoded[1] != byte(value) {
			t.Fatalf("usage %#02x was written as %#02x", value, encoded[1])
		}
		parsed := &PreSharedKeyId{}
		if err := syntax.Unmarshal(encoded, parsed); err != nil {
			t.Fatalf("usage %#02x: syntax.Unmarshal: %v", value, err)
		}
		if !preSharedKeyIdsAgree(id, parsed) {
			t.Fatalf("usage %#02x decoded to %s", value, describePreSharedKeyId(parsed))
		}
	}
}

// ---------------------------------------------------------------------------
// ValSem401: the nonce length
// ---------------------------------------------------------------------------

// TestPreSharedKeyIdValidateNonceLength is ValSem401 stated the way the plan states it: an
// id that is valid in every other respect, and would therefore be accepted by a Validate
// that never looked at the nonce, is refused for its nonce alone.
func TestPreSharedKeyIdValidateNonceLength(t *testing.T) {
	crypto := pskTestCrypto(t)
	id := &PreSharedKeyId{PskType: PskTypeExternal, PskId: []byte{1}, PskNonce: make([]byte, 31)}
	// the refusal will be ValSem(ValSem401, ...) once the validation plan lands, and it
	// matches the sentinel through Unwrap either way. Asserting the code itself is p8's
	// TestValSem401_PskNonceLength; CodeOf is p8-internal and this plan does not reach
	// for it.
	if err := id.Validate(crypto); !errors.Is(err, errPskNonceLength) {
		t.Fatalf("err = %v, want the ValSem401 refusal", err)
	}
	id.PskNonce = make([]byte, 32)
	if err := id.Validate(crypto); err != nil {
		t.Fatalf("a 32 octet nonce was refused: %v", err)
	}
}

// TestPreSharedKeyIdValidateDerivesTheNonceLengthFromTheProvider is the half the two
// registered ciphersuites cannot state, because both have Nh = 32 and a literal 32 is
// indistinguishable from the derivation against either of them.
//
// The lengths swept are the three the mlswg psk_secret corpus actually carries, so this is
// not a hypothetical: RFC 9420 registers ciphersuites at SHA-384 and SHA-512, their vectors
// are in this tree, and a rule pinned to 32 would accept a 32 octet nonce for all of them —
// a nonce half the length the RFC requires, on the field whose whole job is to keep two uses
// of one pre shared key apart.
func TestPreSharedKeyIdValidateDerivesTheNonceLengthFromTheProvider(t *testing.T) {
	for _, hashSize := range []int{32, 48, 64} {
		crypto := pskCryptoWithHashSize(t, hashSize)
		for _, arm := range []*PreSharedKeyId{
			{PskType: PskTypeExternal, PskId: []byte{1}},
			{PskType: PskTypeResumption, Usage: ResumptionPskUsageApplication, PskGroupId: []byte{1}},
		} {
			exact := clonePreSharedKeyId(arm)
			exact.PskNonce = make([]byte, hashSize)
			if err := exact.Validate(crypto); err != nil {
				t.Errorf("Nh %d: a nonce of exactly Nh was refused: %v", hashSize, err)
			}
			for _, wrong := range []int{0, hashSize - 1, hashSize + 1, 32} {
				if wrong == hashSize {
					continue
				}
				off := clonePreSharedKeyId(arm)
				off.PskNonce = make([]byte, wrong)
				if err := off.Validate(crypto); !errors.Is(err, errPskNonceLength) {
					t.Errorf("Nh %d: a %d octet nonce was accepted with err = %v, want the ValSem401 refusal",
						hashSize, wrong, err)
				}
			}
		}
	}
}

// pskSecretVector is the part of one mlswg psk_secret.json entry this file reads.
type pskSecretVector struct {
	CipherSuite uint16 `json:"cipher_suite"`
	Psks        []struct {
		PskId    string `json:"psk_id"`
		PskNonce string `json:"psk_nonce"`
	} `json:"psks"`
}

// loadPskSecretVectors reads the pinned psk_secret corpus.
func loadPskSecretVectors(t *testing.T) []pskSecretVector {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "vectors", "psk_secret.json"))
	if err != nil {
		t.Fatalf("read psk_secret.json: %v", err)
	}
	vectors := []pskSecretVector{}
	if err := json.Unmarshal(body, &vectors); err != nil {
		t.Fatalf("parse psk_secret.json: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("psk_secret.json parsed to no entries")
	}
	return vectors
}

// TestPreSharedKeyIdValidateAcceptsEveryUpstreamPsk is the positive control ValSem401 needs
// and the negative sweep above cannot be: every pre shared key another implementation put in
// the psk_secret corpus must pass, at its own ciphersuite's Nh.
//
// A rule that refused too much would be as damaging as one that refused too little — it
// would make the vector family unpassable — and a rule tested only against nonces this file
// constructed could not tell the difference. The corpus carries three distinct Nh values,
// which is asserted, so this cannot quietly become a test about 32.
func TestPreSharedKeyIdValidateAcceptsEveryUpstreamPsk(t *testing.T) {
	lengthsSeen := map[int]int{}
	checked := 0
	for index, vector := range loadPskSecretVectors(t) {
		for position, psk := range vector.Psks {
			pskId, err := hex.DecodeString(psk.PskId)
			if err != nil {
				t.Fatalf("vector %d psk %d: psk_id is not hex: %v", index, position, err)
			}
			nonce, err := hex.DecodeString(psk.PskNonce)
			if err != nil {
				t.Fatalf("vector %d psk %d: psk_nonce is not hex: %v", index, position, err)
			}
			id := &PreSharedKeyId{PskType: PskTypeExternal, PskId: pskId, PskNonce: nonce}
			if err := id.Validate(pskCryptoWithHashSize(t, len(nonce))); err != nil {
				t.Errorf("vector %d psk %d (suite %#04x, %d octet nonce) was refused: %v",
					index, position, vector.CipherSuite, len(nonce), err)
				continue
			}
			// and the same value one octet short must not be, so the acceptance above
			// is a decision rather than a rule that says yes to everything.
			short := clonePreSharedKeyId(id)
			short.PskNonce = nonce[:len(nonce)-1]
			if err := short.Validate(pskCryptoWithHashSize(t, len(nonce))); !errors.Is(err, errPskNonceLength) {
				t.Errorf("vector %d psk %d: a nonce one octet short was accepted with err = %v", index, position, err)
			}
			lengthsSeen[len(nonce)]++
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("the psk_secret corpus yielded no pre shared key, so this test validated nothing")
	}
	if len(lengthsSeen) < 2 {
		t.Fatalf("every upstream nonce was the same length (%v), so this test cannot tell the derivation from a literal", lengthsSeen)
	}
	t.Logf("%d upstream psks accepted, nonce lengths %v", checked, lengthsSeen)
}

// ---------------------------------------------------------------------------
// ValSem402: the type and the resumption usage
// ---------------------------------------------------------------------------

// TestPreSharedKeyIdValidateUsage is ValSem402 stated the way the plan states it: only
// Resumption(Application) and External are acceptable. ReInit and Branch usages belong to
// features v1 does not implement, and accepting one here would let them in through the key
// schedule.
func TestPreSharedKeyIdValidateUsage(t *testing.T) {
	crypto := pskTestCrypto(t)
	for _, usage := range []ResumptionPskUsage{ResumptionPskUsageReInit, ResumptionPskUsageBranch} {
		id := &PreSharedKeyId{
			PskType:    PskTypeResumption,
			Usage:      usage,
			PskGroupId: []byte{1},
			PskNonce:   make([]byte, 32),
		}
		if err := id.Validate(crypto); !errors.Is(err, errPskType) {
			t.Fatalf("usage %d err = %v, want the ValSem402 refusal", usage, err)
		}
	}
	ok := &PreSharedKeyId{
		PskType:    PskTypeResumption,
		Usage:      ResumptionPskUsageApplication,
		PskGroupId: []byte{1},
		PskNonce:   make([]byte, 32),
	}
	if err := ok.Validate(crypto); err != nil {
		t.Fatalf("Resumption(Application) was refused: %v", err)
	}
}

// TestPreSharedKeyIdValidateAcceptsOnlyApplicationOfEveryResumptionUsage is the derived
// form of the rule above, over the whole octet range rather than over the two values the
// RFC happens to have named. A usage the registry gains later, or one a peer invents, is
// judged here on the commit it appears rather than on the commit somebody widens a list.
//
// The registry read is checked for the three RFC values first, so the sweep cannot pass by
// having derived nothing.
func TestPreSharedKeyIdValidateAcceptsOnlyApplicationOfEveryResumptionUsage(t *testing.T) {
	derived := registryConstantsOfType(t, "ResumptionPskUsage")
	for name, want := range map[string]uint64{
		"ResumptionPskUsageApplication": 1,
		"ResumptionPskUsageReInit":      2,
		"ResumptionPskUsageBranch":      3,
	} {
		if got, ok := derived[name]; !ok || got != want {
			t.Fatalf("the derivation read %s = %d (present %v), want %d", name, got, ok, want)
		}
	}
	crypto := pskTestCrypto(t)
	accepted, refused := 0, 0
	for value := 0; value <= 0xff; value++ {
		id := &PreSharedKeyId{
			PskType:    PskTypeResumption,
			Usage:      ResumptionPskUsage(value),
			PskGroupId: []byte{1},
			PskNonce:   make([]byte, crypto.HashSize()),
		}
		err := id.Validate(crypto)
		if ResumptionPskUsage(value) == ResumptionPskUsageApplication {
			if err != nil {
				t.Errorf("usage %#02x is Application and was refused: %v", value, err)
				continue
			}
			accepted++
			continue
		}
		if !errors.Is(err, errPskType) {
			t.Errorf("usage %#02x was accepted with err = %v, want the ValSem402 refusal", value, err)
			continue
		}
		refused++
	}
	if accepted != 1 {
		t.Fatalf("%d of the 256 usage octets were accepted, want exactly Application", accepted)
	}
	if refused != 0xff {
		t.Fatalf("%d of the 255 non-Application usage octets were refused", refused)
	}
	// the derived registry members that are not Application are the named half of the
	// class the sweep above covers; naming them is what makes a failure readable.
	for name, value := range derived {
		if ResumptionPskUsage(value) == ResumptionPskUsageApplication {
			continue
		}
		t.Logf("%s (%d) is refused by ValSem402, as the v1 profile requires", name, value)
	}
}

// TestPreSharedKeyIdValidateRefusesEveryUnregisteredPskType asserts the type half of
// ValSem402 over the complement of the derived registry. The nonce is correct in every
// case, so a Validate that never reached the type switch would accept all 254 of them.
func TestPreSharedKeyIdValidateRefusesEveryUnregisteredPskType(t *testing.T) {
	registered := registeredPskTypes(t)
	crypto := pskTestCrypto(t)
	refused, known := 0, 0
	for value := 0; value <= 0xff; value++ {
		id := &PreSharedKeyId{
			PskType:    PskType(value),
			PskId:      []byte{1},
			Usage:      ResumptionPskUsageApplication,
			PskGroupId: []byte{1},
			PskNonce:   make([]byte, crypto.HashSize()),
		}
		err := id.Validate(crypto)
		if registered[uint64(value)] {
			if err != nil {
				t.Errorf("psktype %#02x is registered and Validate refused it: %v", value, err)
				continue
			}
			known++
			continue
		}
		if !errors.Is(err, errPskType) {
			t.Errorf("psktype %#02x was accepted with err = %v, want the ValSem402 refusal", value, err)
			continue
		}
		refused++
	}
	if known == 0 {
		t.Fatal("no registered psktype was accepted, so the control half of this sweep evaluated nothing")
	}
	if refused != 0x100-known {
		t.Fatalf("%d of the %d unregistered psktypes were refused by Validate", refused, 0x100-known)
	}
}

// TestPreSharedKeyIdValidateIgnoresTheUsageFieldOnTheExternalArm asserts what the union
// implies: usage is not part of the external arm, so its value cannot make an external id
// invalid. A rule that read the field regardless would refuse ids that are perfectly well
// formed on the wire, since the octet never travelled and whatever the struct holds there
// came from the caller rather than from a peer.
func TestPreSharedKeyIdValidateIgnoresTheUsageFieldOnTheExternalArm(t *testing.T) {
	crypto := pskTestCrypto(t)
	for value := 0; value <= 0xff; value++ {
		id := &PreSharedKeyId{
			PskType:  PskTypeExternal,
			PskId:    []byte{1},
			Usage:    ResumptionPskUsage(value),
			PskNonce: make([]byte, crypto.HashSize()),
		}
		if err := id.Validate(crypto); err != nil {
			t.Fatalf("an external id with usage %#02x was refused: %v", value, err)
		}
	}
}

// TestPreSharedKeyIdTheTwoRefusalsAreDistinguishable asserts ValSem401 and ValSem402 do not
// answer to each other under errors.Is.
//
// This is the property that makes both of the tests above mean anything. Two refusals
// carrying one sentinel would make a nonce length failure indistinguishable from a usage
// failure at every call site that branches on them, and every assertion in this file that
// asks for one would be answered yes by the other — which is exactly how a sweep that
// checks nothing reports green.
func TestPreSharedKeyIdTheTwoRefusalsAreDistinguishable(t *testing.T) {
	crypto := pskTestCrypto(t)
	nonceFailure := (&PreSharedKeyId{
		PskType:  PskTypeExternal,
		PskId:    []byte{1},
		PskNonce: make([]byte, crypto.HashSize()-1),
	}).Validate(crypto)
	usageFailure := (&PreSharedKeyId{
		PskType:    PskTypeResumption,
		Usage:      ResumptionPskUsageReInit,
		PskGroupId: []byte{1},
		PskNonce:   make([]byte, crypto.HashSize()),
	}).Validate(crypto)

	if nonceFailure == nil || usageFailure == nil {
		t.Fatalf("one of the two refusals did not fire: nonce %v, usage %v", nonceFailure, usageFailure)
	}
	if errors.Is(nonceFailure, errPskType) {
		t.Error("the ValSem401 refusal also answers to the ValSem402 sentinel")
	}
	if errors.Is(usageFailure, errPskNonceLength) {
		t.Error("the ValSem402 refusal also answers to the ValSem401 sentinel")
	}
	if errors.Is(errPskNonceLength, errPskType) || errors.Is(errPskType, errPskNonceLength) {
		t.Error("the two sentinels alias each other, so no test in this file can tell them apart")
	}
	if errPskNonceLength.Error() == errPskType.Error() {
		t.Error("the two sentinels carry the same message, so a log cannot tell them apart")
	}
}

// TestPreSharedKeyIdValidateReportsTheNonceBeforeTheType pins which refusal a caller sees
// when an id violates both rules. It is an ordering claim rather than a correctness one,
// and it is here because the answer has to be deterministic: the validation plan reports a
// ValSem code to the caller and to the interop report, and a rule order that drifted would
// move a vector from one code's coverage row to another's without any test failing.
func TestPreSharedKeyIdValidateReportsTheNonceBeforeTheType(t *testing.T) {
	crypto := pskTestCrypto(t)
	both := &PreSharedKeyId{
		PskType:  PskType(0x7f),
		PskNonce: make([]byte, crypto.HashSize()-1),
	}
	err := both.Validate(crypto)
	if !errors.Is(err, errPskNonceLength) {
		t.Fatalf("an id with a short nonce and an unregistered type reported %v, want the ValSem401 refusal", err)
	}
	if errors.Is(err, errPskType) {
		t.Fatal("the refusal answers to both sentinels, so the order it reports is not observable")
	}
}
