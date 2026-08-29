// The proposal wire codecs, and the two things about them that are not round trips.
//
// The arm check is derived off the struct rather than driven from a list of the arms somebody
// remembered, because the failure it prevents is a NEW arm added with no line in the count: the
// proposal encodes, the new arm is dropped on the floor, and the ProposalRef over it is the
// reference of a proposal that says something else.
//
// The other is the key package stand-in guard. This file is the reason mls/key_package.go
// exists ahead of the plan that owns it, so this is where the notice that says so is held to
// still being true.
package mls

import (
	"bytes"
	"errors"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

func TestProposalTypeIsSixteenBitsOnTheWire(t *testing.T) {
	proposal := Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 3}}
	encoded, err := syntax.Marshal(&proposal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x03}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded %x, want %x -- ProposalType must be uint16", encoded, want)
	}
}

func TestProposalRoundTripRemove(t *testing.T) {
	proposal := Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 7}}
	encoded, err := syntax.Marshal(&proposal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	decoded := Proposal{}
	if err := syntax.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Remove == nil || decoded.Remove.Removed != 7 {
		t.Fatalf("decoded %+v", decoded.Remove)
	}
	reencoded, err := syntax.Marshal(&decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
	}
}

// The codec is not the profile gate. (*Profile).CheckProposalType refuses psk, reinit and
// external_init under the v1 profile; the codec must round trip all three or the `messages`
// vector family, which carries every registered type, fails for a reason that is a policy.
func TestProposalCodecAcceptsProfileRefusedTypes(t *testing.T) {
	proposal := Proposal{
		ProposalType: ProposalTypeExternalInit,
		ExternalInit: &ExternalInit{KemOutput: []byte{0x01, 0x02, 0x03}},
	}
	encoded, err := syntax.Marshal(&proposal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded := Proposal{}
	if err := syntax.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.ExternalInit == nil || !bytes.Equal(decoded.ExternalInit.KemOutput, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("decoded %+v", decoded.ExternalInit)
	}
}

// GREASE: parsed and ignored, never generated.
func TestProposalPreservesUnknownTypeVerbatim(t *testing.T) {
	encoded := []byte{0x0a, 0x0a, 0xde, 0xad, 0xbe, 0xef}
	decoded := Proposal{}
	if err := syntax.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.ProposalType != ProposalType(0x0a0a) {
		t.Fatalf("proposal type %04x", decoded.ProposalType)
	}
	if decoded.UnknownType != ProposalType(0x0a0a) {
		t.Fatalf("unknown type %04x", decoded.UnknownType)
	}
	if !bytes.Equal(decoded.UnknownBody, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("unknown body %x", decoded.UnknownBody)
	}
	reencoded, err := syntax.Marshal(&decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
	}
}

// The forge's malformed arm: a registered body under an unregistered discriminant, which is what
// the validation plan's ValSem tests need and what stops a second encoder being written to
// produce it.
func TestProposalUnknownTypeOverridesTheDiscriminant(t *testing.T) {
	proposal := Proposal{
		ProposalType: ProposalTypeRemove,
		Remove:       &Remove{Removed: 3},
		UnknownType:  ProposalType(0x0a0a),
	}
	encoded, err := syntax.Marshal(&proposal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []byte{0x0a, 0x0a, 0x00, 0x00, 0x00, 0x03}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded %x, want %x", encoded, want)
	}
}

func TestProposalRejectsArmMismatch(t *testing.T) {
	proposal := Proposal{ProposalType: ProposalTypeRemove}
	if _, err := syntax.Marshal(&proposal); !errors.Is(err, ErrContentArmMismatch) {
		t.Fatalf("got %v, want ErrContentArmMismatch", err)
	}
}

// proposalArmFields is every field of Proposal that carries a BODY, derived off the type.
//
// The derivation is "a field that can hold something" -- a pointer or a slice -- and not a list
// of the seven arms plus UnknownBody, for the reason this project keeps rediscovering: a list
// written today understates the class the day somebody adds to it, and the way a dropped arm
// fails is silent. The two discriminants are ProposalType values and are excluded by the same
// reading rather than by name, so a discriminant renamed does not fall into the class and an
// eighth arm added does.
func proposalArmFields(t *testing.T) []string {
	t.Helper()
	proposal := reflect.TypeOf(Proposal{})
	found := []string{}
	for i := 0; i < proposal.NumField(); i += 1 {
		field := proposal.Field(i)
		switch field.Type.Kind() {
		case reflect.Pointer, reflect.Slice:
			found = append(found, field.Name)
		}
	}
	if len(found) < 2 {
		t.Fatalf("the derivation read %v out of Proposal, which is fewer arms than the type has, so the gate below would run over almost nothing", found)
	}
	slices.Sort(found)
	return found
}

// TestEveryArmOfAProposalIsCountedByItsArmCheck holds checkArm's hand written count to the type
// it is counting.
//
// The count is eight lines of source and the class it stands for is derived here, so an eighth
// arm added to Proposal with no line beside it fails on the commit that adds it. What that
// failure prevents is not a compile error and not a bad encoding: a proposal carrying two arms
// encodes as ONE of them, so two distinct Proposal values serialize identically and therefore
// carry the SAME ProposalRef -- and a reference two different proposals share is a commit that
// applies a change its proposer did not publish.
func TestEveryArmOfAProposalIsCountedByItsArmCheck(t *testing.T) {
	base := func() Proposal {
		return Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 4}}
	}
	// the control: the base itself must encode, or every refusal below is a refusal of
	// something this test broke rather than of the second arm it added
	valid := base()
	if _, err := syntax.Marshal(&valid); err != nil {
		t.Fatalf("the one armed base proposal did not encode: %v", err)
	}
	refused := 0
	for _, name := range proposalArmFields(t) {
		if name == "Remove" {
			continue
		}
		second := base()
		field := reflect.ValueOf(&second).Elem().FieldByName(name)
		switch field.Kind() {
		case reflect.Pointer:
			field.Set(reflect.New(field.Type().Elem()))
		case reflect.Slice:
			field.Set(reflect.ValueOf([]byte{0x00}).Convert(field.Type()))
		default:
			t.Fatalf("%s came out of the derivation and is neither a pointer nor a slice", name)
		}
		if _, err := syntax.Marshal(&second); !errors.Is(err, ErrContentArmMismatch) {
			t.Errorf("a proposal carrying Remove and %s encoded with %v, and the %s it carries is nowhere in those bytes; the two values share one encoding and therefore one ProposalRef",
				name, err, name)
			continue
		}
		refused += 1
	}
	if refused == 0 {
		t.Fatal("no second arm was refused, so this gate observed nothing")
	}
	t.Logf("%d second arms refused, derived off the fields of Proposal", refused)
}

func TestProposalOrRefRoundTrip(t *testing.T) {
	cases := []ProposalOrRef{
		{Type: ProposalOrRefTypeProposal, Proposal: &Proposal{
			ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}},
		{Type: ProposalOrRefTypeReference, Reference: ProposalRef{0xaa, 0xbb, 0xcc}},
	}
	for i := range cases {
		encoded, err := syntax.Marshal(&cases[i])
		if err != nil {
			t.Fatalf("case %d: marshal: %v", i, err)
		}
		decoded := ProposalOrRef{}
		if err := syntax.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("case %d: unmarshal: %v", i, err)
		}
		reencoded, err := syntax.Marshal(&decoded)
		if err != nil {
			t.Fatalf("case %d: re-marshal: %v", i, err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatalf("case %d: re-encoded %x, want %x", i, reencoded, encoded)
		}
	}
}

func TestProposalOrRefRejectsReservedType(t *testing.T) {
	decoded := ProposalOrRef{}
	err := syntax.Unmarshal([]byte{0x00}, &decoded)
	if !errors.Is(err, ErrUnknownProposalOrRefType) {
		t.Fatalf("got %v, want ErrUnknownProposalOrRefType", err)
	}
}

// An empty reference is wire legal and is the encoding of "no reference", so a commit carrying
// one names a proposal that cannot be looked up -- and names it identically to every other
// commit that made the same mistake, which is worse than naming nothing.
func TestProposalOrRefRefusesAnEmptyReference(t *testing.T) {
	empty := ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: ProposalRef{}}
	if _, err := syntax.Marshal(&empty); !errors.Is(err, ErrContentArmMismatch) {
		t.Fatalf("got %v, want ErrContentArmMismatch", err)
	}
	// and the decoder agrees with the encoder about it, so what one refuses to write the
	// other refuses to read
	decoded := ProposalOrRef{}
	if err := syntax.Unmarshal([]byte{0x02, 0x00}, &decoded); err == nil {
		t.Fatalf("a reference of no octets decoded to %+v", decoded)
	}
}

// TestTheKeyPackageStandInDoesNotOutliveItsOwnersLanding is the self-deleting half of the notice
// at the top of mls/key_package.go.
//
// That file is the TreeKEM plan's task 7A and it is here early and INCOMPLETE, because the Add
// arm above carries a KeyPackage by value and package mls is one package. The notice says so and
// says that task 7A fills the file in rather than creating it. A notice describing a file it no
// longer describes is worse than none -- the next reader believes it -- so the moment anything
// beyond the codec lands in that file, this fails and asks for the notice to go.
//
// What counts as "the rest has landed" is DERIVED: every package level declaration of
// key_package.go that is not one of the four the stand-in declares. NewKeyPackage, Ref and
// Validate all trip it, and so does whatever else task 7A brings, without this test having to
// name them.
func TestTheKeyPackageStandInDoesNotOutliveItsOwnersLanding(t *testing.T) {
	const file = "key_package.go"
	const notice = "task 7A does not create this file, it FILLS IT IN"
	standIn := []string{"KeyPackage", "KeyPackage.marshalCore", "KeyPackage.MarshalMLS", "KeyPackage.UnmarshalMLS"}

	declared := packageLevelDeclarations(t, ".")
	for _, name := range standIn {
		if declared[name] != file {
			t.Fatalf("%s is declared in %q and this guard expects it in %s; the stand-in has been renamed or moved and this gate is reading the wrong file",
				name, declared[name], file)
		}
	}
	source, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	landed := []string{}
	for name, at := range declared {
		if at != file || slices.Contains(standIn, name) {
			continue
		}
		landed = append(landed, name)
	}
	slices.Sort(landed)
	if len(landed) > 0 {
		if strings.Contains(string(source), notice) {
			t.Errorf("%s now declares %v beyond the codec stand-in, so task 7A has landed and the notice saying it has not is still at the top of the file",
				file, landed)
		}
		return
	}
	if !strings.Contains(string(source), notice) {
		t.Fatalf("%s declares only the codec stand-in and no longer carries the notice saying whose file it is and what is missing from it",
			file)
	}
}

// TestKeyPackageOpensWithItsVersionAndThenItsCiphersuite is the field-order statement the codec
// stand-in owes, and it is here rather than in the file it is about because that file is another
// plan's and is filled in rather than created.
//
// Version and CipherSuite are ADJACENT uint16s. An encoder that writes them the other way round
// round trips its own output perfectly, produces a key package of exactly the right length, and
// disagrees with every other implementation -- which arrives as a joiner nobody can add, at the
// first Welcome shared with anybody. A round trip cannot see it and nothing else in this package
// was looking: the two fields swapped survived the whole of mls and message green, measured.
//
// The golden is derived from RFC 9420 section 10 rather than read back through the encoder: the
// version, the ciphersuite, then init_key as an opaque<V>. Only the prefix is written out, because
// what follows is a LeafNode whose own golden leaf_node_test.go already holds.
func TestKeyPackageOpensWithItsVersionAndThenItsCiphersuite(t *testing.T) {
	keyPackage := KeyPackage{
		Version:     ProtocolVersionMls10,
		CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
		InitKey:     HpkePublicKey{0xaa, 0xbb},
		LeafNode:    *testLeafNodeOfSource(LeafNodeSourceKeyPackage),
		Signature:   []byte{0xcc},
	}
	encoded, err := syntax.Marshal(&keyPackage)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []byte{
		0x00, 0x01, // version: mls10
		0x00, 0x03, // cipher_suite: X25519/ChaCha20/SHA-256/Ed25519
		0x02, 0xaa, 0xbb, // init_key<V>
	}
	if !bytes.HasPrefix(encoded, want) {
		t.Fatalf("a key package opens with %x, and RFC 9420 section 10 writes %x -- version, then cipher_suite, then init_key",
			encoded[:min(len(encoded), len(want))], want)
	}

	decoded := KeyPackage{}
	if err := syntax.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Version != keyPackage.Version || decoded.CipherSuite != keyPackage.CipherSuite {
		t.Fatalf("decoded version %d suite %d, want %d and %d",
			decoded.Version, decoded.CipherSuite, keyPackage.Version, keyPackage.CipherSuite)
	}
	reencoded, err := syntax.Marshal(&decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
	}
}

// ---------------------------------------------------------------------------
// the layout RFC 9420 section 12.1 gives each registered arm
// ---------------------------------------------------------------------------

// proposalArmSample is one registered proposal arm: the field of Proposal it populates, a value
// carrying exactly that arm, and the octets section 12.1 writes it as.
type proposalArmSample struct {
	field    string
	proposal Proposal
	golden   []byte
}

// proposalArmDelegated is the encoding of a structure a proposal arm hands over to WHOLE.
//
// It is the one part of a golden below that is not written out octet by octet, and what it
// claims is a delegation and an offset rather than a layout: an Add carries a KeyPackage exactly
// as key_package.go writes one, beginning at the octet after the discriminant, with nothing of
// this file's own wrapped around it. Those structures' layouts are held by their own goldens --
// TestKeyPackageOpensWithItsVersionAndThenItsCiphersuite above, leaf_node_test.go's hand derived
// forms, psk_test.go's -- and transcribing them again here would be a second opinion that agrees
// with whichever of the two was written later.
func proposalArmDelegated(t *testing.T, codec syntax.Codec) []byte {
	t.Helper()
	encoded, err := syntax.Marshal(codec)
	if err != nil {
		t.Fatalf("encode the structure a proposal arm delegates to: %v", err)
	}
	return encoded
}

// proposalArmSamples is one Proposal per registered arm together with the octets RFC 9420
// section 12.1 writes it as.
//
// The goldens are derived from the RFC and stated here rather than read back through the encoder
// under test, and that is the whole point of the gate below. Five of the seven registered arms
// were never encoded AND decoded by anything in this package: ReInit's Version and CipherSuite,
// two ADJACENT uint16s, could be swapped on BOTH the encode and the decode side -- a layout that
// round trips its own output perfectly, produces a proposal of exactly the right length, and
// disagrees with every other implementation in the world -- and the whole of ./mls/... and
// ./message/... stayed green. Measured, not supposed.
//
// It is the same defect KeyPackage's adjacent Version and CipherSuite carried, and the reason it
// is answered here as a TABLE over the derived arm set rather than as a second one-off test is
// that a one-off test is what the first one was. A ProposalRef is a hash of the whole encoding,
// so two implementations disagreeing about any arm's layout compute different references for one
// proposal -- the "stable, self consistent and wrong" fork framing_preimage.go's own comment says
// the reference exists to prevent.
func proposalArmSamples(t *testing.T) map[ProposalType]proposalArmSample {
	t.Helper()
	// one extensions<V> for the two arms that carry one, and the octets RFC 9420 section 6.3.1
	// writes it as. The vector prefix counts BYTES and not entries, which is the single easiest
	// thing in this encoding to get wrong and the thing a round trip cannot see.
	extensions := []Extension{{ExtensionType: ExtensionTypeApplicationId, ExtensionData: []byte{0x42}}}
	extensionOctets := []byte{
		0x04,       // extensions<V>: four octets of entries follow
		0x00, 0x01, // extension_type: application_id
		0x01, 0x42, // extension_data<V>
	}
	keyPackage := KeyPackage{
		Version:     ProtocolVersionMls10,
		CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
		InitKey:     HpkePublicKey{0xaa, 0xbb},
		LeafNode:    *testLeafNodeOfSource(LeafNodeSourceKeyPackage),
		Signature:   []byte{0xcc},
	}
	leafNode := *testLeafNodeOfSource(LeafNodeSourceUpdate)
	psk := PreSharedKeyId{PskType: PskTypeExternal, PskId: []byte{0x51, 0x52}, PskNonce: []byte{0x61}}
	return map[ProposalType]proposalArmSample{
		ProposalTypeAdd: {
			field:    "Add",
			proposal: Proposal{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: keyPackage}},
			golden:   append([]byte{0x00, 0x01}, proposalArmDelegated(t, &keyPackage)...),
		},
		ProposalTypeUpdate: {
			field:    "Update",
			proposal: Proposal{ProposalType: ProposalTypeUpdate, Update: &Update{LeafNode: leafNode}},
			golden:   append([]byte{0x00, 0x02}, proposalArmDelegated(t, &leafNode)...),
		},
		ProposalTypeRemove: {
			field:    "Remove",
			proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 7}},
			golden: []byte{
				0x00, 0x03, // proposal_type: remove
				0x00, 0x00, 0x00, 0x07, // removed: uint32, and not the leaf index's own width
			},
		},
		ProposalTypePreSharedKey: {
			field:    "PreSharedKey",
			proposal: Proposal{ProposalType: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKey{Psk: psk}},
			golden:   append([]byte{0x00, 0x04}, proposalArmDelegated(t, &psk)...),
		},
		ProposalTypeReInit: {
			field: "ReInit",
			proposal: Proposal{ProposalType: ProposalTypeReInit, ReInit: &ReInit{
				GroupId:     []byte{0x9a, 0x9b, 0x9c},
				Version:     ProtocolVersionMls10,
				CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
				Extensions:  extensions,
			}},
			// section 12.1.5: group_id<V>, then version, then cipher_suite, then extensions.
			// The two uint16s are the pair this whole table exists for -- mls10 is 0x0001 and
			// the suite is 0x0003, chosen to differ, because a version and a ciphersuite that
			// happened to be equal would let the swap through.
			golden: joinBytes(
				[]byte{0x00, 0x05},
				[]byte{0x03, 0x9a, 0x9b, 0x9c},
				[]byte{0x00, 0x01},
				[]byte{0x00, 0x03},
				extensionOctets,
			),
		},
		ProposalTypeExternalInit: {
			field: "ExternalInit",
			proposal: Proposal{ProposalType: ProposalTypeExternalInit,
				ExternalInit: &ExternalInit{KemOutput: []byte{0x01, 0x02, 0x03}}},
			golden: []byte{
				0x00, 0x06, // proposal_type: external_init
				0x03, 0x01, 0x02, 0x03, // kem_output<V>
			},
		},
		ProposalTypeGroupContextExtensions: {
			field: "GroupContextExtensions",
			proposal: Proposal{ProposalType: ProposalTypeGroupContextExtensions,
				GroupContextExtensions: &GroupContextExtensions{Extensions: extensions}},
			golden: append([]byte{0x00, 0x07}, extensionOctets...),
		},
	}
}

// TestEveryRegisteredProposalArmEncodesToTheLayoutSection121Writes holds every arm of this
// codec to the RFC, in both directions, over a class derived twice.
//
// The table is joined to the ProposalType registry AND to the arm fields of the struct, so an
// eighth arm added to Proposal, or an eighth code point registered in extension.go, fails here
// on the commit that lands it rather than shipping as an arm nothing ever encoded. Before this
// gate only two of the seven were ever both encoded and decoded, and TestProposalCodecAccepts-
// ProfileRefusedTypes -- the one test that reaches past Remove -- covers ExternalInit alone.
//
// The re-encode is not redundant with the encode. A swap present on both sides of the codec is
// caught by the first comparison; a swap present on the DECODE side only round trips nothing and
// is caught by the second; and an arm the decoder drops on the floor is caught by the arm check
// between them.
func TestEveryRegisteredProposalArmEncodesToTheLayoutSection121Writes(t *testing.T) {
	samples := proposalArmSamples(t)
	covered := slices.Sorted(maps.Keys(samples))

	// the code point join. The reserved zero is excluded by its VALUE and not by its name: it is
	// not an arm, because checkArm's default clause treats it as an unregistered type whose body
	// is carried verbatim, which is the GREASE path and not a layout.
	declared := []ProposalType{}
	for _, value := range registryConstantsOfType(t, "ProposalType") {
		if value == uint64(ProposalTypeReserved) {
			continue
		}
		declared = append(declared, ProposalType(value))
	}
	slices.Sort(declared)
	if !slices.Equal(declared, covered) {
		t.Fatalf("package mls registers the proposal types %v and this table lays out %v; an arm with no golden is an arm no test has ever encoded and decoded, and its layout is whatever the encoder happens to do",
			declared, covered)
	}

	// the arm join, off the same derivation TestEveryArmOfAProposalIsCountedByItsArmCheck uses.
	// UnknownBody is excluded because it is not a registered arm: it is the verbatim body an
	// unregistered type carries, and it has no layout of its own to be wrong about.
	arms := []string{}
	for _, name := range proposalArmFields(t) {
		if name == "UnknownBody" {
			continue
		}
		arms = append(arms, name)
	}
	laid := []string{}
	for _, proposalType := range covered {
		laid = append(laid, samples[proposalType].field)
	}
	slices.Sort(laid)
	if !slices.Equal(arms, laid) {
		t.Fatalf("Proposal carries the arms %v and this table populates %v; the two derivations disagree, so one of them has stopped describing the type",
			arms, laid)
	}

	for _, proposalType := range covered {
		sample := samples[proposalType]
		// the row is what it says it is, before anything is read off it
		field := reflect.ValueOf(sample.proposal).FieldByName(sample.field)
		if !field.IsValid() || field.IsNil() {
			t.Fatalf("the %s row does not populate the arm it names, so whatever it encodes to is not that arm", sample.field)
		}
		encoded, err := syntax.Marshal(&sample.proposal)
		if err != nil {
			t.Errorf("%s: marshal: %v", sample.field, err)
			continue
		}
		if !bytes.Equal(encoded, sample.golden) {
			t.Errorf("a %s proposal encodes to %x and RFC 9420 section 12.1 writes %x; a layout that disagrees with the RFC and agrees with itself produces a different ProposalRef for the same proposal, so every peer computes a name for it that this one does not",
				sample.field, encoded, sample.golden)
			continue
		}
		decoded := Proposal{}
		if err := syntax.Unmarshal(sample.golden, &decoded); err != nil {
			t.Errorf("%s: the published layout did not decode: %v", sample.field, err)
			continue
		}
		if decoded.ProposalType != proposalType {
			t.Errorf("%s: the layout decoded as proposal type %04x, want %04x", sample.field, decoded.ProposalType, proposalType)
			continue
		}
		if decodedArm := reflect.ValueOf(decoded).FieldByName(sample.field); !decodedArm.IsValid() || decodedArm.IsNil() {
			t.Errorf("%s: the layout decoded with that arm empty, so the decoder read the discriminant and dropped the body", sample.field)
			continue
		}
		reencoded, err := syntax.Marshal(&decoded)
		if err != nil {
			t.Errorf("%s: re-marshal: %v", sample.field, err)
			continue
		}
		if !bytes.Equal(reencoded, sample.golden) {
			t.Errorf("a %s proposal decoded from %x re-encodes to %x; the two halves of this codec disagree about that arm's layout, which is the one shape a round trip over the encoder's own output cannot see",
				sample.field, sample.golden, reencoded)
		}
	}
	t.Logf("%d registered proposal arms, each encoded to and decoded from the layout section 12.1 gives it", len(covered))
}
