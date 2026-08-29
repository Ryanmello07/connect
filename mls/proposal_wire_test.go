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
