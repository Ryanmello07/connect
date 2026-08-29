// Unit tests for framing.go and framing_errors.go: the three RFC 9420 section 6 framing
// registries, the Sender codec, and the structural refusals this layer declares.
package mls

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ---------------------------------------------------------------------------
// the widths the wire format gives the three registries
// ---------------------------------------------------------------------------

// The upper half of each width, as a compile time statement. ^T(0) is a typed constant equal
// to the type's own maximum, so converting it to the octet or the pair of octets the wire
// format gives that registry is exactly the sentence "this type is no wider than that", and a
// widened type stops COMPILING here rather than failing a test somewhere else.
//
// A conversion of a literal in the other direction -- SenderType(0xff) -- would say only that
// 255 FITS, which rules out a signed octet and nothing else; it compiles unchanged at uint16
// and at every wider type. That is measured on this project rather than supposed: ContentType
// widened to uint16 built clean and failed exactly one test in this package.
const (
	_ = uint8(^ContentType(0))
	_ = uint8(^SenderType(0))
	_ = uint16(^WireFormat(0))
)

// TestTheFramingRegistriesAreTheWidthsTheWireFormatGivesThem is the lower half, which the
// conversions above cannot give: they hold that the type is no WIDER, and this holds that it is
// no narrower. A registry read at fewer octets than the encoding writes moves every field after
// it in the message.
func TestTheFramingRegistriesAreTheWidthsTheWireFormatGivesThem(t *testing.T) {
	for _, one := range []struct {
		name       string
		codePoints int
		want       int
	}{
		{"ContentType", int(^ContentType(0)) + 1, 256},
		{"SenderType", int(^SenderType(0)) + 1, 256},
		{"WireFormat", int(^WireFormat(0)) + 1, 65536},
	} {
		if one.codePoints != one.want {
			t.Errorf("%s holds %d code points and RFC 9420 section 6 gives it %d",
				one.name, one.codePoints, one.want)
		}
	}
}

// ---------------------------------------------------------------------------
// the framing registries, joined to the RFC by name and out of two readings
// ---------------------------------------------------------------------------

// rfc9420FramingCodePoints is what RFC 9420 assigns the three framing registries, keyed by the
// RFC's OWN name for each code point rather than by the Go identifier that carries it:
// WireFormat out of the section 17 IANA "MLS Wire Formats" registry, ContentType and SenderType
// out of the enum bodies section 6 writes beside FramedContent and Sender.
//
// Keyed by the RFC's name because the join below is BY NAME, and that is the whole of what
// makes this more than a restatement of framing.go. A table keyed by Go identifier can only
// ever agree with whatever the person who wrote the constants believed. This project has the
// receipt: ExtensionTypeExternalSenders shipped at external_pub's 0x0004, and the pin written
// to catch exactly that -- transcribed by the same person out of the same RFC section --
// agreed with the same misreading and passed.
var rfc9420FramingCodePoints = map[string]map[string]uint64{
	"WireFormat": {
		"mls_public_message":  0x0001,
		"mls_private_message": 0x0002,
		"mls_welcome":         0x0003,
		"mls_group_info":      0x0004,
		"mls_key_package":     0x0005,
	},
	"ContentType": {
		"application": 1,
		"proposal":    2,
		"commit":      3,
	},
	"SenderType": {
		"member":              1,
		"external":            2,
		"new_member_proposal": 3,
		"new_member_commit":   4,
	},
}

// rfc9420FramingRegistryPrefix is the prefix the RFC's spelling carries that the Go name does
// not. The wire format registry writes mls_public_message; this package writes
// WireFormatPublicMessage, because the type name already says which protocol it belongs to.
// Stated as data, once, rather than folded into each table entry, so the correspondence is one
// claim that can be read rather than five that can disagree.
var rfc9420FramingRegistryPrefix = map[string]string{"WireFormat": "mls_"}

// rfcNameOfFramingConstant is rfcNameOfRegistryConstant plus that prefix.
func rfcNameOfFramingConstant(typeName string, constantName string) string {
	return rfc9420FramingRegistryPrefix[typeName] + rfcNameOfRegistryConstant(typeName, constantName)
}

// TestEveryFramingRegistryHoldsTheCodePointsRfc9420Assigns joins this package's declared
// constants to the RFC's table by NAME, in both directions at once.
//
// Both directions matter and neither implies the other. A table richer than the source names a
// code point nothing declares; a source richer than the table is a constant no gate checks,
// which is how a swapped pair survives -- and a swapped pair is not a type error, is not a
// round trip failure, and is byte exact against any corpus this implementation produced.
func TestEveryFramingRegistryHoldsTheCodePointsRfc9420Assigns(t *testing.T) {
	for _, typeName := range slices.Sorted(maps.Keys(rfc9420FramingCodePoints)) {
		derived := registryConstantsOfType(t, typeName)
		byRfcName := map[string]uint64{}
		for _, name := range slices.Sorted(maps.Keys(derived)) {
			rfcName := rfcNameOfFramingConstant(typeName, name)
			if _, clash := byRfcName[rfcName]; clash {
				t.Fatalf("two constants of %s spell the RFC name %s, so the join below cannot tell them apart",
					typeName, rfcName)
			}
			byRfcName[rfcName] = derived[name]
		}
		if want := rfc9420FramingCodePoints[typeName]; !maps.Equal(byRfcName, want) {
			t.Errorf("%s declares\n %v\nand RFC 9420 assigns\n %v", typeName, byRfcName, want)
		}
	}
}

// rfc9420SelectArmOrder is a SECOND reading of two of those registries, out of a different part
// of the RFC and carrying no numbers at all.
//
// RFC 9420 section 6.1 writes the arms of MLSMessage's select and of FramedContent's select in
// registry order, beginning at the first non-reserved code point. That is an ORDER rather than
// a table of values, so it cannot be a second transcription of the same numbers -- which is
// exactly what makes joining it to the table above worth doing. Every transposition of two code
// points in either registry fails here, including the ones no golden in this task can see
// because no codec here writes them yet.
//
// SenderType is deliberately absent, and saying so is more useful than a table that pretended
// otherwise: section 6 writes the Sender select's arms in the order member, external,
// new_member_commit, new_member_proposal, which is NOT the enum's order, so there is no
// ordering statement to join. rfc9420SenderSelectPayloads below is SenderType's second reading
// instead, and it is a weaker one -- it separates the arms that carry a uint32 from the arms
// that carry nothing, so it catches every swap ACROSS that boundary and no swap within it.
// What that leaves open is stated plainly rather than hidden: member against external, and
// new_member_proposal against new_member_commit, rest on one sentence of RFC 9420 in this
// package today, and the vendored message-protection and messages vectors are the outside
// oracle that will close them.
var rfc9420SelectArmOrder = map[string][]string{
	"WireFormat":  {"mls_public_message", "mls_private_message", "mls_welcome", "mls_group_info", "mls_key_package"},
	"ContentType": {"application", "proposal", "commit"},
}

// TestTheFramingRegistriesRunInTheOrderSection61WritesTheirArms is that join.
func TestTheFramingRegistriesRunInTheOrderSection61WritesTheirArms(t *testing.T) {
	for _, typeName := range slices.Sorted(maps.Keys(rfc9420SelectArmOrder)) {
		arms := rfc9420SelectArmOrder[typeName]
		derived := registryConstantsOfType(t, typeName)
		byRfcName := map[string]uint64{}
		for name, value := range derived {
			byRfcName[rfcNameOfFramingConstant(typeName, name)] = value
		}
		if len(byRfcName) != len(arms) {
			t.Errorf("%s declares %d code points and section 6.1 writes %d arms for it: %v against %v",
				typeName, len(byRfcName), len(arms), slices.Sorted(maps.Keys(byRfcName)), arms)
		}
		for at, arm := range arms {
			value, declared := byRfcName[arm]
			if !declared {
				t.Errorf("section 6.1 writes a %s arm for %s and this package declares no constant that spells it",
					arm, typeName)
				continue
			}
			if want := uint64(at + 1); value != want {
				t.Errorf("%s is the %s %s arm section 6.1 writes, so its code point is %d, and this package declares it at %d",
					arm, ordinalOfSelectArm(at), typeName, want, value)
			}
		}
	}
}

func ordinalOfSelectArm(at int) string {
	for ordinal, name := range []string{"first", "second", "third", "fourth", "fifth"} {
		if ordinal == at {
			return name
		}
	}
	return fmt.Sprintf("%dth", at+1)
}

// rfc9420SenderSelectPayloads is the Sender select of RFC 9420 section 6, read as the number of
// octets each arm carries AFTER the sender_type:
//
//	case member:              uint32 leaf_index      4
//	case external:            uint32 sender_index    4
//	case new_member_commit:                          0
//	case new_member_proposal:                        0
//
// Keyed by the RFC's name and joined against what this package's encoder actually emits, so a
// sender type standing at an arm's code point while carrying a different payload fails here.
var rfc9420SenderSelectPayloads = map[string]int{
	"member":              4,
	"external":            4,
	"new_member_proposal": 0,
	"new_member_commit":   0,
}

// TestEverySenderArmCarriesThePayloadSection6GivesIt measures the payload off the encoder
// rather than reading it out of framing.go, so what it states is a fact about behaviour.
func TestEverySenderArmCarriesThePayloadSection6GivesIt(t *testing.T) {
	derived := registryConstantsOfType(t, "SenderType")
	measured := map[string]int{}
	for _, name := range slices.Sorted(maps.Keys(derived)) {
		encoded, err := syntax.Marshal(testSenderOfType(SenderType(derived[name])))
		if err != nil {
			t.Fatalf("%s: Marshal: %v", name, err)
		}
		if len(encoded) < 1 {
			t.Fatalf("%s: encoded to nothing, so it wrote no discriminant", name)
		}
		if uint64(encoded[0]) != derived[name] {
			t.Errorf("%s: the encoding leads with %#02x and the constant is %#02x",
				name, encoded[0], uint8(derived[name]))
		}
		measured[rfcNameOfFramingConstant("SenderType", name)] = len(encoded) - 1
	}
	if !maps.Equal(measured, rfc9420SenderSelectPayloads) {
		t.Errorf("the Sender encoder writes payloads\n %v\nand RFC 9420 section 6's select gives\n %v",
			measured, rfc9420SenderSelectPayloads)
	}
}

// ---------------------------------------------------------------------------
// the value every golden and every sweep below is built from
// ---------------------------------------------------------------------------

// testSenderOfType is one Sender with BOTH variant fields populated, and populated
// DIFFERENTLY.
//
// Both halves of that matter. Two uint32 fields holding the same octets are encoded identically
// by a codec that wrote one of them twice and by one that swapped them, so the goldens would
// pin nothing -- and LeafIndex and SenderIndex are adjacent fields of the same width, which is
// the one shape five plans of codecs on this project have found no round trip property can see.
// Populating both under EVERY sender type is what the "encoded under the wrong arm" mutation
// needs as well: under new_member_proposal this value carries a leaf index and a sender index
// that must not appear in its encoding at all.
func testSenderOfType(senderType SenderType) *Sender {
	return &Sender{SenderType: senderType, LeafIndex: 0x11223344, SenderIndex: 0x55667788}
}

// senderTypes is the class every sweep below runs over, derived off the type through the
// package's own type checker rather than listed. A fifth sender type declared and left out of a
// hand written list is a sender type nothing here judges.
func senderTypes(t *testing.T) []SenderType {
	t.Helper()
	derived := registryConstantsOfType(t, "SenderType")
	found := []SenderType{}
	for _, value := range derived {
		found = append(found, SenderType(value))
	}
	slices.Sort(found)
	return found
}

// senderVariantPaths is the RFC 9420 section 6 select, written as the field each arm carries.
// The discriminant is not in it: it is written under every arm and belongs to none of them.
var senderVariantPaths = map[SenderType][]string{
	SenderTypeMember:            {"LeafIndex"},
	SenderTypeExternal:          {"SenderIndex"},
	SenderTypeNewMemberProposal: {},
	SenderTypeNewMemberCommit:   {},
}

// senderDiscriminantField is the one field of Sender that is not a variant arm.
const senderDiscriminantField = "SenderType"

// TestTheSenderVariantTableCoversTheTypeAndTheRegistry holds the table above to the two things
// it is a claim about: the declared sender types, and the fields Sender actually has.
//
// Without this the table is a list, and a list is the exemption shape this project keeps
// rediscovering -- a fifth sender type, or a fourth field, silently outside every sweep that
// runs off it.
func TestTheSenderVariantTableCoversTheTypeAndTheRegistry(t *testing.T) {
	declared := senderTypes(t)
	tabled := []SenderType{}
	for senderType := range senderVariantPaths {
		tabled = append(tabled, senderType)
	}
	slices.Sort(tabled)
	if !slices.Equal(declared, tabled) {
		t.Fatalf("the package declares the sender types %v and the variant table covers %v", declared, tabled)
	}
	structType := reflect.TypeOf(Sender{})
	claimed := map[string]int{}
	for _, paths := range senderVariantPaths {
		for _, path := range paths {
			claimed[path] += 1
		}
	}
	for i := 0; i < structType.NumField(); i += 1 {
		name := structType.Field(i).Name
		if name == senderDiscriminantField {
			if claimed[name] != 0 {
				t.Errorf("%s is the discriminant and the variant table lists it as an arm's payload", name)
			}
			delete(claimed, name)
			continue
		}
		switch claimed[name] {
		case 1:
		case 0:
			t.Errorf("Sender.%s is carried by no arm of the variant table, so every sweep run off that table skips it",
				name)
		default:
			t.Errorf("Sender.%s is carried by %d arms of the variant table, and the RFC's select gives each field one",
				name, claimed[name])
		}
		delete(claimed, name)
	}
	for name := range claimed {
		t.Errorf("the variant table names %s and Sender has no such field", name)
	}
}

// ---------------------------------------------------------------------------
// the hand derived goldens
// ---------------------------------------------------------------------------

// handDerivedSenderGolden is one Sender's encoding written out from RFC 9420 section 6 rather
// than read back through the encoder:
//
//	sender_type            uint8                                          1
//	select (member):       uint32 leaf_index    -> 11223344               4
//	select (external):     uint32 sender_index  -> 55667788               4
//	select (new_member_proposal), (new_member_commit):  nothing           0
//
//	member               1 + 4 = 5
//	external             1 + 4 = 5
//	new_member_proposal  1 + 0 = 1
//	new_member_commit    1 + 0 = 1
//
// This is the one test in this file that a symmetric edit cannot survive. Two adjacent
// same-width fields swapped in BOTH halves of the codec round trip perfectly, re-encode byte
// exact, and are invisible to every other property here; so is a field dropped from both
// halves. What separates them is a statement of the encoding written without reference to the
// code, which is what this is.
//
// The octet beside each case name is also what makes an enum transposition visible at the
// codec: the switch is over the CONSTANT and the literal is the RFC's number for that name, so
// two sender types whose values were swapped encode to each other's goldens and fail here.
func handDerivedSenderGolden(senderType SenderType) []byte {
	switch senderType {
	case SenderTypeMember:
		return []byte{0x01, 0x11, 0x22, 0x33, 0x44}
	case SenderTypeExternal:
		return []byte{0x02, 0x55, 0x66, 0x77, 0x88}
	case SenderTypeNewMemberProposal:
		return []byte{0x03}
	case SenderTypeNewMemberCommit:
		return []byte{0x04}
	}
	return nil
}

// handDerivedSenderSizes is the arithmetic in the comment above, stated separately so a
// derivation edited without its comment fails rather than redefining what it is compared to.
var handDerivedSenderSizes = map[SenderType]int{
	SenderTypeMember:            5,
	SenderTypeExternal:          5,
	SenderTypeNewMemberProposal: 1,
	SenderTypeNewMemberCommit:   1,
}

// decodedFormOfSender is what a decode of this sender must produce: the same value with the
// arms the sender type does not carry left at their zero. Derived from the variant table the
// test above holds to the type, so a decoder that filled a field its arm does not carry fails
// without anybody writing a case for it.
func decodedFormOfSender(t *testing.T, sender *Sender) *Sender {
	t.Helper()
	out := *sender
	value := reflect.ValueOf(&out).Elem()
	for senderType, paths := range senderVariantPaths {
		if senderType == sender.SenderType {
			continue
		}
		for _, path := range paths {
			field := value.FieldByName(path)
			if !field.IsValid() {
				t.Fatalf("the variant table names %s and Sender has no such field", path)
			}
			field.Set(reflect.Zero(field.Type()))
		}
	}
	return &out
}

func sameSender(a *Sender, b *Sender) bool {
	return reflect.DeepEqual(a, b)
}

func describeSender(sender *Sender) string {
	return fmt.Sprintf("sender_type=%d leaf_index=%#08x sender_index=%#08x",
		sender.SenderType, uint32(sender.LeafIndex), sender.SenderIndex)
}

// TestSenderMarshalMatchesTheHandDerivedGoldens is the field order and width pin.
func TestSenderMarshalMatchesTheHandDerivedGoldens(t *testing.T) {
	for _, senderType := range senderTypes(t) {
		want := handDerivedSenderGolden(senderType)
		if want == nil {
			t.Fatalf("sender type %d has no hand derived golden, so nothing states its encoding", senderType)
		}
		size, stated := handDerivedSenderSizes[senderType]
		if !stated {
			t.Fatalf("sender type %d has no hand derived size, so its derivation is compared only against itself",
				senderType)
		}
		if len(want) != size {
			t.Fatalf("sender type %d: the hand derivation is %d octets and the arithmetic in its comment says %d",
				senderType, len(want), size)
		}
		encoded, err := syntax.Marshal(testSenderOfType(senderType))
		if err != nil {
			t.Fatalf("sender type %d: Marshal: %v", senderType, err)
		}
		if !bytes.Equal(encoded, want) {
			t.Errorf("sender type %d: Marshal =\n %x\nwant\n %x", senderType, encoded, want)
		}
		decoded := &Sender{}
		if err := syntax.Unmarshal(want, decoded); err != nil {
			t.Fatalf("sender type %d: Unmarshal the golden: %v", senderType, err)
		}
		if expected := decodedFormOfSender(t, testSenderOfType(senderType)); !sameSender(decoded, expected) {
			t.Errorf("sender type %d: the golden decoded to\n %s\nwant\n %s",
				senderType, describeSender(decoded), describeSender(expected))
		}
	}
}

// TestSenderRoundTripEveryType compares the WHOLE decoded value against the original rather
// than the two fields a hand written case would have listed.
//
// The comparison is against the derived expected form and it runs over the derived class, so an
// arm added without a case is swept and a field left standing under an arm that does not carry
// it fails. The whole-value half is what a field dropped from BOTH halves of the codec needs:
// that drop re-encodes byte exact against itself and is simply lost.
func TestSenderRoundTripEveryType(t *testing.T) {
	for _, senderType := range senderTypes(t) {
		in := testSenderOfType(senderType)
		encoded, err := syntax.Marshal(in)
		if err != nil {
			t.Fatalf("sender type %d: Marshal: %v", senderType, err)
		}
		out := &Sender{}
		if err := syntax.Unmarshal(encoded, out); err != nil {
			t.Fatalf("sender type %d: Unmarshal: %v", senderType, err)
		}
		if want := decodedFormOfSender(t, testSenderOfType(senderType)); !sameSender(out, want) {
			t.Errorf("sender type %d: round trip gave\n %s\nwant\n %s",
				senderType, describeSender(out), describeSender(want))
		}
		reencoded, err := syntax.Marshal(out)
		if err != nil {
			t.Fatalf("sender type %d: re-Marshal: %v", senderType, err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Errorf("sender type %d: re-encode =\n %x\nwant\n %x", senderType, reencoded, encoded)
		}
	}
}

// TestTheSenderCodecWritesEveryFieldItsArmCarriesAndNoOther sweeps the fields off the TYPE and
// the carriage off the variant table, so neither is a list somebody kept up to date.
//
// This is the property a golden cannot state on its own: the golden says what the bytes are for
// one value, and this says that each field is what those bytes are a function of. A field
// dropped from the encoder is caught by both; a field written under an arm that does not carry
// it is caught here for every arm at once.
func TestTheSenderCodecWritesEveryFieldItsArmCarriesAndNoOther(t *testing.T) {
	structType := reflect.TypeOf(Sender{})
	observed := map[string]bool{}
	for _, senderType := range senderTypes(t) {
		base, err := syntax.Marshal(testSenderOfType(senderType))
		if err != nil {
			t.Fatalf("sender type %d: Marshal: %v", senderType, err)
		}
		for i := 0; i < structType.NumField(); i += 1 {
			name := structType.Field(i).Name
			if name == senderDiscriminantField {
				continue
			}
			varied := testSenderOfType(senderType)
			field := reflect.ValueOf(varied).Elem().Field(i)
			field.SetUint(field.Uint() ^ 0x0a0b0c0d)
			encoded, err := syntax.Marshal(varied)
			if err != nil {
				t.Fatalf("sender type %d: Marshal with %s varied: %v", senderType, name, err)
			}
			changed := !bytes.Equal(encoded, base)
			carried := slices.Contains(senderVariantPaths[senderType], name)
			if carried && !changed {
				t.Errorf("sender type %d carries %s and varying it left the encoding at %x, so nothing writes it",
					senderType, name, encoded)
			}
			if !carried && changed {
				t.Errorf("sender type %d does not carry %s and varying it changed the encoding to %x",
					senderType, name, encoded)
			}
			observed[name] = observed[name] || changed
		}
	}
	for i := 0; i < structType.NumField(); i += 1 {
		name := structType.Field(i).Name
		if name == senderDiscriminantField {
			continue
		}
		if !observed[name] {
			t.Errorf("%s changed no encoding under any declared sender type, so nothing in this package writes it",
				name)
		}
	}
	// the discriminant is covered by the goldens rather than by the sweep, and that has to be
	// true rather than assumed: every golden leads with a different octet.
	leading := map[byte]SenderType{}
	for _, senderType := range senderTypes(t) {
		golden := handDerivedSenderGolden(senderType)
		if len(golden) == 0 {
			t.Fatalf("sender type %d has no golden", senderType)
		}
		if other, clash := leading[golden[0]]; clash {
			t.Errorf("sender types %d and %d both lead with %#02x, so the discriminant is not what separates them",
				other, senderType, golden[0])
		}
		leading[golden[0]] = senderType
	}
}

// ---------------------------------------------------------------------------
// the refusals
// ---------------------------------------------------------------------------

// undeclaredSenderTypeOctets is every octet the SenderType registry does not name, derived over
// the width of the type against the declared set rather than over the three values a hand
// written case would have probed. The reserved zero is one of them and is not special: it is
// undeclared, and so is 0x05, and so is 0xff.
func undeclaredSenderTypeOctets(t *testing.T) []byte {
	t.Helper()
	declared := senderTypes(t)
	found := []byte{}
	for candidate := 0; candidate <= 0xff; candidate += 1 {
		if slices.Contains(declared, SenderType(candidate)) {
			continue
		}
		found = append(found, byte(candidate))
	}
	if len(found)+len(declared) != int(^SenderType(0))+1 {
		t.Fatalf("the derivation split %d code points into %d declared and %d undeclared",
			int(^SenderType(0))+1, len(declared), len(found))
	}
	return found
}

// TestSenderRejectsReservedAndUnknownType sweeps the whole octet space rather than the three
// values the plan probed, and states the refusal on BOTH halves of the codec.
//
// The encode half is not decoration. The sender type is inside every signature preimage this
// layer builds, so an encoder that wrote an unregistered one would produce signed bytes no peer
// can attribute to anybody; and an encoder whose default arm fell through to writing the octet
// is exactly the shape that survives a decode-only test.
//
// Each undeclared octet is offered twice, bare and with a four octet tail, so a refusal that was
// really a truncation cannot pass for a refusal of the TYPE: the tail case has bytes to spare
// and must still name ErrUnknownSenderType.
func TestSenderRejectsReservedAndUnknownType(t *testing.T) {
	undeclared := undeclaredSenderTypeOctets(t)
	if !slices.Contains(undeclared, 0x00) {
		t.Fatal("0 is declared as a sender type, and RFC 9420 section 6 reserves it")
	}
	for _, octet := range undeclared {
		for _, encoded := range [][]byte{{octet}, {octet, 0xde, 0xad, 0xbe, 0xef}} {
			decoded := &Sender{}
			err := syntax.Unmarshal(encoded, decoded)
			if !errors.Is(err, ErrUnknownSenderType) {
				t.Fatalf("decoding %x: got %v, want ErrUnknownSenderType", encoded, err)
			}
		}
		unencodable := &Sender{SenderType: SenderType(octet), LeafIndex: 1, SenderIndex: 2}
		if _, err := syntax.Marshal(unencodable); !errors.Is(err, ErrUnknownSenderType) {
			t.Fatalf("encoding sender type %#02x: got %v, want ErrUnknownSenderType", octet, err)
		}
	}
	t.Logf("%d undeclared sender type octets refused on both halves of the codec", len(undeclared))
}

// TestSenderRejectsATruncatedArm states the other refusal the decoder can make, over every
// proper prefix of every golden rather than over the boundaries somebody thought of.
func TestSenderRejectsATruncatedArm(t *testing.T) {
	cuts := 0
	for _, senderType := range senderTypes(t) {
		golden := handDerivedSenderGolden(senderType)
		for cut := 0; cut < len(golden); cut += 1 {
			decoded := &Sender{}
			if err := syntax.Unmarshal(golden[:cut], decoded); err == nil {
				t.Errorf("sender type %d: %d of %d octets decoded rather than being refused",
					senderType, cut, len(golden))
				continue
			}
			cuts += 1
		}
	}
	if cuts == 0 {
		t.Fatal("no truncation was built, so this observed nothing")
	}
	t.Logf("%d truncations refused", cuts)
}

// senderPriorContents is every state a receiver can arrive in that this file can build: the
// zero sender, and one of every declared type. Derived over the class rather than over the one
// prior somebody picks, because the failure is per PAIR -- only a receiver that already held an
// arm's payload can leave that payload standing under a type that does not carry it.
func senderPriorContents(t *testing.T) []*Sender {
	t.Helper()
	priors := []*Sender{{}}
	for _, senderType := range senderTypes(t) {
		priors = append(priors, testSenderOfType(senderType))
	}
	return priors
}

// TestASenderDecodesToTheSameValueWhateverItsReceiverHeld is not a round trip property.
//
// The arms of the decoder assign only the field their own type carries, so a decoder that wrote
// through its receiver as it read leaves the PREVIOUS sender's LeafIndex standing under
// external, or its SenderIndex standing under member. The bytes are unaffected -- the stale
// field is not written under the new arm -- so it round trips, re-encodes byte exact and agrees
// with every golden here. What it disagrees with is the same bytes decoded into a fresh
// receiver, which is a sender comparing unequal to itself depending on where it was decoded.
func TestASenderDecodesToTheSameValueWhateverItsReceiverHeld(t *testing.T) {
	priors := senderPriorContents(t)
	for _, senderType := range senderTypes(t) {
		encoded := handDerivedSenderGolden(senderType)
		fresh := &Sender{}
		if err := syntax.Unmarshal(encoded, fresh); err != nil {
			t.Fatalf("sender type %d: Unmarshal into a fresh receiver: %v", senderType, err)
		}
		for at, prior := range priors {
			reused := *prior
			if err := syntax.Unmarshal(encoded, &reused); err != nil {
				t.Fatalf("sender type %d: Unmarshal into a receiver holding prior %d: %v", senderType, at, err)
			}
			if !sameSender(&reused, fresh) {
				t.Errorf("sender type %d: decoding into a receiver that held\n %s\ngave\n %s\nand the same bytes decoded fresh give\n %s",
					senderType, describeSender(prior), describeSender(&reused), describeSender(fresh))
			}
		}
	}
	t.Logf("%d prior receiver contents over %d sender types", len(priors), len(senderTypes(t)))
}

// senderRefusedEncodingsOf is every input this file can build that a decode must refuse: every
// proper prefix of a golden, and every golden under every octet the registry does not name.
func senderRefusedEncodingsOf(t *testing.T, senderType SenderType) [][]byte {
	t.Helper()
	golden := handDerivedSenderGolden(senderType)
	inputs := [][]byte{}
	for cut := 0; cut < len(golden); cut += 1 {
		inputs = append(inputs, golden[:cut])
	}
	for _, octet := range undeclaredSenderTypeOctets(t) {
		altered := bytes.Clone(golden)
		altered[0] = octet
		inputs = append(inputs, altered)
	}
	return inputs
}

// TestARefusedSenderDecodeLeavesItsReceiverUntouched is the discipline Credential and LeafNode
// already keep, stated for the third decoder of this package so the three do not disagree about
// it with only two of them tested.
//
// A decoder that wrote its fields as it read them would leave a receiver holding a sender type
// out of a message this package REFUSED -- a value that never existed anywhere, assembled out of
// the first octet of somebody else's bytes, sitting in a variable the caller may well reuse,
// with nothing in the returned error saying so.
func TestARefusedSenderDecodeLeavesItsReceiverUntouched(t *testing.T) {
	priors := senderPriorContents(t)
	refused, accepted := 0, 0
	for _, senderType := range senderTypes(t) {
		for _, input := range senderRefusedEncodingsOf(t, senderType) {
			for _, prior := range priors {
				held := *prior
				before := *prior
				if err := syntax.Unmarshal(input, &held); err == nil {
					accepted += 1
					continue
				}
				refused += 1
				if sameSender(&held, &before) {
					continue
				}
				t.Errorf("sender type %d: a refused decode of %x into a receiver that held\n %s\nwrote through it, leaving\n %s",
					senderType, input, describeSender(&before), describeSender(&held))
				return
			}
		}
	}
	if accepted != 0 {
		t.Errorf("%d of the inputs this sweep built decoded rather than being refused, so the property was never stated over them",
			accepted)
	}
	if refused == 0 {
		t.Fatal("no input was refused, so this observed nothing")
	}
	t.Logf("%d refused decodes over %d prior receiver contents left the receiver exactly as they found it",
		refused, len(priors))
}

// ---------------------------------------------------------------------------
// the structural framing errors
// ---------------------------------------------------------------------------

// framingErrorsFile is the single file this plan declares its structural errors in. Every gate
// below derives its class from that file rather than from the list, which is the difference
// between sweeping the class and sweeping a copy of it.
const framingErrorsFile = "framing_errors.go"

// framingOwnedErrors is every name framing_errors.go declares, keyed by that name so the
// derivation below can compare the two sets. Nothing here is trusted:
// TestFramingOwnedErrorsIsEveryDeclarationOfItsFile holds it to what the file actually declares,
// in both directions.
var framingOwnedErrors = map[string]error{
	"ErrUnknownWireFormat":        ErrUnknownWireFormat,
	"ErrUnsupportedVersion":       ErrUnsupportedVersion,
	"ErrUnknownSenderType":        ErrUnknownSenderType,
	"ErrContentArmMismatch":       ErrContentArmMismatch,
	"ErrMissingGroupContext":      ErrMissingGroupContext,
	"ErrUnexpectedGroupContext":   ErrUnexpectedGroupContext,
	"ErrWireFormatMismatch":       ErrWireFormatMismatch,
	"ErrSenderNotMember":          ErrSenderNotMember,
	"ErrInvalidPaddingSize":       ErrInvalidPaddingSize,
	"ErrUnknownProposalOrRefType": ErrUnknownProposalOrRefType,
}

// TestFramingOwnedErrorsIsEveryDeclarationOfItsFile derives the class the sweeps below run over
// instead of trusting the transcription of it. An eleventh error declared in that file and left
// off the list is judged by neither sweep, and a count assertion cannot close that because it
// has the wrong polarity: it fails on adding an error and REMEMBERING the list.
func TestFramingOwnedErrorsIsEveryDeclarationOfItsFile(t *testing.T) {
	declared := packageLevelDeclarations(t, ".")
	fromFile := map[string]bool{}
	for name, file := range declared {
		if file == framingErrorsFile {
			fromFile[name] = true
		}
	}
	if len(fromFile) == 0 {
		t.Fatalf("the scan found nothing declared in %s, so this gate compared the list against an empty set",
			framingErrorsFile)
	}
	if !fromFile["ErrUnknownSenderType"] {
		t.Fatalf("the scan did not find ErrUnknownSenderType among the declarations of %s, which certainly declares it, so it is reading something other than that file",
			framingErrorsFile)
	}
	for _, name := range slices.Sorted(maps.Keys(fromFile)) {
		if _, listed := framingOwnedErrors[name]; !listed {
			t.Errorf("%s declares %s and framingOwnedErrors does not list it, so no sweep below judges it; add it there",
				framingErrorsFile, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(framingOwnedErrors)) {
		if !fromFile[name] {
			t.Errorf("framingOwnedErrors lists %s and %s does not declare it, so the sweeps run over a name this file does not own",
				name, framingErrorsFile)
		}
	}
}

// TestFramingErrorsAreDistinctAndNamed asserts no two of the structural errors alias each other,
// so a caller branching on one cannot be answered yes by another, and that each names the
// package it came from so a caller logging one at a distance can tell.
//
// The count pins the file: a name added to it is a change somebody makes deliberately, in the
// same commit, with a reason. What stops the list shrinking, and what stops it lagging behind
// the file, is the derivation above rather than this number.
//
// Ten, where the interface registry's section 7.6 block names ten structural errors plus the
// p6-private ErrUnknownProposalOrRefType -- eleven. The one that is not here is
// ErrUnknownContentType, which already existed in errors_key_schedule.go before this file did,
// and the test below is where that is held rather than papered over.
func TestFramingErrorsAreDistinctAndNamed(t *testing.T) {
	if len(framingOwnedErrors) != 10 {
		t.Fatalf("this file owns %d errors, want the nine structural ones of registry section 7.6 that were not already declared elsewhere plus the p6-private ErrUnknownProposalOrRefType; if one landed or left, say so here in the same commit",
			len(framingOwnedErrors))
	}
	names := slices.Sorted(maps.Keys(framingOwnedErrors))
	for i, name := range names {
		first := framingOwnedErrors[name]
		if first == nil {
			t.Fatalf("%s is nil", name)
		}
		if first.Error() == "" {
			t.Fatalf("%s has an empty message", name)
		}
		if !strings.HasPrefix(first.Error(), "mls: ") {
			t.Errorf("%s reads %q; every typed error of this package names the package it came from",
				name, first.Error())
		}
		for j, other := range names {
			if i == j {
				continue
			}
			second := framingOwnedErrors[other]
			if errors.Is(first, second) {
				t.Errorf("%s answers to %s (%v), so a caller branching on the two reads one as the other",
					name, other, first)
			}
			if first.Error() == second.Error() {
				t.Errorf("%s and %s both read %q, so the two are indistinguishable in a log",
					name, other, first.Error())
			}
		}
	}
}

// theTenStructuralFramingErrors is registry section 7.6's block, by name, including the one name
// this plan's own file does not declare.
var theTenStructuralFramingErrors = []string{
	"ErrUnknownWireFormat", "ErrUnsupportedVersion", "ErrUnknownContentType", "ErrUnknownSenderType",
	"ErrContentArmMismatch", "ErrMissingGroupContext", "ErrUnexpectedGroupContext",
	"ErrWireFormatMismatch", "ErrSenderNotMember", "ErrInvalidPaddingSize",
}

// TestEveryStructuralFramingErrorHasExactlyOneDeclarationSite is where this task's one deviation
// from its own plan is held.
//
// The plan says framing_errors.go declares all ten. Nine of them it does. The tenth,
// ErrUnknownContentType, was already declared -- in errors_key_schedule.go, by the plan that
// owns the secret tree, because the secret tree is what refuses a content type with no ratchet
// behind it -- and "a content type this package does not register" is ONE condition whether it
// is reached off the wire at the codec or off a header at the ratchet lookup. Two sentinels for
// one condition is precisely what every error roster in this package exists to prevent, so the
// framing layer consumes that declaration rather than shadowing it.
//
// This test is what makes that a decision rather than an accident: each of the ten resolves,
// each has exactly one declaration site, and ErrUnknownContentType's is named. A later framing
// task that adds a second declaration of it fails here instead of quietly splitting the
// condition in two, which is the failure the deviation was taken to avoid.
func TestEveryStructuralFramingErrorHasExactlyOneDeclarationSite(t *testing.T) {
	declared := packageLevelDeclarations(t, ".")
	for _, name := range theTenStructuralFramingErrors {
		file, found := declared[name]
		if !found {
			t.Errorf("registry section 7.6 names %s and this package declares no such error", name)
			continue
		}
		want := framingErrorsFile
		if name == "ErrUnknownContentType" {
			want = "errors_key_schedule.go"
		}
		if file != want {
			t.Errorf("%s is declared in %s, and the single declaration site for it is %s", name, file, want)
		}
	}
	// the sentinel this plan consumes must still be a value of its own against the nine it
	// declares, which is the property the cross-file split could quietly lose.
	for _, name := range slices.Sorted(maps.Keys(framingOwnedErrors)) {
		if errors.Is(framingOwnedErrors[name], ErrUnknownContentType) ||
			errors.Is(ErrUnknownContentType, framingOwnedErrors[name]) {
			t.Errorf("%s and ErrUnknownContentType answer for each other", name)
		}
	}
}
