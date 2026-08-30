// The v1 proposal profile gate, and the registry the gate's class is derived from.
//
// The plan supplied eight tests for this task. Seven of them state a single code point each --
// psk is refused, reinit is refused, these four are accepted -- and a gate stated that way is the
// defect rule 5 names: the accepted set is written out by hand over a class that GROWS, and this
// project has been walked past that fourteen times, most recently by a table calling itself
// "every rule of the CreateGroup carve-out" that held five rules of six.
//
// So the class is derived here. The ProposalType constants are read out of this package's own
// source -- names AND values, off the syntax tree rather than matched as text -- and the
// production table is held EQUAL to that set in both directions: a code point registered in
// extension.go with no row in proposalTypeProfile fails, and a row for a code point that no
// longer exists fails too. Every per-type assertion below then runs over the derived set rather
// than over a list, so the eighth proposal type registered by anybody is a failure on the commit
// that registers it rather than a silent gap.
//
// The plan's own eight are kept, in their own section, because a derived sweep and a named case
// answer different questions: the sweep says the class is covered, and the named case says what
// the answer for one member is supposed to look like when somebody reads the failure.
package mls

import (
	"bytes"
	"errors"
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

// ---------------------------------------------------------------------------
// the registry, derived
// ---------------------------------------------------------------------------

// proposalTypeRegistry is every constant of type ProposalType this package declares, mapped to
// the value its declaration gives it.
//
// Read off the syntax tree of the whole package rather than out of extension.go by name, which
// is ledger 21: deriving a class and then writing down the file it lives in is the same defect
// one level up, and a registry constant moved to another file of this package would leave a scan
// keyed on the filename reporting a clean run over a class it had stopped reading. The value is
// parsed from the literal, so a code point changed by one is a changed derivation and not an
// agreed one -- a scan that read only the NAMES would agree with 0xF004 as happily as 0xF003.
func proposalTypeRegistry(t *testing.T) map[string]ProposalType {
	t.Helper()
	registered := map[string]ProposalType{}
	for path, parsed := range decoderSourceOfThisPackage(t) {
		for _, declaration := range parsed.file.Decls {
			generic, isGeneric := declaration.(*ast.GenDecl)
			if !isGeneric || generic.Tok != token.CONST {
				continue
			}
			for _, specification := range generic.Specs {
				value, isValue := specification.(*ast.ValueSpec)
				if !isValue || value.Type == nil || parsed.render(value.Type) != "ProposalType" {
					continue
				}
				for i, name := range value.Names {
					if i >= len(value.Values) {
						t.Fatalf("%s declares %s with no value; this derivation reads the code point off the literal and cannot follow an iota",
							path, name.Name)
					}
					literal, isLiteral := value.Values[i].(*ast.BasicLit)
					if !isLiteral || literal.Kind != token.INT {
						t.Fatalf("%s gives %s a value this derivation cannot read as an integer literal", path, name.Name)
					}
					code, err := strconv.ParseUint(literal.Value, 0, 16)
					if err != nil {
						t.Fatalf("%s gives %s the value %s: %v", path, name.Name, literal.Value, err)
					}
					if held, already := registered[name.Name]; already {
						t.Fatalf("%s is declared twice, as %#04x and %#04x; a wire enum that disagrees by a NUMBER is the drift nothing in this package could see",
							name.Name, uint16(held), code)
					}
					registered[name.Name] = ProposalType(code)
				}
			}
		}
	}
	// the positive control: a derivation that had stopped resolving would answer an empty map,
	// and an empty map satisfies every set comparison below whose other side was emptied with
	// it. These two are certainly declared, and their values are the RFC's.
	for name, want := range map[string]ProposalType{
		"ProposalTypeAdd":                    0x0001,
		"ProposalTypeGroupContextExtensions": 0x0007,
	} {
		if got, found := registered[name]; !found || got != want {
			t.Fatalf("the derivation read %v out of this package, and %s is certainly declared as %#04x there, so it is reading no constant declaration at all",
				registered, name, uint16(want))
		}
	}
	if _, found := registered["ProposalTypeThisCodePointDoesNotExist"]; found {
		t.Fatal("the derivation reports a constant that cannot exist, so it is matching text rather than declarations")
	}
	return registered
}

// proposalTypeValuesOf is the derived registry as a sorted set of code points.
func proposalTypeValuesOf(registered map[string]ProposalType) []ProposalType {
	values := slices.Collect(maps.Values(registered))
	slices.Sort(values)
	return slices.Compact(values)
}

// TestTheV1ProfileClassifiesEveryRegisteredProposalType is rule 5 over the class this gate is
// stated on.
//
// The comparison runs in both directions on purpose. A missing row is a code point the gate
// answers "not registered" for, which is the quiet direction: the refusal is still a refusal, so
// nothing fails, and the day the profile widens to admit that type the reason it is refused is a
// table nobody knew was short. A row with no constant is a classification that outlived what it
// classified.
func TestTheV1ProfileClassifiesEveryRegisteredProposalType(t *testing.T) {
	registered := proposalTypeRegistry(t)
	derived := proposalTypeValuesOf(registered)
	classified := slices.Collect(maps.Keys(proposalTypeProfile))
	slices.Sort(classified)
	if !slices.Equal(derived, classified) {
		t.Fatalf("this package registers the proposal types %v and proposalTypeProfile classifies %v; a registered code point with no row is one the gate refuses as unregistered, and a row with no code point is a classification of nothing. The declarations: %v",
			derived, classified, registered)
	}
	t.Logf("%d registered proposal types, all classified: %v", len(derived), registered)
}

// TestEveryRegisteredProposalTypeIsAcceptedOrRefusedByItsOwnSentinel runs the gate over the
// derived class and holds each answer to the row that classifies it.
//
// The set equality above would pass over a table whose every verdict was wrong, and over a
// checkProposalType that ignored the table entirely and returned nil. This is what says the table
// is what the gate reads. The negative half -- that a refusal answers to its OWN sentinel and to
// none of the other three -- is the half that matters most: three refusals collapsed into one
// value pass every test that asks only whether an error came back, and that shape has cost this
// project three authentication bypasses.
func TestEveryRegisteredProposalTypeIsAcceptedOrRefusedByItsOwnSentinel(t *testing.T) {
	registered := proposalTypeRegistry(t)
	everySentinel := map[string]error{
		"errProfilePsk":              errProfilePsk,
		"errProfileReInit":           errProfileReInit,
		"errProfileExternalCommit":   errProfileExternalCommit,
		"errUnsupportedProposalType": errUnsupportedProposalType,
	}
	accepted, refused := 0, 0
	for _, name := range slices.Sorted(maps.Keys(registered)) {
		proposalType := registered[name]
		want := proposalTypeProfile[proposalType]
		got := defaultProfile().checkProposalType(proposalType)
		if want == nil {
			accepted += 1
			if got != nil {
				t.Errorf("%s is classified as implemented and the gate refused it with %v", name, got)
			}
			continue
		}
		refused += 1
		if !errors.Is(got, want) {
			t.Errorf("%s is classified as refused with %v and the gate answered %v", name, want, got)
			continue
		}
		for sentinelName, other := range everySentinel {
			if other == want || !errors.Is(got, other) {
				continue
			}
			t.Errorf("the refusal of %s answers to %s as well as to its own sentinel; a caller asking which narrowing it hit would be told two of them",
				name, sentinelName)
		}
		// the detail names the type, so a peer told its proposal was refused does not have to
		// diff two captures to find out which one
		if got := got.Error(); !strings.Contains(got, proposalTypeName(proposalType)) {
			t.Errorf("the refusal of %s reads %q and does not name the type that was refused", name, got)
		}
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("the sweep saw %d accepted and %d refused types; a run with nothing on one side states only half the rule",
			accepted, refused)
	}
	t.Logf("%d registered types accepted by the v1 profile, %d refused", accepted, refused)
}

// TestTheFourProfileRefusalsAreFourDistinctValues is errors_lifecycle.go's rule applied to the
// stand-ins this file declares.
//
// errors.Is cannot tell two rules apart when they answer the same value, so two of these spelled
// as one would make every assertion above hold while the gate said "psk" about a reinit.
func TestTheFourProfileRefusalsAreFourDistinctValues(t *testing.T) {
	named := map[string]error{
		"errProfilePsk":              errProfilePsk,
		"errProfileReInit":           errProfileReInit,
		"errProfileExternalCommit":   errProfileExternalCommit,
		"errUnsupportedProposalType": errUnsupportedProposalType,
	}
	for _, first := range slices.Sorted(maps.Keys(named)) {
		for _, second := range slices.Sorted(maps.Keys(named)) {
			if first == second {
				continue
			}
			if errors.Is(named[first], named[second]) {
				t.Errorf("%s answers to %s, so the two name one rule and no caller can tell them apart",
					first, second)
			}
		}
	}
	// and every one of them is a distinct value from the framing sentinel the arm rule answers,
	// because the type rule and the arm rule are two rules
	for _, name := range slices.Sorted(maps.Keys(named)) {
		if errors.Is(named[name], ErrContentArmMismatch) || errors.Is(ErrContentArmMismatch, named[name]) {
			t.Errorf("%s and ErrContentArmMismatch answer to each other", name)
		}
	}
}

// TestProposalTypeNameNamesEveryRegisteredType holds the error message's vocabulary to the
// derived registry.
//
// A name is not a decoration here: it is what a peer is told when this build refuses its
// proposal, and a type that fell through to the hex fallback would be reported as
// proposal_type(0x0008) to somebody who could have been told "branch".
func TestProposalTypeNameNamesEveryRegisteredType(t *testing.T) {
	registered := proposalTypeRegistry(t)
	named := map[string]ProposalType{}
	for _, constant := range slices.Sorted(maps.Keys(registered)) {
		proposalType := registered[constant]
		name := proposalTypeName(proposalType)
		if strings.Contains(name, "proposal_type(") {
			t.Errorf("%s (%#04x) falls through to the hex fallback and is reported as %q", constant, uint16(proposalType), name)
			continue
		}
		if held, already := named[name]; already && held != proposalType {
			t.Errorf("%s and %#04x are both named %q, so a refusal naming it says nothing about which arrived",
				constant, uint16(held), name)
		}
		named[name] = proposalType
	}
	// and the fallback is reached by something, so it is not dead prose: an unregistered code
	// point has to be reportable
	unregistered := ProposalType(0x0A0A)
	if _, registeredHere := proposalTypeProfile[unregistered]; registeredHere {
		t.Fatalf("%#04x has become a registered type and is no longer the unregistered control", uint16(unregistered))
	}
	if got := proposalTypeName(unregistered); !strings.Contains(got, "0x0a0a") {
		t.Errorf("an unregistered code point is named %q and does not carry its value", got)
	}
}

// TestProposalTypePathRequiredSet is RFC 9420 section 12.4's pathRequiredTypes, stated over the
// derived registry rather than over a list of seven.
//
// The plan's version is a table of seven rows. This is the same table with one clause added: it
// must cover every type the registry declares, so an eighth code point cannot be added without
// somebody deciding whether a commit carrying it needs an update path -- which is a question with
// a security answer, since a commit that skipped the path is a commit that did not rotate the
// committer's key.
func TestProposalTypePathRequiredSet(t *testing.T) {
	registered := proposalTypeRegistry(t)
	// RFC 9420 section 12.4: the path required set is update, remove, external_init and
	// group_context_extensions. add, psk and reinit do not require one, and the reserved code
	// point is not a proposal at all.
	required := map[string]bool{
		"ProposalTypeReserved":               false,
		"ProposalTypeAdd":                    false,
		"ProposalTypeUpdate":                 true,
		"ProposalTypeRemove":                 true,
		"ProposalTypePreSharedKey":           false,
		"ProposalTypeReInit":                 false,
		"ProposalTypeExternalInit":           true,
		"ProposalTypeGroupContextExtensions": true,
	}
	if !slices.Equal(slices.Sorted(maps.Keys(required)), slices.Sorted(maps.Keys(registered))) {
		t.Fatalf("this table decides the path requirement for %v and the registry declares %v; a registered type with no row here is a commit shape nobody ruled on",
			slices.Sorted(maps.Keys(required)), slices.Sorted(maps.Keys(registered)))
	}
	for _, name := range slices.Sorted(maps.Keys(required)) {
		if got := proposalTypePathRequired(registered[name]); got != required[name] {
			t.Errorf("proposalTypePathRequired(%s) = %v, want %v", name, got, required[name])
		}
	}
	// an unregistered code point requires no path, because this build never processes one and a
	// true answer would demand a path for a proposal it refuses
	if proposalTypePathRequired(ProposalType(0x0A0A)) {
		t.Error("an unregistered proposal type is reported as requiring an update path")
	}
}

// ---------------------------------------------------------------------------
// the gate, over the whole class
// ---------------------------------------------------------------------------

// proposalOfRegisteredType builds a well formed Proposal of one registered type: the arm that
// type names, populated, and nothing else.
//
// The switch is held to the derived registry by its caller, so a registered type with no case
// here fails rather than being quietly skipped -- which is the failure mode of every sweep whose
// fixture builder is narrower than the class it sweeps.
func proposalOfRegisteredType(t *testing.T, crypto CryptoProvider, member *testMember,
	proposalType ProposalType) *Proposal {

	t.Helper()
	switch proposalType {
	case ProposalTypeReserved:
		// there is no arm for the reserved code point and there cannot be one; the type rule
		// runs before the arm rule, which is what this fixture makes the sweep observe
		return &Proposal{ProposalType: ProposalTypeReserved}
	case ProposalTypeAdd:
		keyPackage, _, _ := testKeyPackage(t, crypto, member)
		return &Proposal{ProposalType: proposalType, Add: &Add{KeyPackage: *keyPackage}}
	case ProposalTypeUpdate:
		leaf, _ := testLeafNode(t, crypto, member)
		return &Proposal{ProposalType: proposalType, Update: &Update{LeafNode: *leaf}}
	case ProposalTypeRemove:
		return &Proposal{ProposalType: proposalType, Remove: &Remove{Removed: LeafIndex(1)}}
	case ProposalTypePreSharedKey:
		return &Proposal{ProposalType: proposalType, PreSharedKey: &PreSharedKey{}}
	case ProposalTypeReInit:
		return &Proposal{ProposalType: proposalType, ReInit: &ReInit{}}
	case ProposalTypeExternalInit:
		return &Proposal{ProposalType: proposalType, ExternalInit: &ExternalInit{}}
	case ProposalTypeGroupContextExtensions:
		return &Proposal{ProposalType: proposalType, GroupContextExtensions: &GroupContextExtensions{}}
	}
	t.Fatalf("no arm fixture for the registered proposal type %#04x; a sweep whose builder is narrower than its class passes over the members it cannot build",
		uint16(proposalType))
	return nil
}

// TestTheProfileGateAnswersEveryRegisteredProposalTypeAsItIsClassified is the whole gate over the
// whole derived class, on proposals whose arm is the one their type names.
//
// The type rule is observed to run BEFORE the arm rule, which is what the reserved code point's
// fixture is for: it has no arm, both rules would refuse it, and only the ordering decides which
// sentinel a caller sees. An ordering that put the arm rule first would report every refused type
// as an arm mismatch and lose the three names the profile has.
func TestTheProfileGateAnswersEveryRegisteredProposalTypeAsItIsClassified(t *testing.T) {
	crypto := testCrypto(t)
	member := testIdentity(t, crypto, "bob")
	registered := proposalTypeRegistry(t)
	for _, name := range slices.Sorted(maps.Keys(registered)) {
		proposalType := registered[name]
		proposal := proposalOfRegisteredType(t, crypto, member, proposalType)
		got := checkProposalProfile(defaultProfile(), proposal)
		want := proposalTypeProfile[proposalType]
		if want == nil {
			if got != nil {
				t.Errorf("a well formed %s proposal was refused with %v", name, got)
			}
			continue
		}
		if !errors.Is(got, want) {
			t.Errorf("a %s proposal was refused with %v, want %v", name, got, want)
		}
		if errors.Is(got, ErrContentArmMismatch) {
			t.Errorf("a %s proposal was refused as an arm mismatch; the profile rule has to run first or every refused type loses its name",
				name)
		}
	}
}

// ---------------------------------------------------------------------------
// the plan's tests
// ---------------------------------------------------------------------------

func TestProfileGateRefusesPsk(t *testing.T) {
	proposal := &Proposal{ProposalType: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKey{}}
	if err := checkProposalProfile(defaultProfile(), proposal); !errors.Is(err, errProfilePsk) {
		t.Fatalf("checkProposalProfile error = %v, want errProfilePsk", err)
	}
}

func TestProfileGateRefusesReInit(t *testing.T) {
	proposal := &Proposal{ProposalType: ProposalTypeReInit, ReInit: &ReInit{}}
	if err := checkProposalProfile(defaultProfile(), proposal); !errors.Is(err, errProfileReInit) {
		t.Fatalf("checkProposalProfile error = %v, want errProfileReInit", err)
	}
}

func TestProfileGateRefusesExternalInit(t *testing.T) {
	proposal := &Proposal{ProposalType: ProposalTypeExternalInit, ExternalInit: &ExternalInit{}}
	if err := checkProposalProfile(defaultProfile(), proposal); !errors.Is(err, errProfileExternalCommit) {
		t.Fatalf("checkProposalProfile error = %v, want errProfileExternalCommit", err)
	}
}

// TestProfileGateRefusesGreaseType is the plan's, over the GREASE arm the codec decodes into.
//
// The codec decodes an unregistered proposal into UnknownType and UnknownBody so the messages
// vector family can round trip it. This plan still refuses it: a GREASE proposal in a commit is
// ValSem113, and a proposal whose arm this build cannot read is one it must drop rather than skip.
func TestProfileGateRefusesGreaseType(t *testing.T) {
	proposal := &Proposal{ProposalType: ProposalType(0x0A0A), UnknownType: ProposalType(0x0A0A)}
	if err := checkProposalProfile(defaultProfile(), proposal); !errors.Is(err, errUnsupportedProposalType) {
		t.Fatalf("checkProposalProfile error = %v, want errUnsupportedProposalType", err)
	}
	// the same refusal over a value whose UnknownType is NOT set, which is the half the plan's
	// version cannot state. A decoded GREASE proposal always carries UnknownType, so the forged
	// discriminant clause refuses it whatever the type rule does -- measured: with the type rule
	// disabled entirely, the case above still passes. This one is refused by the type rule or by
	// nothing.
	byTypeAlone := &Proposal{ProposalType: ProposalType(0x0A0A), UnknownBody: []byte{0x01}}
	if err := checkProposalProfile(defaultProfile(), byTypeAlone); !errors.Is(err, errUnsupportedProposalType) {
		t.Fatalf("an unregistered proposal type carrying no forged discriminant was answered %v, want errUnsupportedProposalType",
			err)
	}
}

// TestCheckProposalTypeAnswersTheWholeCodePointSpaceFromTheRegistry is the total statement of the
// one refusal surface, over all 65536 code points rather than over the eight the registry names.
//
// The derived sweep next door covers the REGISTERED types, which leaves the complement -- every
// GREASE value, and every code point registered after this was written -- stated by nothing. That
// gap is not theoretical: disabling the "not registered" branch of checkProposalType leaves every
// named test in this file passing, because a decoded GREASE proposal carries UnknownType and is
// caught by the forged discriminant clause instead. Two rules, one of which had silently stopped
// running.
func TestCheckProposalTypeAnswersTheWholeCodePointSpaceFromTheRegistry(t *testing.T) {
	registered := proposalTypeValuesOf(proposalTypeRegistry(t))
	unregistered, accepted := 0, 0
	for value := 0; value <= 0xffff; value += 1 {
		proposalType := ProposalType(value)
		got := defaultProfile().checkProposalType(proposalType)
		if !slices.Contains(registered, proposalType) {
			unregistered += 1
			if !errors.Is(got, errUnsupportedProposalType) {
				t.Fatalf("the unregistered code point %#04x was answered %v, want errUnsupportedProposalType",
					value, got)
			}
			continue
		}
		want := proposalTypeProfile[proposalType]
		if want == nil {
			accepted += 1
			if got != nil {
				t.Fatalf("the registered code point %#04x is classified as implemented and was answered %v",
					value, got)
			}
			continue
		}
		if !errors.Is(got, want) {
			t.Fatalf("the registered code point %#04x was answered %v, want %v", value, got, want)
		}
	}
	if unregistered == 0 || accepted == 0 {
		t.Fatalf("the sweep saw %d unregistered and %d accepted code points; a run with nothing on one side states only half the rule",
			unregistered, accepted)
	}
	t.Logf("%d unregistered code points refused, %d registered and accepted", unregistered, accepted)
}

func TestProfileGateAcceptsTheFourV1Types(t *testing.T) {
	crypto := testCrypto(t)
	bob := testIdentity(t, crypto, "bob")
	keyPackage, _, _ := testKeyPackage(t, crypto, bob)
	leaf, _ := testLeafNode(t, crypto, bob)
	for _, proposal := range []*Proposal{
		{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *keyPackage}},
		{ProposalType: ProposalTypeUpdate, Update: &Update{LeafNode: *leaf}},
		{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: LeafIndex(1)}},
		{ProposalType: ProposalTypeGroupContextExtensions, GroupContextExtensions: &GroupContextExtensions{}},
	} {
		if err := checkProposalProfile(defaultProfile(), proposal); err != nil {
			t.Fatalf("checkProposalProfile(%s) = %v, want nil", proposalTypeName(proposal.ProposalType), err)
		}
	}
}

// TestProfileGateRefusesAMismatchedArm is the plan's, with the sentinel named.
//
// The plan's version asks only that an error came back, which a gate that refused every proposal
// would satisfy. The rule it is about is proposal_wire.go's -- the discriminant and the populated
// arm have to agree -- so the value it answers is that rule's sentinel, and NOT the profile's:
// two rules that answer one value are two rules a caller cannot tell apart.
func TestProfileGateRefusesAMismatchedArm(t *testing.T) {
	proposal := &Proposal{ProposalType: ProposalTypeAdd, Remove: &Remove{Removed: 1}}
	err := checkProposalProfile(defaultProfile(), proposal)
	if !errors.Is(err, ErrContentArmMismatch) {
		t.Fatalf("checkProposalProfile error = %v, want ErrContentArmMismatch", err)
	}
	// a SECOND arm hanging off a proposal whose named arm is present is the other half of the
	// same rule, and it is the half a reference cares about: two Proposal values encoding to one
	// run of octets carry one ProposalRef, and the arm that was dropped is a change the proposer
	// believed it had published
	crypto := testCrypto(t)
	bob := testIdentity(t, crypto, "bob")
	keyPackage, _, _ := testKeyPackage(t, crypto, bob)
	both := &Proposal{
		ProposalType: ProposalTypeAdd,
		Add:          &Add{KeyPackage: *keyPackage},
		Remove:       &Remove{Removed: 1},
	}
	if err := checkProposalProfile(defaultProfile(), both); !errors.Is(err, ErrContentArmMismatch) {
		t.Fatalf("a proposal carrying two arms was accepted with %v, want ErrContentArmMismatch", err)
	}
}

func TestProposalCodecIsTheFramingPlans(t *testing.T) {
	// This plan declares no Proposal codec. It uses the one the framing plan ships, through the
	// single byte level entry points, and the round trip is asserted here because every cached
	// ProposalRef is over these bytes.
	proposal := &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: LeafIndex(3)}}
	encoded, err := syntax.Marshal(proposal)
	if err != nil {
		t.Fatalf("syntax.Marshal: %v", err)
	}
	var parsed Proposal
	if err := syntax.Unmarshal(encoded, &parsed); err != nil {
		t.Fatalf("syntax.Unmarshal: %v", err)
	}
	if parsed.ProposalType != ProposalTypeRemove || parsed.Remove == nil || parsed.Remove.Removed != 3 {
		t.Fatalf("parsed = %+v", parsed)
	}
	if err := syntax.Unmarshal(append(encoded, 0xFF), &parsed); !errors.Is(err, syntax.ErrTrailingBytes) {
		t.Fatalf("syntax.Unmarshal with a trailing byte = %v, want ErrTrailingBytes", err)
	}
}

// ---------------------------------------------------------------------------
// the seams the plan's gate does not have
// ---------------------------------------------------------------------------

// TestTheProfileGateRefusesAForgedWireDiscriminant is the rule the plan's sketch has no clause
// for, and it is the one with teeth.
//
// Proposal.MarshalMLS writes UnknownType as the discriminant when it is set and selects the ARM
// by ProposalType. That is deliberate and the codec must keep it: it is how the validation plan's
// forge emits a well formed body under a GREASE code point without a second encoder existing. But
// it means the type this gate is asked about and the type the OCTETS carry can differ, and every
// ProposalRef, every transcript hash and every receiver's own gate run on the octets. Without the
// clause, a proposal is admitted here as an Add and encoded under 0x0005, so the proposer holds a
// reference to an Add and every receiver reads a reinit this profile refuses.
func TestTheProfileGateRefusesAForgedWireDiscriminant(t *testing.T) {
	crypto := testCrypto(t)
	bob := testIdentity(t, crypto, "bob")
	keyPackage, _, _ := testKeyPackage(t, crypto, bob)
	forged := &Proposal{
		ProposalType: ProposalTypeAdd,
		Add:          &Add{KeyPackage: *keyPackage},
		UnknownType:  ProposalTypeReInit,
	}
	// the seam is real: the octets this value encodes to carry the reinit discriminant, and the
	// gate is being asked about an add
	encoded, err := syntax.Marshal(forged)
	if err != nil {
		t.Fatalf("syntax.Marshal the forged proposal: %v", err)
	}
	if len(encoded) < 2 || ProposalType(uint16(encoded[0])<<8|uint16(encoded[1])) != ProposalTypeReInit {
		t.Fatalf("the forged proposal encodes under the discriminant %x, and this test is about the case where that is not the add it claims to be",
			encoded[:min(2, len(encoded))])
	}
	if err := checkProposalProfile(defaultProfile(), forged); !errors.Is(err, errUnsupportedProposalType) {
		t.Fatalf("a proposal that names an add and encodes as a reinit was answered %v, want errUnsupportedProposalType",
			err)
	}
	// and the same forge under an accepted type, so the clause is about the DISAGREEMENT rather
	// than about which type was forged
	alsoForged := &Proposal{
		ProposalType: ProposalTypeAdd,
		Add:          &Add{KeyPackage: *keyPackage},
		UnknownType:  ProposalTypeRemove,
	}
	if err := checkProposalProfile(defaultProfile(), alsoForged); !errors.Is(err, errUnsupportedProposalType) {
		t.Fatalf("a proposal that names an add and encodes as a remove was answered %v, want errUnsupportedProposalType",
			err)
	}
}

// TestTheProfileGateRefusesANilProposal states the one argument shape a caller can reach it with
// that has no type at all.
func TestTheProfileGateRefusesANilProposal(t *testing.T) {
	if err := checkProposalProfile(defaultProfile(), nil); !errors.Is(err, errUnsupportedProposalType) {
		t.Fatalf("checkProposalProfile(profile, nil) = %v, want errUnsupportedProposalType", err)
	}
}

// TestTheProfileGateWithNoProfileRunsTheDefaultOne holds the nil profile fallback to the same
// answers the default profile gives, rather than to "no error".
//
// A fallback that accepted everything when handed no profile would be a gate a caller switches
// off by forgetting an argument, and every call site in this plan passes the default anyway --
// which is exactly why nothing would notice.
func TestTheProfileGateWithNoProfileRunsTheDefaultOne(t *testing.T) {
	crypto := testCrypto(t)
	member := testIdentity(t, crypto, "bob")
	registered := proposalTypeRegistry(t)
	for _, name := range slices.Sorted(maps.Keys(registered)) {
		proposalType := registered[name]
		proposal := proposalOfRegisteredType(t, crypto, member, proposalType)
		withDefault := checkProposalProfile(defaultProfile(), proposal)
		withNone := checkProposalProfile(nil, proposal)
		if (withDefault == nil) != (withNone == nil) {
			t.Errorf("%s is answered %v under the default profile and %v under none", name, withDefault, withNone)
			continue
		}
		if withDefault != nil && !errors.Is(withNone, proposalTypeProfile[proposalType]) {
			t.Errorf("%s is refused with %v under the default profile and %v under none", name, withDefault, withNone)
		}
	}
}

// ---------------------------------------------------------------------------
// the per epoch proposal cache and commit resolution
// ---------------------------------------------------------------------------

// testProposalContent wraps a proposal in the AuthenticatedContent shape the cache stores,
// without going through a full group. The group id and epoch are the ones every test that is not
// about the epoch binding uses.
//
// The provider is in the signature and unread, because the group lifecycle plan writes this
// fixture with one and the tasks after this one call it that way.
func testProposalContent(t *testing.T, crypto CryptoProvider, sender LeafIndex,
	proposal *Proposal) *AuthenticatedContent {

	t.Helper()
	return testProposalContentAt(t, sender, []byte("group"), 1, proposal)
}

// testProposalContentAt is the same fixture with the group id and epoch named, which is what the
// epoch binding tests need and what makes the binding observable at all.
func testProposalContentAt(t *testing.T, sender LeafIndex, groupId []byte, epoch uint64,
	proposal *Proposal) *AuthenticatedContent {

	t.Helper()
	return &AuthenticatedContent{
		WireFormat: WireFormatPrivateMessage,
		Content: FramedContent{
			GroupId:     groupId,
			Epoch:       epoch,
			Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: sender},
			ContentType: ContentTypeProposal,
			Proposal:    proposal,
		},
		Auth: FramedContentAuthData{Signature: []byte("sig")},
	}
}

// testRemoveProposal is a well formed remove of one leaf, which is the cheapest proposal that
// carries a value a test can tell two of apart.
func testRemoveProposal(removed LeafIndex) *Proposal {
	return &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: removed}}
}

// testStoredRemove caches one remove sent by one member and answers its reference.
func testStoredRemove(t *testing.T, crypto CryptoProvider, cache *ProposalCache,
	sender LeafIndex, removed LeafIndex) ProposalRef {

	t.Helper()
	ref, err := cache.Store(crypto, testProposalContent(t, crypto, sender, testRemoveProposal(removed)))
	if err != nil {
		t.Fatalf("Store(remove %d from leaf %d): %v", removed, sender, err)
	}
	return ref
}

// ---------------------------------------------------------------------------
// what a reference names
// ---------------------------------------------------------------------------

func TestProposalCacheResolvesByReference(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()

	ref := testStoredRemove(t, crypto, cache, LeafIndex(1), LeafIndex(4))
	cached, ok := cache.Get(ref)
	if !ok || cached.Sender != 1 || cached.ByValue {
		t.Fatalf("Get = %+v %v", cached, ok)
	}

	list, err := cache.Resolve(crypto, LeafIndex(0),
		[]ProposalOrRef{{Type: ProposalOrRefTypeReference, Reference: ref}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(list.Removes) != 1 || list.Removes[0].Proposal.Remove.Removed != 4 {
		t.Fatalf("Removes = %+v", list.Removes)
	}
	if list.Removes[0].Sender != 1 {
		t.Fatal("the resolved proposal must keep its original sender, not the committer")
	}
	if list.Removes[0].ByValue {
		t.Fatal("a proposal named by reference is not one the commit carried by value")
	}
}

// TestTheCacheAnswersTheReferenceItWasAskedForAndNotTheFirstOneItHolds is the substitution
// property, and it is the one a single entry cache cannot state.
//
// Three entries, each looked up in turn and each required to answer ITS OWN proposal. A lookup
// that answered the first entry it holds -- or the last, or whichever the map iterated to first
// -- passes every test that stores one proposal and gets it back, and it is a proposal
// substitution: the commit names one member's removal and the group applies another's, under a
// reference every peer verifies and agrees with.
func TestTheCacheAnswersTheReferenceItWasAskedForAndNotTheFirstOneItHolds(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	senders := []LeafIndex{1, 2, 3}
	removals := []LeafIndex{7, 8, 9}
	refs := []ProposalRef{}
	for i := range senders {
		refs = append(refs, testStoredRemove(t, crypto, cache, senders[i], removals[i]))
	}
	for i, ref := range refs {
		cached, ok := cache.Get(ref)
		if !ok {
			t.Fatalf("Get(entry %d) missed a reference this cache answered", i)
		}
		if cached.Proposal.Remove.Removed != removals[i] || cached.Sender != senders[i] {
			t.Errorf("Get(entry %d) answered a removal of leaf %d sent by leaf %d, want %d sent by %d",
				i, cached.Proposal.Remove.Removed, cached.Sender, removals[i], senders[i])
		}
		list, err := cache.Resolve(crypto, LeafIndex(0),
			[]ProposalOrRef{{Type: ProposalOrRefTypeReference, Reference: ref}})
		if err != nil {
			t.Fatalf("Resolve(entry %d): %v", i, err)
		}
		if len(list.Removes) != 1 || list.Removes[0].Proposal.Remove.Removed != removals[i] ||
			list.Removes[0].Sender != senders[i] {
			t.Errorf("Resolve(entry %d) answered %+v, want a removal of leaf %d sent by leaf %d",
				i, list.Removes, removals[i], senders[i])
		}
	}
}

// TestTheCacheKeyIsTheWholeReferenceAndNotAPrefixOfIt is the truncation property, stated over
// every octet of the reference rather than over the two ends of it.
//
// A key cut short is not a missed lookup, it is a SUBSTITUTION: two references sharing the
// retained prefix answer the same entry, so a commit naming one proposal resolves to another and
// every peer computing the same truncated key agrees. What separates a whole key from any
// truncation of it is a reference that differs from a stored one at exactly one position -- if
// that position is inside the part the key dropped, the lookup hits. Sweeping every position is
// what makes the statement independent of WHERE the cut is, which an assertion about the last
// byte alone is not: a key of ref[8:] is invisible to it.
func TestTheCacheKeyIsTheWholeReferenceAndNotAPrefixOfIt(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	ref := testStoredRemove(t, crypto, cache, LeafIndex(1), LeafIndex(4))
	if len(ref) == 0 {
		t.Fatal("the stored reference is empty, so every neighbour below is the same reference")
	}
	for i := range ref {
		neighbour := bytes.Clone(ref)
		neighbour[i] ^= 0xFF
		if _, ok := cache.Get(ProposalRef(neighbour)); ok {
			t.Errorf("Get answered an entry for a reference differing from the stored one at octet %d of %d; the lookup is not keyed on the whole reference",
				i, len(ref))
		}
		if _, err := cache.Resolve(crypto, LeafIndex(0),
			[]ProposalOrRef{{Type: ProposalOrRefTypeReference, Reference: ProposalRef(neighbour)}}); err == nil {
			t.Errorf("Resolve accepted a reference differing from the stored one at octet %d of %d",
				i, len(ref))
		}
	}
	// and a reference that is a genuine PREFIX of a stored one, which is the shape a caller
	// sends when it truncates on the wire rather than in the map
	for cut := 1; cut < len(ref); cut += 1 {
		if _, ok := cache.Get(ProposalRef(ref[:cut])); ok {
			t.Errorf("Get answered an entry for the first %d octets of a %d octet reference", cut, len(ref))
		}
	}
}

func TestProposalCacheResolveUnknownReference(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	unknown := ProposalRef(bytes.Repeat([]byte{9}, 32))
	_, err := cache.Resolve(crypto, LeafIndex(0),
		[]ProposalOrRef{{Type: ProposalOrRefTypeReference, Reference: unknown}})
	if !errors.Is(err, errProposalNotCached) {
		t.Fatalf("Resolve error = %v, want errProposalNotCached", err)
	}
}

// TestResolveRefusesOneReferenceNamedTwice is RFC 9420 section 12.2 at the layer that owns
// identity.
//
// A reference IS a name. One name resolving to two entries of one list means a member's single
// published proposal is applied twice -- two removals of one leaf, or two adds of one key package
// -- and every section 12.2 rule that would catch the result belongs to task 7, over a list this
// one has already built. Refusing it here is what keeps the list task 7 validates free of a
// duplicate that the cache itself manufactured.
func TestResolveRefusesOneReferenceNamedTwice(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	ref := testStoredRemove(t, crypto, cache, LeafIndex(1), LeafIndex(4))
	_, err := cache.Resolve(crypto, LeafIndex(0), []ProposalOrRef{
		{Type: ProposalOrRefTypeReference, Reference: ref},
		{Type: ProposalOrRefTypeReference, Reference: ref},
	})
	if !errors.Is(err, errDuplicateProposalReference) {
		t.Fatalf("Resolve error = %v, want errDuplicateProposalReference", err)
	}
	// and the duplicate is refused wherever in the vector it appears, not only when the two are
	// adjacent: a scan comparing each entry with the one before it passes the interleaved shape
	other := testStoredRemove(t, crypto, cache, LeafIndex(2), LeafIndex(5))
	_, err = cache.Resolve(crypto, LeafIndex(0), []ProposalOrRef{
		{Type: ProposalOrRefTypeReference, Reference: ref},
		{Type: ProposalOrRefTypeReference, Reference: other},
		{Type: ProposalOrRefTypeReference, Reference: ref},
	})
	if !errors.Is(err, errDuplicateProposalReference) {
		t.Fatalf("Resolve error over an interleaved duplicate = %v, want errDuplicateProposalReference", err)
	}
}

// ---------------------------------------------------------------------------
// who a proposal is attributed to
// ---------------------------------------------------------------------------

func TestProposalCacheByValueSenderIsCommitter(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	list, err := cache.Resolve(crypto, LeafIndex(5), []ProposalOrRef{{
		Type:     ProposalOrRefTypeProposal,
		Proposal: testRemoveProposal(LeafIndex(2)),
	}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(list.Removes) != 1 || list.Removes[0].Sender != 5 || !list.Removes[0].ByValue {
		t.Fatalf("by-value proposal must be attributed to the committer: %+v", list.Removes)
	}
}

// TestTheCacheAcceptsExactlyOneSenderTypeOfTheWholeCodePointSpace is the attribution rule stated
// over all 256 values a sender type can hold rather than over the four the registry names.
//
// A CachedProposal carries a LeafIndex and a sender that is not a member has none, so caching a
// proposal from any other sender type attributes it to whatever LeafIndex the message happened to
// carry -- zero, for the Sender arms that have no leaf index at all. Leaf 0 is a real member, and
// an Update attributed to it reads as the committer's own under ValSem111.
//
// Every value rather than the three non member constants, because the class here is not the
// registry's: it is "not member", and an enumeration of the three named alternatives says nothing
// about the 252 a forged or GREASE sender carries.
func TestTheCacheAcceptsExactlyOneSenderTypeOfTheWholeCodePointSpace(t *testing.T) {
	crypto := testCrypto(t)
	accepted := []SenderType{}
	for code := 0; code < 256; code += 1 {
		senderType := SenderType(code)
		cache := NewProposalCache()
		content := testProposalContent(t, crypto, LeafIndex(1), testRemoveProposal(LeafIndex(4)))
		content.Content.Sender = Sender{SenderType: senderType, LeafIndex: 1}
		_, err := cache.Store(crypto, content)
		if err == nil {
			accepted = append(accepted, senderType)
			continue
		}
		if !errors.Is(err, errProposalSenderNotMember) {
			t.Errorf("Store with sender type %d answered %v, want errProposalSenderNotMember", code, err)
		}
	}
	if !slices.Equal(accepted, []SenderType{SenderTypeMember}) {
		t.Fatalf("the cache accepts the sender types %v, and a CachedProposal has a leaf index for exactly one of them", accepted)
	}
}

// ---------------------------------------------------------------------------
// the epoch an entry belongs to
// ---------------------------------------------------------------------------

// TestTheCacheIsBoundToTheEpochOfItsFirstEntry is the replay property.
//
// A ProposalRef is a hash over an AuthenticatedContent that carries the group id and the epoch,
// so an entry from another epoch is not merely stale -- it is a name no commit of THIS epoch can
// legitimately carry. A cache that took entries from two epochs would answer the older one's
// references to the newer one's commit, which applies a proposal the group has already applied
// under a reference that still verifies.
func TestTheCacheIsBoundToTheEpochOfItsFirstEntry(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	if _, err := cache.Store(crypto, testProposalContentAt(t, 1, []byte("group"), 7,
		testRemoveProposal(LeafIndex(4)))); err != nil {
		t.Fatalf("Store at epoch 7: %v", err)
	}
	// the epoch after
	if _, err := cache.Store(crypto, testProposalContentAt(t, 1, []byte("group"), 8,
		testRemoveProposal(LeafIndex(5)))); !errors.Is(err, errProposalCacheEpoch) {
		t.Errorf("Store at epoch 8 into a cache holding epoch 7 answered %v, want errProposalCacheEpoch", err)
	}
	// and the epoch before, because a cache that only refused a HIGHER epoch would take a
	// replayed proposal from a closed one
	if _, err := cache.Store(crypto, testProposalContentAt(t, 1, []byte("group"), 6,
		testRemoveProposal(LeafIndex(5)))); !errors.Is(err, errProposalCacheEpoch) {
		t.Errorf("Store at epoch 6 into a cache holding epoch 7 answered %v, want errProposalCacheEpoch", err)
	}
	// and another GROUP at the same epoch, because the epoch number alone is not an identity:
	// every group in this client runs an epoch 7
	if _, err := cache.Store(crypto, testProposalContentAt(t, 1, []byte("other"), 7,
		testRemoveProposal(LeafIndex(5)))); !errors.Is(err, errProposalCacheEpoch) {
		t.Errorf("Store for another group at epoch 7 answered %v, want errProposalCacheEpoch", err)
	}
	if got := len(cache.Pending()); got != 1 {
		t.Errorf("the cache holds %d entries after three refusals, want 1", got)
	}
}

// TestCheckEpochAnswersTheBindingAndClearReleasesIt is the half Store cannot see: an epoch that
// advanced with no proposal arriving in the new one.
func TestCheckEpochAnswersTheBindingAndClearReleasesIt(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	// an empty cache belongs to no epoch: there is nothing in it to be stale
	if err := cache.CheckEpoch([]byte("group"), 99); err != nil {
		t.Fatalf("CheckEpoch on an empty cache = %v, want nil", err)
	}
	if _, err := cache.Store(crypto, testProposalContentAt(t, 1, []byte("group"), 7,
		testRemoveProposal(LeafIndex(4)))); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := cache.CheckEpoch([]byte("group"), 7); err != nil {
		t.Errorf("CheckEpoch for the epoch this cache holds = %v, want nil", err)
	}
	if err := cache.CheckEpoch([]byte("group"), 8); !errors.Is(err, errProposalCacheEpoch) {
		t.Errorf("CheckEpoch for the next epoch = %v, want errProposalCacheEpoch", err)
	}
	if err := cache.CheckEpoch([]byte("other"), 7); !errors.Is(err, errProposalCacheEpoch) {
		t.Errorf("CheckEpoch for another group = %v, want errProposalCacheEpoch", err)
	}
	cache.Clear()
	if err := cache.CheckEpoch([]byte("group"), 8); err != nil {
		t.Errorf("CheckEpoch after Clear = %v, want nil; Clear is what releases the binding", err)
	}
	if got := len(cache.Pending()); got != 0 {
		t.Errorf("Clear left %d entries behind", got)
	}
}

// TestTheCachedGroupIdIsCutFromTheCallersArrayAndNotAliasedToIt is the retention property for the
// one caller array the binding keeps.
//
// The group id arrives inside a buffer the caller decoded and still owns. A binding aliased to it
// changes when the caller reuses that buffer, so a cache that was holding group A silently starts
// answering for group B with no error path anywhere -- and CheckEpoch, the one guard that would
// have said so, agrees with whatever the buffer now holds.
func TestTheCachedGroupIdIsCutFromTheCallersArrayAndNotAliasedToIt(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	groupId := []byte("group")
	if _, err := cache.Store(crypto, testProposalContentAt(t, 1, groupId, 7,
		testRemoveProposal(LeafIndex(4)))); err != nil {
		t.Fatalf("Store: %v", err)
	}
	for i := range groupId {
		groupId[i] = 0x5A
	}
	if err := cache.CheckEpoch([]byte("group"), 7); err != nil {
		t.Errorf("CheckEpoch for the group this cache was bound to = %v after the caller overwrote its own array, want nil", err)
	}
	if err := cache.CheckEpoch(groupId, 7); !errors.Is(err, errProposalCacheEpoch) {
		t.Errorf("CheckEpoch for what the caller's array now holds = %v, want errProposalCacheEpoch", err)
	}
}

// ---------------------------------------------------------------------------
// order, buckets and the path requirement
// ---------------------------------------------------------------------------

func TestProposalCacheBucketsAndOrder(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	refs := []ProposalOrRef{
		{Type: ProposalOrRefTypeProposal, Proposal: testRemoveProposal(LeafIndex(1))},
		{Type: ProposalOrRefTypeProposal, Proposal: testRemoveProposal(LeafIndex(2))},
	}
	list, err := cache.Resolve(crypto, LeafIndex(0), refs)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(list.All) != 2 || list.Len() != 2 {
		t.Fatalf("All = %d, Len = %d, want 2", len(list.All), list.Len())
	}
	if list.All[0].Proposal.Remove.Removed != 1 || list.All[1].Proposal.Remove.Removed != 2 {
		t.Fatal("All must preserve commit order, because Add placement depends on it")
	}
	if !list.PathRequired() {
		t.Fatal("a list containing a remove requires a path")
	}
}

// TestResolveKeepsCommitOrderInAllAndInEveryBucket is the order property over a vector that
// separates the three ways it can be lost.
//
// The commit order is 1, 2, 3 and the entries alternate between by-value and by-reference, so a
// resolution that reversed the vector, that appended the by-reference entries after the by-value
// ones, or that read the cache's own reception order instead of the commit's, each answers a
// different sequence. A two entry vector of one kind, which is what the plan supplies, is
// satisfied by all three.
func TestResolveKeepsCommitOrderInAllAndInEveryBucket(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	// cached in the OPPOSITE order to the one the commit names them in, so a resolution reading
	// the cache's reception order answers 4, 2 rather than 2, 4
	fourth := testStoredRemove(t, crypto, cache, LeafIndex(9), LeafIndex(4))
	second := testStoredRemove(t, crypto, cache, LeafIndex(8), LeafIndex(2))
	list, err := cache.Resolve(crypto, LeafIndex(0), []ProposalOrRef{
		{Type: ProposalOrRefTypeProposal, Proposal: testRemoveProposal(LeafIndex(1))},
		{Type: ProposalOrRefTypeReference, Reference: second},
		{Type: ProposalOrRefTypeProposal, Proposal: testRemoveProposal(LeafIndex(3))},
		{Type: ProposalOrRefTypeReference, Reference: fourth},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := []LeafIndex{1, 2, 3, 4}
	got := []LeafIndex{}
	for _, cached := range list.All {
		got = append(got, cached.Proposal.Remove.Removed)
	}
	if !slices.Equal(got, want) {
		t.Errorf("All removes leaves %v, want %v in the order the commit names them", got, want)
	}
	got = got[:0]
	for _, cached := range list.Removes {
		got = append(got, cached.Proposal.Remove.Removed)
	}
	if !slices.Equal(got, want) {
		t.Errorf("Removes holds %v, want %v; the bucket carries the commit order too, because it is what an applier walks", got, want)
	}
	// and Refs rebuilds the same vector, by value where the commit carried a value and by
	// reference where it named one
	rebuilt := list.Refs()
	if len(rebuilt) != 4 {
		t.Fatalf("Refs rebuilt %d entries, want 4", len(rebuilt))
	}
	for i, entry := range rebuilt {
		byValue := i%2 == 0
		if byValue && (entry.Type != ProposalOrRefTypeProposal || entry.Proposal == nil) {
			t.Errorf("Refs entry %d is %+v, want an inline proposal", i, entry)
		}
		if !byValue && (entry.Type != ProposalOrRefTypeReference || len(entry.Reference) == 0) {
			t.Errorf("Refs entry %d is %+v, want a reference", i, entry)
		}
	}
}

func TestProposalListPathRequiredAddOnly(t *testing.T) {
	crypto := testCrypto(t)
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "bob"))
	cache := NewProposalCache()
	list, err := cache.Resolve(crypto, LeafIndex(0), []ProposalOrRef{{
		Type:     ProposalOrRefTypeProposal,
		Proposal: &Proposal{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}},
	}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if list.PathRequired() {
		t.Fatal("an add-only list does not require a path")
	}
}

// TestAnEmptyProposalListRequiresAPath is the half of RFC 9420 section 12.4's rule that is easy
// to drop, and the half with the security answer: a commit with no proposals and no path changes
// no key material at all, so the epoch advances over a secret every member of the previous epoch
// still holds.
func TestAnEmptyProposalListRequiresAPath(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	list, err := cache.Resolve(crypto, LeafIndex(0), nil)
	if err != nil {
		t.Fatalf("Resolve of an empty vector: %v", err)
	}
	if list.Len() != 0 {
		t.Fatalf("Len = %d over an empty vector", list.Len())
	}
	if !list.PathRequired() {
		t.Fatal("an empty proposal list requires a path; a commit with neither changes no key material")
	}
}

// proposalListBucketNames is every bucket field ProposalList declares, derived off the type
// rather than written down.
//
// All is the one exclusion and it is named rather than filtered by shape: it is the commit-order
// record and holds every proposal, so it is not a bucket and a gate that treated it as one would
// report every proposal as landing in two. A fifth bucket added to the struct is a member of this
// class the moment it is declared, which is what the sweep below needs it to be.
func proposalListBucketNames(t *testing.T) []string {
	t.Helper()
	bucketType := reflect.TypeOf([]CachedProposal{})
	names := []string{}
	for i := 0; i < reflect.TypeOf(ProposalList{}).NumField(); i += 1 {
		field := reflect.TypeOf(ProposalList{}).Field(i)
		if field.Name == "All" || field.Type != bucketType {
			continue
		}
		names = append(names, field.Name)
	}
	if len(names) == 0 {
		t.Fatal("ProposalList declares no bucket of cached proposals, so the sweep below compares nothing")
	}
	slices.Sort(names)
	return names
}

// proposalListBucketLength reads one bucket of a resolved list by name.
func proposalListBucketLength(t *testing.T, list *ProposalList, bucket string) int {
	t.Helper()
	field := reflect.ValueOf(list).Elem().FieldByName(bucket)
	if !field.IsValid() {
		t.Fatalf("ProposalList has no field %s", bucket)
	}
	return field.Len()
}

// TestEveryProposalTypeTheV1ProfileAcceptsLandsInABucketOfItsOwn holds Resolve's bucketing to the
// profile table and to the ProposalList type, in both directions.
//
// Neither side is written down here. The accepted set is the rows of proposalTypeProfile whose
// refusal is nil -- the same table TestTheV1ProfileClassifiesEveryRegisteredProposalType holds
// equal to the registry -- and the buckets are the fields of ProposalList. What the two
// directions catch are different faults. An accepted type with no bucket is counted in All and
// applied by nothing, which is a commit the group agrees to and does not perform; and a bucket no
// accepted type fills is a route Resolve never takes, which is the shape a bucket added for a
// type that was then refused leaves behind. Two accepted types sharing one bucket is the third,
// and it is why the fill is recorded per bucket rather than counted.
func TestEveryProposalTypeTheV1ProfileAcceptsLandsInABucketOfItsOwn(t *testing.T) {
	crypto := testCrypto(t)
	member := testIdentity(t, crypto, "bob")
	registered := proposalTypeRegistry(t)
	buckets := proposalListBucketNames(t)
	accepted := []string{}
	filledBy := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(registered)) {
		proposalType := registered[name]
		refusal, classified := proposalTypeProfile[proposalType]
		if !classified || refusal != nil {
			continue
		}
		accepted = append(accepted, name)
		list, err := NewProposalCache().Resolve(crypto, LeafIndex(0), []ProposalOrRef{{
			Type:     ProposalOrRefTypeProposal,
			Proposal: proposalOfRegisteredType(t, crypto, member, proposalType),
		}})
		if err != nil {
			t.Errorf("Resolve of a %s the v1 profile accepts: %v", name, err)
			continue
		}
		if len(list.All) != 1 {
			t.Errorf("a single %s resolved to %d entries in All", name, len(list.All))
			continue
		}
		landed := []string{}
		for _, bucket := range buckets {
			if proposalListBucketLength(t, list, bucket) != 0 {
				landed = append(landed, bucket)
			}
		}
		if len(landed) != 1 {
			t.Errorf("a %s landed in the buckets %v, want exactly one of %v", name, landed, buckets)
			continue
		}
		if held, already := filledBy[landed[0]]; already {
			t.Errorf("%s and %s both land in %s, so one of the two is applied under the other's rules",
				held, name, landed[0])
			continue
		}
		filledBy[landed[0]] = name
	}
	if len(accepted) == 0 {
		t.Fatal("the v1 profile accepts no proposal type, so this sweep ran over nothing")
	}
	if !slices.Equal(slices.Sorted(maps.Keys(filledBy)), buckets) {
		t.Errorf("the accepted types %v fill the buckets %v and ProposalList declares %v; an accepted type in no bucket is counted in All and applied by nothing, and a bucket nothing fills is a route Resolve never takes",
			accepted, slices.Sorted(maps.Keys(filledBy)), buckets)
	}
	t.Logf("%d accepted proposal types over %d buckets: %v", len(accepted), len(buckets), filledBy)
}

// TestTheListPathRequirementFollowsTheRfcSetForEveryAcceptedType is section 12.4's rule read off
// a resolved list rather than off the predicate, over every type the profile lets through.
//
// The predicate has its own gate next door. What this adds is that PathRequired READS it: a list
// method that answered true for everything, or that consulted a set of its own, agrees with the
// predicate's gate and disagrees with the RFC on exactly the add-only commit.
func TestTheListPathRequirementFollowsTheRfcSetForEveryAcceptedType(t *testing.T) {
	crypto := testCrypto(t)
	member := testIdentity(t, crypto, "bob")
	registered := proposalTypeRegistry(t)
	swept := 0
	for _, name := range slices.Sorted(maps.Keys(registered)) {
		proposalType := registered[name]
		if refusal, classified := proposalTypeProfile[proposalType]; !classified || refusal != nil {
			continue
		}
		list, err := NewProposalCache().Resolve(crypto, LeafIndex(0), []ProposalOrRef{{
			Type:     ProposalOrRefTypeProposal,
			Proposal: proposalOfRegisteredType(t, crypto, member, proposalType),
		}})
		if err != nil {
			t.Errorf("Resolve of a %s: %v", name, err)
			continue
		}
		if got, want := list.PathRequired(), proposalTypePathRequired(proposalType); got != want {
			t.Errorf("a list holding one %s reports PathRequired %v, want %v", name, got, want)
		}
		swept += 1
	}
	if swept == 0 {
		t.Fatal("no accepted proposal type was swept, so this gate states nothing")
	}
}

// ---------------------------------------------------------------------------
// the group context extensions arm
// ---------------------------------------------------------------------------

// TestResolveRefusesASecondGroupContextExtensionsProposal is what makes ProposalList.Extensions
// exact.
//
// RFC 9420 section 12.2 makes a list carrying two of them invalid, and task 7's catalogue
// (ValSem101 to ValSem113) has no code for it -- checked against the plan rather than assumed.
// Extensions answers GCE[0], so without this refusal a commit carrying two would apply one of two
// extension sets with nothing anywhere saying which, and the group would agree to a context no
// member can name.
func TestResolveRefusesASecondGroupContextExtensionsProposal(t *testing.T) {
	crypto := testCrypto(t)
	first := []Extension{{ExtensionType: ExtensionTypeRequiredCapabilities, ExtensionData: []byte{0, 0, 0}}}
	second := []Extension{{ExtensionType: ExtensionTypeUrmessageGroupPolicy, ExtensionData: []byte{1}}}
	_, err := NewProposalCache().Resolve(crypto, LeafIndex(0), []ProposalOrRef{
		{Type: ProposalOrRefTypeProposal, Proposal: &Proposal{
			ProposalType:           ProposalTypeGroupContextExtensions,
			GroupContextExtensions: &GroupContextExtensions{Extensions: first}}},
		{Type: ProposalOrRefTypeProposal, Proposal: &Proposal{
			ProposalType:           ProposalTypeGroupContextExtensions,
			GroupContextExtensions: &GroupContextExtensions{Extensions: second}}},
	})
	if !errors.Is(err, errMultipleGroupContextExtensions) {
		t.Fatalf("Resolve error = %v, want errMultipleGroupContextExtensions", err)
	}
}

// TestExtensionsAnswersTheProposedSetAndNothingWhenThereIsNone
func TestExtensionsAnswersTheProposedSetAndNothingWhenThereIsNone(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	empty, err := cache.Resolve(crypto, LeafIndex(0), []ProposalOrRef{{
		Type: ProposalOrRefTypeProposal, Proposal: testRemoveProposal(LeafIndex(1))}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if exts, ok := empty.Extensions(); ok || exts != nil {
		t.Errorf("a list with no group_context_extensions proposal answered %v %v", exts, ok)
	}
	proposed := []Extension{{ExtensionType: ExtensionTypeRequiredCapabilities, ExtensionData: []byte{0, 0, 0}}}
	list, err := cache.Resolve(crypto, LeafIndex(0), []ProposalOrRef{{
		Type: ProposalOrRefTypeProposal, Proposal: &Proposal{
			ProposalType:           ProposalTypeGroupContextExtensions,
			GroupContextExtensions: &GroupContextExtensions{Extensions: proposed}}}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	exts, ok := list.Extensions()
	if !ok || len(exts) != 1 || exts[0].ExtensionType != ExtensionTypeRequiredCapabilities {
		t.Fatalf("Extensions = %v %v, want the proposed set", exts, ok)
	}
}

// ---------------------------------------------------------------------------
// what the cache keeps, and what it does not
// ---------------------------------------------------------------------------

// TestTheCacheKeepsNothingTheCallerCanStillWriteInto is the retention property over a proposal's
// own body.
//
// A proposal arrives inside a buffer the caller decoded and still owns. An entry cut from that
// buffer changes underneath the group with no error path anywhere, and the commit resolved from
// it is one no peer can reproduce -- the reference was taken over the octets that arrived, and
// what the cache would then answer is whatever the caller wrote afterwards.
func TestTheCacheKeepsNothingTheCallerCanStillWriteInto(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	body := []byte{0x11, 0x22, 0x33}
	proposal := &Proposal{
		ProposalType: ProposalTypeGroupContextExtensions,
		GroupContextExtensions: &GroupContextExtensions{Extensions: []Extension{
			{ExtensionType: ExtensionTypeRequiredCapabilities, ExtensionData: body}}},
	}
	ref, err := cache.Store(crypto, testProposalContent(t, crypto, LeafIndex(1), proposal))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	// the caller goes on owning the arrays it was decoded out of, and reuses them
	for i := range body {
		body[i] = 0xFF
	}
	proposal.GroupContextExtensions.Extensions[0].ExtensionType = ExtensionTypeUrmessageGroupPolicy
	cached, ok := cache.Get(ref)
	if !ok {
		t.Fatal("Get missed the reference Store answered")
	}
	held := cached.Proposal.GroupContextExtensions.Extensions[0]
	if held.ExtensionType != ExtensionTypeRequiredCapabilities {
		t.Errorf("the cached extension type is %#04x after the caller edited its own proposal, want %#04x",
			uint16(held.ExtensionType), uint16(ExtensionTypeRequiredCapabilities))
	}
	if !slices.Equal(held.ExtensionData, []byte{0x11, 0x22, 0x33}) {
		t.Errorf("the cached extension body is %x after the caller overwrote its own array, want 112233", held.ExtensionData)
	}
}

// TestResolveHandsBackNothingTheCacheStillHolds is the same property in the other direction: what
// Resolve answers must not be the cache's own storage, or an applier walking the list writes into
// the entries every later commit of this epoch resolves.
func TestResolveHandsBackNothingTheCacheStillHolds(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	ref := testStoredRemove(t, crypto, cache, LeafIndex(1), LeafIndex(4))
	list, err := cache.Resolve(crypto, LeafIndex(0),
		[]ProposalOrRef{{Type: ProposalOrRefTypeReference, Reference: ref}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	list.All[0].Proposal.Remove.Removed = 99
	list.All[0].Ref[0] ^= 0xFF
	cached, ok := cache.Get(ref)
	if !ok {
		t.Fatal("the caller's edit to the resolved reference reached the key this cache is holding")
	}
	if cached.Proposal.Remove.Removed != 4 {
		t.Errorf("the cached proposal removes leaf %d after the caller edited the resolved list, want 4",
			cached.Proposal.Remove.Removed)
	}
}

// TestStoreHandsBackNothingTheCacheStillHolds is the third direction: the reference Store answers
// is the caller's, and writing into it must change nothing the cache is holding.
//
// Both halves, because the cache holds the reference TWICE -- once as the map key and once as the
// entry's own Ref, which is what Get answers and what a committer names the proposal by. A key
// cut from a string conversion is safe whatever the caller does to the answer, so a probe that
// only looked the entry up would report clean over an entry whose own Ref the caller had just
// rewritten -- and that Ref is the one that ends up in a commit.
func TestStoreHandsBackNothingTheCacheStillHolds(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	ref := testStoredRemove(t, crypto, cache, LeafIndex(1), LeafIndex(4))
	name := bytes.Clone(ref)
	ref[0] ^= 0xFF
	cached, ok := cache.Get(ProposalRef(name))
	if !ok {
		t.Fatal("writing into the reference Store answered renamed the entry the cache is holding")
	}
	if !slices.Equal([]byte(cached.Ref), name) {
		t.Errorf("the entry names itself %x after the caller edited the reference Store answered, want %x",
			cached.Ref, name)
	}
}

// ---------------------------------------------------------------------------
// what the cache refuses
// ---------------------------------------------------------------------------

// TestStoreJudgesItsProviderBeforeAnythingElse records the order the refusals run in, which is
// the difference between a caller told to fix the argument it got wrong and one sent to fix a
// message that was never the problem.
func TestStoreJudgesItsProviderBeforeAnythingElse(t *testing.T) {
	if _, err := NewProposalCache().Store(nil, nil); !errors.Is(err, ErrNilCryptoProvider) {
		t.Errorf("Store(nil, nil) = %v, want ErrNilCryptoProvider", err)
	}
	crypto := testCrypto(t)
	if _, err := NewProposalCache().Store(crypto, nil); !errors.Is(err, errNilAuthenticatedContent) {
		t.Errorf("Store(crypto, nil) = %v, want errNilAuthenticatedContent", err)
	}
	if _, err := NewProposalCache().Resolve(nil, 0, nil); !errors.Is(err, ErrNilCryptoProvider) {
		t.Errorf("Resolve(nil, ...) = %v, want ErrNilCryptoProvider", err)
	}
}

// TestStoreRefusesAnythingThatIsNotAFramedProposal covers the two shapes a caller reaches this
// with: a content type naming another arm, and a proposal content type carrying no proposal.
func TestStoreRefusesAnythingThatIsNotAFramedProposal(t *testing.T) {
	crypto := testCrypto(t)
	commit := testProposalContent(t, crypto, LeafIndex(1), testRemoveProposal(LeafIndex(4)))
	commit.Content.ContentType = ContentTypeCommit
	if _, err := NewProposalCache().Store(crypto, commit); !errors.Is(err, errProposalCacheNotAProposal) {
		t.Errorf("Store of a commit = %v, want errProposalCacheNotAProposal", err)
	}
	empty := testProposalContent(t, crypto, LeafIndex(1), nil)
	if _, err := NewProposalCache().Store(crypto, empty); !errors.Is(err, errProposalCacheNotAProposal) {
		t.Errorf("Store of a proposal content with no proposal = %v, want errProposalCacheNotAProposal", err)
	}
}

// TestTheCacheRunsTheV1ProfileGateOnBothDoors is the parse boundary this plan gives the profile:
// the three registered types v1 does not implement, and every unregistered one, stop at the cache
// rather than at the codec.
func TestTheCacheRunsTheV1ProfileGateOnBothDoors(t *testing.T) {
	crypto := testCrypto(t)
	psk := &Proposal{ProposalType: ProposalTypePreSharedKey, PreSharedKey: &PreSharedKey{}}
	if _, err := NewProposalCache().Store(crypto,
		testProposalContent(t, crypto, LeafIndex(1), psk)); !errors.Is(err, errProfilePsk) {
		t.Errorf("Store of a psk proposal = %v, want errProfilePsk", err)
	}
	if _, err := NewProposalCache().Resolve(crypto, LeafIndex(0), []ProposalOrRef{{
		Type: ProposalOrRefTypeProposal, Proposal: psk}}); !errors.Is(err, errProfilePsk) {
		t.Errorf("Resolve of an inline psk proposal = %v, want errProfilePsk", err)
	}
	grease := &Proposal{ProposalType: ProposalType(0x0A0A), UnknownBody: []byte{1, 2}}
	if _, err := NewProposalCache().Resolve(crypto, LeafIndex(0), []ProposalOrRef{{
		Type: ProposalOrRefTypeProposal, Proposal: grease}}); !errors.Is(err, errUnsupportedProposalType) {
		t.Errorf("Resolve of an inline GREASE proposal = %v, want errUnsupportedProposalType", err)
	}
}

// TestResolveRefusesEveryProposalOrRefShapeTheCodecRefuses is what says the cache reaches
// ProposalOrRef.checkArm rather than restating a subset of it. The empty reference is the one
// that matters most here: it is wire legal, it is the encoding of "no reference", and a cache
// that looked it up would key every commit that made the same mistake to one entry.
func TestResolveRefusesEveryProposalOrRefShapeTheCodecRefuses(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	ref := testStoredRemove(t, crypto, cache, LeafIndex(1), LeafIndex(4))
	for name, entry := range map[string]ProposalOrRef{
		"an unregistered discriminant": {Type: ProposalOrRefType(7), Reference: ref},
		"the reserved discriminant":    {Type: ProposalOrRefTypeReserved, Reference: ref},
		"both arms populated":          {Type: ProposalOrRefTypeReference, Reference: ref, Proposal: testRemoveProposal(1)},
		"no arm at all":                {Type: ProposalOrRefTypeProposal},
		"a reference of no octets":     {Type: ProposalOrRefTypeReference, Reference: ProposalRef{}},
	} {
		if _, err := cache.Resolve(crypto, LeafIndex(0), []ProposalOrRef{entry}); err == nil {
			t.Errorf("Resolve accepted %s", name)
		}
	}
}

// ---------------------------------------------------------------------------
// what the cache offers a committer
// ---------------------------------------------------------------------------

// TestPendingAnswersEveryEntryOnceInReceptionOrder holds the SHOULD of section 12.4 and the
// order Add placement depends on. Storing one proposal twice is the idempotence half: a reference
// is an identity, so the second store is the same entry rather than a second one.
func TestPendingAnswersEveryEntryOnceInReceptionOrder(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	first := testStoredRemove(t, crypto, cache, LeafIndex(1), LeafIndex(4))
	second := testStoredRemove(t, crypto, cache, LeafIndex(2), LeafIndex(5))
	again := testStoredRemove(t, crypto, cache, LeafIndex(1), LeafIndex(4))
	if !slices.Equal([]byte(first), []byte(again)) {
		t.Fatal("one proposal stored twice answered two references")
	}
	pending := cache.Pending()
	if len(pending) != 2 {
		t.Fatalf("Pending answers %d entries after three stores of two proposals, want 2", len(pending))
	}
	for i, want := range []ProposalRef{first, second} {
		if pending[i].Type != ProposalOrRefTypeReference {
			t.Errorf("Pending entry %d is type %d, want a reference", i, pending[i].Type)
		}
		if !slices.Equal([]byte(pending[i].Reference), []byte(want)) {
			t.Errorf("Pending entry %d names %x, want %x", i, pending[i].Reference, want)
		}
	}
	// and what Pending answers resolves, which is the whole of what a committer does with it
	list, err := cache.Resolve(crypto, LeafIndex(0), pending)
	if err != nil {
		t.Fatalf("Resolve of the pending vector: %v", err)
	}
	if len(list.Removes) != 2 || list.Removes[0].Proposal.Remove.Removed != 4 ||
		list.Removes[1].Proposal.Remove.Removed != 5 {
		t.Errorf("the pending vector resolved to %+v", list.Removes)
	}
}
