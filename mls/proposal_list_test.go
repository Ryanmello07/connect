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
	"errors"
	"go/ast"
	"go/token"
	"maps"
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
