// The p7 task 14 tests: what a GroupInfo signature covers, and what (*GroupInfo).Verify
// establishes about a GroupInfo that arrived from somebody else.
//
// The property the whole file is written around is one sentence: a GroupInfo does not verify
// unless a MEMBER OF THE TREE signed it. Everything downstream that reads a GroupInfo's group
// context as an epoch somebody agreed to is standing on that sentence, and until welcome.go
// landed nothing in this build checked a GroupInfo signature at all -- so the tests that matter
// most here are the adversarial ones, and they are built rather than described:
// TestAGroupInfoDoesNotVerifyUnlessAMemberOfTheTreeSignedIt mints a group info signed by
// somebody else's key at a leaf that is not theirs, one signed by a key in no leaf, one
// carrying a signature that is perfectly valid over a DIFFERENT group info, and one carrying a
// signature its own signer made under another label. Each of them verifies against a signature
// check that has any of the four usual holes in it.
//
// Two of the sweeps are derived off the source rather than written down, because the two
// defects they are for are invisible to every behavioural test in this package.
//
//   - TestTheGroupInfoSignatureCoversEveryFieldOfItsToBeSigned reads the FIELDS off
//     GroupInfoTBS, so a field added to the structure joins the sweep on the commit that adds
//     it. A preimage that omits a field is the classic signature defect: the object carries the
//     field, the preimage does not, an attacker rewrites it in flight and the signature still
//     verifies -- and both halves round trip byte exactly on their own, so nothing else here
//     could see it.
//   - TestTheGroupInfoPreimageIsAssembledInExactlyOnePlace reads every composite literal of
//     GroupInfoTBS in the package's production source. A second assembly is how the omission
//     above gets written in the first place, and it agrees with itself perfectly for as long as
//     the two field lists happen to match.
//
// And the refusals are held apart rather than merely present:
// TestEachRuleOfGroupInfoVerifyAnswersItsOwnSentinel reads the sentinels off Verify's own body
// and drives one case per rule, so a body that collapsed two rules onto one value fails here
// rather than leaving every assertion in the area able to pass over the rule it was not
// written for.
package mls

import (
	"bytes"
	"errors"
	"go/ast"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// The group this file's fixture describes. A literal rather than testGroupId(), because
// newTestTree signs its leaves under testGroupId and a group info naming the same thing would
// make a leaf signature and a group info signature agree about a value neither of them
// separately pins.
const welcomeTestGroupId = "the group this info describes"

// testGroupInfoOverTree is an unsigned GroupInfo that names this tree at this epoch.
//
// The tree hash is taken from the tree AS IT STANDS, so a caller that blanks a leaf must build
// the group info afterwards; a fixture that hashed a tree the group info is not going to be
// verified against would make every case below refuse for the fixture's reason rather than for
// its own.
//
// Both extension vectors are non empty, and that is load bearing for the coverage sweep rather
// than decoration: an empty vector is one whose omission from the preimage no mutation of this
// fixture could see, so a sweep run against a fixture with no extensions would report the
// extensions field covered while saying nothing at all.
func testGroupInfoOverTree(t *testing.T, crypto CryptoProvider, tree *RatchetTree,
	signer LeafIndex) *GroupInfo {
	t.Helper()
	treeHash, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	return &GroupInfo{
		GroupContext: GroupContext{
			Version:                 ProtocolVersionMls10,
			CipherSuite:             CipherSuiteX25519ChaCha20Sha256Ed25519,
			GroupId:                 []byte(welcomeTestGroupId),
			Epoch:                   7,
			TreeHash:                treeHash,
			ConfirmedTranscriptHash: bytes.Repeat([]byte{0x31}, crypto.HashSize()),
			Extensions: []Extension{{
				ExtensionType: ExtensionTypeUrmessageGroupPolicy,
				ExtensionData: []byte{0x01, 0x02, 0x03},
			}},
		},
		Extensions: []Extension{{
			ExtensionType: ExtensionTypeRequiredCapabilities,
			ExtensionData: []byte{0x04, 0x05},
		}},
		ConfirmationTag: bytes.Repeat([]byte{0x32}, crypto.HashSize()),
		Signer:          signer,
	}
}

// signedTestGroupInfo is the same fixture, signed by one member's own key at the leaf it names.
func signedTestGroupInfo(t *testing.T, crypto CryptoProvider, tree *RatchetTree,
	members []*testTreeMember, signer LeafIndex) *GroupInfo {
	t.Helper()
	info := testGroupInfoOverTree(t, crypto, tree, signer)
	if err := info.Sign(crypto, members[signer].SignaturePriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return info
}

// TestGroupInfoSignAndVerify is the round trip through the pair, and the positive control every
// refusal below is measured against: without it a Verify that refused everything would satisfy
// every other test in this file.
func TestGroupInfoSignAndVerify(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 4)
	for _, signer := range []LeafIndex{0, 1, 2, 3} {
		info := signedTestGroupInfo(t, crypto, tree, members, signer)
		if len(info.Signature) == 0 {
			t.Fatalf("signer %d: Sign produced no signature", signer)
		}
		if err := info.Verify(crypto, tree); err != nil {
			t.Errorf("signer %d: Verify = %v, want nil", signer, err)
		}
	}
}

// TestGroupInfoSigningTwiceAnswersTheSameSignature is the "the signature is not part of what is
// signed" claim, asked the only way an input can ask it.
//
// The suite's signature scheme is deterministic, so two signatures over one preimage are byte
// identical. A preimage that included the signature field would therefore answer DIFFERENT
// bytes the second time -- the first signature is in the second one's input -- and that is a
// defect no sign-then-verify test can see, because such an implementation still verifies
// whatever it just signed.
func TestGroupInfoSigningTwiceAnswersTheSameSignature(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 2)
	info := signedTestGroupInfo(t, crypto, tree, members, LeafIndex(0))
	first := bytes.Clone(info.Signature)
	if err := info.Sign(crypto, members[0].SignaturePriv); err != nil {
		t.Fatalf("Sign a second time: %v", err)
	}
	if !bytes.Equal(first, info.Signature) {
		t.Errorf("signing twice over one group info answered %x then %x, so the signature field is part of its own preimage",
			first, info.Signature)
	}
}

// TestGroupInfoVerifyRejectsATamperedField is the plainest statement of the rule: a field
// altered after signing is refused, with the signature sentinel and not with some other one.
func TestGroupInfoVerifyRejectsATamperedField(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 4)
	info := signedTestGroupInfo(t, crypto, tree, members, LeafIndex(0))
	info.GroupContext.Epoch = 8
	if err := info.Verify(crypto, tree); !errors.Is(err, ErrWelcomeGroupInfoSignature) {
		t.Fatalf("Verify over a rewritten epoch = %v, want ErrWelcomeGroupInfoSignature", err)
	}
}

// groupInfoTbsFieldPaths is every field of GroupInfoTBS, one path per LEAF field: a struct field
// is descended into, so the group context's own fields are read one at a time rather than as a
// single lump that one change to one of them would report covered.
//
// Read off the TYPE and not typed out, so a field added to either structure joins the sweep on
// the commit that adds it rather than on the commit somebody remembers to edit a list.
func groupInfoTbsFieldPaths(at reflect.Type, prefix string) []string {
	paths := []string{}
	for i := 0; i < at.NumField(); i++ {
		field := at.Field(i)
		name := prefix + field.Name
		if field.Type.Kind() == reflect.Struct {
			paths = append(paths, groupInfoTbsFieldPaths(field.Type, name+".")...)
			continue
		}
		paths = append(paths, name)
	}
	return paths
}

// changeGroupInfoField changes the value at one of those paths, by KIND rather than by name.
//
// Deriving the change from the kind is what lets the paths be derived from the type: a rule
// written per field name would have to be extended by hand for the next field, which is the
// list this file is avoiding. A kind the sweep does not know how to change is a failure rather
// than a skip, for the same reason -- a silently skipped field is a field reported covered.
func changeGroupInfoField(t *testing.T, info *GroupInfo, path string) {
	t.Helper()
	value := reflect.ValueOf(info).Elem()
	for _, name := range strings.Split(path, ".") {
		value = value.FieldByName(name)
		if !value.IsValid() {
			t.Fatalf("a GroupInfo carries no field %s, so its preimage names a field the object does not", path)
		}
	}
	switch value.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value.SetUint(value.Uint() + 1)
	case reflect.Slice:
		if value.Len() == 0 {
			t.Fatalf("the fixture's %s is empty, so nothing this sweep can do to it changes the preimage", path)
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			// a fresh array rather than a write through the fixture's own, so the sweep cannot
			// change a value some earlier row is still holding
			flipped := bytes.Clone(value.Bytes())
			flipped[0] ^= 0xff
			value.SetBytes(flipped)
			return
		}
		value.Set(value.Slice(0, value.Len()-1))
	default:
		t.Fatalf("the sweep has no change for a %s, which is what %s is", value.Kind(), path)
	}
}

// TestTheGroupInfoSignatureCoversEveryFieldOfItsToBeSigned is RFC 9420 section 12.4.3's "the
// signature covers every field above signature", asked of every one of those fields.
//
// Two claims per field, and they are not the same claim. The PREIMAGE has to move, which is the
// direct reading of "covers": a field the preimage does not encode is a field an attacker
// rewrites with the signature still verifying, and it is invisible to a round trip because the
// object and the preimage each round trip perfectly on their own. And Verify has to REFUSE,
// which is the consequence a caller depends on.
//
// The other half of the section's sentence is asked structurally at the end: every field of
// GroupInfo except the signature itself is a field of GroupInfoTBS. A field added to the wire
// type and not to the preimage type is exactly the defect above, arriving one type earlier.
func TestTheGroupInfoSignatureCoversEveryFieldOfItsToBeSigned(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 4)
	paths := groupInfoTbsFieldPaths(reflect.TypeOf(GroupInfoTBS{}), "")
	if len(paths) < 4 {
		t.Fatalf("the preimage's fields read as %v, which is fewer than GroupInfoTBS declares, so this sweep holds almost nothing",
			paths)
	}
	for _, path := range paths {
		info := signedTestGroupInfo(t, crypto, tree, members, LeafIndex(0))
		before, err := info.signaturePreimage()
		if err != nil {
			t.Fatalf("%s: the preimage of the unaltered fixture: %v", path, err)
		}
		changeGroupInfoField(t, info, path)
		after, err := info.signaturePreimage()
		if err != nil {
			t.Errorf("%s: the preimage after the change: %v", path, err)
			continue
		}
		if bytes.Equal(before, after) {
			t.Errorf("%s: changing it left the signature preimage byte identical, so no signature covers that field",
				path)
		}
		if err := info.Verify(crypto, tree); err == nil {
			t.Errorf("%s: Verify accepted a group info whose %s was rewritten after signing", path, path)
		}
	}
	// the same sentence read off the two types rather than off an input: a field of the wire
	// structure that is not a field of the preimage is a field nobody's signature covers, and it
	// would pass the whole sweep above because the sweep reads the preimage's fields
	carried := []string{}
	for i := 0; i < reflect.TypeOf(GroupInfo{}).NumField(); i++ {
		name := reflect.TypeOf(GroupInfo{}).Field(i).Name
		if name == "Signature" {
			continue
		}
		carried = append(carried, name)
	}
	signed := []string{}
	for i := 0; i < reflect.TypeOf(GroupInfoTBS{}).NumField(); i++ {
		signed = append(signed, reflect.TypeOf(GroupInfoTBS{}).Field(i).Name)
	}
	if !slices.Equal(carried, signed) {
		t.Errorf("a GroupInfo carries %v above its signature and its GroupInfoTBS covers %v", carried, signed)
	}
}

// TestTheGroupInfoPreimageIsAssembledInExactlyOnePlace reads every composite literal of
// GroupInfoTBS the package's production source builds.
//
// A second assembly of one preimage is the defect the sweep above can only see once the two
// field lists have already come apart: two assemblies that agree today agree with themselves
// perfectly, and the day a field is added to one of them the other one silently stops covering
// it. welcome_wire.go's (*GroupInfo).toBeSigned is the one description of what a GroupInfo
// signature covers, MarshalMLS goes through it, and welcome.go's signing and verifying halves
// go through it -- so the count that keeps that true is one.
//
// The class is read off the syntax rather than off a list of files, so an assembly written into
// any production file of this package, in any declaration, is found.
func TestTheGroupInfoPreimageIsAssembledInExactlyOnePlace(t *testing.T) {
	found := []string{}
	for _, parsed := range parsedProductionSourcesOfThisPackage(t) {
		for _, declaration := range parsed.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				literal, isLiteral := node.(*ast.CompositeLit)
				if !isLiteral || literal.Type == nil {
					return true
				}
				named, isNamed := literal.Type.(*ast.Ident)
				if !isNamed || named.Name != "GroupInfoTBS" {
					return true
				}
				where := filepath.Base(parsed.fileSet.Position(literal.Pos()).Filename)
				found = append(found, where+" "+parsed.receiverOf(function)+"."+function.Name.Name)
				return true
			})
		}
	}
	slices.Sort(found)
	if !slices.Equal(found, []string{"welcome_wire.go *GroupInfo.toBeSigned"}) {
		t.Errorf("this package assembles a GroupInfoTBS at %v, and one preimage has exactly one assembly",
			found)
	}
}

// TestAGroupInfoDoesNotVerifyUnlessAMemberOfTheTreeSignedIt is the property this whole file is
// written around, driven with the four shapes a signature check with a hole in it accepts.
//
// Each row is a group info a peer could actually send. The first is the substitution the signer
// index exists to prevent -- a signature by a real member, claiming a leaf that is not theirs --
// and a Verify that took its key from anywhere but the leaf it was told to accepts it. The
// second is signed by a key in no leaf at all, which is what a Verify that trusted a key carried
// in the message accepts. The third carries a signature that is perfectly valid, over a
// different group info, which is what a Verify that rebuilt its preimage from the wrong fields
// accepts. The fourth carries one made by the right key over the right bytes under another
// label, which is what a Verify that dropped the label accepts.
func TestAGroupInfoDoesNotVerifyUnlessAMemberOfTheTreeSignedIt(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 4)

	// the positive control, so nothing below passes because Verify refuses everything
	if err := signedTestGroupInfo(t, crypto, tree, members, LeafIndex(0)).Verify(crypto, tree); err != nil {
		t.Fatalf("the honest group info was refused with %v, so every refusal below says nothing", err)
	}

	rows := []struct {
		name  string
		build func(t *testing.T) *GroupInfo
	}{{
		name: "signed by another member of the tree, naming a leaf that is not theirs",
		build: func(t *testing.T) *GroupInfo {
			info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
			if err := info.Sign(crypto, members[2].SignaturePriv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			return info
		},
	}, {
		name: "signed by a key that sits in no leaf of this tree",
		build: func(t *testing.T) *GroupInfo {
			stranger, _, err := crypto.SignatureKeyPair()
			if err != nil {
				t.Fatalf("SignatureKeyPair: %v", err)
			}
			info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
			if err := info.Sign(crypto, stranger); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			return info
		},
	}, {
		name: "carrying a signature that is valid over a different group info",
		build: func(t *testing.T) *GroupInfo {
			other := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
			other.GroupContext.Epoch = 8
			if err := other.Sign(crypto, members[0].SignaturePriv); err != nil {
				t.Fatalf("Sign the other group info: %v", err)
			}
			info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
			info.Signature = other.Signature
			return info
		},
	}, {
		name: "carrying a signature its own signer made over these bytes under another label",
		build: func(t *testing.T) *GroupInfo {
			info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
			content, err := info.signaturePreimage()
			if err != nil {
				t.Fatalf("the preimage: %v", err)
			}
			signature, err := crypto.SignWithLabel(members[0].SignaturePriv, leafNodeSignatureLabel, content)
			if err != nil {
				t.Fatalf("SignWithLabel: %v", err)
			}
			info.Signature = signature
			return info
		},
	}}

	for _, row := range rows {
		err := row.build(t).Verify(crypto, tree)
		if err == nil {
			t.Errorf("a group info %s VERIFIED; the whole provenance line rests on it not doing so", row.name)
			continue
		}
		if !errors.Is(err, ErrWelcomeGroupInfoSignature) {
			t.Errorf("a group info %s answered %v, want ErrWelcomeGroupInfoSignature", row.name, err)
		}
	}
}

// groupInfoVerifySentinels is the roster the rule sweep is held against: the sentinel name
// Verify's own source answers, paired with the value the test can ask errors.Is about.
//
// The names are not what decides the class. groupInfoVerifySentinelNames reads them off the
// body, and the sweep compares the two rosters in both directions, so a rule added to Verify
// with no row here fails and a row naming a refusal Verify no longer makes fails as well.
func groupInfoVerifySentinels() map[string]error {
	return map[string]error{
		"ErrNilCryptoProvider":          ErrNilCryptoProvider,
		"ErrTreeMalformed":              ErrTreeMalformed,
		"ErrUnsupportedVersion":         ErrUnsupportedVersion,
		"errGroupInfoProviderSuite":     errGroupInfoProviderSuite,
		"ErrWelcomeTreeHashMismatch":    ErrWelcomeTreeHashMismatch,
		"ErrLeafIndexOutOfRange":        ErrLeafIndexOutOfRange,
		"errBlankSenderLeaf":            errBlankSenderLeaf,
		"errGroupInfoPreimage":          errGroupInfoPreimage,
		"ErrWelcomeGroupInfoSignature":  ErrWelcomeGroupInfoSignature,
		"ErrMalformedExtension":         ErrMalformedExtension,
		"ErrWelcomeCarriedTreeMismatch": ErrWelcomeCarriedTreeMismatch,
	}
}

// groupInfoVerifySentinelNames is every package level variable (*GroupInfo).Verify returns,
// read off welcome.go's own syntax.
//
// The roster of package level names is collected over every production file before this body is
// read, for the reason nil_argument_test.go's own collection states: a sentinel is regularly
// declared in one file and answered in another -- errBlankSenderLeaf is framing_protect.go's
// and is answered here -- and a per file roster would read that return as an unknown identifier
// and drop it, which is the silent shrink every derivation in this package is written against.
func groupInfoVerifySentinelNames(t *testing.T) []string {
	t.Helper()
	declared := []string{}
	for _, path := range packageLevelFunctions(t).files {
		declared = append(declared, packageLevelVarNamesIn(mustParseSource(t, path))...)
	}
	parsed := mustParseSource(t, "welcome.go")
	names := []string{}
	ast.Inspect(parsed.declarationOf(t, "*GroupInfo", "Verify").Body, func(node ast.Node) bool {
		returned, isReturn := node.(*ast.ReturnStmt)
		if !isReturn {
			return true
		}
		for _, result := range returned.Results {
			ast.Inspect(result, func(inner ast.Node) bool {
				identifier, isIdentifier := inner.(*ast.Ident)
				if isIdentifier && slices.Contains(declared, identifier.Name) &&
					!slices.Contains(names, identifier.Name) {
					names = append(names, identifier.Name)
				}
				return true
			})
		}
		return true
	})
	slices.Sort(names)
	return names
}

// TestEachRuleOfGroupInfoVerifyAnswersItsOwnSentinel is the "four rules, four answers" claim,
// with the rules read off Verify's body rather than listed here.
//
// A rule that answered another rule's value would be a rule no test in this package could
// observe: errors.Is cannot tell two rules apart when they share a value, so an assertion
// written for one of them passes over the other firing instead. This project has shipped that
// defect repeatedly, which is why it is held three ways at once -- the roster is compared
// against the source in both directions, the values are held to being pairwise distinct, and
// every case is required to answer its own sentinel AND none of the others.
func TestEachRuleOfGroupInfoVerifyAnswersItsOwnSentinel(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 4)

	// the blank leaf case gets a tree of its own, blanked BEFORE its group info is built, so its
	// group context names the tree it is verified against and the blank leaf is the only thing
	// wrong with it
	blanked := tree.Clone()
	if err := blanked.Blank(LeafIndex(2).NodeIndex()); err != nil {
		t.Fatalf("Blank leaf 2: %v", err)
	}
	// a second tree, whose leaves are other people's, for the tree hash case
	elsewhere, _ := newTestTree(t, crypto, 4)

	cases := map[string]func(t *testing.T) error{
		"ErrNilCryptoProvider": func(t *testing.T) error {
			return signedTestGroupInfo(t, crypto, tree, members, LeafIndex(0)).Verify(nil, tree)
		},
		"ErrTreeMalformed": func(t *testing.T) error {
			return signedTestGroupInfo(t, crypto, tree, members, LeafIndex(0)).Verify(crypto, nil)
		},
		"ErrWelcomeTreeHashMismatch": func(t *testing.T) error {
			return signedTestGroupInfo(t, crypto, tree, members, LeafIndex(0)).Verify(crypto, elsewhere)
		},
		"ErrLeafIndexOutOfRange": func(t *testing.T) error {
			beyond := LeafIndex(tree.LeafWidth())
			info := testGroupInfoOverTree(t, crypto, tree, beyond)
			if err := info.Sign(crypto, members[0].SignaturePriv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			return info.Verify(crypto, tree)
		},
		"errBlankSenderLeaf": func(t *testing.T) error {
			info := testGroupInfoOverTree(t, crypto, blanked, LeafIndex(2))
			if err := info.Sign(crypto, members[2].SignaturePriv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			return info.Verify(crypto, blanked)
		},
		"ErrWelcomeGroupInfoSignature": func(t *testing.T) error {
			info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
			if err := info.Sign(crypto, members[1].SignaturePriv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			return info.Verify(crypto, tree)
		},
		// rules 2 and 3 are signed by a REAL member at the leaf they name, which is the whole
		// point of them: the version and the suite are inside GroupInfoTBS, so what these drive
		// is a member committing to a version or a suite the verifier is not running, with a
		// signature over it that is perfectly good.
		"ErrUnsupportedVersion": func(t *testing.T) error {
			info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
			info.GroupContext.Version = ProtocolVersion(0x4242)
			if err := info.Sign(crypto, members[0].SignaturePriv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			return info.Verify(crypto, tree)
		},
		"errGroupInfoProviderSuite": func(t *testing.T) error {
			info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
			info.GroupContext.CipherSuite = CipherSuite(0xbeef)
			if err := info.Sign(crypto, members[0].SignaturePriv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			return info.Verify(crypto, tree)
		},
		// nothing signs this one and nothing could: one labelled field holds MaxVectorLength, so
		// this group info has no to-be-signed encoding at all, which is the fault rule 7 is for
		// and is exactly why it is not a signature refusal
		"errGroupInfoPreimage": func(t *testing.T) error {
			info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
			info.Extensions = []Extension{{
				ExtensionType: ExtensionTypeApplicationId,
				ExtensionData: make([]byte, syntax.MaxVectorLength+1),
			}}
			return info.Verify(crypto, tree)
		},
		"ErrMalformedExtension": func(t *testing.T) error {
			carried, err := tree.Encode()
			if err != nil {
				t.Fatalf("encode this tree as a ratchet_tree extension: %v", err)
			}
			info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
			info.Extensions = []Extension{carried, carried}
			if err := info.Sign(crypto, members[0].SignaturePriv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			return info.Verify(crypto, tree)
		},
		"ErrWelcomeCarriedTreeMismatch": func(t *testing.T) error {
			carried, err := elsewhere.Encode()
			if err != nil {
				t.Fatalf("encode the other tree as a ratchet_tree extension: %v", err)
			}
			info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
			info.Extensions = []Extension{carried}
			if err := info.Sign(crypto, members[0].SignaturePriv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			return info.Verify(crypto, tree)
		},
	}

	roster := groupInfoVerifySentinels()
	if named := slices.Sorted(maps.Keys(roster)); !slices.Equal(named, groupInfoVerifySentinelNames(t)) {
		t.Fatalf("(*GroupInfo).Verify answers %v and this gate knows of %v",
			groupInfoVerifySentinelNames(t), named)
	}
	if driven := slices.Sorted(maps.Keys(cases)); !slices.Equal(driven, slices.Sorted(maps.Keys(roster))) {
		t.Fatalf("the cases below drive %v and the roster names %v", driven, slices.Sorted(maps.Keys(roster)))
	}

	// the values themselves, pairwise: two names for one error is one rule wearing two hats, and
	// every assertion below would then pass over the wrong rule firing
	for _, one := range slices.Sorted(maps.Keys(roster)) {
		for _, other := range slices.Sorted(maps.Keys(roster)) {
			if one == other {
				continue
			}
			if errors.Is(roster[one], roster[other]) {
				t.Errorf("%s and %s are one value as far as errors.Is is concerned, so no test can tell those two rules apart",
					one, other)
			}
		}
	}

	for _, name := range slices.Sorted(maps.Keys(cases)) {
		answered := cases[name](t)
		if !errors.Is(answered, roster[name]) {
			t.Errorf("the %s rule answered %v", name, answered)
			continue
		}
		for _, other := range slices.Sorted(maps.Keys(roster)) {
			if other == name {
				continue
			}
			if errors.Is(answered, roster[other]) {
				t.Errorf("the %s rule answered %v, which is also %s, so the two rules cannot be told apart",
					name, answered, other)
			}
		}
	}
}

// TestGroupInfoVerifyComparesTheWholeTreeHash holds the tree hash rule to the WHOLE value.
//
// The rule that a group info names the tree it is verified against is only worth having if it
// reads the whole hash. A comparison of a prefix, or one that skipped an empty value, refuses a
// tree drawn at random almost every time -- so the "verified against another tree" case next
// door passes over it 255 times in 256, which is a test that reports a clean run and holds
// nothing. Measured, not supposed: with the comparison rewritten to read the first octet only,
// the whole of this file passed.
//
// Every row is DERIVED from the tree's own hash rather than from a value written here, so each
// of them differs from the right answer in exactly the one way it names.
//
// The sentinel is asserted and not merely a refusal, which is also what pins the ORDER: these
// group infos have had a field rewritten after signing, so a body that verified the signature
// first would refuse them all with ErrWelcomeGroupInfoSignature and this test would say nothing
// about the tree hash at all.
func TestGroupInfoVerifyComparesTheWholeTreeHash(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 4)
	right, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	if len(right) < 2 {
		t.Fatalf("the tree hash is %d octets, so none of the rows below is a different value", len(right))
	}
	rows := map[string][]byte{
		"its last octet flipped":     append(bytes.Clone(right[:len(right)-1]), right[len(right)-1]^0xff),
		"truncated by one octet":     bytes.Clone(right[:len(right)-1]),
		"extended by one octet":      append(bytes.Clone(right), 0x00),
		"empty":                      {},
		"a run of zeros of its size": make([]byte, len(right)),
	}
	for _, name := range slices.Sorted(maps.Keys(rows)) {
		info := signedTestGroupInfo(t, crypto, tree, members, LeafIndex(0))
		info.GroupContext.TreeHash = rows[name]
		if err := info.Verify(crypto, tree); !errors.Is(err, ErrWelcomeTreeHashMismatch) {
			t.Errorf("a group info naming the tree hash %s answered %v, want ErrWelcomeTreeHashMismatch",
				name, err)
		}
	}
}

// TestAGroupInfoCarryingThisProductsTreeCannotBeSigned records the one size this pair refuses,
// as a measurement rather than as a sentence in a comment.
//
// welcome_wire_test.go measured the codec half: a GroupInfo carrying the ratchet_tree extension
// of the group MASTER sizes this product for is about 1.33 MiB, and it needs
// MaxRatchetTreeLength in all four directions. This is the same measurement made of the
// SIGNATURE, and its answer is different, because the signature preimage becomes one labelled
// field and checkLabelledFieldLength caps a labelled field at MaxVectorLength. So the raised
// bound the codec can be opened at has no counterpart here: signing such a group info is refused
// by the encode, and would be refused by the provider one frame later if the encode let it past.
//
// What that means for p7's remaining tasks, and the reason this is a measurement rather than a
// defect: a GroupInfo does not have to carry the tree. (*GroupInfo).Verify takes the
// *RatchetTree as an argument exactly because the signer's key comes from a tree the joiner
// obtained rather than from the message, so a Welcome that distributes the tree beside the
// group info signs and verifies at any group size this product supports. A group info that
// EMBEDS the tree is the shape that does not, and this is where that is written down.
//
// ErrLengthExceedsMax and not merely an error: a refusal for any other reason would be a
// fixture that had stopped being the thing measured. The size is asserted first for the same
// reason -- a fixture that shrank below the cap would leave this passing while measuring
// nothing.
func TestAGroupInfoCarryingThisProductsTreeCannotBeSigned(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, productGroupLeafCount)
	extension, err := tree.Encode()
	if err != nil {
		t.Fatalf("encode a %d leaf ratchet tree as an extension: %v", productGroupLeafCount, err)
	}
	info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
	info.Extensions = []Extension{extension}
	if len(extension.ExtensionData) <= syntax.MaxVectorLength {
		t.Fatalf("this product's ratchet_tree body is %d octets and one labelled field holds %d, so nothing below measures the cap",
			len(extension.ExtensionData), syntax.MaxVectorLength)
	}
	t.Logf("a group info carrying this product's %d leaf tree carries a %d octet tree body; one labelled field holds %d",
		productGroupLeafCount, len(extension.ExtensionData), syntax.MaxVectorLength)
	if err := info.Sign(crypto, members[0].SignaturePriv); !errors.Is(err, syntax.ErrLengthExceedsMax) {
		t.Errorf("signing a group info carrying this product's own tree answered %v, want ErrLengthExceedsMax", err)
	}
	// and the same group info WITHOUT the embedded tree signs and verifies at that group size,
	// which is what says the refusal above is the extension's and not the size of the group
	beside := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
	if err := beside.Sign(crypto, members[0].SignaturePriv); err != nil {
		t.Fatalf("signing a %d leaf group's info with the tree distributed beside it: %v",
			productGroupLeafCount, err)
	}
	if err := beside.Verify(crypto, tree); err != nil {
		t.Errorf("verifying a %d leaf group's info with the tree distributed beside it: %v",
			productGroupLeafCount, err)
	}
}

// TestTheGroupInfoSignatureLabelIsTheRfcStringAndIsItsOwn pins the label two ways.
//
// The constant against the literal, because a label spelled one way in both halves of this
// package agrees with itself perfectly and with no other implementation: ed25519 signs whatever
// preimage it is handed, and only a peer can tell "GroupInfoTBS" from "GroupInfoTbs". And the
// constant against the OTHER labels this package signs under, because a group info signature
// that were also a valid LeafNodeTBS or KeyPackageTBS signature by the same key is a signature
// over one structure accepted as a signature over another.
//
// The behavioural half is what makes the first one more than a tautology: a signature made here
// under the RFC's own literal, with no reference to the constant at all, has to verify. A
// constant changed in both halves of welcome.go passes the pin above only if the pin reads the
// literal, and passes this only if the literal is what a peer would use.
func TestTheGroupInfoSignatureLabelIsTheRfcStringAndIsItsOwn(t *testing.T) {
	if groupInfoSignatureLabel != "GroupInfoTBS" {
		t.Errorf("the group info signature label is %q, and RFC 9420 section 12.4.3 says GroupInfoTBS",
			groupInfoSignatureLabel)
	}
	for _, other := range []string{leafNodeSignatureLabel, keyPackageSignatureLabel,
		framedContentTBSLabel, updatePathNodeLabel, "GroupInfoTbs", ""} {
		if other == groupInfoSignatureLabel {
			t.Errorf("the group info label is also %q, so a signature over one structure is a signature over another",
				other)
		}
	}
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 2)
	info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
	content, err := info.signaturePreimage()
	if err != nil {
		t.Fatalf("the preimage: %v", err)
	}
	signature, err := crypto.SignWithLabel(members[0].SignaturePriv, "GroupInfoTBS", content)
	if err != nil {
		t.Fatalf("SignWithLabel: %v", err)
	}
	info.Signature = signature
	if err := info.Verify(crypto, tree); err != nil {
		t.Errorf("a signature made under the literal \"GroupInfoTBS\" was refused with %v, so this package signs under a label of its own",
			err)
	}
}

// TestGroupInfoRoundTripThenVerify is the wire half: a signed group info survives an encode and
// a decode byte exactly, and the decoded object still verifies.
//
// The re-encode is compared rather than the struct, because what a peer verifies is the bytes
// it received: a decoder that dropped or reordered a field would produce an object that still
// verifies against a preimage its own encoder rebuilt, and only the byte comparison sees it.
func TestGroupInfoRoundTripThenVerify(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 2)
	info := signedTestGroupInfo(t, crypto, tree, members, LeafIndex(1))
	encoded, err := syntax.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed := GroupInfo{}
	if err := syntax.Unmarshal(encoded, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reencoded, err := syntax.Marshal(&parsed)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("the re-encode is %x and the original is %x", reencoded, encoded)
	}
	if err := parsed.Verify(crypto, tree); err != nil {
		t.Errorf("Verify after a round trip = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// p7 task 14, second pass: the four gaps a review measured in this pair, and the forgery the
// joiner task is about to build.
//
// Each test below exists because a MUTATION of the production body survived the whole suite.
// That is the standard the file's own header sets -- a test that cannot fail is a clean run over
// nothing -- and the four survivors were: a Verify that answered nil for an empty signature, a
// Sign that wrote only into an empty Signature, a signer bound taken from the tree's MEMBER
// COUNT rather than its leaf width, and a Verify that accepted any ciphersuite and any protocol
// version. The fifth thing here is not a mutation at all: it is the shape p7 task 16 will write
// if the precondition on Verify goes unread, asserted as the fact it is.
// ---------------------------------------------------------------------------

// TestAGroupInfoCarryingNoSignatureAtAllIsRefused is finding 2, and the reason it is written at
// all is that `if len(self.Signature) == 0 { return nil }` inserted into Verify passed the full
// suite at 6805 tests.
//
// Every existing negative case in this file supplies a real 64 octet signature, so nothing in
// the package asked what happens to a group info carrying none. Production was already correct
// -- VerifyWithLabel refuses it -- but an empty signature<V> is a WIRE-LEGAL encoding a peer can
// send: syntax.Unmarshal accepts it and yields len(Signature) == 0. So the object is built here
// AND taken off the wire, because the wire is where it comes from, and a fixture assembled in
// memory would leave the decoder's half of the claim untested.
//
// The lengths are swept rather than the empty case alone. What must not decide the answer is the
// LENGTH: a body that refused only the empty vector, or only anything shorter than a signature,
// would pass an empty-signature test while accepting 64 octets of zeros, and the object a peer
// actually sends is whichever of those the peer prefers.
func TestAGroupInfoCarryingNoSignatureAtAllIsRefused(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 4)

	// the positive control, so nothing below passes because Verify refuses everything
	honest := signedTestGroupInfo(t, crypto, tree, members, LeafIndex(0))
	if err := honest.Verify(crypto, tree); err != nil {
		t.Fatalf("the honest group info was refused with %v, so every refusal below says nothing", err)
	}
	real := bytes.Clone(honest.Signature)
	if len(real) == 0 {
		t.Fatal("the honest signature is empty, so the rows below are not the lengths they claim")
	}

	rows := map[string][]byte{
		"absent":                              nil,
		"present and empty":                   {},
		"one octet":                           {0x00},
		"a run of zeros of its size":          make([]byte, len(real)),
		"the real one short an octet":         bytes.Clone(real[:len(real)-1]),
		"the real one with an octet appended": append(bytes.Clone(real), 0x00),
	}
	for _, name := range slices.Sorted(maps.Keys(rows)) {
		info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
		info.Signature = rows[name]
		if err := info.Verify(crypto, tree); !errors.Is(err, ErrWelcomeGroupInfoSignature) {
			t.Errorf("a group info whose signature is %s answered %v, want ErrWelcomeGroupInfoSignature",
				name, err)
		}
	}

	// and off the wire, which is the path that makes the empty case a peer's choice rather than
	// this test's: the encode carries an empty signature<V> and the decode gives it back
	unsigned := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
	encoded, err := syntax.Marshal(unsigned)
	if err != nil {
		t.Fatalf("marshal an unsigned group info: %v", err)
	}
	parsed := GroupInfo{}
	if err := syntax.Unmarshal(encoded, &parsed); err != nil {
		t.Fatalf("unmarshal an unsigned group info: %v", err)
	}
	if len(parsed.Signature) != 0 {
		t.Fatalf("the decoded signature is %d octets, so this half is not driving an empty signature<V> at all",
			len(parsed.Signature))
	}
	if err := parsed.Verify(crypto, tree); !errors.Is(err, ErrWelcomeGroupInfoSignature) {
		t.Errorf("a group info decoded off the wire with an empty signature<V> answered %v, want ErrWelcomeGroupInfoSignature",
			err)
	}
}

// TestSigningAGroupInfoAgainAfterAFieldChangedReplacesTheStaleSignature is finding 3, and it is
// the input TestGroupInfoSigningTwiceAnswersTheSameSignature cannot be.
//
// `if len(self.Signature) == 0 { self.Signature = signature }` survives the full suite, because
// the twice-signing test compares the first signature to the second and under that mutation the
// second Sign is a NO OP -- the two signatures it compares are one signature, and they are equal
// for the worst possible reason.
//
// The order below is p7 task 15's own: a committer assembles a GroupInfo, signs it, fills in the
// confirmation tag once the key schedule has advanced, and signs again. Under the mutation that
// committer publishes a signature over the OLD confirmation tag, and every peer refuses it.
func TestSigningAGroupInfoAgainAfterAFieldChangedReplacesTheStaleSignature(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 2)

	info := signedTestGroupInfo(t, crypto, tree, members, LeafIndex(0))
	stale := bytes.Clone(info.Signature)
	info.ConfirmationTag = bytes.Repeat([]byte{0x5c}, crypto.HashSize())
	if err := info.Sign(crypto, members[0].SignaturePriv); err != nil {
		t.Fatalf("Sign after the confirmation tag was filled in: %v", err)
	}
	if bytes.Equal(stale, info.Signature) {
		t.Fatalf("signing again over a changed confirmation tag left the first signature %x in place",
			stale)
	}
	if err := info.Verify(crypto, tree); err != nil {
		t.Errorf("the group info signed after its confirmation tag was filled in was refused with %v", err)
	}

	// and the stale signature is not merely different, it is REFUSED, which is what says the
	// paragraph above describes a defect rather than a cosmetic difference
	replaced := bytes.Clone(info.Signature)
	info.Signature = stale
	if err := info.Verify(crypto, tree); !errors.Is(err, ErrWelcomeGroupInfoSignature) {
		t.Errorf("the signature taken before the confirmation tag changed answered %v against the changed object, want ErrWelcomeGroupInfoSignature",
			err)
	}
	info.Signature = replaced

	// Sign overwrites whatever it finds and does not defer to it: a signature that was never
	// this object's is replaced the same way a stale one of its own is
	other := testGroupInfoOverTree(t, crypto, tree, LeafIndex(1))
	planted := bytes.Repeat([]byte{0x77}, len(stale))
	other.Signature = bytes.Clone(planted)
	if err := other.Sign(crypto, members[1].SignaturePriv); err != nil {
		t.Fatalf("Sign over a planted signature: %v", err)
	}
	if bytes.Equal(other.Signature, planted) {
		t.Errorf("Sign left a planted signature in place")
	}
	if err := other.Verify(crypto, tree); err != nil {
		t.Errorf("a group info signed over a planted signature was refused with %v", err)
	}
}

// TestTheSignerBoundIsTheTreesLeafWidthAndNotItsMembership is finding 4, and it needs the one
// group shape this file had none of.
//
// Changing Verify's bound from tree.LeafWidth() to LeafCount(tree.MemberCount()) survives the
// full suite, because every tree in this file is full: with n members at width n the two answer
// the same number and no input can tell them apart. A THREE member group pads to width 4, so
// leaf 3 is INSIDE the tree and occupied by nobody -- and the mutation answers
// ErrLeafIndexOutOfRange there, where errBlankSenderLeaf belongs. That is exactly the rule
// collapse this file's header says a single sentinel would hide, arriving through a bound rather
// than through a sentinel.
//
// The shape is asserted before it is used. A fixture that had stopped padding would leave this
// passing while measuring nothing at all.
func TestTheSignerBoundIsTheTreesLeafWidthAndNotItsMembership(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 3)
	if tree.LeafWidth() != 4 || tree.MemberCount() != 3 {
		t.Fatalf("a three member tree here has leaf width %d and %d members; this test separates the two bounds only when they differ",
			tree.LeafWidth(), tree.MemberCount())
	}
	if tree.Leaf(LeafIndex(3)) != nil {
		t.Fatal("leaf 3 of a three member group is occupied, so it is not the trailing blank leaf this test is about")
	}

	// inside the tree and belonging to nobody: the blank leaf rule, and not the index rule
	blank := testGroupInfoOverTree(t, crypto, tree, LeafIndex(3))
	if err := blank.Sign(crypto, members[0].SignaturePriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	answered := blank.Verify(crypto, tree)
	if !errors.Is(answered, errBlankSenderLeaf) {
		t.Errorf("a group info naming the trailing blank leaf 3 of a three member group answered %v, want errBlankSenderLeaf",
			answered)
	}
	if errors.Is(answered, ErrLeafIndexOutOfRange) {
		t.Errorf("leaf 3 was reported as outside a tree four leaves wide, which is what a bound taken from the member count reports; a caller told that goes looking for a malformed sender index over a position that is simply empty")
	}

	// and the position that IS outside the tree still is, so the rule above did not simply
	// swallow the index rule
	beyond := testGroupInfoOverTree(t, crypto, tree, LeafIndex(tree.LeafWidth()))
	if err := beyond.Sign(crypto, members[0].SignaturePriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	outside := beyond.Verify(crypto, tree)
	if !errors.Is(outside, ErrLeafIndexOutOfRange) {
		t.Errorf("a group info naming leaf %d of a four leaf tree answered %v, want ErrLeafIndexOutOfRange",
			tree.LeafWidth(), outside)
	}
	if errors.Is(outside, errBlankSenderLeaf) {
		t.Errorf("a signer index past the end of the tree was reported as a blank leaf, so the two rules cannot be told apart")
	}
}

// TestVerifyRefusesAGroupInfoNamingASuiteOrVersionThisVerifierDoesNotRun is finding 5.
//
// Measured before the rules existed: a GroupInfo whose GroupContext.CipherSuite is 0xbeef,
// signed by a real member, verified through the suite 3 provider, answered nil; so did one
// naming version 0x4242. The suite and the version are INSIDE the signed bytes, which is what
// makes this more than tidiness -- a MEMBER can commit to a suite the verifier is not running,
// and (*GroupInfo).VerifiedContext then hands a proposal cache a group context naming it.
//
// The suite rows are DERIVED from the registry rather than written down: Suites() is this
// package's own closed set, so every registered code point other than the provider's is swept,
// and a third suite added later joins the sweep on the commit that registers it. Two
// unregistered points are swept beside them, because "not this provider's" and "not a suite at
// all" are different inputs and only the first is what the rule is about.
//
// The ORDER is pinned in the same test, because it is the reason these two rules run where they
// do: the tree hash is taken THROUGH the provider, so over a group info naming another suite a
// tree hash comparison holds one suite's hash function against another's. A group info that is
// wrong about BOTH must answer the suite, not the tree.
func TestVerifyRefusesAGroupInfoNamingASuiteOrVersionThisVerifierDoesNotRun(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 4)
	elsewhere, _ := newTestTree(t, crypto, 4)

	if err := signedTestGroupInfo(t, crypto, tree, members, LeafIndex(0)).Verify(crypto, tree); err != nil {
		t.Fatalf("the honest group info was refused with %v, so every refusal below says nothing", err)
	}

	suites := []CipherSuite{}
	for _, registered := range Suites() {
		if registered != crypto.Suite() {
			suites = append(suites, registered)
		}
	}
	if len(suites) == 0 {
		t.Fatal("the registry holds no suite other than the provider's, so the derived rows below are empty")
	}
	suites = append(suites, CipherSuite(0xbeef), CipherSuite(0x0000))
	for _, suite := range suites {
		info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
		info.GroupContext.CipherSuite = suite
		if err := info.Sign(crypto, members[0].SignaturePriv); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := info.Verify(crypto, tree); !errors.Is(err, errGroupInfoProviderSuite) {
			t.Errorf("a group info naming ciphersuite %#04x, signed by a real member and verified through the %#04x provider, answered %v; want errGroupInfoProviderSuite",
				uint16(suite), uint16(crypto.Suite()), err)
		}
	}

	for _, version := range []ProtocolVersion{0x4242, 0x0000, 0xffff} {
		info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
		info.GroupContext.Version = version
		if err := info.Sign(crypto, members[0].SignaturePriv); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := info.Verify(crypto, tree); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("a group info naming protocol version %#04x, signed by a real member, answered %v; want ErrUnsupportedVersion",
				uint16(version), err)
		}
	}

	// the order: wrong about the suite AND about the tree answers the suite, because the tree
	// hash the other rule would compare was taken through a provider this group info does not
	// name
	both := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
	both.GroupContext.CipherSuite = CipherSuite(0xbeef)
	if err := both.Sign(crypto, members[0].SignaturePriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	answered := both.Verify(crypto, elsewhere)
	if !errors.Is(answered, errGroupInfoProviderSuite) {
		t.Errorf("a group info wrong about the suite and about the tree answered %v, want errGroupInfoProviderSuite; a tree hash comparison made under a provider the group info does not name compares two different hash functions",
			answered)
	}
	// and the version outranks the suite for the same reason one level up: a structure that is
	// not mls10 is not one whose ciphersuite field this build knows the meaning of
	neither := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
	neither.GroupContext.Version = ProtocolVersion(0x4242)
	neither.GroupContext.CipherSuite = CipherSuite(0xbeef)
	if err := neither.Sign(crypto, members[0].SignaturePriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := neither.Verify(crypto, tree); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("a group info wrong about the version and the suite answered %v, want ErrUnsupportedVersion", err)
	}
}

// TestAGroupInfoCarriedRatchetTreeMustDescribeTheTreeItIsVerifiedAgainst is Verify's rule 9,
// held to the thing it buys and, in the test after this one, to the thing it does not.
//
// The gap it closes was measured: a GroupInfo whose ratchet_tree extension described tree A
// while its group context named tree B verified against B with the extension ENTIRELY IGNORED,
// because Verify never decoded GroupInfo.Extensions. One object could therefore verify against
// the tree a joiner already trusts and simultaneously carry a different tree for a later code
// path to adopt, with "the group info verified" as its warrant.
//
// The positive control is the first row and it is not decoration: a rule that refused every
// carried tree would satisfy every other row here, and RFC 9420 section 12.4.3.1 exists so a
// Welcome CAN carry the tree.
func TestAGroupInfoCarriedRatchetTreeMustDescribeTheTreeItIsVerifiedAgainst(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := newTestTree(t, crypto, 4)
	elsewhere, _ := newTestTree(t, crypto, 4)

	own, err := tree.Encode()
	if err != nil {
		t.Fatalf("encode this tree as a ratchet_tree extension: %v", err)
	}
	other, err := elsewhere.Encode()
	if err != nil {
		t.Fatalf("encode the other tree as a ratchet_tree extension: %v", err)
	}

	signedOver := func(t *testing.T, exts []Extension) *GroupInfo {
		t.Helper()
		info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
		info.Extensions = exts
		if err := info.Sign(crypto, members[0].SignaturePriv); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return info
	}

	// carrying nothing at all, and carrying the tree it names: both verify, which is what says
	// every refusal below is the rule's and not a blanket
	if err := signedOver(t, nil).Verify(crypto, tree); err != nil {
		t.Fatalf("a group info carrying no ratchet_tree extension was refused with %v", err)
	}
	if err := signedOver(t, []Extension{own}).Verify(crypto, tree); err != nil {
		t.Fatalf("a group info carrying the very tree it is verified against was refused with %v; the extension exists so a welcome can carry the tree",
			err)
	}

	// the gap: one tree in the extension, another in the group context and in the caller's hand
	if err := signedOver(t, []Extension{other}).Verify(crypto, tree); !errors.Is(err,
		ErrWelcomeCarriedTreeMismatch) {
		t.Errorf("a group info carrying a ratchet_tree for another group answered %v, want ErrWelcomeCarriedTreeMismatch; before this rule the extension was not decoded at all",
			err)
	}

	// a carried body that is not a tree, which is the same rule with the decoder's reason behind
	// it rather than a hash comparison
	rows := map[string][]byte{
		"empty":                           {},
		"one octet":                       {0x01},
		"the real body short an octet":    bytes.Clone(own.ExtensionData[:len(own.ExtensionData)-1]),
		"the real body with a byte added": append(bytes.Clone(own.ExtensionData), 0x00),
	}
	for _, name := range slices.Sorted(maps.Keys(rows)) {
		broken := Extension{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: rows[name]}
		if err := signedOver(t, []Extension{broken}).Verify(crypto, tree); !errors.Is(err,
			ErrWelcomeCarriedTreeMismatch) {
			t.Errorf("a group info whose ratchet_tree body is %s answered %v, want ErrWelcomeCarriedTreeMismatch",
				name, err)
		}
	}

	// a foreign tree whose hash AGREES with this tree's in its FIRST OCTET, searched for rather
	// than written down. Without it a rule 9 comparison narrowed to a prefix refuses a tree drawn
	// at random 255 times in 256, so the row above passes over it and reports a clean run -- which
	// is the exact defect TestGroupInfoVerifyComparesTheWholeTreeHash measured of the rule 4
	// comparison, and for an attacker who wants a carried tree adopted it is a one octet search.
	//
	// Drawn rather than constructed because a tree hash cannot be steered: the loop keeps drawing
	// four leaf trees until one collides in that octet and differs overall, which takes 256 draws
	// on average, and an exhausted loop is fatal rather than skipped.
	ownHash, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	var colliding *RatchetTree
	for attempt := 0; attempt < 8192 && colliding == nil; attempt += 1 {
		candidate, _ := newTestTree(t, crypto, 4)
		hash, err := candidate.TreeHash(crypto)
		if err != nil {
			t.Fatalf("TreeHash of a candidate tree: %v", err)
		}
		if hash[0] == ownHash[0] && !bytes.Equal(hash, ownHash) {
			colliding = candidate
		}
	}
	if colliding == nil {
		t.Fatal("no four leaf tree colliding with this one in the first octet of its tree hash turned up in 8192 draws, so this row measures nothing")
	}
	collidingExtension, err := colliding.Encode()
	if err != nil {
		t.Fatalf("encode the colliding tree as a ratchet_tree extension: %v", err)
	}
	if err := signedOver(t, []Extension{collidingExtension}).Verify(crypto, tree); !errors.Is(err,
		ErrWelcomeCarriedTreeMismatch) {
		t.Errorf("a group info carrying a tree whose hash agrees with this one's first octet answered %v, want ErrWelcomeCarriedTreeMismatch; a rule 9 comparison that reads a prefix accepts a carried tree an attacker searched one octet for",
			err)
	}

	// two of them is the extensions vector being illegal rather than the tree being wrong, and it
	// is FindExtensionEntry's refusal because that lookup is this package's ONE door for a
	// repeated extension type -- a second walk written here would be a second selection rule
	if err := signedOver(t, []Extension{own, own}).Verify(crypto, tree); !errors.Is(err,
		ErrMalformedExtension) {
		t.Errorf("a group info carrying two ratchet_tree extensions answered %v, want ErrMalformedExtension", err)
	}

	// rule 9 runs after the signature, so a group info that is wrong about both answers the
	// signature: the decode of a peer-chosen tree is paid only once a member of the caller's
	// tree is known to have signed
	unsigned := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
	unsigned.Extensions = []Extension{other}
	if err := unsigned.Sign(crypto, members[1].SignaturePriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := unsigned.Verify(crypto, tree); !errors.Is(err, ErrWelcomeGroupInfoSignature) {
		t.Errorf("a group info with a bad signature AND a foreign carried tree answered %v, want ErrWelcomeGroupInfoSignature",
			err)
	}
}

// TestAJoinerThatTakesTheTreeOutOfTheGroupInfoItChecksIsProtectedByNothingHere is finding 1, and
// it asserts the SUCCESS of the forgery rather than papering over it.
//
// This is the shape p7 task 16 will build if the precondition on Verify goes unread, and the
// object it accepts is not a near miss: the attacker mints its own four leaf tree with every
// leaf its own, encodes that tree into a ratchet_tree extension, names the group id the joiner
// expects, sets tree_hash to its OWN tree's hash and signs at its own leaf 0. Every rule of
// Verify is TRUE of the result, rule 9 included -- the carried tree and the tree it is verified
// against are the same tree, so they agree, and agreement is not authentication.
//
// A test that asserted only the refusal against the honest tree would let this file read as
// though the gap were closed, which is the one thing the next task must not be told. So both
// halves are asserted, and this test FAILS if either stops being true: if the forgery starts
// being refused, somebody has closed the gap and this account is stale; if the honest tree stops
// refusing it, the door has stopped working altogether.
func TestAJoinerThatTakesTheTreeOutOfTheGroupInfoItChecksIsProtectedByNothingHere(t *testing.T) {
	crypto := testCrypto(t)
	honestTree, _ := newTestTree(t, crypto, 4)
	attackersTree, attackers := newTestTree(t, crypto, 4)

	carried, err := attackersTree.Encode()
	if err != nil {
		t.Fatalf("encode the attacker's tree as a ratchet_tree extension: %v", err)
	}
	// the group id the joiner expects, and the attacker's own tree hash
	forged := testGroupInfoOverTree(t, crypto, attackersTree, LeafIndex(0))
	forged.Extensions = []Extension{carried}
	if err := forged.Sign(crypto, attackers[0].SignaturePriv); err != nil {
		t.Fatalf("the attacker signing its own group info: %v", err)
	}

	// the joiner's mistake, written the way the RFC invites it: resolve the tree out of the very
	// group info being checked
	resolved, err := ParseRatchetTreeFrom(forged.Extensions[0])
	if err != nil {
		t.Fatalf("a joiner parsing the carried ratchet_tree: %v", err)
	}
	if answered := forged.Verify(crypto, resolved); answered != nil {
		t.Fatalf("the self-consistent forgery was refused with %v; if a later task closed this, delete the account of it on (*GroupInfo).Verify rather than leaving this test asserting a gap that no longer exists",
			answered)
	}
	verified, err := forged.VerifiedContext(crypto, resolved)
	if err != nil || verified == nil {
		t.Fatalf("VerifiedContext refused the forgery Verify accepted (%v); the two doors have stopped agreeing", err)
	}
	if !bytes.Equal(verified.Context().GroupId, []byte(welcomeTestGroupId)) {
		t.Fatalf("the vouched-for context names group %x", verified.Context().GroupId)
	}

	// and the half that IS closed: against a tree the joiner already trusts, the same object is
	// refused, which is what says the gap is in WHERE THE TREE CAME FROM and nowhere else
	if err := forged.Verify(crypto, honestTree); !errors.Is(err, ErrWelcomeTreeHashMismatch) {
		t.Errorf("the forgery against the joiner's own tree answered %v, want ErrWelcomeTreeHashMismatch",
			err)
	}
}

// groupInfoVerifyExitControl is a body the exit rule below is proven to read: one refusal that
// names a sentinel, one bare `return err`, one delegation to a helper, and a `return nil`.
//
// A control rather than a second opinion about welcome.go, for the reason every derivation in
// this package carries one: a matcher that had stopped resolving anything reports an EMPTY set
// of unnamed exits, and an empty set is exactly what a compliant body reports. Only source known
// to hold both answers tells the two apart.
const groupInfoVerifyExitControl = `package control

import "errors"

var errControlRefused = errors.New("control: refused")

type Thing struct{}

func (self *Thing) helper() error { return nil }

func (self *Thing) Check(bad bool) error {
	if bad {
		return errControlRefused
	}
	if err := self.helper(); err != nil {
		return err
	}
	return self.helper()
}
`

// groupInfoVerifyUnnamedExits is every exit of one body that refuses without naming what it
// refuses under: a return that is neither `return nil` nor carries a package level variable of
// the package the names were collected from.
//
// Stated over the RETURN and over the ABSENCE of a name, because that is where the class lives.
// `return err`, `return self.checkTheOtherThing(...)` and a wrap of a helper's error with no
// sentinel of this layer are three spellings of one hole, and a rule that banned the identifier
// `err` would report a clean run over the other two.
func groupInfoVerifyUnnamedExits(parsed parsedSource, body *ast.BlockStmt, declared []string) []string {
	unnamed := []string{}
	ast.Inspect(body, func(node ast.Node) bool {
		returned, isReturn := node.(*ast.ReturnStmt)
		if !isReturn {
			return true
		}
		if len(returned.Results) == 1 {
			if identifier, isIdentifier := returned.Results[0].(*ast.Ident); isIdentifier &&
				identifier.Name == "nil" {
				return true
			}
		}
		named := false
		for _, result := range returned.Results {
			ast.Inspect(result, func(inner ast.Node) bool {
				identifier, isIdentifier := inner.(*ast.Ident)
				if isIdentifier && slices.Contains(declared, identifier.Name) {
					named = true
				}
				return true
			})
		}
		if !named {
			unnamed = append(unnamed, parsed.render(returned))
		}
		return true
	})
	return unnamed
}

// TestEveryRefusingExitOfGroupInfoVerifyNamesTheSentinelItRefusesUnder closes the class the
// sentinel roster above cannot see.
//
// groupInfoVerifySentinelNames derives Verify's refusal class from the identifiers in its return
// statements, so an exit spelled `return err` contributes NOTHING to that class while still
// being one of Verify's answers. Two of them lived here -- the tree hash draw and the signature
// preimage -- and the effect is not cosmetic: whatever tree.go or syntax decides to answer next
// becomes a refusal of Verify that no sweep of this package judges, while the roster gate above
// reports a clean run. This is the same understatement rule 5 is about, arriving through an
// omission rather than through a list.
//
// It is stated over Verify and not over every declaration of the file on purpose. Verify is the
// refusal surface a PEER reaches, and its answers are ones a caller branches on; Sign's are its
// own caller's encode and provider failures, with nothing on the wire behind them.
func TestEveryRefusingExitOfGroupInfoVerifyNamesTheSentinelItRefusesUnder(t *testing.T) {
	declared := []string{}
	for _, path := range packageLevelFunctions(t).files {
		declared = append(declared, packageLevelVarNamesIn(mustParseSource(t, path))...)
	}
	if !slices.Contains(declared, "ErrWelcomeGroupInfoSignature") {
		t.Fatalf("the package level variable scan found %d names and not ErrWelcomeGroupInfoSignature, so it is reading something other than this package",
			len(declared))
	}

	control := mustParseText(t, "the unnamed refusal control", groupInfoVerifyExitControl)
	inControl := append(slices.Clone(declared), packageLevelVarNamesIn(control)...)
	reported := groupInfoVerifyUnnamedExits(control,
		control.declarationOf(t, "*Thing", "Check").Body, inControl)
	if len(reported) != 2 {
		t.Fatalf("the rule reported %v out of the control, which holds exactly two unnamed refusals beside one named refusal and one nil; a rule that reported none of them would report a clean run over any body at all",
			reported)
	}

	parsed := mustParseSource(t, "welcome.go")
	body := parsed.declarationOf(t, "*GroupInfo", "Verify").Body
	if unnamed := groupInfoVerifyUnnamedExits(parsed, body, declared); len(unnamed) != 0 {
		t.Errorf("(*GroupInfo).Verify refuses through %v without naming a sentinel; the refusal class gate beside this one derives its class from those identifiers, so an exit with no name in it is an answer of Verify's that nothing in this package sweeps",
			unnamed)
	}
}

// ---------------------------------------------------------------------------
// p7 task 15: what a Welcome carries, and what a joiner can do with it
// ---------------------------------------------------------------------------

// welcomeTestSignedInfo is a signed GroupInfo over a fresh tree, with the members that own its
// leaves.
//
// The group info is signed at leaf 0 by leaf 0's own key, which is the only pairing under which
// (*GroupInfo).Verify answers nil -- so every test below that verifies is measuring what
// BuildWelcome did to the object rather than a fixture that was never verifiable.
func welcomeTestSignedInfo(t *testing.T, crypto CryptoProvider,
	names ...string) (*RatchetTree, []*testMember, *GroupInfo) {

	t.Helper()
	tree, members := testTreeWith(t, crypto, names...)
	info := testGroupInfoOverTree(t, crypto, tree, LeafIndex(0))
	if err := info.Sign(crypto, members[0].SigPriv); err != nil {
		t.Fatalf("Sign the fixture group info: %v", err)
	}
	return tree, members, info
}

// welcomeTestOpenGroupInfo is the joiner's half of the group info seal: open under
// welcome_key/welcome_nonce with EMPTY AAD, then decode.
//
// It is written as the RFC describes the RECEIVE side rather than by calling anything
// BuildWelcome called, which is the whole point of it: a helper that re-used the builder's own
// statements would agree with the builder however either of them was wrong.
func welcomeTestOpenGroupInfo(t *testing.T, crypto CryptoProvider, welcome *Welcome,
	welcomeSecret []byte) *GroupInfo {

	t.Helper()
	key, nonce, err := WelcomeKeyNonce(crypto, welcomeSecret)
	if err != nil {
		t.Fatalf("WelcomeKeyNonce: %v", err)
	}
	plaintext, err := crypto.AeadOpen(key, nonce, nil, welcome.EncryptedGroupInfo)
	if err != nil {
		t.Fatalf("AeadOpen of the encrypted group info with empty AAD: %v", err)
	}
	decoded := &GroupInfo{}
	if err := syntax.Unmarshal(plaintext, decoded); err != nil {
		t.Fatalf("unmarshal the group info this welcome carries: %v", err)
	}
	return decoded
}

// welcomeTestOpenSecrets is the joiner's half of one EncryptedGroupSecrets: open under the
// joiner's init private key with the ENCRYPTED GROUP INFO as the HPKE context, then decode.
func welcomeTestOpenSecrets(t *testing.T, crypto CryptoProvider, welcome *Welcome, at int,
	initPriv HpkePrivateKey) *GroupSecrets {

	t.Helper()
	opened, err := OpenWithLabel(crypto, initPriv, "Welcome", welcome.EncryptedGroupInfo,
		&welcome.Secrets[at].EncryptedGroupSecrets)
	if err != nil {
		t.Fatalf("OpenWithLabel of secrets entry %d: %v", at, err)
	}
	secrets := &GroupSecrets{}
	if err := syntax.Unmarshal(opened, secrets); err != nil {
		t.Fatalf("unmarshal group secrets %d: %v", at, err)
	}
	return secrets
}

// welcomeTestFromCommit parses an MLSMessage(Welcome) as a joiner would and answers the Welcome
// inside it, holding the outer frame to what a Welcome must be framed as.
func welcomeTestFromCommit(t *testing.T, encoded []byte) *Welcome {
	t.Helper()
	if len(encoded) == 0 {
		t.Fatal("this commit answered no welcome, so there is nothing here to read")
	}
	message, err := ParseMLSMessage(encoded)
	if err != nil {
		t.Fatalf("ParseMLSMessage over the welcome: %v", err)
	}
	if message.Version != ProtocolVersionMls10 {
		t.Fatalf("the welcome names version %#04x, want mls10", uint16(message.Version))
	}
	if message.WireFormat != WireFormatWelcome {
		t.Fatalf("the welcome is framed as wire format %#04x, want welcome", uint16(message.WireFormat))
	}
	if message.Welcome == nil {
		t.Fatal("the message is framed as a welcome and carries no welcome arm")
	}
	return message.Welcome
}

// TestBuildWelcomeSealsTheGroupInfoUnderTheWelcomeKey is the plan's own case, and it is where the
// two transcribed details of RFC 9420 section 12.4.3.1 are held: the group info opens with EMPTY
// AAD, and the group secrets open with the ENCRYPTED GROUP INFO as the HPKE context.
//
// Both are invisible to a seal-then-open round trip written through BuildWelcome's own
// statements, which is why every open here is spelled out from the RFC's receive side instead.
func TestBuildWelcomeSealsTheGroupInfoUnderTheWelcomeKey(t *testing.T) {
	crypto := testCrypto(t)
	_, _, info := welcomeTestSignedInfo(t, crypto, "alice")
	joinerSecret := bytes.Repeat([]byte{1}, crypto.HashSize())
	welcomeSecret := bytes.Repeat([]byte{2}, crypto.HashSize())

	bob := testIdentity(t, crypto, "bob")
	kp, initPriv, _ := testKeyPackage(t, crypto, bob)
	welcome, err := BuildWelcome(crypto, crypto.Suite(), info, joinerSecret, welcomeSecret,
		[]WelcomeJoiner{{KeyPackage: *kp, LeafIndex: LeafIndex(1)}})
	if err != nil {
		t.Fatalf("BuildWelcome: %v", err)
	}
	if welcome.CipherSuite != crypto.Suite() {
		t.Fatalf("the welcome names suite %#04x in the clear, want %#04x",
			uint16(welcome.CipherSuite), uint16(crypto.Suite()))
	}
	if len(welcome.Secrets) != 1 {
		t.Fatalf("Secrets = %d, want 1", len(welcome.Secrets))
	}
	ref, err := kp.Ref(crypto)
	if err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if !bytes.Equal(welcome.Secrets[0].NewMember, ref) {
		t.Fatal("the secrets entry is not keyed by the joiner's own KeyPackageRef, so a joiner scanning the vector for itself would not find it")
	}

	decoded := welcomeTestOpenGroupInfo(t, crypto, welcome, welcomeSecret)
	if decoded.GroupContext.Epoch != info.GroupContext.Epoch {
		t.Fatalf("the sealed group info names epoch %d and the one built names %d",
			decoded.GroupContext.Epoch, info.GroupContext.Epoch)
	}
	if !bytes.Equal(decoded.ConfirmationTag, info.ConfirmationTag) {
		t.Fatal("the sealed group info carries a different confirmation tag from the one built")
	}

	secrets := welcomeTestOpenSecrets(t, crypto, welcome, 0, initPriv)
	if !bytes.Equal(secrets.JoinerSecret, joinerSecret) {
		t.Fatal("the joiner secret did not survive the seal")
	}
	if secrets.PathSecret != nil {
		t.Fatal("a commit with no path must produce a null path_secret, and a joiner reads a present one as nodes it must re-derive")
	}
	if secrets.Psks == nil || len(secrets.Psks) != 0 {
		t.Fatalf("Psks = %v, want an empty vector: v1 never sends PSKs and the joiner asserts the vector is empty", secrets.Psks)
	}
}

// TestBuildWelcomeCarriesThePathSecretWhenThereIsOne is the plan's second case: a joiner whose
// entry carries a path secret gets that exact secret back out.
func TestBuildWelcomeCarriesThePathSecretWhenThereIsOne(t *testing.T) {
	crypto := testCrypto(t)
	_, _, info := welcomeTestSignedInfo(t, crypto, "alice")
	welcomeSecret := bytes.Repeat([]byte{2}, crypto.HashSize())
	bob := testIdentity(t, crypto, "bob")
	kp, initPriv, _ := testKeyPackage(t, crypto, bob)
	pathSecret := bytes.Repeat([]byte{9}, crypto.HashSize())
	welcome, err := BuildWelcome(crypto, crypto.Suite(), info,
		bytes.Repeat([]byte{1}, crypto.HashSize()), welcomeSecret,
		[]WelcomeJoiner{{KeyPackage: *kp, LeafIndex: LeafIndex(1), PathSecret: pathSecret}})
	if err != nil {
		t.Fatalf("BuildWelcome: %v", err)
	}
	secrets := welcomeTestOpenSecrets(t, crypto, welcome, 0, initPriv)
	if secrets.PathSecret == nil {
		t.Fatal("the path secret is absent, and a joiner reads absent as \"nothing above you was reset\"")
	}
	if !bytes.Equal(secrets.PathSecret.PathSecret, pathSecret) {
		t.Fatalf("path secret = %x, want %x", secrets.PathSecret.PathSecret, pathSecret)
	}
}

// TestBuildWelcomeSealsEachJoinersSecretsToThatJoinersOwnInitKey is the plan's "covers every
// joiner" case with the assertion it needs to be worth running.
//
// Counting the entries is not the property. A builder that sealed all three to the FIRST
// joiner's init key answers three entries, and every one of them decodes -- for one member. So
// each entry is opened here with ITS OWN joiner's init private key and checked against its own
// key package reference, which is the pairing a Welcome exists to establish.
func TestBuildWelcomeSealsEachJoinersSecretsToThatJoinersOwnInitKey(t *testing.T) {
	crypto := testCrypto(t)
	_, _, info := welcomeTestSignedInfo(t, crypto, "alice")
	joinerSecret := bytes.Repeat([]byte{1}, crypto.HashSize())
	welcomeSecret := bytes.Repeat([]byte{2}, crypto.HashSize())

	joiners := []WelcomeJoiner{}
	initKeys := []HpkePrivateKey{}
	packages := []*KeyPackage{}
	for _, name := range []string{"bob", "carol", "dave"} {
		kp, initPriv, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, name))
		joiners = append(joiners, WelcomeJoiner{
			KeyPackage: *kp,
			LeafIndex:  LeafIndex(len(joiners) + 1),
			// a DISTINCT path secret per joiner, so an entry opened with the wrong member's key
			// is separated by its content and not only by which key opened it
			PathSecret: bytes.Repeat([]byte{byte(0xa0 + len(joiners))}, crypto.HashSize()),
		})
		initKeys = append(initKeys, initPriv)
		packages = append(packages, kp)
	}
	welcome, err := BuildWelcome(crypto, crypto.Suite(), info, joinerSecret, welcomeSecret, joiners)
	if err != nil {
		t.Fatalf("BuildWelcome: %v", err)
	}
	if len(welcome.Secrets) != len(joiners) {
		t.Fatalf("Secrets = %d, want %d: the welcome set MUST cover every new member",
			len(welcome.Secrets), len(joiners))
	}
	for i := range joiners {
		ref, err := packages[i].Ref(crypto)
		if err != nil {
			t.Fatalf("Ref %d: %v", i, err)
		}
		if !bytes.Equal(welcome.Secrets[i].NewMember, ref) {
			t.Fatalf("secrets entry %d is keyed by another member's key package reference", i)
		}
		secrets := welcomeTestOpenSecrets(t, crypto, welcome, i, initKeys[i])
		if secrets.PathSecret == nil ||
			!bytes.Equal(secrets.PathSecret.PathSecret, joiners[i].PathSecret) {

			t.Fatalf("secrets entry %d carries another joiner's path secret", i)
		}
	}
}

// TestTheGroupInfoAWelcomeCarriesIsOneItsJoinerCanVerify is the round trip this task is judged
// on: the object BuildWelcome sealed is checked with (*GroupInfo).Verify, the function a joiner
// will actually run, against the tree that group info names.
//
// BOTH DIRECTIONS ARE HELD, because a positive alone is satisfied by a Verify that answers nil to
// everything. The negative is the same fixture signed by leaf 0's key while NAMING leaf 1 as its
// signer -- a group info that is perfectly well formed, seals and opens byte for byte, and is
// refused because the key at the leaf it names did not make that signature.
func TestTheGroupInfoAWelcomeCarriesIsOneItsJoinerCanVerify(t *testing.T) {
	crypto := testCrypto(t)
	tree, members, info := welcomeTestSignedInfo(t, crypto, "alice", "bob")
	welcomeSecret := bytes.Repeat([]byte{2}, crypto.HashSize())
	carol := testIdentity(t, crypto, "carol")
	kp, _, _ := testKeyPackage(t, crypto, carol)
	joiners := []WelcomeJoiner{{KeyPackage: *kp, LeafIndex: LeafIndex(2)}}

	welcome, err := BuildWelcome(crypto, crypto.Suite(), info,
		bytes.Repeat([]byte{1}, crypto.HashSize()), welcomeSecret, joiners)
	if err != nil {
		t.Fatalf("BuildWelcome: %v", err)
	}
	if err := welcomeTestOpenGroupInfo(t, crypto, welcome, welcomeSecret).Verify(crypto, tree); err != nil {
		t.Fatalf("the group info this welcome carries does not verify against the tree it names: %v", err)
	}

	// the negative, over the one field a joiner resolves the verification key through
	misnamed := testGroupInfoOverTree(t, crypto, tree, LeafIndex(1))
	if err := misnamed.Sign(crypto, members[0].SigPriv); err != nil {
		t.Fatalf("Sign the misnamed group info: %v", err)
	}
	forged, err := BuildWelcome(crypto, crypto.Suite(), misnamed,
		bytes.Repeat([]byte{1}, crypto.HashSize()), welcomeSecret, joiners)
	if err != nil {
		t.Fatalf("BuildWelcome over the misnamed group info: %v", err)
	}
	err = welcomeTestOpenGroupInfo(t, crypto, forged, welcomeSecret).Verify(crypto, tree)
	if !errors.Is(err, ErrWelcomeGroupInfoSignature) {
		t.Fatalf("a group info naming a signer leaf whose key did not sign it verified with %v, want %v",
			err, ErrWelcomeGroupInfoSignature)
	}
}

// TestEachGroupSecretsSealDrawsItsOwnEntropy is the entropy reading, derived from what the
// function PUBLISHES rather than from the line that draws.
//
// THE SAME KEY PACKAGE APPEARS TWICE ON PURPOSE, and it is the only fixture that isolates the
// draw. With one recipient key and one plaintext, every input to the two seals is equal, so the
// only thing left that can separate the two ciphertexts is the randomness each of them takes:
// a build that drew once and reused the encapsulation for both entries answers two entries that
// are byte-identical, and every correctness assertion in this file passes over it.
//
// The group info seal is asserted EQUAL across the two builds in the same breath, and that is the
// control rather than an extra. Its key and nonce are DERIVED from welcome_secret and nothing
// there is drawn, so a build whose group info ciphertext also moved would be one where something
// other than the HPKE draw is varying, and the inequalities above would be measuring that instead.
func TestEachGroupSecretsSealDrawsItsOwnEntropy(t *testing.T) {
	crypto := testCrypto(t)
	_, _, info := welcomeTestSignedInfo(t, crypto, "alice")
	joinerSecret := bytes.Repeat([]byte{1}, crypto.HashSize())
	welcomeSecret := bytes.Repeat([]byte{2}, crypto.HashSize())
	bob := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, bob)
	joiners := []WelcomeJoiner{
		{KeyPackage: *kp, LeafIndex: LeafIndex(1)},
		{KeyPackage: *kp, LeafIndex: LeafIndex(2)},
	}

	welcome, err := BuildWelcome(crypto, crypto.Suite(), info, joinerSecret, welcomeSecret, joiners)
	if err != nil {
		t.Fatalf("BuildWelcome: %v", err)
	}
	first, second := welcome.Secrets[0].EncryptedGroupSecrets, welcome.Secrets[1].EncryptedGroupSecrets
	if bytes.Equal(first.KemOutput, second.KemOutput) {
		t.Fatal("two entries of one welcome share an HPKE encapsulation, so the seal drew once and reused it")
	}
	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Fatal("two entries of one welcome are byte-identical, so nothing separating them was drawn")
	}

	again, err := BuildWelcome(crypto, crypto.Suite(), info, joinerSecret, welcomeSecret, joiners)
	if err != nil {
		t.Fatalf("BuildWelcome a second time: %v", err)
	}
	if bytes.Equal(first.KemOutput, again.Secrets[0].EncryptedGroupSecrets.KemOutput) {
		t.Fatal("two builds over identical arguments produced the same HPKE encapsulation, so the ephemeral is a constant")
	}
	if !bytes.Equal(welcome.EncryptedGroupInfo, again.EncryptedGroupInfo) {
		t.Fatal("the group info ciphertext moved between two builds over identical arguments; its key and nonce are derived and nothing there is drawn, so the entropy readings above are measuring something else")
	}
}

// TestBuildWelcomeRefusesTheArgumentsItCannotBuildFrom holds the three refusals apart, each
// answering a value no other one answers: errors.Is cannot tell two rules apart when they share a
// sentinel, so an assertion written for one passes over the other firing instead.
func TestBuildWelcomeRefusesTheArgumentsItCannotBuildFrom(t *testing.T) {
	crypto := testCrypto(t)
	_, _, info := welcomeTestSignedInfo(t, crypto, "alice")
	secret := bytes.Repeat([]byte{3}, crypto.HashSize())

	if _, err := BuildWelcome(nil, crypto.Suite(), info, secret, secret, nil); !errors.Is(err, ErrNilCryptoProvider) {
		t.Fatalf("no provider = %v, want ErrNilCryptoProvider", err)
	}
	if _, err := BuildWelcome(crypto, crypto.Suite(), nil, secret, secret, nil); !errors.Is(err, errNilWelcomeGroupInfo) {
		t.Fatalf("no group info = %v, want errNilWelcomeGroupInfo", err)
	}
	// the OTHER registered suite, which this provider does not run. A welcome labelled with it
	// would be sealed with this provider's primitives and opened by nobody.
	_, err := BuildWelcome(crypto, CipherSuiteX25519AesGcm128Sha256Ed25519, info, secret, secret, nil)
	if !errors.Is(err, errWelcomeSuiteProvider) {
		t.Fatalf("a suite the provider does not run = %v, want errWelcomeSuiteProvider", err)
	}
	if errors.Is(err, errNilWelcomeGroupInfo) || errors.Is(err, ErrNilCryptoProvider) {
		t.Fatal("the suite refusal answers another rule's sentinel, so no test can tell the two apart")
	}
}

// TestZeroizingAWelcomeJoinerErasesThePathSecretAndLeavesTheKeyPackage is the erase obligation
// this type carries, held over both halves of it.
//
// The key package half is not decoration: it is the joiner's PUBLISHED key package and the caller
// goes on holding it, so an erase that reached into it would destroy a value the caller owns
// while removing nothing an attacker lacks.
func TestZeroizingAWelcomeJoinerErasesThePathSecretAndLeavesTheKeyPackage(t *testing.T) {
	crypto := testCrypto(t)
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "bob"))
	initKey := bytes.Clone(kp.InitKey)
	secret := bytes.Repeat([]byte{0x5a}, crypto.HashSize())
	joiner := WelcomeJoiner{KeyPackage: *kp, LeafIndex: LeafIndex(1), PathSecret: secret}

	joiner.Zeroize()
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("byte %d of the path secret is %#02x after the erase, so this joiner entry was dropped with the epoch's ladder still in it",
				i, b)
		}
	}
	if !bytes.Equal(joiner.KeyPackage.InitKey, initKey) {
		t.Fatal("the erase reached into the joiner's published key package, which is public and is the caller's")
	}
	// idempotent and nil-safe, for the reason every erase here is: a value may be dropped by one
	// path and released by another.
	joiner.Zeroize()
	var absent *WelcomeJoiner
	absent.Zeroize()
}

// TestACommitsWelcomeCarriesTheEpochTheCommitOpens is the end to end reading: everything above
// holds BuildWelcome to its arguments, and this holds the COMMITTER to handing the right ones.
//
// Four things are separated here that a shape assertion cannot tell apart. The group info the
// Welcome carries verifies against the tree the same commit publishes, which is the round trip
// task 16 stands on; it names the committer's own leaf as its signer; it names the epoch the
// commit OPENS; and its confirmation tag is the one the staged epoch computed, which is the
// assertion a group info assembled with the previous epoch's tag fails.
func TestACommitsWelcomeCarriesTheEpochTheCommitOpens(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "welcome-group")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, initPriv, _ := testKeyPackage(t, crypto, bob)
	result, err := group.CreateCommit(nil,
		[]Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}}, nil)
	if err != nil {
		t.Fatalf("CreateCommit: %v", err)
	}
	staged := group.stagedForTest()
	if staged == nil {
		t.Fatal("the commit staged nothing, so there is no epoch for this welcome to be about")
	}
	welcome := welcomeTestFromCommit(t, result.Welcome)
	if welcome.CipherSuite != crypto.Suite() {
		t.Fatalf("the welcome names suite %#04x, want the group's %#04x",
			uint16(welcome.CipherSuite), uint16(crypto.Suite()))
	}
	if len(welcome.Secrets) != 1 {
		t.Fatalf("the welcome carries %d entries and the commit added 1 member", len(welcome.Secrets))
	}
	ref, err := kp.Ref(crypto)
	if err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if !bytes.Equal(welcome.Secrets[0].NewMember, ref) {
		t.Fatal("the welcome is not addressed to the key package the Add named")
	}

	info := welcomeTestOpenGroupInfo(t, crypto, welcome, staged.schedule.WelcomeSecret())
	// the tree the joiner is handed out of band is the one the same commit published
	published, err := UnmarshalRatchetTree(result.RatchetTree)
	if err != nil {
		t.Fatalf("decode the published tree: %v", err)
	}
	if err := info.Verify(crypto, published); err != nil {
		t.Fatalf("the group info this welcome carries does not verify against the tree the commit published: %v", err)
	}
	if info.Signer != group.OwnLeafIndex() {
		t.Fatalf("the welcome's group info names signer leaf %d and the committer is leaf %d",
			info.Signer, group.OwnLeafIndex())
	}
	if info.GroupContext.Epoch != staged.Epoch() {
		t.Fatalf("the welcome's group info names epoch %d and the commit opens epoch %d",
			info.GroupContext.Epoch, staged.Epoch())
	}
	if !bytes.Equal(info.ConfirmationTag, staged.confirmTag) {
		t.Fatal("the welcome's group info carries a confirmation tag the staged epoch did not compute; a joiner checks that tag against the epoch it derives and would refuse this group")
	}

	secrets := welcomeTestOpenSecrets(t, crypto, welcome, 0, initPriv)
	if !bytes.Equal(secrets.JoinerSecret, staged.schedule.JoinerSecret()) {
		t.Fatal("the welcome carries a joiner secret that is not the staged epoch's, so the joiner would derive a different epoch")
	}
	if secrets.PathSecret != nil {
		t.Fatal("this add-only commit carried no update path and the welcome names a path secret anyway")
	}
}

// TestTheWelcomePathSecretIsTheOneForTheLowestNodeTheJoinerAndCommitterShare is the path half,
// and it is checked against the TREE rather than against the plan's own array.
//
// The secret is turned into a node key pair the way the committer turned it into one when it
// installed the node, and the public half is held against the node the published tree carries at
// the lowest node the two leaves share. A build that handed the joiner some other rung of the
// ladder -- the leaf's own parent, say, which is the neighbouring index and the plausible
// mistake -- derives a key that is in the tree, at the wrong place, and only this comparison
// separates the two.
func TestTheWelcomePathSecretIsTheOneForTheLowestNodeTheJoinerAndCommitterShare(t *testing.T) {
	crypto := testCrypto(t)
	group, _, _ := commitTestGroupOfTwo(t, crypto)
	defer group.Close()

	carol := testIdentity(t, crypto, "carol")
	kp, initPriv, _ := testKeyPackage(t, crypto, carol)
	result, err := group.CreateCommit(nil,
		[]Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}},
		// FORCED, because an add-only commit needs no update path: the shape this test is about
		// only exists when the committer resets the nodes above itself.
		&CommitOptions{Force: true})
	if err != nil {
		t.Fatalf("CreateCommit with a forced path: %v", err)
	}
	staged := group.stagedForTest()
	if staged == nil || staged.plan == nil {
		t.Fatal("the forced commit staged no update path plan, so this test is not about the shape it was written for")
	}
	if len(staged.added) != 1 {
		t.Fatalf("the commit added %d leaves, want 1", len(staged.added))
	}
	joinerLeaf := staged.added[0]
	ancestor := CommonAncestor(joinerLeaf.NodeIndex(), group.OwnLeafIndex().NodeIndex())
	if ancestor == joinerLeaf.NodeIndex() || ancestor == group.OwnLeafIndex().NodeIndex() {
		t.Fatalf("the lowest node leaf %d and leaf %d share is one of the two leaves, so this fixture has no interior node to be wrong about",
			joinerLeaf, group.OwnLeafIndex())
	}

	// building the welcome must not erase the COMMITTER's own ladder. The joiner entry holds a
	// COPY of the rung, and an entry that aliased the plan would erase these secrets as a side
	// effect of assembling a message -- the staged epoch is what owes them an erase, at the site
	// that drops it.
	for i, rung := range staged.plan.PathSecrets {
		if len(rung) == 0 {
			t.Fatalf("rung %d of the committer's ladder is empty, so this check observes nothing", i)
		}
		if !slices.ContainsFunc(rung, func(b byte) bool { return b != 0 }) {
			t.Fatalf("rung %d of the committer's own path ladder is all zeros after the welcome was built, so the builder erased storage it had only borrowed",
				i)
		}
	}

	welcome := welcomeTestFromCommit(t, result.Welcome)
	secrets := welcomeTestOpenSecrets(t, crypto, welcome, 0, initPriv)
	if secrets.PathSecret == nil {
		t.Fatal("this commit carried an update path and its welcome names no path secret, so the joiner would seed its direct path from nodes the commit had already reset")
	}
	_, pub, err := DeriveNodeKeyPair(crypto, secrets.PathSecret.PathSecret)
	if err != nil {
		t.Fatalf("DeriveNodeKeyPair over the welcome's path secret: %v", err)
	}
	published, err := UnmarshalRatchetTree(result.RatchetTree)
	if err != nil {
		t.Fatalf("decode the published tree: %v", err)
	}
	node := published.ParentAt(ancestor)
	if node == nil {
		t.Fatalf("the published tree holds no parent node at %d, the lowest node the two leaves share", ancestor)
	}
	if !bytes.Equal(node.EncryptionKey, pub) {
		t.Fatalf("the welcome's path secret derives the key at some node other than %d, the lowest node leaf %d and leaf %d share",
			ancestor, joinerLeaf, group.OwnLeafIndex())
	}
	// and the neighbour that separates "the right node" from "a node in the tree". The LOWEST
	// node of the committer's filtered path is the plausible mistake -- it is the rung the plan
	// stores at index 0 -- so this says the two nodes carry different keys, and the comparison
	// above therefore discriminates between them.
	if lowest := staged.plan.Path[0]; lowest != ancestor {
		lower := published.ParentAt(lowest)
		if lower == nil {
			t.Fatalf("the published tree holds no parent node at %d, the lowest rung of the committer's path", lowest)
		}
		if bytes.Equal(lower.EncryptionKey, node.EncryptionKey) {
			t.Fatal("two nodes of the published path carry one key, so the comparison above cannot tell which node the secret was for")
		}
	}
}

// ---------------------------------------------------------------------------
// the provider stub gate's rule for the structured argument this file owns
// ---------------------------------------------------------------------------

// groupInfoDeepCopy answers a GroupInfo that shares no storage with this one.
//
// The perturbations below edit their copy IN PLACE, so a shallow struct copy would write
// through into the base argument every other row of the stub gate is built from -- the fault
// TestTheLeafNodeStubArgumentsAreFreshStorageEveryCall exists for one structure over.
func groupInfoDeepCopy(info *GroupInfo) *GroupInfo {
	copied := &GroupInfo{
		GroupContext:    *info.GroupContext.Clone(),
		ConfirmationTag: bytes.Clone(info.ConfirmationTag),
		Signer:          info.Signer,
		Signature:       bytes.Clone(info.Signature),
	}
	for _, extension := range info.Extensions {
		copied.Extensions = append(copied.Extensions, Extension{
			ExtensionType: extension.ExtensionType,
			ExtensionData: bytes.Clone(extension.ExtensionData),
		})
	}
	return copied
}

// groupInfoStubEdits is one smallest move per field a GroupInfo declares.
//
// It is a table and the completeness check below is what makes it a class: the FIELDS are read
// off the compiled structure, in both directions, so a GroupInfo that grew a sixth field fails
// here rather than being sealed by a builder no perturbation moves -- which is the same reading
// TestTheGroupInfoSignatureCoversEveryFieldOfItsToBeSigned makes of the preimage, pointed at the
// object instead.
func groupInfoStubEdits() map[string]func(info *GroupInfo) {
	return map[string]func(info *GroupInfo){
		// the epoch, because it is the field two contexts of one group differ in and nothing
		// else; the group context perturbation of the stub gate itself moves the same one.
		"GroupContext":    func(info *GroupInfo) { info.GroupContext.Epoch++ },
		"Extensions":      func(info *GroupInfo) { info.Extensions[0].ExtensionData[0] ^= 0xff },
		"ConfirmationTag": func(info *GroupInfo) { info.ConfirmationTag[0] ^= 0xff },
		"Signer":          func(info *GroupInfo) { info.Signer++ },
		"Signature":       func(info *GroupInfo) { info.Signature[0] ^= 0xff },
	}
}

// providerGroupInfoPerturbations is the stub gate's rule for a *GroupInfo argument, living beside
// the structure it moves the way psk_test.go, leaf_node_test.go and treekem_test.go keep theirs.
//
// Every field is moved and not only the ones that "matter", because what this rule is held
// against is a builder that seals a SECOND assembly of the group info: an assembly that dropped
// the extensions, or the signature, answers the same sealed bytes under every perturbation of
// the field it dropped, and the whole reason a Welcome carries a signed group info is that a
// joiner checks that signature over exactly the fields it was made over.
func providerGroupInfoPerturbations(t *testing.T, operation string, parameter providerParameter,
	argument reflect.Value) []providerPerturbation {

	t.Helper()
	base, isGroupInfo := argument.Interface().(*GroupInfo)
	if !isGroupInfo || base == nil {
		t.Fatalf("the base argument for %s.%s is %v and this rule moves a *GroupInfo",
			operation, parameter.name, argument.Type())
	}
	edits := groupInfoStubEdits()
	declared := reflect.TypeOf(GroupInfo{})
	for i := range declared.NumField() {
		name := declared.Field(i).Name
		if _, written := edits[name]; !written {
			t.Fatalf("GroupInfo declares %s and no perturbation here moves it, so a builder that left that field out of what it seals answers identically under every move this gate makes",
				name)
		}
	}
	for name := range edits {
		if _, found := declared.FieldByName(name); !found {
			t.Fatalf("a perturbation here moves GroupInfo.%s, which the structure no longer declares", name)
		}
	}
	moved := []providerPerturbation{}
	for _, name := range slices.Sorted(maps.Keys(edits)) {
		copied := groupInfoDeepCopy(base)
		edits[name](copied)
		if reflect.DeepEqual(copied, base) {
			t.Fatalf("the move of GroupInfo.%s left %s.%s equal to the base argument, so the gate would call it twice with the same value",
				name, operation, parameter.name)
		}
		moved = append(moved, providerPerturbation{where: name + " moved", value: reflect.ValueOf(copied)})
	}
	return moved
}

// ---------------------------------------------------------------------------
// the two refusals the welcome builder makes about the commit it is built from
// ---------------------------------------------------------------------------

// welcomeTestStagedCommitOf commits one Add and answers the staged epoch plus the group info the
// committer signed for it, without merging.
//
// The group info is rebuilt here rather than read off the commit, because the committer does not
// hand it out: what a test of the refusals below needs is an object of the right shape, and what
// holds the object the PRODUCT seals to the tree it publishes is
// TestACommitsWelcomeCarriesTheEpochTheCommitOpens.
func welcomeTestStagedCommitOf(t *testing.T, crypto CryptoProvider, group *Group,
	name string) (*StagedCommit, *GroupInfo) {

	t.Helper()
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, name))
	if _, err := group.CreateCommit(nil,
		[]Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}}, nil); err != nil {
		t.Fatalf("CreateCommit adding %s: %v", name, err)
	}
	staged := group.stagedForTest()
	if staged == nil {
		t.Fatal("the commit staged nothing")
	}
	return staged, &GroupInfo{
		GroupContext:    *staged.context,
		ConfirmationTag: staged.confirmTag,
		Signer:          group.OwnLeafIndex(),
	}
}

// TestTheWelcomeBuilderRefusesACommitItCannotAddressOrSeed drives the two refusals the builder
// makes about the COMMIT rather than about its arguments, and holds them apart: errors.Is cannot
// tell two rules apart when they answer one value, so an assertion written for either would pass
// over the other firing instead.
//
// Both are reached through a staged commit edited by hand, because neither is reachable through
// (*Group).CreateCommit -- which is the point of writing them down. The pairing of
// StagedCommit.added with (*ProposalList).Adds is an assumption the commit path satisfies today;
// a build where it stopped holding would seal each joiner's secrets to some OTHER joiner's init
// key with every length equal, so the refusal is what stands between that and a silent fork.
func TestTheWelcomeBuilderRefusesACommitItCannotAddressOrSeed(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "welcome-refusals")
	defer group.Close()
	staged, info := welcomeTestStagedCommitOf(t, crypto, group, "bob")

	// the control: unedited, this commit builds a welcome
	if _, err := staged.welcomeMessage(crypto, info); err != nil {
		t.Fatalf("the unedited staged commit refused to build a welcome with %v, so neither case below observes its own rule", err)
	}

	// one more added leaf than the commit named Add proposals
	pairing := *staged
	pairing.added = append(append([]LeafIndex(nil), staged.added...), LeafIndex(7))
	_, err := pairing.welcomeMessage(crypto, info)
	if !errors.Is(err, errWelcomeAddPairing) {
		t.Fatalf("a commit whose added leaves and Add proposals disagree = %v, want errWelcomeAddPairing", err)
	}
	if errors.Is(err, errWelcomePathSecret) {
		t.Fatal("the pairing refusal answers the path secret rule's sentinel, so no test can tell the two apart")
	}

	// a commit that carries an update path plan holding no rung for the node the joiner and the
	// committer share. A plan with an empty ladder is the smallest version of it; what it stands
	// for is a plan whose filtered path does not reach that node, which would hand the joiner a
	// null path_secret for a commit that had just reset every node above it.
	seeding := *staged
	seeding.plan = &UpdatePathPlan{}
	_, err = seeding.welcomeMessage(crypto, info)
	if !errors.Is(err, errWelcomePathSecret) {
		t.Fatalf("a commit with a path and no secret for a joiner = %v, want errWelcomePathSecret", err)
	}
	if errors.Is(err, errWelcomeAddPairing) {
		t.Fatal("the path secret refusal answers the pairing rule's sentinel, so no test can tell the two apart")
	}
}

// theWelcomeJoinerFieldTheSealDoesNotRead is the one field of a joiner entry BuildWelcome
// deliberately does not read, with the reason written out.
//
// A table beside a derivation and not instead of one: the perturbation rule below reads the
// FIELDS off the compiled WelcomeJoiner and checks this table against them in both directions,
// so a field added tomorrow has to be either moved or excused here, and an excuse cannot outlive
// the field it covers.
var theWelcomeJoinerFieldTheSealDoesNotRead = map[string]string{
	"LeafIndex": "the leaf a joiner lands on is the COMMITTER's business and not the seal's. " +
		"(*StagedCommit).welcomeMessage uses it to find the lowest node the joiner and the committer " +
		"share, and by the time an entry reaches BuildWelcome that lookup has happened and its answer " +
		"is the PathSecret beside it. RFC 9420's GroupSecrets carries no leaf index at all -- a joiner " +
		"finds its own leaf by matching the key package it published against the tree -- so a builder " +
		"that read this field would be sealing something the structure on the wire does not have",
}

// welcomeJoinerStubEdits is one smallest move per field of a joiner entry the seal DOES read.
func welcomeJoinerStubEdits() map[string]func(joiner *WelcomeJoiner) {
	return map[string]func(joiner *WelcomeJoiner){
		// the init key the entry is sealed to, which is also inside the reference it is keyed
		// by: any 32 octets are a valid X25519 public key, so this moves the recipient without
		// moving the shape.
		"KeyPackage": func(joiner *WelcomeJoiner) { joiner.KeyPackage.InitKey[0] ^= 0xff },
		"PathSecret": func(joiner *WelcomeJoiner) { joiner.PathSecret[0] ^= 0xff },
	}
}

// providerWelcomeJoinerPerturbations is the stub gate's rule for a []WelcomeJoiner argument,
// living beside the structure it moves the way psk_test.go and leaf_node_test.go keep theirs.
func providerWelcomeJoinerPerturbations(t *testing.T, operation string, parameter providerParameter,
	argument reflect.Value) []providerPerturbation {

	t.Helper()
	base, isJoiners := argument.Interface().([]WelcomeJoiner)
	if !isJoiners || len(base) == 0 {
		t.Fatalf("the base argument for %s.%s is %v with %d entries, and this rule moves a non-empty []WelcomeJoiner",
			operation, parameter.name, argument.Type(), argument.Len())
	}
	edits := welcomeJoinerStubEdits()
	declared := reflect.TypeOf(WelcomeJoiner{})
	for i := range declared.NumField() {
		name := declared.Field(i).Name
		_, moves := edits[name]
		_, excused := theWelcomeJoinerFieldTheSealDoesNotRead[name]
		if moves == excused {
			t.Fatalf("WelcomeJoiner declares %s and this rule neither moves it nor writes down why the seal does not read it (or does both), so nothing here says which the field is",
				name)
		}
	}
	for name := range edits {
		if _, found := declared.FieldByName(name); !found {
			t.Fatalf("a perturbation here moves WelcomeJoiner.%s, which the structure no longer declares", name)
		}
	}
	for name := range theWelcomeJoinerFieldTheSealDoesNotRead {
		if _, found := declared.FieldByName(name); !found {
			t.Fatalf("theWelcomeJoinerFieldTheSealDoesNotRead excuses WelcomeJoiner.%s, which the structure no longer declares",
				name)
		}
	}
	moved := []providerPerturbation{}
	for _, name := range slices.Sorted(maps.Keys(edits)) {
		copied := make([]WelcomeJoiner, 0, len(base))
		for _, entry := range base {
			clone := entry
			clone.KeyPackage.InitKey = bytes.Clone(entry.KeyPackage.InitKey)
			clone.PathSecret = bytes.Clone(entry.PathSecret)
			copied = append(copied, clone)
		}
		edits[name](&copied[0])
		if reflect.DeepEqual(copied, base) {
			t.Fatalf("the move of WelcomeJoiner.%s left %s.%s equal to the base argument, so the gate would call it twice with the same value",
				name, operation, parameter.name)
		}
		moved = append(moved, providerPerturbation{where: name + " moved", value: reflect.ValueOf(copied)})
	}
	return moved
}

// welcomeMethodRowKeyPackage is the published key package the provider method row for
// (*StagedCommit).welcomeMessage addresses its one joiner to.
//
// Minted ONCE for the whole binary, because that row is run three times over three different
// providers and its answers are compared across them. NewKeyPackage draws fresh keys and stamps
// a lifetime off the wall clock, so a row that minted one per call would seal to a different
// init key every time and the routing differential would read that as the provider having moved.
//
// Through a provider of its OWN, for the reason the stub gate's own key package is: the row's
// provider may be one that flips every answer it gives, or one running a wider KDF, and neither
// is a thing to mint a key package with.
var welcomeMethodRowKeyPackage = sync.OnceValues(func() (*KeyPackage, error) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		return nil, err
	}
	kp, _, _, err := NewKeyPackage(crypto, CipherSuiteX25519ChaCha20Sha256Ed25519,
		BasicCredential([]byte("the joiner the welcome method row is addressed to")),
		testCapabilities(), nil)
	return kp, err
})
