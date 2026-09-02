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
		"ErrNilCryptoProvider":         ErrNilCryptoProvider,
		"ErrTreeMalformed":             ErrTreeMalformed,
		"ErrWelcomeTreeHashMismatch":   ErrWelcomeTreeHashMismatch,
		"ErrLeafIndexOutOfRange":       ErrLeafIndexOutOfRange,
		"errBlankSenderLeaf":           errBlankSenderLeaf,
		"ErrWelcomeGroupInfoSignature": ErrWelcomeGroupInfoSignature,
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
