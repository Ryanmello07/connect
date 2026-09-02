// The provenance questions asked from OUTSIDE package mls, which is where they were asked when
// they were answered wrongly.
//
// WHY AN EXTERNAL TEST PACKAGE AT ALL. Every other test of this package is package mls and can
// reach `inner` directly, so none of them can tell what an ATTACKER can reach. The two bypasses
// that defeated the previous round were both written in three lines of an importing package, and a
// gate that only ran with the field in scope was never going to see either of them. This file has
// exactly the reach a peer's code has: the exported identifiers and nothing else.
//
// THE TWO BYPASSES, AND WHAT THIS FILE SAYS ABOUT EACH.
//
//	// BYPASS A -- self-confirming, three lines
//	s, _ := mls.NewKeyScheduleFromEpochSecret(crypto, myOwn32Bytes, &decoded.GroupContext)
//	v, _ := s.ConfirmGroupContext(s.ConfirmationTag(decoded.GroupContext.ConfirmedTranscriptHash))
//	cache, _ := mls.NewProposalCache(v)
//
// A is CLOSED, and it is closed as a class rather than by the removal of a name. A key schedule is
// derived from a secret the same caller supplied over a context the same caller supplied, so
// nothing it can answer is authority; the test below asks the compiled method set of *KeySchedule
// whether ANY method answers a verified context, and the door enumeration asks the whole package's
// exported surface the same question. A second self-confirming door added anywhere fails those,
// where a test naming ConfirmGroupContext would have gone on passing.
//
//	// BYPASS B -- the honest joiner flow over an attacker-chosen joiner_secret
//
// B is NOT CLOSED, and this file says so by RUNNING it rather than by describing it. A Welcome is
// HPKE-sealed to a PUBLISHED init key, so anyone holding the victim's KeyPackage supplies the
// joiner_secret AND the group context, and the resulting key schedule, confirmation tag and
// GroupInfo signature are all perfectly consistent with each other. What (*GroupInfo).Verify adds
// is that the signature must be by a member of THE TREE THE CALLER PASSED -- so the attack now
// requires the attacker to supply the tree as well, which a joiner that lifts the ratchet_tree out
// of the same message hands it for free. The test drives both readings: against the joiner's own
// tree the forgery is refused, and against the tree the attacker supplied it verifies and a cache
// binds to epoch 1<<40 of ATTACKER-CHOSEN-GROUP.
//
// WHAT WOULD ACTUALLY CLOSE B is not a shape of this constructor. It is (*RatchetTree)
// .ValidateAgainstContext run by whoever obtained the tree, plus at least one leaf whose credential
// matches an identity the joiner ALREADY TRUSTS -- an authentication service, which this build does
// not have. Until that lands, the caller of VerifiedContext is the party making the authority
// claim, and the honest thing is a test that says which half is held.
package mls_test

import (
	"bytes"
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls"
	"github.com/urnetwork/connect/mls/syntax"
)

// The group an attacker names when it gets to choose, and the epoch it chooses. Written down once
// because three tests below assert the cache did or did not end up bound to this pair.
const (
	attackersGroupId = "ATTACKER-CHOSEN-GROUP"
	attackersEpoch   = uint64(1) << 40
)

// externalMember is one leaf's key material, kept because a signer outside this package has to hold
// its own private key: the tree publishes only the public half.
type externalMember struct {
	signaturePriv mls.SignaturePrivateKey
	signaturePub  mls.SignaturePublicKey
}

// externalTree builds an n member ratchet tree using nothing but the exported surface.
//
// A rebuild rather than a reach into the package's own fixture, and the duplication is the point:
// what this file is for is what a party outside the package can construct, and a helper it could
// not have written would be testing a reach it does not have. Every leaf is signed at its own index
// under LeafNodeSourceUpdate, which is the source that binds group id and leaf index into the
// signature, so a tree built here is one (*GroupInfo).Verify will accept signatures against.
func externalTree(t *testing.T, crypto mls.CryptoProvider, groupId []byte,
	n uint32) (*mls.RatchetTree, []externalMember) {
	t.Helper()
	tree := mls.NewRatchetTree()
	members := []externalMember{}
	for i := uint32(0); i < n; i += 1 {
		signaturePriv, signaturePub, err := crypto.SignatureKeyPair()
		if err != nil {
			t.Fatalf("SignatureKeyPair(%d): %v", i, err)
		}
		_, encryptionPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
		if err != nil {
			t.Fatalf("DeriveKeyPair(%d): %v", i, err)
		}
		leafKeys := &mls.LeafKeysExtension{
			AlgId:          mls.AlgIdXwing,
			DeviceXwingPub: crypto.Random(mls.XwingPublicKeyLen),
		}
		leafKeysExtension, err := leafKeys.Encode()
		if err != nil {
			t.Fatalf("LeafKeysExtension.Encode(%d): %v", i, err)
		}
		leaf := &mls.LeafNode{
			EncryptionKey: encryptionPub,
			SignatureKey:  signaturePub,
			Credential:    mls.BasicCredential([]byte("outsider")),
			Capabilities: mls.Capabilities{
				Versions:     []mls.ProtocolVersion{mls.ProtocolVersionMls10},
				CipherSuites: []mls.CipherSuite{mls.CipherSuiteX25519ChaCha20Sha256Ed25519},
				Extensions: []mls.ExtensionType{
					mls.ExtensionTypeUrmessageGroupPolicy,
					mls.ExtensionTypeUrmessageLeafKeys,
					mls.ExtensionTypeUrmessageOwnerSuccessor,
				},
				Credentials: []mls.CredentialType{mls.CredentialTypeBasic},
			},
			LeafNodeSource: mls.LeafNodeSourceUpdate,
			Extensions:     []mls.Extension{leafKeysExtension},
		}
		if err := leaf.Sign(crypto, signaturePriv, groupId, mls.LeafIndex(i)); err != nil {
			t.Fatalf("leaf Sign(%d): %v", i, err)
		}
		if err := tree.SetLeaf(mls.LeafIndex(i), leaf); err != nil {
			t.Fatalf("SetLeaf(%d): %v", i, err)
		}
		members = append(members, externalMember{signaturePriv: signaturePriv, signaturePub: signaturePub})
	}
	return tree, members
}

// externalCrypto is the provider every test here runs under.
func externalCrypto(t *testing.T) mls.CryptoProvider {
	t.Helper()
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	return crypto
}

// externalGroupContextOver is the group context an attacker writes when nothing stops it: the group
// it named, the epoch it chose, and the tree hash of whatever tree it means the victim to use.
func externalGroupContextOver(t *testing.T, crypto mls.CryptoProvider,
	tree *mls.RatchetTree) *mls.GroupContext {
	t.Helper()
	treeHash, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	return &mls.GroupContext{
		Version:                 mls.ProtocolVersionMls10,
		CipherSuite:             mls.CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:                 []byte(attackersGroupId),
		Epoch:                   attackersEpoch,
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0x99}, crypto.HashSize()),
	}
}

// externalRoundTrip puts a GroupInfo on the wire and takes it off again, which is how a joiner
// actually comes by one.
//
// Not a convenience: a test that handed the constructor the very structure it had just built in
// memory would be checking a path no peer's message takes, and the decode is where a *GroupContext
// with an attacker's group id and epoch enters this process at all.
func externalRoundTrip(t *testing.T, info *mls.GroupInfo) *mls.GroupInfo {
	t.Helper()
	octets, err := syntax.Marshal(info)
	if err != nil {
		t.Fatalf("marshal the group info: %v", err)
	}
	decoded := &mls.GroupInfo{}
	if err := syntax.Unmarshal(octets, decoded); err != nil {
		t.Fatalf("unmarshal the group info: %v", err)
	}
	return decoded
}

// ---------------------------------------------------------------------------
// bypass A: a key schedule the caller built cannot vouch for the caller's context
// ---------------------------------------------------------------------------

// TestNoKeyScheduleAnswersAVerifiedGroupContext is bypass A closed as a CLASS.
//
// The three line laundering worked because the context went in through an exported KeySchedule
// constructor and came back out vouched for by a tag computed from the same exported type -- one
// party agreeing with itself. Naming the method that did it would let the next one through, so what
// is asked here is the question the bypass is an instance of: does any method of a key schedule
// answer a verified context at all, in any result position? A key schedule is derived from secrets
// its caller supplied over a context its caller supplied, so the answer must be no whatever the
// method is called.
func TestNoKeyScheduleAnswersAVerifiedGroupContext(t *testing.T) {
	crypto := externalCrypto(t)
	tree, _ := externalTree(t, crypto, []byte(attackersGroupId), 1)
	context := externalGroupContextOver(t, crypto, tree)
	schedule, err := mls.NewKeyScheduleFromEpochSecret(crypto,
		bytes.Repeat([]byte{0x4a}, crypto.HashSize()), context)
	if err != nil {
		t.Fatalf("the attacker's own key schedule over its own context: %v", err)
	}
	verified := reflect.TypeOf((*mls.VerifiedGroupContext)(nil))
	held := reflect.TypeOf(schedule)
	if held.NumMethod() == 0 {
		t.Fatal("*KeySchedule exposes no methods at all, so this gate asked nothing")
	}
	for i := range held.NumMethod() {
		method := held.Method(i)
		for at := range method.Type.NumOut() {
			if method.Type.Out(at) != verified {
				continue
			}
			t.Errorf("(*KeySchedule).%s answers a %s at result %d; a key schedule is expanded over a group context ITS CALLER SUPPLIED from a secret ITS CALLER SUPPLIED, so anything it vouches for is the caller vouching for itself -- which is the three line laundering this whole line of work exists to stop",
				method.Name, verified, at)
		}
	}
}

// TestTheZeroVerifiedGroupContextIsTheOnlyOneAnOutsiderCanSpell is what makes the door enumeration
// below the whole story.
//
// mls.VerifiedGroupContext{} compiles anywhere. What stops it being an authority is that the field
// is unexported -- so the literal carries nothing -- and that every consumer refuses the value that
// results. Both halves are asserted here, from outside, because a field that became exported would
// make every gate in this file watch a door that no longer matters.
func TestTheZeroVerifiedGroupContextIsTheOnlyOneAnOutsiderCanSpell(t *testing.T) {
	held := reflect.TypeOf(mls.VerifiedGroupContext{})
	for i := range held.NumField() {
		if held.Field(i).IsExported() {
			t.Fatalf("VerifiedGroupContext.%s is exported, so any package can build one carrying whatever it decoded and the type says nothing at all",
				held.Field(i).Name)
		}
	}
	zero := &mls.VerifiedGroupContext{}
	if got := zero.Context(); got != nil {
		t.Errorf("the zero verified context answered %+v, want nil", got)
	}
	if _, err := mls.NewProposalCache(zero); !errors.Is(err, mls.ErrNilGroupContext) {
		t.Errorf("NewProposalCache(the zero verified context) = %v, want ErrNilGroupContext", err)
	}
}

// TestADecodedGroupInfoIsNotVouchedForByTheTreeTheJoinerIsAlreadyIn is bypass A driven end to end
// with the attacker in the position it is actually in.
//
// The attacker writes a GroupInfo naming its own group at epoch 1<<40, computes a confirmation tag
// its own key schedule agrees with, and puts it on the wire. The victim decodes it and asks the one
// door there is, holding the tree of the group it is really in. The refusal is the tree hash rule,
// which is the FIRST of Verify's four and the one that means "this is not about my group at all".
func TestADecodedGroupInfoIsNotVouchedForByTheTreeTheJoinerIsAlreadyIn(t *testing.T) {
	crypto := externalCrypto(t)
	attackersTree, attackers := externalTree(t, crypto, []byte(attackersGroupId), 1)
	victimsTree, _ := externalTree(t, crypto, []byte("the group the victim is in"), 4)

	context := externalGroupContextOver(t, crypto, attackersTree)
	schedule, err := mls.NewKeyScheduleFromEpochSecret(crypto,
		bytes.Repeat([]byte{0x4a}, crypto.HashSize()), context)
	if err != nil {
		t.Fatalf("the attacker's own key schedule: %v", err)
	}
	info := &mls.GroupInfo{
		GroupContext:    *context,
		ConfirmationTag: schedule.ConfirmationTag(context.ConfirmedTranscriptHash),
		Signer:          mls.LeafIndex(0),
	}
	if err := info.Sign(crypto, attackers[0].signaturePriv); err != nil {
		t.Fatalf("the attacker signing its own group info: %v", err)
	}
	decoded := externalRoundTrip(t, info)
	if !bytes.Equal(decoded.GroupContext.GroupId, []byte(attackersGroupId)) ||
		decoded.GroupContext.Epoch != attackersEpoch {
		t.Fatalf("the decoded group info names epoch %d of group %x, so this test is not driving the attack it describes",
			decoded.GroupContext.Epoch, decoded.GroupContext.GroupId)
	}

	verified, err := decoded.VerifiedContext(crypto, victimsTree)
	if verified != nil {
		t.Errorf("a group info naming epoch %d of %s was vouched for against the tree of a group the attacker is not in",
			attackersEpoch, attackersGroupId)
	}
	if !errors.Is(err, mls.ErrWelcomeTreeHashMismatch) {
		t.Errorf("the attacker's group info answered %v against the victim's own tree, want ErrWelcomeTreeHashMismatch",
			err)
	}
}

// ---------------------------------------------------------------------------
// bypass B: still open, and open in exactly one place
// ---------------------------------------------------------------------------

// TestBypassBIsClosedOnlyAgainstATreeTheJoinerAlreadyTrusts is the honest joiner flow run over an
// attacker-chosen joiner_secret, and it is written to FAIL if anybody makes this file's account of
// it stop being true in either direction.
//
// The attacker's position is real and not weakened for the test: a Welcome is HPKE-sealed to a
// PUBLISHED init key, so the party that seals it chooses the joiner_secret and the group context
// both, and the schedule it derives agrees with the confirmation tag it publishes. The first
// assertion measures exactly that -- the premise the deleted constructor rested on still holds, so
// what changed is the door and not the attacker's reach.
//
// Then the two readings of the new door, and the second is the residual gap stated as a fact:
//
//  1. Against the tree of the group the joiner is really in, the forgery is refused.
//  2. Against the tree the ATTACKER supplied, it VERIFIES, and a proposal cache binds to epoch
//     1<<40 of ATTACKER-CHOSEN-GROUP. Verify establishes that a member of the tree the caller
//     passed signed this -- and when the caller passed the attacker's tree, the attacker is that
//     member. A joiner that lifts the ratchet_tree extension out of the very GroupInfo it is
//     checking has done this to itself.
//
// It asserts the SUCCESS in case 2 rather than papering over it. A test that only asserted case 1
// would let this file read as though B were closed, which is the thing the constructor must not be
// shipped reading as.
func TestBypassBIsClosedOnlyAgainstATreeTheJoinerAlreadyTrusts(t *testing.T) {
	crypto := externalCrypto(t)
	attackersTree, attackers := externalTree(t, crypto, []byte(attackersGroupId), 1)
	victimsTree, _ := externalTree(t, crypto, []byte("the group the victim is in"), 4)
	context := externalGroupContextOver(t, crypto, attackersTree)

	// the joiner secret is the ATTACKER'S, because the Welcome carrying it was sealed to a
	// published init key: whoever holds the victim's key package supplies it
	joinerSecret := bytes.Repeat([]byte{0x11}, crypto.HashSize())
	pskSecret := bytes.Repeat([]byte{0x22}, crypto.HashSize())
	attackersSchedule, err := mls.NewKeyScheduleFromJoiner(crypto, joinerSecret, pskSecret, context)
	if err != nil {
		t.Fatalf("the attacker's joiner schedule: %v", err)
	}
	tag := attackersSchedule.ConfirmationTag(context.ConfirmedTranscriptHash)

	// the premise, measured: the victim deriving the SAME schedule from the secret it was sent
	// finds the tag perfectly good. Nothing about a confirmation tag was ever authority
	victimsSchedule, err := mls.NewKeyScheduleFromJoiner(crypto, joinerSecret, pskSecret, context)
	if err != nil {
		t.Fatalf("the victim's joiner schedule over the same secret: %v", err)
	}
	if !victimsSchedule.VerifyConfirmationTag(context.ConfirmedTranscriptHash, tag) {
		t.Fatal("the joiner flow's own confirmation tag did not verify, so this test is not driving bypass B at all -- the whole point is that it does")
	}

	info := &mls.GroupInfo{
		GroupContext:    *context,
		ConfirmationTag: tag,
		Signer:          mls.LeafIndex(0),
	}
	if err := info.Sign(crypto, attackers[0].signaturePriv); err != nil {
		t.Fatalf("the attacker signing the group info it is sending: %v", err)
	}
	decoded := externalRoundTrip(t, info)

	// 1. the half that IS closed
	if _, err := decoded.VerifiedContext(crypto, victimsTree); !errors.Is(err,
		mls.ErrWelcomeTreeHashMismatch) {
		t.Errorf("the attacker's group info against the joiner's own tree = %v, want ErrWelcomeTreeHashMismatch; a joiner that already knows its group's tree is the case this door does hold",
			err)
	}

	// 2. the half that is NOT, asserted as the fact it is
	verified, err := decoded.VerifiedContext(crypto, attackersTree)
	if err != nil {
		t.Fatalf("the attacker's group info against the attacker's OWN tree = %v; this file's account of the residual gap says it verifies, and an account that has stopped being true is worse than no account -- if a later change closed this, rewrite the header rather than deleting the case",
			err)
	}
	cache, err := mls.NewProposalCache(verified)
	if err != nil {
		t.Fatalf("NewProposalCache over the attacker's verified context: %v", err)
	}
	if cache == nil {
		t.Fatal("no cache was built, so the reading below observes nothing")
	}
	answered := verified.Context()
	if !bytes.Equal(answered.GroupId, []byte(attackersGroupId)) || answered.Epoch != attackersEpoch {
		t.Errorf("the verified context names epoch %d of group %x, want epoch %d of %s; the point of this case is that the attacker's OWN choices came through, so a different answer means the case has drifted off the attack it documents",
			answered.Epoch, answered.GroupId, attackersEpoch, attackersGroupId)
	}
}

// ---------------------------------------------------------------------------
// every exported door onto the type, derived from the compiler
// ---------------------------------------------------------------------------

// externalDoorsOntoAVerifiedGroupContext is every exported declaration of package mls whose
// signature ANSWERS a verified group context, read off the type checker.
//
// The class and not a list of names, which is rule 5 at the only boundary that matters here: what
// stops bypass A coming back is not that ConfirmGroupContext was deleted, it is that there is one
// door and its parameters carry authority. A second door added anywhere in the package -- a method
// of any exported type, a package level function, a package level var holding a function -- lands
// in this class and fails the table until somebody says what it is.
//
// The three shapes are enumerated rather than one, because an exported symbol answering a value can
// be any of them and a rule reading only funcs would report a clean run over the other two.
func externalDoorsOntoAVerifiedGroupContext(t *testing.T) (map[string]string, int) {
	t.Helper()
	found, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list the source of package mls: %v", err)
	}
	paths := []string{}
	for _, path := range found {
		if !strings.HasSuffix(path, "_test.go") {
			paths = append(paths, path)
		}
	}
	if len(paths) == 0 {
		t.Fatal("package mls holds no non test source, so this gate scanned nothing")
	}
	fileSet := token.NewFileSet()
	files := []*ast.File{}
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		file, err := parser.ParseFile(fileSet, path, body, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files = append(files, file)
	}
	refused := []string{}
	config := types.Config{
		Importer: importer.ForCompiler(fileSet, "source", nil),
		Error:    func(err error) { refused = append(refused, err.Error()) },
	}
	checked, err := config.Check("github.com/urnetwork/connect/mls", fileSet, files, nil)
	if err != nil || len(refused) != 0 {
		t.Fatalf("type check package mls from outside it: %v %s", err, strings.Join(refused, "; "))
	}

	doors := map[string]string{}
	judged := 0
	answersOne := func(signature *types.Signature) bool {
		results := signature.Results()
		if results == nil {
			return false
		}
		for at := 0; at < results.Len(); at += 1 {
			if externalNamedAs(results.At(at).Type(), "VerifiedGroupContext") {
				return true
			}
		}
		return false
	}
	scope := checked.Scope()
	for _, name := range scope.Names() {
		object := scope.Lookup(name)
		if !object.Exported() {
			continue
		}
		switch held := object.(type) {
		case *types.Func:
			signature, isSignature := held.Type().(*types.Signature)
			if !isSignature {
				continue
			}
			judged += 1
			if answersOne(signature) {
				doors[name] = signature.String()
			}
		case *types.Var:
			signature, isSignature := held.Type().(*types.Signature)
			if !isSignature {
				continue
			}
			judged += 1
			if answersOne(signature) {
				doors["var "+name] = signature.String()
			}
		case *types.TypeName:
			named, isNamed := held.Type().(*types.Named)
			if !isNamed {
				continue
			}
			for i := 0; i < named.NumMethods(); i += 1 {
				method := named.Method(i)
				if !method.Exported() {
					continue
				}
				signature, isSignature := method.Type().(*types.Signature)
				if !isSignature {
					continue
				}
				judged += 1
				if !answersOne(signature) {
					continue
				}
				receiver := name
				if _, isPointer := signature.Recv().Type().(*types.Pointer); isPointer {
					receiver = "(*" + name + ")"
				}
				doors[receiver+"."+method.Name()] = signature.String()
			}
		}
	}
	return doors, judged
}

// externalNamedAs answers whether the compiler reads a type as the named type spelled name, through
// any number of pointers. The package's own gates keep the same helper for the same reason: a value
// reached through a pointer and one reached directly are the same type to a caller.
func externalNamedAs(found types.Type, name string) bool {
	for {
		pointer, isPointer := found.(*types.Pointer)
		if !isPointer {
			break
		}
		found = pointer.Elem()
	}
	named, isNamed := found.(*types.Named)
	return isNamed && named.Obj() != nil && named.Obj().Name() == name
}

// The exported doors onto a verified group context, with why each is entitled to be one.
var externalVerifiedGroupContextDoors = map[string]string{
	"(*GroupInfo).VerifiedContext": "the one door. It is (*GroupInfo).Verify: a member of the ratchet " +
		"tree the CALLER passed signed this GroupInfoTBS under the GroupInfoTBS label, and the signer's " +
		"public key came out of that tree rather than out of the message -- which is why the tree is in " +
		"the signature and why a door without one would be a caller vouching for itself again",
}

// TestTheOnlyExportedDoorOntoAVerifiedGroupContextIsAVerifiedGroupInfo holds the class above to its
// table in both directions, and then holds the one door to carrying the parameter that makes it a
// door at all.
//
// The parameter assertion is not ceremony. Four rounds of this work produced constructors whose
// signatures carried the VALUE and not the AUTHORITY -- a *GroupContext, then a *KeySchedule the
// caller had just built -- and each read as a check while checking the caller's own say-so. A tree
// is the only thing that can say who a group's members are, so a door that stopped taking one would
// be that mistake for the fifth time, and it fails here.
func TestTheOnlyExportedDoorOntoAVerifiedGroupContextIsAVerifiedGroupInfo(t *testing.T) {
	doors, judged := externalDoorsOntoAVerifiedGroupContext(t)
	if judged == 0 {
		t.Fatal("no exported signature of package mls was resolved, so this gate would report a clean run over any package at all")
	}
	classified := slices.Sorted(maps.Keys(externalVerifiedGroupContextDoors))
	if names := slices.Sorted(maps.Keys(doors)); !slices.Equal(names, classified) {
		t.Fatalf("%v answer a *VerifiedGroupContext to an outside caller and this table names %v; a door with no row is a new way for a peer's octets to acquire this client's vouching, and a row with no door is a claim that outlived what it described",
			names, classified)
	}
	for _, name := range classified {
		if externalVerifiedGroupContextDoors[name] == "" {
			t.Errorf("%s is classified with no account of what entitles it", name)
		}
		t.Logf("%s is %s", name, doors[name])
	}

	door, held := reflect.TypeOf(&mls.GroupInfo{}).MethodByName("VerifiedContext")
	if !held {
		t.Fatal("(*GroupInfo).VerifiedContext is not a method of *GroupInfo, so the table above names a door that is not there")
	}
	tree := reflect.TypeOf((*mls.RatchetTree)(nil))
	takesATree := false
	for at := range door.Type.NumIn() {
		if door.Type.In(at) == tree {
			takesATree = true
		}
	}
	if !takesATree {
		t.Errorf("(*GroupInfo).VerifiedContext takes no %s; the signer's public key is not a field of a GroupInfo, so without a tree there is nothing in the call that can say who the members are and the door is the caller vouching for its own octets",
			tree)
	}
}
