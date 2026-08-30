// The group lifecycle plan's shared fixtures: one identity, one leaf, one key package, built
// the way all twenty three remaining tasks of this plan need them -- and the checks that stop a
// wrong fixture from being agreed with twenty three times over.
//
// A fixture is not an ordinary helper, for the reason tree_testutil_test.go states one plan
// earlier: a fixture that is subtly wrong does not FAIL the tasks that read it, it makes all of
// them agree with the same wrong thing, and what that produces is a green suite. So each of the
// four below is held here, on its own, against something that is not itself:
//
//   - testIdentity, by MINTING TWICE. A fixture that answered one fixed key pair for every
//     member turns every multi member test in this plan into a single member test that happens
//     to run twice: the tree still builds, every leaf still validates, every signature still
//     verifies, and two members are one member. Nothing downstream can see it, because a
//     duplicate key is a perfectly good key.
//   - testKeyPackage, by USING each private half for the thing only it can do. It answers the
//     init key and the encryption key IN THAT ORDER, and the two are opaque byte slices of the
//     same length that round trip and compare fine while being the wrong way round. Swapping
//     them fails nothing until task 16 tries to open a Welcome, fifteen tasks away, with no
//     reason to suspect the fixture. The order test seals to each public half and requires the
//     OTHER private half to fail, which is the only assertion an order can be read off.
//   - testLeafNode and testLeafKeys, by section 7.3 VALIDATION. LeafNode.Validate is p5's,
//     written against the RFC's own rules and tested there, so a fixture leaf no validator would
//     accept is caught here rather than papered over locally by each later task -- and papered
//     over differently by each, which is the shape that makes two tasks disagree about what a
//     valid leaf is.
//   - testKeyPackage again, by its own KeyPackage.Validate. This is the one the plan's draft got
//     wrong. NewKeyPackage draws its own signature key pair and signs the whole key package with
//     it; rebinding the leaf to the member's identity key and re-signing THE LEAF leaves
//     kp.Signature over a preimage that no longer exists and kp.signPriv holding a key the leaf
//     no longer names. Both halves are invisible to a leaf level assertion -- the leaf verifies
//     perfectly -- and both are exactly what task 12's Add path and task 16's JoinKeyMaterial
//     read. So the fixture re-signs the key package too, and the test below is what says so.
package mls

import (
	"bytes"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// testMember is one identity plus the device material a leaf needs.
//
// The tree fixture's per leaf member is testTreeMember, which is a different thing: it carries a
// leaf index and the private halves of a leaf that is already IN a tree. This one is an identity
// before any tree exists.
type testMember struct {
	Name        string
	IdentityPub []byte
	SigPriv     SignaturePrivateKey
	SigPub      SignaturePublicKey
	XwingPub    []byte
}

// testCrypto returns the v1 ciphersuite provider.
func testCrypto(t *testing.T) CryptoProvider {
	t.Helper()
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	return crypto
}

// testIdentity mints a signature key pair and a stand-in X-Wing public key of the right length.
// The X-Wing key is opaque to mls; only its length matters, which is what the extension's own
// encoder refuses anything else for.
//
// A FRESH pair per call, which is the whole content of this helper: two members are two members.
//
// IdentityPub is a COPY of the public key rather than a reconversion of it. SignaturePublicKey
// is a []byte, so []byte(sigPub) shares the array, and a later task that appends to or edits one
// of the two fields edits the other -- a member whose credential silently stops matching its own
// signature key, with nothing at the point of the edit to say so.
func testIdentity(t *testing.T, crypto CryptoProvider, name string) *testMember {
	t.Helper()
	sigPriv, sigPub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair(%s): %v", name, err)
	}
	return &testMember{
		Name:        name,
		IdentityPub: bytes.Clone(sigPub),
		SigPriv:     sigPriv,
		SigPub:      sigPub,
		XwingPub:    crypto.Random(XwingPublicKeyLen),
	}
}

// testCapabilities is what every v1 leaf in these fixtures advertises.
//
// Suites() rather than the one code point, because the capabilities vector says what this member
// CAN do and not what this group runs; a member advertising only the group's own suite is a
// member no other suite could ever add. The three private use extension types are listed because
// every leaf this profile builds carries urmessage_leaf_keys and every group context carries
// urmessage_group_policy, and section 7.3 refuses a leaf that carries or meets an extension type
// it does not list.
//
// No proposal types, and empty is the CONFORMING answer rather than a gap: add, update and
// remove are section 7.2 "default" types, which section 7.2 forbids a leaf to list.
func testCapabilities() Capabilities {
	return Capabilities{
		Versions:     []ProtocolVersion{ProtocolVersionMls10},
		CipherSuites: Suites(),
		Extensions: []ExtensionType{
			ExtensionTypeUrmessageGroupPolicy,
			ExtensionTypeUrmessageLeafKeys,
			ExtensionTypeUrmessageOwnerSuccessor,
		},
		Proposals:   []ProposalType{},
		Credentials: []CredentialType{CredentialTypeBasic},
	}
}

// testLeafKeys builds the urmessage_leaf_keys extension every fixture leaf carries, through
// TreeKEM's own Encode rather than by assembling the body here. Encode answers the whole
// Extension, tag and body together, which is what keeps the body off a path where a caller pairs
// it with a tag of its own choosing.
func testLeafKeys(t *testing.T, m *testMember) Extension {
	t.Helper()
	ext, err := (&LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: m.XwingPub}).Encode()
	if err != nil {
		t.Fatalf("LeafKeysExtension.Encode(%s): %v", m.Name, err)
	}
	return ext
}

// testLeafNode mints one key_package sourced leaf for this member and returns the encryption
// private key that goes with it.
func testLeafNode(t *testing.T, crypto CryptoProvider, m *testMember) (*LeafNode, HpkePrivateKey) {
	t.Helper()
	encPriv, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		t.Fatalf("DeriveKeyPair(%s): %v", m.Name, err)
	}
	leaf, err := NewLeafNode(crypto, m.SigPriv, BasicCredential(m.IdentityPub), encPub,
		testCapabilities(), []Extension{testLeafKeys(t, m)})
	if err != nil {
		t.Fatalf("NewLeafNode(%s): %v", m.Name, err)
	}
	return leaf, encPriv
}

// testKeyPackage mints a key package plus its init and encryption private keys, IN THAT ORDER,
// through TreeKEM's constructor rather than by hand.
//
// NewKeyPackage takes no signer: it draws its own signature key pair, puts the public half in
// the leaf and signs both the leaf and the whole key package with the private half. Every later
// task of this plan needs the key package to be the MEMBER's -- task 12 compares an Add's leaf
// signature key against the proposer's identity, and task 16 reads kp.signPriv into
// JoinKeyMaterial -- so all three of those are rebound here.
//
// All THREE, and that is the correction. Rebinding the leaf alone leaves kp.Signature over the
// old leaf, which KeyPackage.Validate refuses with errKeyPackageBadSignature, and leaves
// kp.signPriv holding a private key whose public half the leaf no longer names, which nothing
// refuses at all -- it is read, used to sign a joiner's first message, and rejected by every
// peer. A key_package leaf's LeafNodeTBS excludes group_id and leaf_index, which is why those
// two arguments are nil and 0.
func testKeyPackage(t *testing.T, crypto CryptoProvider, m *testMember) (*KeyPackage, HpkePrivateKey, HpkePrivateKey) {
	t.Helper()
	kp, initPriv, encPriv, err := NewKeyPackage(crypto, CipherSuiteX25519ChaCha20Sha256Ed25519,
		BasicCredential(m.IdentityPub), testCapabilities(), []Extension{testLeafKeys(t, m)})
	if err != nil {
		t.Fatalf("NewKeyPackage(%s): %v", m.Name, err)
	}
	kp.LeafNode.SignatureKey = m.SigPub
	if err := kp.LeafNode.Sign(crypto, m.SigPriv, nil, 0); err != nil {
		t.Fatalf("LeafNode.Sign(%s): %v", m.Name, err)
	}
	kp.signPriv = m.SigPriv
	content, err := kp.signedPreimage()
	if err != nil {
		t.Fatalf("KeyPackage.signedPreimage(%s): %v", m.Name, err)
	}
	signature, err := crypto.SignWithLabel(m.SigPriv, keyPackageSignatureLabel, content)
	if err != nil {
		t.Fatalf("SignWithLabel(%s): %v", m.Name, err)
	}
	kp.Signature = signature
	return kp, initPriv, encPriv
}

// testLeafValidation is the section 7.3 context a fixture leaf is judged in: this profile's one
// suite, the key_package source both fixtures mint under, and a REAL clock. The clock is real
// because LeafValidationContext reads a NowMs of 0 as "do not check the lifetime at all", and a
// fixture whose lifetime was never checked is a fixture that can ship an expired leaf.
func testLeafValidation(crypto CryptoProvider) *LeafValidationContext {
	return &LeafValidationContext{
		Crypto:         crypto,
		Suite:          CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:        nil,
		LeafIndex:      0,
		ExpectedSource: LeafNodeSourceKeyPackage,
		NowMs:          uint64(max(time.Now().UnixMilli(), 1)),
		ClockSkewMs:    leafLifetimeSkewSeconds * 1000,
	}
}

// lifecycleErrorsFile is the single file this plan declares its policy refusals in. Every gate
// below is keyed on it rather than on a list of names, so a twenty sixth error added by a later
// task of this plan is swept without anybody editing a sweep.
const lifecycleErrorsFile = "errors_lifecycle.go"

// lifecycleOwnedErrors is every name errors_lifecycle.go declares, keyed by that name.
//
// It is the shape framing_errors.go's class already takes, and it is written here rather than
// derived from the file at run time for the reason tree_errors_test.go gives about every one of
// these classes: a class computed from the same file it is judging agrees with that file
// whatever the file says. What holds the two together is
// TestLifecycleOwnedErrorsIsEveryErrorItsFileDeclares, which reads the file's declarations and
// requires the two sets to be equal in BOTH directions, so a sentinel added to the file and not
// to this map -- and a name here the file no longer declares -- is a failure naming it.
//
// mlsErrorClasses holds this under lifecycleErrorsFile, which is what puts these twenty five
// inside TestEveryExportedErrorOfThisPackageIsInAMaintainedClass and inside the exclusivity
// sweep over every ordered pair of this package's classes. Without that entry the whole set is a
// surface a caller can branch on that no sweep in this package judges -- which is exactly the
// hole that gate was written for, and it is the failure this task's first full run produced.
var lifecycleOwnedErrors = map[string]error{
	"ErrGroupSizeExceeded":           ErrGroupSizeExceeded,
	"ErrDeviceLimitExceeded":         ErrDeviceLimitExceeded,
	"ErrAdminRemovedByNonOwner":      ErrAdminRemovedByNonOwner,
	"ErrSuccessionDisabled":          ErrSuccessionDisabled,
	"ErrSuccessionNotNominee":        ErrSuccessionNotNominee,
	"ErrSuccessionQuorum":            ErrSuccessionQuorum,
	"ErrSuccessionFloor":             ErrSuccessionFloor,
	"ErrSuccessionFloorTooShort":     ErrSuccessionFloorTooShort,
	"ErrNoGroupPolicy":               ErrNoGroupPolicy,
	"ErrMalformedExtension":          ErrMalformedExtension,
	"ErrDuplicateRoleEntry":          ErrDuplicateRoleEntry,
	"ErrRolesNotCanonical":           ErrRolesNotCanonical,
	"ErrNoOwner":                     ErrNoOwner,
	"ErrMultipleOwners":              ErrMultipleOwners,
	"ErrWelcomeNoMatchingKeyPackage": ErrWelcomeNoMatchingKeyPackage,
	"ErrWelcomeGroupInfoDecrypt":     ErrWelcomeGroupInfoDecrypt,
	"ErrWelcomeGroupInfoSignature":   ErrWelcomeGroupInfoSignature,
	"ErrWelcomeTreeHashMismatch":     ErrWelcomeTreeHashMismatch,
	"ErrWelcomeLeafNotFound":         ErrWelcomeLeafNotFound,
	"ErrWelcomeSuiteMismatch":        ErrWelcomeSuiteMismatch,
	"ErrGroupIdInUse":                ErrGroupIdInUse,
	"ErrPendingCommitExists":         ErrPendingCommitExists,
	"ErrNoPendingCommit":             ErrNoPendingCommit,
	"ErrEpochStale":                  ErrEpochStale,
	"ErrRemovedFromGroup":            ErrRemovedFromGroup,
}

// TestLifecycleOwnedErrorsIsEveryErrorItsFileDeclares holds the class to the file in both
// directions, which is what makes every sweep below and in tree_errors_test.go run over the set
// the package actually ships rather than over the set somebody last remembered.
func TestLifecycleOwnedErrorsIsEveryErrorItsFileDeclares(t *testing.T) {
	declared := packageLevelDeclarations(t, ".")
	fromFile := []string{}
	for name, file := range declared {
		if file == lifecycleErrorsFile && strings.HasPrefix(name, "Err") {
			fromFile = append(fromFile, name)
		}
	}
	slices.Sort(fromFile)
	// the positive control: a scan reading the wrong file and a prefix filter matching nothing
	// report exactly the clean bill a complete scan reports
	if !slices.Contains(fromFile, "ErrGroupSizeExceeded") {
		t.Fatalf("the scan read %v out of %s, which certainly declares ErrGroupSizeExceeded, so it is reading something other than that file",
			fromFile, lifecycleErrorsFile)
	}
	if want := slices.Sorted(maps.Keys(lifecycleOwnedErrors)); !slices.Equal(fromFile, want) {
		t.Fatalf("%s declares %v and lifecycleOwnedErrors holds %v; every sweep of this package runs over the second, so a sentinel missing from it is one nothing judges",
			lifecycleErrorsFile, fromFile, want)
	}
	if _, held := mlsErrorClasses[lifecycleErrorsFile]; !held {
		t.Fatalf("mlsErrorClasses holds no class for %s, so the package wide exclusivity sweep runs past every one of these",
			lifecycleErrorsFile)
	}
}

// TestLifecycleErrorsAreDistinct sweeps the class rather than a slice literal of its own.
//
// The class is the one the derivation above holds to the file, so a twenty sixth sentinel is
// swept here the moment it is declared, and a sentinel deleted from the file fails there rather
// than quietly shrinking what this loop runs over. The count is still asserted, because a class
// and a sweep that both went empty would agree with each other perfectly.
func TestLifecycleErrorsAreDistinct(t *testing.T) {
	names := slices.Sorted(maps.Keys(lifecycleOwnedErrors))
	if len(names) != 25 {
		t.Fatalf("the lifecycle error set holds %d values, this task produces 25", len(names))
	}
	for _, name := range names {
		a := lifecycleOwnedErrors[name]
		if a == nil {
			t.Fatalf("%s is nil", name)
		}
		if a.Error() == "" {
			t.Fatalf("%s has an empty message", name)
		}
		if !strings.HasPrefix(a.Error(), "mls: ") {
			t.Errorf("%s reads %q; every refusal this package hands a caller names the package it came from",
				name, a.Error())
		}
		for _, other := range names {
			if name != other && errors.Is(a, lifecycleOwnedErrors[other]) {
				t.Fatalf("%s and %s are the same value: %v", name, other, a)
			}
		}
	}
}

func TestLifecycleConstants(t *testing.T) {
	if MaxGroupMembers != 500 {
		t.Fatalf("MaxGroupMembers = %d, want 500", MaxGroupMembers)
	}
	if MaxDeviceLeavesPerIdentity != 10 {
		t.Fatalf("MaxDeviceLeavesPerIdentity = %d, want 10", MaxDeviceLeavesPerIdentity)
	}
}

func TestFixtureIdentityIsUsable(t *testing.T) {
	crypto := testCrypto(t)
	alice := testIdentity(t, crypto, "alice")
	if alice.Name != "alice" {
		t.Fatalf("Name = %q, want alice", alice.Name)
	}
	if len(alice.XwingPub) != XwingPublicKeyLen {
		t.Fatalf("XwingPub length = %d, want %d", len(alice.XwingPub), XwingPublicKeyLen)
	}
	sig, err := crypto.SignWithLabel(alice.SigPriv, "FixtureProbe", []byte("hello"))
	if err != nil {
		t.Fatalf("SignWithLabel: %v", err)
	}
	if err := crypto.VerifyWithLabel(alice.SigPub, "FixtureProbe", []byte("hello"), sig); err != nil {
		t.Fatalf("VerifyWithLabel: %v", err)
	}
	// the credential identity and the signature key are the same bytes, which is what
	// BasicCredential(m.IdentityPub) means in every fixture below
	if !bytes.Equal(alice.IdentityPub, alice.SigPub) {
		t.Fatal("IdentityPub is not the member's own signature public key")
	}
	if len(alice.IdentityPub) == 0 {
		t.Fatal("IdentityPub is empty")
	}
}

// TestFixtureIdentitiesWithDifferentNamesShareNoKeyMaterial is the mint-twice check.
//
// A fixture that answered one fixed key pair for every member is invisible to everything else in
// this plan: the tree builds, the leaves validate, the signatures verify, and every multi member
// test becomes a single member test that runs twice. Every field that carries key material is
// compared, not just the signature key, because a fixture can be fresh in one field and fixed in
// another -- an X-Wing filler drawn once at package level would leave two members sharing a
// device key while their signature keys differed, which is precisely a second device of one
// identity masquerading as a second identity.
func TestFixtureIdentitiesWithDifferentNamesShareNoKeyMaterial(t *testing.T) {
	crypto := testCrypto(t)
	alice := testIdentity(t, crypto, "alice")
	bob := testIdentity(t, crypto, "bob")
	if alice.Name == bob.Name {
		t.Fatalf("both members are named %q, so this test compares one member with itself", alice.Name)
	}
	if bytes.Equal(alice.SigPub, bob.SigPub) {
		t.Error("two members mint the same signature public key")
	}
	if bytes.Equal(alice.SigPriv, bob.SigPriv) {
		t.Error("two members mint the same signature private key")
	}
	if bytes.Equal(alice.IdentityPub, bob.IdentityPub) {
		t.Error("two members carry the same credential identity")
	}
	if bytes.Equal(alice.XwingPub, bob.XwingPub) {
		t.Error("two members carry the same device X-Wing public key")
	}
	// and the private half a member holds is the one its own public half names, which is what
	// says the two were minted as a PAIR rather than crossed between the two members
	sig, err := crypto.SignWithLabel(alice.SigPriv, "FixtureProbe", []byte("alice"))
	if err != nil {
		t.Fatalf("SignWithLabel: %v", err)
	}
	if err := crypto.VerifyWithLabel(bob.SigPub, "FixtureProbe", []byte("alice"), sig); err == nil {
		t.Error("alice's signature verifies under bob's public key, so the two members share a key pair")
	}
}

// TestFixtureLeafNodeIsAcceptedBySection73Validation holds testLeafNode and testLeafKeys to the
// validator every later task will put their output through.
//
// LeafNode.Validate is p5's and is tested against the RFC's own rules there, so it is a measure
// that is not this file. A fixture leaf it refuses is a leaf twenty three tasks would each paper
// over locally, and differently.
func TestFixtureLeafNodeIsAcceptedBySection73Validation(t *testing.T) {
	crypto := testCrypto(t)
	carol := testIdentity(t, crypto, "carol")
	leaf, encPriv := testLeafNode(t, crypto, carol)
	if err := leaf.Validate(testLeafValidation(crypto)); err != nil {
		t.Fatalf("the fixture leaf does not pass section 7.3 validation: %v", err)
	}
	if !bytes.Equal(leaf.SignatureKey, carol.SigPub) {
		t.Error("the fixture leaf is not bound to the member's signature key")
	}
	if _, err := ParseLeafKeysFrom(leaf.Extensions[0]); err != nil {
		t.Fatalf("the fixture leaf's urmessage_leaf_keys entry does not parse: %v", err)
	}
	// the returned private half is the leaf's own encryption key and not some other draw:
	// sealed to what the leaf publishes, opened with what the fixture handed back
	kemOutput, ciphertext, err := crypto.HpkeSeal(leaf.EncryptionKey, []byte("info"), []byte("aad"),
		[]byte("to the leaf"))
	if err != nil {
		t.Fatalf("HpkeSeal to the leaf's encryption key: %v", err)
	}
	opened, err := crypto.HpkeOpen(encPriv, kemOutput, []byte("info"), []byte("aad"), ciphertext)
	if err != nil {
		t.Fatalf("the private key testLeafNode returned does not open a message sealed to the leaf's encryption key: %v", err)
	}
	if !bytes.Equal(opened, []byte("to the leaf")) {
		t.Fatalf("opened %q, want %q", opened, "to the leaf")
	}
}

func TestFixtureKeyPackageIsBoundToItsMember(t *testing.T) {
	crypto := testCrypto(t)
	bob := testIdentity(t, crypto, "bob")
	kp, initPriv, encPriv := testKeyPackage(t, crypto, bob)
	if !bytes.Equal(kp.LeafNode.SignatureKey, bob.SigPub) {
		t.Fatal("the fixture key package leaf is not bound to the member's signature key")
	}
	if len(initPriv) == 0 || len(encPriv) == 0 {
		t.Fatal("NewKeyPackage returned an empty private key")
	}
	if err := kp.LeafNode.VerifySignature(crypto, nil, 0); err != nil {
		t.Fatalf("rebound leaf signature does not verify: %v", err)
	}
	// the signature seed the key package carries is the member's own, which is what task 16
	// reads into JoinKeyMaterial. rebinding the leaf without rebinding this leaves a private
	// key whose public half the leaf no longer names, and nothing refuses that.
	if !bytes.Equal(kp.signPriv, bob.SigPriv) {
		t.Fatal("the fixture key package carries a signature seed that is not the member's own")
	}
}

// TestFixtureKeyPackageIsAcceptedByItsOwnValidate is the check the plan's draft did not make.
//
// KeyPackage.Validate verifies kp.Signature over the WHOLE structure, the leaf included, under
// the leaf's signature key. Rebinding the leaf and re-signing only the leaf leaves that
// signature over a preimage that no longer exists -- a key package every peer refuses, held by a
// fixture whose leaf level assertions all pass.
func TestFixtureKeyPackageIsAcceptedByItsOwnValidate(t *testing.T) {
	crypto := testCrypto(t)
	dave := testIdentity(t, crypto, "dave")
	kp, _, _ := testKeyPackage(t, crypto, dave)
	if err := kp.Validate(crypto, CipherSuiteX25519ChaCha20Sha256Ed25519, time.Now()); err != nil {
		t.Fatalf("the fixture key package does not pass section 10.1 validation: %v", err)
	}
}

// TestFixtureKeyPackageAnswersTheInitKeyBeforeTheEncryptionKey is the ORDER pin, and it is
// written the only way an order can be observed: by using each private half for the thing only
// it can do, and requiring the other one to fail at it.
//
// The two are HpkePrivateKey values of the same length over the same curve. They round trip,
// they compare, they seal and open perfectly -- against their own public halves. Swapping the
// two results of testKeyPackage breaks nothing until task 16 hands the init key to a Welcome
// decryption that needs the encryption key, fifteen tasks from here, in a test that has no
// reason to look at this file.
func TestFixtureKeyPackageAnswersTheInitKeyBeforeTheEncryptionKey(t *testing.T) {
	crypto := testCrypto(t)
	erin := testIdentity(t, crypto, "erin")
	kp, initPriv, encPriv := testKeyPackage(t, crypto, erin)

	// the two public halves are two keys, which is what makes the rest of this test able to
	// tell them apart at all
	if bytes.Equal(kp.InitKey, kp.LeafNode.EncryptionKey) {
		t.Fatal("the key package's init key and its leaf's encryption key are the same value, so nothing below can distinguish their private halves")
	}

	for _, probe := range []struct {
		name string
		pub  HpkePublicKey
		own  HpkePrivateKey
		// the other half, which must NOT open it
		other HpkePrivateKey
	}{
		{name: "init_key", pub: kp.InitKey, own: initPriv, other: encPriv},
		{name: "leaf encryption_key", pub: kp.LeafNode.EncryptionKey, own: encPriv, other: initPriv},
	} {
		kemOutput, ciphertext, err := crypto.HpkeSeal(probe.pub, []byte("info"), []byte("aad"),
			[]byte(probe.name))
		if err != nil {
			t.Fatalf("HpkeSeal to %s: %v", probe.name, err)
		}
		opened, err := crypto.HpkeOpen(probe.own, kemOutput, []byte("info"), []byte("aad"), ciphertext)
		if err != nil {
			t.Fatalf("the private half testKeyPackage answered for %s does not open a message sealed to it: %v; the two results are the wrong way round",
				probe.name, err)
		}
		if !bytes.Equal(opened, []byte(probe.name)) {
			t.Fatalf("%s opened to %q, want %q", probe.name, opened, probe.name)
		}
		if _, err := crypto.HpkeOpen(probe.other, kemOutput, []byte("info"), []byte("aad"), ciphertext); err == nil {
			t.Errorf("the OTHER private half opens a message sealed to %s, so the two are interchangeable and this order is not observable",
				probe.name)
		}
	}
}
