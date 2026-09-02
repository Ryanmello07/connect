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
// mlsErrorClasses holds this under lifecycleErrorsFile, which is what puts all of them inside
// TestEveryExportedErrorOfThisPackageIsInAMaintainedClass and inside the exclusivity sweep over
// every ordered pair of this package's classes. Without that entry the whole set is a surface a
// caller can branch on that no sweep in this package judges -- which is exactly the hole that
// gate was written for, and it is the failure this task's first full run produced.
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
	"ErrWelcomeCarriedTreeMismatch":  ErrWelcomeCarriedTreeMismatch,
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
	// 26 since p7 task 14's second pass wired (*GroupInfo).Verify's rule 9. The count is
	// asserted rather than derived on purpose -- see the note on lifecycleOwnedErrors -- so a
	// later task adding a sentinel moves this number and says which task moved it.
	if len(names) != 26 {
		t.Fatalf("the lifecycle error set holds %d values, this plan declares 26", len(names))
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

// TestFixtureKeyPackageLeafCarriesTheMembersLeafKeysExtension holds testKeyPackage to the one
// thing its leaf must carry beyond a signature, and reads it through the accessor production
// reads it through rather than off leaf.Extensions[0].
//
// NewKeyPackage takes the extensions vector as an ARGUMENT, so handing it nil builds a leaf
// that is well formed, correctly signed, accepted by section 7.3 validation and accepted by
// KeyPackage.Validate, and carries no urmessage_leaf_keys entry at all. Every other assertion
// this file makes about the fixture passes over that leaf. What it produces is a member with no
// wrap key: task 12 adds them, task 16 seals the epoch secret to a key that is not there, and
// the discovery lands on whoever writes the task rather than on the fixture that caused it.
// MASTER section 5.3 is why LeafKeysOf answers absence with a refusal rather than a nil result,
// and this is that refusal turned into an assertion about the fixture.
//
// The X-Wing key is compared against the MEMBER's own rather than merely required to be
// present, because a leaf carrying somebody else's wrap key is the same silent failure one step
// later, and the count is asserted because extensions<V> legally holds two entries of a type on
// the wire while LeafKeysOf REFUSES one that does -- a fixture that appended a second would stop
// being readable at all, and every task joining a member through it would fail at the wrap.
func TestFixtureKeyPackageLeafCarriesTheMembersLeafKeysExtension(t *testing.T) {
	crypto := testCrypto(t)
	frank := testIdentity(t, crypto, "frank")
	kp, _, _ := testKeyPackage(t, crypto, frank)

	keys, err := LeafKeysOf(&kp.LeafNode)
	if err != nil {
		t.Fatalf("the fixture key package's leaf carries no readable urmessage_leaf_keys extension: %v; every task that joins a member through this fixture joins one with no wrap key", err)
	}
	if keys.AlgId != AlgIdXwing {
		t.Errorf("the fixture key package's leaf names wrap algorithm %#04x, want %#04x", keys.AlgId, AlgIdXwing)
	}
	if !bytes.Equal(keys.DeviceXwingPub, frank.XwingPub) {
		t.Error("the fixture key package's leaf carries an X-Wing key that is not this member's, so the epoch wrap would go to somebody else")
	}
	carried := 0
	for i := range kp.LeafNode.Extensions {
		if kp.LeafNode.Extensions[i].ExtensionType == ExtensionTypeUrmessageLeafKeys {
			carried++
		}
	}
	if carried != 1 {
		t.Errorf("the fixture key package's leaf carries %d urmessage_leaf_keys entries, want 1; LeafKeysOf refuses a leaf carrying two, so a fixture with a second has no readable wrap key at all", carried)
	}
	// the entry is inside what the leaf SIGNED, which is what stops a later task from reading a
	// wrap key that no signature covers: marshalCore writes the extensions vector, so a leaf
	// whose signature verifies is a leaf whose extensions were signed
	if err := kp.LeafNode.VerifySignature(crypto, nil, 0); err != nil {
		t.Fatalf("the fixture leaf's signature does not verify, so its extensions vector is not covered by anything: %v", err)
	}
}

// TestFixtureLeafValidationCarriesAClockThatCanRefuseAnExpiredLeaf is the check
// testLeafValidation's own comment promises and nothing held it to.
//
// LeafValidationContext documents NowMs of 0 as an OPT OUT: validateLifetime returns nil before
// it reads either endpoint. So a fixture context answering 0 is a context under which every
// fixture leaf still validates, every assertion in this file still passes, and the section 7.3
// rule the fixture claims to be judged by is the one rule that never runs. What that buys is a
// task shipping an expired leaf with a green suite behind it.
//
// The property is observed rather than asserted about: a leaf whose lifetime ENDED long ago,
// re-signed so that nothing but the lifetime can be what refuses it, must be refused with
// ErrLeafNodeLifetime by the very context the fixtures hand out. Under NowMs of 0 it is
// accepted. The unexpired leaf goes through the same context first, because a context that
// refused everything would produce the refusal below while saying nothing.
func TestFixtureLeafValidationCarriesAClockThatCanRefuseAnExpiredLeaf(t *testing.T) {
	crypto := testCrypto(t)
	grace := testIdentity(t, crypto, "grace")
	leaf, _ := testLeafNode(t, crypto, grace)
	ctx := testLeafValidation(crypto)

	// the control on the context: a leaf inside its own lifetime is accepted by it
	if err := leaf.Validate(ctx); err != nil {
		t.Fatalf("the fixture context refuses a leaf that is inside its own lifetime (%v), so the refusal below would say nothing about the clock", err)
	}
	if ctx.NowMs == 0 {
		t.Fatal("the fixture context carries NowMs 0, which LeafValidationContext documents as an opt out of the lifetime check entirely; every fixture leaf is then judged by seven of section 7.3's eight rules")
	}
	// and it is THIS machine's clock rather than some fixed instant that merely is not zero: a
	// constant far from now is caught by the acceptance above, and a constant near it today
	// stops being near it tomorrow
	if drift := int64(ctx.NowMs) - time.Now().UnixMilli(); drift > 300_000 || drift < -300_000 {
		t.Errorf("the fixture context's NowMs is %d ms away from this machine's clock, so it is not reading a real one", drift)
	}

	// a lifetime that ended in 1970, re-signed under the member's own key so that the signature
	// rule above it cannot be what refuses this leaf
	expired := leaf.Clone()
	expired.Lifetime = Lifetime{NotBefore: 1000, NotAfter: 2000}
	if err := expired.Sign(crypto, grace.SigPriv, nil, 0); err != nil {
		t.Fatalf("re-signing the expired leaf: %v", err)
	}
	if err := expired.Validate(ctx); !errors.Is(err, ErrLeafNodeLifetime) {
		t.Fatalf("the fixture context answered %v for a leaf whose lifetime ended at unix second 2000, want ErrLeafNodeLifetime; the fixture's clock is not checking a lifetime at all", err)
	}
}

// TestFixtureIdentityGivesTheCredentialAndTheSignatureKeySeparateStorage is the clone
// testIdentity's comment argues five lines for, held by something.
//
// SignaturePublicKey is a []byte, so IdentityPub: sigPub gives the two fields ONE backing
// array. Every assertion this file already makes still passes over that: the two are equal, the
// pair signs and verifies, and two members share nothing. What it costs is invisible until a
// later task edits one field in place -- normalising an identity, truncating it, zeroing it
// after use -- and finds it has edited the member's signature key as well, producing a
// credential that no longer matches the key its leaf is signed under, with nothing at the point
// of the edit to say so.
//
// Both directions are edited, because "these two fields do not alias" is a symmetric claim and
// a test that touched only one of them would pass over a fixture that cloned only one.
func TestFixtureIdentityGivesTheCredentialAndTheSignatureKeySeparateStorage(t *testing.T) {
	crypto := testCrypto(t)
	heidi := testIdentity(t, crypto, "heidi")
	// the guard on the premise: the two carry the same VALUE, which is what makes an aliasing
	// question meaningful at all. two unrelated keys would pass every edit below trivially.
	if !bytes.Equal(heidi.IdentityPub, heidi.SigPub) {
		t.Fatal("the fixture's credential identity is not the member's signature public key, so this test would pass on two unrelated values")
	}
	if len(heidi.IdentityPub) == 0 {
		t.Fatal("the fixture's credential identity is empty, so there is no byte to edit")
	}

	heidi.IdentityPub[0] ^= 0xff
	if bytes.Equal(heidi.IdentityPub, heidi.SigPub) {
		t.Fatal("editing the credential identity edited the signature public key: the two fields share one backing array")
	}
	heidi.IdentityPub[0] ^= 0xff

	heidi.SigPub[0] ^= 0xff
	if bytes.Equal(heidi.IdentityPub, heidi.SigPub) {
		t.Fatal("editing the signature public key edited the credential identity: the two fields share one backing array")
	}
	heidi.SigPub[0] ^= 0xff

	if !bytes.Equal(heidi.IdentityPub, heidi.SigPub) {
		t.Fatal("the two edits above did not restore the fixture, so the comparisons they made were not about aliasing")
	}
}
