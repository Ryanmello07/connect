// The tests of the RFC 9420 section 10 KeyPackage: its construction, its reference, its
// validation, and the two properties of key_package.go that nothing behavioural can see.
//
// Three of the tests below exist because of a substitution rather than because of a rule, and
// each names the substitution it was written against:
//
//   - TestKeyPackageValidateReadsTheClockItWasHanded, against a Validate that never reads its
//     now argument. Every test that drives one timestamp passes over that body, and this
//     project has shipped exactly that shape at another layer.
//   - TestNewKeyPackageDrawsTheInitAndEncryptionKeysFromSeparateEntropy, against a constructor
//     that answers one key pair twice. It survived a whole green suite one plan ago, because
//     nothing that round trips or that checks a length can see two keys that are one.
//   - TestTheKeyPackageSignaturePreimageIsAssembledExactlyOnce, against a second assembly of
//     the signed prefix written with the fields in the same order. That one produces the same
//     bytes, so it has no behaviour at all to observe and the gate is over the source.
package mls

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect/mls/syntax"
)

// The suite every key package here is built at, written once so that a test which means to
// vary the suite is visibly doing so.
const keyPackageTestSuite = CipherSuiteX25519ChaCha20Sha256Ed25519

func testKeyPackageCapabilities() Capabilities {
	return Capabilities{
		Versions:     []ProtocolVersion{ProtocolVersionMls10},
		CipherSuites: []CipherSuite{keyPackageTestSuite},
		Extensions:   []ExtensionType{ExtensionTypeUrmessageLeafKeys},
		Proposals:    []ProposalType{ProposalTypeAdd, ProposalTypeUpdate, ProposalTypeRemove},
		Credentials:  []CredentialType{CredentialTypeBasic},
	}
}

// One key package over a provider of its own, with both HPKE private halves.
func newTestKeyPackage(t *testing.T) (CryptoProvider, *KeyPackage, HpkePrivateKey, HpkePrivateKey) {
	t.Helper()
	crypto, err := NewCryptoProvider(keyPackageTestSuite)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	kp, initPriv, encPriv, err := NewKeyPackage(crypto, keyPackageTestSuite,
		BasicCredential([]byte("alice")), testKeyPackageCapabilities(), nil)
	if err != nil {
		t.Fatalf("NewKeyPackage: %v", err)
	}
	return crypto, kp, initPriv, encPriv
}

// testResignKeyPackage puts a valid signature back on a key package a test has altered, using
// the seed the constructor kept.
//
// It exists so that a test can reach a refusal that lives BELOW the signature check. Validate
// verifies the key package signature before it hands the leaf on, and every field of the leaf
// is inside that signature, so an altered leaf is refused as a forgery and the rule the test
// was aiming at is never reached.
func testResignKeyPackage(t *testing.T, crypto CryptoProvider, kp *KeyPackage) {
	t.Helper()
	content, err := kp.signedPreimage()
	if err != nil {
		t.Fatalf("signedPreimage: %v", err)
	}
	signature, err := crypto.SignWithLabel(kp.signPriv, keyPackageSignatureLabel, content)
	if err != nil {
		t.Fatalf("SignWithLabel: %v", err)
	}
	kp.Signature = signature
}

func TestNewKeyPackageRoundTripsAndValidates(t *testing.T) {
	crypto, err := NewCryptoProvider(keyPackageTestSuite)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	leafKeys := &LeafKeysExtension{
		AlgId:          AlgIdXwing,
		DeviceXwingPub: make([]byte, XwingPublicKeyLen),
	}
	ext, err := leafKeys.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	kp, initPriv, encPriv, err := NewKeyPackage(crypto, keyPackageTestSuite,
		BasicCredential([]byte("alice")), testKeyPackageCapabilities(), []Extension{ext})
	if err != nil {
		t.Fatalf("NewKeyPackage: %v", err)
	}
	if len(initPriv) == 0 || len(encPriv) == 0 {
		t.Fatalf("NewKeyPackage returned empty private keys")
	}
	if bytes.Equal(initPriv, encPriv) {
		t.Fatalf("the init and encryption key pairs are the same")
	}
	if bytes.Equal(kp.InitKey, kp.LeafNode.EncryptionKey) {
		t.Fatalf("init_key equals the leaf encryption key")
	}
	if kp.Version != ProtocolVersionMls10 || kp.CipherSuite != keyPackageTestSuite {
		t.Fatalf("version %d suite %#04x, want %d and %#04x",
			kp.Version, uint16(kp.CipherSuite), ProtocolVersionMls10, uint16(keyPackageTestSuite))
	}
	// the extensions argument is the LEAF's, which is where this profile puts
	// urmessage_leaf_keys; see NewKeyPackage's own comment
	if len(kp.LeafNode.Extensions) != 1 || kp.LeafNode.Extensions[0].ExtensionType != ExtensionTypeUrmessageLeafKeys {
		t.Fatalf("the leaf carries %v, want the urmessage_leaf_keys extension it was handed",
			kp.LeafNode.Extensions)
	}
	if err := kp.Validate(crypto, keyPackageTestSuite, time.Now()); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	encoded, err := syntax.Marshal(kp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out := &KeyPackage{}
	if err := syntax.Unmarshal(encoded, out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	reencoded, err := syntax.Marshal(out)
	if err != nil {
		t.Fatalf("re-Marshal: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("re-encode differs")
	}
	if err := out.Validate(crypto, keyPackageTestSuite, time.Now()); err != nil {
		t.Fatalf("decoded Validate: %v", err)
	}
	if err := syntax.Unmarshal(append(encoded, 0x00), &KeyPackage{}); !errors.Is(err, syntax.ErrTrailingBytes) {
		t.Fatalf("trailing byte err = %v, want ErrTrailingBytes", err)
	}
}

func TestKeyPackageRefIsStableAndBindsEveryField(t *testing.T) {
	crypto, kp, _, _ := newTestKeyPackage(t)
	ref, err := kp.Ref(crypto)
	if err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if len(ref) != crypto.HashSize() {
		t.Fatalf("ref length = %d, want %d", len(ref), crypto.HashSize())
	}
	again, err := kp.Ref(crypto)
	if err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if !bytes.Equal(ref, again) {
		t.Fatalf("Ref is not deterministic")
	}
	other, _, _, err := NewKeyPackage(crypto, keyPackageTestSuite,
		BasicCredential([]byte("alice")), testKeyPackageCapabilities(), nil)
	if err != nil {
		t.Fatalf("NewKeyPackage: %v", err)
	}
	otherRef, err := other.Ref(crypto)
	if err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if bytes.Equal(ref, otherRef) {
		t.Fatalf("two key packages with fresh keys share a ref")
	}
}

// TestKeyPackageRefCoversTheSignatureAndNotOnlyTheSignedPrefix is the reference's own
// statement of WHICH bytes it hashes, and it is here because the two candidates differ by one
// field and agree on everything a length or a determinism check can ask.
//
// A Ref taken over the KeyPackageTBS prefix is the same length, is just as deterministic, and
// differs between any two key packages built from fresh keys -- so the test above passes over
// it unchanged. What it stops doing is distinguishing two key packages that carry the same
// fields under different signatures, which is exactly the pair a commit has to be able to
// name apart: a member holding one and a member holding the other would agree they were adding
// the same joiner while holding two different structures, and every later tree hash disagrees.
func TestKeyPackageRefCoversTheSignatureAndNotOnlyTheSignedPrefix(t *testing.T) {
	crypto, kp, _, _ := newTestKeyPackage(t)
	ref, err := kp.Ref(crypto)
	if err != nil {
		t.Fatalf("Ref: %v", err)
	}
	// the independent computation, assembled here rather than read back through Ref
	encoded, err := syntax.Marshal(kp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := MakeKeyPackageRef(crypto, encoded); !bytes.Equal(ref, want) {
		t.Fatalf("Ref answered %x and RefHash over the whole encoding is %x", ref, want)
	}
	// and the candidate it must NOT be
	tbs, err := kp.signedPreimage()
	if err != nil {
		t.Fatalf("signedPreimage: %v", err)
	}
	if bytes.Equal(ref, MakeKeyPackageRef(crypto, tbs)) {
		t.Fatalf("Ref hashed the KeyPackageTBS prefix; two key packages differing only in their signature would then share a reference")
	}
	// the property that says so without reference to either assembly: moving the signature
	// alone moves the ref
	moved := *kp
	moved.Signature = append([]byte(nil), kp.Signature...)
	moved.Signature[0] ^= 0x01
	movedRef, err := moved.Ref(crypto)
	if err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if bytes.Equal(ref, movedRef) {
		t.Fatalf("the ref did not move when the signature did, so it is not taken over the whole key package")
	}
}

func TestKeyPackageValidateRejects(t *testing.T) {
	crypto, err := NewCryptoProvider(keyPackageTestSuite)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	build := func(t *testing.T) *KeyPackage {
		t.Helper()
		kp, _, _, err := NewKeyPackage(crypto, keyPackageTestSuite,
			BasicCredential([]byte("alice")), testKeyPackageCapabilities(), nil)
		if err != nil {
			t.Fatalf("NewKeyPackage: %v", err)
		}
		return kp
	}

	wrongVersion := build(t)
	wrongVersion.Version = ProtocolVersion(0x0002)
	testResignKeyPackage(t, crypto, wrongVersion)
	if err := wrongVersion.Validate(crypto, keyPackageTestSuite, time.Now()); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("version mismatch err = %v, want ErrUnsupportedVersion", err)
	}

	wrongSuite := build(t)
	if err := wrongSuite.Validate(crypto, CipherSuiteX25519AesGcm128Sha256Ed25519, time.Now()); !errors.Is(err, errProfileCiphersuite) {
		t.Fatalf("suite mismatch err = %v, want errProfileCiphersuite", err)
	}
	// and the same refusal reached from the other side: the key package names another suite
	// and the group runs this one, which is the direction a joiner's advertisement arrives in
	otherSuite := build(t)
	otherSuite.CipherSuite = CipherSuiteX25519AesGcm128Sha256Ed25519
	testResignKeyPackage(t, crypto, otherSuite)
	if err := otherSuite.Validate(crypto, keyPackageTestSuite, time.Now()); !errors.Is(err, errProfileCiphersuite) {
		t.Fatalf("advertised suite mismatch err = %v, want errProfileCiphersuite", err)
	}

	tampered := build(t)
	tampered.InitKey = HpkePublicKey(bytes.Repeat([]byte{0xEE}, len(tampered.InitKey)))
	err = tampered.Validate(crypto, keyPackageTestSuite, time.Now())
	if !errors.Is(err, errKeyPackageBadSignature) {
		t.Fatalf("tampered init key err = %v, want errKeyPackageBadSignature", err)
	}
	// the broad question the wrap keeps answerable, which is what a caller with no interest in
	// which structure failed asks
	if !errors.Is(err, errBadSignature) {
		t.Fatalf("tampered init key err = %v, which does not answer the package's signature sentinel", err)
	}

	// an update-source leaf, NOT re-signed: it is refused as a forgery, because the source is
	// inside the key package's own preimage
	wrongSource := build(t)
	wrongSource.LeafNode.LeafNodeSource = LeafNodeSourceUpdate
	if err := wrongSource.Validate(crypto, keyPackageTestSuite, time.Now()); !errors.Is(err, errKeyPackageBadSignature) {
		t.Fatalf("an update-source leaf err = %v, want errKeyPackageBadSignature", err)
	}
	// and re-signed, which is what a hostile peer would send: now the leaf's own section 7.3
	// source rule is what refuses it, which is the delegation this Validate is made of
	resigned := build(t)
	resigned.LeafNode.LeafNodeSource = LeafNodeSourceUpdate
	testResignKeyPackage(t, crypto, resigned)
	if err := resigned.Validate(crypto, keyPackageTestSuite, time.Now()); !errors.Is(err, ErrLeafNodeSourceMismatch) {
		t.Fatalf("a re-signed update-source leaf err = %v, want ErrLeafNodeSourceMismatch", err)
	}

	expired := build(t)
	far := time.Unix(int64(expired.LeafNode.Lifetime.NotAfter)+2*3600, 0)
	if err := expired.Validate(crypto, keyPackageTestSuite, far); !errors.Is(err, ErrLeafNodeLifetime) {
		t.Fatalf("expired err = %v, want ErrLeafNodeLifetime", err)
	}
}

// TestKeyPackageValidateReadsTheClockItWasHanded is the one test in this file written against a
// body rather than against a rule.
//
// Validate takes a now, and a Validate that never reads it -- one that passed 0 for NowMs,
// which LeafValidationContext documents as an opt out, or one that stamped time.Now() over the
// argument -- answers nil for every key package this package mints and passes every test above.
// All of them drive one timestamp, taken from the same clock the constructor just stamped the
// lifetime off, so none of them can see it. This one holds ONE key package against three
// instants and a fourth that is not a clock at all, and the key package is built once so that
// the only thing moving between the cases is the argument.
func TestKeyPackageValidateReadsTheClockItWasHanded(t *testing.T) {
	crypto, kp, _, _ := newTestKeyPackage(t)
	notBefore := int64(kp.LeafNode.Lifetime.NotBefore)
	notAfter := int64(kp.LeafNode.Lifetime.NotAfter)
	skew := int64(leafLifetimeSkewSeconds)
	if notAfter <= notBefore {
		t.Fatalf("the minted lifetime is %d..%d, which contains no instant to be inside of",
			notBefore, notAfter)
	}

	cases := []struct {
		what string
		now  time.Time
		want error
	}{
		{
			what: "a minute before not_before, past the skew this validator tolerates",
			now:  time.Unix(notBefore-skew-60, 0),
			want: ErrLeafNodeLifetime,
		},
		{
			what: "halfway through the lifetime",
			now:  time.Unix(notBefore+(notAfter-notBefore)/2, 0),
			want: nil,
		},
		{
			what: "a minute after not_after, past the skew this validator tolerates",
			now:  time.Unix(notAfter+skew+60, 0),
			want: ErrLeafNodeLifetime,
		},
		{
			// the zero time.Time is a clock nobody set, and it must not become the
			// documented NowMs opt out on the way in; see the clamp in Validate
			what: "the zero time, which is a machine whose clock is not set",
			now:  time.Time{},
			want: ErrLeafNodeLifetime,
		},
	}
	// the cases must actually differ, or this test drives one instant under four names
	seen := map[int64]string{}
	for _, one := range cases {
		if already, repeated := seen[one.now.Unix()]; repeated {
			t.Fatalf("%q and %q are the same instant, so this test varies nothing", already, one.what)
		}
		seen[one.now.Unix()] = one.what
	}

	for _, one := range cases {
		err := kp.Validate(crypto, keyPackageTestSuite, one.now)
		if one.want == nil {
			if err != nil {
				t.Errorf("%s: Validate = %v, want nil", one.what, err)
			}
			continue
		}
		if !errors.Is(err, one.want) {
			t.Errorf("%s: Validate = %v, want %v -- a validator that answers the same thing at every instant is not reading the clock it was handed",
				one.what, err, one.want)
		}
	}
}

// TestKeyPackageSignsUnderTheRfcLabel pins the label and shows the signature verifying under
// it, taken apart from Validate.
//
// The label is the whole of what stops a key package signature being a valid signature over
// some other structure the same key signed, and the same key signs a LeafNodeTBS inside this
// very structure -- so of every neighbour in this package, that is the one the separation has
// to hold against. That the primitive is label bound at all is crypto_labels_test.go's; what
// is here is that THIS construction reaches it with the RFC's string.
func TestKeyPackageSignsUnderTheRfcLabel(t *testing.T) {
	if keyPackageSignatureLabel != "KeyPackageTBS" {
		t.Fatalf("the key package signature label is %q, and RFC 9420 section 10 writes KeyPackageTBS",
			keyPackageSignatureLabel)
	}
	crypto, kp, _, _ := newTestKeyPackage(t)
	content, err := kp.signedPreimage()
	if err != nil {
		t.Fatalf("signedPreimage: %v", err)
	}
	if err := crypto.VerifyWithLabel(kp.LeafNode.SignatureKey, "KeyPackageTBS",
		content, kp.Signature); err != nil {
		t.Fatalf("the signature does not verify under the literal RFC label over the KeyPackageTBS bytes: %v", err)
	}
	// every other label this package signs under, plus the two spellings a reader's eye slides
	// over. The identifiers are in-package, so a label renamed away fails to compile here
	// rather than leaving this list naming a neighbour that no longer exists.
	for _, label := range []string{
		leafNodeSignatureLabel, framedContentTBSLabel, updatePathNodeLabel, "KeyPackageTbs", "",
	} {
		if label == keyPackageSignatureLabel {
			t.Fatalf("%q is offered here as a label the key package signature must NOT verify under, and it is the label it signs under",
				label)
		}
		if err := crypto.VerifyWithLabel(kp.LeafNode.SignatureKey, label,
			content, kp.Signature); err == nil {
			t.Errorf("the key package signature verifies under %q as well, so the label separates nothing", label)
		}
	}
}

// TestNewKeyPackageDrawsTheInitAndEncryptionKeysFromSeparateEntropy holds the constructor to
// producing two key pairs rather than one used twice.
//
// This is the entropy substitution, and it is the reason the test opens a message under each
// public half with the private half it was handed rather than comparing the two byte strings.
// A comparison catches the crude form -- one draw feeding both DeriveKeyPair calls -- and
// catches neither of the two next to it: a constructor that answers the encryption private key
// in the init position, and one that publishes the encryption public key as the init_key. Both
// hand back a key package that encodes, validates, refs and round trips, and both leave the
// joiner unable to open the Welcome that was sealed to what it published.
//
// RFC 9420 has these as two keys because they are used by different parties at different
// times: the init key opens the Welcome that admits this member, the encryption key opens
// every commit's path secret afterwards. A member whose two keys are one is a member for whom
// compromising either compromises both, for the life of the group.
func TestNewKeyPackageDrawsTheInitAndEncryptionKeysFromSeparateEntropy(t *testing.T) {
	crypto, kp, initPriv, encPriv := newTestKeyPackage(t)
	if bytes.Equal(initPriv, encPriv) {
		t.Fatalf("the two private halves are one key")
	}
	if bytes.Equal(kp.InitKey, kp.LeafNode.EncryptionKey) {
		t.Fatalf("init_key and the leaf's encryption_key are one key")
	}

	probe := []byte("the message a joiner has to be able to open")
	info := []byte("key package entropy probe")
	sealTo := func(t *testing.T, what string, pub HpkePublicKey) ([]byte, []byte) {
		t.Helper()
		kemOutput, ciphertext, err := crypto.HpkeSeal(pub, info, nil, probe)
		if err != nil {
			t.Fatalf("seal to the %s: %v", what, err)
		}
		return kemOutput, ciphertext
	}
	opens := func(priv HpkePrivateKey, kemOutput []byte, ciphertext []byte) bool {
		opened, err := crypto.HpkeOpen(priv, kemOutput, info, nil, ciphertext)
		return err == nil && bytes.Equal(opened, probe)
	}

	initKem, initCiphertext := sealTo(t, "published init_key", kp.InitKey)
	if !opens(initPriv, initKem, initCiphertext) {
		t.Errorf("the init private key this constructor returned does not open a message sealed to the init_key it published; the caller holds a key package it cannot be admitted with")
	}
	if opens(encPriv, initKem, initCiphertext) {
		t.Errorf("the encryption private key opens a message sealed to the init_key, so the two key pairs are one")
	}

	encKem, encCiphertext := sealTo(t, "leaf encryption_key", kp.LeafNode.EncryptionKey)
	if !opens(encPriv, encKem, encCiphertext) {
		t.Errorf("the encryption private key this constructor returned does not open a message sealed to the leaf's encryption_key; the caller holds a leaf it cannot decrypt a commit at")
	}
	if opens(initPriv, encKem, encCiphertext) {
		t.Errorf("the init private key opens a message sealed to the leaf's encryption_key, so the two key pairs are one")
	}
}

// TestNewKeyPackageKeepsTheSigningSeedOffTheWireAndBesideItsOwnLeaf is the field the plan calls
// signPriv, in both directions.
//
// Beside its own leaf: the seed has to be the one the leaf named as its signature_key, or the
// group lifecycle plan assembles JoinKeyMaterial around a key that signs nothing the group will
// accept, and the first Update that member sends is refused with nothing to point at.
//
// Off the wire: it is a private key, and a decode over a receiver that already held one has to
// clear it. Otherwise a caller that decoded a stranger's key package into a value its own
// constructor had filled in holds that stranger's public half beside its own signing seed, and
// nothing in the value says the two do not belong together.
func TestNewKeyPackageKeepsTheSigningSeedOffTheWireAndBesideItsOwnLeaf(t *testing.T) {
	_, kp, _, _ := newTestKeyPackage(t)
	if len(kp.signPriv) == 0 {
		t.Fatalf("NewKeyPackage kept no signature seed, so nothing can sign this member's later updates")
	}
	pub, err := signaturePublicKeyOf(kp.signPriv)
	if err != nil {
		t.Fatalf("signaturePublicKeyOf: %v", err)
	}
	if !bytes.Equal(pub, kp.LeafNode.SignatureKey) {
		t.Fatalf("the kept seed derives %x and the leaf names %x as its signature_key",
			pub, kp.LeafNode.SignatureKey)
	}

	encoded, err := syntax.Marshal(kp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(encoded, kp.signPriv) {
		t.Fatalf("the signature seed is inside the %d encoded octets of the key package", len(encoded))
	}
	fresh := &KeyPackage{}
	if err := syntax.Unmarshal(encoded, fresh); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(fresh.signPriv) != 0 {
		t.Fatalf("a decoded key package carries a signature seed")
	}
	// the direction that needs a decoder which STAGES: a receiver that already held one
	reused := &KeyPackage{}
	*reused = *kp
	if err := syntax.Unmarshal(encoded, reused); err != nil {
		t.Fatalf("Unmarshal over a used receiver: %v", err)
	}
	if len(reused.signPriv) != 0 {
		t.Fatalf("a decode over a receiver that held a signature seed left it there, beside a public key that came off the wire")
	}
}

// ---------------------------------------------------------------------------
// the one assembly of the signed preimage
// ---------------------------------------------------------------------------

// mlsEncodingEmitters is every identifier that writes part of an MLS encoding, derived from
// three sources and listed in none of them.
//
// Derived because a list is the defect this gate exists to catch, one level up. The obvious
// spelling of this class is "the Write methods somebody thought of", and the encoder that a
// second assembly would actually be written with is whichever one that list forgot. So the
// class is: every Write method the compiler sees on *syntax.Writer, every method of
// syntax.Marshaler, and every package level function of this package's own non test source
// whose name begins with write in either case -- which is where WriteExtensions and
// writeUint16Vec come from without either being typed here.
//
// The anchors below are a guard on the SCAN and not on the class: a derivation that read
// nothing reports the same clean bill a complete one reports.
func mlsEncodingEmitters(t *testing.T) map[string]bool {
	t.Helper()
	emitters := map[string]bool{}
	writer := reflect.TypeOf(&syntax.Writer{})
	for i := 0; i < writer.NumMethod(); i++ {
		if name := writer.Method(i).Name; strings.HasPrefix(name, "Write") {
			emitters[name] = true
		}
	}
	marshaler := reflect.TypeOf((*syntax.Marshaler)(nil)).Elem()
	for i := 0; i < marshaler.NumMethod(); i++ {
		emitters[marshaler.Method(i).Name] = true
	}
	for name, file := range packageLevelDeclarations(t, ".") {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(name), "write") {
			emitters[name] = true
		}
	}
	for _, anchor := range []string{"WriteUint16", "WriteOpaque", "MarshalMLS", "WriteExtensions"} {
		if !emitters[anchor] {
			t.Fatalf("the emitter derivation read %d names and %s is not among them, so it read something other than this package and the syntax writer",
				len(emitters), anchor)
		}
	}
	return emitters
}

// declarationsEmittingIn is every function of one parsed file whose body calls an emitter.
//
// Calls and not mentions, deliberately. key_package.go's signedPreimage hands marshalCore to
// marshalBytes as a VALUE, which is the whole point of it -- one assembly, reached rather than
// repeated -- and a scan over mentions would read that as a second writer.
func declarationsEmittingIn(parsed parsedSource, emitters map[string]bool) []string {
	return declarationsEmittingWhere(parsed, emitters, func(parsedSource, *ast.FuncDecl) bool { return true })
}

// declarationsEmittingWhere is the same walk narrowed to the declarations a caller's filter
// keeps, which is what lets one scan ask about one structure's codec across a whole package.
//
// The split exists because "every declaration that emits" is the right class for one file and
// far too wide for a package: mls declares dozens of codecs and all of them emit. The narrowing
// has to happen inside this walk rather than in a second one, or the widened gate below would be
// a re-implementation with its own bugs, which is how a gate ends up agreeing with itself.
func declarationsEmittingWhere(parsed parsedSource, emitters map[string]bool,
	keep func(parsedSource, *ast.FuncDecl) bool) []string {
	emitting := []string{}
	for _, declaration := range parsed.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Body == nil || !keep(parsed, function) {
			continue
		}
		emits := false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, isCall := node.(*ast.CallExpr)
			if !isCall {
				return true
			}
			switch callee := call.Fun.(type) {
			case *ast.Ident:
				emits = emits || emitters[callee.Name]
			case *ast.SelectorExpr:
				emits = emits || emitters[callee.Sel.Name]
			}
			return true
		})
		if emits {
			emitting = append(emitting, function.Name.Name)
		}
	}
	slices.Sort(emitting)
	return emitting
}

// keyPackageOwnFieldNames is every field name the KeyPackage declares and no other structure of
// this package's non test source does.
//
// It is the arm of the subject filter that a free function cannot get around by taking the
// structure apart. A second assembly written as a package level helper over a KeyPackage names
// the type in its signature and is caught by the first arm; one written over the fields does
// not, but it still has to write the init key, and InitKey is a name only this structure
// declares.
//
// DERIVED by walking every struct declaration of the package rather than typed out, because
// which of this structure's names are its own changes as its neighbours grow fields: Version and
// CipherSuite are GroupContext's too, Extensions and Signature belong to half the package, and a
// list written today is a list of the wrong names a plan from now.
func keyPackageOwnFieldNames(t *testing.T, sources []parsedSource) []string {
	t.Helper()
	subject := reflect.TypeOf(KeyPackage{}).Name()
	mine := []string{}
	elsewhere := map[string]bool{}
	for _, parsed := range sources {
		for _, declaration := range parsed.file.Decls {
			types, isTypeDeclaration := declaration.(*ast.GenDecl)
			if !isTypeDeclaration || types.Tok != token.TYPE {
				continue
			}
			for _, specification := range types.Specs {
				named, isNamed := specification.(*ast.TypeSpec)
				if !isNamed {
					continue
				}
				structure, isStruct := named.Type.(*ast.StructType)
				if !isStruct {
					continue
				}
				for _, field := range structure.Fields.List {
					for _, fieldName := range field.Names {
						if named.Name.Name == subject {
							mine = append(mine, fieldName.Name)
							continue
						}
						elsewhere[fieldName.Name] = true
					}
				}
			}
		}
	}
	own := []string{}
	for _, name := range mine {
		if !elsewhere[name] {
			own = append(own, name)
		}
	}
	slices.Sort(own)
	if len(own) == 0 {
		t.Fatalf("no field name is the %s's alone among this package's structures, so the subject filter below is one arm short and states less than it reads",
			subject)
	}
	return own
}

// keyPackageIsTheSubjectOf answers whether one declaration's subject is the key package.
//
// Two arms and both derived. The first is the structure itself: a method on it, or a parameter
// or result that names it. Rendered as TYPES and never as the text of the whole signature,
// because crypto_labels.go's MakeKeyPackageRef takes a parameter NAMED keyPackage carrying
// []byte, and a match on the spelling would pull the reference hash into a gate about the
// preimage. The second is keyPackageOwnFieldNames, which is what a helper written over the
// fields rather than over the value still has to name.
//
// The honest limit, stated rather than left for a reader to find. A helper declared in another
// file that took the five fields as its own parameters, under its own spellings, and was called
// from signedPreimage escapes both arms: it names no KeyPackage and mentions no field of one.
// What this gate is for is the second assembly somebody writes because they did not know the
// first existed, and that one is written over the structure. A deliberate one is not in reach of
// a source scan at all, and the behavioural half -- that the bytes signed are the bytes
// marshalled -- is what TestKeyPackageRefCoversTheSignatureAndNotOnlyTheSignedPrefix and the
// tampering rows of TestKeyPackageValidateRejects hold.
func keyPackageIsTheSubjectOf(parsed parsedSource, function *ast.FuncDecl, own []string) bool {
	subject := reflect.TypeOf(KeyPackage{}).Name()
	declared := []string{parsed.receiverOf(function)}
	for _, field := range function.Type.Params.List {
		declared = append(declared, parsed.render(field.Type))
	}
	if function.Type.Results != nil {
		for _, field := range function.Type.Results.List {
			declared = append(declared, parsed.render(field.Type))
		}
	}
	for _, text := range declared {
		if strings.Contains(text, subject) {
			return true
		}
	}
	names := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		identifier, isIdentifier := node.(*ast.Ident)
		if isIdentifier && slices.Contains(own, identifier.Name) {
			names = true
		}
		return true
	})
	return names
}

// The control: the mutation this gate exists for, landed as a file of its own.
//
// A byte identical second assembly. It writes the same fields in the same order as marshalCore,
// so every signature it produces verifies, every key package validates, every round trip round
// trips and the whole of mls and message stays green. There is no behaviour to observe; what
// there is, is a second declaration that emits.
//
// It is a SEPARATE FILE and that is the whole point of this control. The version of this gate it
// replaces read key_package.go by name, and a reviewer landed exactly this text in
// mls/key_package_tbs.go, pointed signedPreimage at it, and watched 6604 tests pass. The in-file
// form of the same mutation was caught; only the file boundary saved it. The control's file name
// is deliberately unrelated to key_package so that a scan narrowed by a name pattern rather than
// by a file list fails here too.
const keyPackageSecondAssemblyControl = `package control

func (self *KeyPackage) keyPackageTbs(w *syntax.Writer) error {
	w.WriteUint16(uint16(self.Version))
	w.WriteUint16(uint16(self.CipherSuite))
	w.WriteOpaque(self.InitKey)
	if err := self.LeafNode.MarshalMLS(w); err != nil {
		return err
	}
	return WriteExtensions(w, self.Extensions)
}
`

// TestTheKeyPackageSignaturePreimageIsAssembledExactlyOnce is the file header's first claim,
// as a gate.
//
// A second assembly of the signed prefix is a second OPINION about what a key package signs.
// Two implementations of one preimage disagree by bytes the day one of them changes, and a key
// package that verifies under one and not the other is a joiner nobody can add -- discovered
// at somebody else's Welcome, not here. While they agree, they agree PERFECTLY: identical
// bytes, identical signatures, identical refs, no round trip and no verification anywhere in
// this package or in message able to tell them apart. That is why this gate is over the source
// and why it is derived.
//
// The subject is a PACKAGE and not a file, which is the correction this version carries. What
// the name claims is that the preimage is assembled exactly once; what the previous version
// checked is that key_package.go assembles it exactly once, and package mls is one package, so
// any later task can reach signedPreimage's job from any file without knowing this gate exists.
// A gate that derives one axis and enumerates another is not a derived gate: this one derived
// its emitter class off *syntax.Writer's method set, with four anchors guarding the scan, and
// then handed it one file name.
//
// So the scope is every non test file of the package, and the narrowing that makes that a
// useful question is derived too -- keyPackageIsTheSubjectOf, off the type and off the field
// names only this structure declares. Three controls, because a scan and a filter can each fail
// silently: the mutation must be READ when it is landed one file over, the subject filter must
// keep less than the package emits, and the anchor on the own-field derivation must hold.
func TestTheKeyPackageSignaturePreimageIsAssembledExactlyOnce(t *testing.T) {
	emitters := mlsEncodingEmitters(t)
	sources := packageSources(t)
	own := keyPackageOwnFieldNames(t, sources)
	// the anchor on the second arm: this structure certainly declares an init key, and a
	// derivation that read something other than this package would answer without it
	if !slices.Contains(own, "InitKey") {
		t.Fatalf("the struct walk read %v as the field names the key package alone declares, and it certainly declares InitKey, so it read something other than this package",
			own)
	}
	scan := func(over []parsedSource) []string {
		found := []string{}
		for _, parsed := range over {
			found = append(found, declarationsEmittingWhere(parsed, emitters,
				func(in parsedSource, function *ast.FuncDecl) bool {
					return keyPackageIsTheSubjectOf(in, function, own)
				})...)
		}
		slices.Sort(found)
		return found
	}

	// the control, landed one file over rather than inside key_package.go
	control := scan(append(slices.Clone(sources),
		mustParseText(t, "second_assembly_control.go", keyPackageSecondAssemblyControl)))
	if want := []string{"MarshalMLS", "keyPackageTbs", "marshalCore"}; !slices.Equal(control, want) {
		t.Fatalf("over a package carrying a second assembly one file over, the scan read %v, want %v; whatever it reports about the real package, it is not reading a second assembly next door",
			control, want)
	}

	emitting := scan(sources)
	if want := []string{"MarshalMLS", "marshalCore"}; !slices.Equal(emitting, want) {
		t.Errorf("this package assembles the key package encoding in %v, want %v. marshalCore is the one assembly of the signed prefix and MarshalMLS reaches it; anything else is a second opinion about what a key package signs, and two implementations of one preimage disagree by bytes the day one of them changes",
			emitting, want)
	}

	// and the filter is separating something rather than passing the package through, which is
	// the control on the widening itself: a filter that keeps everything it is shown, or a scan
	// that read one file, both answer a short list and both look like this one passing
	everything := []string{}
	for _, parsed := range sources {
		everything = append(everything, declarationsEmittingIn(parsed, emitters)...)
	}
	if len(everything) <= len(emitting) {
		t.Fatalf("the package wide scan read %d emitting declarations in all and %d of them as the key package's; the filter is keeping everything it is shown, or the scan read one file's worth of the package",
			len(everything), len(emitting))
	}
	t.Logf("%d emitting declarations across the %d non test files of this package, %d of them the key package's: %v",
		len(everything), len(sources), len(emitting), emitting)
}

// ---------------------------------------------------------------------------
// what the package wide stub gate cannot hold NewKeyPackage to
// ---------------------------------------------------------------------------

// keyPackageWithoutItsClock is one key package encoded with its leaf's Lifetime replaced by a
// fixed window and both signatures dropped.
//
// The lifetime is the one part of this structure that is not a function of what NewKeyPackage
// was handed -- NewLeafNode stamps it off the wall clock -- so two calls a second apart differ
// in it, and because it sits inside the LeafNodeTBS and inside the KeyPackageTBS, in BOTH
// signatures too. Normalising it is what makes two calls comparable at all, and it is exactly
// why the package wide stub gate excuses this constructor from every comparison it makes across
// calls.
//
// The whole structure is encoded rather than a chosen field, so an argument that reached any
// part of it is observed. The two SIGNATURES are dropped with the lifetime because they cover it
// and would carry the clock straight back in; what holds the key package signature to depending
// on the fields it covers is TestKeyPackageRefIsStableAndBindsEveryField and the tampering rows
// of TestKeyPackageValidateRejects, over the same encoding.
func keyPackageWithoutItsClock(t *testing.T, kp *KeyPackage) string {
	t.Helper()
	normalised := *kp
	normalised.LeafNode = *kp.LeafNode.Clone()
	normalised.LeafNode.Lifetime = Lifetime{NotBefore: 1, NotAfter: 2}
	normalised.LeafNode.Signature = nil
	normalised.Signature = nil
	encoded, err := syntax.Marshal(&normalised)
	if err != nil {
		t.Fatalf("encode a key package with its clock normalised out: %v", err)
	}
	return hex.EncodeToString(encoded)
}

// keyPackageCall is NewKeyPackage's whole argument list, one EXPORTED field per declared
// parameter.
//
// Exported because the sweep reaches each field through reflect and reflect refuses to write an
// unexported one. A parameter resolves to the field of its own name with the first letter
// raised, so a parameter this list has no field for is fatal rather than swept by nothing --
// which is the failure mode a written out argument list has, and the one three gates in this
// package have already been caught in.
type keyPackageCall struct {
	Crypto CryptoProvider
	Suite  CipherSuite
	Cred   Credential
	Caps   Capabilities
	Exts   []Extension
}

func (self *keyPackageCall) fieldFor(t *testing.T, parameter string) reflect.Value {
	t.Helper()
	name := strings.ToUpper(parameter[:1]) + parameter[1:]
	field := reflect.ValueOf(self).Elem().FieldByName(name)
	if !field.IsValid() {
		t.Fatalf("NewKeyPackage declares a parameter %s and this argument list has no %s field for it, so nothing below moves it",
			parameter, name)
	}
	return field
}

// build is one call, answered as a string so that a refusal and a key package are comparable.
//
// The answer is the ENCODING and not the two private halves beside it, and that is a measurement
// rather than a preference. The first version of this read the structure and both private keys,
// on the reasoning that they are results too; dropping them from the answer altogether changed
// no verdict of this sweep, because every argument this constructor is handed reaches the
// encoding and the private halves move only when a public half already has. An assertion no
// mutation can kill is weight a reader has to reason about for nothing, so it is not here. What
// holds the two private halves to being two rather than one is
// TestNewKeyPackageDrawsTheInitAndEncryptionKeysFromSeparateEntropy, which opens a message under
// each public half with the private half it was handed -- a property this sweep does not state.
func (self keyPackageCall) build(t *testing.T) string {
	t.Helper()
	kp, _, _, err := NewKeyPackage(self.Crypto, self.Suite, self.Cred, self.Caps, self.Exts)
	if err != nil {
		return "refused: " + err.Error()
	}
	return keyPackageWithoutItsClock(t, kp)
}

// One well formed urmessage_leaf_keys entry, so that the extensions argument has an element to
// move as well as a length. A slice that can only grow states a weaker property than one that
// can also be shortened and reached into.
func keyPackageSweepExtension(t *testing.T) Extension {
	t.Helper()
	entry, err := (&LeafKeysExtension{
		AlgId:          AlgIdXwing,
		DeviceXwingPub: repeatByte(0x55, XwingPublicKeyLen),
	}).Encode()
	if err != nil {
		t.Fatalf("LeafKeysExtension.Encode: %v", err)
	}
	return entry
}

// keyPackageSweepArguments is one complete argument list, built fresh on every call.
//
// Fresh because the derived edits write IN PLACE and a shallow copy shares every slice: a row
// built off a value an earlier row had edited moves away from something the constructor was
// never called with.
//
// The provider is over a FIXED entropy script rather than the process source. NewKeyPackage
// draws three key pairs of its own, so two calls over crypto/rand answer different bytes
// whatever they were handed, and every row below would report an argument as observed on the
// strength of the randomness.
//
// The capabilities advertise every REGISTERED suite rather than the one this file builds at, so
// the suite move below stays inside a leaf whose capabilities cover it and a refusal there is
// the constructor's rule rather than this test's own arguments.
func keyPackageSweepArguments(t *testing.T) keyPackageCall {
	t.Helper()
	caps := testKeyPackageCapabilities()
	caps.CipherSuites = Suites()
	return keyPackageCall{
		Crypto: mustProviderOver(t, keyPackageTestSuite, providerStubStream(0x80)),
		Suite:  keyPackageTestSuite,
		Cred:   BasicCredential([]byte("alice")),
		Caps:   caps,
		Exts:   []Extension{keyPackageSweepExtension(t)},
	}
}

// keyPackageConstructorParameters is NewKeyPackage's parameter list, read off its own
// declaration.
//
// Derived rather than typed out, and this is the SCOPE half of the rule the enumeration failures
// of this project keep landing on: a sweep with five names written down goes on reporting a
// clean run the day a sixth argument lands. The file declaring it is found rather than named,
// for the same reason one level up.
func keyPackageConstructorParameters(t *testing.T) []string {
	t.Helper()
	parsed := sourceDeclaringPackageFunction(t, "NewKeyPackage")
	names := []string{}
	for _, parameter := range parametersOf(t, parsed, "NewKeyPackage",
		parsed.declarationOf(t, "", "NewKeyPackage").Type) {
		names = append(names, parameter.name)
	}
	if len(names) == 0 {
		t.Fatal("NewKeyPackage was read as taking no argument at all, so the sweep below runs over nothing")
	}
	return names
}

// keyPackageArgumentMove is one way of making one argument different, named for the failure
// message and keyed by the parameter it moves.
type keyPackageArgumentMove struct {
	parameter string
	name      string
	apply     func(t *testing.T, call *keyPackageCall)
}

// keyPackageArgumentMoves is every move this sweep makes, derived off the TYPE of each declared
// parameter rather than off its name or off a list.
//
// Three rules, and which one applies is decided by the parameter's type, so a parameter that is
// renamed keeps its rule and a parameter that is retyped loses it loudly.
//
//   - the provider: another provider at the same suite over ANOTHER entropy script. Every key in
//     the answer is drawn through it, so a constructor that built a provider of its own out of a
//     hardcoded suite -- which is a WORKING constructor, because both registered suites are
//     X25519 and Ed25519 and every corpus here is at one of them -- answers the same bytes over
//     both scripts and is caught here.
//   - the ciphersuite: every OTHER registered suite, WITH the provider that runs it. The two move
//     together because NewKeyPackage refuses a provider that does not run the suite it was named,
//     so a suite moved alone is not an accepted call at all -- and a refusal would let a body
//     that stored a hardcoded suite pass on the strength of the guard that read the argument,
//     which is the shape this sweep exists to catch. Moving the pair separates them: the two
//     registered suites share X25519, SHA-256 and Ed25519 and differ only in their AEAD, so every
//     key and both signatures come back IDENTICAL and the stored ciphersuite is the only thing
//     that can have moved.
//   - everything else: leafNodeEditsOf, the same derivation the leaf's codec sweeps run on, so an
//     argument that grows a field is swept on the commit that lands it rather than when somebody
//     remembers to extend a list.
//
// A refusal counts as an observation, for the stub gate's reason: an argument that moved a call
// from accepted to rejected has been read just as surely as one that moved the bytes.
func keyPackageArgumentMoves(t *testing.T, parameters []string) []keyPackageArgumentMove {
	t.Helper()
	base := keyPackageSweepArguments(t)
	providerType := reflect.TypeOf((*CryptoProvider)(nil)).Elem()
	suiteType := reflect.TypeOf(CipherSuite(0))
	moves := []keyPackageArgumentMove{}
	for _, parameter := range parameters {
		field := base.fieldFor(t, parameter)
		before := len(moves)
		switch field.Type() {
		case providerType:
			moves = append(moves, keyPackageArgumentMove{
				parameter: parameter,
				name:      "a provider at the same suite over another entropy script",
				apply: func(t *testing.T, call *keyPackageCall) {
					call.Crypto = mustProviderOver(t, call.Suite, providerStubStream(0x40))
				},
			})
		case suiteType:
			for _, suite := range Suites() {
				if suite == base.Suite {
					continue
				}
				moves = append(moves, keyPackageArgumentMove{
					parameter: parameter,
					name:      fmt.Sprintf("suite %#04x, over the provider that runs it", uint16(suite)),
					apply: func(t *testing.T, call *keyPackageCall) {
						call.Suite = suite
						call.Crypto = mustProviderOver(t, suite, providerStubStream(0x80))
					},
				})
			}
		default:
			for _, edit := range leafNodeEditsOf(parameter, field, leafNodeSources(t)) {
				moves = append(moves, keyPackageArgumentMove{
					parameter: parameter,
					name:      edit.name,
					apply: func(t *testing.T, call *keyPackageCall) {
						edit.apply(call.fieldFor(t, parameter))
					},
				})
			}
		}
		if len(moves) == before {
			t.Fatalf("NewKeyPackage declares %s, of type %s, and no move was derived for it, so this sweep would state nothing about that argument",
				parameter, field.Type())
		}
	}
	return moves
}

// TestNewKeyPackageReadsEveryArgumentItWasHanded is the half of the package wide stub gate that
// the wall clock exemption takes away, put back over the arguments this constructor has.
//
// The exemption is real -- two calls a second apart sign different key packages for a reason
// that is not the arguments -- and until this landed it was a HOLE. crypto_test.go's loop
// continues before the per argument perturbation for every name in
// providerConstructionsAnsweringOffTheWallClock, so unobserved was never populated for this
// constructor, and NewLeafNode's twin of this test had no equivalent here. Measured on the
// committed tree, twice by a reviewer and once by the owner: a body that replaced the credential
// it was handed with BasicCredential("mallory"), and a body that read the suite in a guard and
// then stored a hardcoded one, each passed 6604 tests with zero failures. Every key package in
// the system would have been minted under an identity and a suite the caller never named.
//
// The property is the gate's: an argument that changes must change the answer, or the
// constructor is a function of fewer things than its signature says. Three differences from the
// leaf's twin. The answer is read with the lifetime normalised out, which is what makes the
// comparison stable across a second boundary. The parameter list is DERIVED off the declaration,
// so a sixth argument is swept on the commit that lands it or fails here. And the answer carries
// the two private halves as well as the structure, because they are results too.
//
// It is not a source shape check and it must not become one. TestNoStubShapesRemainInSource
// catches the crude form -- an argument never mentioned at all -- and records its own limit
// where it is declared: a body which reads a parameter and then ignores the value still passes
// it. That is exactly what both measured substitutions do, so this one drives the constructor
// and reads the argument out of the OUTPUT.
func TestNewKeyPackageReadsEveryArgumentItWasHanded(t *testing.T) {
	parameters := keyPackageConstructorParameters(t)
	answer := keyPackageSweepArguments(t).build(t)
	if strings.HasPrefix(answer, "refused") {
		t.Fatalf("NewKeyPackage refused this test's own arguments (%s), so every row below compares two refusals", answer)
	}
	// the control on the normalisation and on the fixed script: two calls with one argument
	// list answer the same thing, or every "it moved" below is the clock or the entropy rather
	// than the argument
	if repeated := keyPackageSweepArguments(t).build(t); repeated != answer {
		t.Fatalf("NewKeyPackage answered\n %s\nand then\n %s\nfor one argument list with the clock normalised out",
			answer, repeated)
	}
	moves := keyPackageArgumentMoves(t, parameters)
	moved := map[string]int{}
	for _, move := range moves {
		with := keyPackageSweepArguments(t)
		move.apply(t, &with)
		if with.build(t) == answer {
			t.Errorf("NewKeyPackage answered the same key package with %s, so it does not read the %s it was handed",
				move.name, move.parameter)
			continue
		}
		moved[move.parameter] += 1
	}
	for _, parameter := range parameters {
		if moved[parameter] == 0 {
			t.Errorf("no derived move to %s changed what NewKeyPackage answered, so this sweep observed nothing about that argument",
				parameter)
		}
	}
	t.Logf("%d derived moves across the %d arguments NewKeyPackage declares (%v)",
		len(moves), len(parameters), parameters)
}

// TestNewKeyPackageRefusesAProviderThatDoesNotRunTheSuiteItWasNamed pins the decision
// errKeyPackageProviderSuite records.
//
// On the committed tree NewKeyPackage(NewCryptoProvider(0x0001), 0x0003, ...) answered no error,
// produced a key package advertising 0x0003, and Validate(crypto, 0x0003, now) ACCEPTED it --
// because Validate compares the structure's suite against its argument and never against the
// provider. Harmless only while the two registered suites share X25519, SHA-256 and Ed25519 and
// differ solely in their AEAD; a third suite that moves any of those makes it a key package
// whose signature no peer can check, published before anybody finds out.
//
// The sweep is over every ORDERED PAIR of registered suites rather than over the one pair that
// exists today, so the suite p8 registers is covered by the commit that registers it. The
// matched pairs are in the sweep as well as the mismatched ones: a guard that refused
// everything would satisfy a test that only drove mismatches, and it would be a guard nothing
// could mint a key package through.
func TestNewKeyPackageRefusesAProviderThatDoesNotRunTheSuiteItWasNamed(t *testing.T) {
	suites := Suites()
	if len(suites) < 2 {
		t.Fatalf("this package registers %v, and a mismatch has to be made of two suites", suites)
	}
	caps := testKeyPackageCapabilities()
	caps.CipherSuites = suites
	for _, running := range suites {
		for _, named := range suites {
			crypto := mustProviderOver(t, running, providerStubStream(0x80))
			kp, initPriv, encPriv, err := NewKeyPackage(crypto, named,
				BasicCredential([]byte("alice")), caps, nil)
			if running == named {
				if err != nil {
					t.Errorf("NewKeyPackage over a provider running %#04x and naming %#04x: %v",
						uint16(running), uint16(named), err)
				}
				continue
			}
			if !errors.Is(err, errKeyPackageProviderSuite) {
				t.Errorf("NewKeyPackage over a provider running %#04x and naming %#04x answered %v, want errKeyPackageProviderSuite",
					uint16(running), uint16(named), err)
			}
			if kp != nil || initPriv != nil || encPriv != nil {
				t.Errorf("NewKeyPackage answered a key package and %d and %d private octets alongside the refusal of a provider running %#04x named %#04x",
					len(initPriv), len(encPriv), uint16(running), uint16(named))
			}
		}
	}
	// and the refusal comes before anything is drawn, which is what keeps a caller's mistake
	// from costing three key pairs of entropy and what makes it reproducible
	counting := &countingReader{inner: providerStubStream(0x80)}
	crypto := mustProviderOver(t, suites[0], counting)
	if _, _, _, err := NewKeyPackage(crypto, suites[1], BasicCredential([]byte("alice")), caps, nil); err == nil {
		t.Fatalf("a provider running %#04x minted a key package naming %#04x", uint16(suites[0]), uint16(suites[1]))
	}
	if counting.drawn != 0 {
		t.Errorf("NewKeyPackage drew %d octets before refusing a provider that does not run the suite it was named",
			counting.drawn)
	}
}

// TestTheZeroKeyPackageIsRefusedOnItsCredentialAndNotItsLeafSource is the claim
// provider_nil_test.go's two key package rows rest on, as an assertion rather than as prose.
//
// Those rows drive a ZERO valued KeyPackage at a nil provider to say the provider is judged
// before the receiver, and the comment above them has to name the refusal the receiver WOULD
// have produced -- otherwise they state that one of two orders was taken without saying what the
// other one answers. That comment said ErrTreeMalformed, on the leaf's source. It is
// errProfileCredentialType, on the leaf's CREDENTIAL: Credential.MarshalMLS refuses a type that
// is not basic before it writes an octet, and the credential is the third field of the leaf the
// structure Ref marshals carries, so the encoder never reaches the source at all.
//
// This project reads a justification comment as a claim, and a claim nothing checks is exactly
// how a wrong one survives review. This is the check.
func TestTheZeroKeyPackageIsRefusedOnItsCredentialAndNotItsLeafSource(t *testing.T) {
	crypto, err := NewCryptoProvider(keyPackageTestSuite)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	ref, refErr := (&KeyPackage{}).Ref(crypto)
	if !errors.Is(refErr, errProfileCredentialType) {
		t.Errorf("(&KeyPackage{}).Ref answered %v, want errProfileCredentialType: the zero leaf's credential type is 0 and the encoder refuses it before it reaches the source",
			refErr)
	}
	if errors.Is(refErr, ErrTreeMalformed) {
		t.Errorf("(&KeyPackage{}).Ref answered %v, which answers ErrTreeMalformed; the reason written above provider_nil_test.go's key package rows named that refusal and it does not happen",
			refErr)
	}
	if ref != nil {
		t.Errorf("(&KeyPackage{}).Ref answered the reference %x alongside its refusal", ref)
	}
	// and the neighbouring row's reason, which WAS right: a zero key package names version 0,
	// so a Validate that judged its receiver first would answer for a version nobody chose
	if err := (&KeyPackage{}).Validate(crypto, keyPackageTestSuite, time.Now()); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("(&KeyPackage{}).Validate answered %v, want ErrUnsupportedVersion", err)
	}
}
