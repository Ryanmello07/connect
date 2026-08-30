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
	"errors"
	"go/ast"
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
	emitting := []string{}
	for _, declaration := range parsed.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Body == nil {
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

// The control: key_package.go with the mutation this gate exists for, written so that the two
// assemblies agree byte for byte.
//
// signedPreimage here writes the same fields in the same order as marshalCore, so every
// signature it produces verifies, every key package validates, every round trip round trips
// and the whole of mls and message stays green. There is no behaviour to observe; what there
// is, is a second declaration that emits, and that is what the scan reads.
const keyPackageSecondAssemblyControl = `package control

func (self *KeyPackage) marshalCore(w *syntax.Writer) error {
	w.WriteUint16(uint16(self.Version))
	w.WriteOpaque(self.InitKey)
	return WriteExtensions(w, self.Extensions)
}

func (self *KeyPackage) MarshalMLS(w *syntax.Writer) error {
	if err := self.marshalCore(w); err != nil {
		return err
	}
	w.WriteOpaque(self.Signature)
	return nil
}

func (self *KeyPackage) signedPreimage() ([]byte, error) {
	w := syntax.NewWriter()
	w.WriteUint16(uint16(self.Version))
	w.WriteOpaque(self.InitKey)
	if err := WriteExtensions(w, self.Extensions); err != nil {
		return nil, err
	}
	return w.Bytes()
}

func (self *KeyPackage) Ref(crypto CryptoProvider) ([]byte, error) {
	encoded, err := syntax.Marshal(self)
	if err != nil {
		return nil, err
	}
	return MakeKeyPackageRef(crypto, encoded), nil
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
// and why it is derived: what it asserts is that exactly two declarations of key_package.go
// emit any part of the encoding, and that they are the codec's own two.
//
// The control is the mutation itself, run through the same derivation, and it must be reported.
func TestTheKeyPackageSignaturePreimageIsAssembledExactlyOnce(t *testing.T) {
	emitters := mlsEncodingEmitters(t)

	control := declarationsEmittingIn(
		mustParseText(t, "key_package_second_assembly_control.go", keyPackageSecondAssemblyControl), emitters)
	if want := []string{"MarshalMLS", "marshalCore", "signedPreimage"}; !slices.Equal(control, want) {
		t.Fatalf("over a control that assembles the preimage twice the scan read %v, want %v; whatever it reports about the real file, it is not reading a second assembly",
			control, want)
	}

	emitting := declarationsEmittingIn(mustParseSource(t, "key_package.go"), emitters)
	if want := []string{"MarshalMLS", "marshalCore"}; !slices.Equal(emitting, want) {
		t.Errorf("key_package.go emits the encoding from %v, want %v. marshalCore is the one assembly of the signed prefix and MarshalMLS reaches it; anything else here is a second opinion about what a key package signs, and two implementations of one preimage disagree by bytes the day one of them changes",
			emitting, want)
	}
}
