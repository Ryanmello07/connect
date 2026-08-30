// The RFC 9420 section 10 KeyPackage: one joiner's advertised init key and leaf node, signed
// as a unit, together with everything a fresh one is minted from.
//
// This file landed in two halves. The codec came first, out of order, because the framing
// plan's Proposal carries an Add arm holding a KeyPackage BY VALUE and package mls is one
// package: a struct cannot name a type that does not exist, so nothing downstream of Proposal
// compiled until the six fields and the two codec methods were here. The signing half -- the
// constructor, the reference, the validation, the label and the signature private key the
// constructor keeps -- arrived with TreeKEM task 7A, which is what owns this file.
//
// TWO THINGS ABOUT THIS FILE ARE LOAD BEARING and neither is visible from a round trip.
//
// The signed preimage is assembled ONCE, by marshalCore, and signedPreimage below reaches
// it through marshalBytes rather than writing the fields again. A second assembly of one
// preimage is a second OPINION about what a key package signs rather than a convenience: two
// implementations of one preimage disagree by bytes, and a key package that verifies under one
// and not the other is a joiner nobody can add. The disagreement is invisible while the two
// happen to write the same fields in the same order, so nothing behavioural can see it -- what
// sees it is TestTheKeyPackageSignaturePreimageIsAssembledExactlyOnce, which derives the set of
// declarations of this PACKAGE that emit any part of an encoding and whose subject is the key
// package, and requires it to be marshalCore and MarshalMLS and nothing else. The package and
// not this file: package mls is one package, a second assembly declared one file over is the
// same second opinion, and a scan told which file to read goes on reporting a clean bill while
// the thing it guards is written next door. That was measured as well -- the file scoped version
// of this gate passed a whole green suite with a byte identical second assembly one file over.
//
// Validate reads the clock it is HANDED. A validity check that never touches its now argument
// passes every test that does not vary it, and this project has shipped that shape at another
// layer already, so TestKeyPackageValidateReadsTheClockItWasHanded drives one key package at a
// now before its lifetime, inside it, and after it.
//
// What is NOT here, so that a reader who finds section 10.1 short does not take it for an
// omission: ValSem104, init_key != leaf.encryption_key, is the group lifecycle plan's, because
// it is a property of a proposal list rather than of one key package. Everything section 7.3
// says about the leaf is delegated whole to LeafNode.Validate under LeafNodeSourceKeyPackage,
// and the reference is delegated whole to the crypto plan's MakeKeyPackageRef. Neither is
// reimplemented here.
package mls

import (
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/connect/mls/syntax"
)

// KeyPackage is one joiner's advertised init key and leaf node, signed as a unit.
type KeyPackage struct {
	Version     ProtocolVersion
	CipherSuite CipherSuite
	InitKey     HpkePublicKey
	LeafNode    LeafNode
	Extensions  []Extension
	Signature   []byte

	// The seed the leaf's signature key was derived from, set by NewKeyPackage and by
	// nothing else. It is not a field of the encoding -- marshalCore stops above it and
	// UnmarshalMLS clears it -- so it is zero on every key package that arrived off the
	// wire, which is the only honest value there: nobody publishes a private key.
	//
	// Unexported and read directly by the group lifecycle plan when it assembles
	// JoinKeyMaterial, because package mls is one package.
	signPriv SignaturePrivateKey
}

// The RFC 9420 section 10 signature label, written once because a label spelled one way in
// the signing half and another in the verifying half agrees with itself perfectly: ed25519
// signs whatever preimage it is handed, and only a peer can tell "KeyPackageTBS" from
// "KeyPackageTbs". The label is the whole of what stops a key package signature being a valid
// signature over some other structure the same key signed -- leaf_node.go's
// leafNodeSignatureLabel is the neighbour it separates this one from, and the two are made by
// the SAME key over overlapping bytes, which is what makes the separation matter here more
// than anywhere else in this package.
const keyPackageSignatureLabel = "KeyPackageTBS"

// errProfileCiphersuite is ErrProfileCiphersuite in the validation plan's catalogue, where it
// is the v1 single-suite refusal, and that plan owns the single declaration site for the
// exported name. It has not landed in this package yet, so the refusal is carried by this
// unexported value until it does -- the shape credential.go's errProfileCredentialType and
// extension.go's errMissingRequiredCapability already take, and
// TestNoValidationOwnedNameHasLandedBesideItsStandIn fails on the commit that lands the
// exported twin beside it.
var errProfileCiphersuite = errors.New("mls: ciphersuite is outside the v1 profile")

// errKeyPackageProviderSuite refuses a provider that does not run the suite the caller named.
//
// The two arguments are ONE decision written twice. Every key in the answer and the signature
// over the whole of it come from the PROVIDER's primitives, and suite is what the structure
// ADVERTISES those primitives to be, so a mismatch mints a key package whose signature was made
// under a scheme it does not name. Nothing in this tree can see that today: the two registered
// suites share X25519, SHA-256 and Ed25519 and differ only in their AEAD, so a key package
// minted over an 0x0001 provider and advertising 0x0003 verifies, validates, round trips and is
// accepted by this file's own Validate -- measured on the committed tree rather than supposed.
// It stops being invisible at the first registered suite that moves one of those primitives,
// which p8 lands, and by then the key packages have been published.
//
// It is refused HERE, at the one call where both values are the same caller's in the same
// statement, rather than at the peer that cannot verify. Validate is deliberately NOT given the
// same rule, and the difference is a decision rather than an oversight: its suite argument is
// the GROUP's, RFC 9420 section 10.1's comparison is the key package against the group, and a
// third opinion taken off the validator's own provider would change the identity of a refusal a
// caller already branches on. What closes that side is this one -- with the pairing enforced
// where a key package is minted, a structure naming a suite its keys were not made under has to
// have come from outside this package.
var errKeyPackageProviderSuite = errors.New("mls: the provider does not run the ciphersuite this key package would name")

// errKeyPackageBadSignature is ValSem010 for a key package, and it WRAPS leaf_node.go's
// errBadSignature rather than being a second value for one condition, which is exactly what
// framing_protect.go's errFramedContentBadSignature does one layer over.
//
// The wrap is what makes the two distinguishable while keeping the broad question answerable.
// Validate verifies the KEY PACKAGE signature and then hands the leaf to LeafNode.Validate,
// which verifies the LEAF signature under a different label over different bytes -- two
// refusals a caller reads identically through errBadSignature alone. A test asserting only the
// broad question cannot say which of the two fired, and an error a test cannot distinguish is
// a rule a test cannot observe.
var errKeyPackageBadSignature = fmt.Errorf("mls: key package signature does not verify: %w", errBadSignature)

// marshalCore writes KeyPackageTBS: every field the signature covers, which is all of them but
// the signature.
//
// It is separated from MarshalMLS rather than inlined into it because the signing half needs
// precisely these bytes. One writer for the signed prefix and for the whole structure is what
// keeps the two from drifting: a signature taken over a prefix assembled a second time is a
// signature over whatever that second assembly happened to write.
func (self *KeyPackage) marshalCore(w *syntax.Writer) error {
	w.WriteUint16(uint16(self.Version))
	w.WriteUint16(uint16(self.CipherSuite))
	w.WriteOpaque(self.InitKey)
	if err := self.LeafNode.MarshalMLS(w); err != nil {
		return err
	}
	return WriteExtensions(w, self.Extensions)
}

func (self *KeyPackage) MarshalMLS(w *syntax.Writer) error {
	if err := self.marshalCore(w); err != nil {
		return err
	}
	w.WriteOpaque(self.Signature)
	return nil
}

// UnmarshalMLS reads every field and only then writes the receiver.
//
// The staging is leaf_node.go's and framing.go's, for their reason: a decoder that assigned as
// it read would leave a caller's KeyPackage holding the version and init key out of a message
// this package REFUSED, beside a leaf node from whatever the value held before. That pair is a
// key package no peer ever published, and nothing in the returned error says so.
//
// The signature seed is cleared with the rest, and that is the same argument in the one place
// it is a secret: a KeyPackage value decoded over a receiver NewKeyPackage had filled in would
// otherwise carry the old leaf's private signing seed beside a stranger's public key, and the
// caller has no way to see that the two do not belong together.
func (self *KeyPackage) UnmarshalMLS(r *syntax.Reader) error {
	version, err := r.ReadUint16()
	if err != nil {
		return err
	}
	suite, err := r.ReadUint16()
	if err != nil {
		return err
	}
	initKey, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	leafNode := LeafNode{}
	if err := leafNode.UnmarshalMLS(r); err != nil {
		return err
	}
	extensions, err := ReadExtensions(r)
	if err != nil {
		return err
	}
	signature, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	*self = KeyPackage{
		Version:     ProtocolVersion(version),
		CipherSuite: CipherSuite(suite),
		InitKey:     HpkePublicKey(initKey),
		LeafNode:    leafNode,
		Extensions:  extensions,
		Signature:   signature,
	}
	return nil
}

var _ syntax.Codec = (*KeyPackage)(nil)

// signedPreimage is RFC 9420 section 10's KeyPackageTBS, and it is one statement long on
// purpose: it hands marshalCore to marshalBytes and adds nothing of its own.
//
// KeyPackageTBS is a preimage and never a message, so it does not go through syntax.Marshal:
// nothing decodes these bytes, and the trailing byte contract Marshal carries belongs to a
// wire type. It differs from leaf_node.go's signatureContent, which opens its own Writer,
// because that one has a variant suffix to write after the core and this one has none -- there
// is nothing here for a closure to hide.
//
// It is NOT spelled signatureContent, which is the name leaf_node.go gives the same job one
// layer down, and the difference is load bearing rather than cosmetic. Several of this
// package's gates walk a call graph keyed by NAME with no receiver, so two methods sharing a
// spelling are one node: with this one called signatureContent, LeafNode.Sign, its verifier
// and the provider's own SignWithLabel all became names that reach marshalBytes, and
// extension_test.go's loose-body rule reported a crypto primitive as an extension body
// assembler. Measured. extension_test.go's own PskSecret exemption is the same collision
// caught one plan earlier and paid for with a table entry instead.
func (self *KeyPackage) signedPreimage() ([]byte, error) {
	return marshalBytes(self.marshalCore)
}

// NewKeyPackage mints a fresh key package: a fresh signature key pair, a fresh init key pair,
// a fresh leaf encryption key pair, a key_package source leaf over the last two, and a
// signature over the whole thing.
//
// THREE key pairs and not two, and the init pair and the encryption pair are drawn from
// SEPARATE entropy. They are two keys in RFC 9420 because they are used by different parties
// at different times -- the init key decrypts the Welcome that admits this member, the
// encryption key decrypts every commit's path secret afterwards -- so a member whose two keys
// are one is a member for whom compromising either compromises both, for the whole life of the
// group. A constructor that derived both from one draw answers a perfectly well formed key
// package that every test which does not compare the two halves accepts; this project has
// measured that exact substitution surviving a whole green suite one plan ago, which is why
// the two draws are separate statements here and why
// TestNewKeyPackageDrawsTheInitAndEncryptionKeysFromSeparateEntropy opens a message under each
// public half with the private half it was handed.
//
// The three private halves leave by different doors, which is deliberate rather than untidy.
// The two HPKE halves are RESULTS, because the caller has to persist them against the ref
// before it publishes anything -- a key package published without its private halves stored is
// a Welcome nobody can open. The signature seed rides on the unexported field instead, because
// it is the same key the leaf named as its signature_key and the group lifecycle plan reads it
// off the value when it assembles JoinKeyMaterial.
//
// The provider and the suite are compared before anything is drawn, and
// errKeyPackageProviderSuite carries the argument: they are one decision written twice, and a
// key package advertising a suite its keys were not made under is invisible to every behavioural
// test in this tree for as long as the registered suites share their primitives.
//
// The extensions are the LEAF's, not the key package's. RFC 9420 has both, and this profile
// puts urmessage_leaf_keys (0xF002) on the leaf because it is a property of the device rather
// than of the advertisement: it has to survive into the ratchet tree, and only the leaf does.
func NewKeyPackage(crypto CryptoProvider, suite CipherSuite, cred Credential,
	caps Capabilities, exts []Extension) (kp *KeyPackage, initPriv HpkePrivateKey,
	encPriv HpkePrivateKey, err error) {
	// the provider is refused before any argument is judged, which is the only order that
	// does not dereference it: a draw that reached the provider for a length first would
	// take the caller's process rather than its call
	if crypto == nil {
		return nil, nil, nil, fmt.Errorf("%w: every key here is drawn and the key package is signed through it",
			ErrNilCryptoProvider)
	}
	// before anything is drawn, so a caller's mistake costs no entropy and no key pair. The
	// suite named and the suite run are one decision written twice, and
	// errKeyPackageProviderSuite is where the reason a disagreement cannot be answered here is
	// written down.
	if crypto.Suite() != suite {
		return nil, nil, nil, fmt.Errorf("%w: the provider runs %#04x and this key package would name %#04x",
			errKeyPackageProviderSuite, uint16(crypto.Suite()), uint16(suite))
	}
	signPriv, _, err := crypto.SignatureKeyPair()
	if err != nil {
		return nil, nil, nil, err
	}
	initPriv, initPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		return nil, nil, nil, err
	}
	// a SECOND draw, and the reason is in this function's own header: one draw feeding both
	// DeriveKeyPair calls answers two identical key pairs, and nothing about the key package
	// that comes back says so
	encPriv, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		return nil, nil, nil, err
	}
	leaf, err := NewLeafNode(crypto, signPriv, cred, encPub, caps, exts)
	if err != nil {
		return nil, nil, nil, err
	}
	kp = &KeyPackage{
		Version:     ProtocolVersionMls10,
		CipherSuite: suite,
		InitKey:     initPub,
		LeafNode:    *leaf,
		Extensions:  nil,
		signPriv:    signPriv,
	}
	content, err := kp.signedPreimage()
	if err != nil {
		return nil, nil, nil, err
	}
	signature, err := crypto.SignWithLabel(signPriv, keyPackageSignatureLabel, content)
	if err != nil {
		return nil, nil, nil, err
	}
	kp.Signature = signature
	return kp, initPriv, encPriv, nil
}

// Ref is RFC 9420 section 5.2's KeyPackageRef: RefHash over the WHOLE marshalled key package,
// which is the signature as well as everything the signature covers.
//
// The whole structure and not the signed prefix, and the difference is the point. A commit
// names the key package it is adding by this value, so two key packages that differ only in
// their signature must not share a ref: a member holding one and a member holding the other
// would agree they were adding the same joiner while holding two different structures, and
// every later tree hash would disagree. Ed25519 as this package uses it is deterministic, so
// the second signature has to come from somewhere else -- which is exactly the case that
// matters, because it is a peer's, not this client's.
// TestKeyPackageRefCoversTheSignatureAndNotOnlyTheSignedPrefix is what says so.
func (self *KeyPackage) Ref(crypto CryptoProvider) ([]byte, error) {
	if crypto == nil {
		return nil, fmt.Errorf("%w: the reference is hashed through it", ErrNilCryptoProvider)
	}
	encoded, err := syntax.Marshal(self)
	if err != nil {
		return nil, err
	}
	return MakeKeyPackageRef(crypto, encoded), nil
}

// Validate is RFC 9420 section 10.1 for one key package, minus the 100-series proposal checks.
//
// The order is cheapest-and-most-structural first, and the first two positions are load
// bearing rather than tidy. The version and the ciphersuite are what decide whether the rest
// of this structure means anything at all -- a key package naming another suite carries keys
// of another shape and a signature under another scheme -- so they are refused before a
// primitive is asked to verify anything. The key package's own signature is checked before the
// leaf is handed on, because that signature is what binds the init key to the leaf: a leaf
// that verifies on its own inside a key package whose signature does not is somebody else's
// leaf republished under a stranger's init key.
//
// now is the caller's clock and it reaches the lifetime check by way of NowMs. Section 7.3
// makes the lifetime a MUST for a leaf a client is SENDING, and every caller of this is
// sending or is about to admit a joiner, so the clock is a required argument rather than an
// optional one -- see the note on the clamp below for what happens to a clock before the
// epoch, which is the one value LeafValidationContext reads as an opt out.
func (self *KeyPackage) Validate(crypto CryptoProvider, suite CipherSuite, now time.Time) error {
	if crypto == nil {
		return fmt.Errorf("%w: the key package's signature is verified through it", ErrNilCryptoProvider)
	}
	// framing_errors.go's exported sentinel and not the profile one, because "this is not
	// mls10" is the same refusal here that it is for a frame and a caller branches on it the
	// same way. The profile sentinel below answers a different question -- this IS mls10 and
	// the suite is not the group's -- and collapsing the two would hand a caller reading
	// "ciphersuite is outside the v1 profile" a structure whose ciphersuite was fine.
	if self.Version != ProtocolVersionMls10 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, self.Version)
	}
	if self.CipherSuite != suite {
		return fmt.Errorf("%w: the key package names %#04x and this group runs %#04x",
			errProfileCiphersuite, uint16(self.CipherSuite), uint16(suite))
	}
	content, err := self.signedPreimage()
	if err != nil {
		return err
	}
	// the LEAF's signature key, which is the only public key a key package carries that could
	// have made this signature: section 10 says the key package is signed by the same key the
	// leaf names, and NewKeyPackage signs with exactly that seed
	if err := crypto.VerifyWithLabel(self.LeafNode.SignatureKey, keyPackageSignatureLabel,
		content, self.Signature); err != nil {
		return errKeyPackageBadSignature
	}
	return self.LeafNode.Validate(&LeafValidationContext{
		Crypto:         crypto,
		Suite:          suite,
		GroupId:        nil,
		LeafIndex:      0,
		ExpectedSource: LeafNodeSourceKeyPackage,
		// clamped to one millisecond rather than to zero, and the one is the whole point:
		// LeafValidationContext reads a NowMs of 0 as "this caller has no trustworthy clock,
		// do not check the lifetime at all". A clock before the unix epoch is a machine whose
		// clock is not set, and clamping that to the opt out would turn the one input a
		// validator cannot trust into the one input that disables the check it exists for.
		// One millisecond is before every lifetime this package mints, so it is refused.
		NowMs:       uint64(max(now.UnixMilli(), 1)),
		ClockSkewMs: leafLifetimeSkewSeconds * 1000,
	})
}
