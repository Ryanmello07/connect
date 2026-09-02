// RFC 9420 section 12.4.3: signing a GroupInfo, and deciding whether the one a peer sent was
// signed by a member of the group it describes.
//
// welcome_wire.go carries the structures and their codecs and says so in its own header --
// "nothing here decides whether a GroupInfo's signature is good". This file is where that is
// decided, and until it landed nothing in this build decided it anywhere: VerifyWithLabel had
// production callers for FramedContentTBS, KeyPackage and LeafNode and none at all for
// GroupInfoTBS, so a decoded GroupInfo naming any group at any epoch was as good as one a
// member signed. Everything downstream that treats a GroupInfo's group context as an epoch
// somebody agreed to rests on Verify, which is why what Verify does and does not establish is
// written out rather than left to be inferred.
//
// WHAT VERIFY ESTABLISHES. That the member at leaf GroupInfo.Signer of the ratchet tree the
// CALLER holds signed these exact bytes, and that the group context those bytes carry names
// that same tree. It establishes nothing about whether that tree is the group's tree -- that is
// (*RatchetTree).ValidateAgainstContext's, run by whoever obtained the tree -- and nothing
// about the confirmation tag, which is the key schedule's and needs an epoch secret this file
// never sees.
//
// THE PRECONDITION THAT SENTENCE HIDES IS THE MOST IMPORTANT THING IN THIS FILE, and it is
// written out in full on Verify itself, under "WHERE THE TREE COMES FROM". A JOINER CANNOT
// AUTHENTICATE THE TREE FROM THE WELCOME ALONE, whatever shape its call site takes: an attacker
// that mints its own tree and signs at its own leaf is answered nil, and it makes no difference
// whether the joiner lifted that tree out of the GroupInfo's ratchet_tree extension or was handed
// it as a parameter of its own, because both octet strings arrive over one wire from one sender.
// p7 task 16's JoinFromWelcome takes the tree as a separate ratchetTree []byte, so nobody writing
// it may read that separation as the check. Read that paragraph before writing the call site.
//
// The signer's public key is NOT a field of GroupInfo, and that is the whole reason Verify
// takes a tree. A structure that carried the key its own signature is checked under verifies
// under whatever key its sender chose to put in it, which is a signature by nobody: the
// property this file exists for is that a GroupInfo does not verify unless a MEMBER OF THE TREE
// signed it, and the only thing that can say who the members are is the tree.
//
// ONE RULE, ONE ANSWER, AND NO BARE RETURNS. The rules are enumerated on Verify itself and each
// of them answers a sentinel no other one answers. One sentinel behind two rules is a rule no
// test can observe -- errors.Is cannot tell them apart, so every assertion in the area passes
// over a refusal that fired for the wrong reason -- and that is this project's most repeated
// defect rather than a hypothetical.
//
// Nothing in Verify returns a bare err, which is the same rule stated over the EXITS rather than
// over the sentinels. TestEachRuleOfGroupInfoVerifyAnswersItsOwnSentinel derives Verify's
// refusal class from the identifiers in its own return statements, so an exit spelled
// `return err` is one that gate cannot see: whatever a helper three layers down decides to
// answer silently becomes one of Verify's answers, unnamed and unswept, and the gate reports a
// clean run over it. Every exit here names the sentinel it refuses under and wraps the cause
// behind it.
package mls

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// groupInfoSignatureLabel is the RFC 9420 section 12.4.3 label, written once for the reason
// leaf_node.go's own label states: a label spelled one way in the signing half and another in
// the verifying half agrees with itself perfectly, because ed25519 signs whatever preimage it
// is handed and only a PEER can tell "GroupInfoTBS" from "GroupInfoTbs". It is also what keeps
// a GroupInfo signature from being a valid LeafNodeTBS or KeyPackageTBS signature by the same
// key.
const groupInfoSignatureLabel = "GroupInfoTBS"

// errGroupInfoProviderSuite is Verify's rule 3: the provider this check is being made through
// does not run the ciphersuite the group info's own group context names.
//
// It mirrors key_package.go's errKeyPackageProviderSuite, which is the same question asked of the
// same argument one structure over, and it is deliberately NOT ErrWelcomeSuiteMismatch. That
// sentinel reads "welcome ciphersuite does not match the key package" and names a different
// fault: the CLEARTEXT suite of a Welcome held against the suite of the key package the joiner
// published, a comparison of two values neither of which this method is handed. Task 16 is where
// that one is wired. Collapsing the two would hand a caller repairing its key package a refusal
// about a group info whose key package was never in question.
var errGroupInfoProviderSuite = errors.New(
	"mls: the provider does not run the ciphersuite this group info names")

// errGroupInfoPreimage names a GroupInfo whose own to-be-signed structure will not encode.
//
// A refusal about the OBJECT and not about its signature, which is why it is not
// ErrWelcomeGroupInfoSignature: with no preimage there are no bytes to check a signature over, so
// nothing whatever has been decided about the signature, and a caller told its peer's signature
// was bad would go looking in the wrong place.
//
// It is reachable rather than defensive. (*RatchetTree).Encode writes a ratchet_tree body at the
// raised MaxRatchetTreeLength bound, one labelled field holds MaxVectorLength, and
// TestAGroupInfoCarryingThisProductsTreeCannotBeSigned measures that this product's own tree
// exceeds it -- so a group info decoded at the raised bound reaches this exit.
var errGroupInfoPreimage = errors.New(
	"mls: this group info's to-be-signed structure did not encode")

// signaturePreimage is the bytes a GroupInfo signature is over: this object's GroupInfoTBS,
// serialized.
//
// It goes through (*GroupInfo).toBeSigned rather than assembling a GroupInfoTBS of its own, and
// that is the point of this function rather than a saving of four lines. welcome_wire.go states
// the rule the assembly would break: a field the object carries and the preimage omits is a
// field nobody's signature covers, an attacker rewrites it in flight with the signature still
// verifying, and no round trip test can see it because each half round trips perfectly on its
// own. A second assembly of one preimage is exactly that defect and it has already cost this
// project a round on KeyPackage.
//
// One function for both halves, for leaf_node.go's reason one layer down: a preimage built one
// way to sign and another way to verify agrees with itself and with nobody else.
//
// The value is addressed because GroupInfoTBS is a syntax.Marshaler on its POINTER; toBeSigned
// answers a value, so the address is taken here rather than at two call sites.
func (self *GroupInfo) signaturePreimage() ([]byte, error) {
	tbs := self.toBeSigned()
	return syntax.Marshal(&tbs)
}

// Sign replaces this GroupInfo's signature with one over its GroupInfoTBS under the
// "GroupInfoTBS" label.
//
// The signature field is not part of what is signed -- toBeSigned stops above it -- so signing
// twice over one GroupInfo answers the same bytes and a stale signature left on the receiver
// cannot feed into the new one.
//
// IT REPLACES, UNCONDITIONALLY, and that word is what p7 task 15 rests on. A committer assembles
// a GroupInfo, signs it, fills in the confirmation tag once the key schedule has advanced, and
// signs again; a Sign that wrote only into an EMPTY Signature would answer nil to that second
// call and leave the first signature -- taken over a different confirmation tag -- standing on
// the object it hands out. That defect survives a sign-then-verify test, and it survives
// TestGroupInfoSigningTwiceAnswersTheSameSignature as well, because under it the second call does
// nothing at all and the two signatures compared are one signature.
// TestSigningAGroupInfoAgainAfterAFieldChangedReplacesTheStaleSignature is the input that can see
// it, and it is written around exactly that.
//
// It does NOT check that priv is the private half of the key at leaf Signer. The signer has no
// tree here and a caller that signs at the wrong index produces a GroupInfo every peer refuses,
// which is Verify's answer rather than a second copy of the rule made against a tree this side
// may not hold.
func (self *GroupInfo) Sign(crypto CryptoProvider, priv SignaturePrivateKey) error {
	if crypto == nil {
		return fmt.Errorf("%w: the signature over the GroupInfoTBS is made through it",
			ErrNilCryptoProvider)
	}
	content, err := self.signaturePreimage()
	if err != nil {
		return err
	}
	signature, err := crypto.SignWithLabel(priv, groupInfoSignatureLabel, content)
	if err != nil {
		return err
	}
	self.Signature = signature
	return nil
}

// Verify answers nil only if the member at leaf Signer of THIS tree signed this GroupInfo's
// GroupInfoTBS, and this tree is the tree that signed group context names.
//
// WHERE THE TREE COMES FROM. THIS IS THE PRECONDITION VERIFY CANNOT CHECK AND ITS CALLER MUST.
//
// Verify's guarantee is entirely RELATIVE to the *RatchetTree it is handed. Read the sentence
// above with the emphasis where it belongs: A MEMBER OF THIS TREE SIGNED THIS GROUP INFO ABOUT
// THIS TREE. It does not say that this tree is the group anyone meant to join, and no shape of
// this signature could make it say so -- a joiner holds no prior state to check a tree against,
// which is the whole reason the tree is a parameter rather than something derived here. That is
// not a defect in Verify. It is a precondition on its CALLER, and until this paragraph it was
// written down nowhere.
//
// So the tree a caller passes must come from OUTSIDE THE WELCOME, and outside the WHOLE message
// rather than outside one field of it. Measured on this build:
//
//	an attacker mints its own four leaf tree with every leaf its own, sets
//	GroupContext.GroupId to whatever the joiner expects, sets GroupContext.TreeHash to its OWN
//	tree's hash, and signs at its own leaf 0. Verify against the attacker's tree is answered
//	NIL. Against the honest tree the same object correctly answers ErrWelcomeTreeHashMismatch.
//
// Every rule below passes over that object because every rule below is TRUE of it: a member of
// that tree did sign that group info about that tree. The forgery is self-consistent, and
// self-consistency is the whole of what a signature check can establish.
//
// THE PARAMETER SHAPE IS NOT THE FIX, which is the sentence this paragraph exists for, because
// an earlier version of it did not say so. That version warned against ONE spelling -- lifting
// the tree out of the GroupInfo's own ratchet_tree extension, which RFC 9420 section 12.4.3.1
// invites and which is written carried, _ := ParseRatchetTreeFrom(ext); info.Verify(crypto,
// carried) -- and p7 task 16's
//
//	JoinFromWelcome(cfg *GroupConfig, welcome []byte, ratchetTree []byte, keys *JoinKeyMaterial)
//
// takes the tree as its OWN parameter, so an implementer reads that warning as obeyed by
// construction while THE IDENTICAL FORGERY WORKS UNCHANGED: the attacker supplies both byte
// strings, they arrive over one wire from one sender, and which parameter an octet came in is
// not a property anything here can check. That was measured, with nothing changed but where the
// octets came from.
//
// WHAT A CALLER MUST DO INSTEAD is anchor on something the joiner held BEFORE the Welcome
// arrived. There are two such things and only the second of them closes this:
//
//  1. THE KEY PACKAGE THE WELCOME IS ADDRESSED TO. A joiner must find its own
//     EncryptedGroupSecrets by the reference of a KeyPackage IT published and open it with an init
//     private key only it holds, refusing under ErrWelcomeNoMatchingKeyPackage otherwise -- which
//     is the sentinel p7 task 16's own test names for a Welcome addressed to somebody else. That
//     establishes this Welcome was made for THIS joiner, which is worth having, and it establishes
//     nothing about who made it: a published KeyPackage is public and anybody at all may build a
//     group around one.
//  2. A SIGNER CREDENTIAL THE JOINER ALREADY TRUSTS, matched against at least one leaf of the
//     tree, together with (*RatchetTree).ValidateAgainstContext run over that tree by whoever
//     obtained it, against a group context that came from somewhere the joiner already trusts.
//     This is the half that actually closes it, and this build does not have it: there is no
//     authentication service here, so no credential in any leaf means anything to a joiner yet.
//
// Until 2 exists, NO call site of this method can answer "is this the group I meant to join" --
// not JoinFromWelcome, not any other parameter list -- and none of them may be written as though
// it did. The CALLER is the party making the authority claim, and the tree it passes is what
// says so.
//
// THE RULES, in the order they run. Each answers a sentinel no other one answers.
//
//  1. The provider and the tree are there at all -- ErrNilCryptoProvider, ErrTreeMalformed. The
//     tree is refused as a malformed tree rather than as any later rule: no tree is not a tree
//     whose hash disagrees, nor an index outside one, and a caller handed one of those answers
//     would go looking for a fault in a GroupInfo that may be perfectly good.
//
//  2. The group context names mls10 -- ErrUnsupportedVersion. framing_errors.go's exported
//     sentinel and not a profile one, for the reason (*KeyPackage).Validate states next door:
//     "this is not mls10" is the same refusal here that it is for a frame, and a caller branches
//     on it the same way.
//
//  3. The group context names the ciphersuite this provider runs -- errGroupInfoProviderSuite.
//     It runs BEFORE the tree hash and that order is load bearing: the hash rule 4 compares is
//     taken THROUGH crypto, so over a group info naming another suite that comparison holds one
//     suite's hash function against another's and answers about nothing. It is a real refusal
//     rather than hygiene, because the ciphersuite is INSIDE the signed bytes: without this rule
//     a MEMBER can commit to a suite the verifier is not running, and
//     (*GroupInfo).VerifiedContext then hands a proposal cache a group context naming it.
//     Measured before it existed: a group info whose GroupContext.CipherSuite is 0xbeef, signed
//     by a real member and verified through the suite 3 provider, answered nil. Version 0x4242
//     did the same.
//
//  4. The group context's tree_hash is this tree's hash -- ErrWelcomeTreeHashMismatch. It runs
//     before every index rule because an index into a tree the group context does not name means
//     nothing at all: "leaf 5" of some other tree is not the member the signature is claimed to
//     be by. It is also the cheaper of the two structural comparisons, which is the order
//     (*RatchetTree).ValidateAgainstContext keeps for the same reason.
//
//     ErrWelcomeTreeHashMismatch and that method's ErrTreeHashMismatch are two values for what
//     is arithmetically one comparison, and they STAY two. What separates them is who is asking:
//     this rule asks whether a GROUP INFO names the tree in hand, and that one asks whether a
//     TREE matches the context it is being validated against. There is deliberately no wrap
//     between them -- TestOnlyTheSanctionedWrapsHoldAcrossThisPackagesErrorClasses forbids one
//     across this package's maintained error classes, and its sanctioned-wrap table is
//     tree_errors.go's argument about tree INDEX sentinels rather than a general escape hatch --
//     so a caller that wants "is this the group's tree" must ask both. That is written here
//     because the two are indistinguishable at a glance and a later reader's first instinct is
//     to make one wrap the other.
//
//  5. Signer is inside the tree -- ErrLeafIndexOutOfRange. The bound is the tree's LEAF WIDTH and
//     never its member count, and the two are not interchangeable: a three member group pads to
//     width 4, so leaf 3 is INSIDE the tree and occupied by nobody. A bound taken from the member
//     count answers this rule where rule 6 belongs, which is the rule collapse rule 6's note is
//     about, and a group with a trailing blank leaf is the one shape that separates them.
//
//  6. The leaf at Signer is not blank -- errBlankSenderLeaf. A blank leaf is a position no
//     member occupies, so there is no key to verify under; taking one from anywhere else is the
//     substitution this whole file exists to refuse.
//
//  7. This group info's own GroupInfoTBS encodes -- errGroupInfoPreimage. Not a signature
//     refusal: with no preimage nothing has been decided about the signature at all.
//
//  8. The signature verifies under that leaf's signature_key -- ErrWelcomeGroupInfoSignature.
//
//  9. The ratchet_tree extension this group info CARRIES, if it carries one, describes the tree
//     it has just been verified against -- ErrMalformedExtension for a group info carrying two
//     of them, which is FindExtensionEntry's refusal and this package's one door for that
//     question, and ErrWelcomeCarriedTreeMismatch for one that carries a tree and means another.
//
// Rules 5 and 6 are kept apart although (*RatchetTree).Leaf answers nil for both. They are
// different faults -- a peer that named leaf 2^31 has sent something structurally impossible,
// and a peer that named a removed member's position has sent something merely wrong -- and a
// single sentinel would let a test asserting either one pass over the other.
//
// Every way the primitive can refuse becomes one sentinel at rule 8, with the primitive's own
// error wrapped rather than dropped: a wrong length key, a wrong length signature and a
// signature over other content all arrived from the network, and a caller has the same branch to
// take for all three. An EMPTY signature<V> is among them and is not a hypothetical -- it is a
// wire-legal encoding, syntax.Unmarshal accepts it and leaves len(Signature) == 0 -- and it is
// VerifyWithLabel that refuses it, which is why there is no length rule of this file's own.
//
// WHAT RULE 9 BUYS AND WHAT IT DOES NOT. Before it, a group info whose ratchet_tree extension
// described tree A while its group context named tree B verified against B with the extension
// ENTIRELY IGNORED: Verify never decoded GroupInfo.Extensions. That let one object simultaneously
// verify against the tree a joiner already trusts and carry a different tree for some later code
// path to adopt, with "the group info verified" as the warrant. Rule 9 closes it -- the two
// readings of "the group's tree" a single GroupInfo offers can no longer disagree.
//
// It does NOT make the carried tree trustworthy, and it must not be read as doing so. In the
// forgery above the extension and the tree AGREE, because they are the same tree, so rule 9
// passes and Verify answers nil. Agreement is not authentication. Rule 9 removes a discrepancy
// and adds no authority whatever, and a caller that reads it as permission to lift the tree out
// of the extension has made exactly the mistake the paragraphs above are about.
//
// It runs LAST, after the signature, which is a cost decision with a security reading: it decodes
// and hashes a ratchet tree chosen by whoever sent the group info, so that work is paid only for
// a group info a member of the CALLER'S tree has already been shown to have signed. The body it
// decodes is bounded by rule 7 having succeeded -- one labelled field holds MaxVectorLength -- so
// the raised bound (*RatchetTree).Encode writes at is not reachable through here.
func (self *GroupInfo) Verify(crypto CryptoProvider, tree *RatchetTree) error {
	if crypto == nil {
		return fmt.Errorf("%w: the signature over the GroupInfoTBS is checked through it",
			ErrNilCryptoProvider)
	}
	// refused rather than dereferenced, and refused as a malformed tree rather than as any of
	// the rules below: no tree is not a tree whose hash disagrees, nor an index outside one, and
	// a caller handed one of those answers would go looking for a fault in a GroupInfo that may
	// be perfectly good. TreeHash on a nil receiver is a nil dereference at rule 4, which takes
	// the caller's process rather than its call.
	if tree == nil {
		return fmt.Errorf("%w: there is no ratchet tree for this group info to be checked against",
			ErrTreeMalformed)
	}
	if self.GroupContext.Version != ProtocolVersionMls10 {
		return fmt.Errorf("%w: the group info names %#04x",
			ErrUnsupportedVersion, uint16(self.GroupContext.Version))
	}
	// before the tree hash, because the tree hash below is taken THROUGH crypto: over a group
	// info naming another suite that comparison holds one suite's hash function against
	// another's, and a mismatch there would report a tree disagreement where the real fault is
	// that this provider cannot check this group info at all.
	if self.GroupContext.CipherSuite != crypto.Suite() {
		return fmt.Errorf("%w: the group info names %#04x and the provider runs %#04x",
			errGroupInfoProviderSuite, uint16(self.GroupContext.CipherSuite), uint16(crypto.Suite()))
	}
	treeHash, err := tree.TreeHash(crypto)
	if err != nil {
		// named rather than returned bare. TreeHash's own refusal for a tree whose width is not
		// a tree's is already ErrTreeMalformed, so this wrap changes no caller's branch -- what
		// it changes is that this EXIT is one the refusal class derivation can see, instead of
		// an unnamed hole through which whatever tree.go decides to answer next silently becomes
		// one of Verify's answers.
		return fmt.Errorf("%w: the tree this group info is checked against does not hash: %w",
			ErrTreeMalformed, err)
	}
	// through crypto/subtle for guardrail 8's reason, which is the class rather than this line:
	// a tree hash is public, and every comparison in this package that decides whether a
	// structure is ADOPTED is spelled the one way so no later reader has to work out which of
	// them were the safe ones. Unequal lengths answer zero, so an absent or truncated tree_hash
	// is a mismatch rather than a panic.
	if subtle.ConstantTimeCompare(treeHash, self.GroupContext.TreeHash) != 1 {
		return fmt.Errorf("%w: the tree hashes to %x and the group info names %x",
			ErrWelcomeTreeHashMismatch, treeHash, self.GroupContext.TreeHash)
	}
	// LeafWidth and not MemberCount, per rule 5's note: a trailing blank leaf is inside the tree
	// and belongs to nobody, so a bound taken from the member count would answer this rule over
	// the position the blank leaf rule two lines down is for.
	if LeafCount(self.Signer) >= tree.LeafWidth() {
		return fmt.Errorf("%w: the group info names signer leaf %d and the tree holds %d leaves",
			ErrLeafIndexOutOfRange, self.Signer, tree.LeafWidth())
	}
	leaf := tree.Leaf(self.Signer)
	if leaf == nil {
		return fmt.Errorf("%w: the group info names signer leaf %d", errBlankSenderLeaf, self.Signer)
	}
	content, err := self.signaturePreimage()
	if err != nil {
		return fmt.Errorf("%w: %w", errGroupInfoPreimage, err)
	}
	if err := crypto.VerifyWithLabel(leaf.SignatureKey, groupInfoSignatureLabel,
		content, self.Signature); err != nil {
		return fmt.Errorf("%w: leaf %d: %w", ErrWelcomeGroupInfoSignature, self.Signer, err)
	}
	// rule 9, inline rather than in a helper of its own. A helper would put every sentinel it
	// answers behind a `return self.something(...)` this function's refusal class derivation
	// cannot see, which is the defect the file header's "no bare returns" paragraph is about: the
	// reader of that gate would be told Verify answers six sentinels while it answered nine.
	carried, carriesATree, err := FindExtensionEntry(self.Extensions, ExtensionTypeRatchetTree)
	if err != nil {
		// FindExtensionEntry's own refusal of a repeated type, which this package holds as its
		// ONE door for that question; named here so the exit is visible, and the cause kept.
		return fmt.Errorf("%w: this group info's extensions vector carries ratchet_tree twice: %w",
			ErrMalformedExtension, err)
	}
	if !carriesATree {
		return nil
	}
	carriedTree, err := ParseRatchetTreeFrom(carried)
	if err != nil {
		// a carried tree that will not decode is a carried tree that is not the one in hand,
		// which is this rule's single answer with the decoder's own reason wrapped behind it.
		// Rule 8 having passed bounds this body at one labelled field, so nothing here decodes at
		// the raised ratchet_tree bound.
		return fmt.Errorf("%w: the carried ratchet_tree did not decode: %w",
			ErrWelcomeCarriedTreeMismatch, err)
	}
	carriedHash, err := carriedTree.TreeHash(crypto)
	if err != nil {
		return fmt.Errorf("%w: the carried ratchet_tree does not hash: %w",
			ErrWelcomeCarriedTreeMismatch, err)
	}
	// the tree hash is the identity of a tree everywhere else in this package, so it is what "the
	// same tree" means here too; comparing the two ENCODINGS instead would make this rule refuse
	// over spellings rather than over trees. Through subtle for the reason the rule 4 comparison
	// is.
	if subtle.ConstantTimeCompare(carriedHash, treeHash) != 1 {
		return fmt.Errorf("%w: the carried ratchet_tree hashes to %x and the tree it was verified against hashes to %x",
			ErrWelcomeCarriedTreeMismatch, carriedHash, treeHash)
	}
	return nil
}
