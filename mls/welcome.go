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
// The signer's public key is NOT a field of GroupInfo, and that is the whole reason Verify
// takes a tree. A structure that carried the key its own signature is checked under verifies
// under whatever key its sender chose to put in it, which is a signature by nobody: the
// property this file exists for is that a GroupInfo does not verify unless a MEMBER OF THE TREE
// signed it, and the only thing that can say who the members are is the tree.
//
// FOUR RULES, FOUR ANSWERS. A group context naming a different tree, a signer index past the
// end of the tree, a signer index naming a blank leaf, and a signature that does not verify
// under that leaf's key are four different things to be wrong about, and each answers its own
// sentinel. One sentinel behind four rules is a rule no test can observe -- errors.Is cannot
// tell two of them apart, so every assertion in the area passes over a refusal that fired for
// the wrong reason -- and that is this project's most repeated defect rather than a
// hypothetical.
package mls

import (
	"crypto/subtle"
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

// Verify answers nil only if the member at leaf Signer of this tree signed this GroupInfo's
// GroupInfoTBS, and this tree is the tree that signed group context names.
//
// The four rules run in the order below and each answers its own sentinel.
//
//  1. The group context's tree_hash is this tree's hash -- ErrWelcomeTreeHashMismatch. It runs
//     FIRST because everything after it is an index into this tree, and an index into a tree the
//     group context does not name means nothing at all: "leaf 5" of some other tree is not the
//     member the signature is claimed to be by. It is also the cheaper of the two structural
//     comparisons, which is the order (*RatchetTree).ValidateAgainstContext keeps for the same
//     reason.
//  2. Signer is inside the tree -- ErrLeafIndexOutOfRange.
//  3. The leaf at Signer is not blank -- errBlankSenderLeaf. A blank leaf is a position no
//     member occupies, so there is no key to verify under; taking one from anywhere else is the
//     substitution this whole file exists to refuse.
//  4. The signature verifies under that leaf's signature_key -- ErrWelcomeGroupInfoSignature.
//
// Rules 2 and 3 are kept apart although (*RatchetTree).Leaf answers nil for both. They are
// different faults -- a peer that named leaf 2^31 has sent something structurally impossible,
// and a peer that named a removed member's position has sent something merely wrong -- and a
// single sentinel would let a test asserting either one pass over the other.
//
// Every way the primitive can refuse becomes one sentinel at rule 4, with the primitive's own
// error wrapped rather than dropped: a wrong length key, a wrong length signature and a
// signature over other content all arrived from the network, and a caller has the same branch
// to take for all three.
func (self *GroupInfo) Verify(crypto CryptoProvider, tree *RatchetTree) error {
	if crypto == nil {
		return fmt.Errorf("%w: the signature over the GroupInfoTBS is checked through it",
			ErrNilCryptoProvider)
	}
	// refused rather than dereferenced, and refused as a malformed tree rather than as any of
	// the four rules: no tree is not a tree whose hash disagrees, nor an index outside one, and
	// a caller handed one of those answers would go looking for a fault in a GroupInfo that may
	// be perfectly good. LeafWidth on a nil receiver is a nil dereference two lines down, which
	// takes the caller's process rather than its call.
	if tree == nil {
		return fmt.Errorf("%w: there is no ratchet tree for this group info to be checked against",
			ErrTreeMalformed)
	}
	treeHash, err := tree.TreeHash(crypto)
	if err != nil {
		return err
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
		return err
	}
	if err := crypto.VerifyWithLabel(leaf.SignatureKey, groupInfoSignatureLabel,
		content, self.Signature); err != nil {
		return fmt.Errorf("%w: leaf %d: %w", ErrWelcomeGroupInfoSignature, self.Signer, err)
	}
	return nil
}
