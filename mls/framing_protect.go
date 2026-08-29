// Signing, MACing, encrypting and their inverses for RFC 9420 section 6.
//
// The preimages themselves are framing_preimage.go's and the wire types are framing.go's, so
// this file is only the operations: what is signed, with which key, under which label, and
// what a verifier does with the answer. Keeping the three apart is what makes a preimage
// change a one file diff -- a defect there produces a group that agrees with itself and
// diverges permanently from every peer, and there is no failure mode a reviewer is worse at
// spotting in a diff that also moves the crypto around.
//
// Every operation here verifies rather than reporting, which is spec A section 5.9's
// guardrail G7 and the reason none of these answers a bool. This project has shipped three
// authentication bypasses and every one of them passed the whole suite: a verifier that
// discarded a tag error and returned the zero tag, a verifier that rewrote the tag it was
// checking, and a variable time comparison through a name a ban list did not enumerate. What
// they have in common is a caller that was handed something it could ignore.
package mls

import (
	"crypto/subtle"
	"errors"
	"fmt"
)

// The label RFC 9420 section 6.1 signs a FramedContentTBS under, written once because a label
// spelled one way in the signing half and another in the verifying half agrees with itself
// perfectly: ed25519 signs whatever preimage it is handed, and only a peer can tell
// "FramedContentTBS" from "FramedContentTbs". The label is the whole of what stops a framing
// signature being a valid signature over some other structure the same key signed --
// leaf_node.go's leafNodeSignatureLabel and treekem.go's updatePathNodeLabel are the two
// neighbours it separates this one from.
const framedContentTBSLabel = "FramedContentTBS"

// errFramedContentBadSignature is ValSem010 for a framed content, and it is a stand in in the
// sense leaf_node.go's errBadSignature is: the validation plan owns the single declaration
// site for the exported ErrBadSignature, that name has not landed in this package yet, and
// the stand in gate fails on the commit that lands the exported twin beside either of these.
//
// It WRAPS errBadSignature rather than being a second value for one condition. "The signature
// does not verify" is one thing to a caller however it was reached, so errors.Is answers the
// broad question for both; what the wrap buys is a message that names the structure, because
// a framing refusal that read "leaf node signature does not verify" would send a reader to
// the wrong layer. When ErrBadSignature lands, this becomes ValSem(ValSem010,
// ErrBadSignature) and both stand ins go in the same commit.
//
// Every failure of the verify collapses into this one value on purpose, which is the plan's
// requirement and worth stating rather than leaving to be re-derived: a caller that could
// tell a malformed signature from a wrong key from a signature over other bytes learns which
// of its guesses was closest, and a caller has no branch to take on any of the three other
// than rejecting the message.
var errFramedContentBadSignature = fmt.Errorf("mls: framed content signature does not verify: %w", errBadSignature)

// errNilAuthenticatedContent is what VerifyAuthenticatedContent answers a caller that passed
// no message, for errNilFramedContent's reason: a nil dereference out of a verifier takes the
// caller's process rather than its call.
var errNilAuthenticatedContent = errors.New("mls: verify requires an authenticated content")

// SignAuthenticatedContent signs a FramedContent under RFC 9420 section 6.1 and answers the
// AuthenticatedContent that carries it, with an EMPTY confirmation tag.
//
// The empty tag is the shape and not an omission. A commit's confirmation tag is a MAC over a
// confirmed transcript hash that is itself taken over this signature, so the tag cannot exist
// until the signature does; the caller that is committing sets Auth.ConfirmationTag once it
// has advanced the transcript, and VerifyAuthenticatedContent below refuses a commit that
// still carries none.
//
// The provider is checked before anything else is read, which is (*AuthenticatedContent).
// ProposalRef's discipline: a body that built its preimage first would answer
// ErrUnknownSenderType or ErrMissingGroupContext to a caller whose actual mistake was passing
// no provider, and send it to fix a message that was never the problem.
//
// The answer carries the caller's own FramedContent by value, sharing the byte slices inside
// it. That is deliberate and it is the reason this is not a copy: an AuthenticatedContent IS
// the caller's message with authenticators attached, every field of it is about to be
// serialized and sent, and a deep copy here would be a second opinion about what was signed.
// What is fresh is the signature, which is the only thing this function produces.
func SignAuthenticatedContent(crypto CryptoProvider, priv SignaturePrivateKey,
	wireFormat WireFormat, content *FramedContent, groupContext []byte) (*AuthenticatedContent, error) {

	if crypto == nil {
		return nil, fmt.Errorf("%w: the signature is the provider's", ErrNilCryptoProvider)
	}
	tbs, err := FramedContentTBSBytes(wireFormat, content, groupContext)
	if err != nil {
		return nil, err
	}
	signature, err := crypto.SignWithLabel(priv, framedContentTBSLabel, tbs)
	if err != nil {
		return nil, err
	}
	return &AuthenticatedContent{
		WireFormat: wireFormat,
		Content:    *content,
		Auth:       FramedContentAuthData{Signature: signature},
	}, nil
}

// VerifyAuthenticatedContent is ValSem010, and ValSem009 for a commit.
//
// The preimage is rebuilt from the message's OWN wire format and content rather than from
// anything the caller says about them, which is what makes the wire format binding worth
// having: a PublicMessage replayed as a PrivateMessage carries a different first field into
// the preimage, so the signature over one does not verify against the other. The group
// context is the caller's, because it is the receiver's own epoch and not something the
// message gets to assert.
//
// The empty signature is refused before the preimage is built, and that ordering is the point
// rather than an optimisation. An empty Signature is the ZERO VALUE of a FramedContentAuthData
// -- the state a freshly allocated one is in -- and this project shipped a bypass whose whole
// shape was an all zero authenticator reaching a comparison that accepted it. What this line
// says is that the refusal does not depend on the provider agreeing: a provider whose
// VerifyWithLabel accepted an empty signature would still not get one past here.
//
// Every failure OF THE SIGNATURE answers errFramedContentBadSignature and nothing narrower,
// for the reason that value's own comment gives.
//
// A refusal of the PREIMAGE travels out of here verbatim, and that is the deliberate other
// half of the rule rather than a leak in it. FramedContentTBSBytes answers
// ErrUnknownWireFormat, ErrUnknownSenderType, ErrMissingGroupContext or
// ErrUnexpectedGroupContext for a message this function could not assemble a preimage out of
// at all: there is no verification to have failed, so there is no verification answer to
// collapse them into, and errFramedContentBadSignature would tell a caller that a signature
// nothing ever checked did not verify. None of the four separates a right key from a wrong
// one -- three of them are the sender type's own select on the group context the RECEIVER
// supplied -- so the thing an unauthenticated message must not learn is not in any of them.
// What it must not learn is which of ValSem010 and ValSem009 it failed, and that is the
// ordering below.
//
// TestVerifyAnswersThePreimagesRefusalVerbatimAndCollapsesEverySignatureFailure holds both
// halves, over the two registries rather than over three inputs somebody picked.
func VerifyAuthenticatedContent(crypto CryptoProvider, pub SignaturePublicKey,
	authContent *AuthenticatedContent, groupContext []byte) error {

	if crypto == nil {
		return fmt.Errorf("%w: the verification is the provider's", ErrNilCryptoProvider)
	}
	if authContent == nil {
		return errNilAuthenticatedContent
	}
	if len(authContent.Auth.Signature) == 0 {
		return errFramedContentBadSignature
	}
	tbs, err := FramedContentTBSBytes(authContent.WireFormat, &authContent.Content, groupContext)
	if err != nil {
		return err
	}
	if err := crypto.VerifyWithLabel(pub, framedContentTBSLabel, tbs, authContent.Auth.Signature); err != nil {
		return errFramedContentBadSignature
	}
	// ValSem009, checked AFTER the signature and never before it. A commit whose tag is
	// missing is refused either way, and doing it in this order means an unauthenticated
	// message cannot learn which of the two rules it failed.
	if authContent.Content.ContentType == ContentTypeCommit && len(authContent.Auth.ConfirmationTag) == 0 {
		return errMissingConfirmationTag
	}
	return nil
}

// ---------------------------------------------------------------------------
// the membership tag, RFC 9420 section 6.2
// ---------------------------------------------------------------------------

// errMissingMembershipTag is ValSem007 in the validation plan's catalogue, and it is a stand
// in on exactly errFramedContentBadSignature's terms: that plan owns the single declaration
// site for the exported ErrMissingMembershipTag, the name has not landed in this package yet,
// and TestNoValidationOwnedNameHasLandedBesideItsStandIn fails on the commit that lands the
// exported twin beside this one. When it lands, this becomes ValSem(ValSem007,
// ErrMissingMembershipTag) and every stand in of this file goes in that same commit.
//
// It is its own value rather than a spelling of errBadMembershipTag, and the separation is the
// rule rather than a nicety: "the sender sent no tag" and "the tag does not verify" are two
// different messages to a receiver -- the first is a message no member of any group could have
// produced, the second is a message some member of some group produced under another key -- and
// RFC 9420 gives them two codes because a validator that collapsed them cannot say which of its
// rules refused. What a caller does about either is the same and is not the point.
var errMissingMembershipTag = errors.New("mls: public message carries no membership tag")

// errBadMembershipTag is ValSem008, on the same terms.
//
// Every failure of the comparison collapses into this one value, for the reason
// errFramedContentBadSignature's comment gives: a caller that could tell a wrong key from a
// wrong preimage from a tag of the wrong length learns which of its guesses was closest, and
// has no branch to take on any of the three other than rejecting the message.
var errBadMembershipTag = errors.New("mls: membership tag does not verify")

// ComputeMembershipTag is MAC(membership_key, AuthenticatedContentTBM), RFC 9420 section 6.2:
// the tag a member attaches to a PublicMessage to say that it came from inside the group.
//
// The key is membership_key and NOT confirmation_key. The two are adjacent DeriveSecret calls
// over one epoch secret, so they are the same length and indistinguishable from random, and a
// swap produces a perfectly well formed tag that this implementation would also accept back
// from itself -- there is no input to this function that separates them. What separates them is
// the membership_tag mlswg published in message-protection.json, which
// TestTheMembershipTagPreimageIsTheOneThePublishedTagsWereTakenOver compares against.
//
// The preimage is AuthenticatedContentTBMBytes' and is not rebuilt here, so everything that
// function's comment says about the wire format, the auth data and the group context is the
// property of this tag too.
//
// The provider is checked before anything else is read, which is SignAuthenticatedContent's
// discipline: a body that built its preimage first would answer ErrUnknownSenderType or
// ErrMissingGroupContext to a caller whose actual mistake was passing no provider.
//
// THE KEY IS REFUSED TWICE before any of it is macced, and both refusals are about a key that
// is publicly known rather than about tidiness. A membership_key that is not KDF.Nh bytes is
// ErrSecretLength, which is what the nine other raw secret parameters of this package answer
// for the reason that sentinel gives: a short key macs perfectly and produces a tag no peer
// agrees with, and the mistake surfaces later as an unauthenticated message rather than as the
// length it was. A membership_key that is KDF.Nh ZERO bytes is ErrEpochErased, and that one is
// the forgery: an epoch leaving PastEpochWindow is zeroized IN PLACE, so the erase leaves the
// header exactly as it was and no length check can see it, and an HMAC under a run of zeros is
// not a weak tag but a PUBLIC one that any party computes with no knowledge of the group. It
// would come back with err == nil.
//
// p4's (*KeySchedule).MembershipTag refuses exactly that key through secretIsLive, and section
// 6.2 has these two doors into it. A guard on one door only is a guard on whichever door the
// caller happened to pick, which is how this was found: p6's door accepted the erased key, a
// nil key and a five byte key, and answered a tag for each.
//
// The zero test is crypto/subtle.ConstantTimeCompare against a run of zeros rather than a loop
// that stops at the first non zero byte, for secretIsLive's reason: the whole key is read
// whatever the first byte holds, so an erased epoch's refusal takes the same time as a live
// epoch's answer and nothing about this epoch's own key is readable from how long it ran.
func ComputeMembershipTag(crypto CryptoProvider, membershipKey []byte,
	authContent *AuthenticatedContent, groupContext []byte) ([]byte, error) {

	if crypto == nil {
		return nil, fmt.Errorf("%w: the tag is the provider's mac", ErrNilCryptoProvider)
	}
	if len(membershipKey) != crypto.HashSize() {
		return nil, fmt.Errorf("%w: membership key is %d bytes, want %d",
			ErrSecretLength, len(membershipKey), crypto.HashSize())
	}
	if subtle.ConstantTimeCompare(membershipKey, make([]byte, len(membershipKey))) == 1 {
		return nil, ErrEpochErased
	}
	tbm, err := AuthenticatedContentTBMBytes(authContent, groupContext)
	if err != nil {
		return nil, err
	}
	return crypto.Mac(membershipKey, tbm), nil
}

// verifyMembershipTag is ValSem007 and ValSem008: the membership_tag a PublicMessage carries is
// present, and it is the one this epoch's membership_key produces over the
// AuthenticatedContentTBM the RECEIVER reassembled.
//
// It answers an error and never a bool, and that is guardrail G7 rather than a house style. A
// false membership tag is FATAL TO THE MESSAGE: this is the only authentication a member's
// PublicMessage carries besides the signature, so a caller that logged the refusal and carried
// on would be applying a proposal or a commit that no member of the group sent. p7 is the
// caller -- it is where ValSem008 is raised on the receive path -- and the obligation it
// inherits is written here because this is the function it will reach:
//
//	p7 MUST RETURN on this refusal rather than logging it and continuing.
//
// The obligation is stated rather than only enforced because p7 has a second door into the same
// rule. (*KeySchedule).VerifyMembershipTag answers a BOOL, by design, since p4 owns the key
// schedule and never sees a framing type; a p7 that reaches for that one instead is handed the
// one result shape a caller can ignore by not looking at it, and this package has shipped three
// authentication bypasses whose common shape was exactly that. Whichever door p7 uses, a
// membership tag that does not verify ends the message.
//
// The comparison is CryptoProvider.MacVerify and nothing else, which is guardrail G8: it
// reaches crypto/subtle.ConstantTimeCompare, and it refuses a length mismatch AHEAD of the
// comparison rather than comparing as much of the tag as fits -- a prefix comparison accepts
// every truncation of a valid tag, which is a forgery an attacker finds in 256 tries.
// bytes.Equal, hmac.Equal and bytes.HasPrefix all answer the same bool here and none of them is
// this. What says there is no spelling of them that routes around the rule is
// TestNothingThisPackageShipsComparesDataOutsideConstantTime, in this package's own
// constant_time_test.go: it reads every file this package ships, this one included, against a
// class it DERIVES from the imports of that source, so those three are in it and so is every
// comparator of every package a later edit imports. No count is written here on purpose. The
// number this sentence used to give was the OTHER gate's -- message/writeauth_test.go scans its
// own directory and reports clean over a bytes.Equal planted in this file -- and a count is the
// half of a claim like this that goes stale in silence.
// TestTheMembershipTagCommentaryNamesGatesThatExistAndAClassThatHoldsItsSpellings is what keeps
// the two sentences above from being prose nobody measured. The bool MacVerify answers is
// converted in the same expression that produces it and never leaves this function.
//
// The KEY is refused ahead of the message, on both counts ComputeMembershipTag's comment
// states and for the reasons it gives. The ordering is that function's and the nil provider's:
// a receiver whose membership_key is the wrong width or has been erased has made a mistake
// about its OWN epoch, and a body that judged the message first would answer ValSem007 or the
// preimage's own refusal to a caller whose actual fault was the key -- sending it to look at a
// message that was never the problem. An erased key here is the whole rule failing open:
// HMAC-SHA256 under KDF.Nh zero bytes is publicly computable, so every tag an attacker cares to
// write verifies, and this is the only authentication a member's PublicMessage carries besides
// the signature.
//
// The absent tag is refused before the preimage is built, and the refusal is written on the
// LENGTH rather than on == nil, which is emptyByteSpellings' rule: a decoder that read an empty
// opaque<V> hands back a slice that is non nil and has capacity, and a guard spelled == nil
// accepts it. That input is a PublicMessage whose membership_tag field is present and empty --
// wire legal, and a message no member could have produced.
//
// That ORDERING is observed rather than only stated, by
// TestTheAbsentMembershipTagIsRefusedAheadOfEveryPreimageThatCannotBeBuilt. Moved below the
// AuthenticatedContentTBMBytes call this guard still refuses every tagless message whose
// preimage assembles, so what separates the two orders is only a message that is tagless AND
// unbuildable -- and every one of those answers ValSem007 here.
func verifyMembershipTag(crypto CryptoProvider, membershipKey []byte,
	authContent *AuthenticatedContent, groupContext []byte, tag []byte) error {

	if crypto == nil {
		return fmt.Errorf("%w: the comparison is the provider's", ErrNilCryptoProvider)
	}
	if len(membershipKey) != crypto.HashSize() {
		return fmt.Errorf("%w: membership key is %d bytes, want %d",
			ErrSecretLength, len(membershipKey), crypto.HashSize())
	}
	if subtle.ConstantTimeCompare(membershipKey, make([]byte, len(membershipKey))) == 1 {
		return ErrEpochErased
	}
	if len(tag) == 0 {
		return errMissingMembershipTag
	}
	tbm, err := AuthenticatedContentTBMBytes(authContent, groupContext)
	if err != nil {
		return err
	}
	if !crypto.MacVerify(membershipKey, tbm, tag) {
		return errBadMembershipTag
	}
	return nil
}
