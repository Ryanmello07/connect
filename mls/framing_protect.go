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

	"github.com/urnetwork/connect/mls/syntax"
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

// ---------------------------------------------------------------------------
// the PublicMessage, RFC 9420 section 6.2
// ---------------------------------------------------------------------------

// errApplicationMustBeCiphertext is ValSem005 in the validation plan's catalogue, and it is a
// stand in on exactly errMissingMembershipTag's terms: that plan owns the single declaration site
// for the exported ErrApplicationMustBeCiphertext, the name has not landed in this package yet,
// and TestNoValidationOwnedNameHasLandedBesideItsStandIn fails on the commit that lands the
// exported twin beside this one. When it lands, every return of it below becomes
// ValSem(ValSem005, ErrApplicationMustBeCiphertext).
//
// The rule it carries is RFC 9420's and not this product's, and the two are worth keeping apart
// because they refuse at different places for different reasons. ValSem005 says an APPLICATION
// message must never be sent in the clear: application data is the user's plaintext, a
// PublicMessage is authenticated and not encrypted, and a sender that framed one this way would
// put the message body on the transport with a signature attached. Spec A's A-ASSUME-4 goes
// further and refuses every PublicMessage at the group config, handshake messages included -- but
// that is a policy the group can in principle be configured out of, and this is a rule of the
// protocol that it cannot.
//
// BOTH directions raise it. A sender is stopped from building one, and a receiver refuses one a
// hostile peer built anyway -- which is the half that has to exist, because the sender's guard
// protects nobody from a peer that does not run this code.
var errApplicationMustBeCiphertext = errors.New("mls: an application message must be sent as a PrivateMessage")

// errUnexpectedMembershipTag is what an open answers a PublicMessage carrying a membership tag
// under a sender type RFC 9420 section 6.2 gives the field to nobody but a member.
//
// Refused rather than ignored, which is ErrUnexpectedGroupContext's rule one layer down and is
// here for that sentinel's reason exactly: a caller holding a message with a tag on it believes
// the tag was checked, and an open that read the sender type, skipped the tag and answered a
// verified object has told that caller its message carries two authenticators when it carries
// one. The tag on such a message can be checked against nothing -- an external sender has no
// leaf and a new member has not joined, so neither holds a membership_key any tag could have
// been taken under -- so there is no third option where it is verified instead.
//
// It is not reachable from the wire and that is not a reason to leave it out. PublicMessage's
// section 6.2 select reads the field off the member arm alone, so a peer cannot put one here;
// what can is this package's own caller, assembling a message in memory, which is the half of
// the class the codec's guard does not cover. It is its own value rather than
// errMissingMembershipTag because the two are opposite mistakes -- one message carries a tag
// nothing can check and the other is missing the one thing that says it came from inside the
// group -- and a caller told the wrong one is sent to fix the wrong field.
//
// Unexported rather than declared beside ErrUnexpectedGroupContext in framing_errors.go: that
// file is the interface registry's section 7.6 block, its ten names are joined to the registry
// by TestFramingErrorsAreDistinctAndNamed, and an eleventh added there would be this package
// helping itself to a name in a roster another plan owns.
var errUnexpectedMembershipTag = errors.New("mls: membership tag supplied for a sender type that forbids it")

// errNilPublicMessage is what OpenPublicMessage answers a caller that passed no message, for
// errNilAuthenticatedContent's reason: a nil dereference out of a library takes the caller's
// process rather than its call, and says nothing about which argument was wrong.
var errNilPublicMessage = errors.New("mls: open requires a public message")

// errNilSignatureKeyResolver is what an open answers a caller that passed no resolver.
//
// It is its own value rather than a resolver that answers no key, and the difference is the one
// this package keeps everywhere: "the caller passed nothing" is a caller's mistake, and "no key
// could be found for this sender" is a message's. Collapsing them would let a receive path whose
// resolver wiring was never hooked up report the same refusal as a message from a leaf that has
// been removed, and only one of those is worth retrying.
var errNilSignatureKeyResolver = errors.New("mls: open requires a signature key resolver")

// SignatureKeyResolver answers the signature public key of a message's sender.
//
// A key is resolved rather than supplied because of what section 6.3 does with the sender. A
// PrivateMessage hides it: the Sender lives inside the encrypted sender data, so nothing -- not
// the receiver, not the caller -- knows whose key to check until that data has been decrypted,
// which happens inside the open. A caller cannot choose the key in advance because at the moment
// it calls there is nothing to choose it by.
//
// Passing a resolver rather than a key is therefore what lets an open verify the signature ITSELF
// instead of handing back an unverified object and a sender for the caller to check later, which
// is guardrail G7. The two shapes differ in exactly one way and it is the way that matters: the
// second one is a caller that can forget. This package has shipped three authentication bypasses
// and every one of them was a caller handed something it could ignore.
//
// PublicMessage carries its sender in the clear and does not need the indirection. It takes one
// anyway so that both wire formats present one interface to p7's receive path: a receive path
// that took a key on one branch and a resolver on the other would have two shapes of the same
// question, and the branch that took the key is the one somebody eventually passes the wrong key
// to.
//
// A resolver that has no key for a sender says so by returning an error, and the open answers it
// verbatim. That refusal is not a signature failure -- there is nothing to verify against -- and
// the caller has a different thing to do about it.
type SignatureKeyResolver func(sender Sender) (SignaturePublicKey, error)

// StaticSignatureKey is a resolver that answers with one key whatever the sender says.
//
// For the published test vectors, which supply a single signature_pub and a single sender, and for
// two party tests. It is deliberately NOT what a group uses: a real receive path resolves the key
// out of the ratchet tree at the sender's own leaf, and a group that answered every sender with
// one key would accept any member's message as any other member's.
func StaticSignatureKey(pub SignaturePublicKey) SignatureKeyResolver {
	// the key is COPIED out of the caller's slice rather than captured, which is this package's
	// rule about caller bytes and has a sharper edge on a closure than it has anywhere else. A
	// captured slice is a window onto a buffer the caller still owns: a caller that reused it --
	// for the next member's key, say, while iterating a roster -- would silently change which key
	// every message this resolver is ever handed to is verified under, long after the call that
	// built it returned, and there is no moment at which that shows up as an error.
	answered := append(SignaturePublicKey(nil), pub...)
	return func(sender Sender) (SignaturePublicKey, error) {
		return answered, nil
	}
}

// SealPublicMessage wraps a signed AuthenticatedContent as a PublicMessage, computing the
// membership tag for a member sender. It is ValSem005 on the send path.
//
// It does NOT sign. The signature is SignAuthenticatedContent's and is already inside the
// authContent this is handed, which is what keeps the wire format binding honest: the wire format
// is inside the signature preimage, so a message signed as one format and sealed as another is a
// message whose signature verifies against neither. That is the ErrWireFormatMismatch below, and
// it is a refusal rather than a correction for the reason framedContentTBS refuses a group context
// it was not expecting -- a caller that re-stamped the field would be shipping a signature over a
// preimage the caller never built.
//
// The provider is checked before anything else is read, which is SignAuthenticatedContent's
// discipline: a body that judged its message first would answer ValSem005 or
// ErrWireFormatMismatch to a caller whose actual mistake was passing no provider, and send it to
// fix a message that was never the problem. It is checked even on the path that never reaches the
// provider -- an external sender takes no membership tag -- because "does this call need a
// provider" is not a question a caller can answer before it makes the call.
//
// ValSem005 stands ahead of the wire format check, and the order is stated because both refusals
// are reachable at once -- an application message signed under some other wire format fails both
// -- and because nothing but this sentence and a test said which one answers. It is the receive
// path's order: OpenPublicMessage refuses ValSem005 ahead of everything it does, so a caller that
// frames an application message in the clear is told the same rule by its own send path that
// every peer would tell it, rather than being sent to fix a wire format and then told about the
// content type on the next call. TestSealPublicMessageRefusesApplicationContentAheadOfEveryWireFormatMismatch
// is what holds the order to that, over the wire format registry rather than over one row.
//
// The membership tag is computed for a MEMBER sender and for no other, which is RFC 9420 section
// 6.2's select and not an optimisation. The tag says "the sender was inside the group", and the
// three other sender types are by definition not: an external sender has no leaf and no
// membership_key, and a new member has not joined yet. A tag attached to one of those would be a
// claim nothing could verify, and section 6.2 gives the field no place on the wire.
func SealPublicMessage(crypto CryptoProvider, membershipKey []byte,
	authContent *AuthenticatedContent, groupContext []byte) (*PublicMessage, error) {

	if crypto == nil {
		return nil, fmt.Errorf("%w: the membership tag is the provider's mac", ErrNilCryptoProvider)
	}
	if authContent == nil {
		return nil, errNilAuthenticatedContent
	}
	if authContent.Content.ContentType == ContentTypeApplication {
		return nil, errApplicationMustBeCiphertext
	}
	if authContent.WireFormat != WireFormatPublicMessage {
		return nil, ErrWireFormatMismatch
	}
	message := &PublicMessage{Content: authContent.Content, Auth: authContent.Auth}
	if authContent.Content.Sender.SenderType == SenderTypeMember {
		tag, err := ComputeMembershipTag(crypto, membershipKey, authContent, groupContext)
		if err != nil {
			return nil, err
		}
		message.MembershipTag = tag
	}
	return message, nil
}

// OpenPublicMessage is the receive half: ValSem005, then ValSem007 and ValSem008, then ValSem010
// and ValSem009. It answers the AuthenticatedContent only once every one of them has passed.
//
// It answers a verified object and never an object plus a verdict, which is guardrail G7 and the
// reason this signature has no bool in it. Both authenticators are checked here, so a caller
// holding the answer is holding a message that came from inside the group AND from the leaf it
// names. A shape that handed back the content and left either check to the caller would be a
// caller that can forget, and this package has shipped three bypasses of exactly that shape.
//
// The APPLICATION refusal comes first, before either authenticator, and the order is deliberate.
// ValSem005 is a fact about the message's own framing that needs no key to see: an application
// message in a PublicMessage is one no conforming sender produces, so there is no reason to spend
// a MAC and a signature verification on it, and no reason to let a peer learn whether this
// receiver holds the epoch by how long the refusal took.
//
// The membership tag is checked BEFORE the signature, which is RFC 9420 section 6.2's order and
// worth stating because the reverse also "works". The membership tag is the cheaper check and it
// is the one that says the message came from inside the group at all; a receiver that verified the
// signature first would be doing public key work on behalf of any party that can reach the
// transport.
//
// Both of those orderings are OBSERVED and not merely stated, which they were not for a while.
// TestOpenPublicMessageRefusesInTheOrderSectionSixTwoRequires builds a message that breaks
// several of these rules at once and asserts which refusal answers, and it counts what the
// provider was asked to do before the refusal came back -- so "no public key work on behalf of
// the transport" is read off the verifications that ran rather than off the error alone. Every
// ordering here survived the whole suite as a reversal before that gate existed.
//
// The tag is checked only for a MEMBER sender, for SealPublicMessage's reason: no other sender
// type has a membership_key, and section 6.2 gives none of them the field. It is not a hole a peer
// can walk through by claiming to be external -- the sender type is inside the signature preimage,
// so a member's message re-labelled external does not verify, and the sender type also decides
// whether the group context is bound into that preimage at all.
//
// A tag carried by one of the other three is REFUSED rather than passed over, which is the arm
// this select used to have no answer for: it read the sender type, took the no-tag branch, and
// left message.MembershipTag read by nothing and refused by nothing. errUnexpectedMembershipTag
// says why that is not a nicety.
//
// The refusal of the tag travels out verbatim and is never collapsed into the signature's, which
// is what keeps ValSem007 and ValSem008 distinguishable to a validator that has to say which of
// its rules refused. What an unauthenticated peer must not learn is which of ValSem010 and
// ValSem009 it failed, and VerifyAuthenticatedContent's own ordering is what handles that.
func OpenPublicMessage(crypto CryptoProvider, membershipKey []byte, message *PublicMessage,
	resolve SignatureKeyResolver, groupContext []byte) (*AuthenticatedContent, error) {

	if crypto == nil {
		return nil, fmt.Errorf("%w: both authenticators are the provider's", ErrNilCryptoProvider)
	}
	if message == nil {
		return nil, errNilPublicMessage
	}
	if resolve == nil {
		return nil, errNilSignatureKeyResolver
	}
	if message.Content.ContentType == ContentTypeApplication {
		return nil, errApplicationMustBeCiphertext
	}
	authContent := message.AuthenticatedContent()
	if message.Content.Sender.SenderType == SenderTypeMember {
		err := verifyMembershipTag(crypto, membershipKey, authContent, groupContext, message.MembershipTag)
		if err != nil {
			return nil, err
		}
	} else if len(message.MembershipTag) != 0 {
		// the other half of section 6.2's select, and it is a refusal for the reason
		// errUnexpectedMembershipTag gives. The guard is spelled on the LENGTH and not on
		// != nil, which is emptyByteSpellings' rule: a decoder hands back a non nil slice
		// for an empty opaque<V> and a caller can re-slice one to nothing, and neither of
		// those is a tag anybody attached.
		return nil, errUnexpectedMembershipTag
	}
	pub, err := resolve(message.Content.Sender)
	if err != nil {
		return nil, err
	}
	if err := VerifyAuthenticatedContent(crypto, pub, authContent, groupContext); err != nil {
		return nil, err
	}
	return authContent, nil
}

// ---------------------------------------------------------------------------
// the sender data, RFC 9420 section 6.3.2
// ---------------------------------------------------------------------------

// errDecryptFailed is ValSem006 in the validation plan's catalogue, and it is a stand in on
// errApplicationMustBeCiphertext's terms exactly: that plan owns the single declaration site for
// the exported ErrDecryptFailed, the name has not landed in this package yet, and
// TestNoValidationOwnedNameHasLandedBesideItsStandIn fails on the commit that lands the exported
// twin beside this one. When it lands, every return of it below becomes ValSem(ValSem006,
// ErrDecryptFailed).
//
// It is ONE value for the whole of "this message does not decrypt", and that is the rule rather
// than a shortcut. p2's ErrAeadOpen never escapes this layer: a caller that could tell a wrong
// key from a wrong nonce from a tampered ciphertext from an associated data it disagreed about
// learns which of its guesses was closest, which is a decryption oracle offered to whoever can
// reach the transport -- and a receiver has no branch to take on any of the four other than
// dropping the message. The sender data half and the content half of section 6.3 answer the same
// value for the same reason: which of the two AEAD opens failed is itself a fact about the key
// schedule that an unauthenticated peer must not be able to read off a refusal.
var errDecryptFailed = errors.New("mls: message does not decrypt")

// errNilSenderData is what a seal answers a caller that passed no sender data, for
// errNilAuthenticatedContent's reason: a nil dereference out of a library takes the caller's
// process rather than its call, and says nothing about which argument was wrong.
var errNilSenderData = errors.New("mls: seal requires sender data")

// errNilPrivateMessage is what section 6.3's operations answer a caller that passed no header.
//
// The header is not decoration to these two: its group_id, epoch and content_type ARE the
// associated data, so a nil one is not a missing option but a missing third of the input, and
// there is no default header that could stand in for it without producing an AEAD nobody else can
// open.
var errNilPrivateMessage = errors.New("mls: the section 6.3 operations require the message header")

// sealSenderData encrypts a SenderData under RFC 9420 section 6.3.2, keyed off the content
// ciphertext it will travel beside.
//
// The KEY IS DERIVED FROM THE CIPHERTEXT, which is the one thing about this operation worth
// understanding before reading it. sender_data_secret does not ratchet: every member holds the
// same one for the whole epoch, so sealing every header under it directly would be one key and
// one nonce over every message anybody sends in that epoch, which is a reused keystream. Section
// 6.3.2 fixes that by sampling the content ciphertext into the expansion, so each message's
// header is sealed under its own key -- and it is why this function takes the ciphertext at all
// when it is not the thing being encrypted.
//
// The derivation itself is NOT here. It is SenderDataKeyNonce, in secret_tree.go, which is the
// copy mlswg's secret-tree.json covers; the private one that used to sit in this file was the
// untested duplicate of a construction whose two failure modes -- a sample of the wrong length,
// and a short ciphertext padded rather than used whole -- both produce a perfectly well formed key
// that simply interoperates with nobody. Two copies of that is two chances to get it wrong and one
// vector set. framing_protect_test.go holds the sample rule from this side anyway, because this is
// the caller that ships broken if that derivation ever drifts.
//
// The AAD is senderDataAAD's and covers group_id, epoch and content_type and NOT
// authenticated_data, which is section 6.3.2's structure and is load bearing in an
// order-of-operations way: the sender data is opened FIRST, because it is what names the leaf
// whose ratchet holds the content key, so an AAD here that reached into the content step would
// leave a receiver with no order in which it could do the two.
//
// The provider is checked before anything else is read, which is SignAuthenticatedContent's
// discipline: a body that marshalled its sender data first would answer a codec error to a caller
// whose actual mistake was passing no provider.
func sealSenderData(crypto CryptoProvider, senderDataSecret []byte, senderData *SenderData,
	header *PrivateMessage, ciphertext []byte) ([]byte, error) {

	if crypto == nil {
		return nil, fmt.Errorf("%w: the sender data key and nonce are two expansions through it", ErrNilCryptoProvider)
	}
	if senderData == nil {
		return nil, errNilSenderData
	}
	if header == nil {
		return nil, errNilPrivateMessage
	}
	plaintext, err := syntax.Marshal(senderData)
	if err != nil {
		return nil, err
	}
	aad, err := senderDataAAD(header.GroupId, header.Epoch, header.ContentType)
	if err != nil {
		return nil, err
	}
	key, nonce, err := SenderDataKeyNonce(crypto, senderDataSecret, ciphertext)
	if err != nil {
		return nil, err
	}
	return crypto.AeadSeal(key, nonce, aad, plaintext)
}

// openSenderData is the receive half, and it is ValSem006.
//
// It is handed the CIPHERTEXT as well as the encrypted header because the ciphertext is what keys
// this open, per sealSenderData's note. That makes the content ciphertext authenticated by this
// step as well as by its own: a peer that rewrote a single octet of it derives a different sender
// data key here, so the header stops opening -- which is why the two byte slice arguments are not
// interchangeable, and why a caller that passed the wrong one sees a decryption failure rather
// than a length error.
//
// Every failure of the AEAD collapses into errDecryptFailed, for the reason that sentinel's
// comment gives. What does NOT collapse into it is a plaintext that opened and then failed to
// decode: reaching that point required a valid AEAD tag, so it is a fact about a peer that holds
// this epoch's secrets and sent a malformed structure, and not about an attacker probing. There is
// no oracle in telling the two apart, and collapsing them would send an operator looking for a key
// mismatch when what happened is a peer's codec.
//
// syntax.Unmarshal and not a bare UnmarshalMLS over a Reader, which is the difference between "the
// sender data decoded" and "the plaintext WAS a sender data". Unmarshal joins the decoder's answer
// with Done, so a plaintext carrying twelve good octets and a tail is refused. Without that check
// this open accepts an unbounded family of encodings of one header, and a receiver that accepts
// two encodings of one object while the protocol signs and macs over serialized forms is the shape
// a malleability bug is built out of.
func openSenderData(crypto CryptoProvider, senderDataSecret []byte, encryptedSenderData []byte,
	header *PrivateMessage, ciphertext []byte) (*SenderData, error) {

	if crypto == nil {
		return nil, fmt.Errorf("%w: the sender data key and nonce are two expansions through it", ErrNilCryptoProvider)
	}
	if header == nil {
		return nil, errNilPrivateMessage
	}
	aad, err := senderDataAAD(header.GroupId, header.Epoch, header.ContentType)
	if err != nil {
		return nil, err
	}
	key, nonce, err := SenderDataKeyNonce(crypto, senderDataSecret, ciphertext)
	if err != nil {
		return nil, err
	}
	plaintext, err := crypto.AeadOpen(key, nonce, aad, encryptedSenderData)
	if err != nil {
		// p2's ErrAeadOpen never escapes: every open failure on this path is ValSem006, and
		// distinguishing them would be a decryption oracle.
		return nil, errDecryptFailed
	}
	senderData := &SenderData{}
	if err := syntax.Unmarshal(plaintext, senderData); err != nil {
		return nil, err
	}
	return senderData, nil
}

// ---------------------------------------------------------------------------
// PrivateMessageContent and its padding, RFC 9420 section 6.3.1
// ---------------------------------------------------------------------------

// PaddingSizeV1 is the MLS level padding this product emits, and it is ZERO.
//
// connect/message already pads ct_body to a size bucket -- MASTER section 8 requires
// octet_length(ct_body) to equal size_bucket_bytes[b]+16 exactly -- so padding here would be
// padding inside padding: it cannot narrow a bucket that has already been rounded up, and every
// octet of it pushes a message that was sitting under a bucket boundary up onto the next rung of a
// ladder MASTER deliberately did not renumber. Two padding schemes stacked also make the OUTER one
// the only one an observer sees, so the inner one buys nothing an attacker on the wire can be
// denied by it.
//
// The DECODER is deliberately more permissive than this constant. Any all-zero padding length is
// accepted, because peers in the interop harness emit their own padding and a receiver that
// refused it would fail the harness against implementations doing nothing wrong.
const PaddingSizeV1 = 0

// errNonZeroPadding is ValSem011 in the validation plan catalogue, and it is a stand in on
// errDecryptFailed terms exactly: that plan owns the single declaration site for the exported
// ErrNonZeroPadding, the name has not landed in this package yet, and
// TestNoValidationOwnedNameHasLandedBesideItsStandIn fails on the commit that lands the exported
// twin beside this one. When it lands, the return below becomes ValSem(ValSem011,
// ErrNonZeroPadding).
//
// It names NO position and NO count, and that is the rule rather than terseness. The padding is
// the tail of a plaintext an attacker would like to learn about a byte at a time, and a refusal
// that said "byte 9 of 16 is non zero" is a decoder that answers, for each position, whether the
// bytes before it were zero -- which is the padding oracle every one of this class of bugs has
// been. The check that raises it accumulates over the WHOLE tail rather than stopping at the first
// offending octet, so the position is absent from the timing as well as from the words.
var errNonZeroPadding = errors.New("mls: private message padding is not all zero")

// marshalPrivateMessageContentWithPadding serializes RFC 9420 section 6.3.1
// PrivateMessageContent: the content arm the type selects, the auth data, and then the caller
// supplied padding octets.
//
// It takes the padding as OCTETS rather than as a count, and that is why there is one serializer
// here rather than the two the plan drafts. The count form has no production caller -- every
// production path arrives with bytes already, because SealPrivateMessage builds them from
// PaddingSizeV1 and hands them down -- and this package refuses a production declaration nothing
// in production names. The count form the plan pins is a thing the TESTS want, so it lives beside
// them, in framing_protect_test.go, with the same signature and the same refusal for a negative
// size. The refusal that a caller can actually reach is SealPrivateMessage's, which is where a
// padding size enters this package at all.
//
// Caller supplied so that a test can emit the NON ZERO padding ValSem011 is about. Nothing on the
// production path can reach a non-zero tail, so the property has no producer inside this package
// and would otherwise have to be forged by hand-assembling a plaintext -- which tests a
// hand-assembled encoder rather than this one.
//
// The padding carries NO length prefix of its own. It is whatever remains after the content arm
// and the auth data, which is why the decoder below reads to the end rather than asserting full
// consumption.
func marshalPrivateMessageContentWithPadding(content *FramedContent,
	auth *FramedContentAuthData, padding []byte) ([]byte, error) {

	if err := content.checkArms(); err != nil {
		return nil, err
	}
	w := syntax.NewWriter()
	switch content.ContentType {
	case ContentTypeApplication:
		w.WriteOpaque(content.ApplicationData)
	case ContentTypeProposal:
		if err := content.Proposal.MarshalMLS(w); err != nil {
			return nil, err
		}
	case ContentTypeCommit:
		if err := content.Commit.MarshalMLS(w); err != nil {
			return nil, err
		}
	default:
		// unreachable through checkArms, which refuses every unregistered content type ahead
		// of this switch. It is written anyway because the two would otherwise agree only by
		// inspection, and a later task that loosened checkArms would silently produce a
		// plaintext with no content arm in it at all.
		return nil, fmt.Errorf("%w: %d", ErrUnknownContentType, content.ContentType)
	}
	if err := auth.MarshalMLS(w, content.ContentType); err != nil {
		return nil, err
	}
	w.WriteRaw(padding)
	return w.Bytes()
}

// unmarshalPrivateMessageContent rebuilds the FramedContent from the cleartext header plus the
// decrypted body, and enforces ValSem011 over the tail.
//
// The sender comes from the SENDER DATA and not from the plaintext, and the group id, epoch,
// content type and authenticated data come from the header: RFC 9420 section 6.3.1 does not carry
// any of the five inside the encrypted body, so this reassembles rather than decodes them. That is
// why a caller cannot skip the sender data step and open the content first -- there would be no
// leaf index to build the content sender out of, and no ratchet to find the key in.
//
// The padding check is a REFUSAL and it accumulates. Both halves matter. The RFC requires the
// padding be all zero, and a decoder that simply stopped reading at the end of the auth data would
// hand an attacker who can write to the plaintext -- which is to say, any member of the group -- a
// covert channel of unbounded width inside every message, invisible to every signature because the
// padding is inside the AEAD but outside the FramedContent that gets signed. And the accumulation
// is what keeps the refusal from naming which octet offended: an early return would answer the
// same sentinel but would answer it sooner for a non-zero byte at position 0 than at position 15,
// which is the position leaked back through timing.
func unmarshalPrivateMessageContent(plaintext []byte, header *PrivateMessage,
	sender Sender) (*FramedContent, *FramedContentAuthData, error) {

	if header == nil {
		return nil, nil, errNilPrivateMessage
	}
	content := &FramedContent{
		GroupId:           header.GroupId,
		Epoch:             header.Epoch,
		Sender:            sender,
		AuthenticatedData: header.AuthenticatedData,
		ContentType:       header.ContentType,
	}
	r := syntax.NewReader(plaintext)
	switch header.ContentType {
	case ContentTypeApplication:
		applicationData, err := r.ReadOpaque()
		if err != nil {
			return nil, nil, err
		}
		content.ApplicationData = applicationData
	case ContentTypeProposal:
		content.Proposal = &Proposal{}
		if err := content.Proposal.UnmarshalMLS(r); err != nil {
			return nil, nil, err
		}
	case ContentTypeCommit:
		content.Commit = &Commit{}
		if err := content.Commit.UnmarshalMLS(r); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("%w: %d", ErrUnknownContentType, header.ContentType)
	}

	auth := &FramedContentAuthData{}
	if err := auth.UnmarshalMLS(r, header.ContentType); err != nil {
		return nil, nil, err
	}

	// everything left is padding. ReadRaw(Remaining()) consumes it explicitly because this
	// package Reader has no Rest, and the whole tail is read before anything is decided about
	// it so that the amount consumed does not vary with where the first non-zero octet sits.
	padding, err := r.ReadRaw(r.Remaining())
	if err != nil {
		return nil, nil, err
	}
	var accumulated byte
	for _, b := range padding {
		accumulated |= b
	}
	if accumulated != 0 {
		return nil, nil, errNonZeroPadding
	}
	return content, auth, nil
}

// ---------------------------------------------------------------------------
// the message keys and PrivateMessage, RFC 9420 section 6.3.1 and section 9
// ---------------------------------------------------------------------------

// MessageKeySource is the per sender ratchet surface of RFC 9420 section 9 as the framing layer
// needs it: ContentTypeApplication selects the application ratchet and proposal and commit select
// the handshake one, and this layer does not have to know that.
//
// The secret tree implements it and OWNS everything stateful about it -- the skipped key window,
// the retained key bound, the generation counter and its refusal to wrap. Framing holds no key
// beyond the call it was handed in, which is why there is no method here for giving one back.
//
// The three methods are not interchangeable and the split is deliberate. NextMessageKey CONSUMES,
// because a sender that dropped an answer must not be able to ask for the same generation twice.
// MessageKey does NOT, because a receiver has to look a generation up, open the AEAD, and only
// then say the key is spent -- a lookup that consumed would burn the real message key on the first
// forged packet anyone on the network cared to send. EraseMessageKey is that second half, and it
// is total: it is called on paths that never derived a key at all.
type MessageKeySource interface {
	NextMessageKey(contentType ContentType, leaf LeafIndex) (key []byte, nonce []byte, generation uint32, err error)
	MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key []byte, nonce []byte, err error)
	EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)
}

// The secret tree is the production implementation, asserted here rather than described.
//
// This line is the whole contract between the framing plan and the secret tree plan. The two were
// written against each other prose -- one declares the interface, the other declares the methods
// -- and prose is exactly what a signature drifts away from without anything failing: a leaf
// argument widened on one side, a generation returned as uint64 on the other, an argument order
// swapped. Every one of those compiles on its own side and is found, without this, by the message
// protection vector family several plans later.
var _ MessageKeySource = (*SecretTree)(nil)

// errNilMessageKeySource is what section 6.3.1 two operations answer a caller that passed no key
// source, for errNilAuthenticatedContent reason: a nil interface dereference out of a library
// takes the caller process rather than its call, and says nothing about which argument was wrong.
//
// It is refused rather than defaulted for a second reason this argument has and the others do not:
// there is no key source that could stand in for a missing one. A default would either derive
// message keys from nothing, which is a public key every party in the world can compute, or hand
// back the same key for every generation, which is the AEAD nonce reuse the whole of section 9 is
// built to prevent.
var errNilMessageKeySource = errors.New("mls: the section 6.3.1 operations require a message key source")

// applyReuseGuard is RFC 9420 section 6.3.1 reuse_guard: the sender draws four random octets per
// message and XORs them over the FIRST FOUR octets of the ratchet nonce.
//
// What it defends against is a sender whose ratchet state was rolled back -- restored from a
// backup, forked across two devices, resumed after a crash -- and which therefore hands out one
// generation twice. Without the guard that is the same key and the same nonce over two different
// plaintexts, which for a stream cipher AEAD is a total loss of confidentiality for both. With it
// the second message lands on a nonce 2^-32 likely to collide with the first.
//
// It returns a COPY, and that is not caution. The unguarded nonce is what every OTHER member of
// the group derives for this generation, and the guard is per message; writing the guarded value
// back over the ratchet own nonce would leave this sender holding a nonce nobody else computes, so
// every later message it opened at that generation would fail. The secret tree hands out copies
// for its own reasons -- see MessageKey -- and this function does not rely on that, because a
// source that handed out its storage and a guard that wrote through it are two defects that are
// only harmless together.
func applyReuseGuard(nonce []byte, reuseGuard [senderDataReuseGuardSize]byte) []byte {
	guarded := make([]byte, len(nonce))
	copy(guarded, nonce)
	for i := 0; i < len(reuseGuard) && i < len(guarded); i += 1 {
		guarded[i] ^= reuseGuard[i]
	}
	return guarded
}

// SealPrivateMessage encrypts a signed AuthenticatedContent as an RFC 9420 section 6.3
// PrivateMessage, emitting paddingSize octets of zero padding inside the ciphertext.
//
// This is the only place a padding SIZE enters this package, so it is where a negative one is
// refused. Refused rather than clamped: make([]byte, -1) panics, so a clamp is the difference
// between a caller's arithmetic error surfacing as this error and surfacing as a crash inside the
// runtime with this frame nowhere in the message.
func SealPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
	authContent *AuthenticatedContent, paddingSize int) (*PrivateMessage, error) {

	if crypto == nil {
		return nil, fmt.Errorf("%w: the content and the sender data are two AEAD seals through it", ErrNilCryptoProvider)
	}
	if paddingSize < 0 {
		return nil, ErrInvalidPaddingSize
	}
	return sealPrivateMessage(crypto, keys, senderDataSecret, authContent, make([]byte, paddingSize))
}

// sealPrivateMessage is the same seal with caller supplied padding octets, and it is the only copy
// of section 6.3.1 encrypt path: the exported entry point above delegates here.
//
// The CONTENT is encrypted first and the sender data second, which is the order section 6.3.2
// forces rather than a preference: the sender data key is derived from the content ciphertext, so
// the ciphertext has to exist before the header that names its generation can be sealed.
//
// The reuse guard is drawn BEFORE the generation is consumed. Both orders produce the same
// message, and the difference is only visible when the draw fails -- at which point the version
// that consumed first has burned a generation of this leaf ratchet on a message that was never
// built, and every receiver will class that generation as consumed forever after.
func sealPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
	authContent *AuthenticatedContent, padding []byte) (*PrivateMessage, error) {

	if crypto == nil {
		return nil, fmt.Errorf("%w: the content and the sender data are two AEAD seals through it", ErrNilCryptoProvider)
	}
	if keys == nil {
		return nil, errNilMessageKeySource
	}
	if authContent == nil {
		return nil, errNilAuthenticatedContent
	}
	if authContent.WireFormat != WireFormatPrivateMessage {
		return nil, ErrWireFormatMismatch
	}
	content := &authContent.Content
	// section 6.3.2 gives a PrivateMessage sender data a leaf_index and nothing else, so a non
	// member sender has no field on the wire to travel in and no ratchet to draw a key from. It
	// is refused here rather than encoded as leaf zero, which is a real member ratchet and
	// would be a message sealed under somebody else keys.
	if content.Sender.SenderType != SenderTypeMember {
		return nil, ErrSenderNotMember
	}

	plaintext, err := marshalPrivateMessageContentWithPadding(content, &authContent.Auth, padding)
	if err != nil {
		return nil, err
	}
	var reuseGuard [senderDataReuseGuardSize]byte
	copy(reuseGuard[:], crypto.Random(len(reuseGuard)))

	key, nonce, generation, err := keys.NextMessageKey(content.ContentType, content.Sender.LeafIndex)
	if err != nil {
		return nil, err
	}
	aad, err := privateContentAAD(content.GroupId, content.Epoch, content.ContentType,
		content.AuthenticatedData)
	if err != nil {
		return nil, err
	}
	ciphertext, err := crypto.AeadSeal(key, applyReuseGuard(nonce, reuseGuard), aad, plaintext)
	if err != nil {
		return nil, err
	}
	// forward secrecy: the generation this message was sealed under stops existing the moment
	// the message exists. It is erased on the SUCCESS path only -- a seal that failed produced
	// no ciphertext anybody could open, and erasing there would consume the generation while
	// leaving the caller with nothing to send.
	keys.EraseMessageKey(content.ContentType, content.Sender.LeafIndex, generation)

	message := &PrivateMessage{
		GroupId:           content.GroupId,
		Epoch:             content.Epoch,
		ContentType:       content.ContentType,
		AuthenticatedData: content.AuthenticatedData,
		Ciphertext:        ciphertext,
	}
	senderData := &SenderData{
		LeafIndex:  content.Sender.LeafIndex,
		Generation: generation,
		ReuseGuard: reuseGuard,
	}
	encryptedSenderData, err := sealSenderData(crypto, senderDataSecret, senderData, message, ciphertext)
	if err != nil {
		return nil, err
	}
	message.EncryptedSenderData = encryptedSenderData
	return message, nil
}

// OpenPrivateMessage decrypts a section 6.3 PrivateMessage and verifies the sender signature.
// ValSem006, ValSem010 and ValSem011 all come out of it.
//
// The signature is verified HERE rather than being left to the caller, and that is the structural
// reason this function exists at all rather than being a decrypt the group layer calls. Who signed
// a PrivateMessage is not knowable until the sender data has been opened -- the leaf index is
// inside it -- so a caller handed a decrypted AuthenticatedContent and told to go and verify it
// would be handed the sender out of a structure this function had already decided to trust.
//
// The order is section 6.3 and is not interchangeable: sender data, then content, then signature.
// The sender data names the ratchet the content key is in, and the content carries the signature.
// Every AEAD failure on either of the first two collapses into one value, for errDecryptFailed
// reason; the erase happens between the second and the third, because a message whose AEAD opened
// came from somebody holding this epoch keys, and holding the key open across a signature check
// would leave a replay of the same ciphertext decryptable a second time.
func OpenPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
	message *PrivateMessage, resolve SignatureKeyResolver, groupContext []byte) (*AuthenticatedContent, error) {

	if crypto == nil {
		return nil, fmt.Errorf("%w: the sender data and the content are two AEAD opens through it", ErrNilCryptoProvider)
	}
	if keys == nil {
		return nil, errNilMessageKeySource
	}
	if message == nil {
		return nil, errNilPrivateMessage
	}
	if resolve == nil {
		return nil, errNilSignatureKeyResolver
	}

	senderData, err := openSenderData(crypto, senderDataSecret, message.EncryptedSenderData,
		message, message.Ciphertext)
	if err != nil {
		return nil, err
	}
	sender := Sender{SenderType: SenderTypeMember, LeafIndex: senderData.LeafIndex}

	// a refusal here is a fact about the ratchet -- consumed, too far ahead, erased epoch --
	// and it is answered VERBATIM rather than being folded into errDecryptFailed. The two are
	// different statements: this one says the key never existed or no longer does, which is a
	// visible gap the product acts on, and ValSem006 says a key was found and the message did
	// not open under it. A re-derivation here instead of a refusal would be the worse of the two
	// available bugs, because a generation the tree has already handed out is one an attacker
	// can replay.
	key, nonce, err := keys.MessageKey(message.ContentType, senderData.LeafIndex, senderData.Generation)
	if err != nil {
		return nil, err
	}
	aad, err := privateContentAAD(message.GroupId, message.Epoch, message.ContentType,
		message.AuthenticatedData)
	if err != nil {
		return nil, err
	}
	plaintext, err := crypto.AeadOpen(key, applyReuseGuard(nonce, senderData.ReuseGuard),
		aad, message.Ciphertext)
	if err != nil {
		// p2 ErrAeadOpen never escapes: every open failure on this path is ValSem006, and
		// distinguishing them would be a decryption oracle.
		return nil, errDecryptFailed
	}
	keys.EraseMessageKey(message.ContentType, senderData.LeafIndex, senderData.Generation)

	content, auth, err := unmarshalPrivateMessageContent(plaintext, message, sender)
	if err != nil {
		return nil, err
	}
	authContent := &AuthenticatedContent{
		WireFormat: WireFormatPrivateMessage,
		Content:    *content,
		Auth:       *auth,
	}
	pub, err := resolve(sender)
	if err != nil {
		return nil, err
	}
	if err := VerifyAuthenticatedContent(crypto, pub, authContent, groupContext); err != nil {
		return nil, err
	}
	return authContent, nil
}

// ---------------------------------------------------------------------------
// the context and the sender leaf, RFC 9420 section 6
// ---------------------------------------------------------------------------

// errWrongGroupId is ValSem002 in the validation plan's catalogue, and it is a stand in on
// errApplicationMustBeCiphertext's terms exactly: that plan owns the single declaration site for
// the exported ErrWrongGroupId, the name has not landed in this package yet, and
// TestNoValidationOwnedNameHasLandedBesideItsStandIn fails on the commit that lands the exported
// twin beside this one. When it lands, the return below becomes ValSem(ValSem002, ErrWrongGroupId).
var errWrongGroupId = errors.New("mls: framed content names another group")

// errWrongEpoch is ValSem003, on the same terms.
//
// It is its OWN value rather than a second spelling of errWrongGroupId, and the separation is the
// rule rather than a nicety. A message naming another group is one a receiver drops and never
// thinks about again. A message naming another epoch of THIS group is one a receiver may have to
// keep: delivery across a commit reorders, and the epoch that can open the message is one this
// member either had a moment ago or is about to have. A caller handed one value for both would
// either buffer traffic addressed to strangers or discard its own group's.
var errWrongEpoch = errors.New("mls: framed content names another epoch")

// errBlankSenderLeaf is ValSem004, on the same terms.
var errBlankSenderLeaf = errors.New("mls: the sender's leaf is blank")

// errNilLeafOccupancyTest is what CheckSenderLeaf answers a caller that passed no occupancy
// predicate, for errNilSignatureKeyResolver's reason: the predicate is a func rather than a
// pointer and is refused on the same ground, that calling it would take the caller's process
// rather than its call.
//
// It is refused AHEAD of the sender type rather than only on the branch that would call it. A
// rule that answered nil for a non member sender would tell a caller holding no occupancy test
// that its sender had been checked, and the caller cannot see the difference: nil is what a
// checked sender answers too.
var errNilLeafOccupancyTest = errors.New("mls: the sender leaf rule requires a leaf occupancy test")

// CheckFramedContentContext is ValSem002 and ValSem003: the group id and the epoch a FramedContent
// carries are this receiver's own, or the content belongs to another conversation.
//
// Both fields are inside the signature preimage, so a valid signature says only that SOME member
// of SOME group signed these bytes in SOME epoch. It is this rule that turns that into a statement
// about this group and this epoch, which is why it is a refusal a receive path cannot skip: a
// receiver that verified the signature and stopped would accept a member's message from epoch N
// as a message of epoch N+1, and every secret the message is judged under changes at a commit.
//
// The group id comparison reaches crypto/subtle.ConstantTimeCompare and not bytes.Equal. Not
// because a group id is a secret -- it travels in the clear on every PrivateMessage header -- but
// because guardrail 8 is stated over this package's whole source and one exception is how a gate
// stops being a gate. tree_sync.go compares the same field the same way for the same reason. The
// call also refuses a length mismatch by construction, which is the class a prefix comparison
// accepts.
//
// The group id is judged BEFORE the epoch, and the order is stated rather than left to the
// reader. An epoch number is a fact about a group, so a message from another group has no epoch
// this receiver can compare against, and a body that answered ValSem003 for it would tell its
// caller that a stranger's message was one of this group's own that had arrived late.
func CheckFramedContentContext(content *FramedContent, groupId []byte, epoch uint64) error {
	if content == nil {
		return errNilFramedContent
	}
	if subtle.ConstantTimeCompare(content.GroupId, groupId) != 1 {
		return errWrongGroupId
	}
	if content.Epoch != epoch {
		return fmt.Errorf("%w: the content names epoch %d and this is epoch %d",
			errWrongEpoch, content.Epoch, epoch)
	}
	return nil
}

// CheckSenderLeaf is ValSem004: a member sender names a leaf the ratchet tree actually holds a
// member at, and not one that was blanked by a removal or never filled.
//
// It takes a PREDICATE rather than a tree, which is the interface registry's signature and is
// what keeps this layer free of tree types. Framing is the layer below the group, so a framing
// rule that took a *RatchetTree would make every framing test build one, and the group lifecycle
// is what owns the tree -- it passes its own ratchet tree's occupancy test in, and the test here
// needs no group at all.
//
// The refusal names the leaf. A blank sender leaf is a fact about the tree and not about a
// secret: the tree's occupancy is public to every member, and a receiver told only that some
// leaf was blank has to walk its own tree to find out which message it just dropped.
func CheckSenderLeaf(sender Sender, leafOccupied func(LeafIndex) bool) error {
	if leafOccupied == nil {
		return errNilLeafOccupancyTest
	}
	// only a member sender carries a leaf index at all. RFC 9420 section 6's other three sender
	// types select the sender_index or select nothing, so a rule that ran the occupancy test over
	// their zero valued LeafIndex would answer about a field the message never carried -- refusing
	// an external proposal whenever leaf 0 happened to be blank, and passing one whenever it was
	// not.
	if sender.SenderType != SenderTypeMember {
		return nil
	}
	if !leafOccupied(sender.LeafIndex) {
		return fmt.Errorf("%w: leaf %d", errBlankSenderLeaf, sender.LeafIndex)
	}
	return nil
}
