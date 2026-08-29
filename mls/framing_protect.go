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
// Every failure answers errFramedContentBadSignature and nothing narrower, for the reason
// that value's own comment gives.
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
