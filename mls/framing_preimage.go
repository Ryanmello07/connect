// The byte strings RFC 9420 section 6 authenticates or hashes. One structure and one function
// each, one file, no key material: an auditor reading this file sees every preimage in the
// implementation and nothing else.
//
// The isolation is the point. A preimage defect does not produce a wrong ANSWER -- every one of
// these produces a well formed hash or a well formed signature over whatever it was handed. It
// produces two groups: one that agrees with itself and diverges permanently from every peer that
// assembled the same structure differently, from the first commit where they disagree, with no
// recovery path that does not involve somebody noticing. A one file diff is what makes that
// reviewable.
//
// Each preimage is declared as the STRUCTURE the RFC writes it as, with the one codec convention
// C1 allows, rather than as a writer that lays the fields out by hand inside the function that
// hashes them. That is not tidiness. A hand laid preimage is a second encoder over fields that
// already have one, it agrees with the first until the day one of them changes, and no round
// trip property in this package can see the disagreement -- which is exactly the shape
// TestNoTypeOfThisPackageCarriesAByteLevelCodecOfItsOwn exists to refuse.
package mls

import (
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// confirmedTranscriptHashInput is RFC 9420 section 8.2's structure of that name:
//
//	struct {
//	    WireFormat wire_format;
//	    FramedContent content; /* with content_type == commit */
//	    opaque signature<V>;
//	} ConfirmedTranscriptHashInput;
//
// It is unexported because nothing outside this package needs the structure -- p4's transcript
// chain takes the serialized BYTES, which is the interface registry's boundary and what keeps
// framing types out of transcript.go. What it needs to BE is a type with a codec, so that the
// preimage is written by one encoder rather than by a second hand rolled layout of fields
// AuthenticatedContent already knows how to write.
//
// It carries the signature but NOT the confirmation tag, and that omission is the whole design
// of section 8.2: the tag is a MAC over the confirmed transcript hash, so a confirmed hash that
// covered the tag could not be computed before the tag it needs. Dropping the signature instead,
// or keeping the tag as well, each produces a chain that is self consistent and shared with
// nobody.
type confirmedTranscriptHashInput struct {
	WireFormat WireFormat
	Content    FramedContent
	Signature  []byte
}

// MarshalMLS refuses an unregistered wire format before it writes, for the reason
// AuthenticatedContent.MarshalMLS does: this is a hash preimage, and a preimage whose first
// field is a code point no registry declares is a transcript entry no peer can reproduce.
//
// The signature's length prefix is syntax's opaque<V> varint and NOT the record layer's fixed
// thirty two bit one. The two are never interchangeable and the substitution is invisible from
// inside a group: WriteOpaqueLP here produces a transcript that agrees with itself on both sides
// of every group running this code and with no other implementation in the world. transcript.go
// refuses the same substitution one layer up, for the same reason, and says so at length.
func (self *confirmedTranscriptHashInput) MarshalMLS(w *syntax.Writer) error {
	switch self.WireFormat {
	case WireFormatPublicMessage, WireFormatPrivateMessage, WireFormatWelcome,
		WireFormatGroupInfo, WireFormatKeyPackage:
	default:
		return fmt.Errorf("%w: %d", ErrUnknownWireFormat, self.WireFormat)
	}
	w.WriteUint16(uint16(self.WireFormat))
	if err := self.Content.MarshalMLS(w); err != nil {
		return err
	}
	w.WriteOpaque(self.Signature)
	return nil
}

// UnmarshalMLS is the direction nothing in production needs and the tests do: it is what lets
// the published transcript corpus be read back as the structure section 8.2 names, rather than
// as an offset somebody computed. A preimage that only encodes is a preimage no test can hold
// against bytes it did not produce.
func (self *confirmedTranscriptHashInput) UnmarshalMLS(r *syntax.Reader) error {
	wireFormat, err := r.ReadUint16()
	if err != nil {
		return err
	}
	decoded := confirmedTranscriptHashInput{WireFormat: WireFormat(wireFormat)}
	switch decoded.WireFormat {
	case WireFormatPublicMessage, WireFormatPrivateMessage, WireFormatWelcome,
		WireFormatGroupInfo, WireFormatKeyPackage:
	default:
		return fmt.Errorf("%w: %d", ErrUnknownWireFormat, decoded.WireFormat)
	}
	if err := decoded.Content.UnmarshalMLS(r); err != nil {
		return err
	}
	signature, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	decoded.Signature = signature
	*self = decoded
	return nil
}

var _ syntax.Codec = (*confirmedTranscriptHashInput)(nil)

// transcriptHashInput projects the section 8.2 structure out of the authenticated content the
// transcript is being advanced over.
//
// It answers the STRUCTURE rather than its bytes, which is what keeps the serialization in one
// place: the three fields are named here, the layout is named in MarshalMLS above, and nothing
// does both.
func (self *AuthenticatedContent) transcriptHashInput() *confirmedTranscriptHashInput {
	return &confirmedTranscriptHashInput{
		WireFormat: self.WireFormat,
		Content:    self.Content,
		Signature:  self.Auth.Signature,
	}
}

// ConfirmedTranscriptHashInput is the serialized section 8.2 input p4's ConfirmedTranscriptHash
// consumes: Hash(interim_transcript_hash_[n-1] || these bytes) is epoch n's confirmed hash.
//
// Only a commit has one. Section 8.2 chains the transcript over commits, so asking a proposal or
// an application message for an input is a caller error rather than an encoding this could
// produce, and it is refused rather than answered: a transcript that folded in a non-commit is a
// transcript no peer computes the same way, which is the fork the whole of this file exists to
// prevent.
//
// The transcript arithmetic itself is transcript.go's. It consumes these bytes and never sees a
// framing type.
func (self *AuthenticatedContent) ConfirmedTranscriptHashInput() ([]byte, error) {
	if self.Content.ContentType != ContentTypeCommit {
		return nil, fmt.Errorf("%w: transcript hash input requires a commit", ErrContentArmMismatch)
	}
	return syntax.Marshal(self.transcriptHashInput())
}

// ProposalRef is the HashReference a Commit uses to name a by-reference proposal, RFC 9420
// section 5.2.
//
// The hash is over the SERIALIZED AuthenticatedContent and not over the Proposal, so the ref
// covers the wire format, the sender, the epoch and the signature as well as the proposed
// change. Two members proposing the same removal therefore produce different refs, which is what
// stops one member's proposal being committed under another's name -- and a ref taken over the
// FramedContent instead, or over the Proposal, is stable, self consistent and wrong: a commit
// naming a proposal by a ref no peer computes the same way is a commit nobody can apply.
//
// The label and the hash are the crypto plan's MakeProposalRef, reached rather than reproduced.
// The label is the entire domain separation between a proposal reference and a key package
// reference, and a second spelling of it here would be a second opinion about which of the two a
// given digest is.
func (self *AuthenticatedContent) ProposalRef(crypto CryptoProvider) (ProposalRef, error) {
	// the provider first, before the receiver is judged. A body that checked the content type
	// first would answer ErrContentArmMismatch to a caller whose actual mistake was passing no
	// provider, and send it to fix a message that was never the problem.
	if crypto == nil {
		return nil, fmt.Errorf("%w: the reference is a hash and the hash is the provider's", ErrNilCryptoProvider)
	}
	if self.Content.ContentType != ContentTypeProposal {
		return nil, fmt.Errorf("%w: a proposal ref requires a proposal", ErrContentArmMismatch)
	}
	encoded, err := syntax.Marshal(self)
	if err != nil {
		return nil, err
	}
	return ProposalRef(MakeProposalRef(crypto, encoded)), nil
}
