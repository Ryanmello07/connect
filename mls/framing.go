// RFC 9420 section 6 message framing wire types and their codecs.
//
// No crypto lives here. The signed and MACed byte strings are framing_preimage.go and the
// sealing operations are framing_protect.go, so a preimage change stays a one file diff an
// auditor can read. ProtocolVersion and ProtocolVersionMls10 are extension.go's, because the
// interface registry gives every IANA registry enum to the plan that first needed one and
// package mls is one package.
//
// ContentType arrived here by a different route and the route is worth stating, because it is
// the second half of an arrangement the key schedule's own files describe. The secret tree
// implements the MessageKeySource interface this plan declares, that interface is keyed on
// ContentType, and the secret tree landed first -- so ContentType was declared in
// content_type.go, on this plan's behalf, at the signature the interface registry gives it,
// with the standing agreement that this plan's own landing would DELETE that file rather than
// add a second declaration beside it. This is that landing and that is what it did. A second
// declaration of one wire enum disagrees by a NUMBER rather than by a type error, which is the
// one kind of drift nothing in this package could have seen.
//
// None of the three registries here declares its reserved zero as a constant, and that is a
// decision rather than an omission. Every enumeration gate in this package derives a
// registry's members as "the declared constants of that type", so a constant standing at a
// code point the RFC reserves is counted as registered by all of them -- and for ContentType
// specifically, the reserved zero being absent is what makes an unparsed header a refusal
// rather than generation 0 of a real ratchet. The refusal paths therefore name the offending
// value numerically, which is what they have off the wire anyway.
package mls

import (
	"errors"
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// WireFormat selects which of the five MLSMessage arms a message carries. It is a code point
// from the RFC 9420 section 17 IANA MLS Wire Formats registry and is sixteen bits wide, which
// is wider than the five registered values need: the registry is open, and a decoder that read
// it at one octet would misplace every field after it.
type WireFormat uint16

const (
	WireFormatPublicMessage  WireFormat = 0x0001
	WireFormatPrivateMessage WireFormat = 0x0002
	WireFormatWelcome        WireFormat = 0x0003
	WireFormatGroupInfo      WireFormat = 0x0004
	WireFormatKeyPackage     WireFormat = 0x0005
)

// ContentType is the framing content type a FramedContent and a PrivateMessage header carry,
// from RFC 9420 section 6: it selects which arm of FramedContent is populated, and it selects
// which of a leaf's two ratchets protects the message.
//
// Its underlying type is the octet the wire format gives it, and no wider. A content type
// decoded at two octets moves every field after it in the header.
type ContentType uint8

// The three content types RFC 9420 section 6 registers. The zero value is deliberately none of
// them -- it is the reserved code point, and a zero that silently meant "application" would
// route an unparseable header onto a real ratchet rather than being refused.
const (
	ContentTypeApplication ContentType = 1
	ContentTypeProposal    ContentType = 2
	ContentTypeCommit      ContentType = 3
)

// SenderType says who sent a FramedContent. It selects the signature key, it selects whether
// the group context is part of the signature preimage, and it selects which payload the Sender
// structure carries. Eight bits, per the enum RFC 9420 section 6 writes.
type SenderType uint8

const (
	SenderTypeMember            SenderType = 1
	SenderTypeExternal          SenderType = 2
	SenderTypeNewMemberProposal SenderType = 3
	SenderTypeNewMemberCommit   SenderType = 4
)

// Sender is the sender of a FramedContent, a variant structure over SenderType.
//
// LeafIndex is meaningful only under member and SenderIndex only under external; the two
// new_member arms carry no payload at all. Both fields are uint32 and adjacent, so a codec
// that wrote one where the other belongs round trips perfectly and is byte exact against
// itself -- framing_test.go's hand derived goldens are what separates the two orders, and they
// are written from the RFC rather than read back through this file.
type Sender struct {
	SenderType  SenderType
	LeafIndex   LeafIndex
	SenderIndex uint32
}

// MarshalMLS writes the sender_type octet and then the arm that type selects.
//
// An unregistered sender type is refused rather than written, and the refusal is the encoder's
// semantic one rather than a buffer failure, which is why it is a return value: the sender type
// is inside every signature preimage this layer builds, so an encoder that emitted an
// unregistered one would produce signed bytes no peer can attribute to anybody.
func (self *Sender) MarshalMLS(w *syntax.Writer) error {
	switch self.SenderType {
	case SenderTypeMember:
		w.WriteUint8(uint8(self.SenderType))
		w.WriteUint32(uint32(self.LeafIndex))
	case SenderTypeExternal:
		w.WriteUint8(uint8(self.SenderType))
		w.WriteUint32(self.SenderIndex)
	case SenderTypeNewMemberProposal, SenderTypeNewMemberCommit:
		w.WriteUint8(uint8(self.SenderType))
	default:
		return fmt.Errorf("%w: %d", ErrUnknownSenderType, self.SenderType)
	}
	return nil
}

// UnmarshalMLS reads the discriminant, reads the arm it selects, and only then writes the
// receiver.
//
// The staging is the point and it is not free stylistic tidiness. A decoder that assigned the
// receiver as it read would leave a caller's Sender holding a sender type out of a message this
// package REFUSED -- a value that never existed anywhere, assembled from the first octet of
// somebody else's bytes -- with nothing about the returned error saying so. Credential and
// LeafNode already keep this discipline; a third decoder that did not would be the one place a
// refusal is not clean.
func (self *Sender) UnmarshalMLS(r *syntax.Reader) error {
	senderType, err := r.ReadUint8()
	if err != nil {
		return err
	}
	decoded := Sender{SenderType: SenderType(senderType)}
	switch decoded.SenderType {
	case SenderTypeMember:
		leafIndex, err := r.ReadUint32()
		if err != nil {
			return err
		}
		decoded.LeafIndex = LeafIndex(leafIndex)
	case SenderTypeExternal:
		senderIndex, err := r.ReadUint32()
		if err != nil {
			return err
		}
		decoded.SenderIndex = senderIndex
	case SenderTypeNewMemberProposal, SenderTypeNewMemberCommit:
	default:
		return fmt.Errorf("%w: %d", ErrUnknownSenderType, decoded.SenderType)
	}
	*self = decoded
	return nil
}

var _ syntax.Codec = (*Sender)(nil)

// ---------------------------------------------------------------------------
// FramedContentAuthData
// ---------------------------------------------------------------------------

// errMissingConfirmationTag is ValSem009 in the validation plan's catalogue, and that plan owns
// the single declaration site for ErrMissingConfirmationTag. Neither that name nor ValSem
// itself has landed in this package yet, so the refusal is carried by this unexported value
// until they do.
//
// The shape is extension.go's errMissingRequiredCapability and psk.go's three ValSem401 to
// ValSem403 stand ins, for the reason those files give. An exported ErrMissingConfirmationTag
// declared here would be a second public declaration site for a name the validation plan also
// declares, the two would not be the same value, and a caller matching one would silently stop
// matching the other; a name that cannot be reached from outside this package cannot be
// depended on from outside it either, so the swap costs nobody else anything, and every
// consumer of this refusal until then is inside package mls.
//
// The swap is mechanical and it is not left to anybody's memory:
// TestNoValidationOwnedNameHasLandedBesideItsStandIn derives the owed pair from this package's
// own declarations and fails on the commit that lands the real name. When it does, each return
// below becomes ValSem(ValSem009, ErrMissingConfirmationTag) -- the code CodeOf reads, with the
// sentinel still reachable through (*ValidationError).Unwrap.
var errMissingConfirmationTag = errors.New("mls: commit carries no confirmation tag")

// FramedContentAuthData is the pair of authenticators over a FramedContent: the signature every
// content type carries, and the confirmation tag only a commit does.
//
// The content type is a PARAMETER of both codec methods rather than a field of this struct, and
// that is why this type is deliberately NOT a syntax.Codec and carries no var _ assertion.
// RFC 9420 section 6 writes FramedContentAuthData as a select() on the ENCLOSING
// FramedContent's content_type, so it carries no discriminant of its own on the wire. A copy
// stored here would be a second statement of one fact, the two could disagree, and the copy
// rather than the message would be what decided which arm was read -- which is a receiver
// verifying a confirmation tag the sender never sent, or skipping one it did.
//
// It is also why the validation plan's requested HasConfirmationTag field is refused: tag
// presence is DERIVED from the content type, not carried beside it. Its requested MembershipTag
// field is refused on the neighbouring ground, that the membership tag lives on PublicMessage
// where RFC 9420 puts it. Registry section 7.2 fixes exactly the two signatures below.
type FramedContentAuthData struct {
	Signature       []byte
	ConfirmationTag []byte
}

// MarshalMLS writes the signature, and then the confirmation tag when the content type is
// commit and only then.
//
// Every refusal happens before a single octet is written, which is Sender.MarshalMLS's
// discipline and is load bearing for the same reason. This method is handed the CALLER's
// Writer -- there is no syntax.Marshal here, because that entry point takes a one argument
// Marshaler and this codec needs the content type -- so a refusal that had already written the
// signature would leave a caller that ignored the return value holding a shorter encoding with
// no sticky error on the Writer to say so. A FramedContentAuthData is the tail of every
// structure that carries it, so "shorter" means precisely "the confirmation tag is gone".
//
// A commit with no confirmation tag is refused rather than written short for the same reason
// the arm check on FramedContent is a refusal: the tag is what binds a commit to the epoch it
// creates, and a commit that encoded without one would be a message every peer rejects at
// ValSem009 having verified its signature first.
func (self *FramedContentAuthData) MarshalMLS(w *syntax.Writer, contentType ContentType) error {
	switch contentType {
	case ContentTypeApplication, ContentTypeProposal:
		w.WriteOpaque(self.Signature)
		return nil
	case ContentTypeCommit:
		if len(self.ConfirmationTag) == 0 {
			return errMissingConfirmationTag
		}
		w.WriteOpaque(self.Signature)
		w.WriteOpaque(self.ConfirmationTag)
		return nil
	}
	return fmt.Errorf("%w: %d", ErrUnknownContentType, contentType)
}

// UnmarshalMLS reads the arm the content type selects and only then writes the receiver.
//
// The staging is Sender's and Credential's and LeafNode's, and it has one extra edge here. The
// commit arm reads two fields, so a decoder that assigned as it read would leave a caller's
// value holding the signature out of a message this package REFUSED -- one whose confirmation
// tag was truncated or empty -- beside a confirmation tag from whatever the value held before.
// Nothing in the returned error says so, and the pair is a signature and a tag that were never
// carried together by anything.
//
// The content type is checked before any octet is consumed, so an unregistered one does not
// half consume the caller's Reader on its way to being refused.
//
// This codec cannot tell a commit's bytes from a proposal's on its own and does not try: under
// application and proposal it reads the signature and stops, which leaves a commit's tag
// unconsumed rather than silently swallowing it, and the enclosing decode refuses that tail at
// r.Done(). Guessing here is the failure this shape exists to prevent -- a receiver that read a
// commit's confirmation tag off a proposal's bytes would succeed by accident and authenticate
// the wrong structure.
func (self *FramedContentAuthData) UnmarshalMLS(r *syntax.Reader, contentType ContentType) error {
	switch contentType {
	case ContentTypeApplication, ContentTypeProposal:
		signature, err := r.ReadOpaque()
		if err != nil {
			return err
		}
		*self = FramedContentAuthData{Signature: signature}
		return nil
	case ContentTypeCommit:
		signature, err := r.ReadOpaque()
		if err != nil {
			return err
		}
		confirmationTag, err := r.ReadOpaque()
		if err != nil {
			return err
		}
		// an empty tag is wire legal and is the encoding of "no tag". accepting it would put a
		// commit past the presence check with nothing for MacVerify to compare, so the two
		// halves of this codec agree about it: what the encoder refuses to write, the decoder
		// refuses to read.
		if len(confirmationTag) == 0 {
			return errMissingConfirmationTag
		}
		*self = FramedContentAuthData{Signature: signature, ConfirmationTag: confirmationTag}
		return nil
	}
	return fmt.Errorf("%w: %d", ErrUnknownContentType, contentType)
}

// The two signatures registry section 7.2 fixes, as a compile time statement rather than a
// sentence. syntax.Codec cannot express either of them -- both take the content type -- so the
// var _ syntax.Codec line every other codec in this file carries is absent here on purpose, and
// these two are what stands in its place: a later task that "fixes" this type by storing a
// content type field and narrowing the methods to one argument stops COMPILING here.
var (
	_ func(*FramedContentAuthData, *syntax.Writer, ContentType) error = (*FramedContentAuthData).MarshalMLS
	_ func(*FramedContentAuthData, *syntax.Reader, ContentType) error = (*FramedContentAuthData).UnmarshalMLS
)

// ---------------------------------------------------------------------------
// FramedContent
// ---------------------------------------------------------------------------

// FramedContent is the body of a group message before it is authenticated. Exactly one of
// ApplicationData, Proposal and Commit is populated, selected by ContentType.
//
// This is the structure the signature is taken over and the structure the confirmed transcript
// hash is taken over, which is why the arm check below is a REFUSAL rather than a preference:
// MLS authenticates serialized forms, so an encoder that wrote whichever arm happened to be
// non-nil would sign bytes describing a message the caller did not build, and every peer would
// accept it.
type FramedContent struct {
	GroupId           []byte
	Epoch             uint64
	Sender            Sender
	AuthenticatedData []byte
	ContentType       ContentType
	ApplicationData   []byte
	Proposal          *Proposal
	Commit            *Commit
}

// checkArms reports whether exactly the arm ContentType names is populated.
//
// The application arm is the one that cannot be read by counting. ApplicationData is a []byte
// and its zero value is nil, but an application message carrying no bytes is legal and encodes
// to an empty opaque<V> -- so "populated" for that arm is not a question the other two answer
// the same way, and what is refused there is a proposal or a commit standing beside it.
func (self *FramedContent) checkArms() error {
	populated := 0
	if self.ApplicationData != nil {
		populated += 1
	}
	if self.Proposal != nil {
		populated += 1
	}
	if self.Commit != nil {
		populated += 1
	}
	switch self.ContentType {
	case ContentTypeApplication:
		if self.Proposal != nil || self.Commit != nil {
			return ErrContentArmMismatch
		}
	case ContentTypeProposal:
		if self.Proposal == nil || populated != 1 {
			return ErrContentArmMismatch
		}
	case ContentTypeCommit:
		if self.Commit == nil || populated != 1 {
			return ErrContentArmMismatch
		}
	default:
		return fmt.Errorf("%w: %d", ErrUnknownContentType, self.ContentType)
	}
	return nil
}

// MarshalMLS refuses before it writes, which is Sender.MarshalMLS's discipline and is load
// bearing here for a sharper reason than it is there: this structure is the signature preimage
// and the transcript hash preimage, and a half written one that a caller ignored the error from
// is a preimage shorter than the message it claims to describe.
func (self *FramedContent) MarshalMLS(w *syntax.Writer) error {
	if err := self.checkArms(); err != nil {
		return err
	}
	w.WriteOpaque(self.GroupId)
	w.WriteUint64(self.Epoch)
	if err := self.Sender.MarshalMLS(w); err != nil {
		return err
	}
	w.WriteOpaque(self.AuthenticatedData)
	w.WriteUint8(uint8(self.ContentType))
	switch self.ContentType {
	case ContentTypeApplication:
		w.WriteOpaque(self.ApplicationData)
		return nil
	case ContentTypeProposal:
		return self.Proposal.MarshalMLS(w)
	case ContentTypeCommit:
		return self.Commit.MarshalMLS(w)
	}
	return fmt.Errorf("%w: %d", ErrUnknownContentType, self.ContentType)
}

// UnmarshalMLS reads the five fixed fields, resets the receiver, and reads the arm the content
// type selects.
//
// The reset happens after the fixed fields and before the arm, which is Proposal's arrangement
// and not Sender's: the three arms write three different fields, so a fully staged decode would
// be a second FramedContent built only to be copied over the first. What the reset buys is the
// same thing the staging buys next door -- no arm of a previous value survives into a decode of
// bytes that do not carry one.
func (self *FramedContent) UnmarshalMLS(r *syntax.Reader) error {
	groupId, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	epoch, err := r.ReadUint64()
	if err != nil {
		return err
	}
	sender := Sender{}
	if err := sender.UnmarshalMLS(r); err != nil {
		return err
	}
	authenticatedData, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	contentType, err := r.ReadUint8()
	if err != nil {
		return err
	}
	*self = FramedContent{
		GroupId:           groupId,
		Epoch:             epoch,
		Sender:            sender,
		AuthenticatedData: authenticatedData,
		ContentType:       ContentType(contentType),
	}
	switch self.ContentType {
	case ContentTypeApplication:
		applicationData, err := r.ReadOpaque()
		if err != nil {
			return err
		}
		self.ApplicationData = applicationData
		return nil
	case ContentTypeProposal:
		proposal := &Proposal{}
		if err := proposal.UnmarshalMLS(r); err != nil {
			return err
		}
		self.Proposal = proposal
		return nil
	case ContentTypeCommit:
		commit := &Commit{}
		if err := commit.UnmarshalMLS(r); err != nil {
			return err
		}
		self.Commit = commit
		return nil
	}
	return fmt.Errorf("%w: %d", ErrUnknownContentType, self.ContentType)
}

var _ syntax.Codec = (*FramedContent)(nil)

// ---------------------------------------------------------------------------
// AuthenticatedContent
// ---------------------------------------------------------------------------

// AuthenticatedContent is a FramedContent together with the authenticators over it, independent
// of which wire format carried it. It is the object every validation path works on and the
// object a staged commit holds.
//
// The wire format is a FIELD rather than a parameter, and it is inside the serialization,
// because it is inside two preimages: the signature's FramedContentTBS and the confirmed
// transcript hash's input both begin with it. That is what stops one member's public message
// being replayed as another's private one -- the two produce different preimages, so a signature
// made for one does not verify against the other.
//
// FramedContentAuthData is written through the content type this structure already carries
// rather than through a discriminant of its own, which is why the codec below reaches into
// Content for it. A second copy of the content type stored beside the auth data would be a
// second statement of one fact, and the copy rather than the message would decide which arm was
// read.
type AuthenticatedContent struct {
	WireFormat WireFormat
	Content    FramedContent
	Auth       FramedContentAuthData
}

func (self *AuthenticatedContent) MarshalMLS(w *syntax.Writer) error {
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
	return self.Auth.MarshalMLS(w, self.Content.ContentType)
}

// UnmarshalMLS reads the wire format, resets the receiver, and reads the content and then the
// auth data the content's own type selects.
//
// The auth data is read with self.Content.ContentType and not with a value read separately,
// which is the whole of what makes this codec correct: the content type came off THESE bytes,
// so the arm the auth data is read at is the arm the sender wrote.
func (self *AuthenticatedContent) UnmarshalMLS(r *syntax.Reader) error {
	wireFormat, err := r.ReadUint16()
	if err != nil {
		return err
	}
	decoded := AuthenticatedContent{WireFormat: WireFormat(wireFormat)}
	switch decoded.WireFormat {
	case WireFormatPublicMessage, WireFormatPrivateMessage, WireFormatWelcome,
		WireFormatGroupInfo, WireFormatKeyPackage:
	default:
		return fmt.Errorf("%w: %d", ErrUnknownWireFormat, decoded.WireFormat)
	}
	if err := decoded.Content.UnmarshalMLS(r); err != nil {
		return err
	}
	if err := decoded.Auth.UnmarshalMLS(r, decoded.Content.ContentType); err != nil {
		return err
	}
	*self = decoded
	return nil
}

var _ syntax.Codec = (*AuthenticatedContent)(nil)
