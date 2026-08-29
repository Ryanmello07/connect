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
