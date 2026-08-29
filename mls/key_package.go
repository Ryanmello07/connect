// The RFC 9420 section 10 KeyPackage, at its codec surface and nothing else.
//
// OWNERSHIP, and why this file is here early and incomplete. KeyPackage is the TreeKEM plan's,
// task 7A, and mls/key_package.go is the path that task names. It is landed PARTIALLY here
// because the framing plan's Proposal carries an Add arm holding a KeyPackage BY VALUE: package
// mls is one package, a struct cannot name a type that does not exist, and without the Add arm
// nothing downstream of Proposal compiles -- which is FramedContent, AuthenticatedContent, the
// confirmed transcript hash input and every by-reference proposal in a commit.
//
// What is here is exactly what interface registry section 6.5 fixes for the codec: the six
// exported fields, in the RFC's order, and the two codec methods. What is deliberately NOT here
// is everything that needs a signature or a clock -- NewKeyPackage, (*KeyPackage).Ref,
// (*KeyPackage).Validate, the KeyPackageTBS label and the signature private key task 7A stores
// beside the public halves. Those need NewLeafNode and the leaf validation context, and a
// second version of a signature preimage written from this side would be a second OPINION about
// what a key package signs rather than a convenience: two implementations of one preimage
// disagree by bytes, and a key package that verifies under one and not the other is a joiner
// nobody can add.
//
// So task 7A does not create this file, it FILLS IT IN and deletes this notice.
// TestTheKeyPackageStandInDoesNotOutliveItsOwnersLanding fails on the commit that lands the
// rest, which is what stops the notice describing a file it no longer describes.
package mls

import (
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
}

// marshalCore writes KeyPackageTBS: every field the signature covers, which is all of them but
// the signature.
//
// It is separated from MarshalMLS rather than inlined into it because the signing half task 7A
// lands needs precisely these bytes. One writer for the signed prefix and for the whole
// structure is what keeps the two from drifting: a signature taken over a prefix assembled a
// second time is a signature over whatever that second assembly happened to write.
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
