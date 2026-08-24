// The RFC 9420 section 5.1 labelled constructions. Every one of them is a TLS
// presentation language struct, so all of them go through mls/syntax: there is one
// length prefix implementation in the system and one place for a length prefix bug to be.
//
// MLS derives every secret, and signs and macs over, these serialized forms, so a
// preimage that two implementations build differently is a protocol split, and a preimage
// that admits two readings is a signature bypass primitive. That is why nothing here hand
// rolls a prefix.
//
// The whole security argument of this file is the "MLS 1.0 " prefix and the two length
// prefixed fields after it, and none of it is observable from the outside: dropping the
// prefix, altering it, dropping the uint16 length, writing the context raw, or
// transposing label and context each produce a well formed output of exactly the
// requested size. Only a published answer separates them, which is what
// crypto_labels_test.go holds this to.
package mls

import "github.com/urnetwork/connect/mls/syntax"

// The domain separator every MLS label carries before serialization. The version is part
// of it: a future MLS derives different secrets from the same transcript rather than
// silently interoperating with this one.
const MlsLabelPrefix = "MLS 1.0 "

// The sticky writer's error, taken once (convention C2).
//
// Every labelled construction in this file returns bytes and no error, because the
// interface spec A section 3.3 fixes on CryptoProvider has no error return and neither
// does RefHash. That is sound rather than a shortcut: a syntax.Writer's only failure mode
// is a vector longer than its limit, and every value that reaches a labelled construction
// arrived through a decode or an encode already bounded by syntax.MaxVectorLength. A
// panic here is therefore unreachable — and it is a panic rather than a truncation
// because a label that describes more bytes than it carries is exactly the shape a
// signature bypass is built out of.
func mlsLabelBytes(w *syntax.Writer) []byte {
	encoded, err := w.Bytes()
	if err != nil {
		panic("mls: a labelled preimage could not be encoded: " + err.Error())
	}
	return encoded
}

// struct { uint16 length; opaque label<V>; opaque context<V> } KDFLabel, serialized.
//
// The length is the requested output size and not the size of anything in the preimage,
// so two derivations that differ only in how many bytes the caller wanted are still
// separated. The uint16 conversion cannot lose a bit that matters: Expand refuses
// anything above hpkeMaxExpandLength, which is 8160, so a length that survives the call
// is representable, and one that does not stops in Expand rather than deriving under a
// truncated label.
func mlsKdfLabel(label string, context []byte, length int) []byte {
	writer := syntax.NewWriter()
	writer.WriteUint16(uint16(length))
	writer.WriteOpaque([]byte(MlsLabelPrefix + label))
	writer.WriteOpaque(context)
	return mlsLabelBytes(writer)
}

// HKDF-Expand over a preimage that names the label, the context and the output size, so
// no two derivations in the protocol share an info string.
func (self *suiteCryptoProvider) ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte {
	return self.Expand(secret, mlsKdfLabel(label, context, length), length)
}

// The Nh byte derivation with no context. The context field is still written — an empty
// vector is one length byte, not nothing — which is the difference between this and an
// encoder that dropped the field, and the only thing that can see the difference is a
// published answer.
func (self *suiteCryptoProvider) DeriveSecret(secret []byte, label string) []byte {
	return self.ExpandWithLabel(secret, label, nil, self.params.Nh)
}

// The generation is the context, encoded as a big endian uint32 (RFC 9420 section 9). It
// goes through the same writer as everything else: there is one integer encoder in this
// system and it is p1's, so a byte order cannot be chosen twice.
func (self *suiteCryptoProvider) DeriveTreeSecret(secret []byte, label string, generation uint32, length int) []byte {
	writer := syntax.NewWriter()
	writer.WriteUint32(generation)
	return self.ExpandWithLabel(secret, label, mlsLabelBytes(writer), length)
}
