// The RFC 9420 section 17 IANA registries that the key schedule's GroupContext is
// built out of, and the extensions<V> vector codec that closes it.
//
// This file belongs to the TreeKEM plan (p5 task 3), which the interface registry
// section 11 names as the owner of every registry enum: three plans declared
// ProtocolVersion and its constants and one Go package cannot compile two of them.
// It lands here because p4 task 3 consumes the whole set — GroupContext's first
// field is a ProtocolVersion and its last is an extensions vector — and p5 has not
// landed yet, so the alternative was a second, differently shaped copy that would
// have to be unpicked later. Only the declarations GroupContext needs are here.
// Capabilities, RequiredCapabilities, Credential and the credential and proposal
// registries stay p5's, and when p5 task 3 lands it extends this file rather than
// writing its own.
//
// None of these registries is a closed set. A GREASE value, or a code point
// registered after this was written, has to parse and be carried unchanged rather
// than error: refusing an unknown extension type at the codec layer would make the
// decoder the thing that decides policy, and policy belongs to validation.
package mls

import "github.com/urnetwork/connect/mls/syntax"

// ProtocolVersion is a code point from the RFC 9420 section 17.1 protocol version
// registry. It is the first field of GroupContext and so of every epoch binding.
type ProtocolVersion uint16

const ProtocolVersionMls10 ProtocolVersion = 0x0001

// ExtensionType is a code point from the RFC 9420 section 17.3 extension type
// registry. The three 0xF00x values are this project's own, from the private use
// range, and are declared beside the registered ones because they travel in the
// same vector and are subject to the same rules.
type ExtensionType uint16

const (
	ExtensionTypeRatchetTree             ExtensionType = 0x0002
	ExtensionTypeRequiredCapabilities    ExtensionType = 0x0003
	ExtensionTypeExternalSenders         ExtensionType = 0x0004
	ExtensionTypeUrmessageGroupPolicy    ExtensionType = 0xF001
	ExtensionTypeUrmessageLeafKeys       ExtensionType = 0xF002
	ExtensionTypeUrmessageOwnerSuccessor ExtensionType = 0xF003
)

// Extension is one entry of an extensions vector: a registry code point and an
// opaque body whose meaning the code point selects.
type Extension struct {
	ExtensionType ExtensionType
	ExtensionData []byte
}

// MarshalMLS encodes the entry as the RFC 9420 section 6.3.1 struct: a uint16 type
// then opaque extension_data<V>. The leaf writes are return free and no ops after
// the first failure (C2); the error return exists for a semantic refusal and this
// encoder has none.
func (self *Extension) MarshalMLS(w *syntax.Writer) error {
	w.WriteUint16(uint16(self.ExtensionType))
	w.WriteOpaque(self.ExtensionData)
	return nil
}

// UnmarshalMLS decodes one entry, consuming exactly its own two fields, because it
// runs inside a vector region whose remaining bytes belong to the entries after it.
// An unregistered type is accepted and carried: the codec does not decide policy.
func (self *Extension) UnmarshalMLS(r *syntax.Reader) error {
	extensionType, err := r.ReadUint16()
	if err != nil {
		return err
	}
	data, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	self.ExtensionType = ExtensionType(extensionType)
	self.ExtensionData = data
	return nil
}

// the C1 pin: drift between this type and the one codec convention fails at build.
var _ syntax.Codec = (*Extension)(nil)

// WriteExtensions encodes extensions<V> inline into a writer the caller owns.
//
// extensions<V> is never a standalone message — it is always the last field of a
// GroupContext, LeafNode, KeyPackage, GroupInfo or ReInit — so the pair is writer
// and reader taking rather than byte returning, and the length prefix comes from
// syntax.WriteVector rather than from a hand written WriteOpaque at each of those
// five call sites. That prefix counts BYTES and not elements, which is the single
// easiest thing in an MLS codec to get wrong, and writing it once is how it stays
// got right.
func WriteExtensions(w *syntax.Writer, exts []Extension) error {
	return syntax.WriteVector(w, exts, writeOneExtension)
}

// writeOneExtension is WriteVector's element encoder, named rather than written as a
// closure at the call site. The codec entry gate in crypto_labels_test.go pins every
// syntax call this package makes by its source text, and a closure carries its whole
// body into that pin, so a named function keeps the pin readable and keeps an edit to
// the body from reading as a new way of entering the codec.
func writeOneExtension(w *syntax.Writer, ext Extension) error {
	return ext.MarshalMLS(w)
}

// ReadExtensions decodes extensions<V> from a reader the caller owns, consuming
// exactly the declared region. The result is never nil, so an empty vector and an
// absent one stay distinguishable in Go even though the wire has one spelling for
// both.
func ReadExtensions(r *syntax.Reader) ([]Extension, error) {
	return syntax.ReadVector(r, readOneExtension)
}

// readOneExtension is ReadVector's element decoder, named for the reason its encode
// twin is.
func readOneExtension(r *syntax.Reader) (Extension, error) {
	var ext Extension
	err := ext.UnmarshalMLS(r)
	return ext, err
}
