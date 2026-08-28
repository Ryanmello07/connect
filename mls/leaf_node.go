// The LeafNode of RFC 9420 section 7.2: one device's presence in the ratchet tree, and the
// variant codec that both halves of its signature are taken over.
//
// Everything in this file is field ORDER and prefix WIDTH, and neither is visible from a round
// trip. A pair of fields swapped in both halves round trips perfectly, agrees with itself, and
// disagrees with every other implementation; a field dropped from both halves round trips
// byte exact while being lost. What holds those is the hand derived golden in the test file and
// the field assignment cross check against the vendored vectors, not any symmetry property of
// this code.
package mls

import "github.com/urnetwork/connect/mls/syntax"

// LeafNodeSource is RFC 9420 section 7.2: which of the three ways this leaf entered the tree,
// and therefore which variant fields are present and what the signature covers.
//
// It is the discriminant of a `select`, so it decides the LENGTH of the encoding as well as its
// content: a leaf whose source says update carries no lifetime and no parent hash, and the same
// bytes read under key_package would take the sixteen octets of the extensions vector and the
// signature that follow it as a Lifetime.
type LeafNodeSource uint8

const (
	LeafNodeSourceKeyPackage LeafNodeSource = 1
	LeafNodeSourceUpdate     LeafNodeSource = 2
	LeafNodeSourceCommit     LeafNodeSource = 3
)

// Lifetime is present only when the source is key_package. Seconds since the unix epoch.
type Lifetime struct {
	NotBefore uint64
	NotAfter  uint64
}

// LeafNode is RFC 9420 section 7.2: one device's presence in the ratchet tree.
//
// Lifetime and ParentHash are variant fields and are meaningful only under the source that
// carries them. A value holding both is not malformed -- it is what a struct with no sum type
// looks like in Go -- but only the one the source selects is encoded, and a decode leaves the
// others at their zero value.
type LeafNode struct {
	EncryptionKey  HpkePublicKey
	SignatureKey   SignaturePublicKey
	Credential     Credential
	Capabilities   Capabilities
	LeafNodeSource LeafNodeSource
	Lifetime       Lifetime
	ParentHash     []byte
	Extensions     []Extension
	Signature      []byte
}

// marshalCore writes the fields common to LeafNode and LeafNodeTBS, up to and including
// extensions.
//
// It exists so that task 6's LeafNodeTBS cannot drift from this one. The signature is taken
// over exactly these bytes plus the TBS suffix, so a field written here and not there -- or in
// a different order -- is a signature that verifies against a leaf nobody sent.
func (self *LeafNode) marshalCore(w *syntax.Writer) error {
	w.WriteOpaque(self.EncryptionKey)
	w.WriteOpaque(self.SignatureKey)
	if err := self.Credential.MarshalMLS(w); err != nil {
		return err
	}
	if err := self.Capabilities.MarshalMLS(w); err != nil {
		return err
	}
	w.WriteUint8(uint8(self.LeafNodeSource))
	switch self.LeafNodeSource {
	case LeafNodeSourceKeyPackage:
		w.WriteUint64(self.Lifetime.NotBefore)
		w.WriteUint64(self.Lifetime.NotAfter)
	case LeafNodeSourceUpdate:
		// the empty struct arm. nothing is written, which is the whole of the variant
	case LeafNodeSourceCommit:
		w.WriteOpaque(self.ParentHash)
	default:
		// a semantic refusal rather than a buffer failure, so it reaches the caller as a
		// returned error rather than being dropped into the Writer: an unknown source would
		// otherwise be encoded as its octet and no variant at all, which is a leaf every
		// other implementation reads as a different structure
		return ErrTreeMalformed
	}
	return WriteExtensions(w, self.Extensions)
}

// MarshalMLS encodes the whole leaf: the core, then the signature over the TBS of that core.
func (self *LeafNode) MarshalMLS(w *syntax.Writer) error {
	if err := self.marshalCore(w); err != nil {
		return err
	}
	w.WriteOpaque(self.Signature)
	return nil
}

// unmarshalCore reads the same fields in the same order as marshalCore, so that LeafNodeTBS and
// LeafNode cannot come apart at the one place it would not be noticed.
func (self *LeafNode) unmarshalCore(r *syntax.Reader) error {
	encryptionKey, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	signatureKey, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	if err := self.Credential.UnmarshalMLS(r); err != nil {
		return err
	}
	if err := self.Capabilities.UnmarshalMLS(r); err != nil {
		return err
	}
	source, err := r.ReadUint8()
	if err != nil {
		return err
	}
	self.EncryptionKey = HpkePublicKey(encryptionKey)
	self.SignatureKey = SignaturePublicKey(signatureKey)
	self.LeafNodeSource = LeafNodeSource(source)
	switch self.LeafNodeSource {
	case LeafNodeSourceKeyPackage:
		if self.Lifetime.NotBefore, err = r.ReadUint64(); err != nil {
			return err
		}
		if self.Lifetime.NotAfter, err = r.ReadUint64(); err != nil {
			return err
		}
	case LeafNodeSourceUpdate:
		// the empty struct arm, matching the encode half
	case LeafNodeSourceCommit:
		if self.ParentHash, err = r.ReadOpaque(); err != nil {
			return err
		}
	default:
		// the same refusal the encode half makes, and for the stronger reason: an unknown
		// source read leniently would have this decoder guess how many bytes the variant
		// occupies, and every guess accepts a second encoding of some other leaf
		return ErrTreeMalformed
	}
	self.Extensions, err = ReadExtensions(r)
	return err
}

// UnmarshalMLS decodes the whole leaf. It consumes exactly its own fields, because a LeafNode is
// also read inside a ratchet tree and inside a KeyPackage, where the bytes after it are not its.
func (self *LeafNode) UnmarshalMLS(r *syntax.Reader) error {
	if err := self.unmarshalCore(r); err != nil {
		return err
	}
	signature, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	self.Signature = signature
	return nil
}

// the C1 pin: drift between this type and the one codec convention fails at build.
var _ syntax.Codec = (*LeafNode)(nil)

// cloneSlice answers a shallow copy of in, and nil for nil.
//
// nil for nil for group_context.go's cloneBytes reason: an absent vector and a present empty
// one are different bytes on the wire, and a clone that turned one into the other would change
// the encoding of the thing it was asked to duplicate.
//
// Shallow is correct for a slice of scalars and is NOT correct for a slice of structures
// holding storage of their own -- Clone below copies the extension bodies itself for exactly
// that reason.
func cloneSlice[T any](in []T) []T {
	if in == nil {
		return nil
	}
	out := make([]T, len(in))
	copy(out, in)
	return out
}

// Clone answers a leaf that shares no storage with this one.
//
// A leaf is copied whenever it is re-signed or installed in a provisional tree, so nothing may
// alias between two epochs' trees: a commit that is later rejected must leave the epoch it was
// computed against exactly as it found it, and a shared backing array is how a rejected commit
// mutates a tree that never accepted it. Every slice the structure reaches is copied, at every
// depth, because a deep copy that stops one level short is indistinguishable from a complete
// one until the day something writes through the level it missed.
func (self *LeafNode) Clone() *LeafNode {
	out := *self
	out.EncryptionKey = HpkePublicKey(cloneBytes(self.EncryptionKey))
	out.SignatureKey = SignaturePublicKey(cloneBytes(self.SignatureKey))
	out.Credential.Identity = cloneBytes(self.Credential.Identity)
	out.Capabilities.Versions = cloneSlice(self.Capabilities.Versions)
	out.Capabilities.CipherSuites = cloneSlice(self.Capabilities.CipherSuites)
	out.Capabilities.Extensions = cloneSlice(self.Capabilities.Extensions)
	out.Capabilities.Proposals = cloneSlice(self.Capabilities.Proposals)
	out.Capabilities.Credentials = cloneSlice(self.Capabilities.Credentials)
	out.ParentHash = cloneBytes(self.ParentHash)
	out.Signature = cloneBytes(self.Signature)
	out.Extensions = cloneSlice(self.Extensions)
	for i := range out.Extensions {
		out.Extensions[i].ExtensionData = cloneBytes(self.Extensions[i].ExtensionData)
	}
	return &out
}
