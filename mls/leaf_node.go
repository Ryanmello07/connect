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

import (
	"fmt"
	"time"

	"github.com/urnetwork/connect/mls/syntax"
)

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
// others at their zero value. That last part is a property of UnmarshalMLS rather than of the
// switch inside it: the decode is staged and assigned whole, so it holds for a receiver that
// already held a leaf of another source as well as for a fresh one.
//
// A NIL vector and an EMPTY one are the same leaf. Every variable length field here --
// EncryptionKey, SignatureKey, Credential.Identity, the five Capabilities vectors, ParentHash,
// Extensions and Signature -- is written with a length prefix that has one spelling for zero,
// so nil and empty encode to identical bytes, and a decode of those bytes answers the EMPTY
// one: syntax.ReadOpaque allocates and syntax.ReadVector allocates, and neither ever answers
// nil. A leaf built by hand with a nil vector therefore does not survive a round trip under
// reflect.DeepEqual even though its encoding does, which matters wherever two leaves are
// compared as values rather than as bytes. TestANilVectorAndAnEmptyOneAreOneLeafOnTheWire
// states it over every vector of the structure, derived off the type.
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
//
// It writes into its receiver AS IT READS, and the variant arms assign only the field their own
// source carries, so it must be called on a value nobody else holds and that holds nothing:
// UnmarshalMLS below stages a fresh LeafNode for exactly that reason, and task 6's LeafNodeTBS
// owes the same. Called on a receiver that already held a leaf, this leaves the previous value's
// ParentHash or Lifetime standing under a source that does not carry it, and called on a
// receiver whose decode is then refused, it leaves that receiver half written. Both make the
// decoded value depend on something besides the bytes it was read from, which is the assumption
// every comparison of two leaves and every parent hash computed off one rests on.
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
//
// The decode is STAGED and assigned whole, and that is the property rather than a tidiness: the
// leaf this answers is a function of the bytes it read and of nothing the receiver arrived
// holding. Two things follow from it, and neither holds if the fields are written as they are
// read:
//
//   - a refused decode leaves the receiver untouched. Credential.UnmarshalMLS already keeps
//     that discipline -- it refuses the credential type before it reads the identity, so no
//     certificate chain is ever allocated on this package's behalf -- and two decoders of the
//     same commit disagreeing about it is how a caller comes to rely on the wrong one. Every
//     truncation and every unrecognised source is a refusal, and there are more of the first
//     than there are field boundaries.
//   - a receiver decoded into twice answers the second encoding both times. The variant arms
//     assign only the field their own source carries, so a commit leaf decoded into a receiver
//     that held a key_package leaf would otherwise come back carrying the previous leaf's
//     Lifetime. Nothing in the bytes says so, and the value compares unequal to the same bytes
//     decoded fresh.
func (self *LeafNode) UnmarshalMLS(r *syntax.Reader) error {
	staged := LeafNode{}
	if err := staged.unmarshalCore(r); err != nil {
		return err
	}
	signature, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	staged.Signature = signature
	*self = staged
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

// The RFC 9420 section 7.2 signature label, written once because a label spelled one way in
// the signing half and another in the verifying half agrees with itself perfectly: ed25519
// signs whatever preimage it is handed, and only a peer can tell "LeafNodeTBS" from
// "LeafNodeTbs". The label is what keeps a leaf signature from being a valid signature over
// some other structure the same key signed.
const leafNodeSignatureLabel = "LeafNodeTBS"

// errBadSignature is ErrBadSignature in the validation plan's catalogue, where it is ValSem010,
// and that plan owns the single declaration site for the exported name. It has not landed in
// this package yet, so the refusal is carried by this unexported value until it does -- the
// shape credential.go's errProfileCredentialType and extension.go's
// errMissingRequiredCapability already take, and the stand in gate fails on the commit that
// lands the exported twin beside it.
//
// It WRAPS ErrCryptoBadSignature, which is the pairing crypto_errors.go's own header already
// describes for the exported name: the crypto layer says the primitive refused, this layer says
// the leaf is not authentic, and a caller may ask either question rather than having to guess
// which of two sentinels for one condition it will be handed. Standing the wrap up now rather
// than when errors.go lands means no errors.Is answer this package gives changes under that
// commit.
var errBadSignature = fmt.Errorf("mls: leaf node signature does not verify: %w", ErrCryptoBadSignature)

// signatureContent is RFC 9420 section 7.2's LeafNodeTBS: the leaf's fields down to and
// including extensions, followed -- for the update and commit sources ONLY -- by the group id
// and the leaf index.
//
// That trailing select is the whole security value of this preimage, and it is the part an
// implementation can drop while agreeing with itself perfectly. A leaf signed without its group
// id verifies in whatever group it is pasted into. A leaf signed without its leaf index
// verifies at whatever position of the tree it is moved to. Both are member substitutions,
// both sign and verify against this package, and neither is visible to a round trip, to a
// golden taken off this encoder, or to any sign then verify test. What sees them is a corpus
// another implementation signed and the two binding tests beside it.
//
// The key_package arm carries NEITHER, and that is the section 7.2 structure rather than a
// shortcut: the select's key_package case is an empty struct, because a KeyPackage is minted
// before there is a group to bind it to or a position to put it in. Section 7.2's prose says
// only that "the group ID of the group is added as context"; the STRUCTURE adds the leaf index
// as well, and the prose is the half an implementation must not be written from. Section 7.3,
// which is where the leaf validation rules live, restates none of it -- it says only that the
// signature is verified using signature_key -- so the conditional binding is section 7.2's
// alone. groupId and leafIndex are therefore IGNORED under key_package rather than refused: a
// caller holding a group cannot tell from the leaf alone which arm applies, and refusing would
// push that switch into every call site.
//
// LeafNodeTBS is a preimage and never a message, so it does not go through syntax.Marshal:
// nothing decodes these bytes, and the trailing byte contract Marshal carries belongs to a
// wire type.
//
// It opens the Writer itself rather than handing an encoder to marshalBytes, and that is not a
// style choice. TestNoStubShapesRemainInSource reads a declaration's own body for the
// parameters it uses and deliberately does not descend into a function literal, so a preimage
// whose group id and leaf index were touched only inside a closure reads there exactly like one
// that ignored them -- and ignoring them IS the substitution this suffix exists to prevent.
// What is given up is a name: marshalBytes is a fresh Writer, the caller's encoder and Bytes,
// which is these three statements with the section 7.2 select written between them, under the
// same default vector limit for the same reason -- a LeafNodeTBS is one leaf and never a
// ratchet tree.
func (self *LeafNode) signatureContent(groupId []byte, leafIndex LeafIndex) ([]byte, error) {
	w := syntax.NewWriter()
	// the same call MarshalMLS makes, and that shared call is what stops the two from coming
	// apart: a field written in the wire form and not in the preimage is a signature over a
	// structure nobody sent, and it is invisible to both halves of a round trip
	if err := self.marshalCore(w); err != nil {
		return nil, err
	}
	switch self.LeafNodeSource {
	case LeafNodeSourceKeyPackage:
		// the empty struct arm of the section 7.2 select
	case LeafNodeSourceUpdate, LeafNodeSourceCommit:
		w.WriteOpaque(groupId)
		w.WriteUint32(uint32(leafIndex))
	default:
		// unreachable while marshalCore refuses an unknown source first, and written anyway
		// rather than left to fall through. A fall through would make an unrecognised source
		// the third spelling of "no context bound", which is exactly the key_package arm --
		// so a fourth source added later would inherit the unbound preimage in silence
		// instead of failing here.
		return nil, ErrTreeMalformed
	}
	// the Writer's sticky error, surfaced here the way marshalBytes surfaces it: a preimage
	// that came back short is a signature over bytes nobody agreed to
	return w.Bytes()
}

// Sign replaces this leaf's signature with one over its LeafNodeTBS.
//
// The signature field itself is NOT part of what is signed -- marshalCore stops above it --
// so signing twice over one leaf answers the same bytes, and a stale signature left on the
// receiver cannot feed into the new one.
//
// groupId and leafIndex are the context the update and commit sources bind and the key_package
// source ignores; see signatureContent.
func (self *LeafNode) Sign(crypto CryptoProvider, signer SignaturePrivateKey,
	groupId []byte, leafIndex LeafIndex) error {
	if crypto == nil {
		return fmt.Errorf("%w: the signature over the LeafNodeTBS is made through it", ErrNilCryptoProvider)
	}
	content, err := self.signatureContent(groupId, leafIndex)
	if err != nil {
		return err
	}
	signature, err := crypto.SignWithLabel(signer, leafNodeSignatureLabel, content)
	if err != nil {
		return err
	}
	self.Signature = signature
	return nil
}

// VerifySignature answers nil only if this leaf's signature is a signature by this leaf's own
// signature_key over this leaf's LeafNodeTBS in the context it was handed.
//
// Every way the primitive can say no becomes errBadSignature, and the detail is dropped on
// purpose: a wrong length key, a wrong length signature and a signature over other content all
// arrived from the network, and which of them it was is not something a peer gets to learn from
// the error. The refusal is never a nil error and never a partial comparison -- a length
// mismatch is refused inside VerifyWithLabel before anything is compared, which is why nil,
// empty, truncated and over long signatures all reach this line as a refusal rather than as a
// panic.
//
// A failure to BUILD the preimage is returned as itself rather than as a signature failure. An
// unknown leaf_node_source or a credential outside the profile is a structural refusal no
// signature could have repaired, and collapsing it into errBadSignature would send a caller
// looking for a forgery over a leaf that is simply not one this package reads.
func (self *LeafNode) VerifySignature(crypto CryptoProvider,
	groupId []byte, leafIndex LeafIndex) error {
	if crypto == nil {
		return fmt.Errorf("%w: the signature over the LeafNodeTBS is checked through it", ErrNilCryptoProvider)
	}
	content, err := self.signatureContent(groupId, leafIndex)
	if err != nil {
		return err
	}
	if err := crypto.VerifyWithLabel(self.SignatureKey, leafNodeSignatureLabel,
		content, self.Signature); err != nil {
		return errBadSignature
	}
	return nil
}

// Spec A section 3.1: a fresh KeyPackage leaf is valid from now, back dated by the clock skew
// allowance, for the default lifetime.
const (
	leafLifetimeSkewSeconds    uint64 = 3600
	leafLifetimeDefaultSeconds uint64 = 90 * 24 * 3600
)

// NewLeafNode builds and signs the key_package source leaf -- the only source a leaf can carry
// before it is in a tree -- which is signed with no group id and no leaf index, and is why this
// takes neither.
//
// The signature key is DERIVED from the private key it was handed and never generated here.
// Calling SignatureKeyPair inside a constructor that was already given a key pair is how a leaf
// ends up signed by a key nobody holds: the leaf verifies against itself, the caller stores the
// private half it passed in, and every later Update by that member is refused by the group with
// nothing to point at.
//
// Every vector the caller supplied is COPIED before the leaf keeps it. This is the property
// BasicCredential already states for the identity, and it applies to the encryption key, to the
// five capability vectors and to every extension body for the same reason: the leaf outlives
// the call and the caller usually holds a longer buffer it goes on writing into, so a retained
// slice is a leaf that changes after it was signed -- a signature that verified when it was
// made and does not afterwards, with nothing in between to point at. Clone does the copying
// rather than a field list written here, so a field added to LeafNode is copied on the commit
// that adds it.
func NewLeafNode(crypto CryptoProvider, signer SignaturePrivateKey, cred Credential,
	encKey HpkePublicKey, caps Capabilities, exts []Extension) (*LeafNode, error) {
	// the provider is refused before any argument is judged, which is the only order that
	// does not dereference it: a length check that reached the provider for a width first
	// would take the caller's process rather than its call
	if crypto == nil {
		return nil, fmt.Errorf("%w: the leaf is signed and verified through it", ErrNilCryptoProvider)
	}
	signatureKey, err := signaturePublicKeyOf(signer)
	if err != nil {
		return nil, err
	}
	// the clock is read as a SIGNED unix second and clamped before it is widened.
	// time.Now().Unix() is negative on a machine whose clock is not set, and uint64 of a
	// negative second is about 1.8e19 -- a not_before no peer is ever past, carried by a leaf
	// that is otherwise perfectly well formed and correctly signed. Clamping answers a
	// lifetime that is merely wrong, which the receiver's section 7.3 lifetime check refuses.
	now := max(time.Now().Unix(), 0)
	leaf := &LeafNode{
		EncryptionKey:  encKey,
		SignatureKey:   signatureKey,
		Credential:     cred,
		Capabilities:   caps,
		LeafNodeSource: LeafNodeSourceKeyPackage,
		Lifetime: Lifetime{
			NotBefore: uint64(max(now-int64(leafLifetimeSkewSeconds), 0)),
			NotAfter:  uint64(now) + leafLifetimeDefaultSeconds,
		},
		Extensions: exts,
	}
	// everything above is still the caller's storage; from here it is the leaf's own
	leaf = leaf.Clone()
	if err := leaf.Sign(crypto, signer, nil, 0); err != nil {
		return nil, err
	}
	// one ed25519 verify per key package, which buys a failure HERE rather than a leaf every
	// peer refuses later: a provider whose signing half and verifying half disagree, or a
	// preimage that cannot be rebuilt from what was just written, is a leaf nobody can use and
	// there is nothing in the returned value that would say so.
	if err := leaf.VerifySignature(crypto, nil, 0); err != nil {
		return nil, err
	}
	return leaf, nil
}
