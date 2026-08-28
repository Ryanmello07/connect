// The ratchet tree of RFC 9420 section 7: the ParentNode structure and its codec, the Node
// union that occupies one array position, the optional<Node> that one position becomes on the
// wire, and the RatchetTree container every later task of this plan operates on.
//
// Two things in this file decide whether this implementation agrees with a peer or forks from
// it, and neither is visible to a round trip.
//
// The first is what a BLANK node is. RFC 9420 section 4.2 stores the tree as
// optional<Node> ratchet_tree<V>, so a blank position is an ABSENT entry and not a zero valued
// one: absent is a single 0x00 presence octet, present is 0x01 followed by a whole node. An
// implementation that stored a blank as a zero valued Node would round trip against itself
// perfectly, would agree with itself about every accessor, and would hash a different tree from
// every peer -- which is a fork, not a parse error. So a blank here is a nil entry in the node
// array and nothing else, NodeType has no zero valued member so a Node that was never filled in
// cannot be mistaken for either kind, and SetLeaf and SetParent refuse a nil payload rather than
// storing an occupied slot with nothing in it. TestABlankAndAZeroValuedNodeEncodeDifferently and
// TestBlankPositionsAreExactlyTheUnsetOnesAtEveryWidth are what hold it.
//
// The second is unmerged_leaves. RFC 9420 section 7.9.2 requires the vector strictly ascending,
// and the requirement is not cosmetic: the vector is hashed into the parent hash, so two
// orderings of one set are two different parent hashes over one tree. An encoder that emitted
// insertion order and a decoder that accepted it would round trip byte exact and disagree with
// every peer, and one that quietly SORTED on read would agree with itself and with nobody,
// since the bytes a signature and a tree hash were taken over are the bytes that arrived. Both
// halves of this codec therefore REFUSE a vector that is not strictly ascending, with
// ErrUnmergedLeavesNotSorted, rather than repairing it or passing it on.
package mls

import (
	"crypto/subtle"

	"github.com/urnetwork/connect/mls/syntax"
)

// RFC 9420 section 7. Leaf nodes sit at even node indices, parent nodes at odd ones, and the
// octet below is what a decoder reads to learn which of the two a present entry holds.
//
// Neither member is zero, deliberately. The zero value of a Node is therefore a node of no
// type, which no encoder will write and no decoder will accept, so the Go zero value cannot be
// mistaken for a leaf, for a parent, or -- the one that matters -- for a blank.
type NodeType uint8

const (
	NodeTypeLeaf   NodeType = 1
	NodeTypeParent NodeType = 2
)

// ParentNode is RFC 9420 section 7.1:
//
//	struct {
//	    HPKEPublicKey encryption_key;
//	    opaque parent_hash<V>;
//	    uint32 unmerged_leaves<V>;
//	} ParentNode;
//
// EncryptionKey and ParentHash are both opaque<V> and adjacent, which is the pair a symmetric
// field order swap hides in: swapped in both halves they round trip perfectly and produce a
// parent hash no peer computes. TestParentNodeMarshalMatchesTheHandDerivedGoldens is the only
// thing in this package that separates the two orders, because it states the encoding without
// reference to this code.
type ParentNode struct {
	EncryptionKey  HpkePublicKey
	ParentHash     []byte
	UnmergedLeaves []LeafIndex
}

// checkUnmergedLeavesSorted refuses a vector that is not STRICTLY ascending, which is both
// halves of RFC 9420 section 7.9.2's requirement at once: sorted, and free of repeats.
//
// It runs on the encode side as well as the decode side. The decode side is the obvious half --
// a peer's unsorted vector is a tree this implementation must not adopt, and adopting it after
// sorting it would compute a parent hash over bytes nobody sent. The encode side is the half
// that keeps THIS implementation from being the peer that forks: a caller that appended an
// unmerged leaf without inserting it in order has built a tree whose hash no other member
// reproduces, and the cheapest place to find that out is the encode that would have published
// it.
func checkUnmergedLeavesSorted(leaves []LeafIndex) error {
	for i := 1; i < len(leaves); i += 1 {
		if leaves[i-1] >= leaves[i] {
			return ErrUnmergedLeavesNotSorted
		}
	}
	return nil
}

func (self *ParentNode) MarshalMLS(w *syntax.Writer) error {
	if err := checkUnmergedLeavesSorted(self.UnmergedLeaves); err != nil {
		return err
	}
	w.WriteOpaque(self.EncryptionKey)
	w.WriteOpaque(self.ParentHash)
	return syntax.WriteVector(w, self.UnmergedLeaves, writeOneUnmergedLeaf)
}

// writeOneUnmergedLeaf is WriteVector's element encoder, named rather than written as a closure
// for the reason extension.go's writeOneExtension is: the codec entry gate in
// crypto_labels_test.go pins every syntax call this package makes by its source text, and a
// closure carries its whole body into that pin.
func writeOneUnmergedLeaf(w *syntax.Writer, leaf LeafIndex) error {
	w.WriteUint32(uint32(leaf))
	return nil
}

// UnmarshalMLS decodes the parent node, STAGED and assigned whole for LeafNode.UnmarshalMLS's
// reason: the value this answers is a function of the bytes it read and of nothing the receiver
// arrived holding, so a refused decode -- a truncation, or an unmerged vector that is not
// strictly ascending -- leaves the receiver exactly as it found it rather than half written.
func (self *ParentNode) UnmarshalMLS(r *syntax.Reader) error {
	encryptionKey, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	parentHash, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	unmerged, err := syntax.ReadVector(r, readOneUnmergedLeaf)
	if err != nil {
		return err
	}
	if err := checkUnmergedLeavesSorted(unmerged); err != nil {
		return err
	}
	self.EncryptionKey = HpkePublicKey(encryptionKey)
	self.ParentHash = parentHash
	self.UnmergedLeaves = unmerged
	return nil
}

// readOneUnmergedLeaf is ReadVector's element decoder, named for the reason its encode twin is.
func readOneUnmergedLeaf(r *syntax.Reader) (LeafIndex, error) {
	v, err := r.ReadUint32()
	return LeafIndex(v), err
}

// the C1 pin: drift between this type and the one codec convention fails at build.
var _ syntax.Codec = (*ParentNode)(nil)

// Clone answers a parent node that shares no storage with this one, for LeafNode.Clone's
// reason: a commit computed against one epoch's tree and later rejected must leave that tree
// exactly as it found it, and a shared backing array is how a rejected commit mutates a tree
// that never accepted it.
func (self *ParentNode) Clone() *ParentNode {
	return &ParentNode{
		EncryptionKey:  HpkePublicKey(cloneBytes(self.EncryptionKey)),
		ParentHash:     cloneBytes(self.ParentHash),
		UnmergedLeaves: cloneSlice(self.UnmergedLeaves),
	}
}

// Node is one OCCUPIED position in the tree. Exactly one of Leaf and Parent is set, and which
// one is what NodeType says.
//
// A Node value is never how a blank is spelled. A blank is the absence of a Node, which in the
// array below is a nil entry and on the wire is a zero presence octet; see the file header.
type Node struct {
	NodeType NodeType
	Leaf     *LeafNode
	Parent   *ParentNode
}

func (self *Node) Clone() *Node {
	out := &Node{NodeType: self.NodeType}
	if self.Leaf != nil {
		out.Leaf = self.Leaf.Clone()
	}
	if self.Parent != nil {
		out.Parent = self.Parent.Clone()
	}
	return out
}

// OptionalNode is one element of the ratchet_tree vector: optional<Node>.
//
// It is a named type rather than a bare *Node so that the validation plan's codec table and
// fuzz corpus have a decodable unit for a single position, and so that PRESENCE is a field of
// its own rather than something derived from whether the node looks filled in. Derived
// presence is the conflation this file exists to prevent: an absent node and a present node
// that happens to be zero valued are different bytes, different tree hashes, and a fork.
type OptionalNode struct {
	Present bool
	Node    Node
}

// RatchetTree is the tree in RFC 9420 section 4.2 array order. A nil entry is a BLANK node.
//
// The leaf width is always a power of two, so the array is always a complete tree: RFC 9420
// section 7.7 grows and shrinks the tree by doubling and halving, never by one leaf. NOT safe
// for concurrent use.
type RatchetTree struct {
	nodes []*Node
}

// NewRatchetTree answers the one leaf tree, whose single node is blank. Not the empty tree:
// there is no such thing in the array representation, since a node width of zero is not 2n-1
// for any n, and every arithmetic in tree_math.go refuses a leaf count of zero.
func NewRatchetTree() *RatchetTree {
	return &RatchetTree{nodes: make([]*Node, 1)}
}

func (self *RatchetTree) NodeWidth() uint32 {
	return uint32(len(self.nodes))
}

// LeafWidth is a COUNT and not an index, which is why it answers LeafCount: it feeds
// NodeWidth, DirectPath, Root and Resolution, and every one of those takes a count.
func (self *RatchetTree) LeafWidth() LeafCount {
	return LeafCount((self.NodeWidth() + 1) / 2)
}

// growTo grows to at least the given leaf count, by doubling.
//
// Existing node indices are UNCHANGED by a doubling, because RFC 9420 section 7.7 adds a new
// root whose left subtree is the whole existing tree and whose right subtree is blank, and in
// array order that appends. ExtendedLeafCount is the doubling, and it is what refuses to pass
// MaxLeafCount rather than a bound re-derived here.
func (self *RatchetTree) growTo(target LeafCount) error {
	width := self.LeafWidth()
	for width < target {
		extended, err := ExtendedLeafCount(width)
		if err != nil {
			return err
		}
		width = extended
	}
	if width == self.LeafWidth() {
		return nil
	}
	grown := make([]*Node, NodeWidth(width))
	copy(grown, self.nodes)
	self.nodes = grown
	return nil
}

// setNode is the ONE store into the node array, and it carries the compiler directive for the
// reason secret_zeroize.go's file comment gives.
//
// Consolidating the store is not tidiness. The class
// TestEveryEraseHelperCarriesTheNoInlineDirective derives is "writes through storage that
// outlives the call", and a method of this container that indexes into its own node array is
// in that class whatever it stores. The blanking store is exactly the shape the argument is
// about: Blank is how a removed member's leaf, and the key material and credential it
// carries, stops being reachable from this tree, and a compiler is entitled to delete a store
// it can prove is never read again. Three stores would be three declarations each needing the
// directive and each able to lose it independently; one store is one place that can be wrong.
//
//go:noinline
func (self *RatchetTree) setNode(x NodeIndex, node *Node) {
	self.nodes[x] = node
}

// Get answers the node at x, or nil for a blank position and for an index outside the tree.
//
// One nil for both, deliberately: every caller of this is asking "is there a node here to read"
// and an index past the end answers that question the same way a blank does. The callers that
// need the two separated -- SetParent and Blank -- range check for themselves and answer
// ErrNodeIndexOutOfRange.
func (self *RatchetTree) Get(x NodeIndex) *Node {
	if uint32(x) >= self.NodeWidth() {
		return nil
	}
	return self.nodes[x]
}

// Leaf answers the leaf at i, or nil if that position is blank or outside the tree.
//
// The leaf index is range checked HERE and not left to Get's node index check, because
// LeafIndex.NodeIndex is total and wraps: leaf 2^31 answers node 0, so without this check
// Leaf(2^31) would hand back leaf 0's contents as though they were its own.
func (self *RatchetTree) Leaf(i LeafIndex) *LeafNode {
	if LeafCount(i) >= self.LeafWidth() {
		return nil
	}
	node := self.Get(i.NodeIndex())
	if node == nil {
		return nil
	}
	return node.Leaf
}

// ParentAt answers the parent node at x, or nil if that position is blank, outside the tree, or
// holds a leaf.
func (self *RatchetTree) ParentAt(x NodeIndex) *ParentNode {
	node := self.Get(x)
	if node == nil {
		return nil
	}
	return node.Parent
}

// SetLeaf installs a leaf, growing the tree if the index is past its current width.
//
// A nil leaf is REFUSED rather than stored. Storing it would make the position occupied and
// empty at once -- IsBlank would answer false, Leaf would answer nil -- which is exactly the
// blank as zero valued node conflation this file exists to prevent, and the encoder would then
// have a present node with nothing to write. Blank is how a position is emptied.
func (self *RatchetTree) SetLeaf(i LeafIndex, leaf *LeafNode) error {
	if leaf == nil {
		return ErrTreeMalformed
	}
	if LeafCount(i) >= MaxLeafCount {
		return ErrLeafIndexOutOfRange
	}
	if err := self.growTo(LeafCount(i) + 1); err != nil {
		return err
	}
	self.setNode(i.NodeIndex(), &Node{NodeType: NodeTypeLeaf, Leaf: leaf})
	return nil
}

// SetParent installs a parent node at an odd index inside the current tree.
//
// It does NOT grow. A parent node above a leaf that is not in the tree is not a position the
// tree has, and growing on its behalf would invent a subtree nobody added a member to. A nil
// parent is refused for SetLeaf's reason.
func (self *RatchetTree) SetParent(x NodeIndex, parent *ParentNode) error {
	if x.IsLeaf() {
		return ErrNodeTypeMismatch
	}
	if parent == nil {
		return ErrTreeMalformed
	}
	if uint32(x) >= self.NodeWidth() {
		return ErrNodeIndexOutOfRange
	}
	self.setNode(x, &Node{NodeType: NodeTypeParent, Parent: parent})
	return nil
}

// Blank empties a position. The entry becomes ABSENT -- a nil, which is what the encoder writes
// a zero presence octet for -- and never a zero valued Node.
func (self *RatchetTree) Blank(x NodeIndex) error {
	if uint32(x) >= self.NodeWidth() {
		return ErrNodeIndexOutOfRange
	}
	self.setNode(x, nil)
	return nil
}

// BlankDirectPath blanks every parent node between the leaf and the root.
//
// The leaf ITSELF is left alone, because Update and Remove differ only in what they put back
// there: an update installs a new leaf, a remove blanks it, and both blank the same path above.
func (self *RatchetTree) BlankDirectPath(i LeafIndex) error {
	if LeafCount(i) >= self.LeafWidth() {
		return ErrLeafIndexOutOfRange
	}
	path, err := directPathOf(i.NodeIndex(), self.LeafWidth())
	if err != nil {
		return err
	}
	for _, x := range path {
		if err := self.Blank(x); err != nil {
			return err
		}
	}
	return nil
}

// Clone answers a tree that shares no storage with this one, at every depth.
//
// A blank stays a blank: a nil entry clones to a nil entry rather than to an occupied position
// holding a zero valued node, which is the same distinction the wire format draws and the one a
// deep copy is likeliest to lose.
func (self *RatchetTree) Clone() *RatchetTree {
	out := &RatchetTree{nodes: make([]*Node, len(self.nodes))}
	for i, node := range self.nodes {
		if node != nil {
			out.nodes[i] = node.Clone()
		}
	}
	return out
}

// NonBlankLeaves is every occupied leaf slot, ascending.
func (self *RatchetTree) NonBlankLeaves() []LeafIndex {
	out := []LeafIndex{}
	for i := uint32(0); i < uint32(self.LeafWidth()); i += 1 {
		if self.Leaf(LeafIndex(i)) != nil {
			out = append(out, LeafIndex(i))
		}
	}
	return out
}

// Members is NonBlankLeaves under the name the group lifecycle plan uses for it. One
// implementation and not two: a membership list and an occupied leaf list that could ever
// disagree is a group whose roster depends on which question was asked.
func (self *RatchetTree) Members() []LeafIndex {
	return self.NonBlankLeaves()
}

func (self *RatchetTree) MemberCount() uint32 {
	return uint32(len(self.NonBlankLeaves()))
}

// FindLeafBySignatureKey answers the leaf holding this signature key.
//
// The comparison is constant time even though a signature public key is not a secret, because
// what is being protected is not the key but the ANSWER: this runs over every member of a group
// on a path a peer can trigger, and a comparison that returned early would leak how far a
// probed key matched a member's.
func (self *RatchetTree) FindLeafBySignatureKey(key SignaturePublicKey) (LeafIndex, bool) {
	for i := uint32(0); i < uint32(self.LeafWidth()); i += 1 {
		leaf := self.Leaf(LeafIndex(i))
		if leaf == nil {
			continue
		}
		if subtle.ConstantTimeCompare(leaf.SignatureKey, key) == 1 {
			return LeafIndex(i), true
		}
	}
	return 0, false
}

// EncryptionKeyInUse asks whether this HPKE public key is already at some node, leaf or parent.
// The group lifecycle plan's ValSem103 and ValSem110 ask exactly this, once per proposal.
//
// Both kinds of node are read, and that is the whole of it: a duplicate key check that looked
// only at leaves would accept an add whose key is already a parent's, which is a member that
// can decrypt a path secret it was never sent.
func (self *RatchetTree) EncryptionKeyInUse(key HpkePublicKey) bool {
	for x := uint32(0); x < self.NodeWidth(); x += 1 {
		node := self.nodes[x]
		if node == nil {
			continue
		}
		if node.Leaf != nil && subtle.ConstantTimeCompare(node.Leaf.EncryptionKey, key) == 1 {
			return true
		}
		if node.Parent != nil && subtle.ConstantTimeCompare(node.Parent.EncryptionKey, key) == 1 {
			return true
		}
	}
	return false
}

// HasTrailingBlankNodes reports whether the array ends in a blank, which RFC 9420 section
// 12.4.3.1 forbids of an exported ratchet_tree and which ValSem300 refuses.
//
// The LAST node and not a scan, because the node width of any tree is odd and the last index of
// an odd width array is even: the final position is always a leaf, so "the array ends in a
// blank" and "the rightmost leaf is blank" are one question. It is a read of the node array, so
// it lives here rather than being re-derived from the encoding in two other plans.
func (self *RatchetTree) HasTrailingBlankNodes() bool {
	return len(self.nodes) > 0 && self.nodes[len(self.nodes)-1] == nil
}

// ---- NodeShape, so the tree math plan's Resolution and FilteredDirectPath run against a real
// tree. This is what lets that plan hold no resolution algorithm of its own.

func (self *RatchetTree) LeafCount() LeafCount {
	return self.LeafWidth()
}

// IsBlank is the absence test, and it is the same nil the encoder writes a zero presence octet
// for. An index outside the tree reports blank, matching Get.
func (self *RatchetTree) IsBlank(x NodeIndex) bool {
	return self.Get(x) == nil
}

// UnmergedLeaves answers the node's STORED list in stored order.
//
// Stored order and not sorted order: tree_math.go's NodeShape contract says so, and the reason
// is that a repair here would hide the tree that needs rejecting. Sortedness is refused at the
// codec boundary, where the bytes a tree hash is taken over are decided, and checked again by
// whole tree validation; it is not something a resolution walk silently fixes up.
func (self *RatchetTree) UnmergedLeaves(x NodeIndex) []LeafIndex {
	parent := self.ParentAt(x)
	if parent == nil {
		return nil
	}
	return parent.UnmergedLeaves
}

var _ NodeShape = (*RatchetTree)(nil)
