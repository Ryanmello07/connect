// The RFC 9420 section 7.8 tree hash, which is what GroupContext.TreeHash carries and what
// the key schedule therefore binds every epoch's secrets to.
//
// A tree hash that differs by one byte between two implementations is not a validation
// failure, it is a FORK: each side's group context is internally consistent, each side signs
// and verifies against its own, and the two stop agreeing from the first commit onward with
// nothing on the wire that names the disagreement. That is why the tests beside this file are
// weighted the way they are. Self-consistency proves nothing here -- an encoder that writes
// the leaf index after the leaf instead of before it writes it that way every time and agrees
// with itself forever -- so the assertions that can see a defect are the published
// tree-validation corpus, whose hashes this repository did not compute, and a hand-derived
// golden whose preimage is written out byte by byte from the struct definitions below.
package mls

import (
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// leafHashInput is TreeHashInput's leaf arm:
//
//	struct { uint32 leaf_index; optional<LeafNode> leaf_node; } LeafNodeHashInput;
//
// The leaf INDEX is inside the hash input, which is what makes a blank position distinguishable
// from every other blank position: without it every empty leaf of a tree hashes to the same
// value and a tree with two blanks agrees with a tree that has them elsewhere. optional<LeafNode>
// goes through WriteOptional so the presence octet has one implementation and one canonical
// spelling, rather than a second 0-or-1 written here.
func (self *RatchetTree) leafHashInput(w *syntax.Writer, i LeafIndex, leaf *LeafNode) error {
	w.WriteUint8(uint8(NodeTypeLeaf))
	w.WriteUint32(uint32(i))
	return w.WriteOptional(leaf != nil, func(w *syntax.Writer) error {
		return leaf.MarshalMLS(w)
	})
}

// parentHashInput is TreeHashInput's parent arm:
//
//	struct { optional<ParentNode> parent_node; opaque left_hash<V>; opaque right_hash<V>; }
//
// The order of the two child hashes is the whole content of this function and it is not
// recoverable from any tree that is symmetric at the point it is tested. leftHash first.
func (self *RatchetTree) parentHashInput(w *syntax.Writer, parent *ParentNode,
	leftHash, rightHash []byte) error {
	w.WriteUint8(uint8(NodeTypeParent))
	if err := w.WriteOptional(parent != nil, func(w *syntax.Writer) error {
		return parent.MarshalMLS(w)
	}); err != nil {
		return err
	}
	w.WriteOpaque(leftHash)
	w.WriteOpaque(rightHash)
	return nil
}

// treeHash is the hash of the subtree rooted at x, with the leaves in exclude treated as blank
// and every descendant parent node's unmerged_leaves filtered by the same set.
//
// exclude is nil for an ordinary tree hash and is the parent's unmerged_leaves when computing
// an ORIGINAL tree hash for a parent hash, RFC 9420 section 7.9. One recursion serves both, on
// purpose: the original tree hash is the section 7.8 hash of a tree the unmerged leaves were
// never added to, so a second walk that re-derived the same encoding would be a second place
// for the field order to be wrong, and the two would diverge silently because only one of them
// is what the published corpus checks.
//
// A blank position is still hashed, at its own index, rather than skipped -- see leafHashInput.
func (self *RatchetTree) treeHash(crypto CryptoProvider, x NodeIndex,
	exclude map[LeafIndex]bool) ([]byte, error) {
	if crypto == nil {
		return nil, fmt.Errorf("%w: every node's hash input is hashed through it", ErrNilCryptoProvider)
	}
	if uint32(x) >= self.NodeWidth() {
		return nil, ErrNodeIndexOutOfRange
	}
	if x.IsLeaf() {
		i, ok := leafIndexOf(x)
		if !ok {
			return nil, ErrTreeMalformed
		}
		leaf := self.Leaf(i)
		if exclude != nil && exclude[i] {
			leaf = nil
		}
		input, err := marshalBytes(func(w *syntax.Writer) error {
			return self.leafHashInput(w, i, leaf)
		})
		if err != nil {
			return nil, err
		}
		return crypto.Hash(input), nil
	}
	left, ok := leftOf(x)
	if !ok {
		return nil, ErrTreeMalformed
	}
	right, ok := rightOf(x)
	if !ok {
		return nil, ErrTreeMalformed
	}
	leftHash, err := self.treeHash(crypto, left, exclude)
	if err != nil {
		return nil, err
	}
	rightHash, err := self.treeHash(crypto, right, exclude)
	if err != nil {
		return nil, err
	}
	parent := self.ParentAt(x)
	if parent != nil && exclude != nil && len(parent.UnmergedLeaves) > 0 {
		// the filtered copy is a Clone and never the tree's own node: this walk runs over a
		// live tree during a parent hash check, and dropping entries in place would leave the
		// caller holding a tree whose unmerged lists the exclusion had eaten.
		filtered := parent.Clone()
		kept := filtered.UnmergedLeaves[:0]
		for _, leaf := range parent.UnmergedLeaves {
			if !exclude[leaf] {
				kept = append(kept, leaf)
			}
		}
		filtered.UnmergedLeaves = kept
		parent = filtered
	}
	input, err := marshalBytes(func(w *syntax.Writer) error {
		return self.parentHashInput(w, parent, leftHash, rightHash)
	})
	if err != nil {
		return nil, err
	}
	return crypto.Hash(input), nil
}

// NodeTreeHash is the tree hash of the subtree rooted at x. ErrNodeIndexOutOfRange for an index
// outside this tree, which is a different answer from the hash of a blank node -- the blank is
// inside the tree and hashes.
func (self *RatchetTree) NodeTreeHash(crypto CryptoProvider, x NodeIndex) ([]byte, error) {
	if crypto == nil {
		return nil, fmt.Errorf("%w: the subtree's hash is taken through it", ErrNilCryptoProvider)
	}
	return self.treeHash(crypto, x, nil)
}

// TreeHash is the whole tree's hash, which is what GroupContext.TreeHash is set from.
func (self *RatchetTree) TreeHash(crypto CryptoProvider) ([]byte, error) {
	// before rootOf and not after it: a zero valued tree answers ErrTreeMalformed from the
	// arithmetic, and a caller who passed no provider would be sent to look at its tree.
	if crypto == nil {
		return nil, fmt.Errorf("%w: the whole tree's hash is taken through it", ErrNilCryptoProvider)
	}
	root, err := rootOf(self.LeafWidth())
	if err != nil {
		return nil, err
	}
	return self.treeHash(crypto, root, nil)
}

// TreeHashes is every node's tree hash, indexed by node index; the tree-validation vector
// publishes exactly this column and checks all of it.
//
// It re-walks each subtree rather than memoising, so it costs about 2n*log(n) hash calls for an
// n leaf tree rather than the 2n-1 a single bottom up pass would. That is deliberate and it is
// not a placeholder: the alternative is a second encoder for the same structure, and the one
// thing this file must not have is two ways to compute the same hash. It is called once per
// parent-hash check, over trees of a few hundred nodes, and TestTreeHashesIndexedByNode is what
// holds it equal to NodeTreeHash entry for entry.
func (self *RatchetTree) TreeHashes(crypto CryptoProvider) ([][]byte, error) {
	// before the loop, which a tree of no nodes never enters: without this, no provider and an
	// empty tree would answer an empty slice and a nil error rather than a refusal.
	if crypto == nil {
		return nil, fmt.Errorf("%w: every node's hash is taken through it", ErrNilCryptoProvider)
	}
	out := make([][]byte, self.NodeWidth())
	for x := uint32(0); x < self.NodeWidth(); x += 1 {
		hash, err := self.treeHash(crypto, NodeIndex(x), nil)
		if err != nil {
			return nil, err
		}
		out[x] = hash
	}
	return out, nil
}
