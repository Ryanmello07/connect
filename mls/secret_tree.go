// the RFC 9420 section 9 secret tree: the per-sender key material of one epoch, and the
// deletions that make it forward secret.
//
// The tree is walked lazily and destructively. encryption_secret sits at the root, and a
// node secret is expanded into its two children and then erased, so the one value that
// could regenerate a whole subtree stops existing the moment any leaf under it has been
// reached. That erasure is the entire point of the section: every correctness question
// ("what is this leaf's secret?") is answered identically by an implementation that keeps
// every parent forever, and the only question that separates the two is what an attacker
// who takes the process a second later can still derive.
//
// Two things follow, worth stating because neither is obvious from the derivation alone.
// First, deletion is downward-closed but derivation is downward-only: from the secrets that
// remain, no expansion sequence reaches a secret that has been deleted, which is why "take
// the leaf, then erase the path above it" is enough. Second, taking a leaf twice is refused
// rather than answered, because answering it would mean the tree had kept a value it
// promised to destroy.
//
// The tree is always full. RFC 9420 section 7.7 makes a valid leaf count a power of two,
// and p3's Root refuses any other, so every parent reached here has both of its children
// inside the node array.
package mls

import (
	"fmt"
	"sync"
)

// SecretTree holds the node secrets of one epoch that no leaf has consumed yet.
//
// stateLock guards nodes, the only mutable field. crypto, leafCount, width, depth and root
// are written once by the constructor and read without it, which is what lets an exported
// method hold the lock and still read the count. Every unexported helper in this file
// assumes its caller holds stateLock; every exported entry point that touches nodes takes
// it. LeafCount deliberately does NOT take it, so a later exported method can report the
// count while holding it without deadlocking on its own accessor.
type SecretTree struct {
	stateLock sync.Mutex
	crypto    CryptoProvider
	leafCount LeafCount
	width     uint32
	depth     uint32
	root      NodeIndex
	nodes     map[NodeIndex][]byte
}

// NewSecretTree seeds the tree with encryption_secret at the root.
//
// leafCount is a LeafCount and not a LeafIndex (registry override O-4). Both are uint32
// underneath, so the compiler cannot separate them at a call site that passes the wrong
// one, and the wrong one here is the off-by-one that makes the last member of the group
// unreachable while every other leaf still answers.
//
// Root is two-valued and its error is handled rather than shimmed away (convention C3). A
// shim that turned it into node zero would build a tree whose descent starts at a leaf and
// never terminates, and would accept a leaf count of zero and of three. Its sentinel is
// wrapped alongside this package's own, so a caller can ask either "is this a secret tree
// range failure" or "was the leaf count not a power of two" and get the true answer.
func NewSecretTree(crypto CryptoProvider, leafCount LeafCount, encryptionSecret []byte) (*SecretTree, error) {
	if crypto == nil {
		return nil, fmt.Errorf("%w: no crypto provider", ErrSecretLength)
	}
	// measured redundant, and kept anyway: Root refuses zero with ErrLeafCountRange and this
	// constructor wraps that in the same ErrSecretTreeLeafOutOfRange, so deleting these three
	// lines leaves every test in this package passing. It stays for the message — "leaf count
	// is zero" names the caller's mistake and "leaf count out of range" names the library's
	// view of it — and because the check belongs to the precondition this function states.
	if leafCount == 0 {
		return nil, fmt.Errorf("%w: leaf count is zero", ErrSecretTreeLeafOutOfRange)
	}
	// the length is the provider's hash size and never a written down 32. Both registered
	// suites fix Nh at 32, so a literal here agrees with every vector in this tree and
	// silently disagrees with the five registered suites at Nh 48 and 64.
	if len(encryptionSecret) != crypto.HashSize() {
		return nil, fmt.Errorf("%w: encryption secret is %d bytes, want %d",
			ErrSecretLength, len(encryptionSecret), crypto.HashSize())
	}
	root, err := Root(leafCount)
	if err != nil {
		return nil, fmt.Errorf("%w: leaf count %d: %w", ErrSecretTreeLeafOutOfRange, leafCount, err)
	}
	width := NodeWidth(leafCount)
	if width == 0 {
		// unreachable behind Root, which refuses every count NodeWidth answers zero for.
		// It is kept because this constructor should enforce its own precondition rather
		// than inherit it from the function it happens to call first, and because a width
		// of zero would put every child of every parent outside the array.
		return nil, fmt.Errorf("%w: leaf count %d has no node array", ErrSecretTreeLeafOutOfRange, leafCount)
	}
	self := &SecretTree{
		crypto:    crypto,
		leafCount: leafCount,
		width:     width,
		depth:     TreeDepth(leafCount),
		root:      root,
		// the copy is deliberate: the tree erases what it holds, and erasing a caller's
		// slice in place would zero a secret the key schedule still owns.
		nodes: map[NodeIndex][]byte{root: append([]byte(nil), encryptionSecret...)},
	}
	return self, nil
}

// LeafCount is the number of leaves the tree was built for.
//
// No lock: leafCount is written once by the constructor. See the type's comment for why
// that is a requirement here rather than an optimisation.
func (self *SecretTree) LeafCount() LeafCount {
	return self.leafCount
}

// pathToLeaf returns the node indices from the root down to the leaf, inclusive.
//
// The array representation is in-order, so every index in a parent's left subtree is below
// the parent and every index in its right subtree is above it. That comparison is the whole
// descent rule and it needs no parent lookups; the children themselves come from p3's Left
// and Right, so the rule chooses the direction and tree math supplies the node.
//
// The loop is bounded by the tree's own depth rather than left to terminate on an argument
// about Level. It cannot run away for a validated index — Left and Right of a level k node
// are level k-1 — but a structural bound makes termination a property of the code, and the
// bound is derived from the leaf count, so a tree twice as deep walks exactly one step
// further.
//
// The caller holds stateLock, though this function reads no guarded state; it is documented
// that way so the whole unexported surface has one rule.
func (self *SecretTree) pathToLeaf(leaf LeafIndex) ([]NodeIndex, error) {
	if LeafCount(leaf) >= self.leafCount {
		return nil, fmt.Errorf("%w: leaf %d of %d", ErrSecretTreeLeafOutOfRange, leaf, self.leafCount)
	}
	target := leaf.NodeIndex()
	// LeafIndex.NodeIndex is total and wraps at 2^31, so this is what would catch a wrapped
	// index if the count check above ever stopped catching it first. Measured: behind that
	// check it is unreachable, and it is kept for the reason p3's DirectPath keeps a range
	// check Parent already makes — a function enforcing its own precondition rather than
	// inheriting it from the one it happens to call.
	if uint32(target) >= self.width {
		return nil, fmt.Errorf("%w: node %d of width %d", ErrSecretTreeLeafOutOfRange, target, self.width)
	}
	path := make([]NodeIndex, 0, self.depth+1)
	path = append(path, self.root)
	current := self.root
	for steps := uint32(0); current.Level() > 0; steps++ {
		if steps >= self.depth {
			return nil, fmt.Errorf("%w: descent from node %d ran past depth %d",
				ErrSecretTreeLeafOutOfRange, self.root, self.depth)
		}
		var next NodeIndex
		var err error
		if target < current {
			next, err = Left(current)
		} else {
			next, err = Right(current)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: descent from node %d: %w", ErrSecretTreeLeafOutOfRange, current, err)
		}
		current = next
		path = append(path, current)
	}
	if current != target {
		return nil, fmt.Errorf("%w: descent reached node %d, want %d",
			ErrSecretTreeLeafOutOfRange, current, target)
	}
	return path, nil
}

// takeLeafSecret derives and removes the node secret of one leaf, expanding and then
// erasing every ancestor still held along the way.
//
// The caller owns the returned slice and is expected to erase it once both ratchet roots
// exist; this function does not erase it, because the value has to survive the return.
//
// The erasure ORDER is load-bearing and is the one thing here that no correctness test of
// the taken leaf can see: both children are written before the parent is zeroized. Zeroizing
// between the two derives the right child from a run of zeros — a value any party can
// compute with no knowledge of the group — and every leaf under it stays self-consistent, so
// only a comparison against an independent derivation notices.
//
// The caller holds stateLock.
//
// The noinline directive is here because this package's erase-helper gate derives its class
// as "every function that writes through storage outliving the call", and the writes into
// self.nodes put this function in it. Two honest notes about that. The gate is right that
// this function erases -- zeroizeSecret is called from here and the deletion is this
// function's job -- and it is over-broad about why: a map store is a runtime call with
// observable effects, not a store a compiler may delete, so the directive protects the
// zeroize inside zeroizeSecret (which carries its own) rather than anything written here.
// It costs nothing either way; a body this size is far past the inliner's budget.
//
//go:noinline
func (self *SecretTree) takeLeafSecret(leaf LeafIndex) ([]byte, error) {
	path, err := self.pathToLeaf(leaf)
	if err != nil {
		return nil, err
	}
	// the deepest node still held, not the first: the ancestors above it have already been
	// expanded and erased on behalf of an earlier leaf, and starting from the root would
	// need a secret that no longer exists.
	deepest := -1
	for i, node := range path {
		if _, ok := self.nodes[node]; ok {
			deepest = i
		}
	}
	if deepest < 0 {
		return nil, fmt.Errorf("%w: leaf %d", ErrSecretTreeConsumed, leaf)
	}
	nh := self.crypto.HashSize()
	for i := deepest; i < len(path)-1; i++ {
		parent := path[i]
		parentSecret := self.nodes[parent]
		left, err := Left(parent)
		if err != nil {
			return nil, fmt.Errorf("%w: left child of node %d: %w", ErrSecretTreeLeafOutOfRange, parent, err)
		}
		right, err := Right(parent)
		if err != nil {
			return nil, fmt.Errorf("%w: right child of node %d: %w", ErrSecretTreeLeafOutOfRange, parent, err)
		}
		// ExpandWithLabel returns a fresh slice, so the parent can be zeroized after both
		// stores without touching either child.
		if uint32(left) < self.width {
			self.nodes[left] = self.crypto.ExpandWithLabel(parentSecret, "tree", []byte("left"), nh)
		}
		if uint32(right) < self.width {
			self.nodes[right] = self.crypto.ExpandWithLabel(parentSecret, "tree", []byte("right"), nh)
		}
		zeroizeSecret(parentSecret)
		delete(self.nodes, parent)
	}
	target := path[len(path)-1]
	secret, ok := self.nodes[target]
	if !ok {
		return nil, fmt.Errorf("%w: leaf %d", ErrSecretTreeConsumed, leaf)
	}
	delete(self.nodes, target)
	return secret, nil
}
