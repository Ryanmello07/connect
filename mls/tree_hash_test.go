// The tests for the RFC 9420 section 7.8 tree hash.
//
// The weighting here is not the usual one, and the reason is in tree_hash.go's file comment: a
// tree hash that disagrees with another implementation by one byte is a FORK rather than a
// failure, so an assertion that only holds this package to itself is worth almost nothing. An
// encoder that writes the leaf index after the leaf, or the right subtree's hash before the
// left, or drops the presence octet on a blank, is perfectly self-consistent -- it produces one
// stable answer, it round trips, every mutation of the tree still moves it, and the group it
// builds is internally coherent and permanently invisible to everybody else.
//
// So there are three kinds of assertion below and only the last two can see that defect:
//
//   - the plan's three, which say the hash moves when the tree moves. They catch a hash that
//     ignores an input. They do not catch a hash that reads every input in the wrong order.
//   - a hand-derived golden, whose PREIMAGES are written out octet by octet from the section
//     7.8 struct definitions and whose digests were computed outside this repository. It pins
//     the structure -- the node type octet, the width and position of leaf_index, the presence
//     octet on a blank, the order of optional<ParentNode>, left_hash and right_hash -- rather
//     than merely pinning that the structure is stable.
//   - the published tree-validation corpus, whose 908 answers for the two suites this package
//     registers were computed by the working group's implementations and not by this one.
package mls

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"
)

// ---------------------------------------------------------------------------
// the plan's three: the hash moves when the tree moves
// ---------------------------------------------------------------------------

// treeHashObservableVariants is the family the sweep below runs over: this tree, and every one
// step change to it the container can make, DERIVED from the tree's own width rather than
// written out here.
//
// The five hand written mutations this replaced -- blank a leaf, swap two leaves, set a
// parent, add an unmerged, grow the tree -- were a list, and a list is the thing this project
// keeps finding to be narrower than the class it names. Those five blanked node 2 and no other
// node, set a parent at node 1 and no other position, and never moved a leaf that was not leaf
// 0 or leaf 2, so a hash that read one arm of the recursion and not another had nowhere to
// fail. What is derived here is every node of the tree for the blanking, every parent position
// for the parent node, every parent position crossed with every leaf for the unmerged entry,
// every PAIR of leaves for the swap, and the growth, off NodeWidth and LeafWidth rather than
// off a number typed beside them.
func treeHashObservableVariants(t *testing.T, tree *RatchetTree) map[string]*RatchetTree {
	t.Helper()
	variants := map[string]*RatchetTree{"the tree itself": tree.Clone()}
	add := func(what string, change func(clone *RatchetTree) error) {
		t.Helper()
		if _, taken := variants[what]; taken {
			t.Fatalf("two rows of the derived family are named %q, so one of them is not being hashed", what)
		}
		clone := tree.Clone()
		if err := change(clone); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		variants[what] = clone
	}
	width := uint32(tree.LeafWidth())
	parentKey := HpkePublicKey(bytes.Repeat([]byte{0x01}, 32))
	for x := uint32(0); x < tree.NodeWidth(); x += 1 {
		add(fmt.Sprintf("blank node %d", x), func(clone *RatchetTree) error {
			return clone.Blank(NodeIndex(x))
		})
		if NodeIndex(x).IsLeaf() {
			continue
		}
		add(fmt.Sprintf("a parent node at %d", x), func(clone *RatchetTree) error {
			return clone.SetParent(NodeIndex(x), &ParentNode{EncryptionKey: parentKey})
		})
		for i := uint32(0); i < width; i += 1 {
			add(fmt.Sprintf("leaf %d unmerged at node %d", i, x), func(clone *RatchetTree) error {
				return clone.SetParent(NodeIndex(x), &ParentNode{
					EncryptionKey:  parentKey,
					UnmergedLeaves: []LeafIndex{LeafIndex(i)},
				})
			})
		}
	}
	for i := uint32(0); i < width; i += 1 {
		for j := i + 1; j < width; j += 1 {
			add(fmt.Sprintf("swap leaves %d and %d", i, j), func(clone *RatchetTree) error {
				at, other := tree.Leaf(LeafIndex(i)), tree.Leaf(LeafIndex(j))
				if at == nil || other == nil {
					t.Fatalf("leaf %d or leaf %d is blank in the base tree, so this row is not the change it is named for", i, j)
				}
				if err := clone.SetLeaf(LeafIndex(i), other); err != nil {
					return err
				}
				return clone.SetLeaf(LeafIndex(j), at)
			})
		}
	}
	add("a leaf past the current width", func(clone *RatchetTree) error {
		return clone.SetLeaf(LeafIndex(width), tree.Leaf(LeafIndex(0)).Clone())
	})
	return variants
}

// TestTreeHashChangesWithEveryObservableChange states the claim its name makes as INJECTIVITY
// over that derived family: two trees that are different on the wire never share a tree hash.
//
// "Observable" is read off the tree's own encoder rather than decided in this file, which is
// what makes the name honest. The converse is deliberately NOT asserted, and must not be:
// MarshalMLS truncates trailing blank nodes, so a four leaf tree whose last leaf is blank
// encodes as the three leaf array does and hashes differently, and that is a property of the
// wire format rather than a defect of the hash.
//
// What an inequality still cannot see is written here so nobody reads this test as more than
// it is. A hash that reads every input in the WRONG ORDER is injective too: left before right,
// the leaf index before the leaf node, the presence octet on a blank -- flipping any of those
// keeps every tree in this family separate and changes the group. Measured, not supposed: the
// version this replaced passed under a left/right swap in parentHashInput, under a deleted
// leaf index, under a deleted node type octet and under a swap of two fields of
// LeafNode.marshalCore. Those are held by the hand derived goldens below and by the published
// corpus at the end of this file, which is the whole weighting this file's header describes.
func TestTreeHashChangesWithEveryObservableChange(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	tree, _ := newTestTree(t, crypto, 4)
	base, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	if len(base) != crypto.HashSize() {
		t.Fatalf("tree hash length = %d, want %d", len(base), crypto.HashSize())
	}
	variants := treeHashObservableVariants(t, tree)
	// the size is the derivation restated in arithmetic: the tree itself, one row per node for
	// the blanking, one per parent position, one per parent position and leaf for the unmerged
	// entry, one per unordered pair of leaves for the swap, and the growth. a family that came
	// back smaller than this is a derivation that read the width wrong, and it would report a
	// clean sweep having compared almost nothing.
	nodes, leaves := tree.NodeWidth(), uint32(tree.LeafWidth())
	parents := nodes - leaves
	if want := 1 + nodes + parents + parents*leaves + leaves*(leaves-1)/2 + 1; uint32(len(variants)) != want {
		t.Fatalf("the derived family holds %d trees, want %d over a %d node %d leaf tree",
			len(variants), want, nodes, leaves)
	}
	byHash := map[string]string{}
	byEncoding := map[string]string{}
	encoded := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(variants)) {
		wire, err := marshalRatchetTree(variants[name])
		if err != nil {
			t.Fatalf("%s: marshalRatchetTree: %v", name, err)
		}
		hash, err := variants[name].TreeHash(crypto)
		if err != nil {
			t.Fatalf("%s: TreeHash: %v", name, err)
		}
		encoded[name] = string(wire)
		if prior, seen := byHash[string(hash)]; seen && encoded[prior] != string(wire) {
			t.Errorf("%q and %q are different trees on the wire and share the tree hash %x", name, prior, hash)
		}
		byHash[string(hash)] = name
		byEncoding[string(wire)] = name
	}
	// the pairwise check above only ever compares a collision against the LAST tree that hashed
	// to it, so the counts are the half that cannot be walked past: every distinct encoding owes
	// a distinct hash, and fewer hashes than encodings is a collision whichever pair it was.
	if len(byHash) < len(byEncoding) {
		t.Errorf("the family holds %d trees that differ on the wire and only %d distinct tree hashes",
			len(byEncoding), len(byHash))
	}
	if len(byEncoding) < 2 {
		t.Fatalf("every tree in the family encodes the same, so no pair of them could have failed above")
	}
	t.Logf("%d derived trees, %d distinct on the wire, %d distinct tree hashes",
		len(variants), len(byEncoding), len(byHash))
}

func TestTreeHashesIndexedByNode(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 5)
	hashes, err := tree.TreeHashes(crypto)
	if err != nil {
		t.Fatalf("TreeHashes: %v", err)
	}
	if uint32(len(hashes)) != tree.NodeWidth() {
		t.Fatalf("len(TreeHashes) = %d, want %d", len(hashes), tree.NodeWidth())
	}
	for x := uint32(0); x < tree.NodeWidth(); x += 1 {
		one, err := tree.NodeTreeHash(crypto, NodeIndex(x))
		if err != nil {
			t.Fatalf("NodeTreeHash(%d): %v", x, err)
		}
		if !bytes.Equal(one, hashes[x]) {
			t.Fatalf("node %d: TreeHashes disagrees with NodeTreeHash", x)
		}
	}
	rootHash, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	root, err := rootOf(tree.LeafWidth())
	if err != nil {
		t.Fatalf("rootOf: %v", err)
	}
	if !bytes.Equal(rootHash, hashes[root]) {
		t.Fatalf("TreeHash is not the root entry of TreeHashes")
	}
}

// TestBlankLeafStillHashesAtItsIndex says both halves of its own name as BYTES: a blank
// position is HASHED rather than skipped -- the zero presence octet is in the preimage -- and
// what it is hashed with is ITS OWN index.
//
// It used to say only that two blanks at different indices differ, and that was measured to be
// a claim the implementation can break while keeping. With leafHashInput returning early for a
// nil leaf, so a blank writes no presence octet at all, leaf 0 hashed 01 00000000 and leaf 1
// hashed 01 00000001: still different, still passing, and a different group from every other
// implementation. An inequality cannot see what is IN a preimage.
//
// So the preimage is written out here octet by octet, the two rows the corpus of this file
// already holds digests for are checked against those digests -- computed outside this
// repository, which is what makes the spelling section 7.8's rather than this file's -- and
// the tree is asked about EVERY leaf it has rather than about two of them.
func TestBlankLeafStillHashesAtItsIndex(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	tree, _ := newTestTree(t, crypto, 4)
	for x := uint32(0); x < tree.NodeWidth(); x += 1 {
		if err := tree.Blank(NodeIndex(x)); err != nil {
			t.Fatalf("Blank(%d): %v", x, err)
		}
	}
	// the goldens this file carries for leaf 0 and leaf 1 are the same two blank leaf
	// preimages, so the sweep below is anchored at both ends of a uint32 low octet rather than
	// hashing a spelling only this file has ever agreed with.
	published := map[uint32]string{
		0: blankTwoLeafTreeLeafZeroHash,
		1: blankTwoLeafTreeLeafOneHash,
	}
	anchored := 0
	seen := map[string]uint32{}
	width := uint32(tree.LeafWidth())
	if width < 2 {
		t.Fatalf("the tree is %d leaves wide, so no two indices could differ here", width)
	}
	for i := uint32(0); i < width; i += 1 {
		//	01 <leaf index as uint32> 00
		//	node_type=leaf(1), the index this position has and no other, and the presence
		//	octet that spells "there is no leaf here" rather than nothing at all
		want := crypto.Hash(treeHashTestConcat(
			[]byte{byte(NodeTypeLeaf)},
			[]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)},
			[]byte{0x00},
		))
		if golden, isPublished := published[i]; isPublished {
			if got := fmt.Sprintf("%x", want); got != golden {
				t.Fatalf("the hand written blank preimage for leaf %d hashes to %s, want %s; the preimage above and the golden no longer agree",
					i, got, golden)
			}
			anchored += 1
		}
		got, err := tree.NodeTreeHash(crypto, LeafIndex(i).NodeIndex())
		if err != nil {
			t.Fatalf("NodeTreeHash(leaf %d): %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("blank leaf %d hashes to %x, want %x -- node_type, the leaf index as a uint32, then the zero presence octet",
				i, got, want)
		}
		if prior, collided := seen[string(got)]; collided {
			t.Errorf("blank leaf %d hashes the same as blank leaf %d", i, prior)
		}
		seen[string(got)] = i
	}
	if anchored != len(published) {
		t.Errorf("%d of the %d published blank leaf digests were reached, so the sweep is hashing a spelling nothing outside this repository has checked",
			anchored, len(published))
	}
}

// ---------------------------------------------------------------------------
// the hand-derived golden
// ---------------------------------------------------------------------------

// treeHashTestOpaque is opaque<V> of RFC 9420 section 2.1.2, written here rather than reached
// through syntax.Writer.
//
// A preimage assembled with the encoder under test cannot separate two readings of that
// encoder, which is the whole point of the goldens below: if the length prefix were written at
// the wrong width, an expectation built with the same Writer would be wrong in exactly the same
// way and would still match. Only the one octet header is implemented, because every length
// these tests use is 63 or less, and a longer one is a fatal rather than a prefix this helper
// would have to be trusted about.
func treeHashTestOpaque(t *testing.T, bs []byte) []byte {
	t.Helper()
	if len(bs) > 0x3f {
		t.Fatalf("this hand written opaque<V> only spells the one octet header, and %d bytes needs more", len(bs))
	}
	return append([]byte{byte(len(bs))}, bs...)
}

// treeHashTestConcat joins the pieces of a preimage into a fresh slice, so no piece is aliased
// into the result and a later append cannot rewrite a preimage already hashed.
func treeHashTestConcat(pieces ...[]byte) []byte {
	out := []byte{}
	for _, piece := range pieces {
		out = append(out, piece...)
	}
	return out
}

// twoLeafBlankTree is a two leaf tree in which every one of the three nodes is blank.
//
// Built through the public surface -- newTestTree then Blank on each node -- rather than by
// reaching into the node array, so what is hashed is the same shape any other caller can
// produce, and so a Blank that stored a zero valued node instead of removing one would be
// visible here.
func twoLeafBlankTree(t *testing.T, crypto CryptoProvider) *RatchetTree {
	t.Helper()
	tree, _ := newTestTree(t, crypto, 2)
	if tree.NodeWidth() != 3 {
		t.Fatalf("a two member test tree is %d nodes wide, want 3", tree.NodeWidth())
	}
	for _, x := range []NodeIndex{0, 1, 2} {
		if err := tree.Blank(x); err != nil {
			t.Fatalf("Blank(%d): %v", x, err)
		}
	}
	for x := uint32(0); x < tree.NodeWidth(); x += 1 {
		if !tree.IsBlank(NodeIndex(x)) {
			t.Fatalf("node %d is not blank after Blank", x)
		}
	}
	return tree
}

// The three digests of the all blank two leaf tree, computed OUTSIDE this repository -- python
// hashlib over the preimages spelled beside them -- so they are an answer this package did not
// produce. sha256 is the hash of both registered suites, so one set of digests serves both.
//
//	leaf 0   01 00000000 00
//	         node_type=leaf(1), leaf_index=0 as uint32, optional<LeafNode> absent
//	      -> 36c159d76b52e03e496363607c5940227f62f4e048df344b050159bc97bba3d7
//	leaf 1   01 00000001 00
//	      -> a90d4563c6a0ae0417ab3110f1ba68592833465954774201b0a69e8c457dc6ad
//	node 1   02 00 20||h(leaf 0) 20||h(leaf 1)
//	         node_type=parent(2), optional<ParentNode> absent, then the two child hashes each
//	         as opaque<V>: 32 bytes is 0x20 in a one octet varint header
//	      -> d7c368e06ce04517a1a9378b8bee6e886ede978a91da686b94018602db996b23
const (
	blankTwoLeafTreeLeafZeroHash = "36c159d76b52e03e496363607c5940227f62f4e048df344b050159bc97bba3d7"
	blankTwoLeafTreeLeafOneHash  = "a90d4563c6a0ae0417ab3110f1ba68592833465954774201b0a69e8c457dc6ad"
	blankTwoLeafTreeRootHash     = "d7c368e06ce04517a1a9378b8bee6e886ede978a91da686b94018602db996b23"
)

// TestABlankSubtreeHashesToTheHandDerivedGolden is the assertion that a blank position is
// HASHED and not skipped, stated as bytes rather than as an inequality.
//
// The three plan tests above can only say that two blanks at different indices differ, which a
// preimage of nothing but the leaf index satisfies just as well as the RFC's does. What this
// says is which octets go in: the type tag, the four octet index, and the zero presence octet
// that is how "there is no leaf here" is spelled -- as opposed to writing nothing at all for a
// blank, which is a shorter preimage, a different digest and a different group.
func TestABlankSubtreeHashesToTheHandDerivedGolden(t *testing.T) {
	// the tree is built once and hashed under every registered suite. newTestTree's leaves list
	// one suite in their capabilities and section 7.3 validation refuses them under the other,
	// so the builder takes that provider. what the sweep is about is the HASH, and both
	// registered suites name sha256, so one set of goldens serves both or the two have drifted.
	tree := twoLeafBlankTree(t, mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519))
	for _, suite := range Suites() {
		crypto := mustProvider(t, suite)

		leafZero := treeHashTestConcat([]byte{byte(NodeTypeLeaf)}, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00})
		leafOne := treeHashTestConcat([]byte{byte(NodeTypeLeaf)}, []byte{0x00, 0x00, 0x00, 0x01}, []byte{0x00})
		wantZero := crypto.Hash(leafZero)
		wantOne := crypto.Hash(leafOne)
		root := treeHashTestConcat(
			[]byte{byte(NodeTypeParent)},
			[]byte{0x00},
			treeHashTestOpaque(t, wantZero),
			treeHashTestOpaque(t, wantOne),
		)
		wantRoot := crypto.Hash(root)

		// the digests first, against the values computed outside this repository. this is what
		// makes the preimages above a statement about section 7.8 rather than a restatement of
		// whatever this package happens to write.
		for _, one := range []struct {
			what string
			got  []byte
			want string
		}{
			{"leaf 0", wantZero, blankTwoLeafTreeLeafZeroHash},
			{"leaf 1", wantOne, blankTwoLeafTreeLeafOneHash},
			{"the root", wantRoot, blankTwoLeafTreeRootHash},
		} {
			if got := fmt.Sprintf("%x", one.got); got != one.want {
				t.Fatalf("suite %04x: the hand written preimage for %s hashes to %s, want %s; the golden and the preimage beside it no longer agree",
					suite, one.what, got, one.want)
			}
		}

		for _, one := range []struct {
			x    NodeIndex
			want []byte
			what string
		}{
			{0, wantZero, "blank leaf 0"},
			{2, wantOne, "blank leaf 1"},
			{1, wantRoot, "the blank root over two blank leaves"},
		} {
			got, err := tree.NodeTreeHash(crypto, one.x)
			if err != nil {
				t.Fatalf("suite %04x: NodeTreeHash(%d): %v", suite, one.x, err)
			}
			if !bytes.Equal(got, one.want) {
				t.Errorf("suite %04x: %s hashes to %x, want %x", suite, one.what, got, one.want)
			}
		}
		whole, err := tree.TreeHash(crypto)
		if err != nil {
			t.Fatalf("suite %04x: TreeHash: %v", suite, err)
		}
		if !bytes.Equal(whole, wantRoot) {
			t.Errorf("suite %04x: TreeHash of an all blank two leaf tree is %x, want %x", suite, whole, wantRoot)
		}
	}
}

// The digest of the same two leaf tree carrying one ParentNode at the root, computed outside
// this repository over the preimage spelled here.
//
//	ParentNode  20||01*32  00  04||00000001
//	            encryption_key = 32 octets of 0x01 as opaque<V>, parent_hash empty, then
//	            unmerged_leaves as a vector whose length prefix is in BYTES: one uint32 is 4
//	node 1      02 01 <ParentNode> 20||h(leaf 0) 20||h(leaf 1)
//	            node_type=parent(2), optional<ParentNode> PRESENT, the node, then the children
//	         -> e2b9595acece8a79b68ab0df30d4fe5d6bd8f7421912e64b93981ca0ef1c981d
const parentTwoLeafTreeRootHash = "e2b9595acece8a79b68ab0df30d4fe5d6bd8f7421912e64b93981ca0ef1c981d"

// TestAParentNodeHashesInTheHandDerivedOrder pins the parent arm's field order: the optional
// parent node comes BEFORE the two child hashes, and the parent node itself is
// encryption_key, parent_hash, unmerged_leaves.
//
// Nothing else in this file separates those orders. The plan's mutation table moves the hash
// when a parent is set and when an unmerged leaf is added, which a preimage that wrote the
// parent node after the child hashes -- or wrote its three fields in any other order -- moves
// exactly as well.
func TestAParentNodeHashesInTheHandDerivedOrder(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	tree := twoLeafBlankTree(t, crypto)
	parent := &ParentNode{
		EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x01}, 32)),
		UnmergedLeaves: []LeafIndex{1},
	}
	if err := tree.SetParent(NodeIndex(1), parent); err != nil {
		t.Fatalf("SetParent(1): %v", err)
	}
	leafZero := crypto.Hash(treeHashTestConcat([]byte{byte(NodeTypeLeaf)}, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00}))
	leafOne := crypto.Hash(treeHashTestConcat([]byte{byte(NodeTypeLeaf)}, []byte{0x00, 0x00, 0x00, 0x01}, []byte{0x00}))
	parentBytes := treeHashTestConcat(
		treeHashTestOpaque(t, bytes.Repeat([]byte{0x01}, 32)),
		treeHashTestOpaque(t, nil),
		treeHashTestOpaque(t, []byte{0x00, 0x00, 0x00, 0x01}),
	)
	wantRoot := crypto.Hash(treeHashTestConcat(
		[]byte{byte(NodeTypeParent)},
		[]byte{0x01},
		parentBytes,
		treeHashTestOpaque(t, leafZero),
		treeHashTestOpaque(t, leafOne),
	))
	if got := fmt.Sprintf("%x", wantRoot); got != parentTwoLeafTreeRootHash {
		t.Fatalf("the hand written preimage hashes to %s, want the golden %s", got, parentTwoLeafTreeRootHash)
	}
	got, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	if !bytes.Equal(got, wantRoot) {
		t.Errorf("a two leaf tree with one parent node hashes to %x, want %x", got, wantRoot)
	}
	// the same tree with the parent BLANK, so the presence octet is doing work rather than the
	// two goldens differing because the preimages have different lengths for some other reason
	blanked := tree.Clone()
	if err := blanked.Blank(NodeIndex(1)); err != nil {
		t.Fatalf("Blank(1): %v", err)
	}
	blankRoot, err := blanked.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash of the blanked tree: %v", err)
	}
	if bytes.Equal(blankRoot, got) {
		t.Errorf("a present parent node and a blank one hash the same at %x", got)
	}
	if want := blankTwoLeafTreeRootHash; fmt.Sprintf("%x", blankRoot) != want {
		t.Errorf("blanking the parent gives %x, want the blank tree golden %s", blankRoot, want)
	}
}

// ---------------------------------------------------------------------------
// the recursion order
// ---------------------------------------------------------------------------

// TestTheParentHashInputPlacesTheLeftSubtreeFirst is the left-then-right clause, over a tree
// whose two halves are DERIVED to be different rather than hoped to be.
//
// Three members in a four wide tree puts two occupied leaves under the root's left child and
// one occupied leaf plus one blank under its right, and the test refuses to proceed unless the
// two halves actually hash differently -- on a symmetric tree the two orders produce the same
// root and this assertion would pass against either reading.
//
// The recomposition is the assertion, not an inequality: the root's hash is rebuilt from the
// children Left and Right name, in the order section 7.8 states, and compared. Left and Right
// are tree_math's own and are checked against the published tree-math corpus, so this does not
// share its notion of "left" with the shim tree_hash.go reaches them through -- a leftOf that
// answered Right would pass every other test in this package and fail here.
func TestTheParentHashInputPlacesTheLeftSubtreeFirst(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	tree, _ := newTestTree(t, crypto, 3)
	root, err := rootOf(tree.LeafWidth())
	if err != nil {
		t.Fatalf("rootOf: %v", err)
	}
	left, err := Left(root)
	if err != nil {
		t.Fatalf("Left(%d): %v", root, err)
	}
	right, err := Right(root)
	if err != nil {
		t.Fatalf("Right(%d): %v", root, err)
	}
	leftHash, err := tree.NodeTreeHash(crypto, left)
	if err != nil {
		t.Fatalf("NodeTreeHash(%d): %v", left, err)
	}
	rightHash, err := tree.NodeTreeHash(crypto, right)
	if err != nil {
		t.Fatalf("NodeTreeHash(%d): %v", right, err)
	}
	if bytes.Equal(leftHash, rightHash) {
		t.Fatalf("the two halves of this tree hash the same, so no assertion here can separate left-then-right from right-then-left")
	}
	if tree.ParentAt(root) != nil {
		t.Fatalf("the root of a fresh test tree carries a parent node, which the preimage below does not spell")
	}
	inOrder := crypto.Hash(treeHashTestConcat(
		[]byte{byte(NodeTypeParent)},
		[]byte{0x00},
		treeHashTestOpaque(t, leftHash),
		treeHashTestOpaque(t, rightHash),
	))
	reversed := crypto.Hash(treeHashTestConcat(
		[]byte{byte(NodeTypeParent)},
		[]byte{0x00},
		treeHashTestOpaque(t, rightHash),
		treeHashTestOpaque(t, leftHash),
	))
	if bytes.Equal(inOrder, reversed) {
		t.Fatalf("the two orders produce the same preimage digest, so this test cannot fail")
	}
	got, err := tree.NodeTreeHash(crypto, root)
	if err != nil {
		t.Fatalf("NodeTreeHash(%d): %v", root, err)
	}
	if bytes.Equal(got, reversed) {
		t.Fatalf("the root hash is the RIGHT subtree's hash followed by the left; section 7.8 writes left_hash then right_hash, and the two are different groups")
	}
	if !bytes.Equal(got, inOrder) {
		t.Errorf("the root hash is %x, want %x -- left_hash then right_hash over the children Left(%d) and Right(%d) name",
			got, inOrder, root, root)
	}
}

// TestNodeTreeHashRefusesAnIndexOutsideTheTree separates "outside the tree" from "blank", which
// are the two answers this recursion must never conflate: a blank node is inside the tree and
// hashes, and an index past the end has no hash at all.
func TestNodeTreeHashRefusesAnIndexOutsideTheTree(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	tree, _ := newTestTree(t, crypto, 4)
	for _, x := range []NodeIndex{NodeIndex(tree.NodeWidth()), NodeIndex(tree.NodeWidth() + 1)} {
		if _, err := tree.NodeTreeHash(crypto, x); err == nil {
			t.Errorf("NodeTreeHash(%d) on a %d node tree answered a hash", x, tree.NodeWidth())
		}
	}
	last := NodeIndex(tree.NodeWidth() - 1)
	if err := tree.Blank(last); err != nil {
		t.Fatalf("Blank(%d): %v", last, err)
	}
	if _, err := tree.NodeTreeHash(crypto, last); err != nil {
		t.Errorf("NodeTreeHash of the blank node %d: %v; a blank node is in the tree and hashes", last, err)
	}
}

// ---------------------------------------------------------------------------
// the published corpus
// ---------------------------------------------------------------------------

// treeHashValidationVector reads the two columns this file needs out of the mlswg
// tree-validation family: the ratchet tree and the published tree hash of every one of its
// nodes.
//
// A third view of the same corpus, beside tree_math_test.go's resolutions and
// leaf_node_test.go's group id, for the reason those two give: the columns are different and a
// struct carrying all of them would make a change to any one of them a change to all three.
//
// This is NOT the registered family. Family 10 is installed by Task 24, which verifies the
// resolutions, the parent hashes and the leaf signatures together and deletes 10 from
// expectedPendingFamilies in the same commit; registering it here would claim a coverage this
// task does not have. What is here is a direct read of one column, exactly as the two existing
// readers of this file are.
type treeHashValidationVector struct {
	CipherSuite uint16   `json:"cipher_suite"`
	Tree        string   `json:"tree"`
	TreeHashes  []string `json:"tree_hashes"`
}

// What the corpus holds for the two suites this package registers, so a sweep that decoded
// nothing, filtered everything out or stopped early fails here rather than reporting a clean
// run over an empty set. Measured off the vendored file and a property of it: 14 entries per
// suite over two registered suites, and 908 published node hashes between them.
const (
	treeValidationImplementedEntries = 28
	treeValidationTreeHashCount      = 908
)

// TestTreeHashesAgainstThePublishedTreeValidationCorpus is the only assertion in this package
// whose tree hashes this repository did not compute.
//
// Everything else here hashes with this implementation and compares against this
// implementation, or against a preimage one reader wrote twice. These 908 answers were produced
// by the working group's own implementations from their own reading of section 7.8, over trees
// that carry blank leaves, blank parents, occupied parents and unmerged leaves, so a preimage
// that ordered a field differently, wrote a prefix at the wrong width, skipped a blank or
// recursed right-then-left fails here and, for several of those, here alone.
func TestTreeHashesAgainstThePublishedTreeValidationCorpus(t *testing.T) {
	entries := LoadVectorFile(t, treeValidationVectorFile)
	if len(entries) != treeValidationEntryCount {
		t.Fatalf("tree-validation entries: %d, want %d", len(entries), treeValidationEntryCount)
	}
	covered := 0
	confirmed := 0
	for entry, raw := range entries {
		vector := treeHashValidationVector{}
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("entry %d: %v", entry, err)
		}
		suite, implemented := implementedSuite(vector.CipherSuite)
		if !implemented {
			continue
		}
		covered += 1
		label := fmt.Sprintf("tree-validation entry %d", entry)
		crypto := mustProvider(t, suite)
		tree, err := UnmarshalRatchetTree(mustDecodeHex(t, label+" ratchet tree", vector.Tree))
		if err != nil {
			t.Fatalf("%s: decode the published ratchet tree: %v", label, err)
		}
		hashes, err := tree.TreeHashes(crypto)
		if err != nil {
			t.Fatalf("%s: TreeHashes: %v", label, err)
		}
		if len(hashes) != len(vector.TreeHashes) {
			t.Fatalf("%s: computed %d node hashes for a tree the corpus publishes %d for",
				label, len(hashes), len(vector.TreeHashes))
		}
		for x, published := range vector.TreeHashes {
			want := mustDecodeHex(t, fmt.Sprintf("%s node %d hash", label, x), published)
			if !bytes.Equal(hashes[x], want) {
				t.Errorf("%s: node %d hashes to %x, the corpus publishes %x", label, x, hashes[x], want)
				continue
			}
			confirmed += 1
		}
		root, err := rootOf(tree.LeafWidth())
		if err != nil {
			t.Fatalf("%s: rootOf: %v", label, err)
		}
		whole, err := tree.TreeHash(crypto)
		if err != nil {
			t.Fatalf("%s: TreeHash: %v", label, err)
		}
		if !bytes.Equal(whole, hashes[root]) {
			t.Errorf("%s: TreeHash is %x and the published root entry is %x", label, whole, hashes[root])
		}
	}
	if covered != treeValidationImplementedEntries {
		t.Errorf("%d published entries were covered, want %d; the suite filter or the decode moved",
			covered, treeValidationImplementedEntries)
	}
	if confirmed != treeValidationTreeHashCount {
		t.Errorf("%d published node hashes were confirmed, want %d", confirmed, treeValidationTreeHashCount)
	}
}

// TestThePublishedTreeHashComparisonCanSayNo is the negative control for the sweep above.
//
// Every entry of a vendored corpus agrees with a correct implementation, so a comparison that
// could never report a difference passes the whole run and reports 908 confirmations. What
// separates the two is asking the same corpus about a tree it does not describe: one leaf
// blanked out of a published tree moves that leaf's own hash and every hash above it and
// nothing else, and the count of moved entries is asserted against the direct path so that a
// control which found one difference by luck is not read as a control that works.
func TestThePublishedTreeHashComparisonCanSayNo(t *testing.T) {
	entries := LoadVectorFile(t, treeValidationVectorFile)
	checked := 0
	for entry, raw := range entries {
		vector := treeHashValidationVector{}
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("entry %d: %v", entry, err)
		}
		suite, implemented := implementedSuite(vector.CipherSuite)
		if !implemented {
			continue
		}
		label := fmt.Sprintf("tree-validation entry %d", entry)
		crypto := mustProvider(t, suite)
		tree, err := UnmarshalRatchetTree(mustDecodeHex(t, label+" ratchet tree", vector.Tree))
		if err != nil {
			t.Fatalf("%s: decode the published ratchet tree: %v", label, err)
		}
		occupied := tree.NonBlankLeaves()
		if len(occupied) == 0 {
			t.Fatalf("%s: a published ratchet tree has no occupied leaf", label)
		}
		leaf := occupied[0]
		path, err := directPathOf(leaf.NodeIndex(), tree.LeafWidth())
		if err != nil {
			t.Fatalf("%s: directPathOf: %v", label, err)
		}
		if err := tree.Blank(leaf.NodeIndex()); err != nil {
			t.Fatalf("%s: Blank(%d): %v", label, leaf.NodeIndex(), err)
		}
		hashes, err := tree.TreeHashes(crypto)
		if err != nil {
			t.Fatalf("%s: TreeHashes: %v", label, err)
		}
		moved := 0
		for x, published := range vector.TreeHashes {
			want := mustDecodeHex(t, fmt.Sprintf("%s node %d hash", label, x), published)
			if !bytes.Equal(hashes[x], want) {
				moved += 1
			}
		}
		// the blanked leaf and every node on its direct path, and nothing else: a subtree that
		// does not contain the leaf cannot have moved, so a control reporting anything but this
		// is comparing the wrong entries
		if want := 1 + len(path); moved != want {
			t.Errorf("%s: blanking leaf %d moved %d of the published node hashes, want %d -- the leaf itself and the %d nodes of its direct path",
				label, leaf, moved, want, len(path))
		}
		checked += 1
	}
	if checked != treeValidationImplementedEntries {
		t.Errorf("the control ran over %d entries, want %d", checked, treeValidationImplementedEntries)
	}
}

// ---------------------------------------------------------------------------
// the original tree hash, RFC 9420 section 7.9
// ---------------------------------------------------------------------------

// originalTreeHashReference builds the tree section 7.9 DESCRIBES -- the one the excluded
// leaves were never added to -- and hashes it through the ordinary section 7.8 walk.
//
// treeHash folds that construction into the same recursion, on purpose and for the reason its
// doc gives, and the cost of folding it is that the exclude arm has no second opinion
// anywhere: a test that asked the recursion to check itself would agree with any reading of
// it. This is that second opinion, and it is worth what it is because the arm it compares
// against -- exclude nil -- is the one the 908 published node hashes at the end of this file
// check. So a defect in the shared encoder fails there, and a defect in what exclude does to
// the tree fails here.
//
// Every excluded leaf is BLANKED and every parent node's unmerged_leaves has those leaves
// struck out, both through the container's own surface, so what is hashed is a tree any other
// caller could have built.
func originalTreeHashReference(t *testing.T, crypto CryptoProvider, tree *RatchetTree,
	exclude map[LeafIndex]bool) []byte {
	t.Helper()
	without := tree.Clone()
	for i := uint32(0); i < uint32(without.LeafWidth()); i += 1 {
		if !exclude[LeafIndex(i)] {
			continue
		}
		if without.Leaf(LeafIndex(i)) == nil {
			t.Fatalf("leaf %d is already blank in the tree this reference is built from, so excluding it is not a change", i)
		}
		if err := without.Blank(LeafIndex(i).NodeIndex()); err != nil {
			t.Fatalf("Blank(leaf %d): %v", i, err)
		}
	}
	for x := uint32(0); x < without.NodeWidth(); x += 1 {
		parent := without.ParentAt(NodeIndex(x))
		if parent == nil {
			continue
		}
		kept := []LeafIndex{}
		for _, leaf := range parent.UnmergedLeaves {
			if !exclude[leaf] {
				kept = append(kept, leaf)
			}
		}
		filtered := parent.Clone()
		filtered.UnmergedLeaves = kept
		if err := without.SetParent(NodeIndex(x), filtered); err != nil {
			t.Fatalf("SetParent(%d): %v", x, err)
		}
	}
	root, err := rootOf(without.LeafWidth())
	if err != nil {
		t.Fatalf("rootOf: %v", err)
	}
	hash, err := without.treeHash(crypto, root, nil)
	if err != nil {
		t.Fatalf("the reference tree hash: %v", err)
	}
	return hash
}

// TestTheOriginalTreeHashIsTheTreeHashOfTheTreeWithoutThoseLeaves is section 7.9's definition,
// over EVERY subset of a four leaf tree's leaves rather than over a subset somebody picked.
//
// The subsets are derived from the width, which is what puts all three arms of the exclusion
// under assertion at once: a subset naming a leaf under the root's left child and one under
// its right says the set reaches both descendants, a subset naming a leaf that appears in a
// parent's unmerged_leaves says the list is filtered, and the EMPTY subset says a non nil
// exclusion naming nobody changes nothing -- which is the row that fails when the filter keeps
// what it should drop.
//
// All three arms shipped with no behavioural assertion at all, and three separate mutations of
// them survived the whole package: inverting the unmerged filter, dropping the blanking of an
// excluded leaf, and passing nil to the two recursive calls so the exclusion never reached a
// descendant. Each of the three fails here now.
func TestTheOriginalTreeHashIsTheTreeHashOfTheTreeWithoutThoseLeaves(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	tree, _ := newTestTree(t, crypto, 4)
	// unmerged lists at BOTH depths and at the root: an exclusion that reached only the node it
	// was handed would still filter the root's own list, so a tree whose only unmerged entries
	// were at the root could not tell the two readings apart.
	for _, one := range []struct {
		x        NodeIndex
		unmerged []LeafIndex
	}{
		{NodeIndex(1), []LeafIndex{0, 1}},
		{NodeIndex(5), []LeafIndex{3}},
		{NodeIndex(3), []LeafIndex{1, 2, 3}},
	} {
		if err := tree.SetParent(one.x, &ParentNode{
			EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{byte(one.x)}, 32)),
			UnmergedLeaves: one.unmerged,
		}); err != nil {
			t.Fatalf("SetParent(%d): %v", one.x, err)
		}
	}
	plain, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	root, err := rootOf(tree.LeafWidth())
	if err != nil {
		t.Fatalf("rootOf: %v", err)
	}
	width := uint32(tree.LeafWidth())
	if width != 4 {
		t.Fatalf("this sweep is written for a four leaf tree and the builder handed back %d leaves", width)
	}
	answers := map[string]string{}
	for bits := uint32(0); bits < 1<<width; bits += 1 {
		exclude := map[LeafIndex]bool{}
		named := []LeafIndex{}
		for i := uint32(0); i < width; i += 1 {
			if bits&(1<<i) != 0 {
				exclude[LeafIndex(i)] = true
				named = append(named, LeafIndex(i))
			}
		}
		got, err := tree.treeHash(crypto, root, exclude)
		if err != nil {
			t.Fatalf("excluding %v: %v", named, err)
		}
		want := originalTreeHashReference(t, crypto, tree, exclude)
		if !bytes.Equal(got, want) {
			t.Errorf("the original tree hash excluding %v is %x, and the tree those leaves were never added to hashes to %x",
				named, got, want)
		}
		// the two controls that stop sixteen rows from being sixteen readings of one answer: an
		// exclusion naming nobody must leave the hash where it was, and every other one must
		// move it, or the reference is agreeing with the implementation about a change neither
		// of them made.
		if len(named) == 0 {
			if !bytes.Equal(got, plain) {
				t.Errorf("an exclusion naming no leaf answers %x and the ordinary tree hash is %x", got, plain)
			}
		} else if bytes.Equal(got, plain) {
			t.Errorf("excluding %v leaves the tree hash at the ordinary %x", named, plain)
		}
		if prior, collided := answers[string(got)]; collided {
			t.Errorf("excluding %v hashes the same as excluding %s", named, prior)
		}
		answers[string(got)] = fmt.Sprintf("%v", named)
	}
	if len(answers) != 1<<width {
		t.Errorf("%d of the %d subsets of the leaves produced a distinct hash", len(answers), 1<<width)
	}
}

// TestTheOriginalTreeHashOfAnExcludedLeafIsTheHandDerivedBlankGolden pins what the exclusion
// does to a leaf as BYTES rather than as a difference.
//
// The sweep above holds the exclude arm against the nil arm, which is the right second opinion
// about what exclusion MEANS and says nothing about the octets either arm writes. This says the
// octets: an excluded leaf is hashed exactly as a blank one is -- node type, index, presence
// octet zero -- and the digest it must reach is one this repository did not compute. The tree
// is chosen so the exclusion is the only thing that can turn it into the all blank tree those
// goldens were derived for.
func TestTheOriginalTreeHashOfAnExcludedLeafIsTheHandDerivedBlankGolden(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	tree, _ := newTestTree(t, crypto, 2)
	for _, x := range []NodeIndex{1, 2} {
		if err := tree.Blank(x); err != nil {
			t.Fatalf("Blank(%d): %v", x, err)
		}
	}
	if tree.Leaf(LeafIndex(0)) == nil {
		t.Fatalf("leaf 0 is blank before the exclusion, so nothing here could see one")
	}
	plain, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	if got := fmt.Sprintf("%x", plain); got == blankTwoLeafTreeRootHash {
		t.Fatalf("the tree hashes to the all blank golden with nobody excluded, so this test cannot fail")
	}
	exclude := map[LeafIndex]bool{0: true}
	for _, one := range []struct {
		x    NodeIndex
		want string
		what string
	}{
		{LeafIndex(0).NodeIndex(), blankTwoLeafTreeLeafZeroHash, "the excluded leaf itself"},
		{NodeIndex(1), blankTwoLeafTreeRootHash, "the root above it"},
	} {
		got, err := tree.treeHash(crypto, one.x, exclude)
		if err != nil {
			t.Fatalf("%s: treeHash(%d): %v", one.what, one.x, err)
		}
		if fmt.Sprintf("%x", got) != one.want {
			t.Errorf("%s hashes to %x with leaf 0 excluded, want %s -- an excluded leaf is written as an ABSENT one: node_type, index, zero presence octet",
				one.what, got, one.want)
		}
	}
	// the walk READS the tree and never edits it: the exclusion is a question asked about a
	// live tree during a parent hash check, and a caller left holding a tree the question had
	// blanked would commit it.
	after, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash after the excluded walk: %v", err)
	}
	if !bytes.Equal(after, plain) {
		t.Errorf("the tree hash moved from %x to %x across an original tree hash walk, so the walk wrote into the tree it read", plain, after)
	}
}

// TestTheOriginalTreeHashStrikesTheExcludedLeafOutOfUnmergedLeaves is the same statement for
// the parent arm, and it is the one the sweep above cannot make in bytes: the filtered list is
// what is hashed, as the shorter vector, rather than the list the tree still holds.
//
// The golden is the one TestAParentNodeHashesInTheHandDerivedOrder spells octet by octet --
// unmerged_leaves = [1] over two blank leaves -- reached here from a tree whose list is [0, 1]
// by excluding leaf 0. So a filter that kept the excluded entry, or struck out the wrong one,
// hashes a four octet vector of the other index and fails against a digest computed outside
// this repository.
func TestTheOriginalTreeHashStrikesTheExcludedLeafOutOfUnmergedLeaves(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	tree := twoLeafBlankTree(t, crypto)
	if err := tree.SetParent(NodeIndex(1), &ParentNode{
		EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x01}, 32)),
		UnmergedLeaves: []LeafIndex{0, 1},
	}); err != nil {
		t.Fatalf("SetParent(1): %v", err)
	}
	plain, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	if got := fmt.Sprintf("%x", plain); got == parentTwoLeafTreeRootHash {
		t.Fatalf("the unfiltered tree already hashes to the golden the filtered one must reach")
	}
	got, err := tree.treeHash(crypto, NodeIndex(1), map[LeafIndex]bool{0: true})
	if err != nil {
		t.Fatalf("treeHash(1, {0}): %v", err)
	}
	if fmt.Sprintf("%x", got) != parentTwoLeafTreeRootHash {
		t.Errorf("with leaf 0 excluded the root hashes to %x, want %s -- unmerged_leaves is [1] and not [0], [0 1] or []",
			got, parentTwoLeafTreeRootHash)
	}
	// and the tree's own list is untouched, which is what the Clone in the filter is for: this
	// walk runs over a live tree, and a filter applied in place would leave the caller holding a
	// tree the exclusion had eaten.
	parent := tree.ParentAt(NodeIndex(1))
	if parent == nil {
		t.Fatalf("the parent node is gone after the excluded walk")
	}
	if !slices.Equal(parent.UnmergedLeaves, []LeafIndex{0, 1}) {
		t.Errorf("the tree's own unmerged_leaves is %v after the excluded walk, want [0 1]", parent.UnmergedLeaves)
	}
}

// TestTheTreeHashEntryPointsRefuseATreeWithNoLeavesAlike closes a disagreement between the two
// entry points that nothing in this package asked about.
//
// TreeHash asks rootOf, which refuses a leaf count of zero, so a zero valued RatchetTree
// answers ErrTreeMalformed. TreeHashes used to allocate a column of NodeWidth entries and never
// enter the loop, so the SAME receiver answered an empty slice and a nil error. A parent hash
// check reads that column, and a caller that trusted the error would read "this tree has no
// nodes" out of a tree that is not a tree.
func TestTheTreeHashEntryPointsRefuseATreeWithNoLeavesAlike(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	empty := &RatchetTree{}
	if empty.NodeWidth() != 0 || empty.LeafWidth() != 0 {
		t.Fatalf("a zero valued tree is %d nodes and %d leaves wide, so it is not the receiver this test is about",
			empty.NodeWidth(), empty.LeafWidth())
	}
	whole, wholeErr := empty.TreeHash(crypto)
	column, columnErr := empty.TreeHashes(crypto)
	if !errors.Is(wholeErr, ErrTreeMalformed) {
		t.Errorf("TreeHash of a tree with no leaves answered %v, want %v", wholeErr, ErrTreeMalformed)
	}
	if !errors.Is(columnErr, ErrTreeMalformed) {
		t.Errorf("TreeHashes of a tree with no leaves answered %v and the column %v, want %v",
			columnErr, column, ErrTreeMalformed)
	}
	if whole != nil || column != nil {
		t.Errorf("a refusal handed back a hash %x and a column of %d entries", whole, len(column))
	}
	// and the one leaf tree, which IS the narrowest tree there is, still answers both: a guard
	// that refused every tree would satisfy the two clauses above and nothing else.
	one := NewRatchetTree()
	if _, err := one.TreeHash(crypto); err != nil {
		t.Errorf("TreeHash of the one leaf tree: %v", err)
	}
	hashes, err := one.TreeHashes(crypto)
	if err != nil {
		t.Errorf("TreeHashes of the one leaf tree: %v", err)
	}
	if uint32(len(hashes)) != one.NodeWidth() {
		t.Errorf("TreeHashes of the one leaf tree is %d entries over a %d node tree", len(hashes), one.NodeWidth())
	}
}
