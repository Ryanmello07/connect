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
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// the plan's three: the hash moves when the tree moves
// ---------------------------------------------------------------------------

func TestTreeHashChangesWithEveryObservableChange(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 4)
	base, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	if len(base) != crypto.HashSize() {
		t.Fatalf("tree hash length = %d, want %d", len(base), crypto.HashSize())
	}

	mutations := map[string]func(tree *RatchetTree){
		"blank a leaf":    func(tree *RatchetTree) { _ = tree.Blank(NodeIndex(2)) },
		"swap two leaves": func(tree *RatchetTree) { tree.nodes[0], tree.nodes[2] = tree.nodes[2], tree.nodes[0] },
		"set a parent": func(tree *RatchetTree) {
			_ = tree.SetParent(NodeIndex(1), &ParentNode{EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{0x01}, 32))})
		},
		"add an unmerged": func(tree *RatchetTree) {
			_ = tree.SetParent(NodeIndex(1), &ParentNode{
				EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x01}, 32)),
				UnmergedLeaves: []LeafIndex{1},
			})
		},
		"grow the tree": func(tree *RatchetTree) { _ = tree.SetLeaf(LeafIndex(4), tree.Leaf(LeafIndex(0)).Clone()) },
	}
	seen := map[string]string{string(base): "base"}
	for name, mutate := range mutations {
		clone := tree.Clone()
		mutate(clone)
		got, err := clone.TreeHash(crypto)
		if err != nil {
			t.Fatalf("%s TreeHash: %v", name, err)
		}
		if prior, ok := seen[string(got)]; ok {
			t.Fatalf("%s produced the same tree hash as %s", name, prior)
		}
		seen[string(got)] = name
	}
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

func TestBlankLeafStillHashesAtItsIndex(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 4)
	if err := tree.Blank(NodeIndex(0)); err != nil {
		t.Fatalf("Blank(0): %v", err)
	}
	a, err := tree.NodeTreeHash(crypto, NodeIndex(0))
	if err != nil {
		t.Fatalf("NodeTreeHash(0): %v", err)
	}
	if err := tree.Blank(NodeIndex(2)); err != nil {
		t.Fatalf("Blank(2): %v", err)
	}
	b, err := tree.NodeTreeHash(crypto, NodeIndex(2))
	if err != nil {
		t.Fatalf("NodeTreeHash(2): %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("two blank leaves at different indices hash the same")
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
