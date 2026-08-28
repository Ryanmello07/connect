// Tests for the ratchet tree container of RFC 9420 section 7 and for the ParentNode codec.
//
// Three properties here are not round trip properties, and they are the reason this file is
// longer than the code it holds.
//
// A hand derived golden, stated from the RFC without reference to the encoder, is the only
// thing that separates a field order from its mirror image. Two adjacent opaque<V> fields
// swapped in BOTH halves of a codec round trip perfectly and re-encode byte exact; so does a
// field dropped from both halves, while being lost. Both shapes have been found in this package
// before, and neither is visible to any symmetry property.
//
// Comparing the decoded VALUE rather than the re-encoded bytes is the other half of that: a
// dropped field is byte exact against itself and unequal as a value.
//
// And the blank node. optional<Node> makes a blank an ABSENT array entry, so a blank and a zero
// valued node are different bytes and different tree hashes. Every blank assertion below derives
// the blank set from the tree's own node width rather than naming a few indices, because "the
// blanks are where somebody remembered to look" is exactly how that conflation survives a suite.
package mls

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ---------------------------------------------------------------------------
// the values the goldens and the sweeps are built from
// ---------------------------------------------------------------------------

// testParentNodeTemplate is one parent node with every field populated and every field
// different from every other field of its own width.
//
// encryption_key and parent_hash are the SAME width on purpose. They are adjacent opaque<V>
// fields, so a length difference would separate them for free and a swap would be caught by
// arithmetic that has nothing to do with the fields. Equal width means only their CONTENT
// separates them, which is the strictest form of the swap test and what the goldens rest on.
//
// The unmerged list is strictly ascending because RFC 9420 section 7.9.2 requires it and
// because this codec refuses anything else; the refusal has its own test below.
func testParentNodeTemplate() *ParentNode {
	return &ParentNode{
		EncryptionKey:  HpkePublicKey(repeatByte(0xa1, 32)),
		ParentHash:     repeatByte(0xb2, 32),
		UnmergedLeaves: []LeafIndex{1, 2, 5},
	}
}

// testTreeLeaf is one leaf whose keys are a function of its index, so that a tree built below
// has a distinct signature key and a distinct encryption key at every occupied position. Two
// leaves carrying the same key would make FindLeafBySignatureKey and EncryptionKeyInUse pass
// against an implementation that answered the wrong position.
func testTreeLeaf(i uint32) *LeafNode {
	leaf := testLeafNodeTemplate()
	leaf.LeafNodeSource = LeafNodeSourceUpdate
	leaf.SignatureKey = SignaturePublicKey(repeatByte(byte(0x80+i), 32))
	leaf.EncryptionKey = HpkePublicKey(repeatByte(byte(0x40+i), 32))
	return leaf
}

// treeUnderTest builds a tree holding leafCount occupied leaves and a parent node at every
// LEVEL ONE index, and answers it together with the exact set of node indices it filled.
//
// The occupied set is returned rather than described, and every blank assertion below is
// derived from it and from the tree's own NodeWidth. Level one only -- the odd indices
// congruent to 1 modulo 4 -- so that the sweep sees blank parents as well as occupied ones at
// every width above two, which a rule that filled every odd index would not.
func treeUnderTest(t *testing.T, leafCount uint32) (*RatchetTree, map[NodeIndex]bool) {
	t.Helper()
	tree := NewRatchetTree()
	occupied := map[NodeIndex]bool{}
	for i := uint32(0); i < leafCount; i += 1 {
		if err := tree.SetLeaf(LeafIndex(i), testTreeLeaf(i)); err != nil {
			t.Fatalf("SetLeaf(%d): %v", i, err)
		}
		occupied[LeafIndex(i).NodeIndex()] = true
	}
	for x := uint32(1); x < tree.NodeWidth(); x += 4 {
		if err := tree.SetParent(NodeIndex(x), &ParentNode{
			EncryptionKey: HpkePublicKey(repeatByte(byte(0xc0+x), 32)),
		}); err != nil {
			t.Fatalf("SetParent(%d): %v", x, err)
		}
		occupied[NodeIndex(x)] = true
	}
	return tree, occupied
}

// ---------------------------------------------------------------------------
// the hand derived goldens for ParentNode
// ---------------------------------------------------------------------------

// parentNodeGoldenCase is one parent node and the octets RFC 9420 section 7.1 says it encodes
// to, derived by hand. The size is stated separately from the derivation so that a derivation
// edited without its comment fails rather than quietly redefining what it is compared to.
type parentNodeGoldenCase struct {
	name  string
	node  *ParentNode
	bytes []byte
	size  int
}

// parentNodeGoldenCases is the RFC 9420 section 7.1 structure written out from the RFC rather
// than read back through the encoder:
//
//	struct {
//	    HPKEPublicKey encryption_key;      -- opaque<V>
//	    opaque parent_hash<V>;
//	    uint32 unmerged_leaves<V>;
//	} ParentNode;
//
// The populated case:
//
//	encryption_key<V>    32 octets    -> 20 a1*32                          33
//	parent_hash<V>       32 octets    -> 20 b2*32                          33
//	unmerged_leaves<V>   3 x uint32   -> 0c 00000001 00000002 00000005     13
//
// 33 + 33 + 13 = 79 octets.
//
// The unmerged prefix counts BYTES and not elements, which is the single easiest thing in this
// encoding to get wrong and the one a round trip cannot see: three uint32 are twelve octets, so
// it is 0c and never 03, and an encoder writing the element count agrees perfectly with a
// decoder reading one element per unit and with nothing else.
//
// The sixteen leaf case exists for the prefix WIDTH. Sixteen uint32 are 64 octets, which is the
// first length whose varint prefix is two octets rather than one, so it comes out 40 40: a
// fixed one octet prefix moves the total by one and a WriteOpaqueLP -- which would write
// 00000040 -- moves it by three. Neither is visible to a round trip, because this
// implementation would read back whatever it wrote.
//
// The empty cases pin that a zero length field is one zero octet and not an omission, which is
// what keeps a blank parent hash distinguishable from a parent node that carries none.
func parentNodeGoldenCases() []parentNodeGoldenCase {
	ascendingLeaves := func(n uint32) []LeafIndex {
		out := []LeafIndex{}
		for i := uint32(0); i < n; i += 1 {
			out = append(out, LeafIndex(i))
		}
		return out
	}
	sixteenLeafOctets := []byte{}
	for i := 0; i < 16; i += 1 {
		sixteenLeafOctets = append(sixteenLeafOctets, 0x00, 0x00, 0x00, byte(i))
	}
	return []parentNodeGoldenCase{
		{
			name: "populated",
			node: testParentNodeTemplate(),
			bytes: joinBytes(
				[]byte{0x20}, repeatByte(0xa1, 32),
				[]byte{0x20}, repeatByte(0xb2, 32),
				[]byte{0x0c},
				[]byte{0x00, 0x00, 0x00, 0x01},
				[]byte{0x00, 0x00, 0x00, 0x02},
				[]byte{0x00, 0x00, 0x00, 0x05},
			),
			// 33 + 33 + 13
			size: 79,
		},
		{
			name: "no unmerged leaves",
			node: &ParentNode{
				EncryptionKey:  HpkePublicKey(repeatByte(0xa1, 32)),
				ParentHash:     repeatByte(0xb2, 32),
				UnmergedLeaves: []LeafIndex{},
			},
			bytes: joinBytes(
				[]byte{0x20}, repeatByte(0xa1, 32),
				[]byte{0x20}, repeatByte(0xb2, 32),
				[]byte{0x00},
			),
			// 33 + 33 + 1
			size: 67,
		},
		{
			name: "empty parent hash",
			node: &ParentNode{
				EncryptionKey:  HpkePublicKey(repeatByte(0xa1, 32)),
				ParentHash:     []byte{},
				UnmergedLeaves: []LeafIndex{1, 2, 5},
			},
			bytes: joinBytes(
				[]byte{0x20}, repeatByte(0xa1, 32),
				[]byte{0x00},
				[]byte{0x0c},
				[]byte{0x00, 0x00, 0x00, 0x01},
				[]byte{0x00, 0x00, 0x00, 0x02},
				[]byte{0x00, 0x00, 0x00, 0x05},
			),
			// 33 + 1 + 13
			size: 47,
		},
		{
			name: "every field empty",
			node: &ParentNode{
				EncryptionKey:  HpkePublicKey{},
				ParentHash:     []byte{},
				UnmergedLeaves: []LeafIndex{},
			},
			bytes: []byte{0x00, 0x00, 0x00},
			// 1 + 1 + 1
			size: 3,
		},
		{
			name: "sixteen unmerged leaves",
			node: &ParentNode{
				EncryptionKey:  HpkePublicKey(repeatByte(0xa1, 32)),
				ParentHash:     repeatByte(0xb2, 32),
				UnmergedLeaves: ascendingLeaves(16),
			},
			bytes: joinBytes(
				[]byte{0x20}, repeatByte(0xa1, 32),
				[]byte{0x20}, repeatByte(0xb2, 32),
				[]byte{0x40, 0x40}, sixteenLeafOctets,
			),
			// 33 + 33 + 2 + 64
			size: 132,
		},
	}
}

// TestParentNodeMarshalMatchesTheHandDerivedGoldens is the field order and prefix width pin,
// and the one test in this file a symmetric edit cannot survive.
//
// encryption_key and parent_hash swapped in BOTH halves of the codec round trips perfectly and
// re-encodes byte exact; so does either of them dropped from both halves. What separates those
// from this codec is a statement of the encoding written without reference to the code, which
// is what parentNodeGoldenCases is.
func TestParentNodeMarshalMatchesTheHandDerivedGoldens(t *testing.T) {
	cases := parentNodeGoldenCases()
	if len(cases) == 0 {
		t.Fatal("no golden case, so this gate compared nothing")
	}
	for _, testCase := range cases {
		if len(testCase.bytes) != testCase.size {
			t.Fatalf("%s: the hand derivation is %d octets and the arithmetic in its comment says %d",
				testCase.name, len(testCase.bytes), testCase.size)
		}
		encoded, err := syntax.Marshal(testCase.node)
		if err != nil {
			t.Fatalf("%s: Marshal: %v", testCase.name, err)
		}
		if !bytes.Equal(encoded, testCase.bytes) {
			t.Errorf("%s: Marshal =\n %x\nwant\n %x", testCase.name, encoded, testCase.bytes)
		}
	}
}

// TestParentNodeGoldenDecodesToTheValueItWasBuiltFrom compares the decoded VALUE against the
// original rather than the re-encoded bytes against the golden.
//
// That is a different property and it catches a different defect. A field dropped from both
// halves of the codec is byte exact against everything, including the golden if the golden were
// generated from the encoder; what it is not is EQUAL, because the field it never wrote is not
// there when the value comes back. reflect.DeepEqual over the whole structure is what sees it,
// and over the whole structure rather than three named fields, so a field added later is
// covered without this test being edited.
//
// Every golden case is built with non nil empty vectors, because ReadOpaque and ReadVector
// never answer nil: a nil field in the original would compare unequal to a decode of its own
// bytes, which is a property of Go and not of this codec.
func TestParentNodeGoldenDecodesToTheValueItWasBuiltFrom(t *testing.T) {
	for _, testCase := range parentNodeGoldenCases() {
		decoded := &ParentNode{}
		if err := syntax.Unmarshal(testCase.bytes, decoded); err != nil {
			t.Fatalf("%s: Unmarshal the golden: %v", testCase.name, err)
		}
		if !reflect.DeepEqual(decoded, testCase.node) {
			t.Errorf("%s: the golden decoded to\n %+v\nwant\n %+v", testCase.name, decoded, testCase.node)
		}
	}
}

// ---------------------------------------------------------------------------
// unmerged_leaves ordering
// ---------------------------------------------------------------------------

// unmergedLeavesEncoding builds a ParentNode encoding by hand around a given unmerged_leaves
// body, so the decode side can be handed vectors this package's own encoder refuses to
// produce. The two opaque fields are one octet each and empty, so the whole input is the
// unmerged vector plus three prefixes.
func unmergedLeavesEncoding(leaves []uint32) []byte {
	body := []byte{}
	for _, leaf := range leaves {
		body = append(body, byte(leaf>>24), byte(leaf>>16), byte(leaf>>8), byte(leaf))
	}
	return joinBytes([]byte{0x00, 0x00, byte(len(body))}, body)
}

// TestParentNodeRefusesUnmergedLeavesThatAreNotStrictlyAscending holds RFC 9420 section 7.9.2
// on BOTH halves of the codec.
//
// Sorted and unique are one requirement, so both orderings and both repeats are refused with
// one sentinel. The decode half matters because a peer's unsorted vector is a tree whose parent
// hashes nobody else computes; the encode half matters because it is what keeps this
// implementation from being the peer that publishes one.
//
// Refused and not quietly sorted, which are different behaviours and only one of them is the
// RFC's: the bytes a parent hash and a tree hash are taken over are the bytes that arrived, so
// an implementation that sorted on read would agree with itself and with nobody. The accepted
// half of the table is what keeps this from being a decoder that refuses everything.
func TestParentNodeRefusesUnmergedLeavesThatAreNotStrictlyAscending(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		leaves  []uint32
		refused bool
	}{
		{name: "empty", leaves: []uint32{}, refused: false},
		{name: "one", leaves: []uint32{7}, refused: false},
		{name: "ascending", leaves: []uint32{0, 1, 2}, refused: false},
		{name: "ascending with gaps", leaves: []uint32{1, 2, 5}, refused: false},
		{name: "descending", leaves: []uint32{1, 0}, refused: true},
		{name: "duplicated", leaves: []uint32{1, 1}, refused: true},
		{name: "out of order in the middle", leaves: []uint32{0, 3, 2, 4}, refused: true},
		{name: "duplicated at the end", leaves: []uint32{0, 1, 2, 2}, refused: true},
	} {
		asLeaves := []LeafIndex{}
		for _, leaf := range testCase.leaves {
			asLeaves = append(asLeaves, LeafIndex(leaf))
		}

		// the encode half
		_, err := syntax.Marshal(&ParentNode{UnmergedLeaves: asLeaves})
		if testCase.refused != errors.Is(err, ErrUnmergedLeavesNotSorted) {
			t.Errorf("%s: Marshal err = %v, refused should be %v", testCase.name, err, testCase.refused)
		}

		// the decode half, over bytes built without going through the encoder, since the
		// encoder above will not produce the refused ones
		decoded := &ParentNode{ParentHash: []byte("untouched")}
		err = syntax.Unmarshal(unmergedLeavesEncoding(testCase.leaves), decoded)
		if testCase.refused != errors.Is(err, ErrUnmergedLeavesNotSorted) {
			t.Errorf("%s: Unmarshal err = %v, refused should be %v", testCase.name, err, testCase.refused)
			continue
		}
		if !testCase.refused {
			if len(decoded.UnmergedLeaves) != len(asLeaves) {
				t.Errorf("%s: decoded %d unmerged leaves, want %d", testCase.name, len(decoded.UnmergedLeaves), len(asLeaves))
			}
			continue
		}
		// refused rather than repaired: nothing was assigned, so the receiver still holds
		// what it arrived with and no sorted copy of the refused vector exists anywhere
		if !bytes.Equal(decoded.ParentHash, []byte("untouched")) {
			t.Errorf("%s: a refused decode wrote into its receiver", testCase.name)
		}
		if decoded.UnmergedLeaves != nil {
			t.Errorf("%s: a refused decode left %v behind, so it repaired the vector rather than refusing it",
				testCase.name, decoded.UnmergedLeaves)
		}
	}
}

// TestParentNodeCloneSharesNoStorage. A parent node is copied whenever a provisional tree is
// built, so a commit that is later rejected must leave the epoch it was computed against
// exactly as it found it.
func TestParentNodeCloneSharesNoStorage(t *testing.T) {
	original := testParentNodeTemplate()
	clone := original.Clone()
	if !reflect.DeepEqual(clone, original) {
		t.Fatalf("Clone = %+v, want %+v", clone, original)
	}
	clone.EncryptionKey[0] ^= 0xff
	clone.ParentHash[0] ^= 0xff
	clone.UnmergedLeaves[0] = 0xffff
	if original.EncryptionKey[0] != 0xa1 {
		t.Errorf("Clone shares the encryption key with the original")
	}
	if original.ParentHash[0] != 0xb2 {
		t.Errorf("Clone shares the parent hash with the original")
	}
	if original.UnmergedLeaves[0] != LeafIndex(1) {
		t.Errorf("Clone shares the unmerged leaf list with the original")
	}
	// nil stays nil, because an absent vector and a present empty one are different bytes and
	// a clone that changed which one a caller holds changed the value it was asked to copy
	bare := (&ParentNode{}).Clone()
	if bare.EncryptionKey != nil || bare.ParentHash != nil || bare.UnmergedLeaves != nil {
		t.Errorf("Clone of a bare parent node = %+v, want every field nil", bare)
	}
}

// ---------------------------------------------------------------------------
// the blank node
// ---------------------------------------------------------------------------

// TestABlankAndAZeroValuedNodeEncodeDifferently is the statement the whole blank/absent
// distinction rests on, made in octets.
//
// RFC 9420 section 4.2 carries the array as optional<Node>, so an absent entry is one 0x00
// presence octet and a present entry is 0x01 followed by a whole node. An implementation that
// stored a blank as a zero valued node would round trip against itself, would agree with itself
// about every accessor in this file, and would hash a different tree from every peer -- a fork
// rather than a parse error. The two encodings differ in length as well as content here, and
// both are written out by hand.
func TestABlankAndAZeroValuedNodeEncodeDifferently(t *testing.T) {
	blankWriter := syntax.NewWriter()
	if err := blankWriter.WriteOptional(false, func(w *syntax.Writer) error { return nil }); err != nil {
		t.Fatalf("WriteOptional(false): %v", err)
	}
	blank, err := blankWriter.Bytes()
	if err != nil {
		t.Fatalf("blank Bytes: %v", err)
	}

	presentWriter := syntax.NewWriter()
	if err := presentWriter.WriteOptional(true, func(w *syntax.Writer) error {
		return (&ParentNode{}).MarshalMLS(w)
	}); err != nil {
		t.Fatalf("WriteOptional(true): %v", err)
	}
	present, err := presentWriter.Bytes()
	if err != nil {
		t.Fatalf("present Bytes: %v", err)
	}

	// an absent entry is the presence octet and nothing else
	if !bytes.Equal(blank, []byte{0x00}) {
		t.Errorf("a blank entry encodes to %x, want 00", blank)
	}
	// a present zero valued parent node is the presence octet and three empty length prefixes
	if !bytes.Equal(present, []byte{0x01, 0x00, 0x00, 0x00}) {
		t.Errorf("a present zero valued parent node encodes to %x, want 01000000", present)
	}
	if bytes.Equal(blank, present) {
		t.Fatalf("a blank entry and a zero valued node encode identically (%x), which is a tree that agrees with itself and with no peer", blank)
	}
}

// TestNodeTypeHasNoZeroValuedMember is what makes a Go zero value unusable as a node.
//
// A Node that was never filled in carries NodeType zero, which is neither leaf nor parent, so
// no encoder will write it and no decoder will accept it. If either constant were zero, the
// zero value of Node would be a well formed node of that kind and the blank/absent distinction
// would have nothing but a nil pointer holding it up.
func TestNodeTypeHasNoZeroValuedMember(t *testing.T) {
	if NodeTypeLeaf == 0 || NodeTypeParent == 0 {
		t.Fatalf("NodeTypeLeaf = %d and NodeTypeParent = %d; a zero member makes the zero value of Node a well formed node",
			NodeTypeLeaf, NodeTypeParent)
	}
	if NodeTypeLeaf == NodeTypeParent {
		t.Fatalf("NodeTypeLeaf and NodeTypeParent are both %d", NodeTypeLeaf)
	}
	var zero Node
	if zero.NodeType == NodeTypeLeaf || zero.NodeType == NodeTypeParent {
		t.Fatalf("the zero value of Node names a node type")
	}
	// and presence on the wire unit is a field of its own rather than something derived from
	// whether the node looks filled in
	absent := OptionalNode{}
	if absent.Present {
		t.Fatalf("the zero value of OptionalNode reports present")
	}
	if (OptionalNode{Present: true}).Present == absent.Present {
		t.Fatalf("OptionalNode.Present does not distinguish a present entry from an absent one")
	}
}

// TestBlankPositionsAreExactlyTheUnsetOnesAtEveryWidth sweeps every node index of every width
// and requires blankness to agree, at every accessor, with the set of positions that were
// actually filled.
//
// Derived from the width rather than from a handful of named indices, because the defect this
// is about -- a blank materialised into an occupied position holding a zero valued node -- can
// hide at any index a test does not visit, and a tree that round trips against itself will not
// report it anywhere else.
func TestBlankPositionsAreExactlyTheUnsetOnesAtEveryWidth(t *testing.T) {
	blankLeaves, blankParents, occupiedParents := 0, 0, 0
	for _, leafCount := range []uint32{1, 2, 3, 5, 8} {
		tree, occupied := treeUnderTest(t, leafCount)
		if uint32(len(occupied)) == 0 {
			t.Fatalf("%d leaves: nothing was filled, so this sweep judged an empty tree", leafCount)
		}
		for x := uint32(0); x < tree.NodeWidth(); x += 1 {
			index := NodeIndex(x)
			wantBlank := !occupied[index]
			if tree.IsBlank(index) != wantBlank {
				t.Errorf("%d leaves: IsBlank(%d) = %v, want %v", leafCount, x, tree.IsBlank(index), wantBlank)
			}
			if (tree.Get(index) == nil) != wantBlank {
				t.Errorf("%d leaves: Get(%d) == nil is %v, want %v", leafCount, x, tree.Get(index) == nil, wantBlank)
			}
			if index.IsLeaf() {
				leafIndex, err := index.LeafIndex()
				if err != nil {
					t.Fatalf("%d leaves: LeafIndex(%d): %v", leafCount, x, err)
				}
				if (tree.Leaf(leafIndex) == nil) != wantBlank {
					t.Errorf("%d leaves: Leaf(%d) == nil is %v, want %v", leafCount, leafIndex, tree.Leaf(leafIndex) == nil, wantBlank)
				}
				if wantBlank {
					blankLeaves += 1
				}
				continue
			}
			if (tree.ParentAt(index) == nil) != wantBlank {
				t.Errorf("%d leaves: ParentAt(%d) == nil is %v, want %v", leafCount, x, tree.ParentAt(index) == nil, wantBlank)
			}
			if wantBlank {
				blankParents += 1
			} else {
				occupiedParents += 1
			}
		}
		// and a clone keeps exactly the same set blank, which is where a deep copy that
		// materialises a zero valued node in place of a nil would show up
		clone := tree.Clone()
		if clone.NodeWidth() != tree.NodeWidth() {
			t.Fatalf("%d leaves: the clone is %d nodes wide, the original is %d", leafCount, clone.NodeWidth(), tree.NodeWidth())
		}
		for x := uint32(0); x < tree.NodeWidth(); x += 1 {
			if clone.IsBlank(NodeIndex(x)) != tree.IsBlank(NodeIndex(x)) {
				t.Errorf("%d leaves: the clone reports node %d blank = %v, the original %v",
					leafCount, x, clone.IsBlank(NodeIndex(x)), tree.IsBlank(NodeIndex(x)))
			}
		}
	}
	// the sweep is only worth what it visited: a run that never saw a blank leaf, never saw a
	// blank parent, or never saw an occupied parent would pass against an implementation that
	// answered blank for everything or for nothing
	if blankLeaves == 0 || blankParents == 0 || occupiedParents == 0 {
		t.Fatalf("the sweep saw %d blank leaves, %d blank parents and %d occupied parents; it needs all three to separate anything",
			blankLeaves, blankParents, occupiedParents)
	}
}

// TestEveryOccupiedPositionCarriesTheNodeTypeItsIndexRequires derives the type from the index
// parity rather than checking a couple of positions.
//
// The wire format carries the type as an octet, so a leaf at an odd index is the shape a
// hostile ratchet_tree extension arrives in; a container that stored the wrong type would hand
// the tree hash a different structure at that position while every accessor still worked.
func TestEveryOccupiedPositionCarriesTheNodeTypeItsIndexRequires(t *testing.T) {
	checked := 0
	for _, leafCount := range []uint32{1, 3, 5, 8} {
		tree, occupied := treeUnderTest(t, leafCount)
		for x := uint32(0); x < tree.NodeWidth(); x += 1 {
			index := NodeIndex(x)
			node := tree.Get(index)
			if node == nil {
				if occupied[index] {
					t.Errorf("%d leaves: node %d was filled and reads blank", leafCount, x)
				}
				continue
			}
			checked += 1
			want := NodeTypeParent
			if index.IsLeaf() {
				want = NodeTypeLeaf
			}
			if node.NodeType != want {
				t.Errorf("%d leaves: node %d carries type %d, want %d", leafCount, x, node.NodeType, want)
			}
			if index.IsLeaf() && (node.Leaf == nil || node.Parent != nil) {
				t.Errorf("%d leaves: node %d is a leaf index holding leaf=%v parent=%v", leafCount, x, node.Leaf != nil, node.Parent != nil)
			}
			if !index.IsLeaf() && (node.Parent == nil || node.Leaf != nil) {
				t.Errorf("%d leaves: node %d is a parent index holding leaf=%v parent=%v", leafCount, x, node.Leaf != nil, node.Parent != nil)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no occupied position was examined, so this gate judged nothing")
	}
}

// TestBlankingAPositionMakesItAbsentAndNotOccupiedAndEmpty walks every occupied position of a
// tree, blanks it, and requires the whole container to agree that it is gone.
//
// One position at a time against a fresh tree, so the assertions are about the position that
// was blanked and not about whatever the previous iteration left behind.
func TestBlankingAPositionMakesItAbsentAndNotOccupiedAndEmpty(t *testing.T) {
	blanked := 0
	for _, leafCount := range []uint32{1, 3, 5, 8} {
		_, occupied := treeUnderTest(t, leafCount)
		for x := uint32(0); x < uint32(len(occupied))*4; x += 1 {
			index := NodeIndex(x)
			if !occupied[index] {
				continue
			}
			tree, _ := treeUnderTest(t, leafCount)
			before := tree.MemberCount()
			if err := tree.Blank(index); err != nil {
				t.Fatalf("%d leaves: Blank(%d): %v", leafCount, x, err)
			}
			blanked += 1
			if tree.Get(index) != nil {
				t.Errorf("%d leaves: Get(%d) after Blank = %+v, want nil", leafCount, x, tree.Get(index))
			}
			if !tree.IsBlank(index) {
				t.Errorf("%d leaves: IsBlank(%d) is false after Blank", leafCount, x)
			}
			if got := tree.UnmergedLeaves(index); len(got) != 0 {
				t.Errorf("%d leaves: a blanked node reports unmerged leaves %v", leafCount, got)
			}
			if index.IsLeaf() {
				leafIndex, err := index.LeafIndex()
				if err != nil {
					t.Fatalf("LeafIndex(%d): %v", x, err)
				}
				if tree.Leaf(leafIndex) != nil {
					t.Errorf("%d leaves: Leaf(%d) after Blank is not nil", leafCount, leafIndex)
				}
				if tree.MemberCount() != before-1 {
					t.Errorf("%d leaves: blanking leaf %d moved the member count from %d to %d",
						leafCount, leafIndex, before, tree.MemberCount())
				}
				for _, member := range tree.Members() {
					if member == leafIndex {
						t.Errorf("%d leaves: leaf %d is still a member after Blank", leafCount, leafIndex)
					}
				}
				continue
			}
			if tree.ParentAt(index) != nil {
				t.Errorf("%d leaves: ParentAt(%d) after Blank is not nil", leafCount, x)
			}
			if tree.MemberCount() != before {
				t.Errorf("%d leaves: blanking parent %d moved the member count from %d to %d",
					leafCount, x, before, tree.MemberCount())
			}
		}
	}
	if blanked == 0 {
		t.Fatal("nothing was blanked, so this gate judged nothing")
	}
}

// TestSetLeafAndSetParentRefuseANilPayload. A position that is occupied and empty at once is
// the blank-as-zero-valued-node conflation arriving through the front door: IsBlank would
// answer false, Leaf would answer nil, and the encoder would have a present node with nothing
// to write. Blank is how a position is emptied.
func TestSetLeafAndSetParentRefuseANilPayload(t *testing.T) {
	tree, _ := treeUnderTest(t, 4)
	if err := tree.SetLeaf(LeafIndex(3), nil); !errors.Is(err, ErrTreeMalformed) {
		t.Errorf("SetLeaf(3, nil) err = %v, want ErrTreeMalformed", err)
	}
	if tree.Leaf(LeafIndex(3)) == nil {
		t.Errorf("the refused SetLeaf emptied a position that was occupied")
	}
	if err := tree.Blank(NodeIndex(6)); err != nil {
		t.Fatalf("Blank(6): %v", err)
	}
	if err := tree.SetLeaf(LeafIndex(3), nil); !errors.Is(err, ErrTreeMalformed) {
		t.Errorf("SetLeaf(3, nil) err = %v, want ErrTreeMalformed", err)
	}
	if !tree.IsBlank(NodeIndex(6)) {
		t.Errorf("the refused SetLeaf occupied a blank position")
	}
	if err := tree.SetParent(NodeIndex(3), nil); !errors.Is(err, ErrTreeMalformed) {
		t.Errorf("SetParent(3, nil) err = %v, want ErrTreeMalformed", err)
	}
	if !tree.IsBlank(NodeIndex(3)) {
		t.Errorf("the refused SetParent occupied a blank position")
	}
}

// ---------------------------------------------------------------------------
// the container
// ---------------------------------------------------------------------------

// TestRatchetTreeGrowsByDoubling. RFC 9420 section 7.7 grows the tree by adding a blank root
// whose left subtree is the whole existing tree, never by one leaf, so the leaf width is always
// a power of two and the widths are a function of the highest occupied index alone.
func TestRatchetTreeGrowsByDoubling(t *testing.T) {
	tree := NewRatchetTree()
	if tree.LeafWidth() != 1 || tree.NodeWidth() != 1 {
		t.Fatalf("empty tree width = (%d, %d), want (1, 1)", tree.LeafWidth(), tree.NodeWidth())
	}
	// the widths after each SetLeaf, derived from the doubling rule rather than checked only
	// at the end: a container that grew to the final width in one step would pass a test that
	// looked only after the last call
	for i, want := range []struct {
		leaves LeafCount
		nodes  uint32
	}{
		{leaves: 1, nodes: 1},
		{leaves: 2, nodes: 3},
		{leaves: 4, nodes: 7},
		{leaves: 4, nodes: 7},
		{leaves: 8, nodes: 15},
	} {
		if err := tree.SetLeaf(LeafIndex(i), testTreeLeaf(uint32(i))); err != nil {
			t.Fatalf("SetLeaf(%d): %v", i, err)
		}
		if tree.LeafWidth() != want.leaves || tree.NodeWidth() != want.nodes {
			t.Fatalf("after SetLeaf(%d) width = (%d, %d), want (%d, %d)",
				i, tree.LeafWidth(), tree.NodeWidth(), want.leaves, want.nodes)
		}
	}
	if tree.MemberCount() != 5 {
		t.Fatalf("member count = %d, want 5", tree.MemberCount())
	}
	members := tree.Members()
	if !reflect.DeepEqual(members, []LeafIndex{0, 1, 2, 3, 4}) {
		t.Fatalf("members = %v, want [0 1 2 3 4]", members)
	}
	if !reflect.DeepEqual(tree.NonBlankLeaves(), members) {
		t.Fatalf("NonBlankLeaves = %v and Members = %v; they are one list", tree.NonBlankLeaves(), members)
	}
}

// TestGrowingDoesNotMoveTheNodesAlreadyThere. Doubling appends, so every existing node index
// means the same position afterwards. A growth that reindexed would keep every accessor
// working and silently move every member.
func TestGrowingDoesNotMoveTheNodesAlreadyThere(t *testing.T) {
	tree := NewRatchetTree()
	for i := uint32(0); i < 2; i += 1 {
		if err := tree.SetLeaf(LeafIndex(i), testTreeLeaf(i)); err != nil {
			t.Fatalf("SetLeaf(%d): %v", i, err)
		}
	}
	if err := tree.SetParent(NodeIndex(1), testParentNodeTemplate()); err != nil {
		t.Fatalf("SetParent(1): %v", err)
	}
	leafZero, leafOne, parentOne := tree.Get(NodeIndex(0)), tree.Get(NodeIndex(2)), tree.Get(NodeIndex(1))

	if err := tree.SetLeaf(LeafIndex(9), testTreeLeaf(9)); err != nil {
		t.Fatalf("SetLeaf(9): %v", err)
	}
	if tree.LeafWidth() != 16 || tree.NodeWidth() != 31 {
		t.Fatalf("after growing to hold leaf 9, width = (%d, %d), want (16, 31)", tree.LeafWidth(), tree.NodeWidth())
	}
	if tree.Get(NodeIndex(0)) != leafZero || tree.Get(NodeIndex(2)) != leafOne || tree.Get(NodeIndex(1)) != parentOne {
		t.Fatalf("growing moved the nodes that were already in the tree")
	}
	if tree.Leaf(LeafIndex(9)) == nil {
		t.Fatalf("leaf 9 is not in the grown tree")
	}
	if !reflect.DeepEqual(tree.Members(), []LeafIndex{0, 1, 9}) {
		t.Fatalf("members after growing = %v, want [0 1 9]", tree.Members())
	}
}

// TestRatchetTreeSetAndBlank covers the refusals each setter makes at its own boundary.
func TestRatchetTreeSetAndBlank(t *testing.T) {
	tree, _ := treeUnderTest(t, 4)
	parent := &ParentNode{
		EncryptionKey:  HpkePublicKey(repeatByte(0x55, 32)),
		ParentHash:     repeatByte(0x66, 32),
		UnmergedLeaves: []LeafIndex{2, 3},
	}
	if err := tree.SetParent(NodeIndex(3), parent); err != nil {
		t.Fatalf("SetParent: %v", err)
	}
	if got := tree.ParentAt(NodeIndex(3)); got == nil || !reflect.DeepEqual(got.UnmergedLeaves, []LeafIndex{2, 3}) {
		t.Fatalf("ParentAt(3) = %+v", got)
	}
	if tree.ParentAt(NodeIndex(0)) != nil {
		t.Fatalf("ParentAt(0) on a leaf index returned a parent node")
	}
	if err := tree.SetParent(NodeIndex(2), parent); !errors.Is(err, ErrNodeTypeMismatch) {
		t.Fatalf("SetParent on an even index err = %v, want ErrNodeTypeMismatch", err)
	}
	// a parent index past the end is a different refusal from an index of the wrong parity,
	// and a caller repairing the first re-derives an index while the second means the tree is
	// not the tree it thought
	if err := tree.SetParent(NodeIndex(tree.NodeWidth()), parent); !errors.Is(err, ErrNodeIndexOutOfRange) {
		t.Fatalf("SetParent past the end err = %v, want ErrNodeIndexOutOfRange", err)
	}
	if err := tree.Blank(NodeIndex(tree.NodeWidth())); !errors.Is(err, ErrNodeIndexOutOfRange) {
		t.Fatalf("Blank past the end err = %v, want ErrNodeIndexOutOfRange", err)
	}
	// SetLeaf grows rather than refusing, which is the whole difference between the two
	if err := tree.SetLeaf(LeafIndex(99), testTreeLeaf(99)); err != nil {
		t.Fatalf("SetLeaf(99) should grow the tree: %v", err)
	}
	if tree.LeafWidth() != 128 {
		t.Fatalf("after SetLeaf(99) leaf width = %d, want 128", tree.LeafWidth())
	}
	if err := tree.SetLeaf(LeafIndex(MaxLeafCount), testTreeLeaf(0)); !errors.Is(err, ErrLeafIndexOutOfRange) {
		t.Fatalf("SetLeaf at MaxLeafCount err = %v, want ErrLeafIndexOutOfRange", err)
	}
	if err := tree.Blank(NodeIndex(3)); err != nil {
		t.Fatalf("Blank: %v", err)
	}
	if tree.Get(NodeIndex(3)) != nil {
		t.Fatalf("node 3 is not blank after Blank")
	}
}

// TestRatchetTreeBlankDirectPath requires exactly the direct path to be blanked: the tree math
// decides which nodes those are, and everything else the tree held must survive.
//
// Derived from DirectPath rather than from three named indices, and the survivors are checked
// as well as the casualties -- a BlankDirectPath that blanked the whole array would satisfy a
// test that only looked at the path.
func TestRatchetTreeBlankDirectPath(t *testing.T) {
	tree, occupied := treeUnderTest(t, 4)
	for x := uint32(1); x < tree.NodeWidth(); x += 2 {
		if occupied[NodeIndex(x)] {
			continue
		}
		if err := tree.SetParent(NodeIndex(x), &ParentNode{
			EncryptionKey: HpkePublicKey(repeatByte(byte(x), 32)),
		}); err != nil {
			t.Fatalf("SetParent(%d): %v", x, err)
		}
		occupied[NodeIndex(x)] = true
	}

	path, err := DirectPath(LeafIndex(0).NodeIndex(), tree.LeafWidth())
	if err != nil {
		t.Fatalf("DirectPath: %v", err)
	}
	if len(path) == 0 {
		t.Fatal("the direct path of leaf 0 in a four leaf tree is empty, so this test blanks nothing")
	}
	onPath := map[NodeIndex]bool{}
	for _, x := range path {
		onPath[x] = true
	}

	if err := tree.BlankDirectPath(LeafIndex(0)); err != nil {
		t.Fatalf("BlankDirectPath: %v", err)
	}
	survived := 0
	for x := uint32(0); x < tree.NodeWidth(); x += 1 {
		index := NodeIndex(x)
		wantBlank := onPath[index] || !occupied[index]
		if tree.IsBlank(index) != wantBlank {
			t.Errorf("after BlankDirectPath(0), IsBlank(%d) = %v, want %v (on path %v, occupied %v)",
				x, tree.IsBlank(index), wantBlank, onPath[index], occupied[index])
		}
		if !wantBlank {
			survived += 1
		}
	}
	if survived == 0 {
		t.Fatal("BlankDirectPath blanked everything, so nothing separates it from Blank over the whole array")
	}
	if tree.Leaf(LeafIndex(0)) == nil {
		t.Fatal("BlankDirectPath must not blank the leaf itself")
	}
	if err := tree.BlankDirectPath(LeafIndex(tree.LeafWidth())); !errors.Is(err, ErrLeafIndexOutOfRange) {
		t.Fatalf("BlankDirectPath past the width err = %v, want ErrLeafIndexOutOfRange", err)
	}
}

// TestRatchetTreeCloneIsIndependent. Nothing may alias between two epochs' trees: a commit that
// is later rejected must leave the epoch it was computed against exactly as it found it, and a
// shared backing array is how a rejected commit mutates a tree that never accepted it.
func TestRatchetTreeCloneIsIndependent(t *testing.T) {
	tree, _ := treeUnderTest(t, 4)
	if err := tree.SetParent(NodeIndex(3), testParentNodeTemplate()); err != nil {
		t.Fatalf("SetParent: %v", err)
	}

	clone := tree.Clone()
	if err := clone.Blank(NodeIndex(0)); err != nil {
		t.Fatalf("Blank: %v", err)
	}
	if tree.Leaf(LeafIndex(0)) == nil {
		t.Fatal("blanking the clone blanked the original")
	}

	clone2 := tree.Clone()
	clone2.Leaf(LeafIndex(0)).EncryptionKey[0] ^= 0xff
	if tree.Leaf(LeafIndex(0)).EncryptionKey[0] == clone2.Leaf(LeafIndex(0)).EncryptionKey[0] {
		t.Error("Clone shares leaf key material with the original")
	}
	clone2.ParentAt(NodeIndex(3)).EncryptionKey[0] ^= 0xff
	if tree.ParentAt(NodeIndex(3)).EncryptionKey[0] == clone2.ParentAt(NodeIndex(3)).EncryptionKey[0] {
		t.Error("Clone shares parent key material with the original")
	}
	clone2.ParentAt(NodeIndex(3)).UnmergedLeaves[0] = 0xffff
	if tree.ParentAt(NodeIndex(3)).UnmergedLeaves[0] == clone2.ParentAt(NodeIndex(3)).UnmergedLeaves[0] {
		t.Error("Clone shares the unmerged leaf list with the original")
	}
	// and installing into the clone does not reach the original's array
	if err := clone2.SetLeaf(LeafIndex(7), testTreeLeaf(7)); err != nil {
		t.Fatalf("SetLeaf on the clone: %v", err)
	}
	if tree.Leaf(LeafIndex(7)) != nil || tree.LeafWidth() != 4 {
		t.Errorf("growing the clone reached the original: width %d, leaf 7 present %v", tree.LeafWidth(), tree.Leaf(LeafIndex(7)) != nil)
	}
}

// TestRatchetTreeFindLeafBySignatureKey. Every leaf of the test tree carries a distinct
// signature key, so an implementation answering the wrong position fails rather than passing
// against a tree where every answer is the same.
func TestRatchetTreeFindLeafBySignatureKey(t *testing.T) {
	tree, _ := treeUnderTest(t, 3)
	for i := uint32(0); i < 3; i += 1 {
		got, ok := tree.FindLeafBySignatureKey(SignaturePublicKey(repeatByte(byte(0x80+i), 32)))
		if !ok || got != LeafIndex(i) {
			t.Errorf("FindLeafBySignatureKey for leaf %d = (%d, %v), want (%d, true)", i, got, ok, i)
		}
	}
	if _, ok := tree.FindLeafBySignatureKey(SignaturePublicKey(repeatByte(0x09, 32))); ok {
		t.Error("FindLeafBySignatureKey found an absent key")
	}
	// a prefix of a present key is not that key: the comparison is over the whole value, and a
	// length insensitive one would answer here
	if _, ok := tree.FindLeafBySignatureKey(SignaturePublicKey(repeatByte(0x80, 31))); ok {
		t.Error("FindLeafBySignatureKey accepted a prefix of a present key")
	}
	if _, ok := tree.FindLeafBySignatureKey(nil); ok {
		t.Error("FindLeafBySignatureKey accepted a nil key")
	}
	if err := tree.Blank(LeafIndex(1).NodeIndex()); err != nil {
		t.Fatalf("Blank: %v", err)
	}
	if _, ok := tree.FindLeafBySignatureKey(SignaturePublicKey(repeatByte(0x81, 32))); ok {
		t.Error("FindLeafBySignatureKey found a leaf that has been blanked")
	}
}

// TestEncryptionKeyInUseReadsLeavesAndParentsAlike. ValSem103 and ValSem110 ask this once per
// proposal, and a check that looked only at leaves would accept an add whose key is already a
// parent's -- a member that can decrypt a path secret it was never sent.
func TestEncryptionKeyInUseReadsLeavesAndParentsAlike(t *testing.T) {
	tree, _ := treeUnderTest(t, 3)
	for i := uint32(0); i < 3; i += 1 {
		if !tree.EncryptionKeyInUse(HpkePublicKey(repeatByte(byte(0x40+i), 32))) {
			t.Errorf("EncryptionKeyInUse missed leaf %d's key", i)
		}
	}
	if tree.EncryptionKeyInUse(HpkePublicKey(repeatByte(0x99, 32))) {
		t.Error("EncryptionKeyInUse found an absent key")
	}
	if err := tree.SetParent(NodeIndex(1), &ParentNode{
		EncryptionKey:  HpkePublicKey(repeatByte(0x50, 32)),
		UnmergedLeaves: []LeafIndex{1},
	}); err != nil {
		t.Fatalf("SetParent: %v", err)
	}
	if !tree.EncryptionKeyInUse(HpkePublicKey(repeatByte(0x50, 32))) {
		t.Error("EncryptionKeyInUse ignored a parent node key")
	}
	if err := tree.Blank(NodeIndex(1)); err != nil {
		t.Fatalf("Blank: %v", err)
	}
	if tree.EncryptionKeyInUse(HpkePublicKey(repeatByte(0x50, 32))) {
		t.Error("EncryptionKeyInUse answered for a node that has been blanked")
	}
}

// TestRatchetTreeIsTheNodeShapeTheTreeMathWalks. Implementing NodeShape is what lets the tree
// math plan's Resolution and FilteredDirectPath run against a real tree, which is why this plan
// has no resolution algorithm of its own.
func TestRatchetTreeIsTheNodeShapeTheTreeMathWalks(t *testing.T) {
	tree, _ := treeUnderTest(t, 3)
	if err := tree.SetParent(NodeIndex(1), &ParentNode{
		EncryptionKey:  HpkePublicKey(repeatByte(0x50, 32)),
		UnmergedLeaves: []LeafIndex{1},
	}); err != nil {
		t.Fatalf("SetParent: %v", err)
	}
	var shape NodeShape = tree

	// three leaves means a width of four, stated rather than read back off the tree: a
	// comparison against tree.LeafWidth() is the same expression on both sides
	if shape.LeafCount() != LeafCount(4) {
		t.Errorf("NodeShape.LeafCount = %d, want 4", shape.LeafCount())
	}
	if shape.IsBlank(NodeIndex(0)) {
		t.Error("leaf 0 reported blank")
	}
	if !shape.IsBlank(NodeIndex(6)) {
		t.Error("leaf 3 is unoccupied and must report blank")
	}
	if got := shape.UnmergedLeaves(NodeIndex(1)); !reflect.DeepEqual(got, []LeafIndex{1}) {
		t.Errorf("NodeShape.UnmergedLeaves(1) = %v, want [1]", got)
	}
	if got := shape.UnmergedLeaves(NodeIndex(3)); len(got) != 0 {
		t.Errorf("a blank parent has no unmerged leaves, got %v", got)
	}
	if got := shape.UnmergedLeaves(NodeIndex(0)); len(got) != 0 {
		t.Errorf("a leaf has no unmerged leaves, got %v", got)
	}

	// and the resolution the tree math computes over this shape is the one RFC 9420 section
	// 4.1 defines, which is where blankness stops being a fact about this container and
	// starts deciding who a path secret is encrypted to. Node 3 is the root of a four leaf
	// tree and is blank, so it resolves to its children's resolutions: node 1 is occupied and
	// carries leaf 1 as an unmerged leaf, so it is followed immediately by node 2, and node 5
	// is occupied so it stands for the whole right subtree.
	resolution, err := Resolution(shape, NodeIndex(3))
	if err != nil {
		t.Fatalf("Resolution: %v", err)
	}
	if !reflect.DeepEqual(resolution, []NodeIndex{1, 2, 5}) {
		t.Errorf("Resolution(3) = %v, want [1 2 5]", resolution)
	}
	// blanking node 5 pushes the walk down to its children: node 4 is leaf 2 and occupied, so
	// it stands in; node 6 is leaf 3 and blank, and a blank LEAF resolves to nothing at all,
	// which is the one place where treating a blank as a zero valued node would put a member
	// that does not exist into the list a path secret is encrypted to.
	if err := tree.Blank(NodeIndex(5)); err != nil {
		t.Fatalf("Blank(5): %v", err)
	}
	resolution, err = Resolution(shape, NodeIndex(3))
	if err != nil {
		t.Fatalf("Resolution after blanking node 5: %v", err)
	}
	if !reflect.DeepEqual(resolution, []NodeIndex{1, 2, 4}) {
		t.Errorf("Resolution(3) after blanking node 5 = %v, want [1 2 4]", resolution)
	}
}

// TestHasTrailingBlankNodesIsTheLastPositionAndNotAnyBlank. RFC 9420 section 12.4.3.1 forbids
// an exported ratchet_tree ending in a blank; it says nothing about blanks in the middle, and a
// predicate that reported "any blank" would refuse almost every real tree.
func TestHasTrailingBlankNodesIsTheLastPositionAndNotAnyBlank(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		leaves  []uint32
		trailer bool
	}{
		{name: "one leaf, full", leaves: []uint32{0}, trailer: false},
		{name: "two leaves, full", leaves: []uint32{0, 1}, trailer: false},
		{name: "three of four leaves", leaves: []uint32{0, 1, 2}, trailer: true},
		{name: "a hole in the middle", leaves: []uint32{0, 3}, trailer: false},
		{name: "only the last leaf", leaves: []uint32{1}, trailer: false},
		{name: "only the first leaf of two", leaves: []uint32{0, 1}, trailer: false},
	} {
		tree := NewRatchetTree()
		for _, i := range testCase.leaves {
			if err := tree.SetLeaf(LeafIndex(i), testTreeLeaf(i)); err != nil {
				t.Fatalf("%s: SetLeaf(%d): %v", testCase.name, i, err)
			}
		}
		if tree.HasTrailingBlankNodes() != testCase.trailer {
			t.Errorf("%s: HasTrailingBlankNodes = %v, want %v (node width %d)",
				testCase.name, tree.HasTrailingBlankNodes(), testCase.trailer, tree.NodeWidth())
		}
	}
	// and blanking the last leaf of a full tree turns it on, which is the transition ValSem300
	// is about
	tree, _ := treeUnderTest(t, 4)
	if tree.HasTrailingBlankNodes() {
		t.Fatal("a four leaf tree with every leaf occupied reports a trailing blank")
	}
	if err := tree.Blank(LeafIndex(3).NodeIndex()); err != nil {
		t.Fatalf("Blank: %v", err)
	}
	if !tree.HasTrailingBlankNodes() {
		t.Error("blanking the rightmost leaf did not produce a trailing blank")
	}
}

// TestTheAccessorsRefuseAnIndexPastTheWidthRatherThanWrapping.
//
// LeafIndex.NodeIndex is total and wraps: leaf 2^31 answers node 0. Without a leaf range check
// of its own, Leaf would hand back leaf 0's contents for it, which is a member reading another
// member's credential and believing it is their own.
func TestTheAccessorsRefuseAnIndexPastTheWidthRatherThanWrapping(t *testing.T) {
	tree, _ := treeUnderTest(t, 2)
	if tree.Leaf(LeafIndex(0)) == nil {
		t.Fatal("leaf 0 is not in the tree, so the wrap below proves nothing")
	}
	for _, i := range []LeafIndex{LeafIndex(tree.LeafWidth()), LeafIndex(1 << 31), LeafIndex(0xffffffff)} {
		if got := tree.Leaf(i); got != nil {
			t.Errorf("Leaf(%d) on a %d leaf tree = %p, want nil", i, tree.LeafWidth(), got)
		}
	}
	for _, x := range []NodeIndex{NodeIndex(tree.NodeWidth()), NodeIndex(0xffffffff)} {
		if tree.Get(x) != nil {
			t.Errorf("Get(%d) past the end is not nil", x)
		}
		if !tree.IsBlank(x) {
			t.Errorf("IsBlank(%d) past the end is false", x)
		}
		if tree.ParentAt(x) != nil {
			t.Errorf("ParentAt(%d) past the end is not nil", x)
		}
	}
}
