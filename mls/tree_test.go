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
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"strings"
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

// ---------------------------------------------------------------------------
// the trees every structural sweep judges
// ---------------------------------------------------------------------------

// treeCase is one tree a caller can be holding, together with the exact set of node indices
// occupied in it. build answers a FRESH tree per use, so a sweep that blanks or installs cannot
// reach the next assertion through a tree it shared.
type treeCase struct {
	name      string
	leafWidth uint32
	nodeWidth uint32
	occupied  map[NodeIndex]bool
	build     func(t *testing.T) *RatchetTree
}

// treeWithOccupancy answers the tree of this leaf width whose occupied positions are exactly the
// ones the predicate accepts.
//
// The width is reached by installing the rightmost leaf and blanking it again, because the
// container grows only through SetLeaf and RFC 9420 section 7.7 grows it by doubling. That is
// the only route a caller has to a wide tree whose leftmost positions are blank -- which is what
// a group whose first members left is -- and reaching in past the accessors to build one would
// put this helper's own idea of a blank into the trees the sweeps then judge.
func treeWithOccupancy(t *testing.T, leafWidth uint32, isOccupied func(NodeIndex) bool) *RatchetTree {
	t.Helper()
	tree := NewRatchetTree()
	rightmost := LeafIndex(leafWidth - 1)
	if err := tree.SetLeaf(rightmost, testTreeLeaf(leafWidth-1)); err != nil {
		t.Fatalf("SetLeaf(%d) growing to %d leaves: %v", rightmost, leafWidth, err)
	}
	if err := tree.Blank(rightmost.NodeIndex()); err != nil {
		t.Fatalf("Blank(%d): %v", rightmost.NodeIndex(), err)
	}
	if tree.LeafWidth() != LeafCount(leafWidth) {
		t.Fatalf("growing to %d leaves produced a %d leaf tree", leafWidth, tree.LeafWidth())
	}
	for x := uint32(0); x < tree.NodeWidth(); x += 1 {
		index := NodeIndex(x)
		if !isOccupied(index) {
			continue
		}
		if index.IsLeaf() {
			leafIndex, err := index.LeafIndex()
			if err != nil {
				t.Fatalf("LeafIndex(%d): %v", x, err)
			}
			if err := tree.SetLeaf(leafIndex, testTreeLeaf(uint32(leafIndex))); err != nil {
				t.Fatalf("SetLeaf(%d): %v", leafIndex, err)
			}
			continue
		}
		// every occupied parent carries an unmerged leaf, so a sweep that asks a parent for
		// its unmerged list is asking one that has something to answer
		if err := tree.SetParent(index, &ParentNode{
			EncryptionKey:  HpkePublicKey(repeatByte(byte(0xc0+x), 32)),
			UnmergedLeaves: []LeafIndex{LeafIndex(x)},
		}); err != nil {
			t.Fatalf("SetParent(%d): %v", x, err)
		}
	}
	return tree
}

// The name of the one member of the family that is the constructor's own answer, so the
// coverage gate can say it judged that tree rather than a rebuild of it.
const constructedTreeCaseName = "the constructor's answer"

// treeCasesUnderTest is every tree the structural sweeps below judge, derived from the widths the
// container can hold rather than from the handful one helper happens to build.
//
// The family this replaced was one tree per width and every one of them came out of
// treeUnderTest, which fills leaf 0 first. So no sweep in this file had ever seen a tree whose
// leaf 0 was blank, and none of them had ever seen the tree the constructor hands back: a
// NewRatchetTree answering a one leaf tree that held a zero valued *Node rather than an absent
// entry -- occupied and empty at once, the conflation tree.go's file header says SetLeaf and
// SetParent refuse to create -- passed the whole suite. The blank sweep derived its POSITIONS
// from the node width and did not derive its TREES.
//
// So the trees are derived as well, and the derivation is stated as coverage rather than as a
// list: every position of every width has to be seen blank in one member of the family and
// occupied in another, which the gate below asserts of this family before any sweep uses it.
// Exhaustively over every occupancy at the two widths small enough to afford it, and by the
// single occupied and single blank families above that, which is what makes the coverage claim
// true at fifteen positions without thirty two thousand trees.
//
// The constructor's own answer is a member in its own right, and it is the one member no builder
// here reproduces: every other tree in the family has been through SetLeaf.
func treeCasesUnderTest(t *testing.T) []treeCase {
	t.Helper()
	cases := []treeCase{{
		name:      constructedTreeCaseName,
		leafWidth: 1,
		nodeWidth: 1,
		occupied:  map[NodeIndex]bool{},
		build:     func(t *testing.T) *RatchetTree { return NewRatchetTree() },
	}}
	add := func(name string, leafWidth uint32, isOccupied func(NodeIndex) bool) {
		nodeWidth := 2*leafWidth - 1
		occupied := map[NodeIndex]bool{}
		for x := uint32(0); x < nodeWidth; x += 1 {
			if isOccupied(NodeIndex(x)) {
				occupied[NodeIndex(x)] = true
			}
		}
		cases = append(cases, treeCase{
			name:      name,
			leafWidth: leafWidth,
			nodeWidth: nodeWidth,
			occupied:  occupied,
			build: func(t *testing.T) *RatchetTree {
				return treeWithOccupancy(t, leafWidth, isOccupied)
			},
		})
	}
	// the leaf widths are the powers of two, because RFC 9420 section 7.7 grows and shrinks by
	// doubling and halving and no other width is reachable
	for _, leafWidth := range []uint32{1, 2, 4, 8} {
		nodeWidth := 2*leafWidth - 1
		if nodeWidth <= 3 {
			for mask := uint32(0); mask < 1<<nodeWidth; mask += 1 {
				occupancy := mask
				add(fmt.Sprintf("%d leaves, occupancy %0*b", leafWidth, nodeWidth, occupancy), leafWidth,
					func(x NodeIndex) bool { return occupancy&(1<<uint32(x)) != 0 })
			}
			continue
		}
		add(fmt.Sprintf("%d leaves, every position blank", leafWidth), leafWidth,
			func(x NodeIndex) bool { return false })
		add(fmt.Sprintf("%d leaves, every position occupied", leafWidth), leafWidth,
			func(x NodeIndex) bool { return true })
		for x := uint32(0); x < nodeWidth; x += 1 {
			only := NodeIndex(x)
			add(fmt.Sprintf("%d leaves, only node %d occupied", leafWidth, x), leafWidth,
				func(candidate NodeIndex) bool { return candidate == only })
			add(fmt.Sprintf("%d leaves, only node %d blank", leafWidth, x), leafWidth,
				func(candidate NodeIndex) bool { return candidate != only })
		}
	}
	return cases
}

// assertTheTreeAgreesWithItsOccupancy asks every accessor of the container about every position
// of one tree and holds the answers against the set of positions that were actually filled.
//
// One helper rather than one assertion per test, because the property is the same at every entry
// point: a position is either ABSENT -- nil from Get, blank from IsBlank, nothing from Leaf or
// ParentAt, outside Members -- or it holds a node, and there is no third state. Occupied and
// empty at once is the blank as zero valued node conflation, and it reaches a tree through
// whichever accessor nobody thought to ask.
func assertTheTreeAgreesWithItsOccupancy(t *testing.T, label string, tree *RatchetTree, occupied map[NodeIndex]bool, nodeWidth uint32) {
	t.Helper()
	if tree.NodeWidth() != nodeWidth {
		t.Errorf("%s: node width %d, want %d", label, tree.NodeWidth(), nodeWidth)
		return
	}
	members := []LeafIndex{}
	for x := uint32(0); x < nodeWidth; x += 1 {
		index := NodeIndex(x)
		wantBlank := !occupied[index]
		if tree.IsBlank(index) != wantBlank {
			t.Errorf("%s: IsBlank(%d) = %v, want %v", label, x, tree.IsBlank(index), wantBlank)
		}
		if (tree.Get(index) == nil) != wantBlank {
			t.Errorf("%s: Get(%d) == nil is %v, want %v", label, x, tree.Get(index) == nil, wantBlank)
		}
		if index.IsLeaf() {
			leafIndex, err := index.LeafIndex()
			if err != nil {
				t.Fatalf("%s: LeafIndex(%d): %v", label, x, err)
			}
			if (tree.Leaf(leafIndex) == nil) != wantBlank {
				t.Errorf("%s: Leaf(%d) == nil is %v, want %v", label, leafIndex, tree.Leaf(leafIndex) == nil, wantBlank)
			}
			if !wantBlank {
				members = append(members, leafIndex)
			}
			continue
		}
		if (tree.ParentAt(index) == nil) != wantBlank {
			t.Errorf("%s: ParentAt(%d) == nil is %v, want %v", label, x, tree.ParentAt(index) == nil, wantBlank)
		}
	}
	if tree.MemberCount() != uint32(len(members)) {
		t.Errorf("%s: MemberCount = %d, want %d", label, tree.MemberCount(), len(members))
	}
	if got := tree.Members(); !reflect.DeepEqual(got, members) {
		t.Errorf("%s: Members = %v, want %v", label, got, members)
	}
}

// assertEveryOccupiedPositionCarriesItsType derives the node type from the index parity and
// answers how many leaves and how many parents it examined, so a caller can say what it judged.
func assertEveryOccupiedPositionCarriesItsType(t *testing.T, label string, tree *RatchetTree, occupied map[NodeIndex]bool) (int, int) {
	t.Helper()
	leaves, parents := 0, 0
	for x := uint32(0); x < tree.NodeWidth(); x += 1 {
		index := NodeIndex(x)
		node := tree.Get(index)
		if node == nil {
			if occupied[index] {
				t.Errorf("%s: node %d was filled and reads blank", label, x)
			}
			continue
		}
		want := NodeTypeParent
		if index.IsLeaf() {
			want = NodeTypeLeaf
		}
		if node.NodeType != want {
			t.Errorf("%s: node %d carries type %d, want %d", label, x, node.NodeType, want)
		}
		if index.IsLeaf() {
			leaves += 1
			if node.Leaf == nil || node.Parent != nil {
				t.Errorf("%s: node %d is a leaf index holding leaf=%v parent=%v", label, x, node.Leaf != nil, node.Parent != nil)
			}
			continue
		}
		parents += 1
		if node.Parent == nil || node.Leaf != nil {
			t.Errorf("%s: node %d is a parent index holding leaf=%v parent=%v", label, x, node.Leaf != nil, node.Parent != nil)
		}
	}
	return leaves, parents
}

// TestTheFamilyOfTreesTheSweepsJudgeCoversEveryPositionInBothStates is the derivation's own
// gate, and it runs before any sweep uses the family.
//
// A sweep is worth exactly what it was pointed at. The family this replaced covered every
// position of every width in the OCCUPIED state and covered position 0 in the blank state at no
// width at all, which is how a constructor handing back an occupied position where the whole
// file says there is a blank one passed the package. So the claim the sweeps rest on is made
// here and made mechanically: at every width, every position appears blank in some member of
// the family and occupied in some other, some member holds nothing at all, and the constructor's
// own answer is one of the members.
func TestTheFamilyOfTreesTheSweepsJudgeCoversEveryPositionInBothStates(t *testing.T) {
	cases := treeCasesUnderTest(t)
	if len(cases) == 0 {
		t.Fatal("the family is empty, so every sweep over it judges nothing")
	}
	seenBlank := map[uint32]map[uint32]bool{}
	seenOccupied := map[uint32]map[uint32]bool{}
	widths := []uint32{}
	constructed, allBlank := 0, 0
	for _, one := range cases {
		if seenBlank[one.nodeWidth] == nil {
			seenBlank[one.nodeWidth] = map[uint32]bool{}
			seenOccupied[one.nodeWidth] = map[uint32]bool{}
			widths = append(widths, one.nodeWidth)
		}
		for x := uint32(0); x < one.nodeWidth; x += 1 {
			if one.occupied[NodeIndex(x)] {
				seenOccupied[one.nodeWidth][x] = true
			} else {
				seenBlank[one.nodeWidth][x] = true
			}
		}
		if len(one.occupied) == 0 {
			allBlank += 1
		}
		if one.name == constructedTreeCaseName {
			constructed += 1
		}
	}
	slices.Sort(widths)
	for _, nodeWidth := range widths {
		for x := uint32(0); x < nodeWidth; x += 1 {
			if !seenBlank[nodeWidth][x] {
				t.Errorf("no tree of node width %d in the family has node %d blank, so no sweep over it can tell a blank there from a node", nodeWidth, x)
			}
			if !seenOccupied[nodeWidth][x] {
				t.Errorf("no tree of node width %d in the family has node %d occupied, so no sweep over it can tell a node there from a blank", nodeWidth, x)
			}
		}
	}
	if allBlank == 0 {
		t.Error("no member of the family holds nothing at all, which is the shape a constructor hands back and the shape every sweep here used to miss")
	}
	if constructed != 1 {
		t.Errorf("%d members of the family are %q; the constructor's answer is the one tree no builder here reproduces and it has to be judged as itself", constructed, constructedTreeCaseName)
	}
	t.Logf("%d trees over %d widths, %d of them holding nothing", len(cases), len(widths), allBlank)
}

// TestBlankPositionsAreExactlyTheUnsetOnesAtEveryWidth sweeps every node index of every tree in
// the derived family and requires blankness to agree, at every accessor, with the set of
// positions that were actually filled.
//
// Derived from the width AND from the family rather than from a handful of named indices in a
// handful of trees, because the defect this is about -- a blank materialised into an occupied
// position holding a zero valued node -- can hide at any index of any tree a sweep does not
// visit, and a tree that round trips against itself will not report it anywhere else. The tree
// the constructor hands back is where it hid last time.
//
// Every case is judged twice: as built, and cloned. A deep copy that turned a nil entry into an
// occupied position holding a zero valued node is the same conflation arriving through the copy
// constructor, and every provisional tree in TreeKEM is a clone.
func TestBlankPositionsAreExactlyTheUnsetOnesAtEveryWidth(t *testing.T) {
	judged := 0
	for _, one := range treeCasesUnderTest(t) {
		tree := one.build(t)
		assertTheTreeAgreesWithItsOccupancy(t, one.name, tree, one.occupied, one.nodeWidth)
		assertTheTreeAgreesWithItsOccupancy(t, one.name+", cloned", tree.Clone(), one.occupied, one.nodeWidth)
		judged += 2
	}
	if judged == 0 {
		t.Fatal("no tree was judged")
	}
	t.Logf("%d trees judged, originals and clones", judged)
}

// TestEveryOccupiedPositionCarriesTheNodeTypeItsIndexRequires derives the type from the index
// parity rather than checking a couple of positions.
//
// The wire format carries the type as an octet, so a leaf at an odd index is the shape a hostile
// ratchet_tree extension arrives in; a container that stored the wrong type would hand the tree
// hash a different structure at that position while every accessor still worked.
//
// The CLONE of every tree is walked as well as the tree, and that half is not symmetry. Every
// provisional tree in TreeKEM is built through RatchetTree.Clone, so a Node.Clone that dropped
// the node type would make every node of every provisional tree a node of no type -- the value
// TestNodeTypeHasNoZeroValuedMember exists to make unwritable and undecodable. That mutation
// passed the whole suite, because this sweep walked only the original and the clone was checked
// for blankness and for key material independence and never for the types it carried.
func TestEveryOccupiedPositionCarriesTheNodeTypeItsIndexRequires(t *testing.T) {
	leaves, parents, clonedLeaves, clonedParents := 0, 0, 0, 0
	for _, one := range treeCasesUnderTest(t) {
		tree := one.build(t)
		leafCount, parentCount := assertEveryOccupiedPositionCarriesItsType(t, one.name, tree, one.occupied)
		leaves += leafCount
		parents += parentCount
		leafCount, parentCount = assertEveryOccupiedPositionCarriesItsType(t, one.name+", cloned", tree.Clone(), one.occupied)
		clonedLeaves += leafCount
		clonedParents += parentCount
	}
	if leaves == 0 || parents == 0 {
		t.Fatalf("the sweep examined %d occupied leaves and %d occupied parents; it needs both to separate anything", leaves, parents)
	}
	if clonedLeaves == 0 || clonedParents == 0 {
		t.Fatalf("the sweep examined %d cloned leaves and %d cloned parents; a clone that carried no node type is what this half is here for", clonedLeaves, clonedParents)
	}
	t.Logf("%d leaves and %d parents examined, %d and %d of them in clones", leaves, parents, clonedLeaves, clonedParents)
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

// ---------------------------------------------------------------------------
// what the container owns and what it hands back
// ---------------------------------------------------------------------------

// TestInstallingANodeCopiesItAndTheAccessorsHandBackTheStoredOne states the ownership contract
// in the one direction it has, in both halves.
//
// It was unpinned in BOTH directions before: SetLeaf adopting the caller's pointer passed, and
// SetLeaf storing a copy passed, so a later task could flip it with nothing failing. The
// direction chosen is the one RatchetTree.Clone's own comment requires -- nothing may alias
// between two epochs' trees -- because an install that adopted would make
// tree.SetLeaf(i, other.Leaf(j)) put one *LeafNode in two of them, after which a commit computed
// against one epoch and later rejected has already written through the other.
//
// The second half is the part that makes the first usable: the accessors hand back the tree's
// OWN node, so a caller that means to keep editing reads it back rather than holding on to what
// it passed in. A container that copied on the way in and on the way out would pass the first
// half of this and leave no way to edit a tree at all.
func TestInstallingANodeCopiesItAndTheAccessorsHandBackTheStoredOne(t *testing.T) {
	tree, _ := treeUnderTest(t, 4)

	installed := testTreeLeaf(9)
	if err := tree.SetLeaf(LeafIndex(1), installed); err != nil {
		t.Fatalf("SetLeaf: %v", err)
	}
	if stored := tree.Leaf(LeafIndex(1)); stored == installed {
		t.Error("SetLeaf stored the caller's own *LeafNode, so the caller and the tree share one node")
	}
	installed.SignatureKey[0] ^= 0xff
	if tree.Leaf(LeafIndex(1)).SignatureKey[0] == installed.SignatureKey[0] {
		t.Error("writing through the leaf that was installed reached the tree, so SetLeaf adopted it rather than copying it")
	}
	// and the accessor is the way in: this is how a caller edits a leaf it has installed
	before := tree.Leaf(LeafIndex(1)).SignatureKey[0]
	tree.Leaf(LeafIndex(1)).SignatureKey[0] ^= 0xff
	if tree.Leaf(LeafIndex(1)).SignatureKey[0] == before {
		t.Error("writing through Leaf did not reach the tree, so the tree hands out a copy and cannot be edited at all")
	}

	installedParent := testParentNodeTemplate()
	if err := tree.SetParent(NodeIndex(1), installedParent); err != nil {
		t.Fatalf("SetParent: %v", err)
	}
	if stored := tree.ParentAt(NodeIndex(1)); stored == installedParent {
		t.Error("SetParent stored the caller's own *ParentNode")
	}
	installedParent.EncryptionKey[0] ^= 0xff
	if tree.ParentAt(NodeIndex(1)).EncryptionKey[0] == installedParent.EncryptionKey[0] {
		t.Error("writing through the parent node that was installed reached the tree")
	}
	installedParent.UnmergedLeaves[0] = 0xffff
	if tree.ParentAt(NodeIndex(1)).UnmergedLeaves[0] == installedParent.UnmergedLeaves[0] {
		t.Error("the installed parent node shares its unmerged leaf list with the tree")
	}

	// the aliasing this closes, spelled as the operation that would have produced it: one leaf
	// taken out of one tree and installed in another
	other := NewRatchetTree()
	if err := other.SetLeaf(LeafIndex(0), tree.Leaf(LeafIndex(1))); err != nil {
		t.Fatalf("SetLeaf on the second tree: %v", err)
	}
	other.Leaf(LeafIndex(0)).SignatureKey[0] ^= 0xff
	if tree.Leaf(LeafIndex(1)).SignatureKey[0] == other.Leaf(LeafIndex(0)).SignatureKey[0] {
		t.Error("one leaf is installed in two trees at once, which is the aliasing between two epochs' trees that Clone exists to prevent")
	}
}

// TestNodeShapeUnmergedLeavesHandsBackACopyAndNotTheTreesOwnList is the same contract at the one
// accessor whose answer leaves the package.
//
// This is the NodeShape method the tree math walks, so its answer reaches code that has no idea
// it is holding a tree's own storage. Measured before this was pinned: the ordinary go idiom for
// narrowing a list -- kept := answer[:0] followed by append, which is the spelling the tree hash
// task uses -- rewrote a real parent node's unmerged list in place, which is a different parent
// hash at that node and a different tree hash from every peer. It was unpinned in both
// directions, so a later task could have flipped it back silently.
func TestNodeShapeUnmergedLeavesHandsBackACopyAndNotTheTreesOwnList(t *testing.T) {
	tree, _ := treeUnderTest(t, 4)
	if err := tree.SetParent(NodeIndex(3), testParentNodeTemplate()); err != nil {
		t.Fatalf("SetParent: %v", err)
	}
	stored := []LeafIndex{1, 2, 5}
	var shape NodeShape = tree
	if got := shape.UnmergedLeaves(NodeIndex(3)); !reflect.DeepEqual(got, stored) {
		t.Fatalf("UnmergedLeaves(3) = %v, want %v, so what follows measures the wrong list", got, stored)
	}

	// narrowing the answer in place, which is what a caller filtering the list writes
	kept := shape.UnmergedLeaves(NodeIndex(3))[:0]
	kept = append(kept, LeafIndex(9))
	if got := shape.UnmergedLeaves(NodeIndex(3)); !reflect.DeepEqual(got, stored) {
		t.Errorf("a caller that narrowed the answer in place rewrote the tree: the node now holds %v, want %v", got, stored)
	}
	// and writing through an element of it
	answer := shape.UnmergedLeaves(NodeIndex(3))
	answer[0] = 0xffff
	if got := shape.UnmergedLeaves(NodeIndex(3)); !reflect.DeepEqual(got, stored) {
		t.Errorf("a caller that wrote through the answer rewrote the tree: the node now holds %v, want %v", got, stored)
	}
	// two answers do not share storage with each other either, which is the same statement made
	// where a caller holds both
	first, second := shape.UnmergedLeaves(NodeIndex(3)), shape.UnmergedLeaves(NodeIndex(3))
	first[0] = 0xeeee
	if second[0] == first[0] {
		t.Error("two answers from UnmergedLeaves share one backing array")
	}
	// the parent node itself is still reachable and still editable through ParentAt, which is
	// the accessor that hands out the tree's own storage on purpose
	tree.ParentAt(NodeIndex(3)).UnmergedLeaves[0] = 0xabcd
	if got := shape.UnmergedLeaves(NodeIndex(3))[0]; got != 0xabcd {
		t.Errorf("an edit through ParentAt did not reach the answer: got %d", got)
	}
	// a blank position and a leaf answer nothing, which is where an implementation reaching
	// through a nil parent would panic rather than report
	if got := shape.UnmergedLeaves(NodeIndex(5)); len(got) != 0 {
		t.Errorf("a blank parent answered %v", got)
	}
	if got := shape.UnmergedLeaves(NodeIndex(0)); len(got) != 0 {
		t.Errorf("a leaf answered %v", got)
	}
}

// TestFindLeafBySignatureKeyAnswersTheLowestMatchingLeaf pins the tie break, which neither the
// code nor any case in this file stated before: every leaf of the test tree carries a distinct
// signature key, so an implementation answering the LAST match rather than the first passed.
//
// A tie is reachable. This is how a member locates its own leaf in a tree a peer supplied, which
// happens before ValSem101's duplicate signature key refusal has necessarily run over that tree,
// and two members answering different positions for one key would each sign and decrypt as a
// different leaf.
func TestFindLeafBySignatureKeyAnswersTheLowestMatchingLeaf(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		duplicate []uint32
		blank     []uint32
		want      LeafIndex
	}{
		// the answer is the first of the run, not the last
		{name: "leaves 0 and 2 share a key", duplicate: []uint32{0, 2}, want: 0},
		{name: "leaves 0, 1 and 3 share a key", duplicate: []uint32{0, 1, 3}, want: 0},
		// and it is the first MATCH and not merely leaf zero: blanking the lowest holder moves
		// the answer, which an implementation hard wired to 0 fails
		{name: "the lowest holder is blank", duplicate: []uint32{0, 1, 3}, blank: []uint32{0}, want: 1},
		{name: "the two lowest holders are blank", duplicate: []uint32{0, 1, 3}, blank: []uint32{0, 1}, want: 3},
	} {
		tree, _ := treeUnderTest(t, 4)
		shared := SignaturePublicKey(repeatByte(0x7e, 32))
		for _, i := range testCase.duplicate {
			leaf := testTreeLeaf(i)
			leaf.SignatureKey = SignaturePublicKey(repeatByte(0x7e, 32))
			if err := tree.SetLeaf(LeafIndex(i), leaf); err != nil {
				t.Fatalf("%s: SetLeaf(%d): %v", testCase.name, i, err)
			}
		}
		for _, i := range testCase.blank {
			if err := tree.Blank(LeafIndex(i).NodeIndex()); err != nil {
				t.Fatalf("%s: Blank(%d): %v", testCase.name, i, err)
			}
		}
		got, ok := tree.FindLeafBySignatureKey(shared)
		if !ok || got != testCase.want {
			t.Errorf("%s: FindLeafBySignatureKey = (%d, %v), want (%d, true)", testCase.name, got, ok, testCase.want)
		}
	}
}

// ---------------------------------------------------------------------------
// the ParentNode encoding, octet by octet
// ---------------------------------------------------------------------------

// TestATruncatedOrExtendedParentNodeEncodingIsRefused is the counterpart of leaf_node_test.go's
// TestEveryOctetOfALeafNodeEncodingIsLoadBearing, which this structure had none of: the goldens
// were only ever decoded whole.
//
// Every proper prefix of every golden must be refused, and so must every golden with an octet
// added. What holds it today is syntax.Unmarshal's whole buffer requirement rather than anything
// in this file, and that is exactly why it is worth stating here: a ParentNode.UnmarshalMLS that
// stopped consuming its last field would still refuse the whole golden -- the leftover octets
// fail Done -- and would ACCEPT the prefix that ends where its reading stopped, which is a second
// decoder for a structure the parent hash and the tree hash are taken over.
func TestATruncatedOrExtendedParentNodeEncodingIsRefused(t *testing.T) {
	prefixes, extensions := 0, 0
	for _, golden := range parentNodeGoldenCases() {
		if len(golden.bytes) != golden.size {
			t.Fatalf("%s: the golden is %d octets and its stated size is %d", golden.name, len(golden.bytes), golden.size)
		}
		// the whole thing decodes, so a refusal below is the truncation and not the golden
		if err := syntax.Unmarshal(golden.bytes, &ParentNode{}); err != nil {
			t.Fatalf("%s: the complete golden was refused: %v", golden.name, err)
		}
		for cut := 0; cut < len(golden.bytes); cut += 1 {
			prefixes += 1
			if err := syntax.Unmarshal(golden.bytes[:cut], &ParentNode{}); err == nil {
				t.Errorf("%s: the first %d of %d octets decoded as a whole parent node", golden.name, cut, len(golden.bytes))
			}
		}
		for _, extra := range []byte{0x00, 0xff} {
			extensions += 1
			extended := append(bytes.Clone(golden.bytes), extra)
			if err := syntax.Unmarshal(extended, &ParentNode{}); err == nil {
				t.Errorf("%s: the golden with a trailing %#02x decoded as a whole parent node", golden.name, extra)
			}
		}
	}
	if prefixes == 0 || extensions == 0 {
		t.Fatalf("the sweep judged %d prefixes and %d extensions", prefixes, extensions)
	}
	t.Logf("%d prefixes and %d extended encodings refused", prefixes, extensions)
}

// TestOneParentNodesUnmergedLeavesStayAtTheDefaultLimitUnderARaisedOne is the mechanism behind
// the argument the codec table writes down beside this pair's entries.
//
// The syntax package inherits its vector limit downwards on purpose -- subReader hands the
// parent's limit to every nested read, WriteVector builds its scratch at the outer limit -- which
// is what lets a ratchet_tree running at MaxRatchetTreeLength carry fields larger than one
// ordinary structure may. So an entry arguing that unmerged_leaves runs at MaxVectorLength is an
// argument that becomes FALSE, with nothing failing, the moment a ratchet tree codec opens a
// raised writer: sixteen mebibytes is 4,194,304 unmerged leaves at one parent node.
//
// The bound is therefore applied by the codec itself and asserted here through a raised limit,
// which is the only place the difference is visible. Both halves, because an encoder that wrote
// what its decoder refuses is an implementation that cannot read what it sends.
func TestOneParentNodesUnmergedLeavesStayAtTheDefaultLimitUnderARaisedOne(t *testing.T) {
	// the bound is a function of the encoding rather than a number: an unmerged leaf is a
	// uint32, so a vector of exactly this many is exactly MaxVectorLength octets
	if maxUnmergedLeaves != syntax.MaxVectorLength/4 {
		t.Fatalf("maxUnmergedLeaves is %d and the default limit holds %d uint32", maxUnmergedLeaves, syntax.MaxVectorLength/4)
	}
	if syntax.MaxRatchetTreeLength <= syntax.MaxVectorLength {
		t.Fatalf("the ratchet tree limit is %d and the default is %d, so a raised limit proves nothing here",
			syntax.MaxRatchetTreeLength, syntax.MaxVectorLength)
	}
	ascending := func(n int) []LeafIndex {
		out := make([]LeafIndex, n)
		for i := range out {
			out[i] = LeafIndex(i)
		}
		return out
	}
	atTheBound := &ParentNode{
		EncryptionKey:  HpkePublicKey(repeatByte(0xa1, 32)),
		ParentHash:     repeatByte(0xb2, 32),
		UnmergedLeaves: ascending(maxUnmergedLeaves),
	}
	pastTheBound := &ParentNode{
		EncryptionKey:  HpkePublicKey(repeatByte(0xa1, 32)),
		ParentHash:     repeatByte(0xb2, 32),
		UnmergedLeaves: ascending(maxUnmergedLeaves + 1),
	}

	// the encode half. At the bound it encodes under the raised limit and under the default
	// one, so the refusal below is the bound and not the size of the buffer.
	if _, err := syntax.MarshalLimit(atTheBound, syntax.MaxRatchetTreeLength); err != nil {
		t.Fatalf("a vector at the bound was refused at the raised limit: %v", err)
	}
	if _, err := syntax.Marshal(atTheBound); err != nil {
		t.Fatalf("a vector at the bound was refused at the default limit: %v", err)
	}
	if _, err := syntax.MarshalLimit(pastTheBound, syntax.MaxRatchetTreeLength); !errors.Is(err, syntax.ErrLengthExceedsMax) {
		t.Errorf("encoding %d unmerged leaves at the raised limit answered %v, want ErrLengthExceedsMax: the ratchet tree's raised bound belongs to the ARRAY and not to one parent node's unmerged list",
			maxUnmergedLeaves+1, err)
	}
	if _, err := syntax.Marshal(pastTheBound); !errors.Is(err, syntax.ErrLengthExceedsMax) {
		t.Errorf("encoding %d unmerged leaves at the default limit answered %v, want ErrLengthExceedsMax", maxUnmergedLeaves+1, err)
	}

	// the decode half, over bytes built through the vector encoder directly so that a codec
	// which refuses to WRITE the over long vector can still be handed one
	overLong := func() []byte {
		writer := syntax.NewWriterLimit(syntax.MaxRatchetTreeLength)
		writer.WriteOpaque(pastTheBound.EncryptionKey)
		writer.WriteOpaque(pastTheBound.ParentHash)
		if err := syntax.WriteVector(writer, pastTheBound.UnmergedLeaves, writeOneUnmergedLeaf); err != nil {
			t.Fatalf("building the over long encoding: %v", err)
		}
		encoded, err := writer.Bytes()
		if err != nil {
			t.Fatalf("building the over long encoding: %v", err)
		}
		return encoded
	}()
	if err := syntax.UnmarshalLimit(overLong, &ParentNode{}, syntax.MaxRatchetTreeLength); !errors.Is(err, syntax.ErrLengthExceedsMax) {
		t.Errorf("decoding %d unmerged leaves at the raised limit answered %v, want ErrLengthExceedsMax", maxUnmergedLeaves+1, err)
	}
	// and the same decode at the bound is accepted, so the refusal above is the bound and not
	// a decoder that gave up on a large vector
	encodedAtTheBound, err := syntax.MarshalLimit(atTheBound, syntax.MaxRatchetTreeLength)
	if err != nil {
		t.Fatalf("encoding at the bound: %v", err)
	}
	decoded := &ParentNode{}
	if err := syntax.UnmarshalLimit(encodedAtTheBound, decoded, syntax.MaxRatchetTreeLength); err != nil {
		t.Fatalf("a vector at the bound was refused on the way in: %v", err)
	}
	if len(decoded.UnmergedLeaves) != maxUnmergedLeaves {
		t.Errorf("decoding a vector at the bound produced %d leaves, want %d", len(decoded.UnmergedLeaves), maxUnmergedLeaves)
	}
}

// ---------------------------------------------------------------------------
// guardrail 8 over the ratchet tree's own key comparisons
// ---------------------------------------------------------------------------

// The comparison guardrail 8 names, split into the two identifiers a call to it is written from
// so that the rules below can match it without rendering a node against a file set that is not
// its own.
const (
	sanctionedComparisonPackage = "subtle"
	sanctionedComparisonName    = "ConstantTimeCompare"
	ratchetTreeTypeName         = "RatchetTree"
)

func theSanctionedComparison() string {
	return sanctionedComparisonPackage + "." + sanctionedComparisonName
}

// keyShapedTypesOf is every named type these files declare whose underlying type is a slice of
// octets: SignaturePublicKey, HpkePublicKey and their private twins today.
//
// Read off the declarations rather than listed, so a key type a later task declares is under the
// rule the day it is declared rather than the day somebody remembers. A key is what a caller
// probes a tree with, and it is the argument whose comparison the guardrail is about.
func keyShapedTypesOf(files []parsedSource) map[string]bool {
	found := map[string]bool{}
	for _, parsed := range files {
		ast.Inspect(parsed.file, func(node ast.Node) bool {
			spec, isType := node.(*ast.TypeSpec)
			if !isType {
				return true
			}
			slice, isSlice := spec.Type.(*ast.ArrayType)
			if !isSlice || slice.Len != nil {
				return true
			}
			if element, isIdent := slice.Elt.(*ast.Ident); isIdent && (element.Name == "byte" || element.Name == "uint8") {
				found[spec.Name.Name] = true
			}
			return true
		})
	}
	return found
}

// keyQuestion is one member of the class the guardrail runs over, carrying the file it was read
// out of because every rule renders nodes back to source and a node rendered against the wrong
// file set reports the wrong text.
type keyQuestion struct {
	name     string
	host     parsedSource
	function *ast.FuncDecl
}

// qualifiedName is how a member is named in the expectations below: the receiver as it is
// written, then the method name, so a method and a plain function of the same name stay apart.
func (self parsedSource) qualifiedName(function *ast.FuncDecl) string {
	if receiver := self.receiverOf(function); receiver != "" {
		return receiver + "." + function.Name.Name
	}
	return function.Name.Name
}

// parameterTypesOf is one type per parameter, with a group like (a, b []byte) counted twice.
func parameterTypesOf(parsed parsedSource, function *ast.FuncDecl) []string {
	found := []string{}
	if function.Type.Params == nil {
		return found
	}
	for _, field := range function.Type.Params.List {
		rendered := parsed.render(field.Type)
		for range max(len(field.Names), 1) {
			found = append(found, rendered)
		}
	}
	return found
}

// keyQuestionsIn is every declaration in these files that answers a question about a key it was
// handed, over a ratchet tree.
//
// Three conditions and each of them a shape rather than a name: a parameter whose type is one of
// the key types derived above; a bool somewhere in the results, which is what makes the answer a
// yes or no an attacker can probe for rather than a value it computes; and a ratchet tree in the
// receiver or the parameters, which is the scope.
//
// The scope is where it is deliberately. The crypto provider answers questions about keys too and
// is guardrail 8's own subject next door, held by TestMacVerifyComparesInConstantTime and by
// TestEveryTagVerifierComparesThroughMacVerifyAndNothingElse; those verifiers reach ed25519.Verify
// and the HPKE primitives, which is what their gates sanction and what the rule below forbids.
// What had no gate at all was the container. Its two comparisons are over PUBLIC keys, so nothing
// aimed at secrets reaches them, and both survived being rewritten as ordinary go equality with
// the whole package green.
func keyQuestionsIn(files []parsedSource) []keyQuestion {
	keyTypes := keyShapedTypesOf(files)
	found := []keyQuestion{}
	for _, parsed := range files {
		for _, declaration := range parsed.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			takesAKey, mentionsTheTree := false, strings.Contains(parsed.receiverOf(function), ratchetTreeTypeName)
			for _, one := range parameterTypesOf(parsed, function) {
				if keyTypes[strings.TrimPrefix(one, "*")] {
					takesAKey = true
				}
				if strings.Contains(one, ratchetTreeTypeName) {
					mentionsTheTree = true
				}
			}
			if !takesAKey || !mentionsTheTree {
				continue
			}
			answers := false
			for _, field := range fieldsOf(function.Type.Results) {
				if parsed.render(field.Type) == "bool" {
					answers = true
				}
			}
			if !answers {
				continue
			}
			found = append(found, keyQuestion{name: parsed.qualifiedName(function), host: parsed, function: function})
		}
	}
	slices.SortFunc(found, func(a keyQuestion, b keyQuestion) int { return strings.Compare(a.name, b.name) })
	return found
}

// namesOfKeyQuestions is the class as a sorted list of names, which is what the expectations
// below are stated in.
func namesOfKeyQuestions(class []keyQuestion) []string {
	names := []string{}
	for _, one := range class {
		names = append(names, one.name)
	}
	return names
}

// packageLevelConstantsOf is every name these files declare as a constant, which is what lets the
// equality rule tell a control flow decision from a decision about data.
func packageLevelConstantsOf(files []parsedSource) map[string]bool {
	found := map[string]bool{}
	for _, parsed := range files {
		ast.Inspect(parsed.file, func(node ast.Node) bool {
			declaration, isGeneric := node.(*ast.GenDecl)
			if !isGeneric || declaration.Tok != token.CONST {
				return true
			}
			for _, spec := range declaration.Specs {
				if value, isValue := spec.(*ast.ValueSpec); isValue {
					for _, name := range value.Names {
						found[name.Name] = true
					}
				}
			}
			return true
		})
	}
	return found
}

// isConstantExpression is whether one side of a comparison is a constant as far as the rule is
// concerned: a literal, nil, true, false, a composite literal, or a constant this package
// declares.
func isConstantExpression(expr ast.Expr, constants map[string]bool) bool {
	switch typed := expr.(type) {
	case *ast.BasicLit:
		return true
	case *ast.CompositeLit:
		return true
	case *ast.ParenExpr:
		return isConstantExpression(typed.X, constants)
	case *ast.UnaryExpr:
		return isConstantExpression(typed.X, constants)
	case *ast.Ident:
		return typed.Name == "nil" || typed.Name == "true" || typed.Name == "false" || constants[typed.Name]
	}
	return false
}

// variableTimeEqualitiesIn is every == or != in one body with a value on both sides.
//
// This is the shape no class of function names ever sees: string(a) == string(b) mentions no
// comparator at all and is exactly the rewrite that survived here, and a [32]byte compared with
// == is a variable time comparison the language performs for free. A comparison with a constant
// on one side is a control flow decision -- err != nil, a node type against its constant, the
// == 1 that reads the answer out of the sanctioned comparison -- and is not reported.
//
// A length comparison IS reported, because len(a) != len(b) has a value on both sides. That is
// the direction this fails in on purpose: the sanctioned comparison refuses a length mismatch
// itself, so a key question that writes one has put a decision in front of the comparison the
// guardrail put there.
func variableTimeEqualitiesIn(parsed parsedSource, function *ast.FuncDecl, constants map[string]bool) []string {
	found := []string{}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		binary, isBinary := node.(*ast.BinaryExpr)
		if !isBinary || (binary.Op != token.EQL && binary.Op != token.NEQ) {
			return true
		}
		if isConstantExpression(binary.X, constants) || isConstantExpression(binary.Y, constants) {
			return true
		}
		found = append(found, parsed.render(binary))
		return true
	})
	slices.Sort(found)
	return slices.Compact(found)
}

// callsOutOfThisPackageIn is every call in one body that leaves this package for anything other
// than the sanctioned comparison.
//
// This is the comparator ban with its bounds taken off, and it is here because a class derived
// from signatures still has a shape and anything outside that shape is outside it: bytes.Cut
// answers "does this key begin with that one" through three results, and a helper in a package
// nobody has classified answers it however it likes. So for a function whose answer is about a
// key, the rule is not that no comparator is called -- it is that nothing outside this package
// is called at all, with one exception, and the exception is the comparison the guardrail names.
//
// A method on a value is not a call out of the package: the receiver had to come from somewhere,
// and everything that could produce one here is either a call this rule already sees or a value
// of this package's own. A conversion through a predeclared or package level type name is not a
// call at all.
func callsOutOfThisPackageIn(parsed parsedSource, function *ast.FuncDecl, declared declaredNames) []string {
	found := []string{}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		switch callee := call.Fun.(type) {
		case *ast.Ident:
			if declared.functions[callee.Name] || declared.types[callee.Name] || types.Universe.Lookup(callee.Name) != nil {
				return true
			}
			found = append(found, callee.Name)
		case *ast.SelectorExpr:
			rendered := parsed.render(call.Fun)
			if rendered == theSanctionedComparison() {
				return true
			}
			qualifier, isIdent := callee.X.(*ast.Ident)
			if !isIdent || !declared.imports[qualifier.Name] {
				return true
			}
			found = append(found, rendered)
		}
		return true
	})
	slices.Sort(found)
	return slices.Compact(found)
}

// functionsByNameIn is every declaration these files carry, keyed by the name a call to it is
// written with -- the function name, or the method name for a method, since a call site spells
// self.Leaf and not (*RatchetTree).Leaf.
func functionsByNameIn(files []parsedSource) map[string][]*ast.FuncDecl {
	found := map[string][]*ast.FuncDecl{}
	for _, parsed := range files {
		for _, declaration := range parsed.file.Decls {
			if function, isFunction := declaration.(*ast.FuncDecl); isFunction && function.Body != nil {
				found[function.Name.Name] = append(found[function.Name.Name], function)
			}
		}
	}
	return found
}

// reachesTheConstantTimeComparison walks this package's own call graph from one declaration and
// reports whether the sanctioned comparison is anywhere in it.
//
// The transitive half is what says the requirement is about the ANSWER and not about the text of
// one function: a key question that moved its comparison into a helper still satisfies this, and
// one that moved it into a helper written as a byte loop does not. Banning the wrong comparison
// is not the same as requiring the right one -- a function that compared nothing at all passes
// every ban above and fails here.
func reachesTheConstantTimeComparison(function *ast.FuncDecl, byName map[string][]*ast.FuncDecl) bool {
	pending := []*ast.FuncDecl{function}
	seen := map[*ast.FuncDecl]bool{function: true}
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		sanctioned, called := false, []string{}
		ast.Inspect(current.Body, func(node ast.Node) bool {
			call, isCall := node.(*ast.CallExpr)
			if !isCall {
				return true
			}
			switch callee := call.Fun.(type) {
			case *ast.Ident:
				called = append(called, callee.Name)
			case *ast.SelectorExpr:
				called = append(called, callee.Sel.Name)
				qualifier, isIdent := callee.X.(*ast.Ident)
				if isIdent && qualifier.Name == sanctionedComparisonPackage && callee.Sel.Name == sanctionedComparisonName {
					sanctioned = true
				}
			}
			return true
		})
		if sanctioned {
			return true
		}
		for _, name := range called {
			for _, next := range byName[name] {
				if !seen[next] {
					seen[next] = true
					pending = append(pending, next)
				}
			}
		}
	}
	return false
}

// parsedProductionSourcesOfThisPackage is every non test file of this package, parsed. The rule
// reads the directory rather than a file name, so a key question a later task puts in
// tree_sync.go is under the guardrail without an edit here.
func parsedProductionSourcesOfThisPackage(t *testing.T) []parsedSource {
	t.Helper()
	files := []parsedSource{}
	for _, path := range packageSourcePaths(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		files = append(files, mustParseSource(t, path))
	}
	if len(files) == 0 {
		t.Fatal("no production file was parsed, so the guardrail below judged nothing")
	}
	return files
}

// A fixture declaring one of every shape the three rules have to tell apart, so a matcher that
// stopped matching fails here rather than issuing the real source the clean bill a working one
// issues.
//
// Every member is here because some half of some rule has to be the only thing reporting it:
//
//   - ComparesWithBytesEqual and ComparesWithAPrefix are the comparators a ban list would have
//     had to think of, and only the foreign call rule reports them. bytes.HasPrefix leaks
//     strictly more than bytes.Equal does and was outside the six name list this project shipped.
//   - ComparesByConvertingToString names no comparator at all and is the rewrite that actually
//     survived in this file, so only the equality rule reports it.
//   - ComparesAfterALengthFastPath keeps the sanctioned comparison and puts a decision in front
//     of it, so only the equality rule reports it, and it is what says that rule is not merely
//     the foreign call rule spelled differently.
//   - ComparesNothingAtAll answers without comparing, so only the reachability rule reports it.
//   - ComparesThroughAHelperThatLoops and loops are the comparison moved out of the function
//     that answers: the helper carries the byte loop, so the equality rule reports the HELPER and
//     the reachability rule reports the caller, and neither reports the other.
//   - FindsInATreeItWasHanded is a plain function rather than a method, which is what says the
//     class is not "the methods of one type".
//   - FindsInConstantTime, FindsThroughAHelperOfItsOwn and holds are the clean half: one
//     comparing directly and one through a helper, which is what makes the reachability
//     requirement really transitive.
//   - TakesAKeyAndAnswersNoQuestion, AnswersAQuestionAboutNoKey and ComparesKeysWithNoTreeInSight
//     are outside the class on one condition each, and every one of them would be reported if it
//     were inside, so a class that widened fails as loudly as one that narrowed.
const ratchetTreeKeyComparisonControl = `package control

import (
	"bytes"
	"crypto/subtle"
)

type SignaturePublicKey []byte

type RatchetTree struct {
	keys []SignaturePublicKey
}

func (self *RatchetTree) FindsInConstantTime(key SignaturePublicKey) (int, bool) {
	for i, held := range self.keys {
		if subtle.ConstantTimeCompare(held, key) == 1 {
			return i, true
		}
	}
	return 0, false
}

func (self *RatchetTree) FindsThroughAHelperOfItsOwn(key SignaturePublicKey) bool {
	return self.holds(key)
}

func (self *RatchetTree) holds(key SignaturePublicKey) bool {
	return subtle.ConstantTimeCompare(self.keys[0], key) == 1
}

func (self *RatchetTree) ComparesWithBytesEqual(key SignaturePublicKey) bool {
	return bytes.Equal(self.keys[0], key)
}

func (self *RatchetTree) ComparesWithAPrefix(key SignaturePublicKey) bool {
	return bytes.HasPrefix(self.keys[0], key)
}

func (self *RatchetTree) ComparesByConvertingToString(key SignaturePublicKey) bool {
	return string(self.keys[0]) == string(key)
}

func (self *RatchetTree) ComparesAfterALengthFastPath(key SignaturePublicKey) bool {
	if len(key) != len(self.keys[0]) {
		return false
	}
	return subtle.ConstantTimeCompare(self.keys[0], key) == 1
}

func (self *RatchetTree) ComparesNothingAtAll(key SignaturePublicKey) bool {
	_ = key
	return true
}

func (self *RatchetTree) ComparesThroughAHelperThatLoops(key SignaturePublicKey) bool {
	return self.loops(key)
}

func (self *RatchetTree) loops(key SignaturePublicKey) bool {
	held := self.keys[0]
	for i := range held {
		if held[i] != key[i] {
			return false
		}
	}
	return true
}

func FindsInATreeItWasHanded(tree *RatchetTree, key SignaturePublicKey) bool {
	return bytes.Equal(tree.keys[0], key)
}

func (self *RatchetTree) TakesAKeyAndAnswersNoQuestion(key SignaturePublicKey) []byte {
	return bytes.Clone(key)
}

func (self *RatchetTree) AnswersAQuestionAboutNoKey(a []byte, b []byte) bool {
	return bytes.Equal(a, b)
}

func ComparesKeysWithNoTreeInSight(a SignaturePublicKey, b SignaturePublicKey) bool {
	return bytes.Equal(a, b)
}
`

// What the class must read out of the fixture, exactly rather than as a floor. A class that
// widened to take in the three members outside it, or narrowed to drop one of the bad shapes,
// would go on to read the real source the same wrong way and report the same clean bill.
var ratchetTreeKeyComparisonControlClass = []string{
	"*RatchetTree.ComparesAfterALengthFastPath",
	"*RatchetTree.ComparesByConvertingToString",
	"*RatchetTree.ComparesNothingAtAll",
	"*RatchetTree.ComparesThroughAHelperThatLoops",
	"*RatchetTree.ComparesWithAPrefix",
	"*RatchetTree.ComparesWithBytesEqual",
	"*RatchetTree.FindsInConstantTime",
	"*RatchetTree.FindsThroughAHelperOfItsOwn",
	"*RatchetTree.holds",
	"*RatchetTree.loops",
	"FindsInATreeItWasHanded",
}

// The two the class must be seen to LEAVE OUT, named so a reader can tell a deliberate boundary
// from an oversight. ComparesKeysWithNoTreeInSight is the third and is left out by the scope
// rather than by the shape: it compares keys in variable time and is somebody else's guardrail.
var ratchetTreeKeyComparisonControlOutsideTheClass = []string{
	"*RatchetTree.AnswersAQuestionAboutNoKey",
	"*RatchetTree.TakesAKeyAndAnswersNoQuestion",
	"ComparesKeysWithNoTreeInSight",
}

var (
	// the equality rule: a value on both sides of an == or a !=
	ratchetTreeControlVariableTimeEqualities = []string{
		"*RatchetTree.ComparesAfterALengthFastPath",
		"*RatchetTree.ComparesByConvertingToString",
		"*RatchetTree.loops",
	}
	// the foreign call rule: anything outside the package that is not the sanctioned comparison
	ratchetTreeControlForeignCalls = []string{
		"*RatchetTree.ComparesWithAPrefix",
		"*RatchetTree.ComparesWithBytesEqual",
		"FindsInATreeItWasHanded",
	}
	// the reachability rule: the sanctioned comparison is nowhere in the call graph
	ratchetTreeControlUnreached = []string{
		"*RatchetTree.ComparesByConvertingToString",
		"*RatchetTree.ComparesNothingAtAll",
		"*RatchetTree.ComparesThroughAHelperThatLoops",
		"*RatchetTree.ComparesWithAPrefix",
		"*RatchetTree.ComparesWithBytesEqual",
		"*RatchetTree.loops",
		"FindsInATreeItWasHanded",
	}
)

// TestTheKeyComparisonGateFlagsItsControlFixture is the matcher's own control, and it runs before
// the gate over the real source so that a rule which stopped matching fails here rather than
// issuing this package a clean bill.
func TestTheKeyComparisonGateFlagsItsControlFixture(t *testing.T) {
	control := mustParseText(t, "the ratchet tree key comparison control", ratchetTreeKeyComparisonControl)
	files := []parsedSource{control}
	class := keyQuestionsIn(files)
	if got := namesOfKeyQuestions(class); !slices.Equal(got, ratchetTreeKeyComparisonControlClass) {
		t.Fatalf("the class read %v out of the control, want %v", got, ratchetTreeKeyComparisonControlClass)
	}
	// the members outside it are outside it, said by name rather than left implied
	for _, outside := range ratchetTreeKeyComparisonControlOutsideTheClass {
		if slices.Contains(ratchetTreeKeyComparisonControlClass, outside) {
			t.Errorf("%s is named as being outside the class and is inside it", outside)
		}
	}
	declared := namesTheseFilesDeclare(files)
	constants := packageLevelConstantsOf(files)
	byName := functionsByNameIn(files)
	equalities, foreign, unreached := []string{}, []string{}, []string{}
	for _, one := range class {
		if len(variableTimeEqualitiesIn(one.host, one.function, constants)) != 0 {
			equalities = append(equalities, one.name)
		}
		if len(callsOutOfThisPackageIn(one.host, one.function, declared)) != 0 {
			foreign = append(foreign, one.name)
		}
		if !reachesTheConstantTimeComparison(one.function, byName) {
			unreached = append(unreached, one.name)
		}
	}
	if !slices.Equal(equalities, ratchetTreeControlVariableTimeEqualities) {
		t.Errorf("the equality rule reported %v out of the control, want %v", equalities, ratchetTreeControlVariableTimeEqualities)
	}
	if !slices.Equal(foreign, ratchetTreeControlForeignCalls) {
		t.Errorf("the foreign call rule reported %v out of the control, want %v", foreign, ratchetTreeControlForeignCalls)
	}
	if !slices.Equal(unreached, ratchetTreeControlUnreached) {
		t.Errorf("the reachability rule reported %v out of the control, want %v", unreached, ratchetTreeControlUnreached)
	}
}

// TestEveryKeyQuestionTheRatchetTreeAnswersComparesInConstantTime is guardrail 8 over the two
// comparisons this file makes, which no gate in this package reached.
//
// Both of them were rewritten as ordinary go equality -- string(leaf.SignatureKey) == string(key)
// at one and both comparisons at the other -- and the whole package stayed green. The comparison
// is constant time for the reason FindLeafBySignatureKey's own comment gives, and what says so
// today is that comment; no behavioural test in go can see the difference, and a timing
// measurement over a 32 octet comparison on this machine is noise. So what is asserted is what
// was actually verified: mechanically, over the source, so it survives an edit nobody reruns this
// for.
//
// The blind spot is worth naming, because it is the same one the tag verifier gate next door
// documents: the equality rule reads each member's own body, so a byte loop written inside a
// helper is caught by the reachability rule -- the helper is not the sanctioned comparison -- and
// not by the equality rule, unless the helper is itself a member of the class.
func TestEveryKeyQuestionTheRatchetTreeAnswersComparesInConstantTime(t *testing.T) {
	files := parsedProductionSourcesOfThisPackage(t)
	class := keyQuestionsIn(files)
	names := namesOfKeyQuestions(class)
	t.Logf("%d key questions under the gate: %v", len(names), names)
	if len(class) == 0 {
		t.Fatal("the gate found no key question at all, so it is reporting clean having read nothing")
	}
	// the coverage claim, checked rather than assumed: the two this file is about have to be
	// among the ones being judged
	for _, want := range []string{"*RatchetTree.FindLeafBySignatureKey", "*RatchetTree.EncryptionKeyInUse"} {
		if !slices.Contains(names, want) {
			t.Fatalf("the gate is judging %v, which does not include %s", names, want)
		}
	}
	declared := namesTheseFilesDeclare(files)
	constants := packageLevelConstantsOf(files)
	byName := functionsByNameIn(files)
	for _, one := range class {
		for _, equality := range variableTimeEqualitiesIn(one.host, one.function, constants) {
			t.Errorf("%s decides %s, which is a comparison of two values in variable time; every comparison of a key here goes through %s",
				one.name, equality, theSanctionedComparison())
		}
		for _, foreign := range callsOutOfThisPackageIn(one.host, one.function, declared) {
			t.Errorf("%s calls %s; a key question's answer is decided by %s and by nothing else, and what it needs from elsewhere belongs behind a function of this package",
				one.name, foreign, theSanctionedComparison())
		}
		if !reachesTheConstantTimeComparison(one.function, byName) {
			t.Errorf("%s reaches no %s; a function that answers a question about a key without comparing it in constant time is not answering it safely",
				one.name, theSanctionedComparison())
		}
	}
}

// ---------------------------------------------------------------------------
// node resolution -- RFC 9420 section 7.5
// ---------------------------------------------------------------------------
//
// Resolution decides WHO a path secret is encrypted to, so the two directions it can be wrong in
// are not symmetric. Too small and a member who should have been sent the secret is not, which
// is loud -- that member cannot decrypt the next commit and says so. Too large and a member who
// should NOT have been sent it is, which is silent, and the member reading it is one the group
// removed. The clause that produces the silent direction is the unmerged-leaf clause, and the
// clause that produces the quiet-until-interop direction is the ORDER: TreeKEM pairs the entries
// of a resolution positionally with the ciphertexts of an UpdatePath, so a permuted resolution
// seals every secret to the wrong member while having exactly the right members in it.
//
// So nothing below compares two resolutions as sets, and nothing sorts one before comparing.
// equalNodeIndices is elementwise and length-first, and the sweeps compare against a recursion
// written from the RFC's own words rather than against a second reading of the code under test.

// equalNodeIndices is elementwise and never a set comparison, for the reason above: the order of
// a resolution is the contract and not a detail of it, and reflect.DeepEqual over a sorted copy
// -- or a subset test -- passes every permutation there is.
func equalNodeIndices(a, b []NodeIndex) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// rfcResolution is RFC 9420 section 7.5 written as the recursion the RFC states, as the
// independent second reading every sweep below compares against.
//
// A different SHAPE and not a paraphrase. The implementation under test walks an explicit stack
// so a deep tree cannot become deep Go stack, and the subtle part of that version is the push
// order -- right child pushed first so the left is popped first -- which a recursion states
// directly and cannot get wrong the same way. A reference transcribed from the implementation
// would agree with it about a reversed descent, a dropped unmerged list and an inverted blank
// test alike, which is the whole of what these sweeps are for.
//
// The unreachable arms panic rather than answering an empty list. A node that is not a leaf has
// both children at every representable index, so a refusal from Left or Right here is this
// helper being asked something it was never given -- and an empty answer would be a resolution
// that silently lost a whole subtree, which is the exact defect the sweep is looking for.
func rfcResolution(shape NodeShape, x NodeIndex) []NodeIndex {
	if !shape.IsBlank(x) {
		out := []NodeIndex{x}
		for _, leaf := range shape.UnmergedLeaves(x) {
			out = append(out, leaf.NodeIndex())
		}
		return out
	}
	if x.IsLeaf() {
		return []NodeIndex{}
	}
	left, err := Left(x)
	if err != nil {
		panic("rfcResolution: a parent node with no left child: " + err.Error())
	}
	right, err := Right(x)
	if err != nil {
		panic("rfcResolution: a parent node with no right child: " + err.Error())
	}
	return append(rfcResolution(shape, left), rfcResolution(shape, right)...)
}

func TestResolutionRules(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 4)
	root, err := rootOf(tree.LeafWidth())
	if err != nil {
		t.Fatalf("rootOf: %v", err)
	}

	// all parents blank: the root resolves to the four leaves, left to right.
	got := tree.Resolution(root)
	want := []NodeIndex{0, 2, 4, 6}
	if !equalNodeIndices(got, want) {
		t.Fatalf("blank-parent root resolution = %v, want %v", got, want)
	}

	// a blank leaf contributes nothing.
	if err := tree.Blank(NodeIndex(2)); err != nil {
		t.Fatalf("Blank: %v", err)
	}
	got = tree.Resolution(root)
	want = []NodeIndex{0, 4, 6}
	if !equalNodeIndices(got, want) {
		t.Fatalf("with leaf 1 blank, root resolution = %v, want %v", got, want)
	}
	if len(tree.Resolution(NodeIndex(2))) != 0 {
		t.Fatalf("a blank leaf must resolve to the empty list")
	}

	// a non-blank parent resolves to itself, then its unmerged leaves in order.
	if err := tree.SetParent(NodeIndex(1), &ParentNode{
		EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x77}, 32)),
		UnmergedLeaves: []LeafIndex{0},
	}); err != nil {
		t.Fatalf("SetParent: %v", err)
	}
	got = tree.Resolution(NodeIndex(1))
	want = []NodeIndex{1, 0}
	if !equalNodeIndices(got, want) {
		t.Fatalf("non-blank parent resolution = %v, want %v", got, want)
	}
	got = tree.Resolution(root)
	want = []NodeIndex{1, 0, 4, 6}
	if !equalNodeIndices(got, want) {
		t.Fatalf("root resolution = %v, want %v", got, want)
	}

	// the unmerged half again with a list of more than one, and with a stored order that is not
	// the ascending one. RFC 9420 section 7.9.2 requires the vector ascending and both halves of
	// the parent node codec refuse anything else, but the resolution walk reads STORED order and
	// must not be the place that quietly repairs it: a walk that sorted here would answer a
	// resolution no peer computes, over a tree every peer would have rejected outright.
	if err := tree.SetParent(NodeIndex(5), &ParentNode{
		EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x88}, 32)),
		UnmergedLeaves: []LeafIndex{3, 2},
	}); err != nil {
		t.Fatalf("SetParent(5): %v", err)
	}
	got = tree.Resolution(NodeIndex(5))
	want = []NodeIndex{5, 6, 4}
	if !equalNodeIndices(got, want) {
		t.Fatalf("a parent carrying two unmerged leaves resolved to %v, want %v", got, want)
	}

	// the method and the free function the tree math plan owns agree, and the free
	// one is where an out-of-range node index is an error rather than an empty list.
	got = tree.Resolution(root)
	free, err := Resolution(tree, root)
	if err != nil {
		t.Fatalf("Resolution(tree, root): %v", err)
	}
	if !equalNodeIndices(free, got) {
		t.Fatalf("the method and the free function disagree: %v vs %v", got, free)
	}
	if _, err := Resolution(tree, NodeIndex(tree.NodeWidth())); err == nil {
		t.Fatalf("Resolution past the node width returned no error")
	}
}

// TestTheResolutionMethodDropsTheErrorOnlyWhereTheFreeFunctionRefuses pins the one decision this
// task's method makes.
//
// The method answers the empty list for an out-of-range index, and an accepted empty resolution
// is also the empty list, so the two are not distinguishable through it -- that is the whole of
// what dropping the error costs, and it is only sound if the method and the free function agree
// everywhere the free function accepts. A method that had quietly grown a second opinion about
// any in-range node would be a second resolution algorithm, which is the thing this section's
// header says must not exist.
func TestTheResolutionMethodDropsTheErrorOnlyWhereTheFreeFunctionRefuses(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 5)
	if err := tree.SetParent(NodeIndex(3), &ParentNode{
		EncryptionKey:  HpkePublicKey(repeatByte(0x91, 32)),
		UnmergedLeaves: []LeafIndex{1, 3},
	}); err != nil {
		t.Fatalf("SetParent: %v", err)
	}
	refused := 0
	// past the width as well as inside it, so both arms of the method are taken
	for x := uint32(0); x < tree.NodeWidth()+4; x += 1 {
		free, err := Resolution(tree, NodeIndex(x))
		method := tree.Resolution(NodeIndex(x))
		if err != nil {
			refused += 1
			if method == nil {
				t.Errorf("the method answered nil rather than the empty list for the refused index %d", x)
			}
			if len(method) != 0 {
				t.Errorf("the free function refused index %d and the method answered %v", x, method)
			}
			continue
		}
		if !equalNodeIndices(method, free) {
			t.Errorf("at node %d the method answered %v and the free function %v", x, method, free)
		}
	}
	if refused != 4 {
		t.Fatalf("the free function refused %d of the indices past the width, want 4", refused)
	}
}

// resolutionUnmergedRule is one way of hanging an unmerged list on every parent of a sweep tree.
//
// The rules are DERIVED from each node's own subtree rather than written out as literal lists,
// so the same rule applies at every node of every width and the sweep does not depend on somebody
// having remembered which nodes to decorate. RFC 9420 section 7.9 requires a node's unmerged
// leaves to be non-blank leaves inside its own subtree; the sweep respects the subtree half,
// since a leaf outside it would be a tree no validator accepts, and deliberately does not
// respect the non-blank half, because whether an unmerged leaf happens to be blank changes
// nothing about section 7.5's rule and a resolution walk that started caring would be a walk
// doing section 7.9's job in the wrong place.
type resolutionUnmergedRule struct {
	name  string
	apply func(x NodeIndex) []LeafIndex
}

func resolutionUnmergedRules() []resolutionUnmergedRule {
	return []resolutionUnmergedRule{
		{
			// the half of the class every "nobody has been added since the last commit" test
			// lives in, and the half a walk that forgot unmerged leaves entirely still passes
			name:  "no unmerged leaves",
			apply: func(x NodeIndex) []LeafIndex { return nil },
		},
		{
			// the widest list a node can carry, so the resolution of a non-blank parent is
			// longer than the resolution of the whole subtree below it
			name:  "every leaf of the subtree",
			apply: func(x NodeIndex) []LeafIndex { return subtreeLeavesWhere(x, 1, 0) },
		},
		{
			// a list that is neither empty nor everything, and whose entries interleave with
			// the nodes a blank descent would have produced
			name:  "every other leaf of the subtree",
			apply: func(x NodeIndex) []LeafIndex { return subtreeLeavesWhere(x, 2, 0) },
		},
		{
			// the one entry list, and the one entry chosen so the resolution is NOT in
			// ascending node index order: the first leaf of a subtree sits below the node
			// heading it, so a node carrying it resolves to [x, something smaller]. That is
			// figure 10 of RFC 9420, whose [X, B] is [3, 2], and it is the shape a comparison
			// that sorted before comparing would stop being able to see. The LAST leaf of a
			// subtree has a node index above its head and would have made every answer here
			// ascending, which is worth writing down because it is the version this rule was
			// first written as.
			name: "the first leaf of the subtree",
			apply: func(x NodeIndex) []LeafIndex {
				first, _ := SubtreeLeaves(x)
				return []LeafIndex{first}
			},
		},
	}
}

// subtreeLeavesWhere is every leaf under x whose offset within the subtree is congruent to
// offset modulo step, ascending -- which is what RFC 9420 section 7.9.2 requires an
// unmerged_leaves vector to be.
func subtreeLeavesWhere(x NodeIndex, step uint32, offset uint32) []LeafIndex {
	first, last := SubtreeLeaves(x)
	out := []LeafIndex{}
	for leaf := uint32(first); leaf <= uint32(last); leaf += 1 {
		if (leaf-uint32(first))%step == offset {
			out = append(out, LeafIndex(leaf))
		}
	}
	return out
}

// resolutionSweep builds one tree of the given leaf width and walks every blanking pattern of
// its node array, handing each pattern to visit.
//
// EVERY pattern and not a sample: a resolution defect lives in the relationship between a node's
// blankness and its children's, so which positions are blank is the input, and a sweep that
// picked a few trees would be picking a few of exactly the thing under test. Two to the node
// width is 32,768 at eight leaves, which is the whole space at every width this runs at.
//
// The node array is written directly rather than through SetLeaf and SetParent. Those copy the
// node they are handed, deliberately and for a reason recorded on them, and this sweep would
// spend two million clones on it; what the resolution walk reads is IsBlank, LeafCount and
// UnmergedLeaves, and all three read this array. The nodes are built once per rule.
func resolutionSweep(t *testing.T, leafWidth uint32, rule resolutionUnmergedRule,
	visit func(tree *RatchetTree, pattern uint32)) {
	t.Helper()
	nodeWidth := NodeWidth(LeafCount(leafWidth))
	if nodeWidth == 0 || nodeWidth > 20 {
		t.Fatalf("a sweep over %d leaves is %d nodes, which is not a space to enumerate", leafWidth, nodeWidth)
	}
	filled := make([]*Node, nodeWidth)
	for x := uint32(0); x < nodeWidth; x += 1 {
		node := NodeIndex(x)
		if node.IsLeaf() {
			filled[x] = &Node{NodeType: NodeTypeLeaf, Leaf: testTreeLeaf(x / 2)}
			continue
		}
		filled[x] = &Node{NodeType: NodeTypeParent, Parent: &ParentNode{
			EncryptionKey:  HpkePublicKey(repeatByte(byte(0xd0+x), 32)),
			UnmergedLeaves: rule.apply(node),
		}}
	}
	tree := &RatchetTree{nodes: make([]*Node, nodeWidth)}
	for pattern := uint32(0); pattern < uint32(1)<<nodeWidth; pattern += 1 {
		for x := uint32(0); x < nodeWidth; x += 1 {
			if pattern>>x&1 == 1 {
				tree.nodes[x] = filled[x]
			} else {
				tree.nodes[x] = nil
			}
		}
		visit(tree, pattern)
	}
}

// TestResolutionAgreesWithTheRfcRecursionOverEveryBlankingPattern is the derived half of this
// task: every blanking pattern of every node of every small tree, under four rules for the
// unmerged lists, against the recursion RFC 9420 section 7.5 states.
//
// Derived over the blank positions rather than sampled, because the blank positions ARE the
// input to a resolution: which node is blank decides whether the walk emits it or descends past
// it, and a test that blanked three positions somebody chose is a test of those three. At one,
// two and four leaves this is the entire space; at eight leaves it is the entire space of the
// two rules that bracket the unmerged clause -- none at all, and the widest list a node can
// carry -- which is what keeps the run inside a few seconds while still covering every shape.
//
// A resolution longer than one is counted, and required, so this cannot pass over a run in which
// every answer was the empty list.
func TestResolutionAgreesWithTheRfcRecursionOverEveryBlankingPattern(t *testing.T) {
	rules := resolutionUnmergedRules()
	compared := 0
	nonEmpty := 0
	for _, leafWidth := range []uint32{1, 2, 4, 8} {
		for ruleIndex, rule := range rules {
			// eight leaves is 32,768 patterns per rule, so it runs the first and the last rule
			// -- the empty list and the widest one -- rather than all four
			if leafWidth == 8 && ruleIndex != 0 && ruleIndex != 1 {
				continue
			}
			nodeWidth := NodeWidth(LeafCount(leafWidth))
			resolutionSweep(t, leafWidth, rule, func(tree *RatchetTree, pattern uint32) {
				for x := uint32(0); x < nodeWidth; x += 1 {
					got := tree.Resolution(NodeIndex(x))
					want := rfcResolution(tree, NodeIndex(x))
					compared += 1
					if len(got) > 0 {
						nonEmpty += 1
					}
					if !equalNodeIndices(got, want) {
						t.Fatalf("%d leaves, %s, pattern %0*b: Resolution(%d) = %v, and the RFC recursion says %v",
							leafWidth, rule.name, int(nodeWidth), pattern, x, got, want)
					}
				}
			})
		}
	}
	// the space, written down rather than derived from the loop that walked it: one leaf is 1
	// node over 2 patterns, two leaves 3 over 8 and four leaves 7 over 128, each under all four
	// rules, which is 3,688; eight leaves is 15 nodes over 32,768 patterns under two rules,
	// which is 983,040.
	if compared != 986728 {
		t.Fatalf("the sweep made %d comparisons and the space it walks is 986728", compared)
	}
	if nonEmpty*4 < compared {
		t.Fatalf("only %d of %d resolutions were non-empty, so most of this sweep compared nothing against nothing",
			nonEmpty, compared)
	}
}

// TestAResolutionIsOftenNotInAscendingNodeOrder is the guard that makes every comparison in this
// file worth making.
//
// A resolution ascends by node index everywhere EXCEPT at an unmerged leaf, which follows
// immediately behind the node carrying it and is often below it -- figure 10 of RFC 9420 has
// [X, B], which is [3, 2]. If that never happened, a test comparing two resolutions as sets, or
// sorting them before comparing, would be indistinguishable from one comparing them elementwise,
// and the sweep above would pass every permutation there is. So the case is counted rather than
// assumed, and a sweep that stopped producing it fails here.
func TestAResolutionIsOftenNotInAscendingNodeOrder(t *testing.T) {
	rules := resolutionUnmergedRules()
	rule := rules[len(rules)-1]
	if rule.name != "the first leaf of the subtree" {
		t.Fatalf("this test is written against the one entry rule and the last rule is %q", rule.name)
	}
	nodeWidth := NodeWidth(LeafCount(4))
	longEnough := 0
	outOfOrder := 0
	resolutionSweep(t, 4, rule, func(tree *RatchetTree, pattern uint32) {
		for x := uint32(0); x < nodeWidth; x += 1 {
			got := tree.Resolution(NodeIndex(x))
			if len(got) < 2 {
				continue
			}
			longEnough += 1
			if slices.IsSorted(got) {
				continue
			}
			outOfOrder += 1
			// and the consequence stated rather than implied: the sorted copy is a DIFFERENT
			// list, so a comparison that sorted first would have accepted an answer that seals
			// each path secret to the wrong member
			sorted := slices.Clone(got)
			slices.Sort(sorted)
			if equalNodeIndices(sorted, got) {
				t.Fatalf("pattern %0*b: %v is reported out of order and equals its own sorted form",
					int(nodeWidth), pattern, got)
			}
		}
	})
	if longEnough == 0 {
		t.Fatal("no resolution in the sweep held more than one node, so order was never observable")
	}
	if outOfOrder == 0 {
		t.Fatal("every resolution in the sweep was in ascending node order, so a set comparison would pass this file")
	}
}

// corpusTreeOfShape builds a RatchetTree that is blank exactly where a decoded corpus tree is
// blank and carries exactly the unmerged lists it carries.
//
// Through the shape the tree math plan's decoder already produced, and NOT through a second
// reading of the corpus bytes. There is one decoder of a published ratchet_tree in this package's
// tests -- decodeRatchetTreeShape in tree_math_test.go, which walks the presentation language by
// hand and is independent of this package's own codecs -- and task 11 will add the production
// one. A third would be two of them able to disagree about a truncation, and the disagreement
// would show up as this container failing a corpus it actually reproduces.
//
// The node CONTENTS are placeholders, because resolution reads three things about a tree and
// none of them is a key: whether a position is blank, what a parent's unmerged_leaves holds, and
// how many leaves there are. What this therefore compares is the container's NodeShape against
// the corpus, which is the seam this task adds and the one seam
// TestResolutionAgainstPublishedTreeValidationVectors does not cross -- that test runs the same
// corpus against the decoder's own shape struct, so a RatchetTree whose IsBlank or UnmergedLeaves
// answered wrongly would pass it and fail here.
func corpusTreeOfShape(t *testing.T, label string, shape *ratchetTreeShape, width int) *RatchetTree {
	t.Helper()
	tree := &RatchetTree{nodes: make([]*Node, width)}
	for x := uint32(0); x < uint32(width); x += 1 {
		node := NodeIndex(x)
		if shape.IsBlank(node) {
			continue
		}
		if node.IsLeaf() {
			tree.nodes[x] = &Node{NodeType: NodeTypeLeaf, Leaf: testTreeLeaf(x / 2)}
			continue
		}
		tree.nodes[x] = &Node{NodeType: NodeTypeParent, Parent: &ParentNode{
			EncryptionKey:  HpkePublicKey(repeatByte(byte(0xe0+x), 32)),
			UnmergedLeaves: shape.UnmergedLeaves(node),
		}}
	}
	// the container derives its leaf count from the array it was given and the decoder derived
	// its own from the wire form, so this is two independent readings of one tree's width rather
	// than one value compared against itself
	if tree.LeafCount() != shape.LeafCount() {
		t.Fatalf("%s: the container reads %d leaves out of a %d node array and the decoder read %d",
			label, tree.LeafCount(), width, shape.LeafCount())
	}
	for x := uint32(0); x < uint32(width); x += 1 {
		node := NodeIndex(x)
		if tree.IsBlank(node) != shape.IsBlank(node) {
			t.Fatalf("%s: node %d is blank=%v in the container and blank=%v in the decoded shape",
				label, x, tree.IsBlank(node), shape.IsBlank(node))
		}
		if !slices.Equal(tree.UnmergedLeaves(node), shape.UnmergedLeaves(node)) {
			t.Fatalf("%s: node %d carries %v in the container and %v in the decoded shape",
				label, x, tree.UnmergedLeaves(node), shape.UnmergedLeaves(node))
		}
	}
	return tree
}

// TestTheRatchetTreeReproducesEveryPublishedResolution is the independent half of this task: the
// resolution of every node of every tree the mlswg publishes, computed through the real container
// and compared against the answer the mlswg publishes for it.
//
// Independent in the way the sweeps are not. This implementation and the recursion the sweeps
// compare against were both written from one reading of section 7.5, so a misreading shared by
// the two of them survives every sweep in this file; the corpus was produced by implementations
// that never saw either. Twenty-one of its published resolutions are a node followed by leaves
// merged into it, so the unmerged clause is exercised by the corpus and not only by fixtures of
// this file's own making, and seven of them are not in ascending node index order, so an
// implementation that sorted its answer fails here as well as in the sweep above.
//
// Every entry and not only the ciphersuites this package registers, because nothing here does any
// crypto: a resolution is a function of the tree's SHAPE, so the corpus's seven suites are seven
// more trees rather than seven key formats, and skipping five of them would be throwing evidence
// away for no reason. The counts are written down rather than derived from the loop that produced
// them, and three of the four are the constants the tree math plan already pinned this corpus
// with, so a corpus update moves one number in one place.
func TestTheRatchetTreeReproducesEveryPublishedResolution(t *testing.T) {
	entries := LoadVectorFile(t, treeValidationVectorFile)
	if len(entries) != treeValidationEntryCount {
		t.Fatalf("tree-validation entries: %d, want %d", len(entries), treeValidationEntryCount)
	}
	compared := 0
	withUnmerged := 0
	notAscending := 0
	for entry, raw := range entries {
		vector := treeValidationVector{}
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("entry %d: %v", entry, err)
		}
		label := fmt.Sprintf("tree-validation entry %d", entry)
		shape, width := decodeRatchetTreeShape(t, label, MustHex(t, vector.Tree))
		if width != len(vector.Resolutions) {
			t.Fatalf("%s: node width %d from the tree, %d published resolutions",
				label, width, len(vector.Resolutions))
		}
		tree := corpusTreeOfShape(t, label, shape, width)
		for x, published := range vector.Resolutions {
			want := make([]NodeIndex, 0, len(published))
			for _, node := range published {
				want = append(want, NodeIndex(node))
			}
			got := tree.Resolution(NodeIndex(x))
			if !equalNodeIndices(got, want) {
				t.Fatalf("%s: Resolution(%d) = %v, and the corpus publishes %v", label, x, got, want)
			}
			compared += 1
			if len(want) > 1 && want[0] == NodeIndex(x) {
				withUnmerged += 1
			}
			if !slices.IsSorted(want) {
				notAscending += 1
			}
		}
	}
	if compared != treeValidationResolutionCount {
		t.Errorf("compared %d published resolutions, want %d", compared, treeValidationResolutionCount)
	}
	// the unmerged half of section 7.5, counted rather than assumed. An implementation that
	// appended no unmerged leaves at all produces a resolution that is a strict SUBSET of the
	// right one, and every case where nobody has been added since the last commit still passes
	// -- so a run of this corpus that reached none of these would be reporting a clean bill over
	// the one clause that fails silently. The count is the tree math plan's own pin on this
	// corpus, so the two readings of it have to agree.
	if withUnmerged != treeValidationUnmergedCount {
		t.Errorf("%d published resolutions carry a node's unmerged leaves, want %d",
			withUnmerged, treeValidationUnmergedCount)
	}
	if notAscending != 7 {
		t.Errorf("%d published resolutions are not in ascending node order, want 7; an implementation that sorted its answer would pass a run with none",
			notAscending)
	}
}
