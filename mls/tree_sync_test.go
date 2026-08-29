// The whole-tree validation tests, and the one property that decides how nearly every one of
// them is built.
//
// Validate is five sweeps, and the failure this file is written against is not "a check is
// wrong" -- it is "a check runs over the first element of its set and returns nil for the rest".
// That shape passes every fixture whose single bad element happens to sit at position zero, which
// is where a fixture written by hand puts it, and this project has shipped it four times. So no
// test below breaks the first leaf, the first parent, the first entry of an unmerged_leaves
// vector or the first intermediate on a path. Each one derives the positions its set HAS from
// the tree, puts the single offender at every one of them in turn, and requires the refusal at
// each -- with a control at the same shape and no offender, so a fixture that was already broken
// cannot pass as a sweep that works.
//
// The fixtures are planted into the node array rather than installed through SetLeaf and
// SetParent, and plantNode says why: the setters refuse several of the shapes under test, and the
// tree this file is about did not come through them.
package mls

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func testTreeValidationContext(crypto CryptoProvider) *TreeValidationContext {
	return &TreeValidationContext{
		Crypto:  crypto,
		Suite:   CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId: testGroupId(),
		RequiredCaps: &RequiredCapabilities{
			ExtensionTypes:  []ExtensionType{ExtensionTypeUrmessageGroupPolicy, ExtensionTypeUrmessageLeafKeys},
			CredentialTypes: []CredentialType{CredentialTypeBasic},
		},
		GroupExtensions: []Extension{
			{ExtensionType: ExtensionTypeUrmessageGroupPolicy, ExtensionData: []byte("policy")},
		},
		NowMs:       1_000_000,
		ClockSkewMs: 3_600_000,
	}
}

// plantNode installs a node at a raw index, past every refusal SetLeaf and SetParent make.
//
// The doors it bypasses are the point rather than a convenience. SetParent refuses an
// unmerged_leaves entry the tree does not have and refuses a parent body at an even index;
// SetLeaf refuses a leaf body at an odd one. Those are three of the shapes this file has to
// judge, and the tree it judges did not come through either setter -- it was DECODED, out of a
// Welcome or a ratchet_tree extension some peer chose, and the codec enforces neither rule. A
// fixture built through the setters could only ever hold the shapes the setters allow, which is
// exactly the set Validate would then be saying nothing about.
func plantNode(t testing.TB, tree *RatchetTree, x NodeIndex, node *Node) {
	t.Helper()
	if uint32(x) >= tree.NodeWidth() {
		t.Fatalf("plant at node %d: the tree holds %d nodes", x, tree.NodeWidth())
	}
	tree.nodes[x] = node
}

func plantParent(t testing.TB, tree *RatchetTree, x NodeIndex, parent *ParentNode) {
	t.Helper()
	plantNode(t, tree, x, &Node{NodeType: NodeTypeParent, Parent: parent.Clone()})
}

// fillerKey is a 32 byte encryption key for a planted parent, derived from the index it is
// planted at.
//
// Derived and not a constant, because two planted parents sharing a key would answer
// errDuplicateEncryptionKey -- and every unmerged_leaves assertion in this file would then be
// passing on a refusal that has nothing to do with unmerged leaves. It is a repeating two byte
// pattern, which no X25519 public key any fixture here generates will ever be.
// tamperParentHash answers a parent_hash field that is not the one it was given, for any field
// including the EMPTY one.
//
// Flipping a byte of the stored field is the obvious way to write this and it panics on the
// root: an UpdatePath gives the topmost node an empty parent_hash, so the root of every
// committed tree in this package carries a zero length field. A sweep that skipped the root
// rather than tampering with it would leave the one parent nothing above it can claim untested,
// which is where a chain check is likeliest to stop early.
func tamperParentHash(field []byte) []byte {
	return append(cloneBytes(field), 0x5A)
}

func fillerKey(x NodeIndex) HpkePublicKey {
	return HpkePublicKey(bytes.Repeat([]byte{0xE0, byte(x)}, 16))
}

// ---------------------------------------------------------------------------
// the accepting side
// ---------------------------------------------------------------------------

// TestValidateAcceptsAFreshAndACommittedTree is the positive control every refusal below stands
// on: a tree this package builds, before and after a commit, at five widths.
//
// It asserts the node array is untouched as well, at both. Validate is a REFUSAL surface over a
// tree a caller has not agreed to yet, and a validator that normalised a node on its way through
// would leave that caller holding a tree no peer sent -- the same atomicity task 21's merge owes,
// owed here on the accepting path too because a repair made while answering nil is the one
// nothing else in this file would notice.
func TestValidateAcceptsAFreshAndACommittedTree(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	for _, n := range []uint32{1, 2, 3, 5, 8} {
		tree, members := newTestTree(t, crypto, n)
		before := treeSnapshot(tree)
		if err := tree.Validate(testTreeValidationContext(crypto)); err != nil {
			t.Fatalf("n=%d Validate on a fresh tree: %v", n, err)
		}
		if after := treeSnapshot(tree); !slices.Equal(before, after) {
			t.Errorf("n=%d a fresh tree was changed by the validator that accepted it", n)
		}
		if n < 2 {
			continue
		}
		senderTree, _, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)
		before = treeSnapshot(senderTree)
		if err := senderTree.Validate(testTreeValidationContext(crypto)); err != nil {
			t.Fatalf("n=%d Validate after a commit: %v", n, err)
		}
		if after := treeSnapshot(senderTree); !slices.Equal(before, after) {
			t.Errorf("n=%d a committed tree was changed by the validator that accepted it", n)
		}
	}
}

// ---------------------------------------------------------------------------
// check 1: the shape of the node array
// ---------------------------------------------------------------------------

// TestValidateRefusesANodeArrayThatIsNotTwoNMinusOne drives the two structural refusals
// separately, by the detail each carries, so neither is covered only by the other.
//
// They overlap on the inputs but not on the message: a zero width and an even width fail the
// inversion AND the fullness test, while an odd width that is not 2^k+... fails only the second.
// Asserting the detail is what keeps the first branch from becoming unreachable decoration the
// day somebody reorders them.
func TestValidateRefusesANodeArrayThatIsNotTwoNMinusOne(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	full, _ := newTestTree(t, crypto, 8)
	if err := full.Validate(testTreeValidationContext(crypto)); err != nil {
		t.Fatalf("the fixture this truncates does not validate, so every refusal below could be it: %v", err)
	}
	cases := []struct {
		name   string
		width  int
		detail string
	}{
		{"no nodes at all", 0, "is not 2n-1"},
		{"an even node width", 14, "is not 2n-1"},
		{"an odd width whose leaf count is not a power of two", 11, "power of two"},
		{"one node short of a doubling", 13, "power of two"},
	}
	for _, c := range cases {
		broken := full.Clone()
		broken.nodes = broken.nodes[:c.width]
		err := broken.Validate(testTreeValidationContext(crypto))
		if !errors.Is(err, ErrTreeMalformed) {
			t.Errorf("%s: err = %v, want ErrTreeMalformed", c.name, err)
			continue
		}
		if !strings.Contains(err.Error(), c.detail) {
			t.Errorf("%s: err = %q and does not carry %q, so the two structural refusals are indistinguishable",
				c.name, err, c.detail)
		}
	}
}

// TestValidateJudgesTheNodeTypeAtEveryPosition sweeps the wrong kind of node across every slot
// the array has.
//
// Every slot and not one of each parity: the check is a loop and the class it must cover is "any
// position", so a version that judged position zero, or the leaves alone, or stopped at the first
// parent is what this is looking for. The wrong kind for a slot is derived from the slot's own
// parity rather than listed, which is the same derivation the implementation makes and the reason
// the sweep does not have to be told where the leaves are.
func TestValidateJudgesTheNodeTypeAtEveryPosition(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 8)
	if err := tree.Validate(testTreeValidationContext(crypto)); err != nil {
		t.Fatalf("the fixture does not validate, so every refusal below could be it: %v", err)
	}
	sampleLeaf := tree.Leaf(LeafIndex(0)).Clone()
	swept := 0
	for x := uint32(0); x < tree.NodeWidth(); x += 1 {
		wrong := &Node{NodeType: NodeTypeLeaf, Leaf: sampleLeaf.Clone()}
		if NodeIndex(x).IsLeaf() {
			wrong = &Node{NodeType: NodeTypeParent, Parent: &ParentNode{EncryptionKey: fillerKey(NodeIndex(x))}}
		}
		broken := tree.Clone()
		plantNode(t, broken, NodeIndex(x), wrong)
		swept += 1
		if err := broken.Validate(testTreeValidationContext(crypto)); !errors.Is(err, ErrNodeTypeMismatch) {
			t.Errorf("node %d holds the body the other parity takes: err = %v, want ErrNodeTypeMismatch", x, err)
		}
	}
	if swept < 3 {
		t.Fatalf("the sweep ran over %d positions, so it says nothing about a loop that reads one", swept)
	}
}

// TestValidateRefusesANodeThatIsBothKindsOrNeither is the half of "matches its position" that a
// parity test alone does not reach: the declared NodeType and the body present can disagree, and
// a node can carry both bodies or neither.
//
// A node carrying a leaf body and a parent body is the sharpest of the four. Every reader of the
// tree picks one of the two fields, the tree hash picks one and Resolution picks the other, and a
// node that answers both makes those two readers disagree about a tree they both verified.
func TestValidateRefusesANodeThatIsBothKindsOrNeither(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 8)
	leaf := tree.Leaf(LeafIndex(0)).Clone()
	parent := &ParentNode{EncryptionKey: fillerKey(NodeIndex(1))}
	cases := []struct {
		name string
		at   NodeIndex
		node *Node
	}{
		{"a leaf slot holding both bodies", 4, &Node{NodeType: NodeTypeLeaf, Leaf: leaf.Clone(), Parent: parent.Clone()}},
		{"a parent slot holding both bodies", 5, &Node{NodeType: NodeTypeParent, Parent: parent.Clone(), Leaf: leaf.Clone()}},
		{"a leaf slot holding neither body", 4, &Node{NodeType: NodeTypeLeaf}},
		{"a parent slot holding neither body", 5, &Node{NodeType: NodeTypeParent}},
		{"a leaf body under the parent type", 4, &Node{NodeType: NodeTypeParent, Leaf: leaf.Clone()}},
		{"a parent body under the leaf type", 5, &Node{NodeType: NodeTypeLeaf, Parent: parent.Clone()}},
	}
	for _, c := range cases {
		broken := tree.Clone()
		plantNode(t, broken, c.at, c.node)
		if err := broken.Validate(testTreeValidationContext(crypto)); !errors.Is(err, ErrNodeTypeMismatch) {
			t.Errorf("%s: err = %v, want ErrNodeTypeMismatch", c.name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// check 2: every non-blank leaf
// ---------------------------------------------------------------------------

// TestValidateJudgesEveryNonBlankLeafAndNotOnlyTheFirst breaks one leaf's signature at a time,
// at every occupied leaf the tree has.
//
// The occupied set is read off the tree with NonBlankLeaves rather than assumed to be 0..n-1, so
// the sweep covers the positions this fixture actually has and would keep covering them if the
// builder's shape moved.
func TestValidateJudgesEveryNonBlankLeafAndNotOnlyTheFirst(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 8)
	if err := tree.Validate(testTreeValidationContext(crypto)); err != nil {
		t.Fatalf("the fixture does not validate, so every refusal below could be it: %v", err)
	}
	leaves := tree.NonBlankLeaves()
	if len(leaves) < 2 {
		t.Fatalf("the fixture has %d occupied leaves, so a sweep over it says nothing about a loop that reads one",
			len(leaves))
	}
	for _, i := range leaves {
		broken := tree.Clone()
		leaf := broken.Leaf(i)
		leaf.Signature = cloneBytes(leaf.Signature)
		leaf.Signature[0] ^= 0xFF
		err := broken.Validate(testTreeValidationContext(crypto))
		if !errors.Is(err, errBadSignature) {
			t.Errorf("leaf %d carries a broken signature: err = %v, want errBadSignature", i, err)
			continue
		}
		if want := fmt.Sprintf("leaf %d:", i); !strings.Contains(err.Error(), want) {
			t.Errorf("leaf %d was refused as %q, which does not name the leaf that failed", i, err)
		}
	}
}

// TestValidateJudgesALeafAtItsOwnIndexAndNotAtSomeOther holds the binding the inferred source
// leaves in place.
//
// validateLeaves does not demand a leaf_node_source, because a settled tree legally holds all
// three. What it must still enforce is that an update or commit sourced leaf verifies AT THE
// INDEX IT SITS AT -- otherwise a member's own signed leaf, lifted from one position of the tree
// to another, is a valid leaf twice and the tree it makes is one nobody signed.
func TestValidateJudgesALeafAtItsOwnIndexAndNotAtSomeOther(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, members := newTestTree(t, crypto, 8)
	for i := uint32(1); i < uint32(len(members)); i += 1 {
		broken := tree.Clone()
		// member i's own leaf, signed by member i, at member i-1's position. Only the index
		// moved, so a validator that checked the signature without the position accepts it.
		moved := tree.Leaf(LeafIndex(i)).Clone()
		if err := broken.SetLeaf(LeafIndex(i-1), moved); err != nil {
			t.Fatalf("SetLeaf: %v", err)
		}
		if err := broken.Validate(testTreeValidationContext(crypto)); !errors.Is(err, errBadSignature) {
			t.Errorf("leaf %d moved to index %d: err = %v, want errBadSignature", i, i-1, err)
		}
	}
}

// ---------------------------------------------------------------------------
// check 3: key uniqueness
// ---------------------------------------------------------------------------

// TestValidateRejectsDuplicateKeys is the plan's own pair, one repeat of each kind.
func TestValidateRejectsDuplicateKeys(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, members := newTestTree(t, crypto, 4)
	duplicate := tree.Leaf(LeafIndex(1)).Clone()
	duplicate.EncryptionKey = cloneBytes(tree.Leaf(LeafIndex(0)).EncryptionKey)
	if err := duplicate.Sign(crypto, members[1].SignaturePriv, testGroupId(), LeafIndex(1)); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := tree.SetLeaf(LeafIndex(1), duplicate); err != nil {
		t.Fatalf("SetLeaf: %v", err)
	}
	if err := tree.Validate(testTreeValidationContext(crypto)); !errors.Is(err, errDuplicateEncryptionKey) {
		t.Fatalf("err = %v, want errDuplicateEncryptionKey", err)
	}

	tree, members = newTestTree(t, crypto, 4)
	duplicate = tree.Leaf(LeafIndex(1)).Clone()
	duplicate.SignatureKey = cloneBytes(tree.Leaf(LeafIndex(0)).SignatureKey)
	if err := duplicate.Sign(crypto, members[0].SignaturePriv, testGroupId(), LeafIndex(1)); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := tree.SetLeaf(LeafIndex(1), duplicate); err != nil {
		t.Fatalf("SetLeaf: %v", err)
	}
	if err := tree.Validate(testTreeValidationContext(crypto)); !errors.Is(err, errDuplicateSignatureKey) {
		t.Fatalf("err = %v, want errDuplicateSignatureKey", err)
	}
}

// TestValidateFindsADuplicateKeyWhereverThePairSits moves the repeated pair down the tree one
// position at a time.
//
// A uniqueness check written over the first element of the array, or over the first two, accepts
// every tree whose repeat is further along, and a fixture that always duplicates leaf zero cannot
// tell the difference. Each iteration repeats the key of the leaf IMMEDIATELY BEFORE the one it
// plants, so the pair walks to the far end of the array rather than always having one foot at
// index zero.
func TestValidateFindsADuplicateKeyWhereverThePairSits(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	const memberCount = 8
	swept := 0
	for j := uint32(1); j < memberCount; j += 1 {
		for _, kind := range []string{"encryption", "signature"} {
			tree, members := newTestTree(t, crypto, memberCount)
			duplicate := tree.Leaf(LeafIndex(j)).Clone()
			signer := members[j].SignaturePriv
			want := errDuplicateEncryptionKey
			if kind == "signature" {
				duplicate.SignatureKey = cloneBytes(tree.Leaf(LeafIndex(j - 1)).SignatureKey)
				// signed by the member whose key it now publishes, so the leaf still verifies
				// and the only thing wrong with the tree is the repeat
				signer = members[j-1].SignaturePriv
				want = errDuplicateSignatureKey
			} else {
				duplicate.EncryptionKey = cloneBytes(tree.Leaf(LeafIndex(j - 1)).EncryptionKey)
			}
			if err := duplicate.Sign(crypto, signer, testGroupId(), LeafIndex(j)); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if err := tree.SetLeaf(LeafIndex(j), duplicate); err != nil {
				t.Fatalf("SetLeaf: %v", err)
			}
			swept += 1
			if err := tree.Validate(testTreeValidationContext(crypto)); !errors.Is(err, want) {
				t.Errorf("leaves %d and %d share a %s key: err = %v, want %v", j-1, j, kind, err, want)
			}
		}
	}
	if swept < 4 {
		t.Fatalf("the sweep ran %d fixtures, so it says nothing about a loop that reads the front of the array", swept)
	}
}

// TestValidateFindsADuplicateEncryptionKeyAmongTheParentNodes is the half of check 3 that a leaf
// only fixture cannot reach: the rule is over EVERY node, and a version written over the leaves
// alone passes every test above.
//
// It runs every ordered pair of the non-blank parents a commit leaves behind, and then one pair
// across the two kinds -- a parent publishing a leaf's key -- because "leaf and parent alike" is
// two statements and a map keyed per kind satisfies only the first.
func TestValidateFindsADuplicateEncryptionKeyAmongTheParentNodes(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, members := newTestTree(t, crypto, 8)
	senderTree, _, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)
	parents := []NodeIndex{}
	for x := uint32(1); x < senderTree.NodeWidth(); x += 2 {
		if senderTree.ParentAt(NodeIndex(x)) != nil {
			parents = append(parents, NodeIndex(x))
		}
	}
	if len(parents) < 2 {
		t.Fatalf("a commit left %d non-blank parents, so there is no pair to repeat a key across", len(parents))
	}
	for _, from := range parents {
		for _, to := range parents {
			if from == to {
				continue
			}
			broken := senderTree.Clone()
			repeat := broken.ParentAt(to).Clone()
			repeat.EncryptionKey = HpkePublicKey(cloneBytes(broken.ParentAt(from).EncryptionKey))
			plantParent(t, broken, to, repeat)
			if err := broken.Validate(testTreeValidationContext(crypto)); !errors.Is(err, errDuplicateEncryptionKey) {
				t.Errorf("parents %d and %d share an encryption key: err = %v, want errDuplicateEncryptionKey",
					from, to, err)
			}
		}
	}
	for _, leaf := range senderTree.NonBlankLeaves() {
		at := parents[len(parents)-1]
		broken := senderTree.Clone()
		repeat := broken.ParentAt(at).Clone()
		repeat.EncryptionKey = HpkePublicKey(cloneBytes(broken.Leaf(leaf).EncryptionKey))
		plantParent(t, broken, at, repeat)
		if err := broken.Validate(testTreeValidationContext(crypto)); !errors.Is(err, errDuplicateEncryptionKey) {
			t.Errorf("parent %d publishes leaf %d's encryption key: err = %v, want errDuplicateEncryptionKey",
				at, leaf, err)
		}
	}
}

// ---------------------------------------------------------------------------
// check 4: unmerged leaves
// ---------------------------------------------------------------------------

// TestValidateRejectsBadUnmergedLeaves is the plan's table, one refusal per way a single entry
// can be wrong.
//
// The parents are PLANTED rather than installed: SetParent refuses an out of range entry itself,
// so the plan's own version of this table never reaches Validate at all for that row -- it stops
// at the setter and reports a fixture failure. The tree this rule is stated over arrives decoded,
// and the codec checks the order of the vector and nothing about its contents.
func TestValidateRejectsBadUnmergedLeaves(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	cases := []struct {
		name     string
		unmerged []LeafIndex
		want     error
	}{
		{"descending", []LeafIndex{1, 0}, ErrUnmergedLeavesNotSorted},
		{"duplicated", []LeafIndex{1, 1}, ErrUnmergedLeavesNotSorted},
		{"out of range", []LeafIndex{99}, ErrUnmergedLeafInconsistent},
		{"not a descendant", []LeafIndex{3}, ErrUnmergedLeafInconsistent},
	}
	for _, c := range cases {
		tree, _ := newTestTree(t, crypto, 4)
		plantParent(t, tree, NodeIndex(1), &ParentNode{
			EncryptionKey:  fillerKey(NodeIndex(1)),
			UnmergedLeaves: c.unmerged,
		})
		if err := tree.Validate(testTreeValidationContext(crypto)); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	// a blank leaf, which is a member who is gone and a node that still names them
	tree, _ := newTestTree(t, crypto, 4)
	if err := tree.Blank(LeafIndex(1).NodeIndex()); err != nil {
		t.Fatalf("Blank: %v", err)
	}
	plantParent(t, tree, NodeIndex(1), &ParentNode{
		EncryptionKey:  fillerKey(NodeIndex(1)),
		UnmergedLeaves: []LeafIndex{1},
	})
	if err := tree.Validate(testTreeValidationContext(crypto)); !errors.Is(err, ErrUnmergedLeafInconsistent) {
		t.Errorf("a node listing a blank leaf: err = %v, want ErrUnmergedLeafInconsistent", err)
	}
}

// TestValidateJudgesTheUnmergedLeavesOfEveryParentAndNotOnlyTheFirst plants the same offending
// vector at every parent slot in turn.
//
// The slots are derived from the width -- every odd index, which is what the parents are -- so
// the sweep covers the last one and every one in between, and a check that stopped after the
// first non-blank parent it found is a failure at every position but that one.
func TestValidateJudgesTheUnmergedLeavesOfEveryParentAndNotOnlyTheFirst(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 8)
	if err := tree.Validate(testTreeValidationContext(crypto)); err != nil {
		t.Fatalf("the fixture does not validate, so every refusal below could be it: %v", err)
	}
	// the first leaf index this tree does not have, so the entry is wrong at EVERY parent
	// including the root, which "not a descendant" cannot be
	beyond := LeafIndex(tree.LeafWidth())
	swept := 0
	for x := uint32(1); x < tree.NodeWidth(); x += 2 {
		broken := tree.Clone()
		plantParent(t, broken, NodeIndex(x), &ParentNode{
			EncryptionKey:  fillerKey(NodeIndex(x)),
			UnmergedLeaves: []LeafIndex{beyond},
		})
		swept += 1
		err := broken.Validate(testTreeValidationContext(crypto))
		if !errors.Is(err, ErrUnmergedLeafInconsistent) {
			t.Errorf("parent %d lists leaf %d and the tree has %d leaves: err = %v, want ErrUnmergedLeafInconsistent",
				x, beyond, tree.LeafWidth(), err)
			continue
		}
		// the RANGE branch and not the blank leaf branch, which the same sentinel would also
		// answer: an index the tree does not have reaches Leaf as a nil too, so without this the
		// range check could be deleted and this sweep would keep passing on the other one.
		if want := "and the tree has"; !strings.Contains(err.Error(), want) {
			t.Errorf("parent %d: err = %q, which does not report an out of range index", x, err)
		}
	}
	if swept < 2 {
		t.Fatalf("the sweep ran over %d parent slots, so it says nothing about a loop that reads one", swept)
	}
}

// TestValidateJudgesEveryEntryOfAnUnmergedLeavesVector moves the single bad entry along the
// vector without disturbing the vector.
//
// The vector is the same at every iteration -- every leaf the tree has, ascending -- and what
// moves is which leaf is BLANK. So entry k is the only one that offends, the order is never in
// question, and a check applied to element zero of the list passes for every k but zero. The
// control at the top plants the same vector over a tree with no blank leaf and requires that this
// refusal does not fire, which is what stops the sweep from passing on a vector that was wrong to
// begin with.
func TestValidateJudgesEveryEntryOfAnUnmergedLeavesVector(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 8)
	root, err := rootOf(tree.LeafWidth())
	if err != nil {
		t.Fatalf("rootOf: %v", err)
	}
	everyLeaf := []LeafIndex{}
	for i := uint32(0); i < uint32(tree.LeafWidth()); i += 1 {
		everyLeaf = append(everyLeaf, LeafIndex(i))
	}
	if len(everyLeaf) < 3 {
		t.Fatalf("the vector under test has %d entries, so moving the offender along it proves little", len(everyLeaf))
	}
	control := tree.Clone()
	plantParent(t, control, root, &ParentNode{EncryptionKey: fillerKey(root), UnmergedLeaves: everyLeaf})
	if err := control.Validate(testTreeValidationContext(crypto)); errors.Is(err, ErrUnmergedLeafInconsistent) {
		t.Fatalf("the control vector is already inconsistent, so the sweep below proves nothing: %v", err)
	}
	for k := range everyLeaf {
		broken := tree.Clone()
		if err := broken.Blank(everyLeaf[k].NodeIndex()); err != nil {
			t.Fatalf("Blank(%d): %v", everyLeaf[k], err)
		}
		plantParent(t, broken, root, &ParentNode{EncryptionKey: fillerKey(root), UnmergedLeaves: everyLeaf})
		err := broken.Validate(testTreeValidationContext(crypto))
		if !errors.Is(err, ErrUnmergedLeafInconsistent) {
			t.Errorf("entry %d of %d names leaf %d, which is blank: err = %v, want ErrUnmergedLeafInconsistent",
				k, len(everyLeaf), everyLeaf[k], err)
			continue
		}
		if want := fmt.Sprintf("leaf %d, which is blank", everyLeaf[k]); !strings.Contains(err.Error(), want) {
			t.Errorf("entry %d was refused as %q, which does not name the entry that offends", k, err)
		}
	}
}

// TestValidateJudgesEveryIntermediateBetweenAnUnmergedLeafAndTheNodeListingIt walks the offending
// intermediate up the path.
//
// This is the clause the plan's own test reaches at position zero only: it puts the leaf's list
// at node 3 of an eight leaf tree, where exactly one node stands between, so a check that read
// the first intermediate and stopped passes it. Here the list sits at the ROOT, the intermediates
// are derived from the leaf's own direct path, and each of them is the offender in turn.
//
// Both arrangements of the innocent intermediates are run. With them blank the offender is the
// only node the walk can look at, so a walk that skipped blanks and then stopped is caught; with
// them non-blank and carrying the leaf, the walk has to pass over a legitimate entry to reach the
// offender, which is the arrangement a real tree is in.
func TestValidateJudgesEveryIntermediateBetweenAnUnmergedLeafAndTheNodeListingIt(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 8)
	const unmerged = LeafIndex(0)
	root, err := rootOf(tree.LeafWidth())
	if err != nil {
		t.Fatalf("rootOf: %v", err)
	}
	path, err := directPathOf(unmerged.NodeIndex(), tree.LeafWidth())
	if err != nil {
		t.Fatalf("directPathOf: %v", err)
	}
	intermediates := []NodeIndex{}
	for _, x := range path {
		if x == root {
			break
		}
		intermediates = append(intermediates, x)
	}
	if len(intermediates) < 2 {
		t.Fatalf("leaf %d has %d nodes between it and the root, so moving the offender along them proves nothing",
			unmerged, len(intermediates))
	}
	// offender is an index into intermediates, or -1 for the control with no offender at all
	build := func(offender int, othersCarry bool) *RatchetTree {
		out := tree.Clone()
		plantParent(t, out, root, &ParentNode{
			EncryptionKey:  fillerKey(root),
			UnmergedLeaves: []LeafIndex{unmerged},
		})
		for j, x := range intermediates {
			switch {
			case j == offender:
				plantParent(t, out, x, &ParentNode{EncryptionKey: fillerKey(x)})
			case othersCarry:
				plantParent(t, out, x, &ParentNode{
					EncryptionKey:  fillerKey(x),
					UnmergedLeaves: []LeafIndex{unmerged},
				})
			}
		}
		return out
	}
	for _, othersCarry := range []bool{false, true} {
		control := build(-1, othersCarry)
		if err := control.Validate(testTreeValidationContext(crypto)); errors.Is(err, ErrUnmergedLeafInconsistent) {
			t.Fatalf("othersCarry=%v: the control is already inconsistent, so the sweep proves nothing: %v",
				othersCarry, err)
		}
		for k, offender := range intermediates {
			broken := build(k, othersCarry)
			err := broken.Validate(testTreeValidationContext(crypto))
			if !errors.Is(err, ErrUnmergedLeafInconsistent) {
				t.Errorf("othersCarry=%v: node %d between leaf %d and node %d does not list it: err = %v, want ErrUnmergedLeafInconsistent",
					othersCarry, offender, unmerged, root, err)
				continue
			}
			if want := fmt.Sprintf("node %d between them does not", offender); !strings.Contains(err.Error(), want) {
				t.Errorf("othersCarry=%v: the refusal is %q and does not name node %d, so the walk stopped somewhere else",
					othersCarry, err, offender)
			}
		}
	}
}

// TestValidateRejectsAnUnmergedLeafThatAnIntermediateDoesNotCarry is the plan's own fixture,
// kept because it is the one shape a published tree is likeliest to have -- a list at a node two
// levels up with one node in between.
func TestValidateRejectsAnUnmergedLeafThatAnIntermediateDoesNotCarry(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 8)
	// the node at 3 lists leaf 0, and node 1 between them does not.
	plantParent(t, tree, NodeIndex(1), &ParentNode{EncryptionKey: fillerKey(NodeIndex(1))})
	plantParent(t, tree, NodeIndex(3), &ParentNode{
		EncryptionKey:  fillerKey(NodeIndex(3)),
		UnmergedLeaves: []LeafIndex{0},
	})
	if err := tree.Validate(testTreeValidationContext(crypto)); !errors.Is(err, ErrUnmergedLeafInconsistent) {
		t.Fatalf("err = %v, want ErrUnmergedLeafInconsistent", err)
	}
}

// ---------------------------------------------------------------------------
// check 5: the parent hashes, which are VerifyParentHashes' and not restated here
// ---------------------------------------------------------------------------

// TestValidateVerifiesTheParentHashOfEveryNonBlankParent breaks the chain at each parent a commit
// left behind, one at a time.
//
// The whole point of the check is that Validate CALLS it: a version that ran the four cheaper
// sweeps and returned nil accepts every tree in this test, and accepts every tree in every other
// test in this file too, because nothing else here depends on the chain.
func TestValidateVerifiesTheParentHashOfEveryNonBlankParent(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, members := newTestTree(t, crypto, 8)
	senderTree, _, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)
	if err := senderTree.Validate(testTreeValidationContext(crypto)); err != nil {
		t.Fatalf("the committed fixture does not validate, so every refusal below could be it: %v", err)
	}
	swept := 0
	for x := uint32(1); x < senderTree.NodeWidth(); x += 2 {
		parent := senderTree.ParentAt(NodeIndex(x))
		if parent == nil {
			continue
		}
		broken := senderTree.Clone()
		tampered := broken.ParentAt(NodeIndex(x)).Clone()
		tampered.ParentHash = tamperParentHash(tampered.ParentHash)
		plantParent(t, broken, NodeIndex(x), tampered)
		swept += 1
		if err := broken.Validate(testTreeValidationContext(crypto)); !errors.Is(err, ErrParentHashMismatch) {
			t.Errorf("parent %d carries a tampered parent_hash: err = %v, want ErrParentHashMismatch", x, err)
		}
	}
	if swept < 2 {
		t.Fatalf("a commit left %d non-blank parents to tamper with, so the sweep says little", swept)
	}
}

// TestValidateRefusesASplicedSubtreeThatKeepsTheHashChain is the reason this file calls
// VerifyParentHashes instead of restating RFC 9420 section 7.9.2.
//
// The plan this task came from states that rule with ONE condition where the RFC states three,
// and owner decision 68 records it. The condition it drops is the one that constrains the child's
// RESOLUTION to be exactly the claimant plus the parent's unmerged leaves under it -- and the
// resolution is the set a commit encrypts path secrets to. The tree built here is what dropping
// it costs: every parent_hash chains, every leaf verifies at its own index, every key is unique,
// every unmerged_leaves vector is empty, and node 1 is spliced into the resolution of the root's
// left child beside nothing at all, so the next honest commit would seal a path secret to a key
// the splicer chose.
//
// The four cheaper checks are driven directly and required to pass, which is what makes the
// refusal attributable: a fixture that failed for any other reason would report the same sentinel
// through a different door.
func TestValidateRefusesASplicedSubtreeThatKeepsTheHashChain(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, members := newTestTree(t, crypto, 8)
	spliced, _, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)
	if err := spliced.Validate(testTreeValidationContext(crypto)); err != nil {
		t.Fatalf("the committed fixture does not validate, so the refusal below could be it: %v", err)
	}
	// blanking node 3 widens the resolution of the root's left child from the single node 3 to
	// node 1 and the two leaves under node 5, which is the room the splice needs: a resolution of
	// one entry cannot hold a claimant and a stranger at once.
	if err := spliced.Blank(NodeIndex(3)); err != nil {
		t.Fatalf("Blank(3): %v", err)
	}
	// node 1 is given the parent hash the root's left child is supposed to carry, so it satisfies
	// conditions 1 and 2 of section 7.9.2 exactly.
	rootHash, err := spliced.ParentHash(crypto, NodeIndex(7), NodeIndex(11))
	if err != nil {
		t.Fatalf("ParentHash(7, 11): %v", err)
	}
	claimant := spliced.ParentAt(NodeIndex(1)).Clone()
	claimant.ParentHash = rootHash
	plantParent(t, spliced, NodeIndex(1), claimant)
	// and the committer's own leaf is re-chained onto node 1's new field, so node 1 itself is
	// still claimed by exactly one descendant. Without this the tree would be refused at node 1
	// and the assertion below would hold against a version that never checked the root.
	leafHash, err := spliced.ParentHash(crypto, NodeIndex(1), NodeIndex(2))
	if err != nil {
		t.Fatalf("ParentHash(1, 2): %v", err)
	}
	committer := spliced.Leaf(LeafIndex(0))
	committer.ParentHash = leafHash
	if err := committer.Sign(crypto, members[0].SignaturePriv, testGroupId(), LeafIndex(0)); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ctx := testTreeValidationContext(crypto)
	if err := spliced.validateStructure(); err != nil {
		t.Fatalf("the spliced tree fails the structure check, so the refusal is not the splice: %v", err)
	}
	if err := spliced.validateLeaves(ctx); err != nil {
		t.Fatalf("the spliced tree fails the leaf check, so the refusal is not the splice: %v", err)
	}
	if err := spliced.validateKeyUniqueness(); err != nil {
		t.Fatalf("the spliced tree fails the key uniqueness check, so the refusal is not the splice: %v", err)
	}
	if err := spliced.validateUnmergedLeaves(); err != nil {
		t.Fatalf("the spliced tree fails the unmerged leaves check, so the refusal is not the splice: %v", err)
	}
	// the claimant really is in the resolution of the root's left child, and it is not alone --
	// which is the whole of condition 3 and the whole of what the plan's version does not ask.
	resolution := spliced.Resolution(NodeIndex(3))
	if !slices.Contains(resolution, NodeIndex(1)) || len(resolution) < 2 {
		t.Fatalf("the resolution of node 3 is %v, which is not a claimant spliced in beside others; the fixture does not pose the question",
			resolution)
	}
	if err := spliced.Validate(ctx); !errors.Is(err, ErrParentHashMismatch) {
		t.Fatalf("a spliced subtree with an intact hash chain: err = %v, want ErrParentHashMismatch", err)
	}
}

// ---------------------------------------------------------------------------
// check 6: the binding to the epoch that pinned the tree
// ---------------------------------------------------------------------------

func TestValidateAgainstContextChecksTheTreeHash(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 4)
	treeHash, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	gc := &GroupContext{
		Version:     ProtocolVersionMls10,
		CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:     testGroupId(),
		Epoch:       1,
		TreeHash:    treeHash,
	}
	if err := tree.ValidateAgainstContext(testTreeValidationContext(crypto), gc); err != nil {
		t.Fatalf("ValidateAgainstContext: %v", err)
	}
	// every byte of the digest and not the first one alone, so a comparison over a prefix is a
	// failure here rather than a thing nothing asks about
	for i := range treeHash {
		gc.TreeHash = cloneBytes(treeHash)
		gc.TreeHash[i] ^= 0xFF
		if err := tree.ValidateAgainstContext(testTreeValidationContext(crypto), gc); !errors.Is(err, ErrTreeHashMismatch) {
			t.Fatalf("byte %d of the pinned tree hash flipped: err = %v, want ErrTreeHashMismatch", i, err)
		}
	}
	for _, c := range []struct {
		name string
		hash []byte
	}{
		{"an absent tree hash", nil},
		{"an empty tree hash", []byte{}},
		{"a truncated tree hash", cloneBytes(treeHash)[:len(treeHash)-1]},
		{"a lengthened tree hash", append(cloneBytes(treeHash), 0)},
	} {
		gc.TreeHash = c.hash
		if err := tree.ValidateAgainstContext(testTreeValidationContext(crypto), gc); !errors.Is(err, ErrTreeHashMismatch) {
			t.Errorf("%s: err = %v, want ErrTreeHashMismatch", c.name, err)
		}
	}
}

// TestValidateAgainstContextRunsEveryCheckValidateRuns is the half a tree hash test cannot see:
// the context binding is an ADDITION to Validate and never a replacement for it, and a version
// that compared the hash and returned would accept every broken tree above as long as its digest
// was pinned honestly.
func TestValidateAgainstContextRunsEveryCheckValidateRuns(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, members := newTestTree(t, crypto, 4)
	broken := tree.Clone()
	duplicate := broken.Leaf(LeafIndex(1)).Clone()
	duplicate.EncryptionKey = cloneBytes(broken.Leaf(LeafIndex(0)).EncryptionKey)
	if err := duplicate.Sign(crypto, members[1].SignaturePriv, testGroupId(), LeafIndex(1)); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := broken.SetLeaf(LeafIndex(1), duplicate); err != nil {
		t.Fatalf("SetLeaf: %v", err)
	}
	// the group context pins the BROKEN tree honestly, so check 6 is satisfied and only the
	// checks Validate makes can refuse it
	treeHash, err := broken.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	gc := &GroupContext{
		Version:     ProtocolVersionMls10,
		CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:     testGroupId(),
		Epoch:       1,
		TreeHash:    treeHash,
	}
	if err := broken.ValidateAgainstContext(testTreeValidationContext(crypto), gc); !errors.Is(err, errDuplicateEncryptionKey) {
		t.Fatalf("err = %v, want errDuplicateEncryptionKey", err)
	}
}

// ---------------------------------------------------------------------------
// the refusals that are about the arguments rather than the tree
// ---------------------------------------------------------------------------

// TestValidateRefusesAMissingProviderAndAMissingContext holds the three arguments that cannot be
// absent.
//
// A nil context and a context with a nil provider must answer the same thing about the same
// missing thing, which is LeafNode.Validate's rule one layer down; and a nil GroupContext is
// refused rather than dereferenced, because "there was nothing to compare against" must not
// arrive at a caller as a match.
func TestValidateRefusesAMissingProviderAndAMissingContext(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, _ := newTestTree(t, crypto, 4)
	if err := tree.Validate(nil); !errors.Is(err, ErrNilCryptoProvider) {
		t.Errorf("Validate(nil): err = %v, want ErrNilCryptoProvider", err)
	}
	if err := tree.Validate(&TreeValidationContext{}); !errors.Is(err, ErrNilCryptoProvider) {
		t.Errorf("Validate with no provider: err = %v, want ErrNilCryptoProvider", err)
	}
	if err := tree.ValidateAgainstContext(nil, &GroupContext{}); !errors.Is(err, ErrNilCryptoProvider) {
		t.Errorf("ValidateAgainstContext(nil, gc): err = %v, want ErrNilCryptoProvider", err)
	}
	if err := tree.ValidateAgainstContext(testTreeValidationContext(crypto), nil); !errors.Is(err, ErrTreeHashMismatch) {
		t.Errorf("ValidateAgainstContext with no group context: err = %v, want ErrTreeHashMismatch", err)
	}
}

// ---------------------------------------------------------------------------
// atomicity
// ---------------------------------------------------------------------------

// TestValidateLeavesTheTreeExactlyAsItFoundIt is task 21's obligation at this door.
//
// A refused tree is a tree the caller never adopted, and a validator that repaired, sorted or
// blanked anything on its way to a refusal hands that caller a structure no peer sent -- which
// the caller then keeps, because the refusal told them the tree was somebody else's problem. The
// whole node array is compared, not the tree hash: a parent_hash field written back is invisible
// to the hash of a tree whose leaves are update sourced, which is exactly the fixture family
// above.
func TestValidateLeavesTheTreeExactlyAsItFoundIt(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	sound, members := newTestTree(t, crypto, 8)
	committed, _, _, _ := createAndEncryptPath(t, crypto, sound, members[0], nil)

	badType := sound.Clone()
	plantNode(t, badType, NodeIndex(5), &Node{NodeType: NodeTypeLeaf, Leaf: sound.Leaf(LeafIndex(0)).Clone()})

	badLeaf := sound.Clone()
	badLeaf.Leaf(LeafIndex(6)).Signature[0] ^= 0xFF

	badKeys := sound.Clone()
	repeat := badKeys.Leaf(LeafIndex(7)).Clone()
	repeat.EncryptionKey = cloneBytes(badKeys.Leaf(LeafIndex(6)).EncryptionKey)
	if err := repeat.Sign(crypto, members[7].SignaturePriv, testGroupId(), LeafIndex(7)); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := badKeys.SetLeaf(LeafIndex(7), repeat); err != nil {
		t.Fatalf("SetLeaf: %v", err)
	}

	badUnmerged := sound.Clone()
	plantParent(t, badUnmerged, NodeIndex(13), &ParentNode{
		EncryptionKey:  fillerKey(NodeIndex(13)),
		UnmergedLeaves: []LeafIndex{0},
	})

	badChain := committed.Clone()
	tampered := badChain.ParentAt(NodeIndex(7)).Clone()
	tampered.ParentHash = tamperParentHash(tampered.ParentHash)
	plantParent(t, badChain, NodeIndex(7), tampered)

	cases := []struct {
		name    string
		tree    *RatchetTree
		refused bool
	}{
		{"a sound fresh tree", sound, false},
		{"a sound committed tree", committed, false},
		{"a node of the wrong type", badType, true},
		{"a leaf whose signature does not verify", badLeaf, true},
		{"a repeated encryption key", badKeys, true},
		{"an unmerged leaf outside the subtree", badUnmerged, true},
		{"a broken parent hash chain", badChain, true},
	}
	for _, c := range cases {
		before := treeSnapshot(c.tree)
		err := c.tree.Validate(testTreeValidationContext(crypto))
		if refused := err != nil; refused != c.refused {
			t.Errorf("%s: err = %v, refused = %v, want refused = %v", c.name, err, refused, c.refused)
		}
		if after := treeSnapshot(c.tree); !slices.Equal(before, after) {
			t.Errorf("%s: the validator changed the caller's tree", c.name)
			for i := range before {
				if i < len(after) && before[i] != after[i] {
					t.Errorf("  %s -> %s", before[i], after[i])
				}
			}
		}
		// and the same through the context door, which hashes the tree as well as walking it
		gc := &GroupContext{TreeHash: bytes.Repeat([]byte{0x00}, 32)}
		before = treeSnapshot(c.tree)
		if err := c.tree.ValidateAgainstContext(testTreeValidationContext(crypto), gc); err == nil {
			t.Errorf("%s: ValidateAgainstContext accepted a tree the group context does not pin", c.name)
		}
		if after := treeSnapshot(c.tree); !slices.Equal(before, after) {
			t.Errorf("%s: ValidateAgainstContext changed the caller's tree", c.name)
		}
	}
}
