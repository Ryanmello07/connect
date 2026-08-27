// tests for the RFC 9420 section 9 secret tree: the descent, and the deletions that are
// the forward secrecy.
//
// Half of this file asks what a value IS, and that half is cheap: every implementation of
// section 9 that derives correctly agrees on it, including one that never deletes anything.
// The other half asks what is NO LONGER REACHABLE, which is the property the section exists
// for and the one nothing else in this package has needed yet. Where that question runs into
// what go can actually observe — a copy the runtime made, a value left in a register — the
// limit is written down in the comment rather than papered over with an assertion that would
// pass either way.
//
// What the plan's own six tests were measured unable to fail, run verbatim against fifteen
// single-edit mutants of secret_tree.go, each mutant confirmed applied by diff before its
// result was believed:
//
//   - TestSecretTreeLeafCount never failed against any of the fifteen. It builds one tree of
//     eight leaves and asks for eight back, so an accessor whose body is "return 8" satisfies
//     it. Replaced here by a sweep over every swept width, which fails against exactly that
//     mutant.
//   - TestSecretTreeRejectsOutOfRangeLeaf never failed against any of the fifteen, INCLUDING
//     the one that deletes the leaf-count range check outright. Its two probes, 8 and 1<<20,
//     are both refused by the node-array bound instead, so the check it exists to exercise can
//     be removed with the test still green -- and with it removed, leaf 2^31 wraps to node 0
//     and the tree hands out leaf 0's secret to a sender claiming an index no tree can hold.
//     The version here probes 1<<31, (1<<31)+4 and 0xffffffff, and fails against that mutant.
//   - TestSecretTreeDescentDerivesBothChildren does fail against a swapped label and a mirrored
//     descent, but not against the erasure moved one step too early -- the mutation its own
//     last assertion names. "leaf 7 is still reachable" is checked as err == nil, and a right
//     subtree derived from a run of zeros is still perfectly reachable. The version here
//     compares leaf 7's bytes.
//   - TestSecretTreeLeafSecretIsTakenOnce sees the map delete but not the erasure: it passes
//     against a tree that never calls zeroizeSecret at all, which is the half of the forward
//     secrecy claim in its own doc comment that it does not observe.
//
// No plan test failed against any of: never zeroizing a node secret, hardcoding the KDF width
// to 32, ignoring Root's error, or hardcoding the node-array width.
package mls

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// stTestCrypto returns the ciphersuite 0x0003 provider the secret tree KATs use.
func stTestCrypto(t *testing.T) CryptoProvider {
	t.Helper()
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	return crypto
}

const stVectorEncryptionSecret = "59227ed552e4a6db0779d43aea694fd1b2c2540e605a099b95cf852b41e8ea66"

// stSweptLeafCounts is every full leaf count this file sweeps. It is written as a range
// rather than a list so that "the sizes covered" is a bound and not a set somebody has to
// keep in step with the assertions: every power of two from one leaf to sixty-four.
func stSweptLeafCounts() []LeafCount {
	counts := []LeafCount{}
	for n := LeafCount(1); n <= 64; n *= 2 {
		counts = append(counts, n)
	}
	return counts
}

// stLeavesOf returns the leaf indices of a tree, derived from its node array's width rather
// than picked. Leaves are the even node indices below the width, so this is the same set the
// implementation has to reach and it is obtained from tree math rather than from a literal.
func stLeavesOf(t *testing.T, leafCount LeafCount) []LeafIndex {
	t.Helper()
	width := NodeWidth(leafCount)
	if width == 0 {
		t.Fatalf("NodeWidth(%d) is zero, so this sweep would cover nothing", leafCount)
	}
	leaves := []LeafIndex{}
	for node := uint32(0); node < width; node += 2 {
		leaves = append(leaves, LeafIndex(node/2))
	}
	if LeafCount(len(leaves)) != leafCount {
		t.Fatalf("width %d yields %d leaves for a count of %d", width, len(leaves), leafCount)
	}
	return leaves
}

// stExpectedNodeSecret derives one node's secret from the encryption secret independently of
// the code under test.
//
// It shares no arithmetic with the descent. pathToLeaf decides direction by comparing the
// target index against the node it is standing on; this walks p3's DirectPath UPWARD to
// learn the ancestry, replays it downward, and asks Left and Right at each step which child
// the next node actually is. So a descent that went to the sibling, or that labelled the
// left child "right", disagrees with this and cannot disagree with it in the same direction.
//
// The expansion length is read off the provider for the same reason the implementation reads
// it: both registered suites fix Nh at 32, so a literal here would agree with a literal there
// and the pair would be wrong together.
func stExpectedNodeSecret(t *testing.T, crypto CryptoProvider, encryptionSecret []byte,
	leafCount LeafCount, node NodeIndex) []byte {
	t.Helper()
	upward, err := DirectPath(node, leafCount)
	if err != nil {
		t.Fatalf("DirectPath(%d, %d): %v", node, leafCount, err)
	}
	chain := make([]NodeIndex, 0, len(upward)+1)
	for i := len(upward) - 1; i >= 0; i-- {
		chain = append(chain, upward[i])
	}
	chain = append(chain, node)
	root, err := Root(leafCount)
	if err != nil {
		t.Fatalf("Root(%d): %v", leafCount, err)
	}
	if chain[0] != root {
		t.Fatalf("the replay starts at node %d, want the root %d", chain[0], root)
	}
	secret := append([]byte(nil), encryptionSecret...)
	for i := 0; i+1 < len(chain); i++ {
		parent, child := chain[i], chain[i+1]
		left, err := Left(parent)
		if err != nil {
			t.Fatalf("Left(%d): %v", parent, err)
		}
		right, err := Right(parent)
		if err != nil {
			t.Fatalf("Right(%d): %v", parent, err)
		}
		switch child {
		case left:
			secret = crypto.ExpandWithLabel(secret, "tree", []byte("left"), crypto.HashSize())
		case right:
			secret = crypto.ExpandWithLabel(secret, "tree", []byte("right"), crypto.HashSize())
		default:
			t.Fatalf("node %d is neither child of %d", child, parent)
		}
	}
	return secret
}

// TestNewSecretTreeRejectsBadInput asserts a wrong-length root secret, a zero leaf count and
// a leaf count that is not a power of two are refused, so a tree can never exist in a shape
// no leaf can be reached in.
//
// The non-full count is the one that is only refused because Root's error is handled rather
// than shimmed away (convention C3): a shim answering node zero for it would build a tree
// with a leaf for a root.
func TestNewSecretTreeRejectsBadInput(t *testing.T) {
	crypto := stTestCrypto(t)
	good := MustHex(t, stVectorEncryptionSecret)
	if _, err := NewSecretTree(crypto, 8, good[:31]); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("short encryption secret err = %v, want ErrSecretLength", err)
	}
	if _, err := NewSecretTree(crypto, 8, append(append([]byte(nil), good...), 0x00)); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("long encryption secret err = %v, want ErrSecretLength", err)
	}
	if _, err := NewSecretTree(crypto, 8, nil); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("nil encryption secret err = %v, want ErrSecretLength", err)
	}
	if _, err := NewSecretTree(crypto, 0, good); !errors.Is(err, ErrSecretTreeLeafOutOfRange) {
		t.Fatalf("zero leaf count err = %v, want ErrSecretTreeLeafOutOfRange", err)
	}
	// every non-power-of-two count below the sweep's ceiling, derived rather than listed.
	refused := 0
	for n := LeafCount(1); n <= 64; n++ {
		if IsFullLeafCount(n) {
			continue
		}
		_, err := NewSecretTree(crypto, n, good)
		if !errors.Is(err, ErrSecretTreeLeafOutOfRange) {
			t.Fatalf("leaf count %d err = %v, want ErrSecretTreeLeafOutOfRange", n, err)
		}
		// p3's own sentinel survives the wrap, so a caller can ask which of the two range
		// failures this was rather than only that it was one of them.
		if !errors.Is(err, ErrLeafCountNotFull) {
			t.Fatalf("leaf count %d err = %v, want it to wrap ErrLeafCountNotFull too", n, err)
		}
		refused++
	}
	// 64 counts in 1..64, of which 1, 2, 4, 8, 16, 32 and 64 are full.
	if refused != 57 {
		t.Fatalf("refused %d non-full counts in 1..64, want 57", refused)
	}
	if _, err := NewSecretTree(nil, 8, good); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("nil provider err = %v, want a refusal rather than a nil dereference", err)
	}
}

// TestSecretTreeLeafCount asserts the accessor reports what was built, at the count type
// tree math defines. A LeafIndex here would compile and be wrong.
func TestSecretTreeLeafCount(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	for _, n := range stSweptLeafCounts() {
		tree, err := NewSecretTree(crypto, n, encryptionSecret)
		if err != nil {
			t.Fatalf("NewSecretTree(%d): %v", n, err)
		}
		var got LeafCount = tree.LeafCount()
		if got != n {
			t.Fatalf("LeafCount = %d, want %d", got, n)
		}
	}
}

// TestSecretTreeSingleLeafRootIsTheLeaf asserts that in a one-leaf tree the root node and
// leaf 0 are the same node, so the encryption secret is the leaf secret with no intervening
// "tree"/"left" derivation.
func TestSecretTreeSingleLeafRootIsTheLeaf(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	tree, err := NewSecretTree(crypto, 1, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	leafSecret, err := tree.takeLeafSecret(0)
	if err != nil {
		t.Fatalf("takeLeafSecret: %v", err)
	}
	if !bytes.Equal(leafSecret, encryptionSecret) {
		t.Fatalf("leaf secret = %x, want the encryption secret %x", leafSecret, encryptionSecret)
	}
}

// TestSecretTreeDescentDerivesBothChildren asserts a descent toward leaf 0 in an eight-leaf
// tree produces exactly the RFC's "tree"/"left" and "tree"/"right" expansions, and that
// leaf 7 is still reachable afterwards — and holds the right value — because the sibling
// subtree secret was retained and was derived before its parent was erased.
func TestSecretTreeDescentDerivesBothChildren(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	tree, err := NewSecretTree(crypto, 8, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}

	nh := crypto.HashSize()
	left := crypto.ExpandWithLabel(encryptionSecret, "tree", []byte("left"), nh)
	leftLeft := crypto.ExpandWithLabel(left, "tree", []byte("left"), nh)
	wantLeaf0 := crypto.ExpandWithLabel(leftLeft, "tree", []byte("left"), nh)

	got, err := tree.takeLeafSecret(0)
	if err != nil {
		t.Fatalf("takeLeafSecret(0): %v", err)
	}
	if !bytes.Equal(got, wantLeaf0) {
		t.Fatalf("leaf 0 secret = %x, want %x", got, wantLeaf0)
	}

	// the plan's version of this test asked only that leaf 7 still answered. That passes
	// against a descent that erased the root between its two children, because the right
	// subtree would then be a consistent tree derived from zeros. What separates them is the
	// value, so the value is what is compared.
	rightRight := crypto.ExpandWithLabel(
		crypto.ExpandWithLabel(encryptionSecret, "tree", []byte("right"), nh),
		"tree", []byte("right"), nh)
	wantLeaf7 := crypto.ExpandWithLabel(rightRight, "tree", []byte("right"), nh)
	leaf7, err := tree.takeLeafSecret(7)
	if err != nil {
		t.Fatalf("leaf 7 became unreachable after descending to leaf 0: %v", err)
	}
	if !bytes.Equal(leaf7, wantLeaf7) {
		t.Fatalf("leaf 7 secret = %x, want %x", leaf7, wantLeaf7)
	}
}

// TestSecretTreeDescentReachesEveryLeafOfEveryWidth is the descent's real coverage: every
// leaf of every full tree from one to sixty-four leaves, with the leaf set taken from the
// node array's width rather than chosen, and every answer compared against an independent
// replay of the ancestry p3's DirectPath reports.
//
// The pairwise distinctness at the end is what catches a descent that reaches A leaf rather
// than THE leaf: two leaves answering the same bytes is the shape a swapped Left/Right or a
// mis-signed comparison takes when the expectation happens to be symmetric.
func TestSecretTreeDescentReachesEveryLeafOfEveryWidth(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	compared := 0
	for _, n := range stSweptLeafCounts() {
		seen := map[string]LeafIndex{}
		for _, leaf := range stLeavesOf(t, n) {
			// a fresh tree per leaf, so this measures the descent and not the order the
			// previous leaves happened to consume the path in. The order is measured
			// separately below.
			tree, err := NewSecretTree(crypto, n, encryptionSecret)
			if err != nil {
				t.Fatalf("NewSecretTree(%d): %v", n, err)
			}
			got, err := tree.takeLeafSecret(leaf)
			if err != nil {
				t.Fatalf("takeLeafSecret(%d) in a %d leaf tree: %v", leaf, n, err)
			}
			want := stExpectedNodeSecret(t, crypto, encryptionSecret, n, leaf.NodeIndex())
			if !bytes.Equal(got, want) {
				t.Fatalf("leaf %d of %d = %x, want %x", leaf, n, got, want)
			}
			if other, ok := seen[string(got)]; ok {
				t.Fatalf("leaves %d and %d of a %d leaf tree have the same secret", other, leaf, n)
			}
			seen[string(got)] = leaf
			compared++
		}
	}
	// one comparison per leaf of each swept width: 1+2+4+8+16+32+64.
	if compared != 127 {
		t.Fatalf("compared %d leaves, want 127", compared)
	}
}

// TestSecretTreeEveryLeafSurvivesEveryTakeOrder asserts that consuming the leaves of one
// tree in any order gives every leaf the same secret a fresh tree gives it.
//
// This is the assertion the deletion has to survive. An erasure one step too early, or a
// parent erased before its second child is written, leaves the tree internally consistent —
// the remaining subtree still derives cleanly from whatever it was seeded with — so the only
// thing that sees it is a comparison against a derivation that never deleted anything.
func TestSecretTreeEveryLeafSurvivesEveryTakeOrder(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	compared := 0
	for _, n := range stSweptLeafCounts() {
		leaves := stLeavesOf(t, n)
		orders := [][]LeafIndex{}
		forward := append([]LeafIndex(nil), leaves...)
		orders = append(orders, forward)
		reverse := []LeafIndex{}
		for i := len(leaves) - 1; i >= 0; i-- {
			reverse = append(reverse, leaves[i])
		}
		orders = append(orders, reverse)
		// outside in, which interleaves the two halves of the tree and so alternates which
		// subtree is being descended into on consecutive takes.
		interleaved := []LeafIndex{}
		for i, j := 0, len(leaves)-1; i <= j; i, j = i+1, j-1 {
			interleaved = append(interleaved, leaves[i])
			if i != j {
				interleaved = append(interleaved, leaves[j])
			}
		}
		orders = append(orders, interleaved)
		for _, order := range orders {
			if len(order) != len(leaves) {
				t.Fatalf("an order over a %d leaf tree has %d entries", n, len(order))
			}
			tree, err := NewSecretTree(crypto, n, encryptionSecret)
			if err != nil {
				t.Fatalf("NewSecretTree(%d): %v", n, err)
			}
			for _, leaf := range order {
				got, err := tree.takeLeafSecret(leaf)
				if err != nil {
					t.Fatalf("takeLeafSecret(%d) of %d: %v", leaf, n, err)
				}
				want := stExpectedNodeSecret(t, crypto, encryptionSecret, n, leaf.NodeIndex())
				if !bytes.Equal(got, want) {
					t.Fatalf("leaf %d of %d taken in this order = %x, want %x", leaf, n, got, want)
				}
				compared++
			}
			// the tree is empty once every leaf has been taken: nothing was retained that
			// no leaf will ever ask for again.
			if len(tree.nodes) != 0 {
				t.Fatalf("a %d leaf tree retained %d node secrets after every leaf was taken", n, len(tree.nodes))
			}
		}
	}
	if compared != 3*127 {
		t.Fatalf("compared %d takes, want %d", compared, 3*127)
	}
}

// TestSecretTreeParentSecretIsGoneOnceBothChildrenExist is the deletion, observed rather
// than assumed.
//
// What "gone" can honestly mean in go, stated because the name of this test promises more
// than the language delivers. The assertion below reads the SAME backing array the tree
// handed to zeroizeSecret, so what it observes is that the bytes at that address are zero
// and that the map no longer names them. It cannot observe a copy the runtime made — a
// growth that moved the array, a spill to a stack frame that is now garbage, a value still
// in a register — and no go program can. secret_zeroize.go says the same thing at length and
// this test claims exactly what that file claims and nothing more.
//
// The other half of the claim is that both children existed BEFORE the parent went, and that
// is what the two value comparisons hold: the retained right subtree and the left subtree's
// surviving leaf both equal a derivation from the live root secret, which they could not if
// the root had been zeroized between the two stores.
func TestSecretTreeParentSecretIsGoneOnceBothChildrenExist(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	const leafCount = LeafCount(8)
	tree, err := NewSecretTree(crypto, leafCount, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	held, ok := tree.nodes[tree.root]
	if !ok {
		t.Fatalf("the constructor did not seed the root")
	}
	if len(held) != crypto.HashSize() {
		t.Fatalf("the root secret is %d bytes, want %d", len(held), crypto.HashSize())
	}
	// the control. Without it "held is all zeros" is satisfied by a tree that never held
	// anything, and the assertion would be measuring nothing.
	if bytes.Equal(held, make([]byte, len(held))) {
		t.Fatalf("the root secret was already zero before the descent, so this test measures nothing")
	}

	if _, err := tree.takeLeafSecret(0); err != nil {
		t.Fatalf("takeLeafSecret(0): %v", err)
	}

	if _, ok := tree.nodes[tree.root]; ok {
		t.Fatalf("the root secret is still held after both of its children were derived")
	}
	if !bytes.Equal(held, make([]byte, len(held))) {
		t.Fatalf("the root's bytes are %x, want them erased in place", held)
	}

	right, err := Right(tree.root)
	if err != nil {
		t.Fatalf("Right(root): %v", err)
	}
	retained, ok := tree.nodes[right]
	if !ok {
		t.Fatalf("the root's right child was not retained, so the erasure took the subtree with it")
	}
	if want := stExpectedNodeSecret(t, crypto, encryptionSecret, leafCount, right); !bytes.Equal(retained, want) {
		t.Fatalf("the retained right child = %x, want %x — it was not derived from the live root secret", retained, want)
	}
	// the left child is on the path and was itself expanded and erased, so what stands for
	// it is a leaf underneath it.
	leaf1, err := tree.takeLeafSecret(1)
	if err != nil {
		t.Fatalf("takeLeafSecret(1): %v", err)
	}
	if want := stExpectedNodeSecret(t, crypto, encryptionSecret, leafCount, LeafIndex(1).NodeIndex()); !bytes.Equal(leaf1, want) {
		t.Fatalf("leaf 1 = %x, want %x", leaf1, want)
	}
}

// TestSecretTreeDeletedSecretsAreNotDerivableFromWhatRemains is the property the deletion
// exists for: after a leaf has been taken, no sequence of derivations over the secrets the
// tree still holds reaches any secret it destroyed.
//
// The closure is computed rather than sampled. Derivation in section 9 goes one way — a node
// secret expands into its two children and nothing expands into a parent — so the full set an
// attacker holding the tree's remaining state can compute is exactly the subtrees under the
// retained nodes, and that set is walked in full and compared against every destroyed value.
func TestSecretTreeDeletedSecretsAreNotDerivableFromWhatRemains(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	const leafCount = LeafCount(8)
	tree, err := NewSecretTree(crypto, leafCount, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	taken, err := tree.takeLeafSecret(0)
	if err != nil {
		t.Fatalf("takeLeafSecret(0): %v", err)
	}

	// everything the take was supposed to destroy: leaf 0's own node and every ancestor of
	// it, named by tree math rather than by hand.
	target := LeafIndex(0).NodeIndex()
	ancestors, err := DirectPath(target, leafCount)
	if err != nil {
		t.Fatalf("DirectPath: %v", err)
	}
	destroyed := map[string]NodeIndex{}
	for _, node := range append([]NodeIndex{target}, ancestors...) {
		destroyed[string(stExpectedNodeSecret(t, crypto, encryptionSecret, leafCount, node))] = node
	}
	if len(destroyed) != len(ancestors)+1 {
		t.Fatalf("two of the destroyed nodes have the same secret, so this test cannot tell them apart")
	}
	// the taken leaf's own secret is one of them, which is what says the map holds the real
	// values and not a parallel mistake.
	if _, ok := destroyed[string(taken)]; !ok {
		t.Fatalf("the secret takeLeafSecret returned is not the one this test derived for leaf 0")
	}

	// the closure of what remains, and its expected size derived from the levels of the
	// retained nodes: a node at level k roots a subtree of 2^(k+1)-1 nodes.
	wantReachable := 0
	for node := range tree.nodes {
		wantReachable += (1 << (node.Level() + 1)) - 1
	}
	reachable := map[string]NodeIndex{}
	frontier := []NodeIndex{}
	for node, secret := range tree.nodes {
		reachable[string(secret)] = node
		frontier = append(frontier, node)
	}
	secretOf := map[NodeIndex][]byte{}
	for node, secret := range tree.nodes {
		secretOf[node] = secret
	}
	for len(frontier) > 0 {
		node := frontier[0]
		frontier = frontier[1:]
		if node.Level() == 0 {
			continue
		}
		left, err := Left(node)
		if err != nil {
			t.Fatalf("Left(%d): %v", node, err)
		}
		right, err := Right(node)
		if err != nil {
			t.Fatalf("Right(%d): %v", node, err)
		}
		nh := crypto.HashSize()
		for child, label := range map[NodeIndex]string{left: "left", right: "right"} {
			secretOf[child] = crypto.ExpandWithLabel(secretOf[node], "tree", []byte(label), nh)
			reachable[string(secretOf[child])] = child
			frontier = append(frontier, child)
		}
	}
	if len(reachable) != wantReachable {
		t.Fatalf("the closure of the retained state has %d distinct secrets, want %d", len(reachable), wantReachable)
	}
	// 11 for an eight leaf tree with leaf 0 taken: leaf 1, the level-1 node over leaves 2
	// and 3 with its two children, and the level-2 node over leaves 4 to 7 with its six.
	if wantReachable != 11 {
		t.Fatalf("the retained state roots %d derivable secrets, want 11", wantReachable)
	}
	for secret, node := range reachable {
		if gone, ok := destroyed[secret]; ok {
			t.Fatalf("node %d's secret is still derivable, as node %d, from what the tree retained", gone, node)
		}
	}
}

// TestSecretTreeLeafSecretIsTakenOnce asserts the second call for one leaf fails, in every
// swept width and for every leaf of it.
//
// Retaining it would keep a secret alive that has already produced both ratchet roots, which
// is exactly the forward secrecy RFC 9420 section 9 is for. The sweep is what stops this
// holding only for the first leaf of the first tree: an implementation that deleted the leaf
// but kept an ancestor would answer the second call from the ancestor, and only a leaf whose
// ancestors are still held shows it.
func TestSecretTreeLeafSecretIsTakenOnce(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	refused := 0
	for _, n := range stSweptLeafCounts() {
		for _, leaf := range stLeavesOf(t, n) {
			tree, err := NewSecretTree(crypto, n, encryptionSecret)
			if err != nil {
				t.Fatalf("NewSecretTree(%d): %v", n, err)
			}
			if _, err := tree.takeLeafSecret(leaf); err != nil {
				t.Fatalf("takeLeafSecret(%d): %v", leaf, err)
			}
			if _, err := tree.takeLeafSecret(leaf); !errors.Is(err, ErrSecretTreeConsumed) {
				t.Fatalf("second take of leaf %d of %d err = %v, want ErrSecretTreeConsumed", leaf, n, err)
			}
			refused++
		}
	}
	if refused != 127 {
		t.Fatalf("refused %d second takes, want 127", refused)
	}
}

// TestSecretTreeRejectsOutOfRangeLeaf asserts a leaf beyond the tree is a typed error and not
// an index panic on a message from a peer.
//
// The last two are the ones a smaller test misses. LeafIndex.NodeIndex is total and wraps at
// 2^31, so leaf 2^31 sits at node 0 — indistinguishable from leaf 0 to anything that range
// checks the NODE and not the LEAF. A tree that accepted it would hand out leaf 0's secret to
// a sender claiming an index no tree can hold.
func TestSecretTreeRejectsOutOfRangeLeaf(t *testing.T) {
	crypto := stTestCrypto(t)
	tree, err := NewSecretTree(crypto, 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	for _, leaf := range []LeafIndex{8, 9, 1 << 20, 1 << 31, (1 << 31) + 4, 0xffffffff} {
		if _, err := tree.takeLeafSecret(leaf); !errors.Is(err, ErrSecretTreeLeafOutOfRange) {
			t.Fatalf("leaf %d err = %v, want ErrSecretTreeLeafOutOfRange", leaf, err)
		}
	}
	// and the refusals cost nothing: leaf 0 is still there afterwards, so an out of range
	// index from a peer cannot be used to consume a leaf it does not own.
	if _, err := tree.takeLeafSecret(0); err != nil {
		t.Fatalf("leaf 0 after six refused indices: %v", err)
	}
}

// TestSecretTreeReadsItsSecretWidthOffTheProviderItWasHanded is the differential the registry
// cannot supply.
//
// Both registered suites fix Nh at 32, and 32 is also Nk on the chacha suite, the length of
// every vector in this tree, and the literal a body would have written down — so inside the
// registry a read of HashSize() and a written 32 are the same number and no test here can
// separate them. This provider is assembled instead, at the Nh 48 five registered suites
// carry, and every other length it reports differs from 48, so each substitution is a
// different number rather than the same one.
func TestSecretTreeReadsItsSecretWidthOffTheProviderItWasHanded(t *testing.T) {
	crypto := &suiteCryptoProvider{params: &labelKatSyntheticParams, random: rand.Reader}
	nh := crypto.HashSize()
	if nh != labelKatSyntheticParams.Nh {
		t.Fatalf("the fixture reports Nh %d, want %d", nh, labelKatSyntheticParams.Nh)
	}
	// the substitutions this provider has to be able to see. A length here equal to Nh would
	// leave every assertion below satisfied by the literal it exists to catch.
	for _, other := range []struct {
		name  string
		value int
	}{
		{name: "the registry's own hash size", value: 32},
		{name: "this suite's Nk", value: crypto.KeySize()},
		{name: "this suite's Nn", value: crypto.NonceSize()},
		{name: "this suite's Nt", value: labelKatSyntheticParams.Nt},
	} {
		if other.value == nh {
			t.Fatalf("%s is %d, the same as this fixture's Nh, so this differential is blind to it",
				other.name, other.value)
		}
	}

	encryptionSecret := bytes.Repeat([]byte{0x5a}, nh)
	// the length both registered suites fix is refused here, which is the length half of the
	// same claim: the constructor sizes its input by the provider and not by a literal.
	if _, err := NewSecretTree(crypto, 8, encryptionSecret[:32]); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("a 32 byte secret for an Nh 48 suite err = %v, want ErrSecretLength", err)
	}
	tree, err := NewSecretTree(crypto, 8, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	got, err := tree.takeLeafSecret(5)
	if err != nil {
		t.Fatalf("takeLeafSecret(5): %v", err)
	}
	if len(got) != nh {
		t.Fatalf("leaf secret is %d bytes for a suite whose Nh is %d", len(got), nh)
	}
	// and the length moved inside the preimage with it, not only in the size of the answer:
	// KDFLabel carries the length, so a body expanding to 32 and a body expanding to 48
	// disagree in every byte rather than in a prefix.
	want := stExpectedNodeSecret(t, crypto, encryptionSecret, 8, LeafIndex(5).NodeIndex())
	if !bytes.Equal(got, want) {
		t.Fatalf("leaf 5 = %x, want %x", got, want)
	}
	atThirtyTwo := crypto.ExpandWithLabel(encryptionSecret, "tree", []byte("right"), 32)
	atNh := crypto.ExpandWithLabel(encryptionSecret, "tree", []byte("right"), nh)
	if bytes.Equal(atThirtyTwo, atNh[:32]) {
		t.Fatalf("expanding to 32 and to %d agree on their first 32 bytes, so a hardcoded length "+
			"would be a truncation this test could not see", nh)
	}
	// worth recording, because it is why the assertion above is a prefix comparison and not
	// a whole tree derivation: with a hardcoded 32 the SECOND expansion of this suite is
	// handed a 32 byte pseudorandom key for a 48 byte hash, which the provider refuses
	// outright. So on this fixture a hardcoded width does not produce a wrong secret, it
	// produces no secret at all — a louder failure than the one being guarded against, but
	// only on a suite whose Nh exceeds 32, which is exactly what the registry does not have.

}

// TestSecretTreeDoesNotEraseTheCallersEncryptionSecret asserts the constructor copies what it
// is handed.
//
// The tree erases the secrets it holds, and the encryption secret it is seeded with is one of
// the nine the key schedule owns and zeroizes on its own schedule. Seeding the root with the
// caller's slice would mean building a secret tree silently destroyed the epoch's
// encryption_secret, and every existing test would still pass because the tree itself would
// be correct.
func TestSecretTreeDoesNotEraseTheCallersEncryptionSecret(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	original := append([]byte(nil), encryptionSecret...)
	tree, err := NewSecretTree(crypto, 4, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	if _, err := tree.takeLeafSecret(0); err != nil {
		t.Fatalf("takeLeafSecret: %v", err)
	}
	if !bytes.Equal(encryptionSecret, original) {
		t.Fatalf("the caller's encryption secret is now %x, want it untouched at %x", encryptionSecret, original)
	}
	// and the copy goes the other way too: mutating the caller's slice after construction
	// does not move the tree, so the tree is not aliasing it.
	fresh, err := NewSecretTree(crypto, 4, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	for i := range encryptionSecret {
		encryptionSecret[i] ^= 0xff
	}
	got, err := fresh.takeLeafSecret(2)
	if err != nil {
		t.Fatalf("takeLeafSecret: %v", err)
	}
	want := stExpectedNodeSecret(t, crypto, original, 4, LeafIndex(2).NodeIndex())
	if !bytes.Equal(got, want) {
		t.Fatalf("leaf 2 = %x, want %x — the tree aliased the caller's slice", got, want)
	}
}
