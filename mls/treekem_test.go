// Tests for the path secret ladder of RFC 9420 section 7.4, the node key each rung derives, and
// the private half of the tree one member holds.
//
// Three properties here are not round trip properties, and they are why this file is longer than
// the code it holds.
//
// The ASYMMETRY. A member handed the path secret of a node can derive every node above it and
// none below it, and that is the whole security argument for sealing one secret to a whole
// subtree. A ladder that ran downward derives, matches the tree, and round trips exactly as the
// right one does -- so the negative direction is asserted here as loudly as the positive: a
// member holding rung k must reach every node above and must report that it holds nothing at any
// node below.
//
// The INTERMEDIATE SECRET. node_secret = DeriveSecret(path_secret, "node") sits between the rung
// and the KEM, and handing the path secret straight to DeriveKeyPair produces a key pair that is
// deterministic, that differs at every rung, and that every member agrees on -- every property a
// determinism or distinctness test can see, and the wrong key at every node in the group. Only a
// comparison against a derivation this package did not make separates the two, which is what the
// published TreeKEM corpus is for below, and what
// TestTheNodeKeyPairIsTheKemKeyOfTheNodeSecretAndNotOfThePathSecret states from the RFC's own
// words.
//
// And CONSISTENT's second clause. A state whose path secrets belong to the previous epoch
// derives private keys nobody's public half matches, and the symptom arrives one commit later as
// a decryption failure against a perfectly well formed commit. The clause that catches it is the
// KEY comparison and not the blank-node check in front of it, so there is a case here whose node
// is present and carries the key of a DIFFERENT secret -- without it, a Consistent that checked
// only for a blank node passes every test the shape of this file otherwise suggests.
package mls

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// the ladder
// ---------------------------------------------------------------------------

// TestDerivePathSecretsIsALadder is the plan's own golden: each rung is DeriveSecret of the one
// below it under the label "path", the first rung is the caller's own secret, and the answer is
// one longer than the count asked for because section 8.1 makes the rung past the root the
// commit secret.
func TestDerivePathSecretsIsALadder(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	initial := crypto.Random(crypto.HashSize())
	secrets := DerivePathSecrets(crypto, initial, 3)
	if len(secrets) != 4 {
		t.Fatalf("len = %d, want count+1", len(secrets))
	}
	if !bytes.Equal(secrets[0], initial) {
		t.Fatalf("path_secret[0] is not the initial secret")
	}
	for i := 1; i < len(secrets); i++ {
		want := crypto.DeriveSecret(secrets[i-1], "path")
		if !bytes.Equal(secrets[i], want) {
			t.Fatalf("path_secret[%d] is not DeriveSecret(path_secret[%d], \"path\")", i, i-1)
		}
		if bytes.Equal(secrets[i], secrets[i-1]) {
			t.Fatalf("path_secret[%d] equals its predecessor", i)
		}
	}
}

// TestDerivePathSecretsRunsUpwardAndNeverBackDown is the direction the golden above cannot see.
//
// The golden compares each rung against DeriveSecret of the one BELOW it, which a ladder built
// in either order satisfies as long as the sequence is consistent with itself: reverse the
// answer and rung 0 stops being the initial secret, which the golden does catch -- but a ladder
// that ran the other way while still reporting the initial secret first would not be a sequence
// this package can produce and is not what this test is for.
//
// What is asserted here is the ONE WAY property as a value property: from any rung, climbing
// reaches exactly the rungs above it and never reproduces a rung below it. That is what makes it
// safe to hand a subtree the secret of its own node -- the members under it learn the path from
// there up and nothing about the sender's leaf -- and it is checked over every starting rung
// rather than over one somebody picked.
func TestDerivePathSecretsRunsUpwardAndNeverBackDown(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	full := DerivePathSecrets(crypto, crypto.Random(crypto.HashSize()), 6)
	climbed := 0
	for from := range full {
		above := DerivePathSecrets(crypto, full[from], len(full)-1-from)
		if len(above) != len(full)-from {
			t.Fatalf("climbing from rung %d of %d gave %d rungs, want %d",
				from, len(full), len(above), len(full)-from)
		}
		for j, rung := range above {
			if !bytes.Equal(rung, full[from+j]) {
				t.Fatalf("climbing from rung %d reached a different rung at %d than the whole ladder holds at %d",
					from, j, from+j)
			}
			climbed += 1
			// and the negative: nothing reachable from rung `from` is a rung below it.
			for below := 0; below < from; below++ {
				if bytes.Equal(rung, full[below]) {
					t.Fatalf("climbing from rung %d reproduced rung %d, which is below it; the ladder runs both ways",
						from, below)
				}
			}
		}
	}
	if climbed == 0 {
		t.Fatal("the sweep climbed nothing")
	}
}

// TestTheNodeKeyPairIsTheKemKeyOfTheNodeSecretAndNotOfThePathSecret pins the one construction in
// this file that a self-consistency test cannot see.
//
// RFC 9420 section 7.4 writes node_secret = DeriveSecret(path_secret, "node") and derives the
// node's key pair from THAT. Every observable property a round trip can reach -- determinism,
// one key pair per rung, both members of the group agreeing -- holds just as well for a body
// that handed the path secret straight to the KEM, and the group it produces is internally
// consistent and interoperates with nobody. So the RFC's construction is transcribed here, and
// the three near misses are named and required to differ: the path secret itself, the rung above
// it, and the node secret of the rung above.
func TestTheNodeKeyPairIsTheKemKeyOfTheNodeSecretAndNotOfThePathSecret(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	pathSecret := bytes.Repeat([]byte{0x2b}, crypto.HashSize())
	gotPriv, gotPub, err := DeriveNodeKeyPair(crypto, pathSecret)
	if err != nil {
		t.Fatalf("DeriveNodeKeyPair: %v", err)
	}
	wantPriv, wantPub, err := crypto.DeriveKeyPair(crypto.DeriveSecret(pathSecret, "node"))
	if err != nil {
		t.Fatalf("the RFC's own construction: %v", err)
	}
	if !bytes.Equal(gotPriv, wantPriv) || !bytes.Equal(gotPub, wantPub) {
		t.Fatalf("DeriveNodeKeyPair = (%x, %x), and KEM.DeriveKeyPair(DeriveSecret(path_secret, \"node\")) = (%x, %x)",
			gotPriv, gotPub, wantPriv, wantPub)
	}
	for _, near := range []struct {
		name string
		ikm  []byte
	}{
		{name: "the path secret handed straight to the KEM", ikm: pathSecret},
		{name: "the rung above", ikm: crypto.DeriveSecret(pathSecret, "path")},
		{name: "the node secret of the rung above",
			ikm: crypto.DeriveSecret(crypto.DeriveSecret(pathSecret, "path"), "node")},
	} {
		_, pub, err := crypto.DeriveKeyPair(near.ikm)
		if err != nil {
			t.Fatalf("%s: %v", near.name, err)
		}
		if bytes.Equal(gotPub, pub) {
			t.Fatalf("the node key pair is indistinguishable from %s", near.name)
		}
	}
}

// TestDeriveNodeKeyPairIsDeterministicAndDistinctFromThePathSecret is the plan's golden. It is
// kept for the determinism half -- every member that learns a rung must derive the identical
// node key or nobody decrypts -- and it is NOT what holds the construction: see the test above,
// which is the one a key pair derived from the wrong secret fails.
func TestDeriveNodeKeyPairIsDeterministicAndDistinctFromThePathSecret(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	pathSecret := crypto.Random(crypto.HashSize())
	priv1, pub1, err := DeriveNodeKeyPair(crypto, pathSecret)
	if err != nil {
		t.Fatalf("DeriveNodeKeyPair: %v", err)
	}
	priv2, pub2, err := DeriveNodeKeyPair(crypto, pathSecret)
	if err != nil {
		t.Fatalf("DeriveNodeKeyPair: %v", err)
	}
	if !bytes.Equal(pub1, pub2) || !bytes.Equal(priv1, priv2) {
		t.Fatalf("DeriveNodeKeyPair is not deterministic")
	}
	_, otherPub, err := DeriveNodeKeyPair(crypto, crypto.DeriveSecret(pathSecret, "path"))
	if err != nil {
		t.Fatalf("DeriveNodeKeyPair: %v", err)
	}
	if bytes.Equal(pub1, otherPub) {
		t.Fatalf("two rungs of the ladder derive the same key pair")
	}
}

// ---------------------------------------------------------------------------
// the private state over a real tree
// ---------------------------------------------------------------------------

// installPathSecrets keys every node of a leaf's filtered direct path from one initial secret and
// answers the path together with the rungs it installed.
//
// The tree's public halves are written from the SAME ladder the private state below is built
// from, which is what a commit does: the sender derives the ladder, writes the public key of each
// rung into the tree, and seals each rung to the copath. Nothing here is task 18's UpdatePath --
// there is no encryption and no signature -- it is the minimum shape in which "the derived key
// pair matches the public key already in the tree" is a question that can be asked at all.
func installPathSecrets(t *testing.T, crypto CryptoProvider, tree *RatchetTree,
	sender LeafIndex, initial []byte) ([]NodeIndex, [][]byte) {
	t.Helper()
	path, err := tree.FilteredDirectPath(sender)
	if err != nil {
		t.Fatalf("FilteredDirectPath(%d): %v", sender, err)
	}
	if len(path) < 2 {
		t.Fatalf("leaf %d has a filtered direct path of %v, and a path with fewer than two nodes cannot separate above from below",
			sender, path)
	}
	secrets := DerivePathSecrets(crypto, initial, len(path))
	for at, node := range path {
		_, pub, err := DeriveNodeKeyPair(crypto, secrets[at])
		if err != nil {
			t.Fatalf("DeriveNodeKeyPair for node %d: %v", node, err)
		}
		if err := tree.SetParent(node, &ParentNode{EncryptionKey: pub}); err != nil {
			t.Fatalf("SetParent(%d): %v", node, err)
		}
	}
	return path, secrets
}

// TestAPathSecretReachesEveryNodeAboveItAndNoneBelow is the asymmetry, over a real tree.
//
// A member that learns the rung at path[k] climbs from there and must end up holding exactly the
// nodes at and above k. Three things are asserted at once, and each catches something the others
// do not:
//
//   - every node from k up is available, and the key it derives is the one the TREE carries at
//     that node. A private state that derives keys nobody's public half matches is a member who
//     cannot decrypt anything, and without this it is caught at commit time in task 22 rather
//     than here.
//   - every node below k reports that no key is available. This is the direction that matters:
//     a state that answered a key for a node below would be a member reading the part of the path
//     it was never sealed, and every one of those keys derives cleanly and looks exactly right.
//   - Consistent agrees, which is the same statement made through the entry point the commit path
//     actually calls.
func TestAPathSecretReachesEveryNodeAboveItAndNoneBelow(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	tree, members := newTestTree(t, crypto, 8)
	sender := members[0].LeafIndex
	path, secrets := installPathSecrets(t, crypto, tree, sender,
		crypto.Random(crypto.HashSize()))
	// the member that receives the rungs is a different one, at a leaf that is not on the
	// path and whose own node index is none of the path nodes.
	receiver := members[5]
	above, below := 0, 0
	for from := range path {
		state := NewTreeKEMPrivate(receiver.LeafIndex, receiver.EncryptionPriv)
		for at, rung := range DerivePathSecrets(crypto, secrets[from], len(path)-1-from) {
			state.PathSecrets[path[from+at]] = rung
		}
		if err := state.Consistent(crypto, tree); err != nil {
			t.Fatalf("a state built from the rung at path[%d] = node %d disagrees with the tree it was derived into: %v",
				from, path[from], err)
		}
		for at, node := range path {
			key, held, err := state.NodePrivateKey(crypto, node)
			if err != nil {
				t.Fatalf("NodePrivateKey(%d): %v", node, err)
			}
			if at < from {
				if held {
					t.Fatalf("a member holding only the rung at path[%d] answered a private key for node %d, which is BELOW it; the ladder runs downward",
						from, node)
				}
				below += 1
				continue
			}
			if !held {
				t.Fatalf("a member holding the rung at path[%d] cannot derive node %d, which is at or above it",
					from, node)
			}
			_, pub, err := DeriveNodeKeyPair(crypto, state.PathSecrets[node])
			if err != nil {
				t.Fatalf("DeriveNodeKeyPair at node %d: %v", node, err)
			}
			parent := tree.ParentAt(node)
			if parent == nil {
				t.Fatalf("node %d of the path is blank in the tree the rungs were installed into", node)
			}
			if !bytes.Equal(pub, parent.EncryptionKey) {
				t.Fatalf("the key derived at node %d is %x and the tree carries %x", node, pub, parent.EncryptionKey)
			}
			if len(key) == 0 {
				t.Fatalf("NodePrivateKey(%d) answered an empty key", node)
			}
			above += 1
		}
	}
	if above == 0 || below == 0 {
		t.Fatalf("the sweep reached %d nodes at or above the rung it started from and %d below it; with either at zero this test holds one direction rather than the two it states",
			above, below)
	}
	t.Logf("%d nodes derivable from a rung at or below them, %d refused from a rung above them", above, below)
}

// TestConsistentRefusesAPathSecretThatDerivesTheWrongKey is the clause the plan's own test cannot
// see.
//
// That test drives Consistent against a BLANK node and then against the right key, so a body
// whose only check was "is this node present" passes it -- and that body accepts every private
// state a previous epoch left behind, which is exactly the drift Consistent exists to catch. The
// table below separates the two: the node is present in every row, and only its contents move.
func TestConsistentRefusesAPathSecretThatDerivesTheWrongKey(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	build := func(t *testing.T) (*RatchetTree, *TreeKEMPrivate, []NodeIndex, [][]byte) {
		t.Helper()
		tree, members := newTestTree(t, crypto, 8)
		path, secrets := installPathSecrets(t, crypto, tree, members[0].LeafIndex,
			bytes.Repeat([]byte{0x3c}, crypto.HashSize()))
		state := NewTreeKEMPrivate(members[5].LeafIndex, members[5].EncryptionPriv)
		for at, node := range path {
			state.PathSecrets[node] = secrets[at]
		}
		return tree, state, path, secrets
	}
	// the control: the untouched pair agrees, or every refusal below is one that was already
	// there.
	tree, state, _, _ := build(t)
	if err := state.Consistent(crypto, tree); err != nil {
		t.Fatalf("the fixture does not agree with itself, so nothing below is about the case it names: %v", err)
	}
	for _, row := range []struct {
		name   string
		breaks func(t *testing.T, tree *RatchetTree, state *TreeKEMPrivate, path []NodeIndex, secrets [][]byte)
	}{
		{name: "a rung that derives some other key", breaks: func(t *testing.T, tree *RatchetTree, state *TreeKEMPrivate, path []NodeIndex, secrets [][]byte) {
			state.PathSecrets[path[0]] = crypto.DeriveSecret(secrets[0], "path")
		}},
		{name: "a rung flipped in one octet", breaks: func(t *testing.T, tree *RatchetTree, state *TreeKEMPrivate, path []NodeIndex, secrets [][]byte) {
			flipped := bytes.Clone(secrets[len(path)-1])
			flipped[0] ^= 0x01
			state.PathSecrets[path[len(path)-1]] = flipped
		}},
		{name: "the tree re-keyed under the state", breaks: func(t *testing.T, tree *RatchetTree, state *TreeKEMPrivate, path []NodeIndex, secrets [][]byte) {
			_, pub, err := DeriveNodeKeyPair(crypto, bytes.Repeat([]byte{0x4d}, crypto.HashSize()))
			if err != nil {
				t.Fatalf("DeriveNodeKeyPair: %v", err)
			}
			if err := tree.SetParent(path[1], &ParentNode{EncryptionKey: pub}); err != nil {
				t.Fatalf("SetParent(%d): %v", path[1], err)
			}
		}},
		{name: "a node the tree has blanked", breaks: func(t *testing.T, tree *RatchetTree, state *TreeKEMPrivate, path []NodeIndex, secrets [][]byte) {
			if err := tree.Blank(path[0]); err != nil {
				t.Fatalf("Blank(%d): %v", path[0], err)
			}
		}},
		{name: "a state whose leaf the tree does not have", breaks: func(t *testing.T, tree *RatchetTree, state *TreeKEMPrivate, path []NodeIndex, secrets [][]byte) {
			if err := tree.Blank(state.LeafIndex.NodeIndex()); err != nil {
				t.Fatalf("Blank(%d): %v", state.LeafIndex.NodeIndex(), err)
			}
		}},
		{name: "a rung held at a node that is not on the path at all", breaks: func(t *testing.T, tree *RatchetTree, state *TreeKEMPrivate, path []NodeIndex, secrets [][]byte) {
			// node 5 is a parent of this tree that no rung was installed at, so it is
			// blank; holding a secret for it is a state from a tree of another shape.
			state.PathSecrets[NodeIndex(5)] = secrets[0]
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			tree, state, path, secrets := build(t)
			row.breaks(t, tree, state, path, secrets)
			if err := state.Consistent(crypto, tree); !errors.Is(err, ErrPathSecretMismatch) {
				t.Fatalf("Consistent over %s gave err = %v, want ErrPathSecretMismatch", row.name, err)
			}
		})
	}
	// and a state holding NO rungs at all over a tree that has its leaf is consistent: the
	// refusals above must be about the secrets and not about having any.
	empty := NewTreeKEMPrivate(state.LeafIndex, state.EncryptionPriv)
	if err := empty.Consistent(crypto, tree); err != nil {
		t.Fatalf("a member holding no path secret at all was refused: %v", err)
	}
}

// TestTreeKEMPrivateNodePrivateKeyAndConsistency is the plan's golden for the container.
func TestTreeKEMPrivateNodePrivateKeyAndConsistency(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, members := newTestTree(t, crypto, 4)
	priv := NewTreeKEMPrivate(members[0].LeafIndex, members[0].EncryptionPriv)

	// the leaf's own key is always available.
	got, ok, err := priv.NodePrivateKey(crypto, members[0].LeafIndex.NodeIndex())
	if err != nil || !ok {
		t.Fatalf("NodePrivateKey(own leaf) = (_, %v, %v)", ok, err)
	}
	if !bytes.Equal(got, members[0].EncryptionPriv) {
		t.Fatalf("NodePrivateKey(own leaf) is not the leaf private key")
	}
	if _, ok, _ := priv.NodePrivateKey(crypto, NodeIndex(1)); ok {
		t.Fatalf("NodePrivateKey(1) is available with no path secret held")
	}

	// holding a path secret for node 1 makes node 1's key available, and Consistent
	// agrees with the tree only when the tree carries the derived public key.
	pathSecret := crypto.Random(crypto.HashSize())
	_, pub, err := DeriveNodeKeyPair(crypto, pathSecret)
	if err != nil {
		t.Fatalf("DeriveNodeKeyPair: %v", err)
	}
	priv.PathSecrets[NodeIndex(1)] = pathSecret
	if err := priv.Consistent(crypto, tree); !errors.Is(err, ErrPathSecretMismatch) {
		t.Fatalf("Consistent with a blank node 1 err = %v, want ErrPathSecretMismatch", err)
	}
	if err := tree.SetParent(NodeIndex(1), &ParentNode{EncryptionKey: pub}); err != nil {
		t.Fatalf("SetParent: %v", err)
	}
	if err := priv.Consistent(crypto, tree); err != nil {
		t.Fatalf("Consistent: %v", err)
	}
	derived, ok, err := priv.NodePrivateKey(crypto, NodeIndex(1))
	if err != nil || !ok {
		t.Fatalf("NodePrivateKey(1) with a path secret held = (_, %v, %v)", ok, err)
	}
	wantPriv, _, err := DeriveNodeKeyPair(crypto, pathSecret)
	if err != nil {
		t.Fatalf("DeriveNodeKeyPair: %v", err)
	}
	if !bytes.Equal(derived, wantPriv) {
		t.Fatalf("NodePrivateKey(1) is not the private half the rung derives")
	}
	clone := priv.Clone()
	clone.PathSecrets[NodeIndex(1)][0] ^= 0xFF
	if bytes.Equal(clone.PathSecrets[NodeIndex(1)], priv.PathSecrets[NodeIndex(1)]) {
		t.Fatalf("Clone shares path secret backing arrays")
	}
}

// TestTheStateSharesNoStorageWithItsCallerOrItsClone is the aliasing half, over every door into
// the state rather than the one the plan's golden happens to open.
//
// A rejected commit is the case. The caller works on a clone, the commit loses a race and is
// dropped, and a clone that shared one array with its parent has already written through to the
// state the group is still running on -- with every key still deriving and nothing to point at.
// The plan's golden holds the path secret map; the leaf key and the map's own membership are the
// other two, and neither is visible from it.
func TestTheStateSharesNoStorageWithItsCallerOrItsClone(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	callersLeafKey := bytes.Repeat([]byte{0x11}, 32)
	callersRung := bytes.Repeat([]byte{0x22}, crypto.HashSize())
	state := NewTreeKEMPrivate(LeafIndex(3), HpkePrivateKey(callersLeafKey))
	state.PathSecrets[NodeIndex(7)] = bytes.Clone(callersRung)

	// the constructor's own copy, which is what keeps a member decrypting after its caller
	// reuses the buffer the key arrived in.
	callersLeafKey[0] ^= 0xFF
	if bytes.Equal(state.EncryptionPriv, callersLeafKey) {
		t.Fatal("NewTreeKEMPrivate kept the caller's leaf key array")
	}
	callersLeafKey[0] ^= 0xFF

	clone := state.Clone()
	clone.EncryptionPriv[0] ^= 0xFF
	if bytes.Equal(clone.EncryptionPriv, state.EncryptionPriv) {
		t.Fatal("Clone shares the leaf private key array")
	}
	clone.EncryptionPriv[0] ^= 0xFF
	clone.PathSecrets[NodeIndex(7)][0] ^= 0xFF
	if bytes.Equal(clone.PathSecrets[NodeIndex(7)], state.PathSecrets[NodeIndex(7)]) {
		t.Fatal("Clone shares path secret backing arrays")
	}
	// and the MAP itself, which is the half neither byte comparison reaches: a clone sharing
	// the map holds every rung the abandoned commit added.
	clone.PathSecrets[NodeIndex(9)] = bytes.Repeat([]byte{0x33}, crypto.HashSize())
	if _, leaked := state.PathSecrets[NodeIndex(9)]; leaked {
		t.Fatal("a rung added to the clone appeared in the state it was cloned from")
	}
	if state.LeafIndex != clone.LeafIndex {
		t.Fatalf("Clone answered leaf %d for a state at leaf %d", clone.LeafIndex, state.LeafIndex)
	}
}

// ---------------------------------------------------------------------------
// the published corpus
// ---------------------------------------------------------------------------

// treekemPrivateVector is the part of one entry of treekem.json this file reads: the ratchet
// tree of an epoch and the private state each member of it holds.
//
// The update_paths half is deliberately not read here. Verifying one is tasks 18 through 22's
// and registering family 11 is theirs to do; what this file can answer for is the part of that
// corpus its own two constructions decide, which is whether a published path secret derives the
// public key the published tree carries at its node.
type treekemPrivateVector struct {
	CipherSuite   uint16                     `json:"cipher_suite"`
	RatchetTree   string                     `json:"ratchet_tree"`
	LeavesPrivate []treekemLeafPrivateVector `json:"leaves_private"`
}

type treekemLeafPrivateVector struct {
	Index          uint32                    `json:"index"`
	EncryptionPriv string                    `json:"encryption_priv"`
	PathSecrets    []treekemPathSecretVector `json:"path_secrets"`
}

type treekemPathSecretVector struct {
	Node       uint32 `json:"node"`
	PathSecret string `json:"path_secret"`
}

// Transcriptions of what testdata/vectors/treekem.json holds at the pinned mlswg commit. A
// decoder that quietly stopped early, a filter that matched nothing, and a sweep that read a
// field that is not there all report exactly what a complete run reports without these.
const treekemEntryCount = 77
const treekemLeafPrivateCount = 124
const treekemPathSecretCount = 310

// TestEveryPublishedPathSecretDerivesTheNodeKeyItsRatchetTreeCarries is the only oracle in this
// file that is independent of this repository.
//
// Everything else here compares two derivations this package makes, or compares one against the
// RFC transcribed by the same reader who wrote the code. Neither separates a node key derived
// from the wrong secret: the whole group agrees with itself, every rung derives, every state is
// consistent, and the implementation interoperates with nobody. The working group's own
// implementations produced these path secrets and these trees, so a node_secret step that was
// skipped, labelled differently, or applied twice fails here and nowhere else in this package.
//
// The negative control is what makes the green run mean something. Every published case agrees
// with this implementation, so a Consistent that checked everything and one that returned nil
// produce identical runs over the corpus; the only way to separate them is to hand it an answer
// that is wrong on purpose and require the refusal.
func TestEveryPublishedPathSecretDerivesTheNodeKeyItsRatchetTreeCarries(t *testing.T) {
	entries := LoadVectorFile(t, "treekem.json")
	if len(entries) != treekemEntryCount {
		t.Fatalf("treekem.json holds %d entries, want %d", len(entries), treekemEntryCount)
	}
	matched, declined, leaves, secrets, deep := 0, 0, 0, 0, 0
	for at, raw := range entries {
		var vector treekemPrivateVector
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("entry %d: %v", at, err)
		}
		suite, ok := implementedSuite(vector.CipherSuite)
		if !ok {
			declined += 1
			continue
		}
		matched += 1
		crypto := mustProvider(t, suite)
		tree, err := UnmarshalRatchetTree(MustHex(t, vector.RatchetTree))
		if err != nil {
			t.Fatalf("entry %d: UnmarshalRatchetTree: %v", at, err)
		}
		for _, published := range vector.LeavesPrivate {
			leaves += 1
			state := NewTreeKEMPrivate(LeafIndex(published.Index),
				HpkePrivateKey(MustHex(t, published.EncryptionPriv)))
			for _, rung := range published.PathSecrets {
				state.PathSecrets[NodeIndex(rung.Node)] = MustHex(t, rung.PathSecret)
				secrets += 1
			}
			if len(published.PathSecrets) > 1 {
				deep += 1
			}
			if err := state.Consistent(crypto, tree); err != nil {
				t.Errorf("entry %d, leaf %d: the published path secrets do not derive the published tree's node keys: %v",
					at, published.Index, err)
				continue
			}
			// the control, per case rather than once: one octet of one published rung
			// flipped, and the refusal is required. A comparator that answered nil
			// unconditionally satisfies every line above it.
			if len(published.PathSecrets) == 0 {
				continue
			}
			wrong := state.Clone()
			node := NodeIndex(published.PathSecrets[0].Node)
			wrong.PathSecrets[node][0] ^= 0x01
			if err := wrong.Consistent(crypto, tree); !errors.Is(err, ErrPathSecretMismatch) {
				t.Fatalf("entry %d, leaf %d: one octet of the rung at node %d flipped gave err = %v, want ErrPathSecretMismatch",
					at, published.Index, node, err)
			}
		}
	}
	if matched+declined != len(entries) {
		t.Fatalf("%d entries matched and %d were declined, and the file holds %d",
			matched, declined, len(entries))
	}
	if matched == 0 || leaves != treekemLeafPrivateCount || secrets != treekemPathSecretCount {
		t.Fatalf("the run read %d entries at a registered suite, %d private leaf states and %d path secrets; want %d states and %d secrets",
			matched, leaves, secrets, treekemLeafPrivateCount, treekemPathSecretCount)
	}
	if deep == 0 {
		t.Fatal("no published private state held more than one path secret, so the loop inside Consistent ran at most once in every case")
	}
	t.Logf("%d of %d entries at a registered suite: %d private leaf states, %d path secrets, %d of the states holding more than one",
		matched, len(entries), leaves, secrets, deep)
}
