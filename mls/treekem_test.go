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
	"fmt"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
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
//
// SWEPT rather than sampled, and the negative direction is why. One tree, one sender and one
// receiver made three observations of the direction that carries the whole security argument --
// a member holding rung k must be refused every node below k -- and three observations of a
// refusal is three chances for a body that refuses for the wrong reason to look right. The sweep
// below runs every width whose filtered path is long enough to have an above and a below at all,
// and every member of each as the sender, with the receiver derived from the tree rather than
// chosen.
//
// A sender whose filtered path holds fewer than two nodes is SKIPPED rather than excluded by a
// width, and the skips are counted. Which senders those are is a property of the filter -- in a
// three member tree leaf 2's step past the blank leaf 3 is filtered away and its path is one node
// -- so a width chosen to avoid them is a width that stops avoiding them the day the filter
// changes. There is no node below a single rung, and a run that was all one node paths would
// report a zero in the negative direction as a pass, which is what the counters below refuse.
func TestAPathSecretReachesEveryNodeAboveItAndNoneBelow(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	above, below, senders, ladders, tooShort := 0, 0, 0, 0, 0
	for width := uint32(2); width <= 8; width += 1 {
		for at := uint32(0); at < width; at += 1 {
			tree, members := newTestTree(t, crypto, width)
			sender := members[at].LeafIndex
			where := fmt.Sprintf("%d members, sender %d", width, sender)
			filtered, err := tree.FilteredDirectPath(sender)
			if err != nil {
				t.Fatalf("%s: FilteredDirectPath: %v", where, err)
			}
			if len(filtered) < 2 {
				tooShort += 1
				continue
			}
			path, secrets := installPathSecrets(t, crypto, tree, sender,
				crypto.Random(crypto.HashSize()))
			senders += 1
			// the member that receives the rungs is a different one, derived from the tree
			// rather than chosen; its own node index is none of the path nodes because every
			// path node is a parent.
			receiver := members[(at+1)%width]
			for from := range path {
				ladders += 1
				state := NewTreeKEMPrivate(receiver.LeafIndex, receiver.EncryptionPriv)
				for step, rung := range DerivePathSecrets(crypto, secrets[from], len(path)-1-from) {
					state.PathSecrets[path[from+step]] = rung
				}
				if err := state.Consistent(crypto, tree); err != nil {
					t.Fatalf("%s: a state built from the rung at path[%d] = node %d disagrees with the tree it was derived into: %v",
						where, from, path[from], err)
				}
				for step, node := range path {
					key, held, err := state.NodePrivateKey(crypto, node)
					if err != nil {
						t.Fatalf("%s: NodePrivateKey(%d): %v", where, node, err)
					}
					if step < from {
						if held {
							t.Fatalf("%s: a member holding only the rung at path[%d] answered a private key for node %d, which is BELOW it; the ladder runs downward",
								where, from, node)
						}
						below += 1
						continue
					}
					if !held {
						t.Fatalf("%s: a member holding the rung at path[%d] cannot derive node %d, which is at or above it",
							where, from, node)
					}
					_, pub, err := DeriveNodeKeyPair(crypto, state.PathSecrets[node])
					if err != nil {
						t.Fatalf("%s: DeriveNodeKeyPair at node %d: %v", where, node, err)
					}
					parent := tree.ParentAt(node)
					if parent == nil {
						t.Fatalf("%s: node %d of the path is blank in the tree the rungs were installed into", where, node)
					}
					if !bytes.Equal(pub, parent.EncryptionKey) {
						t.Fatalf("%s: the key derived at node %d is %x and the tree carries %x", where, node, pub, parent.EncryptionKey)
					}
					if len(key) == 0 {
						t.Fatalf("%s: NodePrivateKey(%d) answered an empty key", where, node)
					}
					above += 1
				}
			}
		}
	}
	if above == 0 || below == 0 || senders == 0 {
		t.Fatalf("the sweep ran %d senders over %d ladders, reached %d nodes at or above the rung it started from and %d below it; with either direction at zero this test holds one of the two it states",
			senders, ladders, above, below)
	}
	t.Logf("%d senders over widths 2 to 8 and %d skipped for a filtered path of fewer than two nodes, %d ladders, %d nodes derivable from a rung at or below them, %d refused from a rung above them",
		senders, tooShort, ladders, above, below)
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
// and OUT OF the state rather than the one the plan's golden happens to open.
//
// A rejected commit is the case for the entry doors. The caller works on a clone, the commit
// loses a race and is dropped, and a clone that shared one array with its parent has already
// written through to the state the group is still running on -- with every key still deriving and
// nothing to point at. The plan's golden holds the path secret map; the leaf key and the map's
// own membership are the other two, and neither is visible from it.
//
// The EXIT door is the last section and it was the door this test's name promised and did not
// cover. NodePrivateKey has two arms: the derived arm hands back what DeriveKeyPair just made
// and shares nothing, and the own-leaf arm used to hand back the state's live field. One
// function answering two ownership contracts is a caller that cannot have a policy, and the
// policy this package ships for this material is zeroizeSecret -- so "erase the private key when
// the decrypt is done", which is right for every other answer the function gives, erased the
// member's own leaf key and left it unable to decrypt again. Measured, before the fix: zeroizing
// the own-leaf answer wiped TreeKEMPrivate.EncryptionPriv, 0x11 x32 to zeros, and no test saw it.
//
// The exit door is swept rather than sampled. The doors are derived from the tree -- the member's
// own leaf node plus every node it holds a rung for -- so an arm added later is swept the day it
// is added, and both arms are covered by the same assertion rather than by one that happens to
// open the right one.
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

	// and the exit door, over every node this member can answer for.
	tree, members := newTestTree(t, crypto, 8)
	path, secrets := installPathSecrets(t, crypto, tree, members[0].LeafIndex,
		crypto.Random(crypto.HashSize()))
	holder := NewTreeKEMPrivate(members[5].LeafIndex, members[5].EncryptionPriv)
	for at, node := range path {
		holder.PathSecrets[node] = secrets[at]
	}
	ownLeafKey := bytes.Clone(holder.EncryptionPriv)
	doors := append([]NodeIndex{holder.LeafIndex.NodeIndex()}, path...)
	for _, x := range doors {
		answer, held, err := holder.NodePrivateKey(crypto, x)
		if err != nil || !held {
			t.Fatalf("NodePrivateKey(%d) = (_, %v, %v), and every door in this sweep is one the member holds", x, held, err)
		}
		kept := bytes.Clone(answer)
		if len(kept) == 0 {
			t.Fatalf("NodePrivateKey(%d) answered an empty key, so erasing it observes nothing", x)
		}
		// the policy task 22 is entitled to have: erase the private key once it is spent.
		zeroizeSecret(answer)
		again, held, err := holder.NodePrivateKey(crypto, x)
		if err != nil || !held {
			t.Fatalf("NodePrivateKey(%d) after erasing its own previous answer = (_, %v, %v)", x, held, err)
		}
		if !bytes.Equal(again, kept) {
			t.Fatalf("erasing the key NodePrivateKey answered for node %d changed what it answers next time, %x then %x: the answer aliases the state",
				x, kept, again)
		}
	}
	// the same statement made against the field directly, because the leaf key is the one the
	// re-ask above would also have been able to answer from a wiped array.
	if !bytes.Equal(holder.EncryptionPriv, ownLeafKey) {
		t.Fatalf("the state's own leaf key is %x after the sweep and was %x: an answer this member handed out aliased it",
			holder.EncryptionPriv, ownLeafKey)
	}
	if err := holder.Consistent(crypto, tree); err != nil {
		t.Fatalf("the state stopped agreeing with its tree after its own answers were erased: %v", err)
	}
	t.Logf("%d doors out of the state swept, 1 own leaf and %d derived rungs", len(doors), len(path))
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

// ---------------------------------------------------------------------------
// task 18: the secrets, keys and parent hashes of an UpdatePath
// ---------------------------------------------------------------------------

// TestCreateUpdatePathSecretsInstallsAChainThatVerifies is the plan's own sweep: the shapes
// agree, every public key is the one its path secret derives, the commit secret is the rung past
// the root, the leaf is a re-signed commit leaf, and the tree the call leaves behind passes
// section 7.9.2.
func TestCreateUpdatePathSecretsInstallsAChainThatVerifies(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	for _, n := range []uint32{2, 3, 4, 7, 8} {
		tree, members := newTestTree(t, crypto, n)
		plan, err := tree.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
			members[0].SignaturePriv, testGroupId())
		if err != nil {
			t.Fatalf("n=%d CreateUpdatePathSecrets: %v", n, err)
		}
		if len(plan.Path) == 0 {
			t.Fatalf("n=%d the filtered direct path is empty in a group of more than one", n)
		}
		if len(plan.PathSecrets) != len(plan.Path) {
			t.Fatalf("n=%d %d path secrets for %d nodes", n, len(plan.PathSecrets), len(plan.Path))
		}
		if len(plan.PublicKeys) != len(plan.Path) {
			t.Fatalf("n=%d %d public keys for %d nodes", n, len(plan.PublicKeys), len(plan.Path))
		}
		if len(plan.CommitSecret) != crypto.HashSize() {
			t.Fatalf("n=%d commit secret length = %d", n, len(plan.CommitSecret))
		}
		want := crypto.DeriveSecret(plan.PathSecrets[len(plan.PathSecrets)-1], "path")
		if !bytes.Equal(plan.CommitSecret, want) {
			t.Fatalf("n=%d commit secret is not the rung past the root", n)
		}
		for i, x := range plan.Path {
			parent := tree.ParentAt(x)
			if parent == nil {
				t.Fatalf("n=%d node %d was not installed", n, x)
			}
			if !bytes.Equal(parent.EncryptionKey, plan.PublicKeys[i]) {
				t.Fatalf("n=%d node %d carries a different key from the plan", n, x)
			}
			if len(parent.UnmergedLeaves) != 0 {
				t.Fatalf("n=%d node %d kept unmerged leaves across a fresh path", n, x)
			}
			_, derived, err := DeriveNodeKeyPair(crypto, plan.PathSecrets[i])
			if err != nil {
				t.Fatalf("n=%d DeriveNodeKeyPair: %v", n, err)
			}
			if !bytes.Equal(derived, plan.PublicKeys[i]) {
				t.Fatalf("n=%d node %d public key is not derived from its path secret", n, x)
			}
		}
		leaf := tree.Leaf(members[0].LeafIndex)
		if leaf.LeafNodeSource != LeafNodeSourceCommit {
			t.Fatalf("n=%d leaf source = %d, want commit", n, leaf.LeafNodeSource)
		}
		if len(leaf.ParentHash) != crypto.HashSize() {
			t.Fatalf("n=%d leaf parent hash length = %d", n, len(leaf.ParentHash))
		}
		if err := leaf.VerifySignature(crypto, testGroupId(), members[0].LeafIndex); err != nil {
			t.Fatalf("n=%d the re-signed leaf does not verify: %v", n, err)
		}
		if err := tree.VerifyParentHashes(crypto); err != nil {
			t.Fatalf("n=%d VerifyParentHashes after a fresh path: %v", n, err)
		}
	}
}

// TestCreateUpdatePathSecretsGivesTheLeafAnIndependentKey is the plan's second: the leaf key is
// rotated, it is NOT derivable from path_secret[0], and the private state the call answers is
// consistent with the tree it left behind.
func TestCreateUpdatePathSecretsGivesTheLeafAnIndependentKey(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, members := newTestTree(t, crypto, 4)
	before := cloneBytes(tree.Leaf(members[0].LeafIndex).EncryptionKey)
	plan, err := tree.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
		members[0].SignaturePriv, testGroupId())
	if err != nil {
		t.Fatalf("CreateUpdatePathSecrets: %v", err)
	}
	after := tree.Leaf(members[0].LeafIndex).EncryptionKey
	if bytes.Equal(before, after) {
		t.Fatalf("the leaf encryption key was not rotated")
	}
	// the leaf key must NOT be derivable from path_secret[0]: everyone who decrypts
	// that secret would otherwise hold the sender's leaf private key.
	_, fromPathSecret, err := DeriveNodeKeyPair(crypto, plan.PathSecrets[0])
	if err != nil {
		t.Fatalf("DeriveNodeKeyPair: %v", err)
	}
	if bytes.Equal(after, fromPathSecret) {
		t.Fatalf("the leaf key is derived from path_secret[0]")
	}
	if len(plan.Private.EncryptionPriv) == 0 {
		t.Fatalf("the plan's private state carries no leaf private key")
	}
	if plan.Private.LeafIndex != members[0].LeafIndex {
		t.Fatalf("private state leaf index = %d", plan.Private.LeafIndex)
	}
	for i, x := range plan.Path {
		if !bytes.Equal(plan.Private.PathSecrets[x], plan.PathSecrets[i]) {
			t.Fatalf("private state is missing the path secret for node %d", x)
		}
	}
	if err := plan.Private.Consistent(crypto, tree); err != nil {
		t.Fatalf("Consistent: %v", err)
	}
}

// TestCreateUpdatePathSecretsInASingleMemberGroup is the plan's third: a lone member's filtered
// direct path is empty, so there is no node to claim and the commit leaf's parent_hash field is
// the zero-length octet string rather than a digest of nothing.
func TestCreateUpdatePathSecretsInASingleMemberGroup(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	tree, members := newTestTree(t, crypto, 1)
	plan, err := tree.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
		members[0].SignaturePriv, testGroupId())
	if err != nil {
		t.Fatalf("CreateUpdatePathSecrets: %v", err)
	}
	if len(plan.Path) != 0 {
		t.Fatalf("path = %v, want empty", plan.Path)
	}
	if len(plan.CommitSecret) != crypto.HashSize() {
		t.Fatalf("commit secret length = %d", len(plan.CommitSecret))
	}
	leaf := tree.Leaf(members[0].LeafIndex)
	if leaf.LeafNodeSource != LeafNodeSourceCommit || len(leaf.ParentHash) != 0 {
		t.Fatalf("a lone member's leaf must be a commit leaf with a zero-length parent hash, got source %d and %d bytes",
			leaf.LeafNodeSource, len(leaf.ParentHash))
	}
}

// treeHashOf is the section 7.8 hash of a whole tree, taken through the provider.
func treeHashOf(t *testing.T, crypto CryptoProvider, tree *RatchetTree) []byte {
	t.Helper()
	hash, err := tree.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	return hash
}

// testGroupContextOver is the serialized GroupContext of an epoch whose tree hashes to this,
// which is the shape of the HPKE info task 20 seals every path secret under.
//
// Everything but the tree hash is fixed, so two contexts built by this helper differ only where
// the trees they were taken over differ. That is the whole instrument: the ordering defect this
// file is about is invisible unless the two contexts are distinguishable, and a helper that
// varied an epoch number as well would make them differ for a reason that is not the tree's.
func testGroupContextOver(t *testing.T, treeHash []byte) []byte {
	t.Helper()
	context := &GroupContext{
		Version:                 ProtocolVersionMls10,
		CipherSuite:             CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:                 testGroupId(),
		Epoch:                   7,
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0x77}, 32),
	}
	encoded, err := syntax.Marshal(context)
	if err != nil {
		t.Fatalf("Marshal(GroupContext): %v", err)
	}
	return encoded
}

// aFreshEncryptionKeyOtherThan is a well formed HPKE public key that is not the one handed in.
func aFreshEncryptionKeyOtherThan(t *testing.T, crypto CryptoProvider, key HpkePublicKey) HpkePublicKey {
	t.Helper()
	for attempt := 0; attempt < 8; attempt += 1 {
		_, other, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
		if err != nil {
			t.Fatalf("DeriveKeyPair: %v", err)
		}
		if !bytes.Equal(other, key) {
			return other
		}
	}
	t.Fatalf("eight draws from the provider all answered the key they were meant to differ from")
	return nil
}

// TestCreateUpdatePathSecretsLeavesTheTreeAtTheEpochItOpens is the ordering constraint the
// architecture note names, asserted at the boundary task 18 owns.
//
// UpdatePath generation is split in two because the HPKE encryption context task 20 seals each
// path secret under is the serialized GroupContext of the epoch the commit OPENS, and that
// context's tree_hash is only computable once the path's public keys are in the tree. So what
// this half owes its caller is a tree that has already moved: after this call, TreeHash is the
// new epoch's tree hash and the GroupContext built from it is the one every peer will decrypt
// against.
//
// An implementation that left the caller holding the previous epoch's tree -- one that worked on
// a clone, or that answered the plan before installing what it had computed -- produces
// ciphertexts every peer rejects, and it is invisible to any test where the two contexts are not
// distinguished. So both are built here and compared, and the THIRD tree is built too: the
// half-mutated one, direct path blanked and nothing put back, which is what a caller would hash
// if the install had been left to it.
//
// The last sweep is what says the keys are actually inside that hash rather than merely
// alongside it. Its positions come from the plan's own path rather than being picked, because a
// sampled node is a node the defect can be at.
func TestCreateUpdatePathSecretsLeavesTheTreeAtTheEpochItOpens(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	tree, members := newTestTree(t, crypto, 8)
	sender := members[3].LeafIndex

	previous := tree.Clone()
	// the tree mid-operation: the sender's own direct path blanked and nothing installed yet
	halfway := tree.Clone()
	if err := halfway.BlankDirectPath(sender); err != nil {
		t.Fatalf("BlankDirectPath: %v", err)
	}

	plan, err := tree.CreateUpdatePathSecrets(crypto, sender, members[3].SignaturePriv, testGroupId())
	if err != nil {
		t.Fatalf("CreateUpdatePathSecrets: %v", err)
	}
	opened := treeHashOf(t, crypto, tree)
	if stale := treeHashOf(t, crypto, previous); bytes.Equal(opened, stale) {
		t.Fatalf("the tree hash after the call is the one it had before it, so the caller would build the new epoch's GroupContext out of the previous epoch's tree")
	}
	if mid := treeHashOf(t, crypto, halfway); bytes.Equal(opened, mid) {
		t.Fatalf("the tree hash after the call is the hash of the blanked path with nothing installed, so the public keys this call computed are not in the tree it left behind")
	}
	// the two contexts task 20 has to tell apart, spelled out
	if bytes.Equal(testGroupContextOver(t, opened), testGroupContextOver(t, treeHashOf(t, crypto, previous))) {
		t.Fatalf("the GroupContext over the new tree and the one over the old tree serialize alike, so this test cannot see which of them an encryption used")
	}

	// every public key of the path is inside the hash the caller binds the epoch to
	swept, hashed := 0, 0
	for i, x := range plan.Path {
		held := tree.ParentAt(x)
		if held == nil {
			t.Fatalf("node %d was not installed", x)
		}
		swapped := tree.Clone()
		if err := swapped.SetParent(x, &ParentNode{
			EncryptionKey: aFreshEncryptionKeyOtherThan(t, crypto, plan.PublicKeys[i]),
			ParentHash:    cloneBytes(held.ParentHash),
		}); err != nil {
			t.Fatalf("SetParent(%d): %v", x, err)
		}
		if bytes.Equal(treeHashOf(t, crypto, swapped), opened) {
			t.Errorf("node %d's public key is not inside the tree hash the caller binds this epoch to", x)
		}
		swept += 1
		// and so is the parent hash it carries, wherever there is one to move. The node at the
		// top of the path carries the zero-length octet string, which is a value with no byte
		// to flip rather than an exemption, so it is skipped and counted.
		if len(held.ParentHash) == 0 {
			continue
		}
		rehung := tree.Clone()
		field := cloneBytes(held.ParentHash)
		field[0] ^= 0xff
		if err := rehung.SetParent(x, &ParentNode{
			EncryptionKey: cloneBytes(held.EncryptionKey),
			ParentHash:    field,
		}); err != nil {
			t.Fatalf("SetParent(%d): %v", x, err)
		}
		if bytes.Equal(treeHashOf(t, crypto, rehung), opened) {
			t.Errorf("node %d's parent hash is not inside the tree hash the caller binds this epoch to", x)
		}
		hashed += 1
	}
	// and the re-signed leaf, which is the other thing this call installed
	releafed := tree.Clone()
	leaf := tree.Leaf(sender).Clone()
	leaf.EncryptionKey = aFreshEncryptionKeyOtherThan(t, crypto, leaf.EncryptionKey)
	if err := releafed.SetLeaf(sender, leaf); err != nil {
		t.Fatalf("SetLeaf: %v", err)
	}
	if bytes.Equal(treeHashOf(t, crypto, releafed), opened) {
		t.Errorf("the sender's new leaf key is not inside the tree hash the caller binds this epoch to")
	}
	if swept == 0 || hashed == 0 {
		t.Fatalf("the sweep read %d path nodes and %d parent hash fields; a zero in either is a direction this test did not reach",
			swept, hashed)
	}
	t.Logf("%d path nodes and %d parent hash fields held inside the new epoch's tree hash", swept, hashed)
}

// updatePathChainOf reads the parent hash chain a tree CARRIES along one filtered direct path,
// rung by rung: rung 0 is the leaf's field and rung i+1 is the field at steps[i].
func updatePathChainOf(t *testing.T, tree *RatchetTree, sender LeafIndex, steps []PathStep) [][]byte {
	t.Helper()
	chain := make([][]byte, len(steps)+1)
	leaf := tree.Leaf(sender)
	if leaf == nil {
		t.Fatalf("leaf %d is blank", sender)
	}
	chain[0] = cloneBytes(leaf.ParentHash)
	for i, step := range steps {
		parent := tree.ParentAt(step.Node)
		if parent == nil {
			t.Fatalf("node %d of the filtered path is blank", step.Node)
		}
		chain[i+1] = cloneBytes(parent.ParentHash)
	}
	return chain
}

// recomputeUpdatePathChain writes section 7.9's chain over the tree it is given and answers it in
// updatePathChainOf's rungs.
//
// From the RFC's sentence rather than from treekem.go: "If P is the root, then the parent_hash
// field is set to a zero-length octet string. Otherwise, parent_hash is the parent hash of the
// next node after P on the filtered direct path", and section 7.9.1's "the parent_hash field of
// D is equal to the parent hash of P with copath child S. This is the case even when the node D
// is a leaf node." That is a recurrence from the top down, and it MUTATES the tree it walks --
// each node's field has to be final before the node below it can be hashed -- so every caller
// below hands it a clone.
func recomputeUpdatePathChain(t *testing.T, crypto CryptoProvider, tree *RatchetTree,
	steps []PathStep) [][]byte {
	t.Helper()
	chain := make([][]byte, len(steps)+1)
	carried := []byte{}
	for i := len(steps) - 1; i >= 0; i -= 1 {
		parent := tree.ParentAt(steps[i].Node)
		if parent == nil {
			t.Fatalf("node %d of the filtered path is blank", steps[i].Node)
		}
		parent.ParentHash = carried
		chain[i+1] = cloneBytes(carried)
		hash, err := tree.ParentHash(crypto, steps[i].Node, steps[i].CopathChild)
		if err != nil {
			t.Fatalf("ParentHash(%d, %d): %v", steps[i].Node, steps[i].CopathChild, err)
		}
		carried = hash
	}
	chain[0] = cloneBytes(carried)
	return chain
}

// TestTheUpdatePathParentHashChainMovesEverythingBelowANodeAndNothingAbove is the dependency
// structure of the chain, swept.
//
// Two properties, and the second is what makes the first worth stating. The chain a commit
// installs is the one section 7.9's recurrence produces from the root down -- that is asserted
// elementwise, so a chain computed in the other direction, or one that stopped short of the
// leaf, is a mismatch at a named rung rather than a verdict. And the recurrence really is a
// chain: a fresh key at one node of the path moves the parent hash of every rung BELOW it and no
// rung at or above it, because the hash at a rung above covers the OTHER child's subtree.
//
// The second half is the one that separates a real chain from a set of digests that merely
// verify. An implementation that hashed each node against a constant instead of against the node
// above it produces a full length chain over which VerifyParentHashes has nothing to say at the
// nodes it never links -- and every rung of it would be insensitive to a change higher up, which
// is exactly what this sweep counts.
//
// Both the positions and the senders are DERIVED. Every width from two to eight, every member of
// each as the sender, and every rung of each path as the node that changes; a sender whose
// filtered path is shorter than two nodes has no above and below to separate and is SKIPPED with
// a counter rather than excluded by a width, because which senders those are is a property of
// the filter and changes when the filter does.
func TestTheUpdatePathParentHashChainMovesEverythingBelowANodeAndNothingAbove(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	senders, moved, held, tooShort := 0, 0, 0, 0
	for width := uint32(2); width <= 8; width += 1 {
		for at := uint32(0); at < width; at += 1 {
			tree, members := newTestTree(t, crypto, width)
			sender := members[at].LeafIndex
			plan, err := tree.CreateUpdatePathSecrets(crypto, sender, members[at].SignaturePriv, testGroupId())
			if err != nil {
				t.Fatalf("width=%d sender=%d CreateUpdatePathSecrets: %v", width, sender, err)
			}
			steps, err := tree.filteredPathSteps(sender)
			if err != nil {
				t.Fatalf("width=%d sender=%d filteredPathSteps: %v", width, sender, err)
			}
			if len(steps) != len(plan.Path) {
				t.Fatalf("width=%d sender=%d the plan carries %d nodes and the tree's filtered path has %d",
					width, sender, len(plan.Path), len(steps))
			}
			if len(steps) < 2 {
				tooShort += 1
				continue
			}
			senders += 1
			// the chain as installed is the chain section 7.9's recurrence produces
			installed := updatePathChainOf(t, tree, sender, steps)
			original := recomputeUpdatePathChain(t, crypto, tree.Clone(), steps)
			for rung := range original {
				if !bytes.Equal(installed[rung], original[rung]) {
					t.Fatalf("width=%d sender=%d rung %d of the installed chain is %x and section 7.9's recurrence gives %x",
						width, sender, rung, installed[rung], original[rung])
				}
			}
			if len(original[len(steps)]) != 0 {
				t.Errorf("width=%d sender=%d the node at the top of the filtered path carries %d bytes, and section 7.9 gives it the zero-length octet string",
					width, sender, len(original[len(steps)]))
			}
			for k := range steps {
				changed := tree.Clone()
				node := changed.ParentAt(steps[k].Node)
				if node == nil {
					t.Fatalf("width=%d sender=%d node %d is blank", width, sender, steps[k].Node)
				}
				if err := changed.SetParent(steps[k].Node, &ParentNode{
					EncryptionKey: aFreshEncryptionKeyOtherThan(t, crypto, node.EncryptionKey),
					ParentHash:    cloneBytes(node.ParentHash),
				}); err != nil {
					t.Fatalf("SetParent(%d): %v", steps[k].Node, err)
				}
				after := recomputeUpdatePathChain(t, crypto, changed, steps)
				for rung := range after {
					// rung k is the parent hash OF node steps[k], so it and every rung under
					// it are downstream of that node's key and every rung above it is not
					shouldMove := rung <= k
					same := bytes.Equal(original[rung], after[rung])
					if shouldMove && same {
						t.Errorf("width=%d sender=%d a fresh key at node %d (rung %d of the path) left rung %d of the chain unchanged, and rung %d is below it",
							width, sender, steps[k].Node, k, rung, rung)
					}
					if !shouldMove && !same {
						t.Errorf("width=%d sender=%d a fresh key at node %d (rung %d of the path) moved rung %d of the chain, and rung %d is at or above it",
							width, sender, steps[k].Node, k, rung, rung)
					}
					if shouldMove {
						moved += 1
					} else {
						held += 1
					}
				}
			}
		}
	}
	if senders == 0 || moved == 0 || held == 0 {
		t.Fatalf("the sweep ran %d senders and made %d must-move and %d must-hold observations, with %d paths too short; a zero in any of the three is a direction this test did not reach",
			senders, moved, held, tooShort)
	}
	t.Logf("%d senders, %d must-move and %d must-hold observations, %d paths too short to have an above and a below",
		senders, moved, held, tooShort)
}
