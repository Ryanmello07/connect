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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
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
//
// Its name promises more than its body observes, and the two halves it does NOT observe are
// named here rather than left for the next reader to discover the way this one was. "Independent"
// has two more meanings past "not derived from path_secret[0]", and a constant satisfies both of
// the assertions below: a leaf key pair seeded from thirty two zero octets is not the old key and
// is not DeriveNodeKeyPair(path_secret[0]), so it passes here while being the same leaf private
// key in every group in the world. And the private key this checks is only checked for being
// non-empty, so a state whose EncryptionPriv came from a second, independent key pair -- one that
// cannot open anything sealed to the leaf key the tree publishes -- passes too. Both were applied
// and the whole package stayed green.
//
// TestCreateUpdatePathSecretsDrawsEveryOctetStringItPublishesFromFreshEntropy holds the first and
// TestThePrivateStateOpensEverythingSealedToTheKeysThisCommitInstalls holds the second. What is
// left here is worth keeping: the rotation and the one derivation the RFC forbids are the two
// things a reader looks for under this name, and they are stated where they are easiest to read.
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

// ---------------------------------------------------------------------------
// task 18: the four mutants a review found this file could not see
// ---------------------------------------------------------------------------
//
// Everything above this line compares two derivations of the same commit against each other:
// the public key at a node against the key its own path secret derives, the commit secret
// against DeriveSecret of the last rung, the installed chain against a recomputation of it.
// Every one of those holds over a commit whose entropy is a constant. A sender that seeded its
// leaf key pair from thirty two zero octets installs the SAME leaf private key in every group
// in the world, agrees with itself at every node, satisfies Consistent, verifies its parent
// hashes and passed all of it -- measured, not supposed. So do a path secret ladder seeded from
// a constant, a private state whose leaf key has no relationship to the leaf key the tree
// publishes, and a filtered direct path published root-first.
//
// What separates those four from a correct commit is never a comparison inside one run. It is a
// second run: against a different entropy stream, against the tree's own filtered path, or
// against the HPKE round trip the private state exists to perform. That is what the four tests
// below are.

// octetStringsUnder is every non-empty octet string reachable from a value: any slice or array
// of octets, and any named type spelled over one, found through pointers, structs, slices,
// arrays and maps.
//
// Reflective rather than a list of fields, which is the whole reason it is worth writing. The
// property the freshness test asserts is about EVERY octet string a commit produces, and a
// field added to UpdatePathPlan or to a node by a later task is under that property the day it
// is declared rather than the day somebody remembers to add it here. The octets are read one at
// a time through Uint rather than through Bytes because the walk descends into RatchetTree's
// unexported node array, and a value obtained that way refuses to be handed out whole.
//
// Zero-length strings are skipped. The topmost node of a filtered path carries the zero-length
// octet string section 7.9 gives it, which is a value with no entropy in it either way, and a
// walk that reported it would make every run share one member with every other.
func octetStringsUnder(value reflect.Value) [][]byte {
	found := [][]byte{}
	var walk func(reflect.Value)
	walk = func(at reflect.Value) {
		if !at.IsValid() {
			return
		}
		switch at.Kind() {
		case reflect.Pointer, reflect.Interface:
			if !at.IsNil() {
				walk(at.Elem())
			}
		case reflect.Slice, reflect.Array:
			if at.Kind() == reflect.Slice && at.IsNil() {
				return
			}
			if at.Type().Elem().Kind() == reflect.Uint8 {
				if at.Len() == 0 {
					return
				}
				octets := make([]byte, at.Len())
				for i := range octets {
					octets[i] = byte(at.Index(i).Uint())
				}
				found = append(found, octets)
				return
			}
			for i := 0; i < at.Len(); i += 1 {
				walk(at.Index(i))
			}
		case reflect.Map:
			for _, key := range at.MapKeys() {
				walk(key)
				walk(at.MapIndex(key))
			}
		case reflect.Struct:
			for i := 0; i < at.NumField(); i += 1 {
				walk(at.Field(i))
			}
		}
	}
	walk(value)
	return found
}

// hexSetOf is a set of octet strings keyed by their hex, which is how the sweep below asks
// whether two runs produced one value without caring where in either structure it sat.
func hexSetOf(values [][]byte) map[string]bool {
	found := map[string]bool{}
	for _, value := range values {
		found[hex.EncodeToString(value)] = true
	}
	return found
}

// TestCreateUpdatePathSecretsDrawsEveryOctetStringItPublishesFromFreshEntropy is the property
// no comparison inside one commit can make.
//
// A commit that seeds its leaf key pair, or its whole path secret ladder, from a constant is
// self-consistent at every point this file otherwise checks: each public key is the one its
// path secret derives, the commit secret is the rung past the root, the private state is
// Consistent with the tree, the parent hashes verify. It is also the same leaf private key, the
// same path_secret[0] and the same commit secret in every group that implementation ever runs
// -- so the copath of any one commit anywhere holds the sender's leaf key everywhere. Both
// mutants were applied and the whole package stayed green.
//
// The instrument is two entropy streams over ONE tree. Everything about the two runs is
// identical except the octets the provider hands out, so an octet string that comes back the
// same from both was not drawn: it was carried out of the tree, or it is a constant. The
// carried half is derived from the input tree itself rather than listed, so a credential, a
// signature key or an extension body the fixture happens to hold is excused by being IN it and
// nothing else is.
//
// The class of values judged is derived too, by walking the plan and the tree the call left
// behind for every octet string in them. A field a later task adds to either is under this
// property without an edit here, which is the half a named list of five secrets would lose.
//
// Two controls, because a differential test's failure mode is having no difference to see.
// Running the SAME stream twice must reproduce the run exactly, which is what says a difference
// between the two streams is the entropy rather than incidental nondeterminism; and the values
// the RFC makes secret are looked up by name in the drawn set, which is what says the walk
// found them at all. A walker that returned nothing would satisfy the intersection property and
// nothing else.
func TestCreateUpdatePathSecretsDrawsEveryOctetStringItPublishesFromFreshEntropy(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	fixture, members := newTestTree(t, crypto, 8)
	const at = 3
	sender := members[at].LeafIndex

	// what the call may answer without having drawn it: every octet string the tree it was
	// handed already held, plus the group id the caller passes in
	carried := hexSetOf(octetStringsUnder(reflect.ValueOf(fixture)))
	carried[hex.EncodeToString(testGroupId())] = true
	if len(carried) < 8 {
		t.Fatalf("the input tree walked to %d octet strings, and an eight member tree holds a key, a credential and an extension body per leaf; the walk is not reading it",
			len(carried))
	}

	// one commit over a copy of that tree, under a provider whose entropy the caller chose
	run := func(first byte) (map[string]bool, map[string][]byte) {
		tree := fixture.Clone()
		drawn := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, providerStubStream(first))
		plan, err := tree.CreateUpdatePathSecrets(drawn, sender, members[at].SignaturePriv, testGroupId())
		if err != nil {
			t.Fatalf("stream %#02x: CreateUpdatePathSecrets: %v", first, err)
		}
		produced := append(octetStringsUnder(reflect.ValueOf(plan)), octetStringsUnder(reflect.ValueOf(tree))...)
		drew := map[string]bool{}
		for value := range hexSetOf(produced) {
			if !carried[value] {
				drew[value] = true
			}
		}
		named := map[string][]byte{
			"the sender's new leaf encryption key, as the tree publishes it": tree.Leaf(sender).EncryptionKey,
			"the leaf private key the plan's private state keeps":            plan.Private.EncryptionPriv,
			"path_secret[0]":                                                 plan.PathSecrets[0],
			"the commit secret":                                              plan.CommitSecret,
		}
		for i, x := range plan.Path {
			named[fmt.Sprintf("the public key published at node %d", x)] = plan.PublicKeys[i]
			named[fmt.Sprintf("the path secret the private state holds for node %d", x)] = plan.Private.PathSecrets[x]
		}
		return drew, named
	}

	first, named := run(0x11)
	second, _ := run(0xa4)
	again, _ := run(0x11)

	// the control: one stream is one run, so a value that survives below survives because the
	// entropy did not reach it and not because the fixture wandered
	if !maps.Equal(first, again) {
		t.Fatalf("two commits over one tree under one entropy stream drew %d and %d octet strings and the sets differ; this test cannot tell a constant from a value that varies for some other reason",
			len(first), len(again))
	}
	if len(first) == 0 {
		t.Fatal("the walk found no octet string in the plan or the tree that the input tree did not already hold, so the sweep below compares two empty sets")
	}

	// the coverage claim, checked rather than assumed: the values the RFC makes secret have to
	// be among the ones being judged
	for what, octets := range named {
		if len(octets) == 0 {
			t.Errorf("%s is empty", what)
			continue
		}
		if !first[hex.EncodeToString(octets)] {
			t.Errorf("%s is not among the octet strings this commit drew, so the sweep below is not judging it", what)
		}
	}

	// the property. Nothing a commit produces that its tree did not already hold may repeat
	// across two entropy streams.
	repeated := []string{}
	for value := range first {
		if second[value] {
			repeated = append(repeated, value)
		}
	}
	slices.Sort(repeated)
	for _, value := range repeated {
		what := "an octet string"
		for name, octets := range named {
			if hex.EncodeToString(octets) == value {
				what = name
			}
		}
		t.Errorf("two commits over one tree under two different entropy streams both produced %s = %s; it is a constant of this implementation rather than something this commit drew, which is the sender's own secret handed to every group it ever runs in",
			what, value)
	}
	t.Logf("%d octet strings drawn per commit, %d of them named, none shared across two entropy streams",
		len(first), len(named))
}

// encryptionKeyAt is the HPKE public key a tree carries at one node, whichever kind of node it
// is. A blank position is fatal rather than an empty key: every caller below reads a position
// the commit it just made installed.
func encryptionKeyAt(t *testing.T, tree *RatchetTree, x NodeIndex) HpkePublicKey {
	t.Helper()
	node := tree.Get(x)
	if node == nil {
		t.Fatalf("node %d is blank", x)
	}
	if node.Leaf != nil {
		return node.Leaf.EncryptionKey
	}
	if node.Parent != nil {
		return node.Parent.EncryptionKey
	}
	t.Fatalf("node %d holds neither a leaf nor a parent", x)
	return nil
}

// TestThePrivateStateOpensEverythingSealedToTheKeysThisCommitInstalls is the round trip the
// plan's private half exists to perform, made at the one place both halves are in scope.
//
// TreeKEMPrivate.Consistent deliberately does not check the leaf pair -- the provider surface
// has no private-to-public operation, and its own comment defers it to task 22's decrypt, where
// the UpdatePath carries the public key to compare against. That leaves task 18 as the only
// call in the package where the private key it stores and the public key it installs are both
// present, and before this test nothing related them: the plan's leaf private key could be
// drawn from a second, independent key pair and every test in this file passed, including the
// one named for the leaf's independence, which asserted only that the field was not empty. The
// sender would then hold a private state that cannot open anything sealed to its own published
// leaf key, and would find that out one epoch later as a decryption failure.
//
// So the assertion is the operation itself, through HpkeSeal and HpkeOpen, which the provider
// surface has had since task 15. The class is DERIVED from the commit: the sender's own leaf,
// plus every node of the path the plan publishes, read out of the tree the call left behind
// rather than out of the plan, because what a peer will seal to is what the TREE carries. Both
// arms of NodePrivateKey are exercised by that class without being named -- the leaf is the
// stored-key arm and every path node is the derived arm.
//
// The negative control is per node rather than once. A round trip that succeeded for a reason
// other than the key -- a provider that ignored the private key, say -- would pass every line
// above, so an unrelated private key is required to fail at each of the same positions.
func TestThePrivateStateOpensEverythingSealedToTheKeysThisCommitInstalls(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	info := []byte("urmessage: the info an update path seals under")
	aad := []byte("urmessage: the aad")
	plaintext := []byte("a path secret sized plaintext, thirty two octets.")
	opened, refused, senders := 0, 0, 0
	for _, n := range []uint32{2, 3, 4, 7, 8} {
		for at := uint32(0); at < n; at += 1 {
			tree, members := newTestTree(t, crypto, n)
			sender := members[at].LeafIndex
			plan, err := tree.CreateUpdatePathSecrets(crypto, sender, members[at].SignaturePriv, testGroupId())
			if err != nil {
				t.Fatalf("n=%d sender=%d CreateUpdatePathSecrets: %v", n, sender, err)
			}
			senders += 1
			// the class: the leaf this commit re-keyed, and every node it published a key at
			installed := append([]NodeIndex{sender.NodeIndex()}, plan.Path...)
			for _, x := range installed {
				public := encryptionKeyAt(t, tree, x)
				private, held, err := plan.Private.NodePrivateKey(crypto, x)
				if err != nil {
					t.Fatalf("n=%d sender=%d NodePrivateKey(%d): %v", n, sender, x, err)
				}
				if !held {
					t.Errorf("n=%d sender=%d the commit installed a key at node %d and its own private state holds nothing for it",
						n, sender, x)
					continue
				}
				kemOutput, ciphertext, err := crypto.HpkeSeal(public, info, aad, plaintext)
				if err != nil {
					t.Fatalf("n=%d sender=%d HpkeSeal to node %d: %v", n, sender, x, err)
				}
				got, err := crypto.HpkeOpen(private, kemOutput, info, aad, ciphertext)
				if err != nil {
					t.Errorf("n=%d sender=%d the private state cannot open what was sealed to the key this commit installed at node %d: %v",
						n, sender, x, err)
					continue
				}
				if !bytes.Equal(got, plaintext) {
					t.Errorf("n=%d sender=%d node %d opened to %x, want %x", n, sender, x, got, plaintext)
					continue
				}
				opened += 1
				// the control, at the same node: an unrelated private key must not open it
				other, _, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
				if err != nil {
					t.Fatalf("DeriveKeyPair: %v", err)
				}
				if _, err := crypto.HpkeOpen(other, kemOutput, info, aad, ciphertext); err == nil {
					t.Fatalf("n=%d sender=%d a private key unrelated to node %d opened its ciphertext, so the round trip above says nothing about which key was used",
						n, sender, x)
				}
				refused += 1
			}
		}
	}
	if senders == 0 || opened == 0 || refused == 0 {
		t.Fatalf("the sweep ran %d senders, %d round trips and %d controls; a zero in any of the three is a direction this test did not reach",
			senders, opened, refused)
	}
	t.Logf("%d senders, %d keys installed and opened through the plan's own private state, %d unrelated keys refused",
		senders, opened, refused)
}

// TestTheUpdatePathIsPublishedLeafFirstAlongTheFilteredDirectPath is the order contract, which
// nothing held.
//
// FilteredDirectPath's own doc states it: "The order is the contract and not a detail of it ...
// That is why the tests compare elementwise through equalNodeIndices and never as sets." The
// plan built the same slice and no test compared it against anything -- the two that touch it
// check that it is not empty and that it has the same LENGTH as the filtered path -- so
// publishing it root-first left the whole package green. That reversal is entirely
// self-consistent inside this task, because publicKeys[i] is installed at path[i] and the
// private state is keyed by path[i] too: the topmost node ends up carrying the key derived from
// the LOWEST rung, which inverts the one-way asymmetry this file's header says the security
// argument rests on, and task 19's wire type and task 20's ciphertexts pair positionally with
// exactly this slice.
//
// Two readings, deliberately not one. Elementwise against the tree's own FilteredDirectPath is
// the contract as this package states it; and against tree math's unfiltered direct path, which
// is bottom-up by construction, is the same statement made without the filter in it -- every
// published node is on the sender's direct path and their positions along it strictly ascend.
// A filter that reversed its own answer would satisfy the first and fail the second.
//
// The ladder pairing is here too, because it is the same positional claim about the other half
// of the plan: rung i+1 is DeriveSecret of rung i under "path", and it derives the key
// published one node higher.
//
// Every width from two to eight and every member of each as the sender, since which senders
// have a filtered path shorter than the direct path is a property of the filter.
func TestTheUpdatePathIsPublishedLeafFirstAlongTheFilteredDirectPath(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	senders, published, placed, rungs := 0, 0, 0, 0
	for width := uint32(2); width <= 8; width += 1 {
		for at := uint32(0); at < width; at += 1 {
			tree, members := newTestTree(t, crypto, width)
			sender := members[at].LeafIndex
			before := tree.Clone()
			want, err := before.FilteredDirectPath(sender)
			if err != nil {
				t.Fatalf("width=%d sender=%d FilteredDirectPath: %v", width, sender, err)
			}
			plan, err := tree.CreateUpdatePathSecrets(crypto, sender, members[at].SignaturePriv, testGroupId())
			if err != nil {
				t.Fatalf("width=%d sender=%d CreateUpdatePathSecrets: %v", width, sender, err)
			}
			senders += 1
			// the contract as this package states it, elementwise and never as a set
			if !equalNodeIndices(plan.Path, want) {
				t.Errorf("width=%d sender=%d the plan publishes %v and the filtered direct path of the tree it committed over is %v",
					width, sender, plan.Path, want)
			}
			// and over the tree the call left behind, which is the one task 20 hands on
			after, err := tree.FilteredDirectPath(sender)
			if err != nil {
				t.Fatalf("width=%d sender=%d FilteredDirectPath after the commit: %v", width, sender, err)
			}
			if !equalNodeIndices(plan.Path, after) {
				t.Errorf("width=%d sender=%d the plan publishes %v and the filtered direct path of the tree it left behind is %v",
					width, sender, plan.Path, after)
			}
			published += len(plan.Path)

			// the same claim without the filter in it: tree math's direct path is bottom-up by
			// construction, so a published path that is leaf-first visits its positions in
			// strictly ascending order
			direct, err := directPathOf(sender.NodeIndex(), before.LeafWidth())
			if err != nil {
				t.Fatalf("width=%d sender=%d directPathOf: %v", width, sender, err)
			}
			height := map[NodeIndex]int{}
			for rung, x := range direct {
				height[x] = rung
			}
			last := -1
			for i, x := range plan.Path {
				rung, on := height[x]
				if !on {
					t.Errorf("width=%d sender=%d the plan publishes node %d at position %d, and that node is not on the sender's direct path %v",
						width, sender, x, i, direct)
					continue
				}
				if rung <= last {
					t.Errorf("width=%d sender=%d the plan publishes node %d (rung %d of the direct path) at position %d, after a node at rung %d; the filtered direct path is published leaf-first and this one runs the other way",
						width, sender, x, rung, i, last)
				}
				last = rung
				placed += 1
			}

			// the ladder, paired with the path the same way: rung i+1 is one DeriveSecret above
			// rung i, and it is the secret the node one position higher was keyed from
			for i := 0; i+1 < len(plan.PathSecrets); i += 1 {
				next := crypto.DeriveSecret(plan.PathSecrets[i], "path")
				if !bytes.Equal(next, plan.PathSecrets[i+1]) {
					t.Errorf("width=%d sender=%d path secret %d is not DeriveSecret of path secret %d under the label \"path\"",
						width, sender, i+1, i)
					continue
				}
				_, derived, err := DeriveNodeKeyPair(crypto, next)
				if err != nil {
					t.Fatalf("DeriveNodeKeyPair: %v", err)
				}
				if !bytes.Equal(derived, plan.PublicKeys[i+1]) {
					t.Errorf("width=%d sender=%d the rung above path secret %d does not derive the key published at position %d (node %d)",
						width, sender, i, i+1, plan.Path[i+1])
				}
				rungs += 1
			}
		}
	}
	if senders == 0 || published == 0 || placed == 0 || rungs == 0 {
		t.Fatalf("the sweep ran %d senders, %d published nodes, %d of them placed against the unfiltered direct path and %d ladder steps; a zero in any of the four is a direction this test did not reach",
			senders, published, placed, rungs)
	}
	t.Logf("%d senders, %d published nodes, %d placed against the unfiltered direct path, %d ladder steps",
		senders, published, placed, rungs)
}

// ---------------------------------------------------------------------------
// task 18: what a failed commit must leave behind, and which fault it names
// ---------------------------------------------------------------------------

// errInjectedProviderFault is what the sweep below makes exactly one provider call answer, so
// a refusal produced by the injection is never mistaken for one the tree raised on its own.
var errInjectedProviderFault = errors.New("mls: injected provider fault")

// faultInjectingProvider fails the nth call to a CryptoProvider method that has an error to
// fail with, and passes every other call straight through to the provider it embeds.
//
// The embedded interface is what makes the passthrough total: a method this type does not
// override is answered by the real provider, so the sweep only ever perturbs the one call it
// means to. Which methods it MUST override is not a judgement made here --
// TestTheFaultInjectingProviderCoversEveryProviderCallThatCanFail derives that class off the
// interface itself and calls each member, so a fallible method added to CryptoProvider by a
// later task fails that gate rather than quietly becoming a failure this sweep cannot inject.
type faultInjectingProvider struct {
	CryptoProvider
	failAt int
	calls  int
}

// faults counts this call and answers whether it is the one to fail. Counting happens on every
// fallible call whether or not it fails, which is what makes a run with failAt of zero a census
// of how many injection points the operation has.
func (self *faultInjectingProvider) faults() bool {
	self.calls += 1
	return self.calls == self.failAt
}

func (self *faultInjectingProvider) AeadSeal(key []byte, nonce []byte, aad []byte, plaintext []byte) ([]byte, error) {
	if self.faults() {
		return nil, errInjectedProviderFault
	}
	return self.CryptoProvider.AeadSeal(key, nonce, aad, plaintext)
}

func (self *faultInjectingProvider) AeadOpen(key []byte, nonce []byte, aad []byte, ciphertext []byte) ([]byte, error) {
	if self.faults() {
		return nil, errInjectedProviderFault
	}
	return self.CryptoProvider.AeadOpen(key, nonce, aad, ciphertext)
}

func (self *faultInjectingProvider) SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error) {
	if self.faults() {
		return nil, errInjectedProviderFault
	}
	return self.CryptoProvider.SignWithLabel(priv, label, content)
}

func (self *faultInjectingProvider) VerifyWithLabel(pub SignaturePublicKey, label string, content []byte, sig []byte) error {
	if self.faults() {
		return errInjectedProviderFault
	}
	return self.CryptoProvider.VerifyWithLabel(pub, label, content, sig)
}

func (self *faultInjectingProvider) HpkeSeal(pub HpkePublicKey, info []byte, aad []byte, plaintext []byte) ([]byte, []byte, error) {
	if self.faults() {
		return nil, nil, errInjectedProviderFault
	}
	return self.CryptoProvider.HpkeSeal(pub, info, aad, plaintext)
}

func (self *faultInjectingProvider) HpkeOpen(priv HpkePrivateKey, kemOutput []byte, info []byte, aad []byte, ciphertext []byte) ([]byte, error) {
	if self.faults() {
		return nil, errInjectedProviderFault
	}
	return self.CryptoProvider.HpkeOpen(priv, kemOutput, info, aad, ciphertext)
}

func (self *faultInjectingProvider) DeriveKeyPair(ikm []byte) (HpkePrivateKey, HpkePublicKey, error) {
	if self.faults() {
		return nil, nil, errInjectedProviderFault
	}
	return self.CryptoProvider.DeriveKeyPair(ikm)
}

func (self *faultInjectingProvider) SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error) {
	if self.faults() {
		return nil, nil, errInjectedProviderFault
	}
	return self.CryptoProvider.SignatureKeyPair()
}

// fallibleProviderMethods is every method of CryptoProvider whose results include an error,
// read off the interface type rather than written out.
//
// This is the class the injecting provider has to cover, and it is derived for the reason
// standing rule 5 gives: a hand written list of eight names understates the class the moment a
// ninth fallible method lands, and the sweep that uses it would then report a clean bill over a
// failure it never injected.
func fallibleProviderMethods() []string {
	surface := reflect.TypeOf((*CryptoProvider)(nil)).Elem()
	failure := reflect.TypeOf((*error)(nil)).Elem()
	found := []string{}
	for i := 0; i < surface.NumMethod(); i += 1 {
		method := surface.Method(i)
		for at := 0; at < method.Type.NumOut(); at += 1 {
			if method.Type.Out(at) == failure {
				found = append(found, method.Name)
				break
			}
		}
	}
	slices.Sort(found)
	return found
}

// TestTheFaultInjectingProviderCoversEveryProviderCallThatCanFail holds the fixture to the
// class above, in the only way that cannot go quiet: by CALLING each member.
//
// A structural check -- does this type declare a method of that name -- would be satisfied by
// an override that forgot to consult the counter. So each fallible method is invoked with the
// fault armed at the first call and is required to answer the injected fault: a method the
// fixture does not override reaches the embedded provider and answers something else, or
// panics on the zero arguments, and either way is reported here rather than silently becoming
// a failure the atomicity sweep cannot reach.
func TestTheFaultInjectingProviderCoversEveryProviderCallThatCanFail(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	names := fallibleProviderMethods()
	if len(names) == 0 {
		t.Fatal("no method of CryptoProvider was read as having an error result, so this gate is judging an empty class")
	}
	for _, name := range names {
		armed := CryptoProvider(&faultInjectingProvider{CryptoProvider: crypto, failAt: 1})
		method := reflect.ValueOf(armed).MethodByName(name)
		if !method.IsValid() {
			t.Errorf("CryptoProvider declares %s and the fault injecting provider has no such method", name)
			continue
		}
		arguments := make([]reflect.Value, method.Type().NumIn())
		for i := range arguments {
			arguments[i] = reflect.New(method.Type().In(i)).Elem()
		}
		results := []reflect.Value{}
		if panicked := recoveredPanic(func() { results = method.Call(arguments) }); panicked != nil {
			t.Errorf("%s panicked with %v instead of answering the armed fault, so the fault injecting provider does not override it and the atomicity sweep can never fail that call",
				name, panicked)
			continue
		}
		var answered error
		for _, result := range results {
			if failure, isError := result.Interface().(error); isError && failure != nil {
				answered = failure
			}
		}
		if !errors.Is(answered, errInjectedProviderFault) {
			t.Errorf("%s answered %v with the fault armed at its first call; the fault injecting provider does not override it, so a failure there is one the atomicity sweep cannot inject",
				name, answered)
		}
	}
	t.Logf("%d fallible provider methods, every one of them injectable: %v", len(names), names)
}

// TestCreateUpdatePathSecretsLeavesTheTreeExactlyAsItFoundItWhenItFails is the atomicity
// contract, and it is here because the shipped body did not have one.
//
// Every refusal this call makes was placed ahead of the mutation on purpose -- the nil
// provider, the leaf index, the filtered path -- except one. leaf.Sign is reachable only after
// the direct path has been blanked, the new public keys installed and the parent hash chain
// written, so a signature private key that does not match the ciphersuite used to answer an
// error over a caller's tree whose tree hash had already moved and which VerifyParentHashes
// then refused. Measured on the shipped source, not supposed: the tree hash moved and
// VerifyParentHashes answered "node 1 is claimed by 0 of its descendants". The previous epoch's
// keys are gone at that point, so there is nothing the caller can do with what it is left
// holding, and task 20 would have had to know to throw the tree away.
//
// The failure positions are DERIVED rather than picked. A census run counts how many fallible
// provider calls one commit makes, and the sweep then fails each of them in turn, so a call
// this operation gains or loses moves the sweep with it. On top of that sits the one failure no
// provider fault can produce -- a signature key of the wrong length, which is refused inside
// the provider rather than by failing it -- because that is the exact shape the review found.
//
// The instrument is checked before it is used. Clone is what the snapshot is taken with and
// what the operation works on, so a Clone that normalised anything would make DeepEqual either
// blind or permanently red; requiring a fresh clone to compare equal to its original says which.
func TestCreateUpdatePathSecretsLeavesTheTreeExactlyAsItFoundItWhenItFails(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	fixture, members := newTestTree(t, crypto, 8)
	const at = 3
	sender := members[at].LeafIndex
	if !reflect.DeepEqual(fixture, fixture.Clone()) {
		t.Fatal("a fresh clone of the fixture does not compare equal to it, so DeepEqual cannot say whether a failed call changed a tree")
	}

	// the census: how many fallible provider calls a SUCCESSFUL commit makes, which is the
	// range the sweep covers. failAt of zero never matches, so nothing is injected here.
	census := &faultInjectingProvider{CryptoProvider: crypto}
	probe := fixture.Clone()
	if _, err := probe.CreateUpdatePathSecrets(census, sender, members[at].SignaturePriv, testGroupId()); err != nil {
		t.Fatalf("the census run failed: %v", err)
	}
	if census.calls == 0 {
		t.Fatal("a successful commit made no fallible provider call, so the sweep below has no failure to inject")
	}

	refused := 0
	for point := 1; point <= census.calls; point += 1 {
		tree := fixture.Clone()
		before := tree.Clone()
		faulty := &faultInjectingProvider{CryptoProvider: crypto, failAt: point}
		plan, err := tree.CreateUpdatePathSecrets(faulty, sender, members[at].SignaturePriv, testGroupId())
		if err == nil {
			t.Errorf("failing provider call %d of %d was accepted and answered a plan over %d nodes; a fault the operation swallows is one it built a commit on top of",
				point, census.calls, len(plan.Path))
			continue
		}
		if !errors.Is(err, errInjectedProviderFault) {
			t.Errorf("failing provider call %d of %d answered %v, which is not the injected fault", point, census.calls, err)
		}
		refused += 1
		if !reflect.DeepEqual(tree, before) {
			t.Errorf("failing provider call %d of %d left the caller's tree changed; a commit that answers an error must be a no-op, because the epoch it half-installed cannot be undone",
				point, census.calls)
		}
	}
	if refused != census.calls {
		t.Errorf("%d of the %d fallible provider calls were refused; the sweep is meant to reach every one", refused, census.calls)
	}

	// the failure the injection cannot make, which is the one the review actually found: a
	// signature private key that does not match the ciphersuite, refused INSIDE SignWithLabel
	// and therefore after the whole mutation has happened
	tree := fixture.Clone()
	before := tree.Clone()
	wanted := treeHashOf(t, crypto, before)
	if _, err := tree.CreateUpdatePathSecrets(crypto, sender, SignaturePrivateKey{1, 2, 3}, testGroupId()); err == nil {
		t.Fatal("a signature private key of three octets was accepted, so this half of the test asserts nothing")
	}
	if !reflect.DeepEqual(tree, before) {
		t.Error("a commit refused for a signature key that does not match the ciphersuite left the caller's tree changed")
	}
	// spelled again at the two boundaries a caller actually reads, because those are what the
	// next epoch is built out of
	if got := treeHashOf(t, crypto, tree); !bytes.Equal(got, wanted) {
		t.Errorf("the tree hash moved from %x to %x across a commit that answered an error, so the caller would bind the next epoch to a tree no commit produced",
			wanted, got)
	}
	if err := tree.VerifyParentHashes(crypto); err != nil {
		t.Errorf("a commit that answered an error left the caller's tree failing section 7.9.2: %v", err)
	}
	t.Logf("%d fallible provider calls in one commit, every one of them refused and every one of them a no-op", census.calls)
}

// TestCreateUpdatePathSecretsTellsABlankLeafApartFromAnIndexOutsideTheTree is the split the
// review asked for while the sentinel was still cheap to move.
//
// RatchetTree.Leaf answers nil for a leaf index past the width and for an occupied position
// that has been blanked alike, and a body that let that nil decide answered
// ErrLeafIndexOutOfRange for both. The two callers are opposite: one computed an index wrong
// and repairs it by recomputing one, the other is a member committing from a slot the group
// REMOVED, whose index was right the whole time and whose only repair is to rejoin. Telling the
// second to check its index sends it to look at the one thing that is not the problem.
//
// The blank positions are derived from the tree rather than picked -- every member of an eight
// member tree is blanked in turn -- because which leaf indices are blankable is a property of
// the tree and not of a fixture. The out of range half sweeps from the first index past the
// width, which is the boundary, rather than a number chosen to be obviously too large.
//
// The exclusivity is the half with teeth. The two sentinels are useless if either answers for
// the other, so each refusal is required to match its own and to NOT match the other's, which
// is what a wrap between them would break.
func TestCreateUpdatePathSecretsTellsABlankLeafApartFromAnIndexOutsideTheTree(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	fixture, members := newTestTree(t, crypto, 8)
	width := uint32(fixture.LeafWidth())
	blanked, outside := 0, 0
	for at := uint32(0); at < width; at += 1 {
		tree := fixture.Clone()
		sender := LeafIndex(at)
		if err := tree.Blank(sender.NodeIndex()); err != nil {
			t.Fatalf("Blank(leaf %d): %v", sender, err)
		}
		_, err := tree.CreateUpdatePathSecrets(crypto, sender, members[at].SignaturePriv, testGroupId())
		if !errors.Is(err, ErrLeafBlank) {
			t.Errorf("a commit from blanked leaf %d, which is inside an %d leaf tree, answered %v; want %v",
				sender, width, err, ErrLeafBlank)
		}
		if errors.Is(err, ErrLeafIndexOutOfRange) {
			t.Errorf("a commit from blanked leaf %d answered %v, which also matches ErrLeafIndexOutOfRange; the member is being told to fix an index that was correct",
				sender, err)
		}
		blanked += 1
	}
	for _, sender := range []LeafIndex{LeafIndex(width), LeafIndex(width + 1), LeafIndex(width + 97)} {
		tree := fixture.Clone()
		_, err := tree.CreateUpdatePathSecrets(crypto, sender, members[0].SignaturePriv, testGroupId())
		if !errors.Is(err, ErrLeafIndexOutOfRange) {
			t.Errorf("a commit from leaf %d, which is outside an %d leaf tree, answered %v; want %v",
				sender, width, err, ErrLeafIndexOutOfRange)
		}
		if errors.Is(err, ErrLeafBlank) {
			t.Errorf("a commit from leaf %d, which is outside the tree, answered %v, which also matches ErrLeafBlank; the caller is being told a position exists and is empty when it does not exist",
				sender, err)
		}
		outside += 1
	}
	if blanked == 0 || outside == 0 {
		t.Fatalf("the sweep made %d blank-leaf calls and %d out of range calls; a zero in either is an arm this test did not reach", blanked, outside)
	}
	t.Logf("%d blanked leaves and %d indices past the width, each answered by its own sentinel and by neither the other", blanked, outside)
}

// ---------------------------------------------------------------------------
// task 19: the UpdatePath wire types
// ---------------------------------------------------------------------------

// The three levels of length prefix are what makes this codec different from every other one in
// this package, and two of the shapes that got through elsewhere are exactly the shapes nesting
// hides:
//
// A SYMMETRIC FIELD ORDER SWAP -- two fields exchanged in both halves -- round trips perfectly,
// re-encodes byte exact, and is byte exact against the published corpus too, because the corpus
// check only ever compares what this implementation decoded against what it re-encoded. The only
// thing that separates the two orders is a statement of the encoding written from the RFC without
// reference to the code, which is what the hand derived goldens below are.
//
// A FIELD DROPPED FROM BOTH HALVES round trips byte exact while being lost, because the decoder
// never reads what the encoder never wrote. Only a comparison of the decoded VALUE against the
// original catches it, never a comparison of bytes against re-encoded bytes.
//
// The third shape is this file's own and is NOT a codec property at all: a ciphertext count that
// does not match the resolution the node was built for. The codec is handed bytes and has no
// tree, so it cannot check it; the relation is stated here against the published corpus, so that
// this layer and task 22's decrypt at least agree about what the relation is.

// testUpdatePathFixture is the value every golden below is compared against.
//
// Every octet string in it is DIFFERENT from every other one, and the two fields of a
// ciphertext have different LENGTHS as well -- 32 against 48 -- which is what makes a swap of
// kem_output and ciphertext visible in the bytes at all. Two nodes, the first carrying two
// ciphertexts and the second carrying none, so that the vector prefix is exercised at both a one
// octet and a two octet width and an empty nested vector is covered by the same golden.
func testUpdatePathFixture() *UpdatePath {
	leaf := testLeafNodeTemplate()
	leaf.LeafNodeSource = LeafNodeSourceCommit
	leaf.ParentHash = repeatByte(0x44, 32)
	return &UpdatePath{
		LeafNode: *leaf,
		Nodes: []UpdatePathNode{
			{
				EncryptionKey: HpkePublicKey(repeatByte(0x01, 32)),
				EncryptedPathSecret: []HpkeCiphertext{
					{KemOutput: repeatByte(0x02, 32), Ciphertext: repeatByte(0x03, 48)},
					{KemOutput: repeatByte(0x04, 32), Ciphertext: repeatByte(0x05, 48)},
				},
			},
			{
				EncryptionKey:       HpkePublicKey(repeatByte(0x06, 32)),
				EncryptedPathSecret: []HpkeCiphertext{},
			},
		},
	}
}

// testUpdatePathDecodedForm is what a decode of that fixture must produce as a VALUE.
//
// It differs from the fixture in exactly one way, and it is the leaf's: the template carries a
// lifetime under a commit source, which section 7.2's select does not encode, so a correct
// decode answers the zero lifetime. leaf_node_test.go's decodedFormOf derives that from the
// variant table rather than from a case written here, so a fourth source is handled by this
// comparison on the commit that declares it.
func testUpdatePathDecodedForm(t *testing.T) *UpdatePath {
	t.Helper()
	out := testUpdatePathFixture()
	out.LeafNode = *decodedFormOf(t, &out.LeafNode)
	return out
}

// ---------------------------------------------------------------------------
// the hand derived goldens
// ---------------------------------------------------------------------------

// handDerivedHpkeCiphertext is one HPKECiphertext of the fixture, written out from RFC 9420
// section 6.1 rather than read back through the encoder:
//
//	kem_output<V>    32 octets -> 20 <kem>*32                              33
//	ciphertext<V>    48 octets -> 30 <ct>*48                               49
//	                                                                     ----
//	                                                                       82
//
// Both prefixes are the ONE octet form, because section 2.1.2 gives lengths 0..63 a single octet
// whose top two bits are zero: 32 is 0x20 and 48 is 0x30 with nothing else added. The two
// lengths are deliberately different, so that a codec writing the two fields in the other order
// produces 30 <ct>*48 20 <kem>*32, which is not these bytes.
func handDerivedHpkeCiphertext(kem byte, ct byte) []byte {
	return joinBytes([]byte{0x20}, repeatByte(kem, 32), []byte{0x30}, repeatByte(ct, 48))
}

// handDerivedUpdatePathNodeWithCiphertexts is the fixture's first node:
//
//	encryption_key<V>          32 octets      -> 20 01*32                  33
//	encrypted_path_secret<V>   2 x 82 = 164   -> 40 a4 <164 octets>       166
//	                                                                     ----
//	                                                                      199
//
// The vector prefix is the TWO octet form and the value is the BODY LENGTH IN OCTETS, not the
// element count. 164 is above 63 so section 2.1.2 gives it two octets with the prefix bits 0b01:
// 0x40 | (164 >> 8) = 0x40, then 164 & 0xff = 0xa4. An encoder writing the element count would
// write the single octet 0x02 here, an encoder using the four octet framing would write
// 0x800000a4, and neither is visible to any round trip because this implementation would read
// back whatever it wrote.
func handDerivedUpdatePathNodeWithCiphertexts() []byte {
	return joinBytes(
		[]byte{0x20}, repeatByte(0x01, 32),
		[]byte{0x40, 0xa4},
		handDerivedHpkeCiphertext(0x02, 0x03),
		handDerivedHpkeCiphertext(0x04, 0x05),
	)
}

// handDerivedUpdatePathNodeWithNone is the fixture's second node:
//
//	encryption_key<V>          32 octets      -> 20 06*32                  33
//	encrypted_path_secret<V>   empty          -> 00                         1
//	                                                                     ----
//	                                                                       34
//
// The empty vector is the single zero octet and nothing else, which is also what a nil vector
// encodes to: the wire format has no representation for "absent".
func handDerivedUpdatePathNodeWithNone() []byte {
	return joinBytes([]byte{0x20}, repeatByte(0x06, 32), []byte{0x00})
}

// handDerivedUpdatePathGolden is the whole structure of RFC 9420 section 7.6:
//
//	leaf_node       a commit source leaf, leaf_node_test.go's own derivation       192
//	nodes<V>        199 + 34 = 233 octets of body -> 40 e9 <233 octets>            235
//	                                                                             ----
//	                                                                              427
//
// The leaf comes from handDerivedLeafNodeGolden, which is derived from section 7.2 in the file
// that owns that structure and is checked against its own arithmetic there. Reusing it rather
// than re-deriving it here is deliberate: two hand derivations of one structure drift, and the
// one that drifted would be the one nothing else reads.
//
// 233 is above 63, so its prefix is the two octet form again: 0x40 | (233 >> 8) = 0x40, then
// 233 & 0xff = 0xe9.
func handDerivedUpdatePathGolden() []byte {
	return joinBytes(
		handDerivedLeafNodeGolden(LeafNodeSourceCommit),
		[]byte{0x40, 0xe9},
		handDerivedUpdatePathNodeWithCiphertexts(),
		handDerivedUpdatePathNodeWithNone(),
	)
}

// The arithmetic of the comments above, stated separately so that a derivation edited without
// its comment fails rather than quietly redefining what it is compared to. This is
// leaf_node_test.go's handDerivedLeafNodeSizes at three levels instead of one.
const (
	handDerivedHpkeCiphertextSize          = 82
	handDerivedUpdatePathNodeWithCtSize    = 199
	handDerivedUpdatePathNodeWithNoneSize  = 34
	handDerivedUpdatePathSize              = 427
	handDerivedUpdatePathLeafSize          = 192
	handDerivedUpdatePathNodesRegionLength = 233
)

// TestTheUpdatePathHandDerivationsAgreeWithTheirOwnArithmetic runs before the goldens are used
// for anything, so that a derivation which no longer holds the octets its comment counts fails
// here rather than pinning the encoder to whatever it happens to produce.
func TestTheUpdatePathHandDerivationsAgreeWithTheirOwnArithmetic(t *testing.T) {
	for _, one := range []struct {
		name string
		got  int
		want int
	}{
		{"HPKECiphertext", len(handDerivedHpkeCiphertext(0x02, 0x03)), handDerivedHpkeCiphertextSize},
		{"UpdatePathNode with two ciphertexts", len(handDerivedUpdatePathNodeWithCiphertexts()), handDerivedUpdatePathNodeWithCtSize},
		{"UpdatePathNode with none", len(handDerivedUpdatePathNodeWithNone()), handDerivedUpdatePathNodeWithNoneSize},
		{"the commit leaf", len(handDerivedLeafNodeGolden(LeafNodeSourceCommit)), handDerivedUpdatePathLeafSize},
		{"UpdatePath", len(handDerivedUpdatePathGolden()), handDerivedUpdatePathSize},
	} {
		if one.got != one.want {
			t.Errorf("the hand derivation of %s is %d octets and the arithmetic in its comment says %d",
				one.name, one.got, one.want)
		}
	}
	// the two nested totals, stated as the sums the prefixes above declare rather than as two
	// more constants: a prefix that says one number while the body holds another is the exact
	// defect a golden built out of the same expression on both sides cannot see.
	if got := handDerivedUpdatePathNodeWithCtSize + handDerivedUpdatePathNodeWithNoneSize; got != handDerivedUpdatePathNodesRegionLength {
		t.Errorf("the two nodes are %d octets and the nodes<V> prefix in the golden declares %d",
			got, handDerivedUpdatePathNodesRegionLength)
	}
	if got := handDerivedUpdatePathLeafSize + 2 + handDerivedUpdatePathNodesRegionLength; got != handDerivedUpdatePathSize {
		t.Errorf("the leaf, the two octet prefix and the nodes region are %d octets and the whole derivation says %d",
			got, handDerivedUpdatePathSize)
	}
}

// TestHpkeCiphertextMarshalMatchesTheHandDerivedGolden is the field order and prefix width pin
// for the innermost of the three structures, and it is the only test in this file that a
// kem_output and ciphertext exchanged in BOTH halves does not survive.
func TestHpkeCiphertextMarshalMatchesTheHandDerivedGolden(t *testing.T) {
	in := &HpkeCiphertext{KemOutput: repeatByte(0x02, 32), Ciphertext: repeatByte(0x03, 48)}
	want := handDerivedHpkeCiphertext(0x02, 0x03)
	encoded, err := syntax.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Errorf("Marshal =\n %x\nwant\n %x", encoded, want)
	}
	out := &HpkeCiphertext{}
	if err := syntax.Unmarshal(want, out); err != nil {
		t.Fatalf("Unmarshal the golden: %v", err)
	}
	// the whole value and not the two lengths: a decoder that put the kem output in the
	// ciphertext field agrees about both lengths in every fixture where they are equal, and
	// this package's real ciphertexts are 32 and 48 only by accident of the plaintext.
	if !reflect.DeepEqual(out, in) {
		t.Errorf("the golden decoded to kem_output %x ciphertext %x, want %x and %x",
			out.KemOutput, out.Ciphertext, in.KemOutput, in.Ciphertext)
	}
}

// TestUpdatePathNodeMarshalMatchesTheHandDerivedGoldens is the same pin one level out, over both
// shapes the fixture holds: a node whose ciphertext vector needs the two octet prefix, and one
// whose empty vector needs the single zero octet.
func TestUpdatePathNodeMarshalMatchesTheHandDerivedGoldens(t *testing.T) {
	fixture := testUpdatePathFixture()
	for at, want := range [][]byte{
		handDerivedUpdatePathNodeWithCiphertexts(),
		handDerivedUpdatePathNodeWithNone(),
	} {
		in := fixture.Nodes[at]
		encoded, err := syntax.Marshal(&in)
		if err != nil {
			t.Fatalf("node %d: Marshal: %v", at, err)
		}
		if !bytes.Equal(encoded, want) {
			t.Errorf("node %d: Marshal =\n %x\nwant\n %x", at, encoded, want)
		}
		out := &UpdatePathNode{}
		if err := syntax.Unmarshal(want, out); err != nil {
			t.Fatalf("node %d: Unmarshal the golden: %v", at, err)
		}
		if !reflect.DeepEqual(out, &in) {
			t.Errorf("node %d: the golden decoded to %+v, want %+v", at, out, in)
		}
	}
}

// TestUpdatePathMarshalMatchesTheHandDerivedGolden is the pin over the whole three level
// structure: the leaf, the nodes vector's byte length prefix, and every nested prefix under it.
func TestUpdatePathMarshalMatchesTheHandDerivedGolden(t *testing.T) {
	want := handDerivedUpdatePathGolden()
	encoded, err := syntax.Marshal(testUpdatePathFixture())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Errorf("Marshal =\n %x\nwant\n %x", encoded, want)
	}
	out := &UpdatePath{}
	if err := syntax.Unmarshal(want, out); err != nil {
		t.Fatalf("Unmarshal the golden: %v", err)
	}
	if !reflect.DeepEqual(out, testUpdatePathDecodedForm(t)) {
		t.Errorf("the golden decoded to a value the fixture does not describe:\ngot  %s\nwant %s",
			describeUpdatePath(out), describeUpdatePath(testUpdatePathDecodedForm(t)))
	}
}

// describeUpdatePath spells a path out far enough that a failure above says which of the three
// levels moved, since %+v over a structure of slices of slices prints addresses for the parts
// that matter.
func describeUpdatePath(path *UpdatePath) string {
	out := fmt.Sprintf("leaf{%s} nodes=%d", describeLeafNode(&path.LeafNode), len(path.Nodes))
	for at, node := range path.Nodes {
		out += fmt.Sprintf(" | node %d key=%x ciphertexts=%d", at, node.EncryptionKey, len(node.EncryptedPathSecret))
		for i, ct := range node.EncryptedPathSecret {
			out += fmt.Sprintf(" [%d kem=%x ct=%x]", i, ct.KemOutput, ct.Ciphertext)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// the round trip, as a value rather than as bytes
// ---------------------------------------------------------------------------

// TestUpdatePathRoundTripsAsAWholeValue is the plan's round trip with the comparison it was
// missing.
//
// The plan compared the re-encoded bytes, the node count, the two ciphertext counts and the
// leaf's parent hash. A codec that dropped the kem output from BOTH halves satisfies every one
// of those -- the bytes it does not write it does not read, so the re-encode is exact and every
// count is right -- while losing a field the whole protocol depends on. reflect.DeepEqual
// against the value that went in is what closes that, and it is the only assertion here that
// could not be satisfied by an encoder and a decoder agreeing with each other about the wrong
// thing.
func TestUpdatePathRoundTripsAsAWholeValue(t *testing.T) {
	in := testUpdatePathFixture()
	encoded, err := syntax.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out := &UpdatePath{}
	if err := syntax.Unmarshal(encoded, out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(out, testUpdatePathDecodedForm(t)) {
		t.Fatalf("the round trip did not preserve the value:\ngot  %s\nwant %s",
			describeUpdatePath(out), describeUpdatePath(testUpdatePathDecodedForm(t)))
	}
	reencoded, err := syntax.Marshal(out)
	if err != nil {
		t.Fatalf("re-Marshal: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("re-encode differs:\ngot  %x\nwant %x", reencoded, encoded)
	}
}

// TestANilAndAnEmptyCiphertextVectorAreOneUpdatePathOnTheWire states the one place the Go value
// and the wire disagree, so that a caller comparing two paths as values knows which of the two
// forms a decode answers.
//
// The wire has no representation for "absent", so both encode to the single zero octet; decoding
// answers the empty non nil slice, because syntax.ReadVector never answers nil. A path built by
// hand with a nil vector therefore does not survive a round trip under DeepEqual even though its
// encoding does, which is the same statement leaf_node.go makes about its own vectors.
func TestANilAndAnEmptyCiphertextVectorAreOneUpdatePathOnTheWire(t *testing.T) {
	withNil := testUpdatePathFixture()
	withNil.Nodes[1].EncryptedPathSecret = nil
	withEmpty := testUpdatePathFixture()
	fromNil, err := syntax.Marshal(withNil)
	if err != nil {
		t.Fatalf("Marshal the nil form: %v", err)
	}
	fromEmpty, err := syntax.Marshal(withEmpty)
	if err != nil {
		t.Fatalf("Marshal the empty form: %v", err)
	}
	if !bytes.Equal(fromNil, fromEmpty) {
		t.Fatalf("a nil ciphertext vector encoded to\n %x\nand an empty one to\n %x", fromNil, fromEmpty)
	}
	out := &UpdatePath{}
	if err := syntax.Unmarshal(fromNil, out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Nodes[1].EncryptedPathSecret == nil {
		t.Fatal("the decode answered a nil ciphertext vector, so an empty vector and an absent one are two values in Go for one encoding")
	}
	// and the whole path, which is where a nil nodes vector would show: a path with no nodes
	// at all is what a commit in a group of one publishes.
	alone := &UpdatePath{LeafNode: testUpdatePathFixture().LeafNode}
	encoded, err := syntax.Marshal(alone)
	if err != nil {
		t.Fatalf("Marshal the single member path: %v", err)
	}
	decoded := &UpdatePath{}
	if err := syntax.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("Unmarshal the single member path: %v", err)
	}
	if decoded.Nodes == nil || len(decoded.Nodes) != 0 {
		t.Fatalf("a path with no nodes decoded to %v, want an empty non nil vector", decoded.Nodes)
	}
}

// ---------------------------------------------------------------------------
// what the decoder must refuse
// ---------------------------------------------------------------------------

// TestUpdatePathRejectsTrailingBytes is the plan's refusal, plus the truncation sweep it stated
// for one length only.
//
// The trailing byte half is the one that matters most in this package and is worth the sentence:
// MLS signs over serialized forms, so a decoder that accepts a tail accepts two encodings of one
// object, which is a signature bypass primitive rather than a leniency. It is enforced by
// syntax.Unmarshal's join against Done rather than by anything in this file, and this is what
// says so.
//
// The truncation half runs over EVERY prefix of a valid encoding rather than the one the plan
// cut. There are three levels of length prefix here and a truncation inside any one of them is a
// different code path -- a varint that runs out, a declared length past the end of the input, a
// nested region that ends mid element -- and cutting only the last octet exercises exactly one
// of them.
func TestUpdatePathRejectsTrailingBytes(t *testing.T) {
	encoded, err := syntax.Marshal(testUpdatePathFixture())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := syntax.Unmarshal(append(bytes.Clone(encoded), 0x00), &UpdatePath{}); !errors.Is(err, syntax.ErrTrailingBytes) {
		t.Fatalf("trailing byte err = %v, want ErrTrailingBytes", err)
	}
	refused := 0
	for cut := 0; cut < len(encoded); cut += 1 {
		if err := syntax.Unmarshal(encoded[:cut], &UpdatePath{}); err == nil {
			t.Errorf("Unmarshal of the first %d octets of a %d octet path returned no error", cut, len(encoded))
			continue
		}
		refused += 1
	}
	if refused != len(encoded) {
		t.Fatalf("%d of %d truncations were refused", refused, len(encoded))
	}
	t.Logf("%d truncations of a %d octet path all refused", refused, len(encoded))
}

// TestUpdatePathRefusesANestedVectorThatOverrunsItsParentRegion is the failure three levels of
// length prefix make possible and one level does not: an inner vector that declares more octets
// than the region enclosing it holds, while still declaring fewer than the whole input has left.
//
// Those two numbers are the whole test. A decoder that validated a declared length against the
// bytes remaining in the INPUT rather than in the enclosing region accepts this and reads the
// next node's octets as part of this node's ciphertext vector -- a structure the sender never
// sent, assembled out of its own neighbours, and byte exact on re-encode because the decoder
// would write back what it read. The fixture is built so that the two bounds disagree, and the
// disagreement is asserted before the refusal is required: without that, this test passes
// against exactly the decoder it exists to forbid.
func TestUpdatePathRefusesANestedVectorThatOverrunsItsParentRegion(t *testing.T) {
	leaf := handDerivedLeafNodeGolden(LeafNodeSourceCommit)
	first := handDerivedUpdatePathNodeWithCiphertexts()
	second := handDerivedUpdatePathNodeWithNone()

	// the nodes<V> region is cut down to the first node alone -- 199 octets, prefix 40 c7 --
	// and the second node's octets are left in the buffer after it. So the input still has
	// bytes the region does not.
	nodesRegion := handDerivedUpdatePathNodeWithCtSize
	if nodesRegion != 199 {
		t.Fatalf("the first node is %d octets and this fixture's prefix declares 199", nodesRegion)
	}
	// inside that region: 33 octets of encryption_key, then the ciphertext vector's prefix.
	// The vector's true body is 164 octets and the region has 164 left once the key and the
	// prefix are read, so a declared 190 overruns the region by 26 and is still 8 short of
	// what the buffer holds.
	const declared = 190
	const trueBody = 164
	overrun := joinBytes(
		leaf,
		[]byte{0x40, 0xc7},
		first[:33],
		[]byte{0x40, byte(declared)},
		first[35:],
		second,
	)
	if len(overrun) != len(handDerivedUpdatePathGolden()) {
		t.Fatalf("the fixture is %d octets and the golden it was built from is %d, so the surgery moved something",
			len(overrun), len(handDerivedUpdatePathGolden()))
	}
	afterInnerPrefix := len(leaf) + 2 + 33 + 2
	if remainingInInput := len(overrun) - afterInnerPrefix; declared > remainingInInput {
		t.Fatalf("the fixture declares %d octets and the input has %d left, so a decoder bounded by the input alone would refuse this too and the test would prove nothing",
			declared, remainingInInput)
	}
	if declared <= trueBody {
		t.Fatalf("the fixture declares %d octets and the enclosing region has %d left, so nothing is overrun",
			declared, trueBody)
	}
	if err := syntax.Unmarshal(overrun, &UpdatePath{}); !errors.Is(err, syntax.ErrLengthExceedsInput) {
		t.Fatalf("a ciphertext vector declaring %d octets inside a %d octet region gave err = %v, want ErrLengthExceedsInput",
			declared, trueBody, err)
	}
	// the control: the same surgery with the true length restored is a well formed node
	// followed by a tail, so it must be refused for the OTHER reason. Without it a decoder
	// that refused every input this test builds would pass the assertion above.
	honest := joinBytes(leaf, []byte{0x40, 0xc7}, first, second)
	if err := syntax.Unmarshal(honest, &UpdatePath{}); !errors.Is(err, syntax.ErrTrailingBytes) {
		t.Fatalf("the control, whose only fault is the second node sitting outside the nodes region, gave err = %v, want ErrTrailingBytes", err)
	}
}

// TestUpdatePathDecodeIsStagedAndDoesNotWriteThroughAFailure states the two properties
// leaf_node.go argues for, at the level where they are load bearing.
//
// A refused decode must leave the receiver as it found it. UpdatePath decodes a leaf and then a
// vector, and the leaf is the half that carries a signature, an encryption key and a parent
// hash, so a body that wrote the leaf into the receiver before reading the vector hands a caller
// which logged the error rather than returning it a path assembled out of two different
// messages -- one whose leaf came from the attacker's bytes and whose nodes are the previous
// epoch's.
//
// And a receiver decoded into twice must answer the second encoding, not a mixture.
func TestUpdatePathDecodeIsStagedAndDoesNotWriteThroughAFailure(t *testing.T) {
	full, err := syntax.Marshal(testUpdatePathFixture())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	receiver := &UpdatePath{}
	if err := syntax.Unmarshal(full, receiver); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	before := describeUpdatePath(receiver)

	// the truncations are of a DIFFERENT path from the one the receiver already holds, and
	// that is the whole of what makes a write through observable. This test was first
	// written sweeping truncations of the receiver's OWN encoding and it could not fail:
	// LeafNode's own decode is staged, so a short leaf leaves the receiver untouched either
	// way, and once the leaf is complete an unstaged body writes a leaf identical to the one
	// already there. That version was measured against the unstaged body -- decode the leaf
	// into self.LeafNode, then read the vector -- and it passed. So the second path differs
	// in the leaf AND in the first node.
	other := testUpdatePathFixture()
	other.LeafNode.ParentHash = repeatByte(0x55, 32)
	other.Nodes[0].EncryptionKey = HpkePublicKey(repeatByte(0x66, 32))
	otherEncoded, err := syntax.Marshal(other)
	if err != nil {
		t.Fatalf("Marshal the second path: %v", err)
	}
	if describeUpdatePath(other) == before {
		t.Fatal("the two paths describe identically, so one decoded over the other would be invisible here")
	}
	if len(otherEncoded) <= handDerivedUpdatePathLeafSize {
		t.Fatalf("the second path is %d octets and its leaf alone is %d, so no truncation of it reaches the nodes vector -- which is the only place an unstaged body writes a complete leaf and then fails",
			len(otherEncoded), handDerivedUpdatePathLeafSize)
	}

	// every truncation, so that a failure at any of the three levels is covered rather than
	// the one the last octet happens to reach.
	for cut := 0; cut < len(otherEncoded); cut += 1 {
		if err := syntax.Unmarshal(otherEncoded[:cut], receiver); err == nil {
			t.Fatalf("the first %d octets decoded without error", cut)
		}
		if got := describeUpdatePath(receiver); got != before {
			t.Fatalf("a refused decode of the first %d octets of another path wrote through to the receiver:\ngot  %s\nwant %s",
				cut, got, before)
		}
	}

	// the second decode into the same receiver: a path with no nodes at all, which is what a
	// group of one publishes. A body that appended to what it found, or that left the previous
	// path's nodes standing, answers something no encoding describes.
	alone := &UpdatePath{LeafNode: testUpdatePathFixture().LeafNode}
	encoded, err := syntax.Marshal(alone)
	if err != nil {
		t.Fatalf("Marshal the single member path: %v", err)
	}
	if err := syntax.Unmarshal(encoded, receiver); err != nil {
		t.Fatalf("Unmarshal the single member path: %v", err)
	}
	fresh := &UpdatePath{}
	if err := syntax.Unmarshal(encoded, fresh); err != nil {
		t.Fatalf("Unmarshal into a fresh value: %v", err)
	}
	if !reflect.DeepEqual(receiver, fresh) {
		t.Fatalf("a receiver decoded into twice answered\n %s\nand a fresh one answered\n %s",
			describeUpdatePath(receiver), describeUpdatePath(fresh))
	}

	// the same property one level down, which nothing above can observe: syntax.ReadVector
	// builds a fresh HpkeCiphertext for every element, so a ciphertext decode that assigned
	// as it read is invisible through an UpdatePath. It is visible to a caller decoding into
	// a value it already holds, and the framing plan's Welcome is that caller.
	held := &HpkeCiphertext{KemOutput: repeatByte(0x88, 8), Ciphertext: repeatByte(0x99, 8)}
	kept := *held
	one := handDerivedHpkeCiphertext(0x02, 0x03)
	for cut := 0; cut < len(one); cut += 1 {
		if err := syntax.Unmarshal(one[:cut], held); err == nil {
			t.Fatalf("the first %d octets of a ciphertext decoded without error", cut)
		}
		if !reflect.DeepEqual(held, &kept) {
			t.Fatalf("a refused ciphertext decode of the first %d octets wrote through: kem_output %x ciphertext %x, want %x and %x",
				cut, held.KemOutput, held.Ciphertext, kept.KemOutput, kept.Ciphertext)
		}
	}
}

// ---------------------------------------------------------------------------
// the seal and open adaptation
// ---------------------------------------------------------------------------

// TestSealAndOpenWithLabelRoundTrip is the plan's round trip: the pair agrees with itself, and
// neither a different context nor a different label opens what was sealed.
//
// The two refusals are the point rather than the round trip. A label and a context that were
// dropped on the way into the HPKE info still produce a ciphertext this same pair opens, so the
// only thing that can see the omission is a message sealed under one and opened under the other.
func TestSealAndOpenWithLabelRoundTrip(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	priv, pub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	ct, err := SealWithLabel(crypto, pub, "Welcome", []byte("context"), []byte("secret"))
	if err != nil {
		t.Fatalf("SealWithLabel: %v", err)
	}
	if len(ct.KemOutput) == 0 || len(ct.Ciphertext) == 0 {
		t.Fatalf("SealWithLabel produced an empty ciphertext")
	}
	got, err := OpenWithLabel(crypto, priv, "Welcome", []byte("context"), ct)
	if err != nil {
		t.Fatalf("OpenWithLabel: %v", err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("OpenWithLabel = %q, want %q", got, "secret")
	}
	if _, err := OpenWithLabel(crypto, priv, "Welcome", []byte("other"), ct); err == nil {
		t.Fatalf("the ciphertext opened under a different context")
	}
	if _, err := OpenWithLabel(crypto, priv, "GroupSecrets", []byte("context"), ct); err == nil {
		t.Fatalf("the ciphertext opened under a different label")
	}
	// the two halves of the structure are not interchangeable, which is the failure a
	// transposed adaptation produces and which the round trip above cannot see: it would seal
	// and open transposed values consistently.
	swapped := &HpkeCiphertext{KemOutput: ct.Ciphertext, Ciphertext: ct.KemOutput}
	if _, err := OpenWithLabel(crypto, priv, "Welcome", []byte("context"), swapped); err == nil {
		t.Fatal("a ciphertext whose two fields were exchanged still opened")
	}
	if _, err := OpenWithLabel(crypto, priv, "Welcome", []byte("context"), nil); !errors.Is(err, errNilHpkeCiphertext) {
		t.Fatalf("OpenWithLabel(nil ciphertext) = %v, want errNilHpkeCiphertext", err)
	}
}

// TestSealWithLabelPutsTheKemOutputAndTheCiphertextInTheirOwnFields is what separates the
// adaptation from a transposed one.
//
// EncryptWithLabel answers (kemOutput, ciphertext) and both are []byte, so a transposed
// assignment compiles and round trips through this same pair of functions perfectly. The
// LENGTHS are what tell them apart: RFC 9180 fixes the encapsulated key at the suite's Nenc, and
// the ciphertext is the plaintext plus the suite's Nt. Both numbers are read from the suite
// registry rather than written here, so a suite whose KEM or AEAD differs is covered by this on
// the commit that registers it.
func TestSealWithLabelPutsTheKemOutputAndTheCiphertextInTheirOwnFields(t *testing.T) {
	for _, suite := range registeredSuitesForUpdatePath(t) {
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("LookupSuite(%d): %v", suite, err)
		}
		crypto := mustProvider(t, suite)
		_, pub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
		if err != nil {
			t.Fatalf("DeriveKeyPair: %v", err)
		}
		// a plaintext whose length is neither Nenc nor Nenc plus Nt, so that the two fields
		// cannot be told apart by accident of the fixture.
		plaintext := repeatByte(0x77, 7)
		ct, err := SealWithLabel(crypto, pub, "Welcome", []byte("context"), plaintext)
		if err != nil {
			t.Fatalf("SealWithLabel: %v", err)
		}
		if len(ct.KemOutput) != params.Nenc {
			t.Errorf("%s: kem_output is %d octets, and the suite's Nenc is %d; the two results are transposed",
				params.Name, len(ct.KemOutput), params.Nenc)
		}
		if want := len(plaintext) + params.Nt; len(ct.Ciphertext) != want {
			t.Errorf("%s: ciphertext is %d octets, and the plaintext plus the suite's Nt is %d",
				params.Name, len(ct.Ciphertext), want)
		}
	}
}

// registeredSuitesForUpdatePath is every ciphersuite this package registers, derived off the
// registry rather than listed, so a third suite is swept by the sizes test above on the commit
// that registers it.
func registeredSuitesForUpdatePath(t *testing.T) []CipherSuite {
	t.Helper()
	suites := []CipherSuite{}
	for _, value := range sortedValues(registryConstantsOfType(t, "CipherSuite")) {
		suite := CipherSuite(value)
		if _, err := LookupSuite(suite); err != nil {
			continue
		}
		suites = append(suites, suite)
	}
	if len(suites) == 0 {
		t.Fatal("no registered ciphersuite was derived, so the sweep over them runs over nothing")
	}
	return suites
}

// ---------------------------------------------------------------------------
// the argument rule crypto_test.go's provider gates need for this file's structure
// ---------------------------------------------------------------------------

// providerHpkeCiphertextPerturbations moves an *HpkeCiphertext argument, one byte of one
// field at a time, for the provider gates in crypto_test.go.
//
// The rule lives beside the structure it moves rather than in that file's switch, which is
// where psk_test.go and leaf_node_test.go keep theirs: those gates walk every declaration of
// the package, and a structure declared here whose perturbation is written there is one whose
// rule stops matching when a field is added and says nothing about it.
//
// BOTH fields are moved, and that is the point rather than thoroughness. OpenWithLabel hands
// its two fields to two different parameters of DecryptWithLabel, so an adaptation that passed
// the kem output twice, or passed a constant for one of them, answers a refusal for every
// input and moves under one of these perturbations and not the other -- and a rule that moved
// only the first field would report the second as observed having never changed it.
//
// Each perturbation is a fresh structure over fresh arrays, so a moved value cannot write
// through into the base argument every other row of those gates is built from.
func providerHpkeCiphertextPerturbations(t *testing.T, operation string,
	parameter providerParameter, argument reflect.Value) []providerPerturbation {
	t.Helper()
	base := argument.Interface().(*HpkeCiphertext)
	moved := []providerPerturbation{}
	for _, field := range []struct {
		name string
		at   func(ct *HpkeCiphertext) *[]byte
	}{
		{name: "kem_output", at: func(ct *HpkeCiphertext) *[]byte { return &ct.KemOutput }},
		{name: "ciphertext", at: func(ct *HpkeCiphertext) *[]byte { return &ct.Ciphertext }},
	} {
		length := len(*field.at(base))
		if length == 0 {
			t.Fatalf("the base argument for %s.%s carries no %s, so perturbing that field changes nothing",
				operation, parameter.name, field.name)
		}
		for _, position := range perturbedPositions(length) {
			perturbed := &HpkeCiphertext{
				KemOutput:  bytes.Clone(base.KemOutput),
				Ciphertext: bytes.Clone(base.Ciphertext),
			}
			(*field.at(perturbed))[position] ^= 0xff
			moved = append(moved, providerPerturbation{
				where: fmt.Sprintf("byte %d of %d of the %s", position, length, field.name),
				value: reflect.ValueOf(perturbed),
			})
		}
	}
	if len(moved) == 0 {
		t.Fatalf("no perturbation was built for %s.%s, so that argument is called twice with one value and reported as observed",
			operation, parameter.name)
	}
	return moved
}

// ---------------------------------------------------------------------------
// the published corpus
// ---------------------------------------------------------------------------

// treekemUpdatePathVector is the other half of one entry of treekem.json: the tree an epoch
// started from, and the UpdatePath each member would publish committing over it.
//
// This is the only oracle in this file that is independent of this repository. Everything above
// compares this codec against a derivation the same reader wrote, which separates a swapped
// field order from a correct one but cannot separate this whole family of structures from a
// consistent misreading of section 7.6. The working group's implementations produced these
// octets.
type treekemUpdatePathVector struct {
	CipherSuite uint16                       `json:"cipher_suite"`
	RatchetTree string                       `json:"ratchet_tree"`
	UpdatePaths []treekemPublishedUpdatePath `json:"update_paths"`
}

type treekemPublishedUpdatePath struct {
	Sender     uint32 `json:"sender"`
	UpdatePath string `json:"update_path"`
}

// Transcriptions of what testdata/vectors/treekem.json holds at the pinned mlswg commit, for the
// suites this package implements. A decoder that stopped early, a filter that matched nothing and
// a loop that read a field that is not there all report exactly what a complete run reports
// without these.
const (
	treekemUpdatePathCount         = 124
	treekemUpdatePathNodeCount     = 330
	treekemUpdatePathCiphertexts   = 356
	treekemUpdatePathDeepNodeCount = 26
)

// TestEveryPublishedUpdatePathDecodesAndReEncodesExactly is the corpus half of the codec: 124
// UpdatePaths produced by other implementations, each decoded and re-encoded to the same octets.
//
// It catches the family the goldens above cannot: a prefix width, a field order or a nesting
// this reader transcribed consistently wrongly in both the code and the derivation. It does NOT
// catch a symmetric swap or a dropped field -- the comparison is against what this
// implementation re-encoded, so both are byte exact here -- which is why it is the third test of
// this codec and not the first.
//
// The two negative controls are what make the green run mean something: every published case
// agrees, so a decoder that accepted everything and one that checked everything produce
// identical runs, and only an input that must be refused separates them.
func TestEveryPublishedUpdatePathDecodesAndReEncodesExactly(t *testing.T) {
	paths, nodes, ciphertexts, deep := 0, 0, 0, 0
	forEachPublishedUpdatePath(t, func(at int, tree *RatchetTree, published treekemPublishedUpdatePath, raw []byte) {
		paths += 1
		decoded := &UpdatePath{}
		if err := syntax.Unmarshal(raw, decoded); err != nil {
			t.Fatalf("entry %d, sender %d: Unmarshal a published update path: %v", at, published.Sender, err)
		}
		reencoded, err := syntax.Marshal(decoded)
		if err != nil {
			t.Fatalf("entry %d, sender %d: Marshal: %v", at, published.Sender, err)
		}
		if !bytes.Equal(reencoded, raw) {
			t.Fatalf("entry %d, sender %d: re-encoding a published update path produced\n %x\nwant\n %x",
				at, published.Sender, reencoded, raw)
		}
		nodes += len(decoded.Nodes)
		for _, node := range decoded.Nodes {
			ciphertexts += len(node.EncryptedPathSecret)
			if len(node.EncryptedPathSecret) > 1 {
				deep += 1
			}
		}
		// the controls, per case rather than once. A tail must be refused, and so must the
		// same encoding one octet short; a decoder that answered nil for both satisfies every
		// line above.
		if err := syntax.Unmarshal(append(bytes.Clone(raw), 0x00), &UpdatePath{}); !errors.Is(err, syntax.ErrTrailingBytes) {
			t.Fatalf("entry %d, sender %d: a published path with one octet appended gave err = %v, want ErrTrailingBytes",
				at, published.Sender, err)
		}
		if err := syntax.Unmarshal(raw[:len(raw)-1], &UpdatePath{}); err == nil {
			t.Fatalf("entry %d, sender %d: a published path one octet short decoded without error",
				at, published.Sender)
		}
	})
	if paths != treekemUpdatePathCount || nodes != treekemUpdatePathNodeCount ||
		ciphertexts != treekemUpdatePathCiphertexts || deep != treekemUpdatePathDeepNodeCount {
		t.Fatalf("the run read %d published paths, %d nodes, %d ciphertexts and %d nodes carrying more than one ciphertext; want %d, %d, %d and %d",
			paths, nodes, ciphertexts, deep,
			treekemUpdatePathCount, treekemUpdatePathNodeCount, treekemUpdatePathCiphertexts, treekemUpdatePathDeepNodeCount)
	}
	t.Logf("%d published update paths, %d nodes, %d ciphertexts, %d nodes sealing to more than one resolution node",
		paths, nodes, ciphertexts, deep)
}

// TestEveryPublishedUpdatePathHasOneCiphertextPerResolutionNode states the relation this codec
// deliberately does not enforce, against the corpus, so that the layer which will enforce it and
// the layer which produces it agree about what it IS.
//
// Section 7.6 gives an UpdatePath one node per step of the sender's filtered direct path and one
// ciphertext per node of the resolution of that step's copath child. Neither number is available
// to a codec -- both are properties of a tree at an epoch -- so a path whose counts are wrong is
// perfectly well formed on the wire and is decoded here without complaint. The check belongs to
// the layer holding the tree, which is task 22's decrypt, and it is written down in this file
// because a cross-layer check both sides assume the other makes is a check nobody makes.
//
// Both numbers are recomputed from the published ratchet tree by this package's own tree walk,
// so this is also the first thing that compares that walk against another implementation's
// choice of resolution rather than against itself.
func TestEveryPublishedUpdatePathHasOneCiphertextPerResolutionNode(t *testing.T) {
	paths, checked, separated := 0, 0, 0
	forEachPublishedUpdatePath(t, func(at int, tree *RatchetTree, published treekemPublishedUpdatePath, raw []byte) {
		paths += 1
		decoded := &UpdatePath{}
		if err := syntax.Unmarshal(raw, decoded); err != nil {
			t.Fatalf("entry %d, sender %d: Unmarshal: %v", at, published.Sender, err)
		}
		targets, err := tree.EncryptionTargets(LeafIndex(published.Sender), nil)
		if err != nil {
			t.Fatalf("entry %d, sender %d: EncryptionTargets: %v", at, published.Sender, err)
		}
		if len(targets) != len(decoded.Nodes) {
			t.Fatalf("entry %d, sender %d: the published path carries %d nodes and the filtered direct path of that sender has %d steps",
				at, published.Sender, len(decoded.Nodes), len(targets))
		}
		for i := range targets {
			if len(targets[i]) != len(decoded.Nodes[i].EncryptedPathSecret) {
				t.Fatalf("entry %d, sender %d, node %d: the published node carries %d ciphertexts and the resolution it was built for holds %d nodes",
					at, published.Sender, i, len(decoded.Nodes[i].EncryptedPathSecret), len(targets[i]))
			}
			checked += 1
		}
		// the negative control, per case rather than once. Every published path agrees with
		// the resolution, so a comparison that read a count off the decoded path on BOTH
		// sides -- or that compared two numbers which are equal for every tree in this file
		// -- produces exactly the run a correct one produces. A resolution computed with one
		// leaf excluded is a DIFFERENT set of targets, and somewhere in the corpus it has to
		// disagree with what the sender published, or the comparison above is reading
		// something that cannot vary.
		wrong, err := tree.EncryptionTargets(LeafIndex(published.Sender), []LeafIndex{0})
		if err != nil {
			t.Fatalf("entry %d, sender %d: EncryptionTargets with an exclusion: %v", at, published.Sender, err)
		}
		for i := range wrong {
			if len(wrong[i]) != len(decoded.Nodes[i].EncryptedPathSecret) {
				separated += 1
			}
		}
	})
	if paths != treekemUpdatePathCount || checked != treekemUpdatePathNodeCount {
		t.Fatalf("the run compared %d published paths and %d nodes against the tree; want %d and %d",
			paths, checked, treekemUpdatePathCount, treekemUpdatePathNodeCount)
	}
	if separated == 0 {
		t.Fatal("no published node's ciphertext count differs from the resolution taken with one leaf excluded, so the comparison above is between two numbers that agree whatever the tree says")
	}
	t.Logf("%d published paths, %d nodes whose ciphertext count is the resolution size the tree gives, %d of them separated by the excluded-leaf control",
		paths, checked, separated)
}

// forEachPublishedUpdatePath is the shared walk of treekem.json's update_paths half, so that the
// two properties above run over provably the same set rather than over two filters that could
// drift.
//
// Entries at a suite this package does not implement are skipped rather than failed, matching
// TestEveryPublishedPathSecretDerivesTheNodeKeyItsRatchetTreeCarries above; the counts each
// caller asserts are what stop the skip from swallowing the file.
func forEachPublishedUpdatePath(t *testing.T, visit func(at int, tree *RatchetTree,
	published treekemPublishedUpdatePath, raw []byte)) {
	t.Helper()
	entries := LoadVectorFile(t, "treekem.json")
	if len(entries) != treekemEntryCount {
		t.Fatalf("treekem.json holds %d entries, want %d", len(entries), treekemEntryCount)
	}
	matched, declined := 0, 0
	for at, raw := range entries {
		var vector treekemUpdatePathVector
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("entry %d: %v", at, err)
		}
		if _, ok := implementedSuite(vector.CipherSuite); !ok {
			declined += 1
			continue
		}
		matched += 1
		tree, err := UnmarshalRatchetTree(MustHex(t, vector.RatchetTree))
		if err != nil {
			t.Fatalf("entry %d: UnmarshalRatchetTree: %v", at, err)
		}
		for _, published := range vector.UpdatePaths {
			visit(at, tree, published, MustHex(t, published.UpdatePath))
		}
	}
	if matched+declined != len(entries) {
		t.Fatalf("%d entries matched and %d were declined, and the file holds %d",
			matched, declined, len(entries))
	}
	if matched == 0 {
		t.Fatal("no entry of treekem.json is at a suite this package implements, so the sweep ran over nothing")
	}
}
