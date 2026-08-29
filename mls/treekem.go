// The path secret ladder of RFC 9420 section 7.4, the node key pair each rung derives, and the
// private half of the tree one member holds.
//
// The whole security argument of TreeKEM is an ASYMMETRY, and it is what the tests here are
// built against rather than the round trip. A member handed the path secret of a node can derive
// every node above it -- one DeriveSecret per level, all the way to the root -- and can derive
// nothing below it, because the derivation runs one way and there is no inverse. That is exactly
// what makes it safe to seal one secret to a whole subtree: everybody under the copath child
// learns the path from that node up and learns nothing about the sender's own leaf. A ladder
// that ran the other way would still be a ladder, would still round trip, would still produce
// keys that match at every node, and would hand every member of a subtree the secrets of the
// members below them.
//
// Two constructions and one container, and the thing that is deliberately NOT here:
//
// The leaf's own HPKE key pair is not derived from path_secret[0]. Everyone who can open the
// first ciphertext of an UpdatePath learns path_secret[0], so a leaf key derived from it would
// be the sender's leaf private key handed to the whole copath. It is sampled independently in
// task 19, and the difference is invisible to every test that only checks that keys match --
// both versions produce a private state whose public halves agree with the tree.
//
// path_secret[n] is one rung PAST the root, and it is not an off-by-one. RFC 9420 section 8.1
// makes the value beyond the last path node the commit secret of the epoch, so a caller that
// asked for exactly as many rungs as it has nodes would have to derive that one somewhere else
// -- which is one more place for the ladder to be written differently.
//
// Nothing here is serialized by this package. The state store seals a TreeKEMPrivate (spec A
// section 3.5), and it holds no codec of its own precisely so that the sealing is the only way
// it reaches a disk.
package mls

import (
	"crypto/subtle"
)

// DerivePathSecrets is the ladder of RFC 9420 section 7.4: path_secret[0] is the initial secret
// and path_secret[n] is DeriveSecret(path_secret[n-1], "path").
//
// count+1 values, one per node of the filtered direct path plus the rung beyond the root that
// section 8.1 makes the commit secret.
//
// A nil provider stops the process rather than answering. This construction has no error to
// return -- the interface the plan pins has none -- and with count of zero it never touches the
// provider at all, so the alternative to stopping is handing back a one entry ladder that was
// derived from nothing while looking exactly like one that was. That is the same choice
// crypto.go's Random and Expand make for the same reason: a value of the right shape that no
// provider produced is worse than a stop.
//
// The initial rung is CLONED. It is the caller's array -- in task 22 it is the plaintext an
// HpkeOpen just produced, and in task 18 it is fresh from Random -- and this answer outlives the
// call: it becomes the private state of an epoch. A ladder aliasing its caller's first rung is a
// group whose path secret changes when that buffer is reused.
func DerivePathSecrets(crypto CryptoProvider, initial []byte, count int) [][]byte {
	if crypto == nil {
		panic("mls: DerivePathSecrets was handed no crypto provider, and it has no way to say so")
	}
	out := make([][]byte, 0, count+1)
	out = append(out, cloneBytes(initial))
	for i := 0; i < count; i += 1 {
		out = append(out, crypto.DeriveSecret(out[len(out)-1], "path"))
	}
	return out
}

// DeriveNodeKeyPair is RFC 9420 section 7.4's node key: node_secret = DeriveSecret(path_secret,
// "node"), and the KEM key pair is derived from THAT rather than from the path secret itself.
//
// The intermediate secret is the whole of what this function is. Handing the path secret
// straight to DeriveKeyPair produces a key pair that is deterministic, that differs at every
// rung of the ladder, and that every member holding the path secret agrees on -- which is every
// property a round trip or a determinism test can see, and it is the wrong key at every node in
// the group. Only a comparison against an independent derivation separates the two, which is why
// the published TreeKEM corpus is what holds this and not a self-consistency check.
func DeriveNodeKeyPair(crypto CryptoProvider, pathSecret []byte) (HpkePrivateKey, HpkePublicKey, error) {
	if crypto == nil {
		return nil, nil, ErrNilCryptoProvider
	}
	return crypto.DeriveKeyPair(crypto.DeriveSecret(pathSecret, "node"))
}

// TreeKEMPrivate is what one member holds privately about the ratchet tree: its own leaf HPKE
// key, and the path secrets it has learned, keyed by the node each secret belongs to.
//
// Keyed by node and not by position in a path, which is the difference that matters when the
// tree changes shape. A member's filtered direct path gains and loses nodes as members are added
// and removed, so a slice indexed by depth silently renames every secret it holds the first time
// the path is filtered differently; a map keyed by the node index says what each secret is FOR.
type TreeKEMPrivate struct {
	LeafIndex      LeafIndex
	EncryptionPriv HpkePrivateKey
	PathSecrets    map[NodeIndex][]byte
}

// NewTreeKEMPrivate is the state of a member that holds its leaf key and no path secret yet,
// which is what a joiner has before it has processed a commit.
//
// The leaf private key is copied for DerivePathSecrets' reason: it is the caller's array and
// this state outlives the call.
func NewTreeKEMPrivate(i LeafIndex, encryptionPriv HpkePrivateKey) *TreeKEMPrivate {
	return &TreeKEMPrivate{
		LeafIndex:      i,
		EncryptionPriv: cloneBytes(encryptionPriv),
		PathSecrets:    map[NodeIndex][]byte{},
	}
}

// Clone is a deep copy, and the depth is the point.
//
// A commit is computed against a candidate epoch and may then be rejected -- by the delivery
// service, by a validation failure, or by losing a race with another member's commit -- so the
// caller works on a clone and keeps the original. A clone sharing one backing array with its
// parent is a rejected commit that has already written through to the state the group is still
// running on, and neither the map nor the leaf key may alias for that reason.
func (self *TreeKEMPrivate) Clone() *TreeKEMPrivate {
	out := NewTreeKEMPrivate(self.LeafIndex, self.EncryptionPriv)
	for x, secret := range self.PathSecrets {
		out.PathSecrets[x] = cloneBytes(secret)
	}
	return out
}

// NodePrivateKey answers the HPKE private key for a node if this member can derive one: its own
// leaf, or any node it holds a path secret for.
//
// A (value, ok) shape rather than ErrNoPathSecret, because "this member is not on that part of
// the path" is the ORDINARY condition for every member off the sender's path and not a fault.
// The sentinel belongs to the caller that was expecting to hold one -- task 22's decrypt, which
// has already found a ciphertext addressed to a node it cannot open -- and returning it from
// here would make every ordinary miss look like that failure.
//
// The own-leaf arm is checked first and answers the stored key rather than deriving one. The
// leaf key pair is NOT a rung of the ladder (see the file header), so there is no path secret it
// could be derived from, and a body that fell through to the map for it would answer "not
// available" for the one key every member always has.
//
// Both arms answer FRESH storage, and the own-leaf arm is the one that has to be made to. The
// derived arm hands back what DeriveKeyPair just produced and shares nothing by construction;
// the own-leaf arm is reading a field, and returning it directly hands the caller the state's
// live leaf key. That makes one function answer two different ownership contracts, which is a
// caller that cannot have a policy: this package ships zeroizeSecret for exactly this material
// and task 22 is the consumer, so "erase the private key when the decrypt is done" -- the right
// thing to do with every OTHER answer this function gives -- would erase the member's own leaf
// key and leave it unable to decrypt anything again, with every rung still deriving and nothing
// to point at. NewTreeKEMPrivate and Clone both copy this same array for the mirror of this
// reason; the exit door owes the entry doors their contract.
func (self *TreeKEMPrivate) NodePrivateKey(crypto CryptoProvider, x NodeIndex) (HpkePrivateKey, bool, error) {
	if crypto == nil {
		return nil, false, ErrNilCryptoProvider
	}
	if x == self.LeafIndex.NodeIndex() {
		return cloneBytes(self.EncryptionPriv), true, nil
	}
	secret, ok := self.PathSecrets[x]
	if !ok {
		return nil, false, nil
	}
	priv, _, err := DeriveNodeKeyPair(crypto, secret)
	if err != nil {
		return nil, false, err
	}
	return priv, true, nil
}

// Consistent checks that every path secret this member holds derives the public key the tree
// carries at that node, and that the tree has a leaf at this member's index at all.
//
// This is what catches a private state and a tree that have drifted an epoch apart, and it has
// to be checked rather than assumed because the symptom otherwise arrives one commit later and
// somewhere else: a member whose path secrets belong to the previous epoch derives private keys
// nobody's public half matches, decrypts nothing, and reports a decryption failure against a
// commit that is perfectly well formed.
//
// The comparison is crypto/subtle.ConstantTimeCompare and not bytes.Equal. What is compared here
// is public -- both halves are encryption keys the tree publishes -- so nothing leaks either
// way, and the reason is the class rather than this line: a variable time comparator written
// here is one edit away from being pointed at a secret.
//
// Two gates read this line, and which ones is written down because the sentence that used to
// stand here claimed a coverage nothing provided -- this function was under no comparator gate
// at all, and bytes.Equal here left the whole tree green.
// TestNothingThisPackageShipsComparesDataOutsideConstantTime bans the derived comparator class
// in every function of every production file, which is the half that reads EVERY call site;
// TestEveryKeyQuestionOverTheRatchetTreeIsAnsweredInConstantTime is the narrower half that also
// bans the shape naming no comparator at all, string(a) == string(b), and this function is in
// its class because it holds a key of its own and answers over a tree.
//
// It deliberately does NOT re-derive the leaf public key from EncryptionPriv. The CryptoProvider
// surface has no private-to-public operation, and the leaf key pair is checked where both halves
// exist -- in task 22's DecryptUpdatePath, which compares each derived public key against the
// one the UpdatePath carries.
func (self *TreeKEMPrivate) Consistent(crypto CryptoProvider, tree *RatchetTree) error {
	if crypto == nil {
		return ErrNilCryptoProvider
	}
	if tree == nil || tree.Leaf(self.LeafIndex) == nil {
		return ErrPathSecretMismatch
	}
	for x, secret := range self.PathSecrets {
		parent := tree.ParentAt(x)
		if parent == nil {
			return ErrPathSecretMismatch
		}
		_, pub, err := DeriveNodeKeyPair(crypto, secret)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(pub, parent.EncryptionKey) != 1 {
			return ErrPathSecretMismatch
		}
	}
	return nil
}
