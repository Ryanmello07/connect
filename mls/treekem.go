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
	"errors"

	"github.com/urnetwork/connect/mls/syntax"
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

// UpdatePathPlan is everything the sender computed before any encryption happened: the filtered
// direct path it is about to publish, one path secret and one public key per node of it, the
// re-signed leaf, the epoch's commit secret, and the private state the sender keeps.
//
// It exists because generation is SPLIT, and the split is an ordering constraint rather than a
// style. The HPKE encryption context task 20 seals each path secret under is the serialized
// GroupContext of the epoch the commit OPENS, whose tree_hash is the hash of the tree with these
// public keys and this leaf already installed. So the public half has to land in the tree before
// the context exists, and a single call that did both would either encrypt under the previous
// epoch's context -- ciphertexts every peer rejects, and invisible to any test that does not
// distinguish the two contexts -- or have to compute a tree hash over a tree it had not finished
// mutating.
//
// Nothing here is serialized. UpdatePath, the wire type, is task 19's and carries the public keys
// and the ciphertexts alone; the path secrets in this structure never leave the sender.
type UpdatePathPlan struct {
	Path         []NodeIndex
	PathSecrets  [][]byte
	PublicKeys   []HpkePublicKey
	LeafNode     *LeafNode
	CommitSecret []byte
	Private      *TreeKEMPrivate
}

// CreateUpdatePathSecrets is the secret and public half of RFC 9420 section 7.5's UpdatePath
// generation. It MUTATES the tree: it blanks the sender's direct path, installs the fresh public
// keys and the parent hash chain on the filtered path, and installs the re-signed leaf. After it
// returns, TreeHash is the NEW epoch's tree hash and the caller can build the GroupContext task
// 20 encrypts under.
//
// The parent hashes are assigned from the ROOT DOWN, which is the order section 7.9 requires and
// not a preference. The parent hash of a node is taken over that node's own parent_hash field, so
// the value at the top of the filtered path -- the zero-length octet string section 7.9 gives the
// root -- has to be final before the node below it can be hashed, and so on down to the leaf. A
// loop that ran the other way would hash a placeholder field at every level and produce a chain
// that is full length, stable, self-consistent and rejected by every joiner. Each node's copath
// child comes from the PathStep rather than being re-derived here, so this walk and task 21's
// receiving walk are provably over the same children.
//
// The leaf's own key pair is sampled independently and is NOT the first rung of the ladder.
// Everyone who can open the first ciphertext of the UpdatePath learns path_secret[0], so a leaf
// key derived from it is the sender's leaf private key handed to its whole copath -- and the two
// versions are indistinguishable to any test that only checks that the private state's public
// halves agree with the tree.
//
// CommitSecret is the rung PAST the root, section 8.1, which is why DerivePathSecrets answers one
// more value than there are nodes.
//
// It is ATOMIC. Every mutation is made on a working copy and the receiver adopts it in a single
// assignment at the end, so a call that answers an error leaves the caller's tree exactly as it
// found it. Ordering the refusals ahead of the mutation is not enough on its own and this is not
// a hypothetical: leaf.Sign is reachable only after the direct path has been blanked, the new
// public keys installed and the parent hash chain written, so a signature private key that does
// not match the ciphersuite used to answer an error over a tree whose tree hash had already moved
// and which VerifyParentHashes then refused. A caller cannot repair that -- the previous epoch's
// keys are gone -- so the only safe contract is that a failure is a no-op, and task 20 is a
// caller that would otherwise have to know to throw the tree away.
func (self *RatchetTree) CreateUpdatePathSecrets(crypto CryptoProvider, sender LeafIndex,
	signer SignaturePrivateKey, groupId []byte) (*UpdatePathPlan, error) {
	// before anything is read off the receiver, for the reason the nil provider gate states:
	// every secret, key and hash below comes through this provider, and a caller that passed
	// none is told that rather than being sent to look at a tree that is not the problem.
	// bare rather than wrapped with a reason, which is DeriveNodeKeyPair's spelling two
	// declarations up and is not a style choice here: the shape of this signature puts it inside
	// TestEveryKeyQuestionOverTheRatchetTreeIsAnsweredInConstantTime's derived class, and that
	// gate bans every call out of this package from a member of it.
	if crypto == nil {
		return nil, ErrNilCryptoProvider
	}
	// the two ways a sender has no leaf here are two different faults and are answered as two,
	// which is the range check's whole reason for being written out rather than left to Leaf's
	// nil. An index past the width is a caller that computed an index wrong and repairs it by
	// recomputing one; a blank slot inside the tree is a member committing from a position the
	// group REMOVED, whose index was right the whole time and whose repair is to rejoin. One
	// sentinel for both told the second to fix the thing that was not broken.
	if LeafCount(sender) >= self.LeafWidth() {
		return nil, ErrLeafIndexOutOfRange
	}
	// the working copy the atomicity note above is about. Everything below mutates this and the
	// receiver adopts it in one assignment once the last thing that can fail has succeeded.
	working := self.Clone()
	current := working.Leaf(sender)
	if current == nil {
		return nil, ErrLeafBlank
	}
	// computed before the direct path is blanked: blanking the sender's own direct path cannot
	// change any copath child's resolution, so the filtered path is the same either way, and
	// computing it first keeps the failure ahead of the mutation.
	steps, err := working.filteredPathSteps(sender)
	if err != nil {
		return nil, err
	}
	path := make([]NodeIndex, 0, len(steps))
	for _, step := range steps {
		path = append(path, step.Node)
	}
	// the ladder: one secret per filtered node, plus the rung past the root.
	ladder := DerivePathSecrets(crypto, crypto.Random(crypto.HashSize()), len(path))
	pathSecrets := ladder[:len(path)]
	commitSecret := ladder[len(ladder)-1]

	publicKeys := make([]HpkePublicKey, len(path))
	private := NewTreeKEMPrivate(sender, nil)
	for i := range path {
		_, pub, err := DeriveNodeKeyPair(crypto, pathSecrets[i])
		if err != nil {
			return nil, err
		}
		publicKeys[i] = pub
		private.PathSecrets[path[i]] = cloneBytes(pathSecrets[i])
	}

	// the leaf key pair is sampled independently: deriving it from path_secret[0] would hand the
	// sender's leaf private key to everyone who decrypts that secret.
	leafPriv, leafPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		return nil, err
	}
	private.EncryptionPriv = cloneBytes(leafPriv)

	if err := working.BlankDirectPath(sender); err != nil {
		return nil, err
	}
	// installed BEFORE the parent hashes are taken, and the order is load bearing twice over.
	// The parent hash of a node is a hash of that node's encryption_key, so a chain computed
	// against the blanked tree would refuse outright; and the tree hash the caller reads after
	// this call is the new epoch's only because these keys are in it.
	for i, x := range path {
		if err := working.SetParent(x, &ParentNode{EncryptionKey: publicKeys[i]}); err != nil {
			return nil, err
		}
	}

	// the chain, root down. carried is the parent hash of the node ABOVE the one being written,
	// and it starts as the zero-length octet string section 7.9 gives the top of the path.
	carried := []byte{}
	for i := len(steps) - 1; i >= 0; i -= 1 {
		parent := working.ParentAt(steps[i].Node)
		if parent == nil {
			return nil, ErrTreeMalformed
		}
		parent.ParentHash = carried
		hash, err := working.ParentHash(crypto, steps[i].Node, steps[i].CopathChild)
		if err != nil {
			return nil, err
		}
		carried = hash
	}

	// the leaf carries the parent hash of the LOWEST node of the filtered path, section 7.9.1,
	// and it is a commit leaf so that the field is inside what the signature covers. In a group
	// of one the path is empty and carried is still the zero-length octet string, which is the
	// conforming answer rather than an omission: there is no parent node for the leaf to claim.
	leaf := current.Clone()
	leaf.EncryptionKey = leafPub
	leaf.LeafNodeSource = LeafNodeSourceCommit
	leaf.ParentHash = carried
	if err := leaf.Sign(crypto, signer, groupId, sender); err != nil {
		return nil, err
	}
	if err := working.SetLeaf(sender, leaf); err != nil {
		return nil, err
	}

	// the adoption, and the last statement that can be reached by a failure is above it. A
	// caller holding this tree sees the previous epoch or the new one and never a half of both.
	self.nodes = working.nodes

	return &UpdatePathPlan{
		Path:         path,
		PathSecrets:  pathSecrets,
		PublicKeys:   publicKeys,
		LeafNode:     leaf,
		CommitSecret: commitSecret,
		Private:      private,
	}, nil
}

// ---------------------------------------------------------------------------
// task 19: the UpdatePath wire types
// ---------------------------------------------------------------------------

// errNilHpkeCiphertext is OpenWithLabel handed no ciphertext at all.
//
// Unexported, and that is a decision rather than an omission. Nothing outside this package can
// produce the condition: an HpkeCiphertext only ever reaches an open as an element of an
// UpdatePathNode's vector, which decoding builds by value and never as a nil pointer, so the
// only way here is an in-package caller that lost track of a pointer. It is also what
// TestEveryExportedErrorOfThisPackageIsInAMaintainedClass demands -- an exported Err in a file
// with no maintained error class is one no exclusivity sweep of this package judges, and this
// file has no class.
//
// An error rather than the nil dereference the plan's body would take, for guardrail 7's reason
// one layer up: an open answers a failure as an error and never as a plaintext, and a panic in a
// routine fed by the network is a failure no caller can answer at all.
var errNilHpkeCiphertext = errors.New("mls: no hpke ciphertext was supplied")

// HpkeCiphertext is RFC 9420 section 6.1: one HPKE encryption, the KEM output and the AEAD
// ciphertext, in the order the RFC writes them.
//
//	struct { opaque kem_output<V>; opaque ciphertext<V>; } HPKECiphertext;
//
// ONE declaration and not two. The framing plan's Welcome encrypts its group secrets into
// exactly this structure, and a second copy declared there would be two Go types that agree on
// the wire today and disagree the moment either gains a field -- which is the only reason a
// second declaration ever gets written. So Welcome consumes this one.
//
// The two fields are both []byte and adjacent, so a codec that wrote them in the other order
// compiles, round trips, and re-encodes byte exact against the published corpus. Only a golden
// derived from the RFC separates the two orders, which is what
// TestHpkeCiphertextMarshalMatchesTheHandDerivedGolden is.
type HpkeCiphertext struct {
	KemOutput  []byte
	Ciphertext []byte
}

func (self *HpkeCiphertext) MarshalMLS(w *syntax.Writer) error {
	w.WriteOpaque(self.KemOutput)
	w.WriteOpaque(self.Ciphertext)
	return nil
}

// UnmarshalMLS decodes both fields before either is assigned, which is leaf_node.go's staged
// decode at this scale and holds for the same two reasons: a refused decode leaves the receiver
// exactly as it found it, and a receiver decoded into twice answers the second encoding rather
// than a mixture of both.
func (self *HpkeCiphertext) UnmarshalMLS(r *syntax.Reader) error {
	kemOutput, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	ciphertext, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	self.KemOutput = kemOutput
	self.Ciphertext = ciphertext
	return nil
}

// the C1 pin: drift between this type and the one codec convention fails at build.
var _ syntax.Codec = (*HpkeCiphertext)(nil)

// The element halves of encrypted_path_secret<V>, named rather than written as closures at
// the call site.
//
// That is extension.go's and tree.go's spelling for the same shape, and here it is not only
// consistency: TestEverySyntaxEncoderInThisPackageUsesTheDefaultLimit pins every syntax entry
// point of this package by the SOURCE TEXT of the call, so a closure written inline puts its
// whole body into that table and every later edit to the body is a diff in a limit gate.
func writeOneHpkeCiphertext(w *syntax.Writer, ct HpkeCiphertext) error {
	return ct.MarshalMLS(w)
}

func readOneHpkeCiphertext(r *syntax.Reader) (HpkeCiphertext, error) {
	var ct HpkeCiphertext
	err := ct.UnmarshalMLS(r)
	return ct, err
}

// SealWithLabel is the HpkeCiphertext-shaped form of crypto_labels.go's flat pair.
//
// It lives here rather than there because that file must not name a TreeKEM type -- the crypto
// layer is written so it can be read without the tree -- and because this is the file that owns
// the struct. It is an adaptation of two return values into one structure and deliberately not a
// second HPKE implementation: everything that decides interoperability, the label framing and
// the empty aad, stays in the one place crypto_labels.go's own corpus test holds.
//
// The ORDER of the two results is the whole of what can go wrong here. EncryptWithLabel answers
// (kemOutput, ciphertext) and both are []byte, so a transposed adaptation compiles and is
// invisible to a seal-then-open round trip through this same pair of functions. What separates
// them is the LENGTHS -- the KEM output is the suite's Nenc and the ciphertext is the plaintext
// plus the AEAD tag -- which is what
// TestSealWithLabelPutsTheKemOutputAndTheCiphertextInTheirOwnFields asserts.
func SealWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string,
	context []byte, plaintext []byte) (*HpkeCiphertext, error) {
	kemOutput, ciphertext, err := EncryptWithLabel(crypto, pub, label, context, plaintext)
	if err != nil {
		return nil, err
	}
	return &HpkeCiphertext{KemOutput: kemOutput, Ciphertext: ciphertext}, nil
}

// OpenWithLabel is the inverse, and it forwards to DecryptWithLabel rather than reimplementing
// it so that the "no fallback info" rule that file argues for holds here by construction.
func OpenWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string,
	context []byte, ct *HpkeCiphertext) ([]byte, error) {
	// the provider first and the ciphertext second, and the order is required rather than
	// arbitrary. It is what TestEveryDeclarationHandedANilProviderRefusesRatherThanDereferencingIt
	// demands of every construction taking a provider, and it is the right order anyway: a caller
	// that passed no provider passed nothing this function could have used, and answering it
	// about the ciphertext sends it to look at the argument that is not the problem. Bare rather
	// than wrapped with a reason, which is DeriveNodeKeyPair's spelling in this file.
	if crypto == nil {
		return nil, ErrNilCryptoProvider
	}
	if ct == nil {
		return nil, errNilHpkeCiphertext
	}
	return DecryptWithLabel(crypto, priv, label, context, ct.KemOutput, ct.Ciphertext)
}

// UpdatePathNode is RFC 9420 section 7.6: one node of the sender's filtered direct path, its
// fresh public key, and that node's path secret encrypted once per node in the resolution of the
// copath child.
//
//	struct { HPKEPublicKey encryption_key; HPKECiphertext encrypted_path_secret<V>; } UpdatePathNode;
//
// Nothing in this file checks that the number of ciphertexts is the number of nodes that
// resolution holds, and that is a BOUNDARY rather than a gap worth stating where the type is
// declared. The resolution is a property of a ratchet tree at an epoch, and a codec has neither:
// it is handed bytes. The check belongs to whoever holds the tree the path was built against --
// task 22's decrypt walks the resolution to pick its own ciphertext out of this vector, and is
// the first place both facts exist at once -- and the hazard worth naming is that a check both
// sides assume the other makes is a check nobody makes.
// TestEveryPublishedUpdatePathHasOneCiphertextPerResolutionNode states the relation against the
// published corpus, so the two halves at least agree on what the relation IS.
type UpdatePathNode struct {
	EncryptionKey       HpkePublicKey
	EncryptedPathSecret []HpkeCiphertext
}

func (self *UpdatePathNode) MarshalMLS(w *syntax.Writer) error {
	w.WriteOpaque(self.EncryptionKey)
	return syntax.WriteVector(w, self.EncryptedPathSecret, writeOneHpkeCiphertext)
}

// UnmarshalMLS reads the key and the vector before either is assigned, for the reason
// HpkeCiphertext's decode states.
//
// The vector prefix counts BYTES and not elements, which is syntax.ReadVector's contract rather
// than this file's choice, and it is the one thing about this structure a round trip cannot see:
// an encoder writing an element count and a decoder reading an element count agree with each
// other and with no other implementation. The hand derived goldens are what pin it.
func (self *UpdatePathNode) UnmarshalMLS(r *syntax.Reader) error {
	encryptionKey, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	ciphertexts, err := syntax.ReadVector(r, readOneHpkeCiphertext)
	if err != nil {
		return err
	}
	self.EncryptionKey = HpkePublicKey(encryptionKey)
	self.EncryptedPathSecret = ciphertexts
	return nil
}

var _ syntax.Codec = (*UpdatePathNode)(nil)

// the element halves of nodes<V>, named for the reason the ciphertext pair above is.
func writeOneUpdatePathNode(w *syntax.Writer, node UpdatePathNode) error {
	return node.MarshalMLS(w)
}

func readOneUpdatePathNode(r *syntax.Reader) (UpdatePathNode, error) {
	var node UpdatePathNode
	err := node.UnmarshalMLS(r)
	return node, err
}

// UpdatePath is RFC 9420 section 7.6, the public half of what task 18's UpdatePathPlan computed:
// the sender's re-signed commit leaf, and one node per step of its filtered direct path.
//
//	struct { LeafNode leaf_node; UpdatePathNode nodes<V>; } UpdatePath;
//
// The path secrets themselves are NOT here and never are -- UpdatePathPlan holds those and has
// no codec at all -- so this is the whole of what a commit publishes about the sender's path.
type UpdatePath struct {
	LeafNode LeafNode
	Nodes    []UpdatePathNode
}

func (self *UpdatePath) MarshalMLS(w *syntax.Writer) error {
	if err := self.LeafNode.MarshalMLS(w); err != nil {
		return err
	}
	return syntax.WriteVector(w, self.Nodes, writeOneUpdatePathNode)
}

// UnmarshalMLS decodes into a STAGED value and assigns it whole, which is leaf_node.go's
// discipline carried up one level, and up here it is load bearing in a way it is not inside a
// leaf.
//
// The plan's body decodes the leaf straight into the receiver's own field and then reads the
// nodes vector. A truncated or refused vector then leaves the caller holding an UpdatePath whose
// leaf came from these bytes and whose nodes are whatever the receiver arrived with -- and the
// leaf is the half carrying a signature, an encryption key and a parent hash, so that value is a
// path nobody sent, assembled out of two messages, sitting behind an error the caller may well
// have logged rather than returned. Staging makes the decoded path a function of the bytes it
// was read from and of nothing else.
func (self *UpdatePath) UnmarshalMLS(r *syntax.Reader) error {
	staged := UpdatePath{}
	if err := staged.LeafNode.UnmarshalMLS(r); err != nil {
		return err
	}
	nodes, err := syntax.ReadVector(r, readOneUpdatePathNode)
	if err != nil {
		return err
	}
	staged.Nodes = nodes
	*self = staged
	return nil
}

var _ syntax.Codec = (*UpdatePath)(nil)
